/*
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    ulatencyd is free software: you can redistribute it and/or modify it under 
    the terms of the GNU General Public License as published by the 
    Free Software Foundation, either version 3 of the License, 
    or (at your option) any later version.

    ulatencyd is distributed in the hope that it will be useful, 
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License 
    along with ulatencyd. If not, see http://www.gnu.org/licenses/.
*/

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "xwatch"
#endif

#include "config.h"
#include "ulatency.h"
#include <dbus/dbus-glib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xcb/xcb.h>
#include <X11/Xauth.h>
#include <errno.h>
#include <glib.h>
#include <gmodule.h>
#include <pwd.h>
#include <time.h>

#ifdef DEBUG_XWATCH
#define dprint(...) printf(__VA_ARGS__)
#else
#define dprint(...)
#endif



#define DEFAULT_INTERVAL 1000
#define RETRY_TIMEOUT 30

struct x_server {
  char *name; // unique name for identification
  time_t last_try;
  uid_t uid;
  char *display;
  xcb_connection_t *connection;
  xcb_screen_t *screen;
  xcb_atom_t atom_active;
  xcb_atom_t atom_pid;
  xcb_atom_t atom_client;
  xcb_atom_t window_atom;
  xcb_atom_t cardinal_atom;
  xcb_atom_t string_atom;
};

static void free_x_server(struct x_server *xs) {
  g_debug("remove x_server display: %s", xs->display);
  if(xs->connection)
      xcb_disconnect (xs->connection);
  g_free(xs->name);
  g_free(xs->display);
}

static int xwatch_id; // unique plugin id
static GList *server_list = NULL;  // list of x_server objects
static char *localhost; // char of localhost

static
xcb_atom_t get_atom (xcb_connection_t *conn, xcb_intern_atom_cookie_t ck)
{
  xcb_intern_atom_reply_t *reply;
  xcb_atom_t atom;

  reply = xcb_intern_atom_reply (conn, ck, NULL);
  if (reply == NULL)
      return 0;

  atom = reply->atom;
  free (reply);
  return atom;
}


static inline
xcb_intern_atom_cookie_t intern_string (xcb_connection_t *c, const char *s)
{
    return xcb_intern_atom (c, 0, strlen (s), s);
}

static char *
get_localhost()
{
  char *hostname = NULL, *buf = NULL;
  size_t size = 34; // initial hostname length
  int myerror = 0;

  do {
    errno = 0;

    if (buf)
      size += size;

    if ((buf = realloc (hostname, size)) == NULL) {
      g_warning("malloc failed");
      goto error;
    }
    buf[size - 1] = '\0';
    hostname = buf;
  } while (((myerror = gethostname(hostname, size)) == 0 && hostname[size - 1])
          || errno == ENAMETOOLONG);

  /* gethostname failed, abort. */
  if (myerror) {
    g_warning("can't get hostname");
    goto error;
  }

  return hostname;

error:
  if (buf)
    free(buf);
  return NULL;
}

int create_connection(struct x_server *xs) {
  int  screenNum, i, dsp, parsed = 0;
  char *host;
  char dispbuf[40];   /* big enough to hold more than 2^64 base 10 */
  int dispbuflen;
  xcb_screen_iterator_t iter;
  const xcb_setup_t *setup;
  struct passwd *pw;
  GPtrArray *xauthptr;
  char *save_home, *save_xauth = NULL;

  xs->last_try = time(NULL);

  g_debug("create x-watch connection: '%s'", xs->display);

  parsed = xcb_parse_display(xs->display, &host, &dsp, &screenNum);
  free(host);
  if(!parsed) {
    g_warning("can't parse display: '%s'", xs->display);
    return FALSE;
  }


  dispbuflen = snprintf(dispbuf, sizeof(dispbuf), "%d", dsp);
  if(dispbuflen < 0) {
      printf("cant put display buf\n");
      return FALSE;
  }

  pw = getpwuid(xs->uid);
  save_home = g_strdup(getenv("HOME"));
  save_xauth = g_strdup(getenv("XAUTHORITY"));
  xauthptr = search_user_env(xs->uid, "XAUTHORITY", TRUE);

  setenv("HOME", pw->pw_dir, 1);
  unsetenv("XAUTHORITY");
  i = -1;
  if(seteuid(xs->uid)) {
      g_warning("can't seteuid to %d", xs->uid);
      goto error;
  }

  do {
    xs->connection = xcb_connect(xs->display, &screenNum);

    if(xs->connection) {
      setup = xcb_get_setup(xs->connection);
      if(setup) {
        g_debug("connected to X11 %s", xs->display);
        break;
      }
      xcb_disconnect (xs->connection);
    }
    i++;
    if(!xauthptr)
      goto error;
    if(i >= xauthptr->len)
      goto error;

    setenv("XAUTHORITY", g_ptr_array_index(xauthptr, i), 1);
  } while(TRUE);

  if((getuid() == 0) && seteuid(0)) {
      g_error("can't switch back to root");
  }

  g_ptr_array_unref(xauthptr);

  if(save_home)
    setenv("HOME", save_home, 1);
  else
    unsetenv("HOME");
  if(save_xauth)
    setenv("XAUTHORITY", save_xauth, 1);
  else
    unsetenv("XAUTHORITY");

  g_free(save_xauth);
  g_free(save_home);


  iter = xcb_setup_roots_iterator(setup);  

  // we want the screen at index screenNum of the iterator
  for (i = 0; i < screenNum; ++i) {
      xcb_screen_next (&iter);
  }

  xs->screen = iter.data;


  g_message("connected to X11 host: %s display: %d screen: %d", localhost, dsp, screenNum);

  // fillup the x server atoms
  xcb_intern_atom_cookie_t net_active_ck
      = intern_string (xs->connection, "_NET_ACTIVE_WINDOW");

  xcb_intern_atom_cookie_t net_pid_ck
      = intern_string (xs->connection, "_NET_WM_PID");

  xcb_intern_atom_cookie_t net_client_ck
      = intern_string (xs->connection, "WM_CLIENT_MACHINE");

  xs->atom_active = get_atom (xs->connection, net_active_ck);
  xs->atom_pid = get_atom (xs->connection, net_pid_ck);
  xs->atom_client = get_atom (xs->connection, net_client_ck);


  xcb_intern_atom_cookie_t window_ck
          = intern_string (xs->connection, "WINDOW");

  xcb_intern_atom_cookie_t cardinal_ck
          = intern_string (xs->connection, "CARDINAL");

  xcb_intern_atom_cookie_t string_ck
          = intern_string (xs->connection, "STRING");

  xs->window_atom = get_atom (xs->connection, window_ck);
  xs->cardinal_atom = get_atom (xs->connection, cardinal_ck);
  xs->string_atom = get_atom (xs->connection, string_ck);

  return TRUE;

error:
  seteuid(0);

  g_message("could not connect to display %s \n", xs->display);

  // restore env
  if(save_home)
    setenv("HOME", save_home, 1);
  else
    unsetenv("HOME");
  if(save_xauth)
    setenv("XAUTHORITY", save_xauth, 1);
  else
    unsetenv("XAUTHORITY");

  g_free(save_xauth);
  g_free(save_home);
  g_ptr_array_unref(xauthptr);

  return FALSE;
}

// test if connection is alive, initiate new connection if lost etc
int test_connection(struct x_server *xs) {

    if(xs->connection) {
        if(xcb_connection_has_error(xs->connection)) {
            xcb_disconnect(xs->connection);
            xs->connection = NULL;
            xs->screen = NULL;
            g_debug("got connection problems. disconnectd %s", xs->display);
        } else {
          return TRUE;
        }
    }

    if(!xs->connection) {
        if(xs->last_try && xs->last_try + RETRY_TIMEOUT > time(NULL))
            return FALSE;
        return create_connection(xs);
    }
    return FALSE;
}

gint match_display(gconstpointer a, gconstpointer b) {
  const struct x_server *xa = a;
  return strcmp(xa->display, (const char *)b);
}


void del_connection(struct x_server *rm) {
  free_x_server(rm);
  server_list = g_list_remove(server_list, rm);
  g_free(rm);
}

struct x_server *add_connection(const char *name, uid_t uid, const char *display) {
  struct x_server *nc;
  GList *cur;
  uid_t myid = getuid();

  // test if we are root. we will not be able to connect to other users
  // if we are not root, so skip them
  if(myid && myid != uid)
    return NULL;

  while(TRUE) {
    cur = g_list_find_custom(server_list, display, match_display);
    if(!cur)
      break;
    del_connection(cur->data);
  }

  nc = g_malloc0(sizeof(struct x_server));

  nc->name = g_strdup(name);
  nc->display = g_strdup(display);
  nc->uid = uid;

  create_connection(nc);

  server_list = g_list_append(server_list, nc);

  return nc;
}

pid_t read_pid(struct x_server *conn, int *err) {
  xcb_generic_error_t *error;
  *err = 0;
  pid_t rv = 0;

  dprint("dsp: %s xs: %p conn: %p\n", conn->display, conn, conn->connection);

  xcb_get_property_cookie_t naw =
    xcb_get_property (conn->connection,
                      0,
                      conn->screen->root,
                      conn->atom_active,
                      conn->window_atom,
                      0,
                      1);

  // warning: on some systems this won't return if some GUI application is
  // in frozen cgroup under the freezer subsystem
  xcb_get_property_reply_t *rep =
    xcb_get_property_reply (conn->connection,
                          naw,
                          NULL);

  if(!rep || !xcb_get_property_value_length(rep)) {
    g_free(rep);
    return 0;
  }

  dprint("len: %d ", xcb_get_property_value_length (rep));
  uint32_t win = *(uint32_t *)xcb_get_property_value(rep);
  dprint("win: 0x%x\n", win);
  g_free(rep);

  xcb_get_property_cookie_t caw =
    xcb_get_property (conn->connection,
                    0,
                    win,
                    conn->atom_pid,
                    conn->cardinal_atom,
                    0,
                    1);

  xcb_get_property_reply_t *rep2 =
    xcb_get_property_reply (conn->connection,
                        caw,
                        &error);

  if((error && error->response_type == 0) || 
     !rep2 || !xcb_get_property_value_length(rep2)) {
    g_free(rep2);
    goto error;
  }

  dprint("len: %d ", xcb_get_property_value_length (rep2));
  uint32_t pid = *(uint32_t *)xcb_get_property_value(rep2);
  dprint("pid: %d\n", pid);
  g_free(rep2);

  xcb_get_property_cookie_t ccaw =
    xcb_get_property (conn->connection,
                  0,
                  win,
                  conn->atom_client,
                  conn->string_atom,
                  0,
                  strlen(localhost));

  xcb_get_property_reply_t *rep3 =
    xcb_get_property_reply (conn->connection,
                        ccaw,
                        &error);

  if((error && error->response_type == 0) ||
    !rep3 || !xcb_get_property_value_length(rep3)) {
    g_free(rep3);
    goto error;
  }

  char *client =  xcb_get_property_value(rep3);
#ifdef DEBUG_XWATCH
  char *tmp = g_strndup(xcb_get_property_value(rep3), xcb_get_property_value_length(rep3));
  dprint("client: %d %s\n", xcb_get_property_value_length(rep3), tmp);
  g_free(tmp);
#endif
  if(client && !strncmp(client, localhost, xcb_get_property_value_length(rep3))) {
    rv = pid;
  }

  g_free(rep3);
  g_free(error);

  return rv;
error:
  // error in connection. free x_server connection
  if(error && error->response_type == 0 && error->error_code == 3) {
    g_free(error);
    return 0;
  }
  *err = 1;
  if(error) {
    g_debug("xcb error: %d %d\n", error->response_type, error->error_code);
    g_free(error);
  }
  return 0;
}



#ifndef TEST_XWATCH

static gboolean update_all_server(gpointer data) {
  GList *cur;
  pid_t pid;
  int i;
  u_session *sess;
  GList *csess;
  struct x_server *xs;

  // check the session list for new/changed servers
  // remove dead servers
  for(i = 0; i < g_list_length(server_list);) {
    int found = FALSE;
    cur = g_list_nth(server_list, i);
    xs = cur->data;

    csess = g_list_first(U_session_list);
    while(csess) {
      sess = csess->data;

      if(!strcmp(xs->name, sess->name)) {
        found = TRUE;
        break;
      }
      csess = g_list_next(csess);
    }
    if(!found) {
      del_connection(xs);
    } else {
      i++;
    }
  }
  csess = g_list_first(U_session_list);
  while(csess) {
    sess = csess->data;
    int found = FALSE;
    GList *xcur = g_list_first(server_list);
    while(xcur) {
      xs = xcur->data;
      if(!strcmp(xs->name, sess->name)) {
        found = TRUE;
        break;
      }
      xcur = g_list_next(xcur);
    }
    if(!found && sess->X11Display && strcmp(sess->X11Display, "")) {
      add_connection(sess->name, sess->uid, sess->X11Display);
    }

    csess = g_list_next(csess);
  }

  int error = 0;
  cur = server_list;
  while(cur) {
    struct x_server *xs = cur->data;
    struct user_active *ua = get_userlist(xs->uid, TRUE);

    // we take over the active pid if noone is doing it
    if(ua->active_agent == USER_ACTIVE_AGENT_NONE)
        ua->active_agent = xwatch_id;

    if(
        ua->active_agent != xwatch_id || // test if another agent is doing the active pid
        ua->enabled == FALSE             // test if the user's session is inactive and should be skipped
    ){
        cur = g_list_next(cur);
        continue;
    }

    // if we can't connect, skip
    if(!test_connection(xs)) {
      cur = g_list_next(cur);
      continue;
    }

    pid = read_pid(xs, &error);

    if(pid && error == 0) {
      //printf ("current uid: %d pid: %d\n", xs->uid, pid);
      set_active_pid(xs->uid, pid, 0);
    }

    cur = g_list_next(cur);
  }
  return TRUE;
}
#endif

G_MODULE_EXPORT const gchar*
g_module_check_init (GModule *module)
{
  localhost = get_localhost();
  if(!localhost) {
    return "can't find localhost name";
  }
  xwatch_id = get_plugin_id();
#ifndef TEST_XWATCH
  GError *error = NULL;
  int interval = g_key_file_get_integer(config_data, "xwatch", "poll_interval", &error);
  if(error) {
    interval = DEFAULT_INTERVAL;
    g_error_free(error);
  }
  g_timeout_add(interval, update_all_server, NULL);
  g_message("x server observation active. poll interval: %d", interval);
#endif
  return NULL;
}
