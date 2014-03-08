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

#define  MODULE_NAME "xwatch"

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN MODULE_NAME
#endif

#include "config.h"
#include "ulatency.h"
#include "usession.h"
#include "uhook.h"
#include "ufocusstack.h"
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

static gboolean module_debug = FALSE;
#define m_debug(...) if (module_debug) g_debug (__VA_ARGS__)

#define DEFAULT_INTERVAL 1000
#define RETRY_TIMEOUT 30
static int interval;

struct x_server {
  USession *session;
  time_t last_try;
  guint timeout_id;
  xcb_connection_t *connection;
  xcb_screen_t *screen;
  xcb_atom_t atom_active;
  xcb_atom_t atom_pid;
  xcb_atom_t atom_client;
  xcb_atom_t window_atom;
  xcb_atom_t cardinal_atom;
  xcb_atom_t string_atom;
};

static const gchar *module_name;
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

static int
create_connection (struct x_server *xs) {
  int  screenNum, i, dsp, parsed = 0;
  char *host;
  char dispbuf[40];   /* big enough to hold more than 2^64 base 10 */
  int dispbuflen;
  xcb_screen_iterator_t iter;
  const xcb_setup_t *setup;
  struct passwd *pw;
  GPtrArray *xauthptr;
  char *save_home, *save_xauth = NULL;
  guint uid;
  gchar *display;

  uid = xs->session->uid;
  display = xs->session->X11Display;
  xs->last_try = time(NULL);

  g_debug("create x-watch connection: '%s'", display);

  parsed = xcb_parse_display(display, &host, &dsp, &screenNum);
  if(!parsed) {
    g_warning("can't parse display: '%s'", display);
    return -1;
  }
  free(host);


  dispbuflen = snprintf(dispbuf, sizeof(dispbuf), "%d", dsp);
  if(dispbuflen < 0) {
      printf("cant put display buf\n");
      return -1;
  }

  pw = getpwuid(uid);
  save_home = g_strdup(getenv("HOME"));
  save_xauth = g_strdup(getenv("XAUTHORITY"));
  xauthptr = search_user_env(uid, "XAUTHORITY", TRUE);

  setenv("HOME", pw->pw_dir, 1);
  unsetenv("XAUTHORITY");
  i = -1;
  if(seteuid(uid)) {
      g_warning("can't seteuid to %d", uid);
      goto error;
  }

  do {
    xs->connection = xcb_connect(display, &screenNum);

    if(xs->connection) {
      setup = xcb_get_setup(xs->connection);
      if(setup) {
        g_debug("connected to X11 %s", display);
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

  return 0;

error:
  seteuid(0);

  g_message("could not connect to display %s \n", display);

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

  return 1;
}

// test if connection is alive, initiate new connection if lost etc
static gboolean
test_connection(struct x_server *xs) {

    if(xs->connection) {
        if(xcb_connection_has_error(xs->connection)) {
            xcb_disconnect(xs->connection);
            xs->connection = NULL;
            xs->screen = NULL;
            g_debug("got connection problems. disconnected %s",
                    xs->session->X11Display);
        } else {
          return TRUE;
        }
    }

    if(!xs->connection) {
        if(xs->last_try && xs->last_try + RETRY_TIMEOUT > time(NULL))
            return FALSE;
        return create_connection(xs) == 0;
    }
    return FALSE;
}

static gint
match_session(gconstpointer a, gconstpointer b) {
  const struct x_server *xa = a;
  return xa->session != (USession *) b;
}

static void
del_connection(struct x_server *rm) {
  m_debug("Remove x_server display: %s", rm->session->X11Display);
  if (rm->connection)
    xcb_disconnect (rm->connection);
  DEC_REF (rm->session);
  server_list = g_list_remove (server_list, rm);
  g_free (rm);
}

static inline struct x_server *
find_connection (const USession *sess)
{
  GList *llink;

  llink = g_list_find_custom (server_list, sess, match_session);
  if (llink)
    return (struct x_server *)llink->data;
  else
    return NULL;
}

static struct x_server *
add_connection (USession *sess)
{
  struct x_server *nc;

  nc = find_connection (sess);
  if (nc)
    return nc;

  nc = g_malloc0(sizeof(struct x_server));

  nc->session = sess;
  INC_REF (sess);

  create_connection (nc);

  server_list = g_list_append(server_list, nc);

  return nc;
}

static pid_t
read_pid(struct x_server *conn, int *err) {
  xcb_generic_error_t *error;
  *err = 0;
  pid_t rv = 0;

  dprint("dsp: %s xs: %p conn: %p\n",
         conn->session->X11Display, conn, conn->connection);

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

static pid_t previous_pid = 0;

static gboolean //GSourceFunc
poll_connection (gpointer data)
{
  struct x_server *conn;

  conn = (struct x_server *) data;
  if (test_connection (conn))
    {
      pid_t pid;
      int   error;

      error = 0;
      pid = read_pid (conn, &error);

      if (pid && pid != previous_pid && error == 0)
        {
          previous_pid = pid;
          u_focus_stack_add_pid(conn->session->focus_stack, pid, 0);
          m_debug("PID %d polled on display %s (session %d).",
                  pid, conn->session->X11Display, conn->session->id);
        }
    }

  return TRUE;
}

static void
stop_poll_connection (struct x_server *conn)
{
  if (conn->timeout_id) // if polling
    {
      g_source_remove (conn->timeout_id);
      conn->timeout_id = 0;
      g_info("Polling stopped on display %s (session %d).",
              conn->session->X11Display, conn->session->id);
    }
}

static void
start_poll_connection (struct x_server *conn)
{
  if (conn->timeout_id != 0) // not polling
    return;

  conn->timeout_id = g_timeout_add (interval, poll_connection,
                                      (gpointer) conn);
  g_info("Polling started on display %s (session %d).",
          conn->session->X11Display, conn->session->id);
}

static gboolean //UHookFunc
hook_session_removed (gpointer ignored)
{
  UHookDataSession *hook_data;
  USession         *sess;

  hook_data = (UHookDataSession *) u_hook_list_get_data (
      U_HOOK_TYPE_SESSION_REMOVED);

  sess = hook_data->session;
  if (sess->focus_tracker == module_name) // tracked by xwatch
    {
      struct x_server *conn;

      conn = find_connection (sess);
      g_assert (conn != NULL);
      stop_poll_connection (conn);
      del_connection (conn);
      sess->focus_tracker = NULL;
    }

  DEC_REF (hook_data);
  return TRUE;
}

static gboolean //UHookFunc
hook_session_changed (gpointer ignored)
{
  UHookDataSession *hook_data;
  USession        *sess;

  hook_data = (UHookDataSession *) u_hook_list_get_data (
      U_HOOK_TYPE_SESSION_ACTIVE_CHANGED);

  sess = hook_data->session;
  if (sess->focus_tracker == module_name) // tracked by xwatch
    {
      struct x_server *conn;

      conn = find_connection (sess);;
      g_assert(conn != NULL);
      if (sess->active && !sess->idle)
        start_poll_connection (conn);
      else
        stop_poll_connection (conn);
    }

  DEC_REF (hook_data);
  return TRUE;
}

static gboolean //UHookFunc
hook_tracker_unregister (gpointer ignored)
{
  UHookDataSession *hook_data;
  USession         *sess;
  struct x_server  *conn;

  hook_data = (UHookDataSession *) u_hook_list_get_data (
      U_HOOK_TYPE_SESSION_UNSET_FOCUS_TRACKER);

  sess = hook_data->session;
  g_assert (sess->focus_tracker == module_name);
  sess->focus_tracker = NULL;
  conn = find_connection (sess);
  g_assert(conn != NULL);
  stop_poll_connection (conn);

  DEC_REF (hook_data);
  return TRUE;
}

static gboolean //UHookFunc
hook_tracker_changed (gpointer ignored)
{
  UHookDataSession *hook_data;
  USession         *sess;
  struct x_server  *conn;
  uid_t            myid;

  hook_data = (UHookDataSession *) u_hook_list_get_data (
      U_HOOK_TYPE_SESSION_FOCUS_TRACKER_CHANGED);
  sess = hook_data->session;
  if (sess->focus_tracker
      || (g_strcmp0 (sess->session_type, "x11") != 0
          && g_strcmp0 (sess->session_type, "LoginWindow") != 0))
    // FIXME what about "LoginWindow" type sessions (is this always be x11?)
    goto finish;

  // test if we are root. we will not be able to connect to other users
  // if we are not root, so skip them
  myid = getuid ();
  if (G_UNLIKELY (myid && myid != sess->uid))
      goto finish;

  if (G_UNLIKELY (!u_session_set_focus_tracker(sess, module_name)))
    goto finish;

  /* register xwatch as new focus tracker */
  conn = add_connection (sess);
  g_assert(conn != NULL);
  if (sess->active && !sess->idle)
    start_poll_connection (conn);

finish:
  DEC_REF (hook_data);
  return TRUE;
}


G_MODULE_EXPORT const gchar*
g_module_check_init (GModule *module)
{
  GError *error = NULL;

  localhost = get_localhost();
  if(!localhost)
    return "Can't find localhost name.";
  module_name = g_intern_string(MODULE_NAME);

  interval = g_key_file_get_integer(config_data, "xwatch", "poll_interval", &error);
  if(error) {
    interval = DEFAULT_INTERVAL;
    g_error_free(error);
  }

  module_debug = g_key_file_get_boolean (config_data, "consolekit",
                                        "debug", NULL);

  u_hook_add (U_HOOK_TYPE_SESSION_REMOVED, module_name, hook_session_removed);
  u_hook_add (U_HOOK_TYPE_SESSION_ACTIVE_CHANGED, module_name, hook_session_changed);
  u_hook_add (U_HOOK_TYPE_SESSION_IDLE_CHANGED, module_name, hook_session_changed);
  u_hook_add (U_HOOK_TYPE_SESSION_FOCUS_TRACKER_CHANGED, module_name, hook_tracker_changed);
  u_hook_add (U_HOOK_TYPE_SESSION_UNSET_FOCUS_TRACKER, module_name, hook_tracker_unregister);

  g_message("X server observation active, poll interval: %d ms", interval);
  return NULL;
}

#undef m_debug
