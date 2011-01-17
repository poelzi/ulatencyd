/* !!!!  CLOSE YOUR EYES OR CLOSE THIS FILE :-)  !!!!

or you want to clean up this mess.

current problems:
it is quite hard to connect as root to a local xserver. you need a valid
auth cookie to connnect for detecting the current used window.
getting a valid cookie is hard, xcb uses a different format then the
Xauth parser, but does not export anything usefull obtaining it. 
thats the first reason for all this copied code.
Reading the auth file needs to be done as the user owning it, as root may not
access it in case of nfs for example.

*/

#include "config.h"
#include "ulatency.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xcb/xcb.h>
#include <xcb/xcb_event.h>
#include <xcb/xcb_atom.h>
#include <X11/Xauth.h>
#include <X11/Xdmcp.h>
#include <errno.h>
#include <glib.h>
#include <pwd.h>


enum auth_protos {
    AUTH_MC1,
    N_AUTH_PROTOS
};

#define AUTH_PROTO_XDM_AUTHORIZATION "XDM-AUTHORIZATION-1"
#define AUTH_PROTO_MIT_MAGIC_COOKIE "MIT-MAGIC-COOKIE-1"

static char *authnames[N_AUTH_PROTOS] = {
    AUTH_PROTO_MIT_MAGIC_COOKIE,
};

static int authnameslen[N_AUTH_PROTOS] = {
    sizeof(AUTH_PROTO_MIT_MAGIC_COOKIE) - 1,
};

struct x_server {
    uid_t uid;
    char *display;
    xcb_auth_info_t *auth;
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
  xcb_disconnect (xs->connection);
  g_free(xs->display);
  g_free(xs->auth->name);
  g_free(xs->auth->data);
  g_free(xs->auth);
}

static GList *server_list = NULL;

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

static const char bin2hex_lst[16] = {
'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};


char *bin2hex(const char *data, size_t len) {
  size_t lenout, i;
  char *out;

  if (len == 0) {
    return NULL;
  }

  lenout = (len * 2)+1;

  //printf("len %d\n", (int)lenout);

  out = malloc(lenout);
  if (!out) {
    return NULL;
  }

  for (i=0; i < len; i++) {
    out[2*i]   = bin2hex_lst[(data[i] & 0xf0) >> 4];
    out[2*i+1] = bin2hex_lst[(data[i] & 0x0f)];
  }
  out[lenout-1] = 0;
  return out;
}


int hex2bin(const char *data, size_t len, char **bin, int *len_out) {
  size_t lenout, i;

  if (len == 0) {
    return 1;
  } else if (len % 2) {
    return 1;
  }

  lenout = len / 2;
  char *out = malloc(lenout+1);
  if (!out) {
    return 1;
  }

  for (i=0; i < lenout; i++) {
    char c = data[2*i];
    if (c >= '0' && c <= '9') {
      out[i] = (c - '0') << 4;
    } else if (c >= 'a' && c <= 'f') {
      out[i] = (c - 'a' + 10) << 4;
    } else if (data[2*i] >= 'A' && c <= 'F') {
      out[i] = (c - 'A' + 10) << 4;
    } else {
      free(out);
      return 1;
    }

    c = data[2*i+1];
    if (c >= '0' && c <= '9') {
      out[i] += c - '0';
    } else if (c >= 'a' && c <= 'f') {
      out[i] += c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      out[i] += c - 'A' + 10;
    } else {
      free(out);
      return 1;
    }
  }
  out[lenout] = 0;
  *len_out = lenout;
  *bin = out;

  return 0;
}




static inline
xcb_intern_atom_cookie_t intern_string (xcb_connection_t *c, const char *s)
{
    return xcb_intern_atom (c, 0, strlen (s), s);
}

char *
get_localhost()
{
  char *buf = 0;
  size_t buf_len = 0;
  int myerror = 0;

  do {
    errno = 0;

    if (buf) {
      buf_len += buf_len;
      if ((buf = realloc (buf, buf_len)) == NULL)
        err(1, NULL);
    } else {
      buf_len = 128;        /* Initial guess */
      if ((buf = malloc (buf_len)) == NULL)
        err(1, NULL);
      }
  } while (((myerror = gethostname(buf, buf_len)) == 0 && !memchr (buf, '\0', buf_len))
          || errno == ENAMETOOLONG);

  /* gethostname failed, abort. */
  if (myerror)
    err(1, NULL);

  return buf;
}

static char *localhost;

xcb_auth_info_t *read_xauth(int uid, char *hostname, int display)
{
  int     fd[2], nbytes;
  pid_t   childpid;
  char    readbuffer[40];
  char dispbuf[40];   /* big enough to hold more than 2^64 base 10 */
  int dispbuflen;
  xcb_auth_info_t *rv;
  Xauth *xauth;
  char *tmp;
  xcb_auth_info_t *tmpauth = NULL;
  GString *full_data = g_string_new("");
  int    childrv;


  pipe(fd);
  
  if((childpid = fork()) == -1)
  {
    perror("fork");
    exit(1);
  }

  if(childpid == 0)
  {
    /* Child process closes up input side of pipe */
    close(fd[0]);
    tmpauth = malloc(sizeof(xcb_auth_info_t));
    setuid(uid);
    clearenv();
    struct passwd *pw = getpwuid(uid);

    setenv("HOME", pw->pw_dir, 1);
    dispbuflen = snprintf(dispbuf, sizeof(dispbuf), "%d", display);
    if(dispbuflen < 0) {
      printf("cant put display buf\n");
      return 0;
    }

    xauth = XauGetBestAuthByAddr (FamilyLocal,
                         (unsigned short) strlen(localhost), localhost,
                         (unsigned short) dispbuflen, dispbuf,
                         N_AUTH_PROTOS, authnames, authnameslen);

    if(!xauth)
      exit(1);

    tmpauth->namelen = xauth->name_length;
    tmpauth->name =  g_malloc0(xauth->name_length+1);
    memcpy(tmpauth->name, xauth->name, xauth->name_length);

    tmpauth->datalen = xauth->data_length;
    tmpauth->data =  g_malloc0(xauth->data_length+1);
    memcpy(tmpauth->data, xauth->data, xauth->data_length);

    // move the data as hex
    tmp = bin2hex(tmpauth->name, tmpauth->namelen);
    /* Send "string" through the output side of pipe */
    write(fd[1], tmp, strlen(tmp));
    write(fd[1], ":", 1);
    //printf("send: %s:", tmp);
    free(tmp);
    tmp = bin2hex(tmpauth->data, tmpauth->datalen);
    write(fd[1], tmp, strlen(tmp));
    //printf("%s\n", tmp);
    free(tmp);
    close(fd[1]);
    exit(0);
  }
  else
  {
    /* Parent process closes up output side of pipe */
    close(fd[1]);

    /* Read in a string from the pipe */
    while(TRUE) {
      nbytes = read(fd[0], readbuffer, sizeof(readbuffer));
      if(!nbytes) {
        full_data = g_string_append_c(full_data, 0);
        break;
      }
      full_data = g_string_append_len(full_data, (const char*)&readbuffer, nbytes);
    }
    //printf("Received string: '%s' \n", full_data->str);

    waitpid(childpid, &childrv, 0);

    if(full_data->len < 10)
      return NULL;

    rv = malloc(sizeof(xcb_auth_info_t));
    tmp = strchr(full_data->str, ':');
    hex2bin(full_data->str, tmp-(full_data->str), &rv->name, &rv->namelen);
    hex2bin(tmp+1, (full_data->len - (tmp - full_data->str) - 2), &rv->data, &rv->datalen);
    g_string_free(full_data, TRUE);
    if(!rv->namelen || !rv->datalen) {
      free(rv);
      return NULL;
    }
    close(fd[0]);
    return rv;
  }

  return NULL;
}

struct x_server *create_connection(uid_t uid, const char *display) {
    int  screenNum, i, dsp, parsed = 0;
    char *host;
    char dispbuf[40];   /* big enough to hold more than 2^64 base 10 */
    int dispbuflen;
    xcb_screen_iterator_t iter;
    const xcb_setup_t *setup;
    struct x_server *rv;

    parsed = xcb_parse_display(display, &host, &dsp, &screenNum);

    if(!parsed) {
      g_warning("can't parse display: %s", display);
      return NULL;
    }


    dispbuflen = snprintf(dispbuf, sizeof(dispbuf), "%d", dsp);
    if(dispbuflen < 0) {
        printf("cant put display buf\n");
        return NULL;
    }

    rv = g_malloc0(sizeof(struct x_server));

    rv->display = g_strdup(display);
    rv->uid = uid;
    rv->auth = read_xauth(uid, host, dsp);
    if(!rv->auth) {
      g_warning("can't parse auth data for host: %s", host);
      return NULL;
    }
    rv->connection = xcb_connect_to_display_with_auth_info(display, rv->auth, &screenNum);
    if(!rv->connection) {
      g_warning("can't connect to host: %s", host);
      return NULL;
    }

    setup = xcb_get_setup(rv->connection);
    
    if(!setup) {
      g_warning("can't get setup");
      free_x_server(rv);
      return NULL;
    }

    iter = xcb_setup_roots_iterator(setup);  

    // we want the screen at index screenNum of the iterator
    for (i = 0; i < screenNum; ++i) {
        xcb_screen_next (&iter);
    }

    rv->screen = iter.data;


    g_debug("connected to X11 host: %s display: %d screen: %d \n", localhost, dsp, screenNum);

    // fillup the x server atoms
    xcb_intern_atom_cookie_t net_active_ck
        = intern_string (rv->connection, "_NET_ACTIVE_WINDOW");

    xcb_intern_atom_cookie_t net_pid_ck
        = intern_string (rv->connection, "_NET_WM_PID");

    xcb_intern_atom_cookie_t net_client_ck
        = intern_string (rv->connection, "WM_CLIENT_MACHINE");

    rv->atom_active = get_atom (rv->connection, net_active_ck);
    rv->atom_pid = get_atom (rv->connection, net_pid_ck);
    rv->atom_client = get_atom (rv->connection, net_client_ck);


    xcb_intern_atom_cookie_t window_ck
            = intern_string (rv->connection, "WINDOW");

    xcb_intern_atom_cookie_t cardinal_ck
            = intern_string (rv->connection, "CARDINAL");

    xcb_intern_atom_cookie_t string_ck
            = intern_string (rv->connection, "STRING");

    rv->window_atom = get_atom (rv->connection, window_ck);
    rv->cardinal_atom = get_atom (rv->connection, cardinal_ck);
    rv->string_atom = get_atom (rv->connection, string_ck);

    return rv;
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

struct x_server *add_connection(uid_t uid, const char *display) {
  struct x_server *nc;
  GList *cur;

  while(TRUE) {
    cur = g_list_find_custom(server_list, display, match_display);
    if(!cur)
      break;
    free_x_server(cur->data);
    server_list = g_list_remove(server_list, cur->data);
  }

  nc = create_connection(uid, display);

  if(nc) {
    server_list = g_list_append(server_list, nc);
    return nc;
  }
  return NULL;
}

static int add_all_console_kit(int update) {
  GError *error;
  DBusGProxy *proxy, *cproxy = NULL;
  GPtrArray *array;
  int i;
  char *display;
  pid_t uid;
  GList *cur;
  
  g_type_init ();

  error = NULL;

  proxy = dbus_g_proxy_new_for_name           (U_dbus_connection,
                                               "org.freedesktop.ConsoleKit",
                                               "/org/freedesktop/ConsoleKit/Manager",
                                               "org.freedesktop.ConsoleKit.Manager");
  error = NULL;
  if (!dbus_g_proxy_call (proxy, "GetSessions", &error, G_TYPE_INVALID,
                          dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
                          &array, G_TYPE_INVALID))
    {
      g_warning("Error: %s\n", error->message);
      goto error;
    }


  for (i = 0; i < array->len; i++) {
      error = NULL;
      cproxy = dbus_g_proxy_new_for_name(U_dbus_connection,
                                         "org.freedesktop.ConsoleKit",
                                         g_ptr_array_index(array, i),
                                         "org.freedesktop.ConsoleKit.Session");
      if (!dbus_g_proxy_call (cproxy, "GetUser", &error, G_TYPE_INVALID,
                              G_TYPE_UINT,
                              &uid, G_TYPE_INVALID)) {
          g_warning ("Error: %s\n", error->message);
          goto error;
      }
      if (!dbus_g_proxy_call (cproxy, "GetX11Display", &error, G_TYPE_INVALID,
                              G_TYPE_STRING,
                              &display, G_TYPE_INVALID)) {
          g_warning ("Error: %s\n", error->message);
          goto error;
      }

      if(strcmp(display, "")) {
        if(!update) {
            g_debug("found X11 display %s (uid: %d)", display, uid);
            add_connection(uid, display);
        } else {
            cur = g_list_find_custom(server_list, display, match_display);
            if(!cur)
                add_connection(uid, display);
        }
      }
      g_free(display);
      g_object_unref (cproxy);
  }
  g_ptr_array_free(array, TRUE);
  g_object_unref (proxy);
  return 0;

error:
  if(error)
    g_error_free (error);
  if(cproxy)
    g_object_unref(cproxy);
  g_object_unref (proxy);
  return 1;
}


pid_t read_pid(struct x_server *conn) {
    xcb_generic_error_t *error;

    //printf("conn: %p : %p\n", conn, conn->connection);

    xcb_get_property_cookie_t naw =
      xcb_get_property (conn->connection,
                        0,
                        conn->screen->root,
                        conn->atom_active,
                        conn->window_atom,
                        0,
                        1);
    xcb_get_property_reply_t *rep =
      xcb_get_property_reply (conn->connection,
                            naw,
                            &error);

    if(!rep || !xcb_get_property_value_length(rep))
      return 0;

    //printf("len: %d", xcb_get_property_value_length (rep));
    uint32_t *win = xcb_get_property_value(rep);
    //printf("win: %p\n", *win);

    xcb_get_property_cookie_t caw =
      xcb_get_property (conn->connection,
                      0,
                      *win,
                      conn->atom_pid,
                      conn->cardinal_atom,
                      0,
                      1);
    xcb_get_property_reply_t *rep2 =
      xcb_get_property_reply (conn->connection,
                          caw,
                          &error);

    if(error && error->response_type == 0)
      goto error;

    if(!rep2 || !xcb_get_property_value_length(rep2))
      return 0;

    //printf("len: %d", xcb_get_property_value_length (rep2));
    uint32_t *pid = xcb_get_property_value(rep2);
    //printf("pid: %d\n", *pid);

    xcb_get_property_cookie_t ccaw =
      xcb_get_property (conn->connection,
                    0,
                    *win,
                    conn->atom_client,
                    conn->string_atom,
                    0,
                    strlen(localhost));
    xcb_get_property_reply_t *rep3 =
      xcb_get_property_reply (conn->connection,
                          ccaw,
                          &error);

    if(error && error->response_type == 0)
      goto error;

    if(!rep3 || !xcb_get_property_value_length(rep3))
      return 0;

    //printf("%d: %d \n", rep3->value_len, rep3->bytes_after);

    char *client =  xcb_get_property_value(rep3);
    //printf("client: %d %s\n", xcb_get_property_value_length(rep3), client);
    if(client && !strcmp(client, localhost)) {
      return *pid;
    }
    return 0;
error:
    // error in connection. free x_server connection
    printf("error: %d %d\n", error->response_type, error->error_code);
    del_connection(conn);
    return 1;
}



static gboolean update_all_server(gpointer data) {
#ifndef TEST_XWATCH
  static int run = 0;
  GList *cur;
  pid_t pid;
  int i;

  if(run == 60) {
    run = 0;
    add_all_console_kit(TRUE);
  }
  // we have to use for loop here, because read_pid removes connection
  // on hard errors
  for(i = 0; i < g_list_length(server_list); i++) {
    cur = g_list_nth(server_list, i);
    struct x_server *xs = cur->data;
    pid = read_pid(xs);
    if(pid) {
      //printf ("current uid: %d pid: %d\n", xs->uid, pid);
      set_active_pid(xs->uid, pid);
    }
  }
  run++;
#endif
  return TRUE;
}

int xwatch_init() {
  localhost = get_localhost();
  g_message("x server observation active");
#ifndef TEST_XWATCH
  g_timeout_add_seconds(1, update_all_server, NULL);
#endif
  add_all_console_kit(FALSE);
  return 0;
}

