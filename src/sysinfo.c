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

#include "config.h"
#include "ulatency.h"
#include <glib.h>
#include <string.h>


GList *U_session_list;


/* adapted from consolekit */
GHashTable *
u_read_env_hash (pid_t pid)
{
    char       *path;
    gboolean    res;
    char       *contents;
    gsize       length;
    GError     *error;
    GHashTable *hash;
    int         i;
    gboolean    last_was_null;

    contents = NULL;
    hash = NULL;

    path = g_strdup_printf ("/proc/%u/environ", (guint)pid);

    error = NULL;
    res = g_file_get_contents (path,
                               &contents,
                               &length,
                               &error);
    if (! res) {
        //g_debug("Couldn't read %s: %s", path, error->message);
        g_error_free (error);
        goto out;
    }

    hash = g_hash_table_new_full (g_str_hash,
                                  g_str_equal,
                                  g_free,
                                  g_free);

    last_was_null = TRUE;
    for (i = 0; i < length; i++) {
        if (contents[i] == '\0') {
            last_was_null = TRUE;
            continue;
        }
        if (last_was_null) {
            char **vals;
            vals = g_strsplit (contents + i, "=", 2);
            if (vals != NULL) {
                g_hash_table_insert (hash,
                                     g_strdup (vals[0]),
                                     g_strdup (vals[1]));
                g_strfreev (vals);
            }
        }
        last_was_null = FALSE;
    }

out:
    g_free (contents);
    g_free (path);

    return hash;
}

char *
u_pid_get_env (pid_t       pid,
               const char *var)
{
    char      *path;
    gboolean   res;
    char      *contents;
    char      *val;
    gsize      length;
    GError    *error;
    int        i;
    char      *prefix;
    int        prefix_len;
    gboolean   last_was_null;

    val = NULL;
    contents = NULL;
    prefix = NULL;

    path = g_strdup_printf ("/proc/%u/environ", (guint)pid);

    error = NULL;
    res = g_file_get_contents (path,
                               &contents,
                               &length,
                               &error);
    if (! res) {
        //g_debug ("Couldn't read %s: %s", path, error->message);
        g_error_free (error);
        goto out;
    }


    prefix = g_strdup_printf ("%s=", var);
    prefix_len = strlen(prefix);

    /* FIXME: make more robust */
    last_was_null = TRUE;
    for (i = 0; i < length; i++) {
        if (contents[i] == '\0') {
                last_was_null = TRUE;
                continue;
        }
        if (last_was_null && g_str_has_prefix (contents + i, prefix)) {
                val = g_strdup (contents + i + prefix_len);
                break;
        }
        last_was_null = FALSE;
    }

out:
    g_free (prefix);
    g_free (contents);
    g_free (path);

    return val;
}



GPtrArray *
u_read_0file (pid_t pid, const char *what)
{
    char       *path;
    gboolean    res;
    char       *contents;
    gsize       length;
    GError     *error;
    GPtrArray  *rv = NULL;
    int         i;
    gboolean    last_was_null;

    contents = NULL;

    path = g_strdup_printf ("/proc/%u/%s", (guint)pid, what);

    error = NULL;
    res = g_file_get_contents (path,
                               &contents,
                               &length,
                               &error);
    if (! res) {
        //g_debug ("Couldn't read %s: %s", path, error->message);
        g_error_free (error);
        goto out;
    }

    rv = g_ptr_array_new_with_free_func(g_free);

    last_was_null = TRUE;
    for (i = 0; i < length; i++) {
        if (contents[i] == '\0') {
            last_was_null = TRUE;
            continue;
        }
        if (last_was_null) {
            g_ptr_array_add(rv, g_strdup(contents + i));
        }
        last_was_null = FALSE;
    }

out:
    g_free (contents);
    g_free (path);

    return rv;
}

GPtrArray* search_user_env(uid_t uid, const char *name, int update) {
    GPtrArray* rv = g_ptr_array_new_with_free_func(g_free);
    u_proc *proc = NULL;
    GHashTableIter iter;
    char *val;
    int i, found;

    gpointer ikey, value;

    g_hash_table_iter_init (&iter, processes);
    while (g_hash_table_iter_next (&iter, &ikey, &value)) 
    {
        proc = (u_proc *)value;
        if(proc->proc.euid != uid)
            continue;

        u_proc_ensure(proc, ENVIRONMENT, update);

        if(!proc->environ)
            continue;

        val = g_hash_table_lookup(proc->environ, name);
        if(val) {
            found = FALSE;
            for(i = 0; i < rv->len; i++) {
                if(g_strcmp0((char *)g_ptr_array_index(rv, i), val) == 0) {
                    found = TRUE;
                    break;
                }
            }
            if(!found)
                 g_ptr_array_add(rv, g_strdup(val));

        }
    }
    return rv;
}

#ifdef ENABLE_DBUS

// things would be so much easier here when consolekit would just emit a 
// SessionAdded/SessionRemoved in the manager, we so don't care about seats...

static DBusGProxy *ck_manager_proxy = NULL;

struct ck_seat {
  DBusGProxy *proxy;
  char *name;
};

// list of current seats
static GList *ck_seats = NULL;

gint match_session(gconstpointer a, gconstpointer b) {
  const u_session *sa = a;
  return g_strcmp0(sa->name, (const char *)b);
}

// updates the idle hint of a session
static void session_idle_hint_changed(DBusGProxy *proxy, gboolean hint, u_session *sess) {
  g_debug("CK: idle changed %s -> %d", sess->name, hint);
  sess->idle = hint;
}

static void session_active_changed(DBusGProxy *proxy, gboolean active, u_session *sess) {
  g_debug("CK: active changed %s -> %d", sess->name, active);
  sess->active = active;
}

static void ck_session_added(DBusGProxy *proxy, gchar *name, gpointer ignored) {
    GError *error = NULL;
    u_session *sess = g_malloc0(sizeof(u_session));
    g_message("CK: Session added %s", name);

    sess->proxy = dbus_g_proxy_new_for_name_owner(U_dbus_connection_system,
                                                "org.freedesktop.ConsoleKit",
                                                name,
                                                "org.freedesktop.ConsoleKit.Session",
                                                &error);
    if(error) {
        g_warning ("CK Error: %s\n", error->message);
        g_free(name);
        g_free(sess);
        g_error_free(error);
        return;
    }

    sess->name = g_strdup(name);
    U_session_list = g_list_append(U_session_list, sess);
    // connect to signals
    dbus_g_proxy_add_signal (sess->proxy, "IdleHintChanged",
                             G_TYPE_BOOLEAN, G_TYPE_INVALID);
    dbus_g_proxy_connect_signal(sess->proxy,
                                "IdleHintChanged",
                                G_CALLBACK(session_idle_hint_changed),
                                sess,
                                NULL);
    dbus_g_proxy_add_signal (sess->proxy, "ActiveChanged",
                             G_TYPE_BOOLEAN, G_TYPE_INVALID);
    dbus_g_proxy_connect_signal(sess->proxy,
                                "ActiveChanged",
                                G_CALLBACK(session_active_changed),
                                sess,
                                NULL);

    if(!dbus_g_proxy_call (sess->proxy, "GetIdleHint", &error, G_TYPE_INVALID,
                            G_TYPE_BOOLEAN,
                            &sess->idle, G_TYPE_INVALID)) {
        g_warning ("CK Error: %s\n", error->message);
        g_error_free(error);
    }
    if(!dbus_g_proxy_call (sess->proxy, "IsActive", &error, G_TYPE_INVALID,
                            G_TYPE_BOOLEAN,
                            &sess->active, G_TYPE_INVALID)) {
        g_warning ("CK Error: %s\n", error->message);
        g_error_free(error);
    }
    if (!dbus_g_proxy_call (sess->proxy, "GetUnixUser", &error, G_TYPE_INVALID,
                            G_TYPE_UINT,
                            &sess->uid, G_TYPE_INVALID)) {
      g_warning ("CK Error: %s\n", error->message);
      g_error_free(error);
    }
    if (!dbus_g_proxy_call (sess->proxy, "GetX11Display", &error, G_TYPE_INVALID,
                            G_TYPE_STRING,
                            &sess->X11Display, G_TYPE_INVALID)) {
      g_warning ("CK Error: %s\n", error->message);
      g_error_free(error);
    }
    if (!dbus_g_proxy_call (sess->proxy, "GetX11Display", &error, G_TYPE_INVALID,
                            G_TYPE_STRING,
                            &sess->X11Device, G_TYPE_INVALID)) {
      g_warning ("CK Error: %s\n", error->message);
      g_error_free(error);
    }

}

static void ck_session_removed(DBusGProxy *proxy, gchar *name, gpointer ignored) {
    u_session *sess = NULL;
    GList *cur = U_session_list;
    g_message("CK: Session removed %s", name);
    while(cur) {
      sess = cur->data;
      if(g_strcmp0(name, sess->name) == 0) {
        g_object_unref(sess->proxy);
        g_free(sess->name);
        g_free(sess->X11Display);
        g_free(sess->X11Device);
        g_free(sess->dbus_session);

        U_session_list = g_list_remove(U_session_list, sess);
        break;
      }
      cur = g_list_next(cur);
    }
}


static void ck_seat_added(DBusGProxy *proxy, gchar *name, gpointer ignored) {
    GError *error = NULL;
    g_debug("CK: Seat added %s", name);
    struct ck_seat *seat = g_malloc0(sizeof(struct ck_seat));
    seat->proxy = dbus_g_proxy_new_for_name_owner(U_dbus_connection_system,
                                            "org.freedesktop.ConsoleKit",
                                            name,
                                            "org.freedesktop.ConsoleKit.Seat",
                                            &error);
    if(error) {
        g_warning ("CK Error: %s\n", error->message);
        g_free(name);
        g_free(seat);
        g_error_free(error);
        return;
    }
    seat->name = name;
    ck_seats = g_list_append(ck_seats, seat);

    dbus_g_proxy_add_signal (seat->proxy, "SessionAdded",
                             DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
    dbus_g_proxy_connect_signal(seat->proxy,
                                "SessionAdded",
                                G_CALLBACK(ck_session_added),
                                NULL,
                                NULL);
    dbus_g_proxy_add_signal (seat->proxy, "SessionRemoved",
                             DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
    dbus_g_proxy_connect_signal(seat->proxy,
                                "SessionRemoved",
                                G_CALLBACK(ck_session_removed),
                                NULL,
                                NULL);

}

static void ck_seat_removed(DBusGProxy *proxy, gchar *name, gpointer ignored) {
    struct ck_seat *seat = NULL;
    g_debug("CK: Seat removed %s", name);
    GList *cur = ck_seats;
    while(cur) {
      seat = cur->data;
      if(g_strcmp0(name, seat->name) == 0) {
        g_object_unref(seat->proxy);
        g_free(seat->name);
        ck_seats = g_list_remove(ck_seats, seat);
        break;
      }
      cur = g_list_next(cur);
    }
}

void consolekit_init() {
    GPtrArray *array;
    GError *error = NULL;
    int i;

    if(!U_dbus_connection_system)
      return;

    // cleanup first. the dbus connection could be new
    struct ck_seat *seat = NULL;
    GList *cur = ck_seats;

    if(ck_manager_proxy)
      g_object_unref (ck_manager_proxy);

    while(cur) {
      seat = cur->data;
      g_object_unref(seat->proxy);
      g_free(seat->name);
      cur = g_list_next(cur);
    }
    g_list_free(ck_seats);

    while(U_session_list) {
      u_session *sess= U_session_list->data;
      ck_session_removed(NULL, sess->name, NULL);
    }

    ck_manager_proxy = dbus_g_proxy_new_for_name_owner(U_dbus_connection_system,
                                      "org.freedesktop.ConsoleKit",
                                      "/org/freedesktop/ConsoleKit/Manager",
                                      "org.freedesktop.ConsoleKit.Manager",
                                      &error);
    if(error) {
        g_warning ("CK Error: %s\n", error->message);
        g_error_free(error);
        return;
    }

    dbus_g_proxy_add_signal (ck_manager_proxy, "SeatAdded",
                             G_TYPE_STRING, G_TYPE_INVALID);

    dbus_g_proxy_connect_signal(ck_manager_proxy,
                                "SeatAdded",
                                G_CALLBACK(ck_seat_added),
                                NULL,
                                NULL);

    dbus_g_proxy_add_signal (ck_manager_proxy, "SeatRemoved",
                             G_TYPE_STRING, G_TYPE_INVALID);

    dbus_g_proxy_connect_signal(ck_manager_proxy,
                                "SeatRemoved",
                                G_CALLBACK(ck_seat_removed),
                                NULL,
                                NULL);

    if (!dbus_g_proxy_call (ck_manager_proxy, "GetSeats", &error, G_TYPE_INVALID,
                          dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
                          &array, G_TYPE_INVALID)) {
        g_warning("CK Error: %s\n", error->message);
        g_error_free(error);
    }
    for (i = 0; i < array->len; i++) {
        error = NULL;
        ck_seat_added(NULL, g_ptr_array_index(array, i), NULL);
    }
    g_ptr_array_free(array, TRUE);
    if (!dbus_g_proxy_call (ck_manager_proxy, "GetSessions", &error, G_TYPE_INVALID,
                          dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
                          &array, G_TYPE_INVALID)) {
        g_warning("CK Error: %s\n", error->message);
        g_error_free(error);
    }
    for (i = 0; i < array->len; i++) {
        error = NULL;
        ck_session_added(NULL, g_ptr_array_index(array, i), NULL);
    }
    g_ptr_array_free(array, TRUE);
}

#endif