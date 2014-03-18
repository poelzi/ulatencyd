/*
    Copyright 2010,2011,2012,2013 ulatencyd developers

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

#define _GNU_SOURCE
#define  MODULE_NAME "consolekit"

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN MODULE_NAME
#endif

#include "config.h"

#include "usession-agent.h"
#include "uhook.h"
#include "ulatency.h"

#include <glib.h>
#include <string.h>
#include <gmodule.h>

static gboolean     module_debug = TRUE;

#define m_debug(...)    if (module_debug) g_debug (__VA_ARGS__)

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

// updates the idle hint of a session
static void session_idle_hint_changed (DBusGProxy *proxy, gboolean hint, USession *sess)
{
  m_debug ("IdleHintChanged signal for %s -> %s",
            sess->name, hint ? "TRUE" : "FALSE");
  u_session_idle_hint_changed (sess, hint);
}

static void session_active_changed(DBusGProxy *proxy, gboolean active, USession *sess) {
  m_debug ("ActiveChanged signal for %s -> %s",
            sess->name, active ? "TRUE" : "FALSE");
  u_session_active_changed (sess, active);
}

static USession *
register_session (const gchar *name)
{
  GError *error = NULL;
  USession *sess;

  sess = u_session_new ();

  sess->name = g_strdup (name);
  sess->proxy = dbus_g_proxy_new_for_name_owner(U_dbus_connection_system,
                                              "org.freedesktop.ConsoleKit",
                                              sess->name,
                                              "org.freedesktop.ConsoleKit.Session",
                                              &error);
  if(error) {
      g_warning ("CK error: %s\n", error->message);
      g_warning ("CK session %s won't be tracked.", sess->name);
      g_error_free(error);
      DEC_REF (sess);
      g_assert (sess == NULL);
      return NULL;
  }

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
        g_warning ("CK error: %s\n", error->message);
        g_error_free(error);
        error = NULL;
  }
  if(!dbus_g_proxy_call (sess->proxy, "IsActive", &error, G_TYPE_INVALID,
                          G_TYPE_BOOLEAN,
                          &sess->active, G_TYPE_INVALID)) {
        g_warning ("CK error: %s\n", error->message);
        g_error_free(error);
        error = NULL;
  }
  if (!dbus_g_proxy_call (sess->proxy, "GetUnixUser", &error, G_TYPE_INVALID,
                          G_TYPE_UINT,
                          &sess->uid, G_TYPE_INVALID)) {
        g_warning ("CK error: %s\n", error->message);
        g_error_free(error);
        error = NULL;
  }
  if (!dbus_g_proxy_call (sess->proxy, "GetSessionType", &error, G_TYPE_INVALID,
                          G_TYPE_STRING,
                          &sess->session_type, G_TYPE_INVALID)) {
        g_warning ("CK error: %s\n", error->message);
        g_error_free(error);
        error = NULL;
  }
  if (!dbus_g_proxy_call (sess->proxy, "GetX11Display", &error, G_TYPE_INVALID,
                          G_TYPE_STRING,
                          &sess->X11Display, G_TYPE_INVALID)) {
        g_warning ("CK error: %s\n", error->message);
        g_error_free(error);
        error = NULL;
  }
  if (!dbus_g_proxy_call (sess->proxy, "GetX11DisplayDevice", &error, G_TYPE_INVALID,
                          G_TYPE_STRING,
                          &sess->X11Device, G_TYPE_INVALID)) {
        g_warning ("CK error: %s\n", error->message);
        g_error_free(error);
        error = NULL;
  }

  if (u_session_add (sess))
    {
      DEC_REF (sess);
      g_assert (sess != NULL);
    }
  else
    {
      DEC_REF (sess);
      g_assert (sess == NULL);
    }

  return sess;
}

static void ck_session_added(DBusGProxy *proxy, const gchar *name, gpointer ignored) {
    m_debug ("SessionAdded signal for %s", name);

    if (u_session_find_by_name (name))
      {
        m_debug ("Session already registered.");
        return;
      }

    register_session (name);
}

static void ck_session_removed(DBusGProxy *proxy, const gchar *name, gpointer ignored) {
    m_debug ("SessionRemoved signal for %s", name);
    u_session_remove_by_name (name);
}


static void ck_seat_added(DBusGProxy *proxy, const gchar *name, gpointer ignored) {
    GError *error = NULL;
    m_debug("Seat added %s", name);
    struct ck_seat *seat = g_malloc0(sizeof(struct ck_seat));
    seat->proxy = dbus_g_proxy_new_for_name_owner(U_dbus_connection_system,
                                            "org.freedesktop.ConsoleKit",
                                            name,
                                            "org.freedesktop.ConsoleKit.Seat",
                                            &error);
    if(error) {
        g_warning ("CK error: %s\n", error->message);
        g_warning ("Unable to bind to the seat %s. "
                   "No session of it will be tracked.", name);
        g_free(seat);
        g_error_free(error);
        return;
    }
    seat->name = g_strdup(name);
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

static void ck_seat_removed(DBusGProxy *proxy, const gchar *name, gpointer ignored) {
    struct ck_seat *seat = NULL;
    m_debug("Seat removed %s", name);
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

/*
 * FIXME (optimization)
 * store consolekit cookie in hash table private for consolekit.c module;
 * not as field in u_proc.
 */
static USession*
get_session_for_cookie (const gchar *consolekit_cookie, gboolean *retry)
{
  GError *error = NULL;
  gchar *consolekit_session;
  USession *sess;

  sess = U_sessions;
  while (sess)
    {
      if(g_strcmp0(consolekit_cookie, sess->consolekit_cookie) == 0)
        return sess;
      sess = sess->next;
    }

  if(!U_dbus_connection_system)
    return NULL;

  if (!ck_manager_proxy)
    return NULL;

  if (!dbus_g_proxy_call (ck_manager_proxy, "GetSessionForCookie", &error,
                         G_TYPE_STRING, consolekit_cookie,
                         G_TYPE_INVALID,
                         DBUS_TYPE_G_OBJECT_PATH, &consolekit_session,
                         G_TYPE_INVALID))
    {
      g_warning ("CK GetSessionForCookie('%s'): %s",
                 consolekit_cookie, error->message);
      if (retry != NULL)
        {
          switch (error->code) {
            case DBUS_GERROR_IO_ERROR:
            case DBUS_GERROR_LIMITS_EXCEEDED:
            case DBUS_GERROR_NO_MEMORY:
            case DBUS_GERROR_NO_REPLY:
            case DBUS_GERROR_SPAWN_CHILD_SIGNALED:
            case DBUS_GERROR_SPAWN_EXEC_FAILED:
            case DBUS_GERROR_SPAWN_FAILED:
            case DBUS_GERROR_SPAWN_FORK_FAILED:
            case DBUS_GERROR_TIMED_OUT:
            case DBUS_GERROR_TIMEOUT:
              *retry = TRUE;
              break;

            default:
              *retry = FALSE;
          }
        }
      g_error_free (error);
      return NULL;
    }

  sess = u_session_find_by_name (consolekit_session);
  if (!sess)
    {
      sess = register_session (consolekit_session);
      if (sess)
        {
          m_debug ("session preallocated (id=%d: name=%s)",
                   sess->id, consolekit_session);
        }
      else
        {
          g_free (consolekit_session);
          return NULL;
        }
    }

  sess->consolekit_cookie = g_strdup(consolekit_cookie);
  g_free(consolekit_session);

  return sess;
}

guint
consolekit_u_proc_get_session_id (u_proc *proc)
{
  GHashTable *environ;
  char       *consolekit_cookie;
  guint      retval;

  if (!u_proc_ensure (proc, ENVIRONMENT, UPDATE_ONCE_PER_RUN))
      return USESSION_UNKNOWN;  /* no environment */

  environ = g_hash_table_ref (proc->environ);
  consolekit_cookie = g_hash_table_lookup (environ, "XDG_SESSION_COOKIE");
  if (consolekit_cookie)
    {
      USession *sess = NULL;
      gboolean retry = FALSE;

      sess = get_session_for_cookie (consolekit_cookie, &retry);
      if (sess)
        {
          retval = sess->id;
        }
      else /* probably unable to find session for cookie */
        {
          g_warning ("Unable to get CK session for pid %d despite cookie exists (%s error)",
                     proc->pid, retry ? "temporal" : "permanent");
          retval = retry ? USESSION_UNKNOWN : USESSION_USER_UNKNOWN;
        }
    }
  else /* no consolekit_cookie */
    {
      retval = USESSION_NONE;
    }

  g_hash_table_unref (environ);
  return retval;
}

static gboolean //UHookFunc
bind_to_ck (gpointer ignored)
{
  GPtrArray *array = NULL;
  GError    *error = NULL;
  int       i;

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
      ck_session_added(NULL, g_ptr_array_index(array, i), NULL);
  }
  g_ptr_array_free(array, TRUE);

  return FALSE; // remove from hook list
}

G_MODULE_EXPORT const gchar*
g_module_check_init (GModule *module)
{
    USessionAgent *agent;
    gboolean       registered;
    GError        *error = NULL;

    g_assert (ck_seats == NULL);
    g_assert (ck_manager_proxy == NULL);

    if (!U_dbus_connection_system)
      return "No DBUS connection";

    ck_manager_proxy = dbus_g_proxy_new_for_name_owner(U_dbus_connection_system,
                                      "org.freedesktop.ConsoleKit",
                                      "/org/freedesktop/ConsoleKit/Manager",
                                      "org.freedesktop.ConsoleKit.Manager",
                                      &error);
    if(error) {
        g_warning ("CK error: %s\n", error->message);
        g_error_free(error);
        return "No ConsoleKit.";
    }

    /* register to USession */

    agent = g_new0 (USessionAgent, 1);
    agent->name = MODULE_NAME;
    agent->u_proc_get_session_id_func = consolekit_u_proc_get_session_id;
    agent->session_get_leader_pid_func = NULL;

    registered = u_session_agent_register (agent);

    g_free (agent);

    if (!registered)
      {
        g_object_unref (ck_manager_proxy);
        u_module_close_me (module);
        return "Unable to register agent.";
      }

    module_debug = g_key_file_get_boolean (config_data, "consolekit",
                                          "debug", NULL);

    g_module_make_resident (module);

    /*
     * Give other modules opportunity to register hooks to a sessions related
     * changes; otherwise, should they be focus tracking agents loaded before
     * this module, they will miss initial sessions.
     */
    u_hook_add (U_HOOK_TYPE_ALL_MODULES_LOADED, MODULE_NAME, bind_to_ck);

    return NULL;
}



#else /* ENABLE_DBUS */

G_MODULE_EXPORT const gchar*
g_module_check_init (GModule *module)
{
  return "Compiled without DBUS support."
}

#endif /* ENABLE_DBUS */

#undef m_debug
