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
#include "usession.h"
#include "ufocusstack.h"

#include <stdint.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib-bindings.h>
#include <dbus/dbus-protocol.h>

/* --- definitions --- */

//char INTRO[] = {
//#include "myfile.txt"
//}
#define INTROSPECT \
"    <interface name=\"org.freedesktop.DBus.Properties\">\n" \
"       <method name=\"Get\">\n" \
"          <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n" \
"          <arg name=\"property\" direction=\"in\" type=\"s\"/>\n" \
"          <arg name=\"value\" direction=\"out\" type=\"v\"/>\n" \
"       </method>\n" \
"       <method name=\"Set\">\n" \
"          <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n" \
"          <arg name=\"property\" direction=\"in\" type=\"s\"/>\n" \
"          <arg name=\"value\" direction=\"in\" type=\"v\"/>\n" \
"       </method>\n" \
"    </interface>\n" \
"    <interface name=\"org.freedesktop.DBus.Introspectable\">\n" \
"       <method name=\"Introspect\">\n" \
"          <arg name=\"data\" type=\"s\" direction=\"out\"/>\n" \
"       </method>\n" \
"    </interface>\n"

const char *INTROSPECT_XML_USER =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
    "<node name=\"" U_DBUS_USER_PATH "\">\n"
    "  <interface name=\"" U_DBUS_USER_INTERFACE "\">\n"
    "    <method name=\"setFocusedPid\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "      <arg type=\"t\" name=\"timestamp\" direction=\"in\" />\n"
    "    </method>\n"
    "    <method name=\"getFocusStackLength\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "      <arg type=\"q\" name=\"length\" direction=\"out\" />\n"
    "    </method>\n"
    "    <method name=\"setFocusStackLength\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "      <arg type=\"q\" name=\"length\" direction=\"in\" />\n"
    "    </method>\n"
//"    <method name=\"wishGroup\">\n"
//"      <arg type=\"i\" name=\"pid\" direction=\"in\" />\n"
//"      <arg type=\"i\" name=\"priority\" direction=\"in\" />\n"
//"    </method>\n"
    "  </interface>\n"
    INTROSPECT
    "</node>\n";

const char *INTROSPECT_XML_SYSTEM =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
    "<node name=\"" U_DBUS_SYSTEM_PATH "\">\n"
    "  <interface name=\"" U_DBUS_SYSTEM_INTERFACE "\">\n"
    "    <method name=\"setSchedulerConfig\">\n"
    "      <arg type=\"s\" name=\"name\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"success\" direction=\"out\" />\n"
    "    </method>\n"
    "    <method name=\"listSchedulerConfigs\">\n"
    "      <arg type=\"as\" name=\"names\" direction=\"out\" />\n"
    "    </method>\n"
    "    <method name=\"getSchedulerConfigDescription\">\n"
    "      <arg type=\"s\" name=\"name\" direction=\"in\" />\n"
    "      <arg type=\"s\" name=\"description\" direction=\"out\" />\n"
    "    </method>\n"
    "    <method name=\"listSystemFlags\">\n"
    "      <arg type=\"aa{sv}\" direction=\"out\" />\n"
    "    </method>\n"
    "    <method name=\"addFlag\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "      <arg type=\"t\" name=\"tid\" direction=\"in\" />\n"
    "      <arg type=\"s\" name=\"name\" direction=\"in\" />\n"
    "      <arg type=\"s\" name=\"reason\" direction=\"in\" />\n"
    "      <arg type=\"t\" name=\"timeout\" direction=\"in\" />\n"
    "      <arg type=\"i\" name=\"priority\" direction=\"in\" />\n"
    "      <arg type=\"x\" name=\"value\" direction=\"in\" />\n"
    "      <arg type=\"x\" name=\"threshold\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"inherit\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"urgent\" direction=\"in\" />\n"
    "    </method>\n"
    "    <method name=\"addSystemFlag\">\n"
    "      <arg type=\"s\" name=\"name\" direction=\"in\" />\n"
    "      <arg type=\"s\" name=\"reason\" direction=\"in\" />\n"
    "      <arg type=\"t\" name=\"timeout\" direction=\"in\" />\n"
    "      <arg type=\"i\" name=\"priority\" direction=\"in\" />\n"
    "      <arg type=\"x\" name=\"value\" direction=\"in\" />\n"
    "      <arg type=\"x\" name=\"threshold\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"urgent\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"run_iteration\" direction=\"in\" />\n"
    "    </method>\n"
    "    <method name=\"listFlags\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"recrusive\" direction=\"in\" />\n"
    "      <arg type=\"a(ta{sv})\" name=\"flags\" direction=\"out\" />\n"
    "    </method>\n"
    "    <method name=\"delFlag\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "      <arg type=\"t\" name=\"id\" direction=\"in\" />\n"
    "    </method>\n"
    "    <method name=\"clearFlags\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "    </method>\n"
    "    <method name=\"scheduleTask\">\n"
    "      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"update\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"success\" direction=\"out\" />\n"
    "    </method>\n"
    "    <method name=\"cgroupsCleanup\">\n"
    "      <arg type=\"b\" name=\"instant\" direction=\"in\" />\n"
    "      <arg type=\"b\" name=\"scheduled\" direction=\"out\" />\n"
    "    </method>\n"
    "    <property name=\"config\" type=\"s\" access=\"read\"/>\n"
    "    <property name=\"version\" type=\"s\" access=\"read\"/>\n"
    "  </interface>\n"
    INTROSPECT
    "</node>\n";

// pointer for flags as source
const void *U_DBUS_POINTER = &INTROSPECT_XML_SYSTEM;

#define U_DBUS_ERROR_NO_PID "org.quamquam.ulatency.DBus.Error.PidNotFound"

#define GET_CALLER() \
  do {                                                                        \
    caller = dbus_bus_get_unix_user (c, dbus_message_get_sender(m), &error);  \
    if (caller == (unsigned long) -1)                                         \
      {                                                                       \
        g_warning ("dbus_message_get_unix_user() failed: %s\n",               \
                   error.message);                                            \
        ret = dbus_message_new_error (m, DBUS_ERROR_ACCESS_DENIED,            \
                                      "not a local connection");              \
        goto finish;                                                          \
      }                                                                       \
  } while (0)

#define PUSH_ERROR(ID, MSG) \
  do {                                                                        \
    if (ret)                                                                  \
      dbus_message_unref (ret);                                               \
    if (error.name)                                                           \
      ret = dbus_message_new_error (m, error.name, error.message);            \
    else {                                                                    \
      ret = dbus_message_new_error (m, ID, #MSG);                             \
      goto finish;                                                            \
    }                                                                         \
  } while (0)

#define CHECK_PROC_FROM_PID(PROC, PID) \
  do { \
    PROC = proc_by_pid_with_retry (PID); \
    if (!PROC \
        || U_PROC_HAS_STATE (PROC, UPROC_DEAD) \
        || !u_proc_ensure (PROC, BASIC, UPDATE_ONCE)) \
      { \
        ret = dbus_message_new_error (m, \
                                      U_DBUS_ERROR_NO_PID, \
                                      "PID not found."); \
        goto finish; \
      } \
  } while (0)

#define CHECK_SESSION_FROM_PROC(SESSION, PROC) \
  do { \
    SESSION = u_session_find_by_proc (PROC); \
    if (!SESSION || !SESSION->is_valid) \
      { \
        ret = dbus_message_new_error (m, DBUS_ERROR_FAILED, \
                                      "PID not in session."); \
        goto finish; \
      } \
  } while(0)

#define CHECK_IF_SESSION_ALLOWED_FOR_UID(SESSION, UID) \
  do { \
    if (UID != 0 && UID != SESSION->uid) \
      { /* FIXME: check if sender is in the same session as the process */ \
        ret = dbus_message_new_error (m, DBUS_ERROR_ACCESS_DENIED, \
                               "not allowed to set focus of foreign users"); \
        goto finish; \
      } \
  } while (0)

/* --- functions --- */

static DBusHandlerResult
dbus_user_handler (DBusConnection *c,
                   DBusMessage    *m,
                   void           *userdata)
{
  DBusError    error;
  DBusMessage *ret = NULL;
  uid_t        caller;

  dbus_error_init (&error);

  if (dbus_message_is_method_call (m, U_DBUS_USER_INTERFACE, "setFocusedPid")) {
      pid_t     pid;
      uint64_t  tmpp;
      time_t    timestamp;
      uint64_t  tmpt;

      u_proc   *proc;
      USession *session;

      GET_CALLER ();

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_UINT64, &tmpp,
                                  DBUS_TYPE_UINT64, &tmpt,
                                  DBUS_TYPE_INVALID))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }
      pid = (pid_t) tmpp;
      timestamp = (time_t) tmpt;

      CHECK_PROC_FROM_PID (proc, pid);
      CHECK_SESSION_FROM_PROC (session, proc);
      CHECK_IF_SESSION_ALLOWED_FOR_UID (session, (uid_t) caller);

      if (session->id < USESSION_USER_FIRST)
        {
          ret = dbus_message_new_error (m, DBUS_ERROR_FAILED,
                                        "PID not in user session");
          goto finish;
        }

      u_focus_stack_add_pid(session->focus_stack, pid, timestamp);
      ret = dbus_message_new_method_return (m);

      goto finish;

  }
  else if (dbus_message_is_method_call (m, U_DBUS_USER_INTERFACE,
                                          "getFocusStackLength")) {
      pid_t     pid;
      uint64_t  tpid;

      u_proc   *proc;
      USession *session;

      GET_CALLER ();

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_UINT64, &tpid,
                                  DBUS_TYPE_INVALID))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }
      pid = (pid_t) tpid;

      CHECK_PROC_FROM_PID (proc, pid);
      CHECK_SESSION_FROM_PROC (session, proc);
      CHECK_IF_SESSION_ALLOWED_FOR_UID (session, (uid_t) caller);


      ret = dbus_message_new_method_return (m);
      dbus_message_append_args (ret, DBUS_TYPE_UINT16,
                                &session->focus_stack->max_count,
                                DBUS_TYPE_INVALID);

      goto finish;

    }
  else if (dbus_message_is_method_call (m, U_DBUS_USER_INTERFACE,
                                          "setFocusStackLength")) {
      pid_t     pid;
      uint64_t  tpid;
      guint16   length;

      u_proc   *proc;
      USession *session;

      GET_CALLER ();

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_UINT64, &tpid,
                                  DBUS_TYPE_UINT16, &length,
                                  DBUS_TYPE_INVALID))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }
      pid = (pid_t) tpid;

      CHECK_PROC_FROM_PID (proc, pid);
      CHECK_SESSION_FROM_PROC (session, proc);
      CHECK_IF_SESSION_ALLOWED_FOR_UID (session, (uid_t) caller);

      u_focus_stack_set_length(session->focus_stack, length);

      ret = dbus_message_new_method_return (m);

      goto finish;

    }
  else if (dbus_message_is_method_call (m, DBUS_INTERFACE_PROPERTIES, "Get"))
    {
      const char *interface, *property;

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_STRING, &interface,
                                  DBUS_TYPE_STRING, &property,
                                  DBUS_TYPE_INVALID))
        {
          g_warning ("Failed to parse property get call: %s\n", error.message);
          ret = dbus_message_new_error (m, error.name, error.message);
          goto finish;
        }
    }
  else if (dbus_message_is_method_call (m, DBUS_INTERFACE_PROPERTIES, "Set"))
    {
      const char *interface, *property;
      DBusMessageIter imsg;

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_STRING, &interface,
                                  DBUS_TYPE_STRING, &property,
                                  DBUS_TYPE_INVALID)
          || !dbus_message_iter_init (m, &imsg))
        {
          g_warning ("Failed to parse property set call: %s\n", error.message);
          ret = dbus_message_new_error (m, error.name, error.message);
          goto finish;
        }

      dbus_message_iter_next (&imsg);
      dbus_message_iter_next (&imsg);

      if (g_strcmp0 (interface, U_DBUS_USER_INTERFACE) == 0)
        {
          /*
          struct user_active *ua;
          GET_CALLER ();
          ua = get_userlist (caller, TRUE);
          ret = dbus_message_new_method_return (m);

          // FIXME: Implement getFocusedStack in user interface
          if (g_strcmp0 (property, "activeList") == 0)
            {
              if (!dbus_message_iter_get_arg_type (&imsg) == DBUS_TYPE_UINT32)
                goto error;
              dbus_message_iter_get_basic (&imsg, &ua->max_processes);
              goto finish;
            }

          dbus_message_unref (ret);
          return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
          */
        }
      else
        {
          return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
    }
  else if (dbus_message_is_method_call (m, DBUS_INTERFACE_INTROSPECTABLE,
                                        "Introspect"))
    {
      ret = dbus_message_new_method_return (m);
      dbus_message_append_args (ret, DBUS_TYPE_STRING, &INTROSPECT_XML_USER,
                                DBUS_TYPE_INVALID);
      goto finish;
    }
  else
    {
      return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

finish:
  if (ret)
    {
      dbus_connection_send (c, ret, NULL);
      dbus_message_unref (ret);
    }

  dbus_error_free (&error);

  return DBUS_HANDLER_RESULT_HANDLED;
}

#define PUSH_VARIANT(NAME, VAR, TYPE) \
        do {                                                                  \
          name = #NAME ;                                                      \
          dbus_message_iter_open_container(&entry, DBUS_TYPE_DICT_ENTRY,      \
                                           NULL, &dict);                      \
          dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &name);     \
          dbus_message_iter_open_container(&dict, DBUS_TYPE_VARIANT,          \
                                           TYPE##_AS_STRING, &value);         \
          dbus_message_iter_append_basic(&value, TYPE, VAR);                  \
          dbus_message_iter_close_container(&dict, &value);                   \
          dbus_message_iter_close_container(&entry, &dict);                   \
        } while (0)

static void
push_flag (DBusMessage *ret,
           u_proc      *proc,
           int          recrusive)
{
  GList *cur, *lst;
  char *name = NULL;
  DBusMessageIter imsg, array, value, dict, entry;

  dbus_message_iter_init_append (ret, &imsg);

  if (proc)
    {
      lst = u_proc_list_flags (proc, recrusive);
      cur = lst;
      dbus_message_iter_open_container (&imsg, DBUS_TYPE_ARRAY, "(ta{sv})",
                                        &array);
    }
  else
    {
      cur = g_list_first (system_flags);
      dbus_message_iter_open_container (&imsg, DBUS_TYPE_ARRAY, "a{sv}",
                                        &array);
    }

  while (cur)
    {
      u_flag *fl = cur->data;
      uint64_t flp = (uint64_t) fl;
      uint64_t tid = (uint64_t) fl->tid;
      uint32_t tu32;
      DBusMessageIter strukt, entry;

      if (proc)
        {
          dbus_message_iter_open_container (&array, DBUS_TYPE_STRUCT, NULL,
                                            &strukt);

          dbus_message_iter_append_basic   (&strukt, DBUS_TYPE_UINT64, &flp);
          dbus_message_iter_open_container (&strukt, DBUS_TYPE_ARRAY, "{sv}",
                                            &entry);
        }
      else
        {
          dbus_message_iter_open_container (&array, DBUS_TYPE_ARRAY, "{sv}",
                                            &entry);
        }

      PUSH_VARIANT (name, &fl->name, DBUS_TYPE_STRING);
      PUSH_VARIANT (tid, &tid, DBUS_TYPE_UINT64);
      if (fl->reason)
        PUSH_VARIANT (reason, &fl->reason, DBUS_TYPE_STRING);
      tu32 = (uint32_t) fl->timeout;
      PUSH_VARIANT (timeout, &tu32, DBUS_TYPE_UINT32);
      PUSH_VARIANT (priority, &fl->priority, DBUS_TYPE_INT32);
      PUSH_VARIANT (value, &fl->value, DBUS_TYPE_INT64);
      PUSH_VARIANT (threshold, &fl->threshold, DBUS_TYPE_INT64);
      tu32 = (uint32_t) fl->inherit;
      PUSH_VARIANT (inherit, &tu32, DBUS_TYPE_BOOLEAN);

      if (proc)
        {
          dbus_message_iter_close_container (&strukt, &entry);
          dbus_message_iter_close_container (&array, &strukt);
          DEC_REF(fl);
        }
      else
        {
          dbus_message_iter_close_container (&array, &entry);
        }

      cur = g_list_next(cur);
    }
  dbus_message_iter_close_container (&imsg, &array);
  if (proc)
    g_list_free (lst);
}

#undef PUSH_VARIANT

static void
set_config_callback (struct callback_data *data)
{
  DBusMessage *ret = dbus_message_new_method_return (data->message);
  u_scheduler *sched = scheduler_get ();
  g_message ("DBUS: setSchedulerConfig(\"%s\") executed",
             (char *) data->user_data);
  dbus_bool_t rv = (dbus_bool_t) sched->set_config ((char *) data->user_data);
  dbus_message_append_args (ret, DBUS_TYPE_BOOLEAN, &rv, DBUS_TYPE_INVALID);
  dbus_connection_send (data->connection, ret, NULL);
  dbus_message_unref (ret);
}

static DBusHandlerResult
dbus_system_handler (DBusConnection *c,
                     DBusMessage    *m,
                     void           *userdata)
{
  DBusError error;
  DBusMessage *ret = NULL;
  DBusMessageIter imsg;
  uid_t caller;
  int is2 = 0;

  dbus_error_init (&error);
  if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                   "listSystemFlags"))
    {
      ret = dbus_message_new_method_return (m);
      push_flag (ret, NULL, FALSE);
      goto finish;
    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                        "listFlags"))
    {
      u_proc *proc;
      uint64_t tpid;
      pid_t pid;
      uint32_t recrusive;

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_UINT64, &tpid,
                                  DBUS_TYPE_BOOLEAN, &recrusive,
                                  DBUS_TYPE_INVALID)
          || !dbus_message_iter_init (m, &imsg))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }

      pid = (pid_t) tpid;
      proc = proc_by_pid_with_retry (pid);

      if (!proc)
        PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");

      ret = dbus_message_new_method_return (m);
      push_flag (ret, proc, recrusive);
      goto finish;

    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE, "addFlag"))
    {
      u_proc *proc;
      uint64_t tpid, ttid, timeout;
      int64_t priority, value, threshold;
      uint32_t inherit, urgent;
      u_flag *flag;
      char *name, *reason;

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_UINT64, &tpid,
                                  DBUS_TYPE_UINT64, &ttid,
                                  DBUS_TYPE_STRING, &name,
                                  DBUS_TYPE_STRING, &reason,
                                  DBUS_TYPE_UINT64, &timeout,
                                  DBUS_TYPE_INT32, &priority,
                                  DBUS_TYPE_INT64, &value,
                                  DBUS_TYPE_INT64, &threshold,
                                  DBUS_TYPE_BOOLEAN, &inherit,
                                  DBUS_TYPE_BOOLEAN, &urgent,
                                  DBUS_TYPE_INVALID)
          || !dbus_message_iter_init (m, &imsg))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }

      pid_t pid = (pid_t) tpid;
      pid_t tid = (pid_t) ttid;

      proc = proc_by_pid_with_retry (pid);

      GET_CALLER ();

      if (!proc)
        PUSH_ERROR (U_DBUS_ERROR_NO_PID, "wrong arguments");

      if (caller != 0 && caller != proc->proc->euid)
        PUSH_ERROR (DBUS_ERROR_ACCESS_DENIED, "access denied");

      flag = u_flag_new ((void *) U_DBUS_POINTER, name);
      flag->reason = reason;
      flag->tid = tid;
      flag->timeout = timeout;
      flag->priority = priority;
      flag->value = value;
      flag->threshold = threshold;
      flag->inherit = inherit;
      flag->urgent = urgent;

      u_flag_add (proc, flag, -1);
      DEC_REF(flag);

      ret = dbus_message_new_method_return (m);
      goto finish;

    }
  else if (dbus_message_is_method_call ( m, U_DBUS_SYSTEM_INTERFACE,
                                        "addSystemFlag"))
    {
      uint64_t timeout;
      int64_t priority, value, threshold;
      u_flag *flag;
      gboolean run_iteration;
      uint32_t urgent;
      char *name, *reason;

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_STRING, &name,
                                  DBUS_TYPE_STRING, &reason,
                                  DBUS_TYPE_UINT64, &timeout,
                                  DBUS_TYPE_INT32, &priority,
                                  DBUS_TYPE_INT64, &value,
                                  DBUS_TYPE_INT64, &threshold,
                                  DBUS_TYPE_BOOLEAN, &urgent,
                                  DBUS_TYPE_BOOLEAN, &run_iteration,
                                  DBUS_TYPE_INVALID)
          || !dbus_message_iter_init (m, &imsg))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }

      GET_CALLER ();

      if (caller != 0) // FIXME: query policykit
        PUSH_ERROR (DBUS_ERROR_ACCESS_DENIED, "access denied");

      flag = u_flag_new ((void *) U_DBUS_POINTER, name);
      flag->reason = reason;
      flag->timeout = timeout;
      flag->priority = priority;
      flag->value = value;
      flag->threshold = threshold;
      flag->urgent = urgent;

      u_flag_add (NULL, flag, -1);
      DEC_REF(flag);

      g_message ("DBUS: added system flag: name=\"%s\", reason=\"%s\"",
                 name, reason);

      if (run_iteration)
        {
          system_flags_changed = 1;
          iteration_request (0);
        }

      ret = dbus_message_new_method_return (m);
      goto finish;

    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                        "clearFlags")
           || (is2 = dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                                  "delFlag")))
    {
      u_proc *proc;
      uint64_t tpid;
      uint64_t id;

      if (is2)
        {
          if (!dbus_message_get_args (m, &error,
                                      DBUS_TYPE_UINT64, &tpid,
                                      DBUS_TYPE_UINT64, &id,
                                      DBUS_TYPE_INVALID)
              || !dbus_message_iter_init (m, &imsg))
            {
              PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
            }
        }
      else {
        if (!dbus_message_get_args (m, &error,
                                    DBUS_TYPE_UINT64, &tpid,
                                    DBUS_TYPE_INVALID)
            || !dbus_message_iter_init (m, &imsg))
        {
          PUSH_ERROR(DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }
      }

      pid_t pid = (pid_t) tpid;

      proc = proc_by_pid_with_retry (pid);

      GET_CALLER ();

      if (!proc)
        PUSH_ERROR (U_DBUS_ERROR_NO_PID, "wrong arguments");

      if (caller != 0 && caller != proc->proc->euid)
        PUSH_ERROR (DBUS_ERROR_ACCESS_DENIED, "access denied");

      if (is2)
        u_flag_clear_flag (proc, (void *) id, TRUE);
      else
        u_flag_clear_source (proc, U_DBUS_POINTER, TRUE);

      ret = dbus_message_new_method_return (m);
      goto finish;

    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                        "scheduleTask"))
    {
      u_proc *proc;
      uint32_t update;
      uint64_t tpid;

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_UINT64, &tpid,
                                  DBUS_TYPE_BOOLEAN, &update,
                                  DBUS_TYPE_INVALID)
          || !dbus_message_iter_init (m, &imsg))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }

      pid_t pid = (pid_t) tpid;
      proc = proc_by_pid_with_retry (pid);
      GET_CALLER ();

      if (!proc)
        PUSH_ERROR (U_DBUS_ERROR_NO_PID, "wrong arguments");

      if (caller != 0 && caller != proc->proc->euid)
        PUSH_ERROR (DBUS_ERROR_ACCESS_DENIED, "access denied");

      ret = dbus_message_new_method_return (m);

      int suc = process_run_one (proc, update, FALSE);

      dbus_message_append_args (ret, DBUS_TYPE_BOOLEAN, &suc,
                                DBUS_TYPE_INVALID);

      goto finish;

    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                        "setSchedulerConfig"))
    {
      u_scheduler *sched = scheduler_get ();
      char *tmps = NULL;

      if (!sched || !sched->set_config)
        {
          ret = dbus_message_new_error (m, DBUS_ERROR_FAILED,
            "scheduler does not support setting config");
          goto finish;
        }

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_STRING, &tmps,
                                  DBUS_TYPE_INVALID))
        {
          ret = dbus_message_new_error (m, DBUS_ERROR_INVALID_ARGS,
                                        "wrong arguments");
          goto finish;
        }

      if (!tmps)
        {
          ret = dbus_message_new_error (m, DBUS_ERROR_INVALID_ARGS,
                                        "wrong arguments");
          goto finish;
        }

      GET_CALLER ();
      if (caller == 0)
        {
          //set_config_dbus(tmps);
          ret = dbus_message_new_method_return (m);
          g_message ("DBUS: setSchedulerConfig(\"%s\") executed", tmps);
          dbus_bool_t rv = (dbus_bool_t) sched->set_config (tmps);
          dbus_message_append_args (ret, DBUS_TYPE_BOOLEAN, &rv,
                                    DBUS_TYPE_INVALID);
          goto finish;
        }
      else
        {
          if (!check_polkit ("org.quamquam.ulatencyd.setConfig", c, m,
                             "org.quamquam.ulatencyd.setConfig",
                             set_config_callback, tmps, TRUE, NULL, tmps))
            {
              PUSH_ERROR (DBUS_ERROR_ACCESS_DENIED, "access denied");
            }

          return DBUS_HANDLER_RESULT_HANDLED;
        }

      if (tmps)
          goto finish;

    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                        "listSchedulerConfigs"))
    {
      u_scheduler *sched = scheduler_get ();
      DBusMessageIter imsg, array;
      GPtrArray *configs;
      char *tmp;
      int i;

      if (!sched || !sched->list_configs)
        {
          ret = dbus_message_new_error (m, DBUS_ERROR_FAILED,
              "scheduler does not support setting config");
          goto finish;

        }

      configs = sched->list_configs ();

      ret = dbus_message_new_method_return (m);
      dbus_message_iter_init_append (ret, &imsg);
      dbus_message_iter_open_container (&imsg, DBUS_TYPE_ARRAY, "s", &array);

      if (configs)
        {
          for (i = 0; i < configs->len; i++)
            {
              tmp = g_ptr_array_index (configs, i);
              dbus_message_iter_append_basic (&array, DBUS_TYPE_STRING, &tmp);
            }
          g_ptr_array_unref (configs);
        }
      dbus_message_iter_close_container (&imsg, &array);

      goto finish;

    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                        "getSchedulerConfigDescription"))
    {
      u_scheduler *sched = scheduler_get ();
      char *name, *desc;

      if (!sched || !sched->get_config_description)
        {
          ret = dbus_message_new_error (
              m, DBUS_ERROR_FAILED,
              "scheduler does not support config descriptions");
          goto finish;
        }

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_STRING, &name,
                                  DBUS_TYPE_INVALID))
        {
          ret = dbus_message_new_error (m, DBUS_ERROR_INVALID_ARGS,
                                        "wrong arguments");
          goto finish;
        }

      ret = dbus_message_new_method_return (m);

      desc = sched->get_config_description (name);
      if (desc)
        {
          dbus_message_append_args (ret, DBUS_TYPE_STRING,
                                    &desc, DBUS_TYPE_INVALID);
          g_free (desc);
        }

      goto finish;
    }
  else if (dbus_message_is_method_call (m, U_DBUS_SYSTEM_INTERFACE,
                                        "cgroupsCleanup"))
    {
      int instant;

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_BOOLEAN, &instant,
                                  DBUS_TYPE_INVALID)
          || !dbus_message_iter_init (m, &imsg))
        {
          PUSH_ERROR (DBUS_ERROR_INVALID_ARGS, "wrong arguments");
        }

      GET_CALLER ();

      ret = dbus_message_new_method_return (m);

      int suc = cgroups_cleanup (instant);

      dbus_message_append_args (ret, DBUS_TYPE_BOOLEAN,
                                &suc, DBUS_TYPE_INVALID);
      ret = dbus_message_new_method_return (m);
      goto finish;

    }
  else if (dbus_message_is_method_call (m, DBUS_INTERFACE_PROPERTIES, "Get"))
    {
      const char *interface, *property;
      u_scheduler *sched = scheduler_get ();

      if (!dbus_message_get_args (m, &error,
                                  DBUS_TYPE_STRING, &interface,
                                  DBUS_TYPE_STRING, &property,
                                  DBUS_TYPE_INVALID))
        {
          g_warning ("Failed to parse property get call: %s\n", error.message);
          ret = dbus_message_new_error (m, error.name, error.message);
          goto finish;
        }

      if (g_strcmp0 (interface, U_DBUS_SYSTEM_INTERFACE) == 0)
        {
          ret = dbus_message_new_method_return (m);

          if (g_strcmp0 (property, "config") == 0)
            {
              if (sched->get_config)
                {
                  char *tmp = sched->get_config ();
                  if (tmp)
                    {
                      dbus_message_append_args (ret, DBUS_TYPE_STRING,
                                                &tmp, DBUS_TYPE_INVALID);
                    }
                  g_free (tmp);
                }
              goto finish;
            }
          else if (g_strcmp0 (property, "version") == 0)
            {
              const char *tmp = QUOTEME(VERSION);
              dbus_message_append_args (ret, DBUS_TYPE_STRING,
                                        &tmp, DBUS_TYPE_INVALID);
              goto finish;
            }

          dbus_message_unref (ret);
          return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
      else
        {
          return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

    }
  else if (dbus_message_is_method_call (m, DBUS_INTERFACE_INTROSPECTABLE,
                                        "Introspect"))
    {
      ret = dbus_message_new_method_return (m);
      dbus_message_append_args (ret, DBUS_TYPE_STRING,
                                &INTROSPECT_XML_SYSTEM,
                                DBUS_TYPE_INVALID);
    }
  else
    {
      return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

finish:
  if (ret)
    {
      dbus_connection_send (c, ret, NULL);
      dbus_message_unref (ret);
    }

  dbus_error_free (&error);
  return DBUS_HANDLER_RESULT_HANDLED;
}

gboolean
u_dbus_setup ()
{
  static const DBusObjectPathVTable utable =
    { .message_function = dbus_user_handler, };
  static const DBusObjectPathVTable stable =
    { .message_function = dbus_system_handler, };

  if (!U_dbus_connection)
    {
      g_warning ("dbus connection missing. can't create dbus interface");
      return FALSE;
    }

  DBusError error;
  DBusConnection *c = dbus_g_connection_get_connection (U_dbus_connection);

  dbus_error_init (&error);

#ifdef DEVELOP_MODE
  if (dbus_bus_request_name(c, U_DBUS_SERVICE_NAME,
                            DBUS_NAME_FLAG_REPLACE_EXISTING, &error) < 0)
    {
      g_warning ("Failed to register name on bus: %s\n", error.message);
      goto fail;
    }
#else
  if (dbus_bus_request_name (c, U_DBUS_SERVICE_NAME,
                             DBUS_NAME_FLAG_DO_NOT_QUEUE,
                             &error) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
    {
      g_warning ("daemon already running, can't request: %s",
                U_DBUS_SERVICE_NAME);
      goto fail;
    }
#endif

  dbus_connection_register_object_path (c, U_DBUS_USER_PATH, &utable, NULL);
  dbus_connection_register_object_path (c, U_DBUS_SYSTEM_PATH, &stable, NULL);

  return TRUE;

fail:
  dbus_error_free (&error);
  return FALSE;
}

#undef CHECK_PROC_FROM_PID
#undef CHECK_SESSION_FROM_PROC
#undef CHECK_IF_SESSION_ALLOWED_FOR_UID
#undef PUSH_ERROR
#undef GET_CALLER
#undef INTROSPECT
