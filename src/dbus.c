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
#include <stdint.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib-bindings.h>
#include <dbus/dbus-protocol.h>

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
"    </interface>\n" \
"    <interface name=\"org.freedesktop.DBus.Introspectable\">\n" \
"       <method name=\"Introspect\">\n" \
"          <arg name=\"data\" type=\"s\" direction=\"out\"/>\n" \
"       </method>\n" \
"    </interface>\n"


const char *INTROSPECT_XML_USER = \
"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
"<node name=\"" U_DBUS_USER_PATH "\">\n"
"  <interface name=\"" U_DBUS_USER_INTERFACE "\">\n"
"    <method name=\"setActive\">\n"
"      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
"    </method>\n"
"    <method name=\"setActiveWithUser\">\n"
"      <arg type=\"t\" name=\"uid\" direction=\"in\" />\n"
"      <arg type=\"t\" name=\"pid\" direction=\"in\" />\n"
"    </method>\n"
"    <method name=\"setActiveControl\">\n"
"      <arg type=\"b\" name=\"enabled\" direction=\"in\" />\n"
"    </method>\n"
//"    <method name=\"wishGroup\">\n"
//"      <arg type=\"i\" name=\"pid\" direction=\"in\" />\n"
//"      <arg type=\"i\" name=\"priority\" direction=\"in\" />\n"
//"    </method>\n"
"    <property name=\"activeList\" type=\"q\" access=\"readwrite\"/>\n"
"  </interface>\n"
INTROSPECT
"</node>\n";

const char *INTROSPECT_XML_SYSTEM = \
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
"  </interface>\n"
INTROSPECT
"</node>\n";

static DBusHandlerResult dbus_user_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
    DBusError error;
    DBusMessage *ret = NULL;
    uid_t caller;
    int is2 = 0;
    dbus_error_init(&error);
    if(dbus_message_is_method_call(m, U_DBUS_USER_INTERFACE, "setActive") ||
       (is2 = dbus_message_is_method_call(m, U_DBUS_USER_INTERFACE, "setActiveWithUser"))) {
        uid_t uid;
        pid_t pid;
        uint64_t tmpu;
        uint64_t tmpp;

        if ((caller = dbus_bus_get_unix_user(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                g_warning("dbus_message_get_unix_user() failed: %s\n", error.message);
                ret = dbus_message_new_error(m, DBUS_ERROR_ACCESS_DENIED, "not a local connection");
                goto finish;
        }

        if(is2) {
          if(!dbus_message_get_args(m, &error,
                                    DBUS_TYPE_UINT64, &tmpu,
                                    DBUS_TYPE_UINT64, &tmpp,
                                    DBUS_TYPE_INVALID)) {
              ret = dbus_message_new_error(m, DBUS_ERROR_INVALID_ARGS , "wrong arguments");
              goto finish;
          }
          uid = (uid_t)tmpu;
        } else {
          if(!dbus_message_get_args(m, &error,
                                    DBUS_TYPE_UINT64, &tmpp,
                                    DBUS_TYPE_INVALID)) {
              ret = dbus_message_new_error(m, DBUS_ERROR_INVALID_ARGS , "wrong arguments");
              goto finish;
          }
          uid = (pid_t)caller;
        }
        pid = (pid_t)tmpp;

        if(caller != 0 && caller != uid) {
          ret = dbus_message_new_error(m, DBUS_ERROR_ACCESS_DENIED, "not allowed to set aktive pids of foreign users");

          goto finish;
        }
        set_active_pid(uid, pid);
        ret = dbus_message_new_method_return(m);

        goto finish;

    } else if (dbus_message_is_method_call(m, U_DBUS_USER_INTERFACE, "setActiveControl")) {
        gboolean enable;
        struct user_active *ua;

        if(!dbus_message_get_args(m, &error,
                                  DBUS_TYPE_BOOLEAN, &enable,
                                  DBUS_TYPE_INVALID)) {
            ret = dbus_message_new_error(m, DBUS_ERROR_INVALID_ARGS , "wrong arguments");
            goto finish;
        }
        if ((caller = dbus_bus_get_unix_user(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                g_warning("dbus_message_get_unix_user() failed: %s\n", error.message);
                ret = dbus_message_new_error(m, DBUS_ERROR_ACCESS_DENIED, "not a local connection");
                goto finish;
        }

        ua = get_userlist(caller, TRUE);
        if(enable)
          ua->active_agent = USER_ACTIVE_AGENT_DBUS;
        else
          ua->active_agent = USER_ACTIVE_AGENT_NONE;

        ret = dbus_message_new_method_return(m);

        goto finish;
    } else if (dbus_message_is_method_call(m, DBUS_INTERFACE_PROPERTIES, "Get")) {
        const char *interface, *property;
        struct user_active *ua;

        if (!dbus_message_get_args(m, &error,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID)) {
            g_warning("Failed to parse property get call: %s\n", error.message);
            ret = dbus_message_new_error(m, error.name, error.message);
            goto finish;
        }

        if (g_strcmp0(interface, U_DBUS_USER_INTERFACE) == 0) {

            if ((caller = dbus_bus_get_unix_user(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                    g_warning("dbus_message_get_unix_user() failed: %s\n", error.message);
                    ret = dbus_message_new_error(m, DBUS_ERROR_ACCESS_DENIED, "not a local connection");
                    goto finish;
            }
            ua = get_userlist(caller, TRUE);
            ret = dbus_message_new_method_return(m);

            if(g_strcmp0(property, "activeList") == 0) {
                dbus_message_append_args (ret,
                                          DBUS_TYPE_UINT32, &ua->max_processes,
                                          DBUS_TYPE_INVALID);
                goto finish;
            }

            dbus_message_unref(ret);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        } else	{
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

    } else if (dbus_message_is_method_call(m, DBUS_INTERFACE_PROPERTIES, "Set")) {
        const char *interface, *property;
        struct user_active *ua;
        DBusMessageIter imsg;
        if (!dbus_message_get_args(m, &error,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID) ||
            !dbus_message_iter_init (m, &imsg)) {
              g_warning("Failed to parse property set call: %s\n", error.message);
              ret = dbus_message_new_error(m, error.name, error.message);
              goto finish;
        }
        dbus_message_iter_next(&imsg);
        dbus_message_iter_next(&imsg);

        if (g_strcmp0(interface, U_DBUS_USER_INTERFACE) == 0) {

            if ((caller = dbus_bus_get_unix_user(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                    g_warning("dbus_message_get_unix_user() failed: %s\n", error.message);
                    ret = dbus_message_new_error(m, DBUS_ERROR_ACCESS_DENIED, "not a local connection");
                    goto finish;
            }
            ua = get_userlist(caller, TRUE);
            ret = dbus_message_new_method_return(m);

            if(g_strcmp0(property, "activeList") == 0) {
                if(!dbus_message_iter_get_arg_type(&imsg) == DBUS_TYPE_UINT32)
                    goto error;

                dbus_message_iter_get_basic (&imsg, &ua->max_processes);

                goto finish;
            }

            dbus_message_unref(ret);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        } else	{
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

    } else if (dbus_message_is_method_call(m, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
        ret = dbus_message_new_method_return(m);
        dbus_message_append_args(ret,
                                 DBUS_TYPE_STRING, &INTROSPECT_XML_USER,
                                 DBUS_TYPE_INVALID);
        goto finish;
    } else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

error:
    if(ret)
      dbus_message_unref(ret);
    ret = dbus_message_new_error(m, DBUS_ERROR_INVALID_ARGS , "wrong arguments");


finish:
    if (ret) {
        dbus_connection_send(c, ret, NULL);
        dbus_message_unref(ret);
    }

    dbus_error_free(&error);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult dbus_system_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
    DBusError error;
    DBusMessage *ret = NULL;

    dbus_error_init(&error);
    if(dbus_message_is_method_call(m, U_DBUS_SYSTEM_INTERFACE, "listSystemFlags")) {
        GList *cur;
        u_flag *fl;
        char *name = NULL;
        uint32_t tu32;
        DBusMessageIter imsg, array, dict, entry, value;

        ret = dbus_message_new_method_return(m);
        dbus_message_iter_init_append(ret, &imsg);

        dbus_message_iter_open_container(&imsg, DBUS_TYPE_ARRAY,
            "a{sv}"
            , &array);


        cur = g_list_first(system_flags);

#define PUSH_VARIANT(NAME, VAR, TYPE) \
            name = #NAME ; \
            dbus_message_iter_open_container(&entry, DBUS_TYPE_DICT_ENTRY, NULL, &dict); \
            dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &name); \
            dbus_message_iter_open_container(&dict, DBUS_TYPE_VARIANT, TYPE##_AS_STRING, &value); \
            dbus_message_iter_append_basic(&value, TYPE, VAR); \
            dbus_message_iter_close_container(&dict, &value); \
            dbus_message_iter_close_container(&entry, &dict);
          

        while(cur) {
            fl = cur->data;

            dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
                                             "{sv}", &entry);

            PUSH_VARIANT(name, &fl->name, DBUS_TYPE_STRING);
            PUSH_VARIANT(reason, &fl->reason, DBUS_TYPE_STRING);
            tu32 = (uint32_t)fl->timeout;
            PUSH_VARIANT(timeout, &tu32, DBUS_TYPE_UINT32);
            PUSH_VARIANT(priority, &fl->priority, DBUS_TYPE_INT32);
            PUSH_VARIANT(value, &fl->value, DBUS_TYPE_INT64);
            PUSH_VARIANT(threshold, &fl->threshold, DBUS_TYPE_INT64);
            tu32 = (uint32_t)fl->inherit;
            PUSH_VARIANT(inherit, &tu32, DBUS_TYPE_BOOLEAN);
            dbus_message_iter_close_container(&array, &entry);

            cur = g_list_next(cur);
        }
#undef PUSH_VARIANT
        dbus_message_iter_close_container(&imsg, &array);
        
        goto finish;

    } else if(dbus_message_is_method_call(m, U_DBUS_SYSTEM_INTERFACE, "setSchedulerConfig")) {
        u_scheduler *sched = scheduler_get();
        char *tmps = NULL;

        if (!sched || !sched->set_config) {
            ret = dbus_message_new_error(m, DBUS_ERROR_FAILED, "scheduler does not support setting config");
            goto finish;
        }
        if(!dbus_message_get_args(m, &error,
                                  DBUS_TYPE_STRING, &tmps,
                                  DBUS_TYPE_INVALID)) {
            ret = dbus_message_new_error(m, DBUS_ERROR_INVALID_ARGS , "wrong arguments");
            goto finish;
        }

        if(tmps) {
            ret = dbus_message_new_method_return(m);
            dbus_bool_t rv = (dbus_bool_t)sched->set_config(tmps);
            dbus_message_append_args (ret,
                                      DBUS_TYPE_BOOLEAN, &rv,
                                      DBUS_TYPE_INVALID);
            goto finish;
        } else {
            ret = dbus_message_new_error(m, DBUS_ERROR_INVALID_ARGS , "wrong arguments");
            goto finish;
        }

    } else if(dbus_message_is_method_call(m, U_DBUS_SYSTEM_INTERFACE, "listSchedulerConfigs")) {
        u_scheduler *sched = scheduler_get();
        DBusMessageIter imsg, array;
        GPtrArray *configs;
        char *tmp;
        int i;

        if (!sched || !sched->list_configs) {
            ret = dbus_message_new_error(m, DBUS_ERROR_FAILED, "scheduler does not support setting config");
            goto finish;
        }
        configs = sched->list_configs();

        ret = dbus_message_new_method_return(m);

        dbus_message_iter_init_append(ret, &imsg);

        dbus_message_iter_open_container(&imsg, DBUS_TYPE_ARRAY, "s" , &array);

        if(configs) {
          for(i = 0; i < configs->len; i++) {
              tmp = g_ptr_array_index(configs, i);
              dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &tmp);
          }
          g_ptr_array_unref(configs);
        }
        dbus_message_iter_close_container(&imsg, &array);

        goto finish;

    } else if(dbus_message_is_method_call(m, U_DBUS_SYSTEM_INTERFACE, "getSchedulerConfigDescription")) {
        u_scheduler *sched = scheduler_get();
        char *name, *desc;

        if (!sched || !sched->get_config_description) {
            ret = dbus_message_new_error(m, DBUS_ERROR_FAILED, "scheduler does not support config descriptions");
            goto finish;
        }

        if(!dbus_message_get_args(m, &error,
                                  DBUS_TYPE_STRING, &name,
                                  DBUS_TYPE_INVALID)) {
            ret = dbus_message_new_error(m, DBUS_ERROR_INVALID_ARGS , "wrong arguments");
            goto finish;
        }

        ret = dbus_message_new_method_return(m);

        desc = sched->get_config_description(name);
        if(desc) {
            dbus_message_append_args(ret,
                                     DBUS_TYPE_STRING, &desc,
                                     DBUS_TYPE_INVALID);
            g_free(desc);
        }

        goto finish;

    } else if (dbus_message_is_method_call(m, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
        ret = dbus_message_new_method_return(m);
        dbus_message_append_args(ret,
                                 DBUS_TYPE_STRING, &INTROSPECT_XML_SYSTEM,
                                 DBUS_TYPE_INVALID);
    } else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;


finish:
    if (ret) {
        dbus_connection_send(c, ret, NULL);
        dbus_message_unref(ret);
    }

    dbus_error_free(&error);
    return DBUS_HANDLER_RESULT_HANDLED;
}


void consolekit_init();

gboolean u_dbus_setup() {
    static const DBusObjectPathVTable utable = {
        .message_function = dbus_user_handler,
    };
    static const DBusObjectPathVTable stable = {
        .message_function = dbus_system_handler,
    };

    if(!U_dbus_connection)
      return FALSE;

    DBusError error;
    DBusConnection *c = dbus_g_connection_get_connection(U_dbus_connection);
    
    dbus_error_init(&error);

    if (dbus_bus_request_name(c, U_DBUS_SERVICE_NAME, DBUS_NAME_FLAG_REPLACE_EXISTING, &error) < 0) {
        g_warning("Failed to register name on bus: %s\n", error.message);
        goto fail;
    }

    dbus_connection_register_object_path(c, U_DBUS_USER_PATH, &utable, NULL);
    dbus_connection_register_object_path(c, U_DBUS_SYSTEM_PATH, &stable, NULL);

    consolekit_init();

    return TRUE;

fail:
    dbus_error_free(&error);
    return FALSE;
}

