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

#include "config.h"

#include "usession-agent.h"
#include "ulatency.h"

#include <glib.h>
#include <gmodule.h>

#ifdef ENABLE_DBUS

G_MODULE_EXPORT const gchar*
g_module_check_init (GModule *module)
{
  return "Logind not yet supported.";
}

#if 0

// systemd does not yet support setting properties

void systemd_init() {
    GError *error = NULL;
    DBusGProxy *systemd_proxy = dbus_g_proxy_new_for_name_owner(U_dbus_connection_system,
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      DBUS_INTERFACE_PROPERTIES,
                                      &error);
    if(error) {
        g_message ("systemd: %s\n", error->message);
        g_error_free(error);
        goto out;
    }

    char **empty = NULL;
    GValue val = {0, };

    g_value_init (&val, G_TYPE_STRV);
    //g_value_set_string (&val, &empty);

    if(!dbus_g_proxy_call(systemd_proxy, "Set", &error,
                          G_TYPE_STRING, "org.freedesktop.systemd1.Manager",
                          G_TYPE_STRING, "DefaultControllers",
                          G_TYPE_VALUE, &val,
                          G_TYPE_INVALID)) {
        g_debug("can't unset systemd DefaultControllers: %s", error->message);
        g_error_free(error);
        goto out;
    }

out:
    g_object_unref (systemd_proxy);
}

#endif


#endif /* ENABLE_DBUS */
