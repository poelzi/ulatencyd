/*
    Copyright 2010,2011,2013 ulatencyd developers

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

typedef struct _UModule UModule;

#include "config.h"
#include "ulatency.h"

#include <glib.h>
#include <gmodule.h>

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <fnmatch.h>
#include <string.h>

/**
 * Close module.
 *
 * @param module The GModule should be closed
 *
 * @return TRUE on success, on failure a warning will be logged.
 */
gboolean
u_module_close (GModule *module)
{
  g_return_val_if_fail (module != NULL, FALSE);

  g_message ("Closing module %s.", g_module_name (module));
  if (!g_module_close (module))
    {
      g_warning ("Couldn't close module %s: %s", g_module_name (module), g_module_error ());
      return FALSE;
    }

  return TRUE;
}

static GSourceFunc
_u_module_close_me (gpointer user_data)
{
  u_module_close ((GModule *) user_data);
  return FALSE;
}

/**
 * Request to close module.
 * The closing is scheduled via 'g_idle_add()` so it should be safe to
 * make request from the module itself.
 *
 * @param caller The GModule should be closed.
 */
void
u_module_close_me (GModule *caller)
{
  g_idle_add ((GSourceFunc) _u_module_close_me, caller);
}


/**
 * Load and initialize all modules from directory.
 *
 * @param modules_directory The directory with modules.
 *
 * @return TRUE if at least one module was successfully loaded.
 */
gboolean
u_module_load_directory (char *modules_directory)
{
  DIR             *dip;
  struct dirent   *dit;
  char             rpath[PATH_MAX+1];
  char           **disabled;
  gsize            disabled_len;

  g_info("Loading modules from directory '%s/' ...", modules_directory);

  if ((dip = opendir(modules_directory)) == NULL)
  {
    g_warning ("Couldn't load modules (directory '%s': %s)",
               modules_directory, g_strerror(errno));
    return FALSE;
  }

  disabled = g_key_file_get_string_list(config_data, CONFIG_CORE,
                                      "disabled_modules", &disabled_len, NULL);

  while ((dit = readdir(dip)) != NULL)
    {
      gchar *module_name;
      gboolean skip;
      gsize i;

      if (fnmatch ("*.so", dit->d_name, 0))
        continue;

      module_name = g_strndup(dit->d_name,strlen(dit->d_name)-3);

      skip = FALSE;
      for (i = 0; i < disabled_len; i++)
        if (!g_ascii_strcasecmp (disabled[i], module_name))
          {
            skip = TRUE;
            break;
          }

      if(!skip)
        {
          GModule *module;

          snprintf (rpath, PATH_MAX, "%s/%s", modules_directory, dit->d_name);
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Loading module %s", dit->d_name);

          module = g_module_open (rpath, G_MODULE_BIND_LAZY);
          if (!module) {
            g_warning ("%s", g_module_error());
          }
        }
      else
        {
          g_debug ("Skipped module %s", module_name);
        }

      g_free(module_name);
    }

  g_strfreev (disabled);
  closedir (dip);

  return TRUE;
}
