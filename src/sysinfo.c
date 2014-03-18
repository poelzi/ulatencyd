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
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * Returns contents of file `/proc/<pid>/<what>`.
 *
 * @param pid
 * @param what        name of file in directory `/proc/<pid>/` to read contents
 *                    from.
 * @param[out] length location to store length in bytes of the contents,
 *                    or \c NULL.
 *
 * @return contents of a file as a newly allocated string, use g_free() to free
 *         the returned string.
 * @retval NULL if either reading failed or content is empty:
 * - If content is empty, \a errno is set to \c EEXIST and \a length to \c 0.
 * - If error occurred, \a errno is set appropriately and \a length is not set.
 */
gchar *
u_pid_read_file (pid_t       pid,
                 const char *what,
                 gsize      *length)
{
  gchar *path;
  gchar *contents;
  gint fd;
  gchar buf[4096];
  ssize_t bytes;
  gsize total_bytes;
  gsize total_allocated;
  gint save_errno;

  path = g_strdup_printf ("/proc/%u/%s", (guint)pid, what);

  fd = open (path, O_RDONLY);
  g_free (path);

  if (fd < 0)
    return NULL;

  contents = NULL;
  total_bytes = 0;
  total_allocated = 0;

  while (TRUE)
    {
      bytes = read (fd, buf, sizeof buf);

      if (bytes == -1)
        {
          if (G_UNLIKELY (errno == EINTR))
            continue;
          goto error;
        }
      else if (bytes == 0)
        {
          break;
        }
      else if (G_UNLIKELY (total_bytes > G_MAXSIZE - bytes))
        {
          goto file_too_large;
        }
      else if (G_UNLIKELY (bytes < 0)) {
          g_assert_not_reached();
      }

      if (!contents)
        total_allocated = bytes + 1;
      else
        total_allocated += bytes;

      contents = g_realloc (contents, total_allocated);
      memcpy (contents + total_bytes, buf, bytes);

      total_bytes += bytes;
    }

  close (fd);

  if (G_UNLIKELY (total_allocated == 0))
    errno = EEXIST;
  else
    contents[total_bytes] = '\0';

  if (length)
    *length = total_bytes;

  return contents;

file_too_large:
  errno = EFBIG;

error:
  save_errno = errno;
  g_free (contents);
  close (fd);
  errno = save_errno;

  return NULL;
}

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
        if(proc->proc->euid != uid)
            continue;

        u_proc_ensure(proc, ENVIRONMENT, update ? UPDATE_NOW : UPDATE_ONCE);

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

uint64_t get_number_of_processes() {
    uint64_t rv = 0;
    DIR             *dip = opendir("/proc");
    struct dirent   *dit;

    if(!dip)
        return 0;

    while ((dit = readdir(dip)) != NULL) {
        if(!strcmp(dit->d_name, ".") || !strcmp(dit->d_name, ".."))
            continue;
        if(likely( likely(*dit->d_name > '0') && likely(*dit->d_name <= '9') )) {
            rv++;
        }
    }
    closedir(dip);

    return rv;
}
