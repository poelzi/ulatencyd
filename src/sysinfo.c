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
/**
 * Returns contents of file `/proc/<pid>/environ` as a `GHashTable`.
 *
 * @param pid
 *
 * @return \a pid environment as an `GHashTable` with both keys and values
 *         destroy functions set to `g_free()`. If `environ` file contains only
 *         a null byte ('\0'), empty `GHashTable` is returned.
 * @retval NULL if either reading failed or file content is empty:
 * - If `environ` file is empty, \a errno is set to \c EEXIST.
 * - If error occurred, \a errno is set appropriately.
 */
// FIXME optimize: avoid duplication of strings
GHashTable *
u_read_env_hash (pid_t pid)
{
    char       *contents;
    gsize       length;
    GHashTable *hash;
    int         i;
    gboolean    last_was_null;

    contents = u_pid_read_file (pid, "environ", &length);

    if (contents == NULL)
      return NULL;

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

    g_free (contents);

    return hash;
}

/**
 * Returns content of variable \a var from \a pid environment.
 *
 * @param pid
 * @param var name of environment variable
 *
 * @retval value of a environment variable as a newly allocated string, use
 *         g_free() to free the returned string.
 * @retval NULL if either reading of `/proc/<pid>/environ` failed, its content
 * is empty or \a var is not defined:
 * - If environment content is empty, \a errno is set to \c EEXIST.
 * - If variable is not set, \a errno is set to \c ENOKEY.
 * - If error occurred, \a errno is set appropriately.
 */
char *
u_pid_get_env (pid_t       pid,
               const char *var)
{
    char      *contents;
    char      *val;
    gsize      length;
    int        i;
    char      *prefix;
    int        prefix_len;
    gboolean   last_was_null;

    contents = u_pid_read_file (pid, "environ", &length);

    if (contents == NULL)
      return NULL;

    val = NULL;

    prefix = g_strdup_printf ("%s=", var);
    prefix_len = strlen (prefix);

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

    g_free (prefix);
    g_free (contents);

    if (val == NULL)
      errno = ENOKEY;

    return val;
}

/**
 * Returns contents of file `/proc/<pid>/<what>` containing set of strings
 * separated by null bytes ('\0').
 *
 * @param pid
 * @param what name of file in directory `/proc/<pid>/` to read contents from.
 *
 * @return contents of a file as a `GPtrArray` with destroy function set to
 *         `g_free()`. If file contains only a null byte ('\0'), `GPtrArray`
 *         with length \c 0 is returned.
 * @retval NULL if either reading failed or content is empty:
 * - If content is empty, \a errno is set to \c EEXIST.
 * - If error occurred, \a errno is set appropriately.
 */
// FIXME optimize: avoid duplication of strings
GPtrArray *
u_pid_read_0file (pid_t       pid,
                 const char *what)
{
    char       *contents;
    gsize       length;
    GPtrArray  *rv = NULL;
    int         i;
    gboolean    last_was_null;

    contents = u_pid_read_file (pid, what, &length);

    if (contents == NULL)
      return NULL;

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

    g_free (contents);

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

        if (!u_proc_ensure (proc, ENVIRONMENT,
                            update ? UPDATE_NOW : UPDATE_DEFAULT))
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
