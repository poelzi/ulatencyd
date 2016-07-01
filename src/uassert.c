/*
    Copyright 2014 ulatencyd developers

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

/**
 *  \file uassert.c
 *  \ingroup UAssert
 */

#include "config.h"

#include "uassert.h"

#include "ulatency.h"

#include <proc/readproc.h>
#include <sys/types.h>
#include <glib.h>

struct _cb_data_proc {
  u_proc *proc;
  gchar  *strloc;
} ;

/**
 * Prints critical warning if process exists in /proc/ directory and is not
 * a zombie
 * @param p an #u_proc
 */
gboolean static
_cb_assert_process_dead (gpointer data)
{
  struct _cb_data_proc *d = (struct _cb_data_proc  *)data;
  pid_t    pids [2] = { d->proc->pid, 0 };
  PROCTAB *proctab;
  proc_t  *p;

  proctab = openproc(PROC_FILLSTAT | PROC_PID, pids);
  p = readproc(proctab, NULL);
  if (p)
    {
      if (p->state != 'Z')
        {
          g_critical("Existent process <pid: %d, uid: %d, cmdline: '%s') "
                     "marked as dead at %s",
                     d->proc->pid, d->proc->proc->euid,
                     d->proc->cmdline_match ? d->proc->cmdline_match : "??",
                     d->strloc);
        }
      freeproc(p);
    }
  closeproc(proctab);
  DEC_REF_ALLOW_UNREF (d->proc);
  g_free (d->strloc);
  g_slice_free (struct _cb_data_proc, d);
  return FALSE;
}

void
u_assert_process_dead_real (u_proc      *proc,
                            const gchar *strloc)
{
  struct _cb_data_proc *data;

  data = g_slice_new (struct _cb_data_proc);
  data->proc = proc;
  INC_REF_FORBID_UNREF (proc);
  data->strloc = g_strdup (strloc);
  g_timeout_add_seconds_full(G_PRIORITY_LOW, 1, _cb_assert_process_dead, data, NULL);
}
