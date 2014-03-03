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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <linux/oom.h>
#include "nls.h"
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <fcntl.h>

#ifndef OOM_SCORE_ADJ_MIN
#define OOM_SCORE_ADJ_MIN       (-1000)
#define OOM_SCORE_ADJ_MAX       1000
#endif


const char *to_prio[] = { "none", "realtime", "best-effort", "idle", };

// IO PRIO stuff

static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(__NR_ioprio_set, which, who, ioprio);
}

static inline int ioprio_get(int which, int who)
{
	return syscall(__NR_ioprio_get, which, who);
}

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_CLASS_SHIFT	13

/*  // test
static void ioprio_print(int pid)
{
  int ioprio, ioclass;

  ioprio = ioprio_get(IOPRIO_WHO_PROCESS, pid);

  if (ioprio == -1)
    err(EXIT_FAILURE, _("ioprio_get failed"));
  else {
    ioclass = ioprio >> IOPRIO_CLASS_SHIFT;
    if (ioclass != IOPRIO_CLASS_IDLE) {
      ioprio = ioprio & 0xff;
      printf("%s: prio %d\n", to_prio[ioclass], ioprio);
    } else
      printf("%s\n", to_prio[ioclass]);
  }
}
*/

int ioprio_getpid(pid_t pid, int *ioprio, int *ioclass) {
  int rv = ioprio_get(IOPRIO_WHO_PROCESS, pid);
  if (rv == -1)
    return -1;
  *ioclass = (rv >> IOPRIO_CLASS_SHIFT);
  *ioprio = (rv & 0xff);
  return 0;
}


int ioprio_setpid(pid_t pid, int ioprio, int ioclass)
{
  int rc = ioprio_set(IOPRIO_WHO_PROCESS, pid,
                      ioprio | ioclass << IOPRIO_CLASS_SHIFT);

  return rc;
}

// renice interface

int renice_pid(int pid, int prio) {
  int oldprio;

  errno = 0;
  oldprio = getpriority(PRIO_PROCESS, pid);
  if (oldprio == -1 && errno)
    return -1;

  if(oldprio == prio)
    return 0;

  if (setpriority(PRIO_PROCESS, pid, prio) < 0)
    return -1;

  return 0;
}



// oom adjusting
int adj_oom_killer(pid_t pid, int adj)
{
  int oomfd, val;
  char aval[6];
  char *path;

  val = MAX(OOM_SCORE_ADJ_MIN, MIN(adj, OOM_SCORE_ADJ_MAX));

  g_snprintf(&aval[0], 6, "%d", val);
  path = g_strdup_printf("/proc/%d/oom_score_adj", pid);

  oomfd = open(path, O_NOFOLLOW | O_WRONLY);
  if (oomfd >= 0) {
    if(write(oomfd, &aval, strlen(&aval[0])) < 1) {} // stupid warning :-)
    close(oomfd);
    g_free(path);
    return 0;
  }
  g_free(path);
  return -1;
}

/**
 * Returns number of how oom-killer score is adjusted for #U_PROC
 * @retval >=0 score adjust
 * @retval -1 on failure
 */
int get_oom_killer(pid_t pid)
{
    char       *contents, *path;
    gsize       length;
    GError     *error = NULL;
    int         rv, res;

    path = g_strdup_printf ("/proc/%u/oom_score_adj", (guint)pid);

    res = g_file_get_contents (path,
                               &contents,
                               &length,
                               &error);
    if (!res) {
        g_error_free (error);
        return -1;
    }
    if(!sscanf(contents, "%d", &rv))
      rv = -1;

    g_free(contents);
    g_free(path);

    return rv;
}
