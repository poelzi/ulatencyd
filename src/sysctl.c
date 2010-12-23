#include "ulatency.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
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
#include "nls.h"
#include <fcntl.h>


const char *to_prio[] = { "none", "realtime", "best-effort", "idle", };

// IO PRIO stuff

static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(SYS_ioprio_set, which, who, ioprio);
}

static inline int ioprio_get(int which, int who)
{
	return syscall(SYS_ioprio_get, which, who);
}

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_CLASS_SHIFT	13

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
  char aval[4];
  char *path;

  val = MAX(-17, MIN(adj, 15));

  g_snprintf(&aval[0], 4, "%d", val);
  path = g_strdup_printf("/proc/%d/oom_adj", pid);

  oomfd = open(path, O_NOFOLLOW | O_WRONLY);
  if (oomfd >= 0) {
    (void)write(oomfd, &aval, 3);
    close(oomfd);
    free(path);
    return 0;
  }
  free(path);
  return -1;
}


