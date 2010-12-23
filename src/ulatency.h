#ifndef __ulatency__

#include <glib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proc/procps.h"
#include "proc/readproc.h"
#include <libcgroup.h>


#define VERSION 0.1

#define OPENPROC_FLAGS PROC_FILLMEM | \
  PROC_FILLUSR | PROC_FILLGRP | PROC_FILLSTATUS | PROC_FILLSTAT | \
  PROC_FILLWCHAN | PROC_FILLCGROUP | PROC_FILLSUPGRP

#define CONFIG_CORE "core"

extern GMainLoop *main_loop;
extern GList *filter_list;
extern GKeyFile *config_data;

#define U_HEAD \
  guint ref; \
  guint in_lua;


enum FILTER_TYPES {
  FILTER_LUA,
  FILTER_C
};

enum FILTER_SKIP {
  FILTER_STOP=-1,
};

enum FILTER_PRIORITIES {
  PRIO_IDLE=-1,
};

enum IO_PRIO_CLASS {
  IOPRIO_CLASS_NONE,
  IOPRIO_CLASS_RT,
  IOPRIO_CLASS_BE,
  IOPRIO_CLASS_IDLE,
};



struct lua_callback {
  lua_State *lua_state;
  int lua_state_id;
  int lua_func;
  int lua_data;
};

struct lua_filter {
  lua_State *lua_state;
  int lua_state_id;
  int lua_func;
  int lua_data;
  GRegex *regexp_cmdline;
  GRegex *regexp_basename;
};

struct filter_block {
  unsigned int pid;
  GTime timeout;
  gboolean skip;
};

typedef struct _u_proc {
  U_HEAD;
  struct proc_t proc;
  guint last_update;
} u_proc;

typedef struct _filter {
  U_HEAD;
  enum FILTER_TYPES type;
  char *name;
  int (*check)(u_proc *pr, struct _filter *filter);
  int (*callback)(u_proc *pr, struct _filter *filter);
  void *data;
  GHashTable *skip_filter;
} u_filter;

#define INC_REF(P) P ->ref++;
#define DEC_REF(P) \
  do { P ->ref--; g_assert( P ->ref >= 0);} while(0);

#define LUA_FREE(P) (g_assert(P->in_lua > 0); P->in_lua = 0;)
#define LUA_PUT(P) (P->in_lua = 1;)

#define FREE_IF_UNREF(P,FNK) if( P ->ref == 0 && P ->in_lua == 0) { FNK ( P ); }

// alloc
u_proc* u_proc_new(void);


u_filter *filter_new();
void filter_free(u_filter *filter);

void filter_register(u_filter *filter);
void filter_unregister(u_filter *filter);

void filter_run_for_proc(gpointer data, gpointer user_data);
int l_filter_run_for_proc(u_proc *pr, u_filter *flt);
void cp_proc_t(const struct proc_t *src, struct proc_t *dst);

struct u_cgroup {
  struct cgroup *group;
  char *name;
  int ref;
};

struct u_cgroup_controller {
  struct cgroup_controller *controller;
  char *name;
  int ref; // struct 
};


struct user_active {
  guint uid;
  guint max_processes;
  // FIXME: last change time
  time_t last_change;
  GList *actives;
};

struct user_process {
  guint pid;
  time_t last_change;
};

int ioprio_getpid(pid_t pid, int *ioprio, int *ioclass);
int ioprio_setpid(pid_t pid, int ioprio, int ioclass);

int adj_oom_killer(pid_t pid, int adj);


extern GList* active_users;

void set_active_pid(unsigned int uid, unsigned int pid);
struct user_active* get_userlist(guint uid, gboolean create);

// module 
int (*MODULE_INIT)(void);

#endif