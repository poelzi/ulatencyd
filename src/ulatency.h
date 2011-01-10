#ifndef __ulatency__
#include <glib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proc/procps.h"
#include "proc/readproc.h"
//#include <libcgroup.h>


#define G_LOG_LEVEL_TRACE   1 << 8
#define g_trace(...)    g_log (G_LOG_DOMAIN,         \
                               G_LOG_LEVEL_TRACE,    \
                               __VA_ARGS__)

#define VERSION 0.1

#define OPENPROC_FLAGS PROC_FILLMEM | \
  PROC_FILLUSR | PROC_FILLGRP | PROC_FILLSTATUS | PROC_FILLSTAT | \
  PROC_FILLWCHAN | PROC_FILLCGROUP | PROC_FILLSUPGRP | PROC_FILLCGROUP | PROC_FILLCOM

#define CONFIG_CORE "core"

#define U_HEAD \
  guint ref; \
  void (*free_fnk)(void *data);

struct _U_HEAD {
  U_HEAD;
};

enum U_PROC_STATE {
  UPROC_NEW     = (1<<0),
  UPROC_INVALID = (1<<1),
  UPROC_ALIVE   = (1<<2),
};

#define U_PROC_OK_MASK ~UPROC_INVALID

#define U_PROC_IS_INVALID(P) ( P ->ustate & UPROC_INVALID )
#define U_PROC_IS_VALID(P) ((( P ->ustate & U_PROC_OK_MASK ) & UPROC_INVALID ) == 0)

#define U_PROC_SET_STATE(P,STATE) ( P ->ustate = ( P ->ustate | STATE ))
#define U_PROC_UNSET_STATE(P,STATE) ( P ->ustate = ( P ->ustate & ~STATE ))

enum FILTER_TYPES {
  FILTER_LUA,
  FILTER_C
};

enum FILTER_FLAGS {
  FILTER_STOP          = (1<<0),
  FILTER_SKIP_CHILD   = (1<<1),
};

#define FILTER_TIMEOUT(v) ( v & 0xFFFF)
#define FILTER_FLAGS(v) ( v >> 16)
#define FILTER_MIX(flages,timeout) (( flags << 16 ) | timeout )


enum FILTER_PRIORITIES {
  PRIO_IDLE=-1,
};

// default categories for convinience

/*
#define FLAG_CAT_MEDIA "MEDIA"
#define FLAG_CAT_DESKTOP_UI "DESKTOP_UI"
#define FLAG_CAT_DESKTOP_HIGH "DESKTOP_HIGH"
#define FLAG_CAT_DESKTOP "DESKTOP"
#define FLAG_CAT_DESKTOP_IDLE "DESKTOP_IDLE"
#define FLAG_CAT_DESKTOP_POISON "DESKTOP_POISON"
#define FLAG_CAT_DEAMON "DEAMON"
#define FLAG_CAT_DEAMON_ESSENTIAL "DEAMON_ESSENTIAL"
*/

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
  int filter;
  GRegex *regexp_cmdline;
  GRegex *regexp_basename;
  double min_percent;
};

struct filter_block {
  unsigned int pid;
  GTime timeout;
  gboolean skip;
};

typedef struct _u_proc {
  U_HEAD;
  int           pid; // duplicate of proc.tgid
  int           ustate; // status bits for process
  struct proc_t proc;
  guint         last_update; // for detecting dead processes
  GNode         *node; // for parent/child lookups
  GHashTable    *skip_filter;
  GList         *flags;
  int           changed; // flags or main parameters of process like uid, gid, sid
  void          *filter_owner;
  int           block_scheduler; // this should be respected by the scheduler
  int           lua_data;
} u_proc;

typedef struct _filter {
  U_HEAD;
  enum FILTER_TYPES type;
  char *name;
  int (*precheck)(struct _filter *filter);
  int (*check)(u_proc *pr, struct _filter *filter);
  int (*postcheck)(struct _filter *filter);
  int (*callback)(u_proc *pr, struct _filter *filter);
  void *data;
} u_filter;

#define INC_REF(P) P ->ref++;
#define DEC_REF(P) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) P ; uh->ref--; g_assert(uh->ref >= 0); \
  if( uh->ref == 0 && uh->free_fnk) { uh->free_fnk( P ); P = NULL; }} while(0);

#define FREE_IF_UNREF(P,FNK) if( P ->ref == 0 ) { FNK ( P ); }


#define U_MALLOC(SIZE) g_malloc0(gsize n_bytes);
#define U_FREE(PTR) g_free( PTR );

typedef enum  {
  REASON_UNSET = 0,
  REASON_UNKNOWN,
  REASON_CPU,
  REASON_MEMORY,
  REASON_BLOCK_IO,
  REASON_SWAP_IO
} FLAG_REASON;

/*typedef enum {
  NONE = 0,
  REPLACE_SOURCE,
  ADD,
} FLAG_BEHAVIOUR;
*/
typedef struct _FLAG {
  U_HEAD;
  void     *source;       // pointer to a data structure that is the "owner"
//  FLAG_BEHAVIOUR age;
  char     *name;         // label name
  int      inherit;      // will apply to all children
  int      timeout;       // timeout when the flag will disapear
  FLAG_REASON reason;     // why the flag was set. This makes most sense with emergency flags
  int      priority;      // custom data: priority
  int      value;         // custom data: value
  int      threshold;     // custom data: threshold
} u_flag;


u_flag *u_flag_new(u_filter *source, const char *name);
void u_flag_free(void *data);

int u_flag_add(u_proc *proc, u_flag *flag);
int u_flag_del(u_proc *proc, u_flag *flag);
int u_flag_clear_source(u_proc *proc, void *source);
int u_flag_clear_name(u_proc *proc, const char *name);
int u_flag_clear_all(u_proc *proc);


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

typedef struct {
  int (*all)(void);    // make scheduler run over all processes
  int (*one)(u_proc *);  // schedule for one (new) process
} u_scheduler;


// module prototype
int (*MODULE_INIT)(void);


// global variables
extern GMainLoop *main_loop;
extern GList *filter_list;
extern GKeyFile *config_data;
extern GList* active_users;
extern GHashTable* processes;
extern GNode* processes_tree;
extern lua_State *lua_main_state;
//extern gchar *load_pattern;

// core.c
int load_modules(char *path);
int load_rule_directory(char *path, char *load_pattern);
int load_rule_file(char *name);
int load_lua_rule_file(lua_State *L, char *name);

/* u_proc* u_proc_new(proc_t proc)
 *
 * Allocates a new u_proc structure.
 *
 * @param proc: optional proc_t to copy data from. Will cause state U_PROC_ALIVE.
 * Returns: new allocated u_proc with refcount 1
 */
u_proc* u_proc_new(proc_t *proc);
void cp_proc_t(const struct proc_t *src,struct proc_t *dst);

static inline u_proc *proc_by_pid(int pid) {
  return g_hash_table_lookup(processes, GUINT_TO_POINTER(pid));
}


u_filter *filter_new();
void filter_register(u_filter *filter);
void filter_free(u_filter *filter);
void filter_unregister(u_filter *filter);
void filter_run();
void filter_for_proc(u_proc *proc);

int filter_run_for_proc(gpointer data, gpointer user_data);
void cp_proc_t(const struct proc_t *src, struct proc_t *dst);

// notify system of a new pids/changed/dead pids
int process_new(int pid);
int process_remove(u_proc *proc);
int process_remove_by_pid(int pid);
int process_update_pid(int pid);

int process_update_all();

int scheduler_run_one(u_proc *proc);
int scheduler_run();
int iterate(void *);

int core_init();
void core_unload();

// caches
double get_last_load();
double get_last_percent();




// lua_binding
int l_filter_run_for_proc(u_proc *pr, u_filter *flt);

extern u_scheduler LUA_SCHEDULER;


// sysctrl.c
int ioprio_getpid(pid_t pid, int *ioprio, int *ioclass);
int ioprio_setpid(pid_t pid, int ioprio, int ioclass);
int adj_oom_killer(pid_t pid, int adj);

// group.c
void set_active_pid(unsigned int uid, unsigned int pid);
struct user_active* get_userlist(guint uid, gboolean create);


#endif