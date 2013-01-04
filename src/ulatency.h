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

#ifndef __ulatency_h__
#define __ulatency_h__
#include <glib.h>
#include <gio/gio.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <time.h>
#include <stdint.h>
#include <proc/procps.h>
#include <proc/readproc.h>

#ifdef ENABLE_DBUS
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#endif

#ifdef POLKIT_FOUND
#include <polkit/polkit.h>
#endif

//#include <libcgroup.h>


#define U_LOG_LEVEL_SCHED   1 << 8
#define u_sched(...)    g_log (G_LOG_DOMAIN,         \
                               U_LOG_LEVEL_SCHED,    \
                               __VA_ARGS__)

#define U_LOG_LEVEL_TRACE   1 << 9
#define u_trace(...)    g_log (G_LOG_DOMAIN,         \
                               U_LOG_LEVEL_TRACE,    \
                               __VA_ARGS__)


#define VERSION 0.5.0+exp0.6.0-pre1

//FIXME enable PROC_FILLSUPGRP once adapted to the new libprocps

#define OPENPROC_FLAGS (PROC_FILLMEM | \
  PROC_FILLUSR | PROC_FILLGRP | PROC_FILLSTATUS | PROC_FILLSTAT | \
  PROC_FILLWCHAN /*| PROC_FILLSUPGRP*/ | PROC_LOOSE_TASKS)

#define OPENPROC_FLAGS_MINIMAL (PROC_FILLSTATUS)


#define CONFIG_CORE "core"

#define U_HEAD \
  guint ref; \
  void (*free_fnk)(void *data);

struct _U_HEAD {
  U_HEAD;
};

enum U_PROC_STATE {
  UPROC_NEW          = (1<<0),  //!< new process with basic properties not parsed, u_proc.proc is NULL
  UPROC_INVALID      = (1<<1),
  UPROC_BASIC        = (1<<2),  //!< process has basic properties parsed
  UPROC_ALIVE        = (1<<3),
  UPROC_HAS_PARENT   = (1<<4),
  //! Process is dead, but still may have UPROC_NEW or UPROC_ALIVE state.
  //! This is set if the process could not be found in /proc filesystem while trying to update its properties.
  //! Since this, no function accepting #u_proc will try to update its properties.
  UPROC_DEAD         = (1<<5),
};

#define U_PROC_OK_MASK ~UPROC_INVALID

#define U_PROC_IS_INVALID(P) ( P ->ustate & UPROC_INVALID )
#define U_PROC_IS_VALID(P) ((( P ->ustate & U_PROC_OK_MASK ) & UPROC_INVALID ) == 0)

#define U_PROC_SET_STATE(P,STATE) ( P ->ustate = ( P ->ustate | STATE ))
#define U_PROC_UNSET_STATE(P,STATE) ( P ->ustate = ( P ->ustate & ~STATE ))
#define U_PROC_HAS_STATE(P,STATE) ( ( P ->ustate & STATE ) == STATE )


enum FILTER_TYPES {
  FILTER_LUA,
  FILTER_C
};

enum FILTER_FLAGS {
  FILTER_STOP         = (1<<0),
  FILTER_SKIP_CHILD   = (1<<1),
  FILTER_RERUN_EXEC   = (1<<2),
  FILTER_SKIP_THREADS = (1<<3),
};

#define FILTER_TIMEOUT(v) ( v & 0xFFFF)
#define FILTER_FLAGS(v) ( v >> 16)
#define FILTER_MIX(flags,timeout) (( flags << 16 ) | timeout )


enum FILTER_PRIORITIES {
  PRIO_IDLE=-1,
};

// default categories for convinience

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
  GTime timeout;
  int flags;
};

typedef struct {
  gboolean basic;
  gboolean environment;
  gboolean cmdline;
  gboolean exe;
  gboolean tasks;
  gboolean cgroup;
} u_proc_ensured;


typedef struct {
  U_HEAD;
  int           pid;            //!< duplicate of proc.tgid
  int           ustate;         //!< status bits for process
  proc_t       *proc;           //!< main data storage
  char        **cgroup_origin_raw;  //!< the original cgroups this process was created in
  GHashTable   *cgroup_origin;  //!< the original cgroups this process was created in, table of paths indexed by subsystem
  char        **cgroup_raw;     //!< process cgroups
  //! current cgroups, table of paths indexed by subsystem, update with u_proc_ensure(.., CGROUP)
  //! @note cgroup_raw is in field `proc.cgroup`
  GHashTable   *cgroup;
  GArray        proc_history;   //!< list of history elements
  int           history_len;    //!< desigered history len
  guint         last_update;    //!< counter for detecting dead processes
  GNode         *node;          //!< for parent/child lookups and transversal
  GHashTable    *skip_filter;   //!< storage of #filter_block for filters
  GList         *flags;         //!< list of #u_flag
  int           changed;        //!< flags or main parameters of process like uid, gid, sid changed
  int           block_scheduler; //!< indicates that the process should not be touched by the scheduler
  GPtrArray    *tasks;          //!< array of all process tasks of type #u_task
  int           received_rt;    //!< indicates a process had realtime prio at least once

  int           lua_data;       //!< id for per process lua storage
  // we don't use the libproc parsers here as we do not update these values
  // that often
  char          *cmdfile;       //!< basename of exe file
  GPtrArray     *cmdline;       //!< array of char * of cmdline arguments
  char          *cmdline_match; //!< space concated version of cmdline
  GHashTable    *environ;       //!< char *:char * hash table of process environment
  char          *exe;           //!< executeable of the process

  // fake pgid because it can't be changed.
  pid_t         fake_pgrp;      //!< fake value for pgrp
  pid_t         fake_pgrp_old;
  pid_t         fake_session;   //!< fake value of session
  pid_t         fake_session_old;

  u_proc_ensured ensured;       //!< properties ensured since current iteration start
} u_proc;

typedef struct {
  U_HEAD;
  int     tid;        //!< duplicate of task.tid, but available even if the task was invalidated
  u_proc *proc;       //!< process this task belongs to (NULL if the task was invalidated)
  //! PID of process the task is/was attached to. This is duplicate of proc->pid, task->tgid, proc->tgid, proc->tid,
  //! but it is available even if the task is invalidated.
  int     proc_pid;
  proc_t *task;       //!< pointer to #proc_t datastructure (NULL if the task was invalidated)
  int     lua_data;   //!< id for per task lua storage
} u_task;

#ifdef DEVELOP_MODE

static inline gboolean U_TASK_IS_INVALID(u_task *T) {
  if (T->proc) { g_assert(T->task); g_assert(U_PROC_IS_VALID(T->proc)); return FALSE; }
  else { g_assert(T->task == NULL); return TRUE; }
}

static inline gboolean U_TASK_IS_VALID(u_task *T) {
  if (T->proc) { g_assert(T->task); g_assert(U_PROC_IS_VALID(T->proc)); return TRUE; }
  else { g_assert(T->task == NULL); return FALSE; }
}

#else

#define U_TASK_IS_INVALID(T) ( T ->proc == NULL )
#define U_TASK_IS_VALID(T)   ( T ->proc != NULL )

#endif


typedef struct _filter {
  U_HEAD;
  enum FILTER_TYPES type;
  char *name;                                //!< name of filter
  int (*precheck)(struct _filter *filter);
  int (*check)(u_proc *pr, struct _filter *filter);
  int (*postcheck)(struct _filter *filter);
  int (*callback)(u_proc *pr, struct _filter *filter);
  int (*exit)(u_proc *pr, struct _filter *filter);
  void *data;
} u_filter;

#define INC_REF(P) P ->ref++;
#define DEC_REF(P) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) P ; uh->ref--; g_assert(uh->ref >= 0); \
  if( uh->ref == 0 && uh->free_fnk) { uh->free_fnk( P ); P = NULL; }} while(0);

#define FREE_IF_UNREF(P,FNK) if( P ->ref == 0 ) { FNK ( P ); }


#define U_MALLOC(SIZE) g_malloc0(gsize n_bytes);
#define U_FREE(PTR) g_free( PTR );

/*typedef enum {
  NONE = 0,
  REPLACE_SOURCE,
  ADD,
} FLAG_BEHAVIOUR;
*/
typedef struct _FLAG {
  U_HEAD;
  void          *source;       //!< pointer to a data structure that is the "owner"
//  FLAG_BEHAVIOUR age;
  char          *name;         //!< name of the flag, the convention is to use a hierarchy seperated by .
  char          *reason;       //!< why the flag was set. This makes most sense with emergency flags
  int64_t        tid;           //!< task id, if != 0 belongs to a process task
  time_t         timeout;       //!< timeout when the flag will disappear, create it with ulatency.get_time(seconds)
  int32_t        priority;      //!< custom data: priority
  int64_t        value;         //!< custom data: value
  int64_t        threshold;     //!< custom data: threshold
  uint32_t       inherit : 1;      //!< will apply to all children
} u_flag;


u_flag *u_flag_new(u_filter *source, const char *name);
void u_flag_free(void *data);

int u_flag_add(u_proc *proc, u_flag *flag);
int u_flag_del(u_proc *proc, u_flag *flag);
int u_flag_clear_source(u_proc *proc, const void *source);
int u_flag_clear_name(u_proc *proc, const char *name);
int u_flag_clear_all(u_proc *proc);
int u_flag_clear_flag(u_proc *proc, const void *flag);
int u_flag_clear_timeout(u_proc *proc, time_t timeout);

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


struct user_active_process {
  guint pid;
  time_t last_change;
};

enum USER_ACTIVE_AGENT {
  USER_ACTIVE_AGENT_NONE = 0,
  USER_ACTIVE_AGENT_DISABLED,
  USER_ACTIVE_AGENT_DBUS,
  USER_ACTIVE_AGENT_MODULE=1000,
};

// tracking for user sessions
typedef struct {
  gchar     *name;
  gchar     *X11Display;
  gchar     *X11Device;
  // most likely dbus session
  gchar     *dbus_session;
  uid_t     uid;
  uint32_t  idle;
  uint32_t  active;
#ifdef ENABLE_DBUS
  DBusGProxy *proxy;
#endif
} u_session;

// list of active sessions
extern GList *U_session_list;

struct user_active {
  uid_t uid;
  guint max_processes;
  guint active_agent;   // tracker of the active list
  // FIXME: last change time
  time_t last_change;   // time when the last change happend
  GList *actives;       // list of user_active_process
  gboolean enabled;     // if false, ignore this user active list - useful if the user is not active (or frozen)
};


typedef struct {
  int (*all)(void);    //!< make scheduler run over all processes
  int (*one)(u_proc *);  //!< schedule for one (new) process
  int (*cgroups_cleanup)(int instant); //!< schedule empty cgroups removal
  int (*set_config)(char *name);  //!< configure the scheduler for using a different configuration
  char *(*get_config)(void);  //!< returns the name of current config
  GPtrArray *(*list_configs)(void);  //!< returns a list of valid configs
  char *(*get_config_description)(char *name);
} u_scheduler;


// module prototype
int (*MODULE_INIT)(void);


// global variables
extern GMainLoop *main_loop;
extern GList *filter_list;
extern GKeyFile *config_data;
extern GList* active_users;
extern GHashTable* processes;
extern GHashTable* tasks;
extern GNode* processes_tree;
extern lua_State *lua_main_state;
extern GList* system_flags;
extern int    system_flags_changed;
#ifdef ENABLE_DBUS
extern DBusGConnection *U_dbus_connection; // usully the system bus, but may differ on develop mode
extern DBusGConnection *U_dbus_connection_system; // always the system bus

struct callback_data;

struct callback_data {
    GCancellable *cancellable;
    DBusConnection *connection;
    DBusMessage *message;
    void (*callback)(struct callback_data *data);
    void *user_data;
};
#endif
#ifdef POLKIT_FOUND
PolkitAuthority *U_polkit_authority;

int check_polkit(const char *methode,
             DBusConnection *connection,
             DBusMessage *context,
             char *action_id,
             void (*callback)(struct callback_data *data),
             void *user_data,
             int allow_user_interaction,
             u_proc *proc, char *config);
#else
#define check_polkit(...) FALSE
#endif

//extern gchar *load_pattern;

// ulatencyd.c
int fallback_quit(gpointer exit_code);

// core.c
int load_modules(char *path);
int load_rule_directory(const char *path, const char *load_pattern, int fatal);
int load_rule_file(const char *name);
int load_lua_rule_file(lua_State *L, const char *name);

/* u_proc* u_proc_new(proc_t proc)
 *
 * Allocates a new u_proc structure.
 *
 * @param proc: optional proc_t to copy data from. Will cause state U_PROC_ALIVE.
 * Returns: new allocated u_proc with refcount 1
 */
u_proc* u_proc_new(proc_t *proc);
void cp_proc_t(const struct proc_t *src,struct proc_t *dst);


enum ENSURE_WHAT {
  BASIC,
  ENVIRONMENT,
  CMDLINE,
  EXE,
  TASKS,
  CGROUP
};

enum ENSURE_UPDATE {
  NOUPDATE = 0,
  UPDATE_NOW = 1,
  UPDATE_ONCE = 2
};

int u_proc_ensure(u_proc *proc, enum ENSURE_WHAT what, enum ENSURE_UPDATE update);
GList *u_proc_list_flags (u_proc *proc, gboolean recrusive);
GArray *u_proc_get_current_task_pids(u_proc *proc);


u_filter *filter_new();
void filter_register(u_filter *filter, int instant);
void filter_free(u_filter *filter);
void filter_unregister(u_filter *filter);
void filter_run();
void filter_for_proc(u_proc *proc, GList *list);

int filter_run_for_proc(gpointer data, gpointer user_data);
void cp_proc_t(const struct proc_t *src, struct proc_t *dst);

// notify system of a new pids/changed/dead pids
int process_new(pid_t pid, int noupdate);
int process_new_delay(pid_t pid, pid_t parent);
int process_new_list(GArray *list, int noupdate, int instant);
int process_remove(u_proc *proc);
int process_remove_by_pid(pid_t pid);
// low level update api
int process_update_pids(pid_t pids[]);
int process_update_pid(pid_t pid);
int process_run_one(u_proc *proc, int update, int instant);
void clear_process_skip_filters(u_proc *proc, int block_types);

int process_update_all();

static inline u_proc *proc_by_pid(pid_t pid) {
  return g_hash_table_lookup(processes, GUINT_TO_POINTER(pid));
}

static inline u_proc *proc_by_pid_with_retry(pid_t pid) {
  u_proc *proc = g_hash_table_lookup(processes, GUINT_TO_POINTER(pid));
  if(proc)
    return proc;
  if(process_update_pid(pid))
    return g_hash_table_lookup(processes, GUINT_TO_POINTER(pid));
  return NULL;
}

static inline u_task *task_by_tid(pid_t tid) {
  return g_hash_table_lookup(tasks, GUINT_TO_POINTER(tid));
}

int scheduler_run_one(u_proc *proc);
int scheduler_run();
u_scheduler *scheduler_get();
int scheduler_set(u_scheduler *scheduler);

int iterate(void *);

int cgroups_cleanup(int instant);

int core_init();
void core_unload();

// caches
double get_last_load();
double get_last_percent();

// misc stuff
guint get_plugin_id();

// tools.c

struct u_timer {
  GTimer *timer;
  int count;
};

void recursive_rmdir(const char *path, int add_level);
void u_timer_start(struct u_timer *t);
void u_timer_stop(struct u_timer *t);
void u_timer_stop_clear(struct u_timer *t);

// lua_binding
int l_filter_run_for_proc(u_proc *pr, u_filter *flt);

extern u_scheduler LUA_SCHEDULER;


// sysctrl.c
int ioprio_getpid(pid_t pid, int *ioprio, int *ioclass);
int ioprio_setpid(pid_t pid, int ioprio, int ioclass);
int adj_oom_killer(pid_t pid, int adj);
int get_oom_killer(pid_t pid);

// group.c
void set_active_pid(unsigned int uid, unsigned int pid);
struct user_active* get_userlist(guint uid, gboolean create);
int is_active_pid(u_proc *proc);
int get_active_pos(u_proc *proc);
void enable_active_list(guint uid, gboolean enable);
void clear_active_list(guint uid);

// sysinfo.c
GHashTable * u_read_env_hash (pid_t pid);
char *       u_pid_get_env (pid_t pid, const char *var);
GPtrArray *  search_user_env(uid_t uid, const char *name, int update);
GPtrArray *  u_read_0file (pid_t pid, const char *what);
uint64_t     get_number_of_processes();

// dbus consts
#define U_DBUS_SERVICE_NAME     "org.quamquam.ulatencyd"
#define U_DBUS_USER_PATH        "/org/quamquam/ulatencyd/User"
#define U_DBUS_USER_INTERFACE   "org.quamquam.ulatencyd.User"
#define U_DBUS_SYSTEM_PATH      "/org/quamquam/ulatencyd/System"
#define U_DBUS_SYSTEM_INTERFACE "org.quamquam.ulatencyd.System"
#ifdef DEVELOP_MODE
#define U_DBUS_RETRY_COUNT      1
#else
#define U_DBUS_RETRY_COUNT      5
#endif
#define U_DBUS_RETRY_WAIT       500 * 1000

#endif

// linux_netlink.c
extern gboolean netlink_proc_listening; //!< Linux netlink module listening to proc events
