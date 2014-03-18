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


#define U_LOG_LEVEL_SCHED   1 << 8
#define u_sched(...)    g_log (G_LOG_DOMAIN,         \
                               U_LOG_LEVEL_SCHED,    \
                               __VA_ARGS__)

#define U_LOG_LEVEL_TRACE   1 << 9
#define u_trace(...)    g_log (G_LOG_DOMAIN,         \
                               U_LOG_LEVEL_TRACE,    \
                               __VA_ARGS__)

extern gint U_log_level; //!< Current log level

#ifndef g_info
#define g_info(...)     g_log (G_LOG_DOMAIN,         \
                               G_LOG_LEVEL_INFO,     \
                               __VA_ARGS__)
#endif


#define VERSION 0.5.0+exp0.6.0-pre1

//FIXME enable PROC_FILLSUPGRP once adapted to the new libprocps

#define OPENPROC_FLAGS (PROC_FILLMEM | \
  PROC_FILLUSR | PROC_FILLGRP | PROC_FILLSTATUS | PROC_FILLSTAT | \
  PROC_FILLWCHAN /*| PROC_FILLSUPGRP*/)

#define OPENPROC_FLAGS_MINIMAL (PROC_FILLSTATUS)


#define CONFIG_CORE "core"

#define U_HEAD \
  gint ref; \
  gint unref_forbidden; \
  void (*free_fnk)(void *data);

struct _U_HEAD {
  U_HEAD;
};

/**
 * `printf()` format string determining the #u_proc instance.
 * \see #U_PROC_FORMAT_ARGS(P)
 */
#define U_PROC_FORMAT \
  "u_proc<pid:%d, ppid:%d, euid:%d, ustate:%X, exe:%s, cmdline:%s>"

/**
 * `printf()` arguments for #U_PROC_FORMAT format
 * @param P an #u_proc instance
 */
#define U_PROC_FORMAT_ARGS(P) \
  (P)->pid, (P)->proc->ppid, (P)->proc->euid, (P)->ustate, \
  (P)->exe ? (P)->exe : "??", (P)->cmdline_match ? (P)->cmdline_match : "??"

enum U_PROC_STATE {
  //!< process removed from #processes table and will be freed as soon as
  //!< its reference count drop to zero; implicates #UPROC_VANISHED state
  //!< drop to zero.
  UPROC_INVALID      = (1<<1),
  UPROC_BASIC        = (1<<2),  //!< process has basic properties parsed
  UPROC_HAS_PARENT   = (1<<4),
  UPROC_VANISHED     = (1<<5),  //!< process directory vanished from `/proc/`
  UPROC_ZOMBIE       = (1<<6),  //!< process is a zombie
  //! kernel thread; in rare cases it may be one of not yet detected user space
  //! zombies or already vanished processes (though only root processes).
  //! But it is guaranteed there is no kernel process with UPROC_BASIC but
  //! without UPROC_KERNEL state set.
  UPROC_KERNEL       = (1<<7),
  //! mask for process vanished from `/proc/` and zombies
  UPROC_MASK_DEAD    = UPROC_VANISHED | UPROC_ZOMBIE,
};

#define U_PROC_OK_MASK ~UPROC_INVALID

#define U_PROC_IS_INVALID(P) ( P ->ustate & UPROC_INVALID )
#define U_PROC_IS_VALID(P) ((( P ->ustate & U_PROC_OK_MASK ) & UPROC_INVALID ) == 0)

#define U_PROC_UNSET_STATE(P,STATE) ( P ->ustate = ( P ->ustate & ~( STATE )))
#define U_PROC_HAS_STATE(P,STATE) ( ( P ->ustate & ( STATE )))
#define U_PROC_SET_STATE(P,STATE) ( P ->ustate = ( P ->ustate | ( STATE ) ))


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
  pid_t         fake_sid;   //!< fake value of session
  pid_t         fake_sid_old;

  //! Mask of properties that were already updated since `/proc/PID/` directory
  //! was parsed last time; usually since the current iteration started.
  //! Values are cleared by #update_processes_run() and set/used by
  //! #u_proc_ensure() to determine whether the property should be parsed again.
  //! \see UPDATE_ONCE_PER_RUN
  //! \sa U_PROC_PROPERTIES
  guint ensured_props;

  //! Mask of properties that may be invalid and need to be updated. These
  //! are set if process called a function from `exec()` family and used by
  //! #u_proc_ensure() to determine if the property must be updated even if
  //! update was not requested by the caller.
  //! \sa U_PROC_PROPERTIES
  guint invalid_props;
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


//! Increments reference count of \a P
#define INC_REF(P) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P); \
  uh->ref++; g_assert(uh->ref > 0);} while(0)
//! Increments reference count of \a P
//! and assert the reference count may not drop to zero in future
#define INC_REF_FORBID_UNREF(P) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P); \
  uh->unref_forbidden++; g_assert(uh->unref_forbidden > 0); \
  INC_REF(P);} while(0)
//! Increments reference count of \a P
//! and terminates application if the new reference count is not equal to \a VAL
#define INC_REF_ASSERT_VAL(P, VAL) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P); gint val = (VAL); \
  INC_REF(P); g_assert(uh->ref == val);} while(0)
//! Increments reference count of \a P
//! and terminates application if the new reference count is equal to \a VAL
#define INC_REF_ASSERT_NOT_VAL(P, VAL) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P); gint val = (VAL); \
  DEC_REF(P); g_assert(uh->ref != val1);} while(0)

//! Decrements reference count of \a P; if the reference count drops to zero,
//! free \a P with P->free_fnk
#define DEC_REF(P) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P) ; uh->ref--; \
  g_assert(uh->ref > 0 || (uh->ref == 0 && !uh->unref_forbidden)); \
  if( uh->ref == 0 && uh->free_fnk) { uh->free_fnk( P ); P = NULL; }} while(0)
//! Allows the reference count drop to zero and decrements reference count of
//! \a P; if the reference count drops to zero, free P with P->free_fnk
#define DEC_REF_ALLOW_UNREF(P) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P); \
  uh->unref_forbidden--; g_assert(uh->unref_forbidden >= 0); \
  DEC_REF(P);} while(0)
//! Decrements reference count of \a P unless new count won't be equal to
//! \VAL in which case terminates application
#define DEC_REF_ASSERT_VAL(P, VAL) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P); gint val = (VAL); \
  g_assert(uh->ref == val + 1); DEC_REF(P);} while(0)
//! Decrements reference count of \a P unless new count will be equal to
//! \VAL in which case terminates application
#define DEC_REF_ASSERT_NOT_VAL(P, VAL) \
 do { struct _U_HEAD *uh = (struct _U_HEAD *) (P); gint val = (VAL); \
  g_assert(uh->ref != val + 1); DEC_REF(P);} while(0)

#define FREE_IF_UNREF(P,FNK) if( P ->ref == 0 ) { FNK ( P ); }


#define U_MALLOC(SIZE) g_malloc0(gsize n_bytes);
#define U_FREE(PTR) g_free( PTR );

/*typedef enum {
  NONE = 0,
  REPLACE_SOURCE,
  ADD,
} FLAG_TIMEOUT_BEHAVIOUR;
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
  uint32_t       urgent: 1;     //!< adding/removing the flag will tag the holder (u_proc or system flags) as changed
} u_flag;


u_flag *u_flag_new(u_filter *source, const char *name);
void u_flag_free(void *data);

int u_flag_add(u_proc *proc, u_flag *flag, gint set_changed);
int u_flag_del(u_proc *proc, u_flag *flag, gint set_changed);
int u_flag_clear_source(u_proc *proc, const void *source, gint set_changed);
int u_flag_clear_name(u_proc *proc, const char *name, gint set_changed);
int u_flag_clear_all(u_proc *proc, gint set_changed);
int u_flag_clear_flag(u_proc *proc, const void *flag, gint set_changed);
int u_flag_clear_timeout(u_proc *proc, time_t timeout, gint set_changed);

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

enum USER_ACTIVE_AGENT {       // FIXME remove?
  USER_ACTIVE_AGENT_NONE = 0,
  USER_ACTIVE_AGENT_DISABLED,
  USER_ACTIVE_AGENT_DBUS,
  USER_ACTIVE_AGENT_MODULE=1000,
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

// umodule.c
gboolean u_module_load_directory (char    *modules_directory);
gboolean u_module_close          (GModule *module);
void     u_module_close_me       (GModule *caller);

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
int load_rule_directory(const char *path, const char *load_pattern, int fatal);
int load_rule_file(const char *name);
int load_lua_file(lua_State *L, const char *name);

u_proc* u_proc_new(proc_t *proc);
void cp_proc_t(const struct proc_t *src,struct proc_t *dst);

//! @name Ensure u_proc properties
//! @{

/**
 * Sets of #u_proc properties that are updated as an unit.
 *
 * These are used:
 *  - As argument passed to #u_proc_ensure() to make sure the properties are
 *    available and/or should be updated.
 *  - #u_proc.ensured_props
 *  - #u_proc.invalid_props
 */
enum U_PROC_PROPERTIES {
  BASIC        = (1<<0), //!< all #u_proc properties except those mentioned
                         //!< below
  ENVIRONMENT  = (1<<1), //!< #u_proc.environ
  CMDLINE      = (1<<2), //!< #u_proc.cmdline, #u_proc.cmdline_match,
                         //!< #u_proc.cmdfile
  EXE          = (1<<3), //!< #u_proc.exe
  TASKS        = (1<<4), //!< #u_proc.tasks
  CGROUP       = (1<<5)  //!< #u_proc.cgroup, #u_proc.cgroup_raw and
                         //!< #u_proc.cgroup_origin
};

/**
 * On what conditions #u_proc_ensure() updates #u_proc fields.
 */
enum ENSURE_UPDATE {
  //! do not update fields
  UPDATE_NEVER = -1,
  //! update conditions are selected according the field type
  //! \see #U_PROC_PROPERTIES for more information.
  UPDATE_DEFAULT = 0,
  //! fields are updated unless already set and unless another attempt to update
  //! them occurred since `/proc/<PID>/` directory was parsed last time
  UPDATE_ONCE =  1,
  //! update fields unless an attempt to update them occurred since
  //! `/proc/<PID>/` directory was parsed last time, i.e. since the last time
  //! the process was passed to #update_processes_run()
  UPDATE_ONCE_PER_RUN =  2,
  //! update fields now
  UPDATE_NOW = 3
};

int u_proc_ensure(u_proc *proc, enum U_PROC_PROPERTIES what, enum ENSURE_UPDATE update);

//! @} End of "Ensure #u_proc properties"


void u_proc_set_changed_flag_recursive(u_proc *proc);
void u_proc_clear_changed_flag_recursive(u_proc *proc);
GList *u_proc_list_flags (u_proc *proc, gboolean recrusive);
GArray *u_proc_get_current_task_pids(u_proc *proc);
gboolean u_proc_set_focused (u_proc *proc, time_t timestamp);
guint16 u_proc_get_focus_position (u_proc *proc, gboolean force);



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

/**
 * Returns #u_proc of PID if already known to ulatencyd
 * @param pid PID of process
 * @return #u_proc
 * @retval NULL if process with given \a pid is not in internal #processes hash
 * table, i.e. it was not yet parsed or it is a task not thread leader
 * \see #proc_by_pid_with_retry
 */
static inline u_proc *proc_by_pid(pid_t pid) {
  return g_hash_table_lookup(processes, GUINT_TO_POINTER(pid));
}

/**
 * Returns #u_task of TID if already known to ulatencyd
 * @param tid TID of task
 * @return #u_proc
 * @retval NULL if task with given \a tid is not in internal #tasks hash table,
 * i.e. it was not yes parsed or it is a process (thread leader)
 * \see #proc_by_pid_with_retry
 */
static inline u_task *task_by_tid(pid_t tid) {
  return g_hash_table_lookup(tasks, GUINT_TO_POINTER(tid));
}

u_proc *proc_by_pid_with_retry (pid_t pid);


int scheduler_run_one(u_proc *proc);
int scheduler_run();
u_scheduler *scheduler_get();
int scheduler_set(u_scheduler *scheduler);

extern int iteration_interval;

gboolean iteration_request_full(gint priority, guint milliseconds, gboolean force);
gboolean iteration_request_seconds_full(gint priority, guint seconds);
static inline gboolean iteration_request(guint milliseconds);
static inline gboolean iteration_request_seconds(guint seconds);

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

// sysinfo.c
gchar *      u_pid_read_file (pid_t pid, const char *what, gsize *length) G_GNUC_WARN_UNUSED_RESULT;
GPtrArray *  u_pid_read_0file (pid_t pid, const char *what) G_GNUC_WARN_UNUSED_RESULT;
GHashTable * u_read_env_hash (pid_t pid) G_GNUC_WARN_UNUSED_RESULT;
char *       u_pid_get_env (pid_t pid, const char *var);
GPtrArray *  search_user_env(uid_t uid, const char *name, int update);
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

// linux_netlink.c
extern gboolean netlink_proc_listening; //!< Linux netlink module listening to proc events

#include "uassert.h"

/* --- implemtation --- */

/**
 * Schedule iteration, shortcut to `iteration_request_full()`.
 *
 * Same as calling `iteration_request_full()` with `G_PRIORITY_DEFAULT`+1 priority.
 * `G_PRIORITY_DEFAULT`+1 because we want other events dispatched first.
 */
static inline gboolean
iteration_request(guint milliseconds)
{
  return iteration_request_full (G_PRIORITY_DEFAULT+1, milliseconds, FALSE);
}


/**
 * Schedule iteration with seconds granularity delay, shortcut to `iteration_request_seconds()`.
 *
 * Same as calling `iteration_request_seconds()` with `G_PRIORITY_DEFAULT`+1 priority.
 * `G_PRIORITY_DEFAULT`+1 because we want other events dispatched first.
 */
static inline gboolean
iteration_request_seconds(guint seconds)
{
  return iteration_request_seconds_full (G_PRIORITY_DEFAULT+1, seconds);
}




#endif /* __ulatency_h__ */
