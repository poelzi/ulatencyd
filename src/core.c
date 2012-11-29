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

#define _GNU_SOURCE

#include "config.h"
#include "ulatency.h"

#include <proc/procps.h>
#include <proc/sysinfo.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <fnmatch.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <linux/sched.h>
#include <errno.h>

#ifdef ENABLE_DBUS
#include <dbus/dbus-glib.h>

DBusGConnection *U_dbus_connection;
#endif

lua_State *lua_main_state;
GList *filter_list;
GList *filter_fast_list;
GNode *processes_tree;
GHashTable *processes;
GHashTable *tasks;
u_scheduler scheduler = {NULL};
static int iteration;
static double _last_load;
static double _last_percent;
// flag list of system wide flags
GList *system_flags;
int    system_flags_changed;
// delay rules execution
static long int delay;
static GPtrArray *delay_stack;

// profiling timers
struct u_timer timer_filter;
struct u_timer timer_scheduler;
struct u_timer timer_parse;



// delay new processes

struct delay_proc {
	struct timespec when;
	u_proc  *proc;
};


double get_last_load() {
  return _last_load;
}

double get_last_percent() {
  return _last_percent;
}

guint get_plugin_id() {
  static guint last = USER_ACTIVE_AGENT_MODULE;
  return ++last;
}

/*************************************************************
 * u_task code
 ************************************************************/

/**
 * free u_task instance
 * @param ptr pointer to #u_task
 *
 * frees all memory of a u_task. This function should never be called directly.
 * It as called automatically when the ref counter drops 0
 */

static void u_task_free(void *ptr) {
  u_task *task = ptr;

  g_assert(task->ref == 0);

  // task must be already invalidated
  g_assert(U_TASK_IS_INVALID(task));

  if(task->lua_data) {
    luaL_unref(lua_main_state, LUA_REGISTRYINDEX, task->lua_data);
  }

  g_hash_table_remove(tasks, GUINT_TO_POINTER(task->tid));

  g_slice_free(u_task, task);
}

/**
 * Invalidate the #u_task instance.
 * @param task a #u_task pointer
 *
 * Frees task->task, decrement reference counter for task->proc and set task->proc to NULL.
 */
void u_task_invalidate(u_task *task) {
  if (U_TASK_IS_INVALID(task)) {
    // already invalid
    return;
  }

  freeproc(task->task);
  task->task = NULL;

  DEC_REF(task->proc);
  task->proc = NULL;
}

/**
 * attach task to the process
 * @param proc pointer to #u_proc to which add the task
 * @param t pointer to #proc_t datastructure defining the task
 *
 * If there is no #u_task with the t->tid in the #tasks list, the new #u_task will be allocated
 * (with ref counter 0) and added to the #tasks list. The existing or newly created task will
 * be then attached to the passed #u_proc instance, if not already there, and #u_task ref counter
 * incremented by one.
 *
 * @return newly allocated #u_task reference
 */

u_task* u_proc_add_task(u_proc *proc, proc_t *t) {
  u_task *task;

  // find if the task already exists
  task = g_hash_table_lookup(tasks, GUINT_TO_POINTER(t->tid));

  if (!task) {

    // just create new u_task
    task = g_slice_new0(u_task);
    task->free_fnk = u_task_free;
    g_hash_table_insert(tasks, GUINT_TO_POINTER(t->tid), task);
    g_ptr_array_add(proc->tasks, task);
    task->ref = 1; // tracks only proc->tasks' or lua's references, not references in the task list
  } else {

    // u_task is already in the tasks list
    // assumptions:
    // - any u_task may be attached to at most one u_proc instance at the same time
    // - still our u_task may be attached to a foreign process and be not invalidated, we must handle this

    u_proc *old_proc; // old process containing our u_task
    u_task *cur;
    int i;

    u_task_invalidate(task); //just make sure the task is invalidated (to prevent memleaks)!

    #ifdef DEVELOP_MODE
    // check assumptions - SLOW !!
    GHashTableIter iter;
    gpointer key;
    u_proc *i_proc;
    gboolean found = FALSE;

    g_hash_table_iter_init (&iter, processes);
    while (g_hash_table_iter_next (&iter, &key, (gpointer *) &i_proc))
      {
        if (FALSE == (i_proc->tasks && i_proc->tasks->len))
          continue;
        for(i = 0; i < i_proc->tasks->len; i++) {
          cur = g_ptr_array_index(i_proc->tasks, i);
          if (cur == task || cur->tid == task->tid) {
            g_assert(found == FALSE);
            g_assert(cur == task);
            g_assert(cur->tid == task->tid);
            g_assert(task->proc_pid == i_proc->pid);
            found = TRUE;
          }
        }
      }
    #endif

    old_proc = g_hash_table_lookup(processes, GUINT_TO_POINTER(task->proc_pid));

    if (old_proc != proc) {
      // FIRST, add the task to our process
      g_ptr_array_add(proc->tasks, task);
      INC_REF(task);
      // SECOND (!), remove the task from that other process
      if (old_proc) {
        for(i = 0; i < old_proc->tasks->len; i++) {
          cur = g_ptr_array_index(old_proc->tasks, i);
          if (cur == task) {
            g_ptr_array_remove_index_fast(old_proc->tasks, i);
            break;
          }
        }
      }
    }
  }

  task->tid = t->tid;
  task->proc_pid = proc->pid;

  //the proc should be thread leader
  if (t->tgid != proc->pid) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
          "u_proc_add_task: task (%d: %s) tgid (%d) does not match the process (%d: %s) pid, "
          "this indicates a bug in the code: the thread (task %d) was incorrectly handled as the process (thread leader)",
          t->tid, t->cmd, t->tgid, proc->pid, proc->proc->cmd, proc->pid);
  }

  task->task = t;
  task->proc = proc;
  INC_REF(task->proc); // task holds the proc reference

  return task;
}

/**
 * called when the task is removed from the #u_proc.tasks array.
 * @param ptr a #u_task pointer
 *
 * Invalidates the #u_task (see `u_task_invalidate()`), decrement #u_task reference counter.
 */
static void u_proc_free_task(void *ptr) {
  u_task *task = ptr;
  u_task_invalidate(task);
  DEC_REF(task);
}


/*************************************************************
 * u_proc code
 ************************************************************/

void filter_block_free(gpointer fb) {
  free(fb);
}

void u_head_free(gpointer fb) {
  DEC_REF(fb);
}

/**
 * remove all child nodes
 * @arg proc a #u_proc
 *
 * Unlinks all child nodes from a #u_proc node. Moving them to the parent
 * on @proc and unlinks the node. Makes sure the node is save to remove.
 *
 * @return none
 */

static void u_proc_remove_child_nodes(u_proc *proc) {
  GNode *nparent, *cur;
  u_proc *proc_tmp;
  if(g_node_n_children(proc->node)) {
    // the process which dies has some children. we have to move children
    // to a new parent. Try the parent of the dead process first
    if(proc->node->parent) {
      nparent = proc->node->parent;
    } else {
      proc_tmp = proc_by_pid(1);
      if(proc_tmp && proc_tmp->node) {
        nparent = proc_tmp->node;
      } else {
        // this should not happen, but we have to attach the node somewhere
        // this could happen if the netlink messages arrive befor a fill update
        g_warning("attach child from dead process to root tree");
        nparent = processes_tree;
      }
    }
    g_node_unlink(proc->node);
    g_assert(nparent != proc->node);
    while((cur = g_node_first_child(proc->node)) != NULL) {
      g_node_unlink(cur);
      g_node_append(nparent, cur);
    }
  } else {
    g_node_unlink(proc->node);
  }
}


/**
 * remove pid from delay stack
 * @arg pid #pid_t pid
 *
 * removes process from the delay stack
 *
 * @return none
 */

static void remove_proc_from_delay_stack(pid_t pid) {
  int i = 0;
  struct delay_proc *cur;

  for(i = 0; i < delay_stack->len;) {
      cur = g_ptr_array_index(delay_stack, i);
      if(cur->proc->pid == pid) {
          u_trace("remove delay %d %d:%d", pid, i, delay_stack->len);
          g_ptr_array_remove_index_fast(delay_stack, i);
      } else {
        i++;
      }
  }
}

/**
 * test if pid is in delay stack
 * @arg pid #pid_t pid
 *
 * @return boolean
 */
static int pid_in_delay_stack(pid_t pid) {
  int i = 0;
  struct delay_proc *cur;

  for(i = 0; i < delay_stack->len; i++) {
      cur = g_ptr_array_index(delay_stack, i);
      if(cur->proc->pid == pid)
          return TRUE;
  }
  return FALSE;
}


/**
 * free u_proc instance
 * @arg ptr pointer to #u_proc
 *
 * free's all memory of a u_proc. This function should never be called directly.
 * It as called automaticly when the ref counter drops 0
 *
 * @return none
 */

void u_proc_free(void *ptr) {
  u_proc *proc = ptr;

  g_assert(proc->ref == 0);

  g_free(proc->cmdfile);
  g_free(proc->exe);
  g_free(proc->cmdline_match);
  g_strfreev(proc->cgroup_origin_raw);
  g_strfreev(proc->cgroup_raw);
  if(proc->environ)
      g_hash_table_unref(proc->environ);
  if(proc->cmdline)
      g_ptr_array_unref(proc->cmdline);
  if(proc->cgroup)
      g_hash_table_unref(proc->cgroup);
  if(proc->cgroup_origin)
      g_hash_table_unref(proc->cgroup_origin);


  if(proc->lua_data) {
    luaL_unref(lua_main_state, LUA_REGISTRYINDEX, proc->lua_data);
  }
  g_hash_table_destroy (proc->skip_filter);

  u_flag_clear_all(proc);

  u_proc_remove_child_nodes(proc);

  g_assert(g_node_n_children(proc->node) == 0);
  g_node_destroy(proc->node);
  freeproc(proc->proc);
  g_slice_free(u_proc, proc);
}

/**
 * allocate new #u_proc
 * @arg proc pointer to #proc_t datastructure
 *
 * Allocates a new #u_proc. It can be prefiled with a proc_t datastructure.
 * If \c proc is NULL, the resulting u_proc will have the state UPROC_NEW, otherwise
 * it is UPROC_ALIVE
 *
 * @return newly allocated #u_proc reference
 */

u_proc* u_proc_new(proc_t *proc) {
  u_proc *rv;

  rv = g_slice_new0(u_proc);

  rv->free_fnk = u_proc_free;
  rv->ref = 1;
  rv->skip_filter = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                         NULL, filter_block_free);

  //rv->tasks = g_array_new(FALSE, TRUE, sizeof(proc_t));
  rv->tasks = g_ptr_array_new_with_free_func(u_proc_free_task);
  rv->flags = NULL;
  rv->changed = TRUE;
  rv->node = g_node_new(rv);

  if(proc) {
    rv->pid = proc->tid;
    U_PROC_SET_STATE(rv,UPROC_ALIVE);
    rv->proc = proc;
  } else {
    U_PROC_SET_STATE(rv,UPROC_NEW);
    rv->proc = g_new0(proc_t, 1);
  }

  return rv;
}

/**
 * list all flags from #u_proc
 * @arg proc a #u_proc
 * @arg recrusive boolean if recrusive flags should be returned, too
 *
 * Returns a new allocated GList of all flags. Don't forgett to DECREF the
 * result items and release the list
 *
 * @return @glist
 */

GList *u_proc_list_flags (u_proc *proc, gboolean recrusive) {
  int i = 1;
  u_flag *fl;
  GList *cur, *rv = NULL;

  do {
    cur = g_list_first(proc->flags);
    while(cur) {
      fl = cur->data;
      if(recrusive == 2 && !fl->inherit) {
        cur = g_list_next (cur);
        continue;
      }
      INC_REF(fl);
      rv = g_list_append(rv, fl);
      i++;
      cur = g_list_next (cur);
    }
    if(recrusive) {
      if(!proc->node || !proc->node->parent || proc->node->parent == processes_tree) {
        proc = NULL;
        break;
      }
      proc = (u_proc *)(proc->node->parent->data);
      if(recrusive == 1)
        recrusive = 2;
    }
  } while (recrusive && proc);
  return rv;
}

/**
 * fills all `#u_proc` fields containing information about the process cgroups
 * @param proc[in,out] a #u_proc
 * @param force_update Force `/proc/#/cgroup` parsing
 *
 * Ensures that fields storing the raw cgroups paths are set (`#uproc.cgroup_raw` and `#u_proc.cgroup_origin`).
 * If not or `force_update` requested, fills them with `/proc/#/cgroup` content.
 * Then parse these raw values to `#u_proc.cgroup` and `#u_proc.cgroup_origin` hash tables. Each table item is
 * cgroup path relative to the root of each hierarchy, hashed by the name of the hierarchy subsystem.
 *
 * @retval TRUE if cgroup was set
 * @retval FALSE on failure. `#u_proc.cgroup` will be set to NULL, `#u_proc.cgroup_origin` not touched.
 */
gboolean u_proc_parse_cgroup(u_proc *proc, gboolean force_update) {
  GHashTable *cgroups, *cgroups_origin;
  char       *content;
  char       *path;
  GError     *error = NULL;
  int        i;

  if (proc->cgroup) {
    g_hash_table_unref(proc->cgroup);
    proc->cgroup = NULL;
  }

  if (U_PROC_HAS_STATE(proc, UPROC_DEAD))
    return FALSE;

  //  if needed or requested, read raw values from /proc/#/cgroup into proc->cgroup_raw
  if (!proc->cgroup_raw || force_update) {

    g_strfreev(proc->cgroup_raw);
    proc->cgroup_raw=NULL;

    path = g_strdup_printf ("/proc/%u/cgroup", (guint)proc->pid);

    if(g_file_get_contents(path, &content, NULL, &error)) {
      proc->cgroup_raw = g_strsplit_set(content, "\n", -1);
    } else {
        g_debug("setting state UPROC_DEAD to process - pid: %d", proc->pid);
        U_PROC_SET_STATE(proc, UPROC_DEAD);
        g_error_free(error);
    }

    g_free(path);
    g_free(content);

    if (! proc->cgroup_raw)
      return FALSE;
  }

  // fill proc->cgroup_origin_raw if not already set
  if (!proc->cgroup_origin_raw)
    proc->cgroup_origin_raw = g_strdupv(proc->cgroup_raw);

  /* parse */

  char **lines = proc->cgroup_raw;
  cgroups_origin = NULL;

  cgroups = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  if (!proc->cgroup_origin) {
    cgroups_origin = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  }

  for(i = 0; lines[i]; i++) {
      char **vals;
      vals = g_strsplit (lines[i], ":", 3); // or is regex ^[0-9]+:(.+):(.+) needed?
      if (vals != NULL && g_strv_length(vals) == 3) {
        g_hash_table_insert (cgroups, g_strdup (vals[1]), g_strdup (vals[2]));
        if (cgroups_origin)
          g_hash_table_insert (cgroups_origin, g_strdup (vals[1]), g_strdup (vals[2]));
      }
      g_strfreev (vals);
  }

  if (cgroups_origin)
    proc->cgroup_origin = cgroups_origin;
  if (cgroups) {
    proc->cgroup = cgroups;
    return TRUE;
  }
  return FALSE;
}

/**
 * ensures fields on #u_proc
 * @arg proc a #u_proc
 * @arg what set of varibles to fill from #ENSURE_WHAT
 * @arg update force update
 *
 * Ensures a set of varibles is filled. 
 * If update is true, the variable are updated even if they already exist.
 *
 * @return @success
 */
int u_proc_ensure(u_proc *proc, enum ENSURE_WHAT what, int update) {
  if(what == BASIC) {
    // make sure process has basic values parsed
    if(U_PROC_HAS_STATE(proc,UPROC_BASIC) && !update)
      return TRUE;
    else
      return U_PROC_HAS_STATE(proc, UPROC_DEAD) ? FALSE : process_update_pid(proc->pid);

  } else if(what == TASKS) {
      // FIXME
      return (U_PROC_IS_VALID(proc) ? TRUE : FALSE);
  } else if(what == ENVIRONMENT) {
      if(update && proc->environ) {
          g_hash_table_unref(proc->environ);
          proc->environ = NULL;
      }
      if(!proc->environ)
          proc->environ = U_PROC_HAS_STATE(proc, UPROC_DEAD) ? NULL : u_read_env_hash (proc->pid);
      return (proc->environ != NULL);
  } else if(what == CGROUP) {
      if(update && proc->cgroup) {
          g_hash_table_unref(proc->cgroup);
          proc->cgroup = NULL;
      }
      if(!proc->cgroup && !U_PROC_HAS_STATE(proc, UPROC_DEAD)) {
          u_proc_parse_cgroup(proc, update);
      }
      return (proc->cgroup != NULL);
  } else if(what == CMDLINE) {
      if(update && proc->cmdline) {
          g_ptr_array_unref(proc->cmdline);
          proc->cmdline = NULL;
          if (U_PROC_HAS_STATE(proc, UPROC_DEAD)) {
            g_free(proc->cmdline_match);
            proc->cmdline_match = NULL;
            g_free(proc->cmdfile);
            proc->cmdfile = NULL;
            return FALSE;
          }
      }
      if(!proc->cmdline && !U_PROC_HAS_STATE(proc, UPROC_DEAD)) {
          int i;
          gchar *tmp, *tmp2;

          g_free(proc->cmdline_match);
          proc->cmdline_match = NULL;

          proc->cmdline = u_read_0file (proc->pid, "cmdline");
          // update cmd
          if(proc->cmdline) {
              GString *match = g_string_new("");
              for(i = 0; i < proc->cmdline->len; i++) {
                  if(i)
                      match = g_string_append_c(match, ' ');
                  match = g_string_append(match, g_ptr_array_index(proc->cmdline, i));
              }
              proc->cmdline_match = g_string_free(match, FALSE);
              // empty command line, for kernel threads for example
              if(!proc->cmdline->len)
                return FALSE;
              if(proc->cmdfile) {
                g_free(proc->cmdfile);
                proc->cmdfile = NULL;
              }
              tmp = g_ptr_array_index(proc->cmdline, 0);
              if(tmp) {
                  tmp2 = g_strrstr_len(tmp, -1, "/");
                  if(tmp2 == NULL) {
                    proc->cmdfile = g_strdup(tmp);
                  } else if((tmp2+1-tmp) < strlen(tmp)) {
                    proc->cmdfile = g_strdup(tmp2+1);
                  }
              }
              return TRUE;
          } else {
              return FALSE;
          }
      }
      return (proc->cmdline != NULL);
  } else if(what == EXE) {
      char buf[PATH_MAX+1];
      ssize_t out;
      char *path;
      if(update && proc->exe) {
          g_free(proc->exe);
          proc->exe = NULL;
      }
      if(!proc->exe && !U_PROC_HAS_STATE(proc, UPROC_DEAD)) {
        path = g_strdup_printf ("/proc/%u/exe", (guint)proc->pid);
        out = readlink(path, (char *)&buf, PATH_MAX);
        g_free(path);
        buf[out] = 0;
        if(out > 0) {
            // strip out the ' (deleted)' suffix
            if(out > 10 && !strncmp((char *)&buf[out-10], " (deleted)", 10)) {
                buf[out-10] = 0;
                out -= 10;
            }
            proc->exe = g_strndup((char *)&buf, out);
            return TRUE;
        }
      }
      return (proc->exe != NULL);
  }
  return FALSE;
}


/**
 * up to date list process tasks
 * @arg proc #u_proc to get tasks from
 *
 * Returns a GArray of #pid_t of all tasks from given #u_proc process
 *
 * @return a GArray of #pid_t of all tasks from given #u_proc process
 * @retval NULL if process is dead or `/proc/#/task` could not be read
 */
GArray *u_proc_get_current_task_pids(u_proc *proc) {
    if(U_PROC_HAS_STATE(proc, UPROC_DEAD))
      return NULL;

    GArray *rv = g_array_new(TRUE, TRUE, sizeof(pid_t));

    DIR *dip;
    struct dirent   *dit;
    pid_t tpid;

    char *path = g_strdup_printf("/proc/%d/task", proc->pid);
    dip = opendir(path);

    if(!dip)
        goto out;

    while ((dit = readdir(dip)) != NULL) {
        if(!strcmp(dit->d_name, ".") || !strcmp(dit->d_name, ".."))
            continue;
        tpid = (pid_t)atol(dit->d_name);
        g_array_append_val(rv, tpid);
    }
    closedir(dip);

    g_free(path);
    return rv;
out:
    g_free(path);
    g_array_unref(rv);
    U_PROC_SET_STATE(proc, UPROC_DEAD);
    return NULL;
}

/**
 * free process
 * @arg data a #u_proc pointer
 *
 * INTERNAL: Called when the process is removed from the process_list
 *
 * @return none
 */
static void processes_free_value(gpointer data) {
  // called when a process is freed from the process list
  // this means that the process is not valid anymore and is
  // marked as such
  u_proc *proc = data;
  u_filter *flt;

  U_PROC_UNSET_STATE(proc, UPROC_ALIVE);
  U_PROC_SET_STATE(proc, UPROC_DEAD);

  // run exit hooks
  GList *cur = g_list_first(filter_list);
  while(cur) {
    flt = cur->data;
    if(flt->exit)
      flt->exit(proc, flt);
    cur = cur->next;
  }

  U_PROC_SET_STATE(proc, UPROC_INVALID);
  g_ptr_array_free(proc->tasks, TRUE);
  proc->tasks = NULL;
  u_proc_remove_child_nodes(proc);
  // remove it from the delay stack
  remove_proc_from_delay_stack(proc->pid);

  DEC_REF(proc);
}


static int find_parent_caller_stack(GArray *array, pid_t pid) {
    int i;
    for(i = 0; i < array->len; i++) {
        if(g_array_index(array, pid_t, i) == pid)
            return TRUE;
    }
    return FALSE;
}

static int remove_parent_caller_stack(GArray *array, pid_t pid) {
    int i;
    for(i = 0; i < array->len; i++) {
        if(g_array_index(array, pid_t, i) == pid) {
            g_array_remove_index(array, i);
            return TRUE;
        }
    }
    return FALSE;
}


/**
 * returns the parent of process
 * @arg parent_pid #pid_t of parent
 * @arg child #u_proc of child
 *
 * INTERNAL: lookup the parent #u_proc of a child. Prints warning when missing.
 *
 * @return #u_proc of parent
 */
static inline u_proc *parent_proc_by_pid(pid_t parent_pid, u_proc *child) {
    pid_t update_pid;
    static GArray *updates = NULL;
    if(!updates)
        updates = g_array_new(FALSE, FALSE, sizeof(pid_t));
    u_proc *parent = proc_by_pid(parent_pid);
    // this should't happen, but under fork stress init may not have
    // collected so the parent does not exist, or the parent just died. we try updating
    // the process first and try again.
    if(!parent) {
        g_debug("parent missing: %d, force update", parent_pid);
        if(!find_parent_caller_stack(updates, child->pid)) {
            update_pid = child->pid;
            g_array_append_val(updates, update_pid);
            process_update_pid(update_pid);
            remove_parent_caller_stack(updates, update_pid);
        } else if(!find_parent_caller_stack(updates, child->proc->ppid)) {
            // we try to get the parent as last resort
            update_pid = child->proc->ppid;
            g_array_append_val(updates, update_pid);
            process_update_pid(update_pid);
            remove_parent_caller_stack(updates, update_pid);
        }

        parent = proc_by_pid(child->proc->ppid);
        if(!parent) {
            g_debug("parent missing, second try: %d parent %d", child->pid, child->proc->ppid);
            process_update_pid(child->proc->ppid);
            parent = proc_by_pid(child->proc->ppid);
        }
    }
    if(!parent) {
        g_warning("pid: %d parent %d missing. attaching to pid 1", child->pid, parent_pid);
        return proc_by_pid(1);
    }
    return parent;
}

/**
 * rebuilds the process tree
 *
 * INTERNAL: completly rebuild the process tree. used when a desync is detected
 * on update_processes.
 *
 * @return none
 */
static void rebuild_tree() {
  GHashTableIter iter;
  GList *keys, *cur;
  gpointer key, value;
  u_proc *proc, *parent;

  // clear root node
  g_node_destroy(processes_tree);
  processes_tree = g_node_new(NULL);

  // create nodes first
  g_hash_table_iter_init (&iter, processes);
  while (g_hash_table_iter_next (&iter, &key, &value)) 
  {
    proc = (u_proc *)value;
    proc->node = g_node_new(proc);
    g_node_append(processes_tree, proc->node);
  }

  // now we can lookup the parents and attach the node to the parent
  //g_hash_table_iter_init (&iter, processes);
  keys = g_hash_table_get_keys(processes);
  cur = g_list_first(keys);
  while(cur) 
  {
    proc = (u_proc *)g_hash_table_lookup(processes,cur->data);

    g_assert(proc->proc->ppid != proc->pid);
    if(proc->proc->ppid) {
      // get a parent, hopfully the real one
      parent = parent_proc_by_pid(proc->proc->ppid, proc);

      U_PROC_SET_STATE(proc, UPROC_HAS_PARENT);

      g_assert(parent != proc);
      g_assert(parent && parent->node);
      g_node_unlink(proc->node);
      g_node_append(parent->node, proc->node);
    } else {
      g_node_unlink(proc->node);
      g_node_append(processes_tree, proc->node);

      U_PROC_UNSET_STATE(proc, UPROC_HAS_PARENT);
    }
    cur = cur->next;
  }

  g_list_free(keys);
}

/**
 * detect changes of process
 * @arg old *#proc_t of old values
 * @arg new *#proc_t of new values
 *
 * INTERNAL: detect if the changed values of a u_proc.proc structure are sufficient
 * enough for the #u_proc.changed flag to be set. When the changed flag is set,
 * the scheduler will run again.
 *
 * @return boolean if a major change detected
 */

static int detect_changed(proc_t *old, proc_t *new) {
  // detects changes of main paramenters
  if(old->euid != new->euid || old->session != new->session ||
     old->egid != new->egid || old->pgrp != new->pgrp ||
     old->sched != new->sched || old->rtprio != new->rtprio)
     return 1;
  return 0;
}

/**
 * test if process has changed
 * @arg key unused
 * @arg value #u_proc pointer
 * @arg user_data pointer to int
 *
 * INTERNAL: detect if the process was changed in the last full update run.
 * if not, the process is removed from the process_list
 *
 * @return boolean TRUE if not changed
 */
static gboolean processes_is_last_changed(gpointer key, gpointer value,
                                         gpointer user_data) {
  u_proc *proc = (u_proc *)value;
  int last_changed = *(int *)user_data;
  return (proc->last_update != last_changed);

}

/**
 * remove process
 * @arg proc #u_proc to remove
 *
 * tells the core that a process is not active anymore
 *
 * @return boolean if the process got removed
 */
int process_remove(u_proc *proc) {
  return g_hash_table_remove(processes, GUINT_TO_POINTER(proc->pid));
}

/**
 * remove process by pid
 * @arg proc #pid_t to remove
 *
 * same as process_remove execpt with pid
 *
 * @return boolean if the process got removed
 */
int process_remove_by_pid(pid_t pid) {
  return g_hash_table_remove(processes, GUINT_TO_POINTER(pid));
}

/**
 * clear all changed flags
 *
 * INTERNAL: unset the changed flag. called after a full run.
 *
 * @return none
 */
static void clear_process_changed() {
  GHashTableIter iter;
  gpointer ikey, value;
  u_proc *proc;

  g_hash_table_iter_init (&iter, processes);
  while (g_hash_table_iter_next (&iter, &ikey, &value)) 
  {
    proc = (u_proc *)value;
    proc->changed = FALSE;
  }
  return;
}


// helper for process_clear_filter_block
static gboolean _clear_skip_filters_types(gpointer key, gpointer value, gpointer user_data) {
  struct filter_block *fb = value;
  int *block_type = user_data;

  return !(fb->flags & *block_type);
}

/**
 * clears given skip filters
 *
 * @arg proc #u_proc to change
 * @arg block_types remove the matching block types 
 *
 * clears all filter blocks of given types
 *
 * @return none
 */
void clear_process_skip_filters(u_proc *proc, int block_types) {
  g_hash_table_foreach_remove(proc->skip_filter, 
                              _clear_skip_filters_types,
                              &block_types);

}


// copy the fake value of a parent pid to the child until the real value
// of the child changes from the parent
#define fake_var_fix(FAKE, ORG) \
  if(proc->FAKE && ((proc-> FAKE##_old != proc->proc->ORG) || (proc->FAKE == proc->proc->ORG))) { \
    /* when real value was set, the fake value disapears. */ \
    /*printf("unset fake: %d %d %d %d\n", proc->pid, proc->proc->ORG, proc->FAKE##_old, proc-> FAKE);*/ \
    proc-> FAKE = 0; \
    proc->FAKE##_old = 0; \
    proc->changed = 1; \
  } else if(parent-> FAKE && !proc->FAKE && \
            parent->proc->ORG == proc->proc->ORG && \
            parent-> FAKE != proc->FAKE) { \
    proc-> FAKE = parent->FAKE; \
    proc->FAKE##_old = proc->proc->ORG; \
    proc->changed = 1; \
    /*printf("set fake: pid:%d ppid:%d fake:%d fake_old:%d\n", proc->pid, parent->pid, proc->FAKE, proc->FAKE##_old);*/ \
  }

/**
 * process workarrounds
 * @arg proc #u_proc proc
 * @arg parent #u_proc parent
 *
 * INTERNAL: do workarounds for process parameters that can't be changed in the
 * system but need to for nice grouping.
 *
 * @return boolean if the process got removed
 */
static void process_workarrounds(u_proc *proc, u_proc *parent) {
  // do various workaround jobs here...
  fake_var_fix(fake_pgrp, pgrp);
  fake_var_fix(fake_session, session);
}

#undef fake_var_fix

/**
 * updates processes
 * @arg proctab #PROCTAB 
 * @arg full boolean indicates that a full run is done 
 *
 * parses the /proc filesystem and updates the internal node structure acordingly.
 * This low level function is usually called from wrapper that fill the @proctab
 * accordingly.
 *
 * @return int number of parsed records
 */
int update_processes_run(PROCTAB *proctab, int full) {
  proc_t *p;
  proc_t *t;
  u_proc *proc;
  u_proc *parent;
  u_task *task;
  time_t timeout = time(NULL);
  gboolean full_update = FALSE;
  static int run = 0;
  int rrt;
  int rv = 0;
  int i;
  GList *updated = NULL;
  pid_t *pids = NULL;
  
  if(full)
    run++;

  if(!proctab) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't open /proc");
    return 0;
  }
  if (!full) {
    g_assert(proctab->flags & PROC_PID);
    pids = proctab->pids; // used later do detect dead processes
  }
  while((p = readproc(proctab, NULL))){
    proc = proc_by_pid(p->tid);
    if(proc) {
      // detect change of important parameters that will cause a reschedule
      proc->changed = proc->changed | detect_changed(proc->proc, p);
      // we need to clear the task array first to detect which dynamic mallocs
      // need to be freed as readproc likes to reuse pointers on some dynamic
      // allocations
      if(proc->tasks->len)
        g_ptr_array_foreach(proc->tasks, (GFunc)u_task_invalidate, NULL);
      // free all changable allocated buffers
      freeproc(proc->proc);
      proc->proc = p;
    } else {
      proc = u_proc_new(p);
      g_hash_table_insert(processes, GUINT_TO_POINTER(proc->pid), proc);
    }
    // must still have the process allocated

    if(full)
      proc->last_update = run;

    //save rt received flag
    rrt = proc->received_rt;

    proc->received_rt |= (proc->proc->sched == SCHED_FIFO || proc->proc->sched == SCHED_RR);

    while((t = readtask(proctab,p,NULL))) {
      u_proc_add_task(proc, t);
      proc->received_rt |= (t->sched == SCHED_FIFO || t->sched == SCHED_RR);
    }
    // remove invalid (not readded) tasks
    for(i = 0; i < proc->tasks->len;) {
        task = g_ptr_array_index(proc->tasks, i);
        if(U_TASK_IS_INVALID(task)) {
            u_trace("remove task %d", task->tid);
            g_ptr_array_remove_index_fast(proc->tasks, i);
        } else {
          i++;
        }
    }

    if(rrt != proc->received_rt)
      proc->changed = 1;

    u_proc_ensure(proc, CGROUP, TRUE);

    U_PROC_UNSET_STATE(proc, UPROC_NEW);
    U_PROC_SET_STATE(proc, UPROC_ALIVE);
    if((proctab->flags & OPENPROC_FLAGS) == OPENPROC_FLAGS) {
        U_PROC_SET_STATE(proc, UPROC_BASIC);
    } else
        U_PROC_UNSET_STATE(proc, UPROC_BASIC);

    u_flag_clear_timeout(proc, timeout);
    updated = g_list_append(updated, proc);

    rv++;
  }

  // we update the parent links after all processes are updated
  for(i = 0; i < rv; i++) {
    proc = g_list_nth_data(updated, i);

    if(proc->proc->ppid && proc->proc->ppid != proc->pid) {
      parent = g_hash_table_lookup(processes, GUINT_TO_POINTER(proc->proc->ppid));
      // the parent should exist. in case it is missing we have to run a full
      // tree rebuild then
      if(parent && parent->node) {
        // current parent is not what it should be
        if(proc->node->parent != parent->node) {
          g_node_unlink(proc->node);
          g_node_append(parent->node, proc->node);
        }
        process_workarrounds(proc, parent);
      } else {
        full_update = TRUE;
      }
    } else {
      // this is kinda bad. it is ok for kernel processes and init
      if(proc->node->parent != processes_tree) {
        if(!G_NODE_IS_ROOT(proc->node))
          g_node_unlink(proc->node);
        g_node_append(processes_tree, proc->node);
      }
    }
  }

  if(full) {
    // remove dead processes
    g_hash_table_foreach_remove(processes, 
                                processes_is_last_changed,
                                &run);
  } else {
    // mark dead processes
    while (*pids) {
      proc = proc_by_pid(*pids);
      if (proc && !g_list_find(updated, proc)) {
        g_debug("setting state UPROC_DEAD to process - pid: %d", proc->pid);
        U_PROC_SET_STATE(proc, UPROC_DEAD);
      }
      pids++;
    }
  }
  if(full_update) {
    rebuild_tree();
  }
  g_list_free(updated);
  return rv;
}

/**
 * updates all processes
 *
 * updates all process of the system
 *
 * @return number of process updated
 */
int process_update_all() {
  int rv;
  PROCTAB *proctab;
  proctab = openproc(OPENPROC_FLAGS);
  rv = update_processes_run(proctab, TRUE);
  closeproc(proctab);
  return rv;
}


// calculated the difference between two timespec values
static struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}


/**
 * runs process from delay stack
 *
 * called by timeout to check if processes from the delay stack are old enough
 * to be run through the filters and scheduler
 *
 * @return number of process updated
 */
static int run_new_pid(gpointer ign) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct delay_proc *cur;
    struct timespec td;
    int i;

    GArray *targets = NULL;

    if(!delay_stack->len)
      return TRUE;

    targets = g_array_new(TRUE, FALSE, sizeof(pid_t));

    for(i = 0; i < delay_stack->len;i++) {
        cur = g_ptr_array_index(delay_stack, i);
        td = diff(cur->when, now);
        //printf("test %d  %ld >= %ld\n",  cur->proc->pid, (td.tv_sec * 1000000000 + td.tv_nsec), delay);
        if((td.tv_sec * 1000000000 + td.tv_nsec) >= delay) {
            u_trace("delay stack: run filter for %d", cur->proc->pid);
            g_array_append_val(targets, cur->proc->pid);
            // enforce the scheduler on run when moved from the delay queue
            cur->proc->changed = TRUE;
        }
    }
    process_new_list(targets, TRUE, FALSE);

    // process_new_list removes the entries it processes from the delay stack
    // buf it the process is dead already, they stay here in the list. we make
    // sure they are removed.
    for(i=0; i<targets->len; i++) {
      remove_proc_from_delay_stack(g_array_index(targets, pid_t, i));
    }

    g_array_unref(targets);
    return TRUE;
}


/**
 * adds a new process via delay stack
 * @arg pid new pid to create
 * @arg parent pid of parent process
 *
 * this function creates a delay process. This means that a #u_proc instance is
 * created and linked into the process tree, but the process is not parsed and 
 * the rules and scheduler run on it. If the delay process sticks in the system
 * for the configured "delay" or is updated by the full update in between, the
 * process will be parsed fully and run through the rules and scheduler.
 * This is the prefered way to notifiy the core of new processes as it allows to
 * save cpu time for processes that die very quickly.
 * Passing a parent helps to skip reading basic data from /proc
 * @attention Do not pass threads.
 *
 * @return boolean. TRUE if process could be created.
 */
gboolean process_new_delay(pid_t pid, pid_t parent) {
  u_proc *proc, *proc_parent;
  struct delay_proc *lp;
  g_assert(pid != 0);
  if(!delay) {
      return process_new(pid, TRUE);
  }
  proc = proc_by_pid(pid);
  if(!proc) {
    if(parent) {
      proc = u_proc_new(NULL);
      proc->pid = pid;
      proc->proc->tid = pid;
      proc->proc->ppid = parent;
      U_PROC_SET_STATE(proc, UPROC_HAS_PARENT);
      // put it into the lists
      proc_parent = parent_proc_by_pid(parent, proc);
      g_node_append(proc_parent->node, proc->node);
      g_hash_table_insert(processes, GUINT_TO_POINTER(pid), proc);
    } else {
      if(!process_update_pid(pid))
        return FALSE;  // already dead
      proc = proc_by_pid(pid);
      if(!proc)       // if process_update_pid(pid) was successful, this cannot happen, right?
        return FALSE;
    }
    lp = g_malloc(sizeof(struct delay_proc));
    lp->proc = proc;
    clock_gettime(CLOCK_MONOTONIC, &(lp->when));
    g_ptr_array_add(delay_stack, lp);
    proc->changed = FALSE;
    filter_for_proc(proc, filter_fast_list);
    if(proc->changed) {
      process_run_one(proc, FALSE, FALSE);
      return TRUE;
    }
    proc->changed = TRUE;
  } else {
    // we got a exec event, so the process changed daramaticly.
    // clear all filter blocks that requested rerun on exec
    clear_process_skip_filters(proc, FILTER_RERUN_EXEC);
    // force update on basic data, they will be invalid anyway
    int old_changed = proc->changed;

    u_proc_ensure(proc, CMDLINE, TRUE);
    u_proc_ensure(proc, BASIC, TRUE); //runs process_update_pid()
    u_proc_ensure(proc, EXE, TRUE);

    // if a process is in the new stack, his changed settings will be true
    // for sure, but we only want to schedule him, if the instant filters
    // change something. 
    // if the process is old, we run the filters and let the scheduler decide
    if(pid_in_delay_stack(proc->pid)) {
      proc->changed = FALSE;
      filter_for_proc(proc, filter_fast_list);
      if(proc->changed) {
        process_run_one(proc, FALSE, FALSE);
        return TRUE;
      }
      proc->changed = old_changed;
    } else {
      process_run_one(proc, FALSE, TRUE);
    }
  }

  return TRUE;
}


/**
 * updates list of pids
 * @arg pids #pid_t array
 *
 * Updates a list of processes. The @pids list must be terminated with 0.
 *
 * @return int. number of processes updated
 */
int process_update_pids(pid_t pids[]) {
  int rv;
  PROCTAB *proctab;
  u_timer_start(&timer_parse);
  proctab = openproc(OPENPROC_FLAGS | PROC_PID, pids);
  rv = update_processes_run(proctab, FALSE);
  u_timer_stop(&timer_parse);
  closeproc(proctab);
  return rv;

}

/**
 * updates a single pid
 * @arg pid #pid_t to update
 *
 * Updates a single pid. If you have a list of processes to update, better use
 * process_update_pids
 *
 * @return int. number of processes updated
 */
int process_update_pid(pid_t pid) {
  pid_t pids [2] = { pid, 0 };
  return process_update_pids(pids);
}

/**
 * instant add new process
 * @arg pid #pid_t to update
 * @arg noupdate skip if process already exists
 *
 * Indicates a new process and runs the rules and scheduler on it.
 * @attention Do not pass threads.
 *
 * @return boolean. Sucess
 */
int process_new(int pid, int noupdate) {
  u_proc *proc;
  // if the process is already dead we can exit
  if(noupdate && proc_by_pid(pid))
      return FALSE;
  if(!process_update_pid(pid))
    return FALSE;
  proc = proc_by_pid(pid);
  if(!proc)
    return FALSE;
  process_run_one(proc, FALSE, TRUE);
  return TRUE;
}

/**
 * updates list of processes
 * @param list array of #pid_t
 * @param update boolean, update even if existing
 * @param instant boolean, if instant filters should be run first
 *
 * Indicates a list of new processes and runs the rules and scheduler on it.
 *
 * @return boolean. Success
 */
int process_new_list(GArray *list, int update, int instant) {
  u_proc *proc;
  int i, j = 0;
  pid_t *pids = (pid_t *)malloc((list->len+1)*sizeof(pid_t));
  //int pid_t = malloc(sizeof(pid_t)*(list->len+1));
  for(i = 0; i < list->len; i++) {
    if(update || !proc_by_pid(g_array_index(list,pid_t,i))) {
      pids[j] = g_array_index(list,pid_t,i);
      j++;
    }
  }
  pids[j] = 0;
  // if the process is already dead we can exit
  process_update_pids(pids);
  for(i=0; i < list->len; i++) {
    proc = proc_by_pid(g_array_index(list,pid_t,i));
    if(!proc)
      continue;
    process_run_one(proc, FALSE, instant);
  }
  free(pids);
  return TRUE;
}

/**
 * run filters and scheduler on one process
 * @param proc #u_proc to run
 * @param update boolean: update process before run
 * @param instant boolean: if instant filters should be run too
 *
 * @return boolean. Success
 */
int process_run_one(u_proc *proc, int update, int instant) {
  // remove it from delay stack
  remove_proc_from_delay_stack(proc->pid);

  // update process if requested
  if (update)
    process_update_pid(proc->pid);

  // we must ensure BASIC properties are set and not schedule already dead processes
  if (!u_proc_ensure(proc, BASIC, FALSE) || U_PROC_HAS_STATE(proc, UPROC_DEAD)) {
    // process is dead
    process_remove(proc);
    return FALSE;
  }

  if (instant)
    filter_for_proc(proc, filter_fast_list);
  filter_for_proc(proc, filter_list);
  scheduler_run_one(proc);
  return TRUE;
}


/**
 * free flags
 * @ptr: #u_flag pointer
 *
 * INTERNAL: free a u_flag structure. It is called when the ref count drops 0.
 *
 * @return none
 */
void u_flag_free(void *ptr) {
  u_flag *flag = ptr;

  g_assert(flag->ref == 0);

  if(flag->name)
    g_free(flag->name);
  if(flag->reason)
    g_free(flag->reason);
  g_slice_free(u_flag, flag);
}

/**
 * u_flag_new:
 * @arg source pointer to identify the source
 * @arg name char * name of flag
 *
 * Allocates a new u_flag
 *
 * @return #u_flag pointer
 */
u_flag *u_flag_new(u_filter *source, const char *name) {
  u_flag *rv;

  rv = g_slice_new0(u_flag);

  rv->free_fnk = u_flag_free;
  rv->ref = 1;
  rv->source = source;

  if(name) {
    rv->name = g_strdup(name);
  }

  return rv;
}

/**
 * add flag to process
 * @arg proc #u_proc to add the flag to, or NULL for system flags
 * @arg flag #u_flag to add
 *
 * Adds a new flag to the u_proc or system flag list.
 *
 * @return boolean. TRUE on success.
 */
int u_flag_add(u_proc *proc, u_flag *flag) {
  if(proc) {
    if(!g_list_find(proc->flags, flag)) {
      proc->flags = g_list_insert(proc->flags, flag, 0);
      INC_REF(flag);
    }
    proc->changed = 1;
  } else {
    if(!g_list_find(system_flags, flag)) {
      system_flags = g_list_insert(system_flags, flag, 0);
      INC_REF(flag);
    }
  }
  return TRUE;
}

/**
 * delete flag from process
 * @arg proc #u_proc to remove the flag from, or NULL for system flags
 * @arg flag #u_flag to remove
 *
 * Removes a flag from a process or system flags.
 *
 * @return boolean. TRUE on success.
 */
int u_flag_del(u_proc *proc, u_flag *flag) {
  if(proc) {
    if(g_list_index(proc->flags, flag) != -1) {
      DEC_REF(flag);
    }
    proc->flags = g_list_remove(proc->flags, flag);
    proc->changed = 1;
    return TRUE;
  } else {
    if(g_list_index(system_flags, flag) != -1) {
      DEC_REF(flag);
    }
    system_flags = g_list_remove(system_flags, flag);
    return TRUE;
  }
  return FALSE;
}

static gint u_flag_match_source(gconstpointer a, gconstpointer match) {
  u_flag *flg = (u_flag *)a;

  if(flg->source == match)
    return 0;

  return -1;
}

static gint u_flag_match_flag(gconstpointer a, gconstpointer match) {
  u_flag *flg = (u_flag *)a;

  if(flg == match)
    return 0;

  return -1;
}


static int u_flag_match_name(gconstpointer a, gconstpointer name) {
  u_flag *flg = (u_flag *)a;

  return strcmp(flg->name, (char *)name);
}

static int u_flag_match_timeout(gconstpointer a, gconstpointer time) {
  u_flag *flg = (u_flag *)a;
  time_t t = GPOINTER_TO_UINT(time);
  if(flg->timeout == 0)
    return TRUE;
  return (flg->timeout > t);
}


#define CLEAR_BUILD(NAME, ARG, CMP) \
int NAME (u_proc *proc, ARG ) { \
  GList *item; \
  int rv = 0; \
  while((item = CMP ) != NULL) { \
    if(proc) { \
      proc->flags = g_list_remove_link (proc->flags, item); \
      DEC_REF(item->data); \
      item->data = NULL; \
      proc->changed = 1; \
      rv++; \
      g_list_free(item); \
    } else { \
      system_flags = g_list_remove_link (system_flags, item); \
      DEC_REF(item->data); \
      item->data = NULL; \
      system_flags_changed = 1; \
      rv ++; \
      g_list_free(item); \
    } \
  } \
  return rv; \
} 

CLEAR_BUILD(u_flag_clear_source, const void *var, g_list_find_custom(proc ? proc->flags : system_flags, var, u_flag_match_source))

CLEAR_BUILD(u_flag_clear_name, const char *name, g_list_find_custom(proc ? proc->flags : system_flags, name, u_flag_match_name))

CLEAR_BUILD(u_flag_clear_flag, const void *var, g_list_find_custom(proc ? proc->flags : system_flags, var, u_flag_match_flag))

CLEAR_BUILD(u_flag_clear_timeout, time_t tm, g_list_find_custom(proc ? proc->flags : system_flags, GUINT_TO_POINTER(tm), u_flag_match_timeout))

int u_flag_clear_all(u_proc *proc) {
  GList *item;
  int rv = 0;
  if(proc) {
    while((item = g_list_first(proc->flags)) != NULL) {
      proc->flags = g_list_remove_link (proc->flags, item);
      DEC_REF(item->data);
      item->data = NULL;
      proc->changed = 1;
      rv++;
      g_list_free(item);
    }
    g_list_free(proc->flags);
  } else {
    while((item = g_list_first(system_flags)) != NULL) {
      system_flags = g_list_remove_link(system_flags, item);
      DEC_REF(item->data);
      item->data = NULL;
      g_list_free(item);
      rv++;
      system_flags_changed = 1;
    }
    g_list_free(system_flags);
  }
  return rv;
}


/*************************************************************
 * filter code
 ************************************************************/

void u_filter_free(void *ptr) {
  // FIXME
}

u_filter* filter_new() {
  u_filter *rv = malloc(sizeof(u_filter));
  memset(rv, 0, sizeof(u_filter));
  rv->free_fnk = u_filter_free;
  return rv;
}

void filter_register(u_filter *filter, int instant) {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "register new filter:%s instant:%d", filter->name ? filter->name : "unknown", instant);
  if(instant) {
      filter_fast_list = g_list_append(filter_fast_list, filter);
  } else {
      filter_list = g_list_append(filter_list, filter);
  }
}


int filter_run_for_proc(gpointer data, gpointer user_data) {
  u_proc *proc = data;
  u_filter *flt = user_data;
  struct filter_block *flt_block =NULL;
  int rv = 0;
  time_t ttime = 0;
  int timeout, flags;

  //printf("filter for proc %p\n", flt);

  g_assert(data);

  flt_block = (struct filter_block *)g_hash_table_lookup(proc->skip_filter, GUINT_TO_POINTER(flt));

  //g_hash_table_lookup
  if(flt_block) {
    if(flt_block->flags & FILTER_STOP)
      return 0;
    time (&ttime);
    if(flt_block->timeout > ttime)
      return 0;
  }

  if(flt->check) {
    // if return 0 the real callback will be skipped
    if(!flt->check(proc, flt))
      return 0;
  }

  rv = flt->callback(proc, flt);

  if(rv == 0)
    return rv;

  if(!flt_block) {
    flt_block = malloc(sizeof(struct filter_block));
    memset(flt_block, 0, sizeof(struct filter_block));
    g_hash_table_insert(proc->skip_filter, GUINT_TO_POINTER(flt), flt_block);
  }

  timeout = FILTER_TIMEOUT(rv);
  flags = FILTER_FLAGS(rv);
  if(timeout) {
    if(!ttime)
      time (&ttime);
    flt_block->timeout = ttime + abs(timeout);
  }
  flt_block->flags = flags;

  return rv;
}

static GNode *blocked_parent;

gboolean filter_run_for_node(GNode *node, gpointer data) {
  GNode *tmp;
  int rv;
  
  //u_filter *uf = data;
  //printf("rfn %s ;", uf->name);
  //printf("run for node\n");
  if(node == processes_tree)
    return FALSE;
  if(blocked_parent) {
    do {
      tmp = node->parent;
      if(!tmp)
        break;

      if(tmp == blocked_parent) {
        // we don't run filters on nodes those parent set the skip child flag
        return FALSE;
      } else if (tmp == processes_tree) {
        // we can unset the block, as we must have left all childs
        blocked_parent = NULL;
        break;
      }
    } while(TRUE);
  }
  rv = filter_run_for_proc(node->data, data);

  if(FILTER_FLAGS(rv) & FILTER_SKIP_CHILD) {
    blocked_parent = node;
  }
  return FALSE;
}

int scheduler_run() {
  // FIXME make scheduler more flexible
  if(scheduler.all) {
    return scheduler.all();
  } else {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "no scheduler.all set");
  }
  return 1;
}

int scheduler_run_one(u_proc *proc) {
  // FIXME make scheduler more flexible
  int rv;
  if(scheduler.one) {
    u_timer_start(&timer_scheduler);
    rv = scheduler.one(proc);
    u_timer_stop(&timer_scheduler);
    return rv;
  }
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "no scheduler.one set");
  return 1;
}

void filter_for_proc(u_proc *proc, GList *list) {
  /* run all filters on one proc */
  u_timer_start(&timer_filter);
  GList *cur = g_list_first(list);
  while(cur) {
    filter_run_for_proc(proc, cur->data);
    cur = g_list_next(cur);
  }
  u_timer_stop(&timer_filter);
}


void filter_run() {
  u_filter *flt;
  int i = 0;
  //printf("run filter %p, %d\n", filter_list, g_list_length(filter_list));
  GList *cur;
  if(filter_fast_list) {
    cur = g_list_first(filter_fast_list);
  } else {
    cur = g_list_first(filter_list);
    i=1;
  }
  while(cur) {
    flt = cur->data;
    blocked_parent = NULL;
    if(flt->precheck)
      if(!flt->precheck(flt)) {
        cur = g_list_next(cur);
        continue;
      }
    g_debug("run filter: %s", flt->name);
    //printf("children %d %d\n", g_node_n_children(processes_tree), g_node_n_nodes (processes_tree,G_TRAVERSE_ALL ));
    g_node_traverse(processes_tree, G_PRE_ORDER,G_TRAVERSE_ALL, -1, 
                    filter_run_for_node, flt);

    if(flt->postcheck) {
      flt->postcheck(flt);
    }
    cur = g_list_next(cur);
    if(!cur && i == 0) {
        cur = g_list_first(filter_list);
        i++;
    }

  }
  blocked_parent = NULL;
}

static void update_caches() {
  double a, b;
  
  loadavg(&_last_load, &a, &b);
  _last_percent = (_last_load / (double)smp_num_cpus);

}


int iterate(gpointer rv) {
  time_t timeout = time(NULL);
  GTimer *timer = g_timer_new();
  gdouble last, current, tparse, tfilter, tscheduler;
  gulong dump;

  tparse = g_timer_elapsed(timer_parse.timer, &dump);
  tfilter = g_timer_elapsed(timer_filter.timer, &dump);
  tscheduler = g_timer_elapsed(timer_scheduler.timer, &dump);

  g_debug("spend between iterations: update=%0.2F filter=%0.2F scheduler=%0.2F total=%0.2F", 
          tparse, tfilter, tscheduler, (tparse + tfilter + tscheduler));

  g_timer_start(timer);
  u_flag_clear_timeout(NULL, timeout);
  iteration += 1;
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "start iteration %d:", iteration);
  update_caches();
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "update processes:");

  last = g_timer_elapsed(timer, &dump);
  process_update_all();
  // we can completly clean the delay stack as all processes are now to be scheduled
  if(delay_stack->len)
    g_ptr_array_remove_range(delay_stack, 0, delay_stack->len);
  current = g_timer_elapsed(timer, &dump);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "took %0.2F. run filter:", (current - last));
  last = current;
  filter_run();
  current = g_timer_elapsed(timer, &dump);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "took %0.2F. schedule:", (current - last));
  last = current;
  scheduler_run();
  g_timer_stop(timer);
  current = g_timer_elapsed(timer, &dump);
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "took %0.2F. complete run %d took %0.2F", (current - last), iteration, current);

  clear_process_changed();
  system_flags_changed = 0;
  // g_timer_reset causes strange effects...
  g_timer_destroy(timer);

  u_timer_stop_clear(&timer_parse);
  u_timer_stop_clear(&timer_filter);
  u_timer_stop_clear(&timer_scheduler);

  // try the make current memory non swapalbe
  if(mlockall(MCL_CURRENT) && getuid() == 0)
    g_debug("can't mlock memory");


  return GPOINTER_TO_INT(rv);
}

static int cgroups_cleanup_wrapper(gpointer instant) {
  scheduler.cgroups_cleanup(GPOINTER_TO_INT(instant));
  return FALSE;
}

/**
 * Ask scheduler to remove empty cgroups.
 * @param instant Scheduler does not clean cgroups instantly but set
 * a timeout to avoid overhead. Set this to TRUE if timeout should be avoided.
 * @return FALSE if scheduler does not support cgroups cleaning, otherwise TRUE
 */
int cgroups_cleanup(int instant) {
  if(scheduler.cgroups_cleanup) {
    g_timeout_add(0, cgroups_cleanup_wrapper, GUINT_TO_POINTER(instant));
    return TRUE;
  } else {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "no scheduler.cgroups_cleanup set");
    return FALSE;
  }
}

/***************************************************************************
 * scheduler stuff
 **************************************************************************/

int scheduler_set(u_scheduler *sched) {
  if(sched) {
    memcpy(&scheduler, sched, sizeof(u_scheduler));
  } else {
    memset(&scheduler, 0, sizeof(u_scheduler));
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "unset scheduler");
  }
  return 0;
}

u_scheduler *scheduler_get() {
  return &scheduler;
}



/***************************************************************************
 * rules and modules handling
 **************************************************************************/

int load_rule_directory(const char *path, const char *load_pattern, int fatal) {
  char rpath[PATH_MAX+1];
  gsize  disabled_len;
  int i, j;
  char **disabled;
  char *rule_name = NULL;
  struct stat sb;

  disabled = g_key_file_get_string_list(config_data, CONFIG_CORE,
                                        "disabled_rules", &disabled_len, NULL);


  g_message("load rule directory: %s", path);


  struct dirent **namelist;
  int n;

  n = scandir(path, &namelist, 0, versionsort);
  if (n < 0) {
     perror("scandir");
     g_log(G_LOG_DOMAIN, fatal ? G_LOG_LEVEL_ERROR : G_LOG_LEVEL_WARNING, strerror(errno));
  } else {
     for(i = 0; i < n; i++) {

        if(fnmatch("*.lua", namelist[i]->d_name, 0)) {
          free(namelist[i]);
          continue;
        }
        rule_name = g_strndup(namelist[i]->d_name,strlen(namelist[i]->d_name)-4);
        if(load_pattern && (fnmatch(load_pattern, namelist[i]->d_name, 0) != 0))
          goto skip;

        for(j = 0; j < disabled_len; j++) {
          if(!g_ascii_strcasecmp(disabled[j], rule_name))
            goto skip;
        }

        snprintf(rpath, PATH_MAX, "%s/%s", path, namelist[i]->d_name);
        if (stat(rpath, &sb) == -1)
            goto skip;
        if((sb.st_mode & S_IFMT) != S_IFREG)
            goto next;

        if(load_lua_rule_file(lua_main_state, rpath) && fatal)
          abort();
    next:
        g_free(rule_name);
        rule_name = NULL;

        free(namelist[i]);
        continue;
    skip:
        g_debug("skip rule: %s", namelist[i]->d_name);
        g_free(rule_name);
        rule_name = NULL;

        free(namelist[i]);
     }
     free(namelist);
  }
  g_strfreev(disabled);
  return 0;
}


int load_modules(char *modules_directory) {
  DIR             *dip;
  struct dirent   *dit;
  char rpath[PATH_MAX+1];
  char *minit_name, *module_name, *error;
  char **disabled;
  gsize  disabled_len, i;
  gboolean skip;
  void *handle;
  int (*minit)(void);

  if ((dip = opendir(modules_directory)) == NULL)
  {
    perror("opendir");
    g_warning("Couldn't load modules (directory '%s': %s)", modules_directory, strerror(errno));
    return 0;
  }

  disabled = g_key_file_get_string_list(config_data, CONFIG_CORE,
                                        "disabled_modules", &disabled_len, NULL);

  while ((dit = readdir(dip)) != NULL)
  {
    skip = FALSE;
    if(fnmatch("*.so", dit->d_name, 0))
      continue;

    module_name = g_strndup(dit->d_name,strlen(dit->d_name)-3);

    for(i = 0; i < disabled_len; i++) {
      if(!g_ascii_strcasecmp(disabled[i], module_name)) {
        skip = TRUE;
        break;
      }
    }
    if(!skip) {
      snprintf(rpath, PATH_MAX, "%s/%s", modules_directory, dit->d_name);
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "load module %s", dit->d_name);

      handle = dlopen(rpath, RTLD_LAZY);
      if (!handle) {
        //fprintf(stderr, "%s\n", dlerror());
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't load module %s", rpath);
      }
      dlerror();

      minit_name = g_strconcat(module_name, "_init", NULL);
      *(void **) (&minit) = dlsym(handle, minit_name);

      if ((error = dlerror()) != NULL)  {
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't load module %s: %s", module_name, error);
      }

      if(minit())
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "module %s returned error", module_name);

      free(minit_name);
    } else
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "skip module %s", module_name);

    g_free(module_name);
  }
  g_strfreev(disabled);
  closedir(dip);
  return 1;
}

int luaopen_ulatency(lua_State *L);
int luaopen_bc(lua_State *L);

int u_dbus_setup();


int core_init() {
  // load config
  int i;
  iteration = 1;
  filter_list = NULL;

  smp_num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

  // initialize profiling timer
  timer_filter.timer = g_timer_new();
  timer_filter.count = 0;
  g_timer_stop(timer_filter.timer);
  timer_scheduler.timer = g_timer_new();
  timer_scheduler.count = 0;
  g_timer_stop(timer_scheduler.timer);
  timer_parse.timer = g_timer_new();
  timer_parse.count = 0;
  g_timer_stop(timer_parse.timer);


#ifdef ENABLE_DBUS
  for(i = 1; TRUE; i++) {
    if(u_dbus_setup())
      break;
    else {
      if(i > U_DBUS_RETRY_COUNT) {
        #ifdef DEVELOP_MODE
          g_warning("failed to setup dbus");
          break;
        #else
          g_warning("give up requesting dbus name. exit");
          exit(1);
        #endif
      } else {
          usleep(U_DBUS_RETRY_WAIT);
      }
    }

  }
#endif

#ifdef POLKIT_FOUND
#ifdef POLKIT_HAVE_GET_SYNC
  U_polkit_authority = polkit_authority_get_sync (NULL, NULL);
#else
  U_polkit_authority = polkit_authority_get();
#endif
#endif
  // delay stack 
  delay_stack = g_ptr_array_new_with_free_func(free);
  delay = g_key_file_get_integer(config_data, CONFIG_CORE, "delay_new_pid", NULL);

  processes_tree = g_node_new(NULL);
  processes = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, 
                                    processes_free_value);
  tasks = g_hash_table_new(g_direct_hash, g_direct_equal);

  // configure lua
  lua_main_state = luaL_newstate();
  luaL_openlibs(lua_main_state);
  luaopen_bc(lua_main_state);
  luaopen_ulatency(lua_main_state);
#ifdef LIBCGROUP
  luaopen_cgroup(lua_main_state);
#endif

  // FIXME make it configurable
  scheduler_set(&LUA_SCHEDULER);

  if(load_lua_rule_file(lua_main_state, QUOTEME(LUA_CORE_FILE)))
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't load core library");

  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "core initialized");
  if(delay)
    g_timeout_add((int)(delay / 3), run_new_pid, NULL);
  // we save delay as ns for easier comparison
  delay = delay * 1000000;
  return 1;
}

void core_unload() {
  if(lua_main_state) {
    lua_gc (lua_main_state, LUA_GCCOLLECT, 0);
  }
}

