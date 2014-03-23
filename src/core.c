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
#include "usession.h"
#include "ufocusstack.h"
#include "uhook.h"

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

//! seconds between iterations,
//! the change will be effective from the end of next iteration
int iteration_interval;

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

  u_flag_clear_all(proc, FALSE);

  u_proc_remove_child_nodes(proc);

  g_assert(g_node_n_children(proc->node) == 0);
  g_node_destroy(proc->node);
  freeproc(proc->proc);
  g_slice_free(u_proc, proc);
}

/**
 * Allocates a new #u_proc structure.
 * @arg proc optional pointer to #proc_t structure to copy data from.
 *
 * Allocates a new #u_proc. It can be pre-filled with a proc_t structure.
 *
 * @return pointer to newly allocated #u_proc with the reference count set to 1
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
    rv->proc = proc;
  } else {
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
 * Updates #u_proc->cgroup_raw and fills #u_proc->cgroup_origin_raw if not
 * already filled.
 * @param proc an #u_proc
 * @retval TRUE if #u_proc->cgroup_raw has been updated
 */
gboolean
u_proc_update_cgroup_raw (u_proc *proc)
{
  char     *cgroups;

  if (G_UNLIKELY (U_PROC_HAS_STATE (proc, UPROC_VANISHED)))
    return FALSE;

  cgroups = u_pid_read_file (proc->pid, "cgroup", NULL);

  if (G_UNLIKELY (cgroups == NULL))
    {
      /* vanished process */
      if (errno == ENOENT || errno == ESRCH)
        {
          U_PROC_SET_STATE (proc, UPROC_VANISHED);
        }
      /* empty cgroup file - this can never happen */
      else if (errno == EEXIST)
        {
          g_critical ("%s: " U_PROC_FORMAT "Process cgroup file is empty!",
                      G_STRFUNC, U_PROC_FORMAT_ARGS (proc));
        }
      else
        {
          g_critical ("%s: " U_PROC_FORMAT " error %d: %s",
                      G_STRFUNC, U_PROC_FORMAT_ARGS (proc),
                      errno, strerror (errno));
        }
      return FALSE;
    }

  g_strfreev (proc->cgroup_raw);
  proc->cgroup_raw = g_strsplit_set (cgroups, "\n", -1);
  if (proc->cgroup_origin_raw == NULL)
    proc->cgroup_origin_raw = g_strdupv (proc->cgroup_raw);

  g_free (cgroups);

  return TRUE;
}

/**
 * Updates #u_proc->cgroup and related fields; #u_proc_ensure() helper function.
 * \see #u_proc_ensure() for description of its behavior.
 */
gboolean u_proc_update_cgroup(u_proc *proc) {
  GHashTable  *cgroups, *cgroups_origin;
  char       **lines;

  if (G_UNLIKELY (U_PROC_HAS_STATE (proc, UPROC_VANISHED)))
    return proc->cgroup != NULL;

  proc->ensured_props |= CGROUP;

  if (!u_proc_update_cgroup_raw (proc))
    return proc->cgroup != NULL;

  /* parse */

  cgroups = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  if (G_LIKELY (proc->cgroup_origin != NULL))
    cgroups_origin = NULL;
  else
    cgroups_origin = g_hash_table_new_full (g_str_hash,
                                            g_str_equal, g_free, g_free);

  lines = proc->cgroup_raw;
  while (*lines)
    {
      char **vals;
      /*
       * Ulatencyd will not run with multiple subsystems mounted in single
       * hierarchy, so assume in /proc/<pid>/cgroup there is always only one
       * subsys_name on each line <hierarchy_number>:<subsys_name>:<cgroup>
       *
       * Another approach is to use hierarchy_number as index into hash
       * table generated from /proc/cgroups. Would it be faster?
       */
      vals = g_strsplit (*lines, ":", 3);
      if (vals != NULL && g_strv_length(vals) == 3)
        {
          g_hash_table_insert (cgroups, g_strdup (vals[1]), g_strdup (vals[2]));
          if (cgroups_origin)
            g_hash_table_insert (cgroups_origin,
                                 g_strdup (vals[1]), g_strdup (vals[2]));
        }
      g_strfreev (vals);
      lines++;
    }

  if (cgroups_origin)
    proc->cgroup_origin = cgroups_origin;

  if (cgroups)
    {
      if (proc->cgroup != NULL)
        g_hash_table_unref (proc->cgroup);
      proc->cgroup = cgroups;
      return TRUE;
    }
  else
    {
      return proc->cgroup != NULL;
    }
}

/**
 * Updates #u_proc basic fields; #u_proc_ensure() helper function.
 * \see #u_proc_ensure() for description of its behavior.
 */
inline static gboolean
u_proc_update_basic (u_proc *proc)
{
  if (G_UNLIKELY (U_PROC_HAS_STATE (proc, UPROC_VANISHED)))
    return U_PROC_HAS_STATE (proc, BASIC);

  process_update_pid (proc->pid);
  return U_PROC_HAS_STATE (proc, BASIC);
}

/**
 * Updates #u_proc->environ table; #u_proc_ensure() helper function.
 * \see #u_proc_ensure() for description of its behavior.
 */
static gboolean
u_proc_update_environment (u_proc *proc)
{
  GHashTable *env;

  /*
   * Skip vanished, kernel and zombie processes.
   * Kernel and zombie processes have always empty environ file.
   */
  if (U_PROC_HAS_STATE (proc, UPROC_KERNEL | UPROC_MASK_DEAD))
    return proc->environ != NULL;

  proc->ensured_props |= ENVIRONMENT;
  env = u_read_env_hash (proc->pid);

  if (G_UNLIKELY (env == NULL))
    {
      /* vanished process */
      if (errno == ENOENT || errno == ESRCH)
        {
          U_PROC_SET_STATE (proc, UPROC_VANISHED);
        }
      /* empty environ file => it is kernel process or a zombie */
      else if (errno == EEXIST)
        {
          /* test if it is a sure zombie */
          if ((proc->ustate & (UPROC_BASIC | UPROC_KERNEL)) == UPROC_BASIC
               || proc->environ != NULL)
            U_PROC_SET_STATE (proc, UPROC_ZOMBIE);
        }
      else
        {
          g_critical ("%s: " U_PROC_FORMAT " error %d: %s",
                      G_STRFUNC, U_PROC_FORMAT_ARGS (proc),
                      errno, strerror (errno));
        }
      return proc->environ != NULL;
    }

    if (proc->environ != NULL)
      g_hash_table_unref (proc->environ);
    proc->environ = env;

    return TRUE;
}

/**
 * Updates #u_proc->cmdline and related fields; #u_proc_ensure() helper function.
 * \see #u_proc_ensure() for description of its behavior.
 */
static gboolean
u_proc_update_cmdline (u_proc *proc)
{
  GPtrArray  *cmdline;
  gchar      *cmd;
  GString    *match;
  int         i;

  /*
   * Skip vanished, kernel and zombie processes.
   * Kernel and zombie processes have always empty cmdline file.
   */
  if (U_PROC_HAS_STATE (proc, UPROC_MASK_DEAD | UPROC_KERNEL))
    return proc->cmdline && proc->cmdline->len > 0;

  proc->ensured_props |= CMDLINE;

  cmdline = u_pid_read_0file (proc->pid, "cmdline");

  if (G_UNLIKELY (cmdline == NULL))
    {
      /* vanished process */
      if (errno == ENOENT || errno == ESRCH)
        {
          U_PROC_SET_STATE (proc, UPROC_VANISHED);
        }
      /* empty cmdline file => it is kernel process or a zombie */
      else if (errno == EEXIST)
        {
          /* test if it is a sure zombie */
          if ((proc->ustate & (UPROC_BASIC | UPROC_KERNEL)) == UPROC_BASIC
               || (proc->cmdline != NULL && cmdline->len > 0))
            U_PROC_SET_STATE (proc, UPROC_ZOMBIE);
        }
      else
        {
          g_critical ("%s: " U_PROC_FORMAT " error %d: %s",
                      G_STRFUNC, U_PROC_FORMAT_ARGS (proc),
                      errno, strerror (errno));
        }
      return proc->cmdline && proc->cmdline->len > 0;
    }

  if (G_UNLIKELY (cmdline->len == 0))
    {
      /*
       * There was only null byte ('\0').
       * If my understanding is correct, this can never happen.
       */
      g_critical ("%s: " U_PROC_FORMAT
                  "Process cmdline contains only a null byte; "
                  "this is a sign of ulatencyd wrong assumptions.",
                  G_STRFUNC, U_PROC_FORMAT_ARGS (proc));
      g_ptr_array_unref (cmdline);
      return proc->cmdline && proc->cmdline->len > 0;
    }

  if (proc->cmdline != NULL)
    {
      g_ptr_array_unref (proc->cmdline);
      g_assert (proc->cmdline_match != NULL);
      g_assert (proc->cmdfile != NULL);
      g_free (proc->cmdline_match);
      g_free (proc->cmdfile);
    }
  proc->cmdline = cmdline;

  match = g_string_new ("");
  for (i = 0; i < cmdline->len; i++)
    {
      if (i > 0)
          match = g_string_append_c(match, ' ');
      match = g_string_append (match,
                               g_ptr_array_index(cmdline, i));
    }
  proc->cmdline_match = g_string_free (match, FALSE);

  proc->cmdfile = NULL;
  cmd = g_ptr_array_index (proc->cmdline, 0);
  if (cmd)
    {
      gchar *slash;
      slash = g_strrstr_len (cmd, -1, "/");
      if (slash == NULL)
        proc->cmdfile = g_strdup (cmd);
      else if ((slash + 1 - cmd) < strlen(cmd))
        proc->cmdfile = g_strdup (slash + 1);
    }
  if (G_UNLIKELY (proc->cmdfile == NULL))
    proc->cmdfile = g_strdup ("");

  return proc->cmdline->len > 0;
}

/**
 * Updates #u_proc->exe field; #u_proc_ensure() helper function.
 * \see #u_proc_ensure() for description of its behavior.
 */
static gboolean
u_proc_update_exe (u_proc *proc)
{
  char buf[PATH_MAX+1];
  ssize_t out;
  char *path;

  /*
   * Skip vanished, kernel and zombie processes.
   * Kernel and zombie processes have always exe file which cannot be
   * dereferenced.
   */
  if (U_PROC_HAS_STATE (proc, UPROC_MASK_DEAD | UPROC_KERNEL))
    return proc->exe != NULL;

  proc->ensured_props |= EXE;

  path = g_strdup_printf ("/proc/%u/exe", (guint) proc->pid);
  out = readlink (path, (char *) &buf, PATH_MAX);
  if (out < 0)
    {
      if (G_LIKELY (errno == ENOENT || errno == ESRCH))
        {
          /*
           * It's kernel thread, a zombie or the process vanished.
           */
          if ((proc->ustate & (UPROC_BASIC | UPROC_KERNEL)) == UPROC_BASIC
              || proc->exe)
            {
              /*
               * It is not a kernel thread, so it's either zombie or vanished.
               */
              char *pid_dir = g_strdup_printf ("/proc/%u/", (guint) proc->pid);
              if (access(pid_dir, F_OK) == 0)
                U_PROC_SET_STATE (proc, UPROC_ZOMBIE);
              else if (errno == ENOENT)
                U_PROC_SET_STATE (proc, UPROC_VANISHED);
              else
                {
                  g_critical ("%s: " U_PROC_FORMAT " access '%s' error %d: %s",
                              G_STRFUNC, U_PROC_FORMAT_ARGS (proc),
                              pid_dir, errno, strerror(errno));
                }
              g_free (pid_dir);
            }
        }
      else
        {
          g_critical ("%s: " U_PROC_FORMAT " readlink '%s' error %d: %s",
                      G_STRFUNC, U_PROC_FORMAT_ARGS (proc),
                      path, errno, strerror(errno));
        }
      g_free (path);
      return proc->exe != NULL;
   }
  g_free (path);
  buf[out] = 0;

  // strip out the ' (deleted)' suffix
  if (out > 10 && !strncmp ((char *) &buf[out-10], " (deleted)", 10))
    {
      buf[out-10] = 0;
      out -= 10;
    }
  if (G_UNLIKELY (proc->exe ))
    g_free (proc->exe);
  proc->exe = g_strndup((char *)&buf, out);

  return proc->exe != NULL;
}

/**
 * Ensures if a set of #u_proc fields is filled.
 * @param proc   an #u_proc
 * @param what   ensure what fields
 * @param update whether (on what occasions) fields should be updated
 *
 * @retval TRUE if required fields are set
 * @retval FALSE if required fields are not set
 *         (i.e. were __never__ successfully parsed)
 *
 * By calling this function you may ensure whether the set of properties is set
 * and say whether they should be updated first. But you cannot elaborate
 * whether or when they were actually updated or whether the update was
 * successful; only if properties are set at the end.
 * If the properties should be updated but weren't, because the process died,
 * became a zombie, or it is actually a kernel process, you may test #u_proc
 * states /#U_PROC_HAS_STATE()/ which are always set by this function on
 * expected errors. On other (unexpected) errors, there is nothing you can do
 * with it anyway; user has been already informed by critical warning, and the
 * code should continue if older values of properties are available (\c TRUE was
 * returned) or give up if required properties are not set (\c FALSE was
 * returned).
 * \note
 * If called on \a proc with state #UPROC_VANISHED, this function never attempts
 * to update fields, otherwise fields are or are not updated according passed
 * \a update argument.
 * \note
 * In case fields could not be updated as result of an error indicating \a proc
 * is gone, the \a proc state is set to #UPROC_VANISHED; fields preserve their
 * old values until all references to \a proc drop to zero and \a proc is freed.
 * If DEVELOP_MODE is defined, check is made whether \a proc is really not
 * present in `/proc/` directory; critical warning is logged if it still exists,
 * because this indicates wrong ulatencyd assumptions and should be fixed.
 * \note
 * Similar, if an error indicating \a proc is a zombie, its state is set to
 * #UPROC_ZOMBIE, fields preserve their old values and in DEVELOP_MODE test
 * is performed to ensure correctness of the decision.
 * \note In case of other error, fields are preserved too but critical warning
 * is logged, as this is a sign of something went unexpectedly wrong.
 * \note If required update fails and fields do not have old values, i.e. were
 * never successfully updated, \c FALSE is returned and consecutive calls with
 * \a update value #UPDATE_ONCE or #UPDATE_ONCE_PER_RUN are ignored until
 * `/proc/<PID/` directory is parsed again.
 */
gboolean
u_proc_ensure (u_proc                 *proc,
               enum U_PROC_PROPERTIES  what,
               enum ENSURE_UPDATE      update)
{
  if (U_PROC_HAS_STATE(proc, UPROC_VANISHED))
    {
      update = UPDATE_NEVER;
    }
  else if (G_UNLIKELY ((proc->invalid_props & what) && update != UPDATE_NEVER))
    {
      update = UPDATE_NOW;
      proc->invalid_props &= ~what;
    }
  else if (update == UPDATE_DEFAULT)
    {
      switch (what)
      {
        case BASIC:
        case TASKS:
        case ENVIRONMENT:
        case CGROUP:
          update = UPDATE_ONCE_PER_RUN;
          break;

        case CMDLINE:
        case EXE:
          update = UPDATE_ONCE;
          break;
      }
    }

  switch (what)
    {
    case BASIC:
      if (update == UPDATE_NEVER
          || U_PROC_HAS_STATE(proc, UPROC_BASIC))
        return U_PROC_HAS_STATE(proc, UPROC_BASIC);
      else
        return u_proc_update_basic (proc);
      break;

    case TASKS:
      /*
      * Tasks are available for every parsed process, regardless openproc flags,
      * but currently when /proc is parsed it is always opened with
      * OPENPROC_FLAGS, so we may consider TASKS equal to BASIC, except only
      * valid processes have tasks.
      */
      if (U_PROC_HAS_STATE(proc, UPROC_INVALID))
        return FALSE;
      else
        return u_proc_ensure(proc, BASIC, update);
      break;

    case ENVIRONMENT:
      if (update == UPDATE_NEVER
          || (update == UPDATE_ONCE_PER_RUN
              && (proc->ensured_props & ENVIRONMENT))
          || (update == UPDATE_ONCE
              && ((proc->ensured_props & ENVIRONMENT)
                  || proc->environ != NULL)))
        return proc->environ != NULL;
      else
        return u_proc_update_environment (proc);
      break;

    case CGROUP:
      if (update == UPDATE_NEVER
          || (update == UPDATE_ONCE && proc->cgroup != NULL)
          || (update == UPDATE_ONCE_PER_RUN && (proc->ensured_props & CGROUP)))
        {
          return proc->cgroup != NULL;
        }
      else
        {
          return u_proc_update_cgroup (proc);
        }

    case CMDLINE:
      if (update == UPDATE_NEVER
          || (update == UPDATE_ONCE_PER_RUN && (proc->ensured_props & CMDLINE))
          || (update == UPDATE_ONCE
              && ((proc->ensured_props & CMDLINE) || proc->cmdline != NULL)))
        {
          return proc->cmdline != NULL && proc->cmdline->len > 0;
        }
      else
        {
          return u_proc_update_cmdline (proc);
        }
      break;

    case EXE:
      if (update == UPDATE_NEVER
          || (update == UPDATE_ONCE_PER_RUN && (proc->ensured_props & EXE))
          || (update == UPDATE_ONCE
              && ((proc->ensured_props & EXE) || proc->exe != NULL)))
        {
          return proc->exe != NULL;
        }
      else
        {
          return u_proc_update_exe (proc);
        }
      break;

    default:
      return FALSE;
    }
}


/**
 * up to date list process tasks
 * @arg proc #u_proc to get tasks from
 *
 * Returns a GArray of #pid_t of all tasks from given #u_proc process
 *
 * @return a GArray of #pid_t of all tasks from given #u_proc process
 * @retval NULL if process vanished or `/proc/#/task` could not be read
 */
GArray *u_proc_get_current_task_pids(u_proc *proc) {
    if(U_PROC_HAS_STATE(proc, UPROC_VANISHED))
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
    U_PROC_SET_STATE(proc, UPROC_VANISHED);
    return NULL;
}

/**
 * Add process to the focus stack in #USession instance it belongs to.
 *
 * @param proc #u_proc instance
 * @param timestamp (optional) time when the process was focused. If 0, current
 * time will be used.
 *
 * This function adds passed process to focus stack in corresponding #USession
 * instance on position determined by `timestamp`. This means that the process
 * must be member of an user session. The session will be automatically
 * determined.
 *
 * @return TRUE on success; FALSE if the process is not member of
 * any user session or if the process was not added to the stack
 * because its position would be after the #UFocusStack->max_count.
 * \ingroup UProc UFocus
 */
gboolean
u_proc_set_focused (u_proc       *proc,
                    time_t       timestamp)
{
  USession        *session;

  /* checks */
  g_return_val_if_fail (proc, FALSE);
  session = u_session_find_by_proc (proc);
  if (G_UNLIKELY (!session))
    {
      g_warning ("%s: PID %d does not belong to any session.",
                 G_STRFUNC, proc->pid);
      return FALSE;
    }

  if (G_UNLIKELY (session->id < USESSION_USER_FIRST))
    {
      g_warning ("%s: PID %d does not belong to any user session.",
                 G_STRFUNC, proc->pid);
      return FALSE;
    }

  if (G_UNLIKELY (!session->is_valid))
    return FALSE;

  return u_focus_stack_add_pid(session->focus_stack, proc->pid, timestamp);
}

/**
 * Returns process position in focus stack.
 *
 * @param proc process which position should be returned
 * @param force If the session to which the process belongs is not active,
 * this function will return 0 regardless process position, unless `force` is
 * TRUE.
 *
 * @return Process position (>0) or 0 if process is not in user session focus
 * stack or the session is inactive (unless \a force is TRUE)
 */
guint16
u_proc_get_focus_position (u_proc *proc, gboolean force)
{
  USession *session;

  g_return_val_if_fail (proc, FALSE);

  session = u_session_find_by_proc (proc);
  if (G_UNLIKELY( !session || !session->is_valid
                  || session->id < USESSION_USER_FIRST))
    return 0;
  if (session->active || force)
    return u_focus_stack_get_pid_position(session->focus_stack, proc->pid);
  else
    return 0;
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

  U_PROC_SET_STATE(proc, UPROC_VANISHED);

  // run exit hooks
  GList *cur = g_list_first(filter_list);
  while(cur) {
    flt = cur->data;
    if(flt->exit)
      flt->exit(proc, flt);
    cur = cur->next;
  }

  //! [Invoking hooks with feedback.]
  if (U_PROC_HAS_STATE (proc, UPROC_BASIC)
      && u_hook_list_is_setup (U_HOOK_TYPE_PROCESS_EXIT))
    {
      UHookDataProcessExit *data;

      data = (UHookDataProcessExit *) u_hook_list_get_data (
          U_HOOK_TYPE_PROCESS_EXIT);
      data->proc = proc;
      u_hook_list_invoke (U_HOOK_TYPE_PROCESS_EXIT);
      DEC_REF (data);
    }
  //! [Invoking hooks with feedback.]

  U_PROC_SET_STATE(proc, UPROC_INVALID);
  g_ptr_array_free(proc->tasks, TRUE);
  proc->tasks = NULL;
  u_proc_remove_child_nodes(proc);
  // remove it from the delay stack
  remove_proc_from_delay_stack(proc->pid);

  DEC_REF(proc);
}

/**
 * Returns #u_proc of PID or thread leader if PID is a thread (task)
 * @param pid             PID of a process or task
 *
 * @return #u_proc process or thread leader if \a pid is a thread
 * @retval NULL if \a pid vanished from `/proc/` or it is a thread which
 * thread leader does no more exist.
 */
u_proc *proc_by_pid_with_retry (pid_t pid)
{
  u_proc *proc;
  u_task *task;

  if (G_UNLIKELY (pid) <= 0)
    return NULL;

  proc = g_hash_table_lookup (processes, GUINT_TO_POINTER (pid));
  if (proc)
    return proc;

  task = task_by_tid (pid);
  if (task)
    {
      return task->proc;
    }
  else
    {
      pid_t    pids[2] = {pid, 0};
      PROCTAB *proctab;
      proc_t  *p;

      proctab = openproc (PROC_FILLSTATUS | PROC_PID | PROC_LOOSE_TASKS, pids);
      p = readproc (proctab, NULL);
      closeproc (proctab);

      if (!p)
        return NULL; // vanished

      pid = p->tgid;
      pids[0] = pid;
      freeproc (p);

      if (process_update_pids (pids))
        return g_hash_table_lookup(processes, GUINT_TO_POINTER(pid));
      else
        return NULL;
    }
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
 * @arg child_noupdate If TRUE, don't try to update the child (called from update_processes_run)
 *
 * INTERNAL: lookup the parent #u_proc of a child. Prints warning when missing.
 *
 * @return #u_proc of parent
 */
static inline u_proc *parent_proc_by_pid(pid_t parent_pid, u_proc *child, gboolean child_noupdate) {
    pid_t update_pid;
    static GArray *updates = NULL;
    if(!updates)
        updates = g_array_new(FALSE, FALSE, sizeof(pid_t));
    u_proc *parent = proc_by_pid(parent_pid);
    if (parent) {
        return parent;
    } else {
        /*
         * This shouldn't happen, but under fork stress init may not have
         * collected so the parent does not exist, or the parent just died or
         * the parent is a thread. We try updating the process first and try
         * again.
         */
        if(!child_noupdate && !find_parent_caller_stack(updates, child->pid)) {
            // try update the child first, maybe was reparented
            g_debug("child %d parent (%d) missing: force child update", child->pid, parent_pid);
            update_pid = child->pid;
            g_array_append_val(updates, update_pid);
            process_update_pid(update_pid);
            remove_parent_caller_stack(updates, update_pid);
        } else if(!find_parent_caller_stack(updates, child->proc->ppid)) {
            // child updated but the parent is still missing, try update parent
            g_debug("child %d parent (%d) missing: force update parent", child->pid, parent_pid);
            update_pid = child->proc->ppid;
            g_array_append_val(updates, update_pid);
            process_update_pid(update_pid);
            remove_parent_caller_stack(updates, update_pid);
        }

        parent = proc_by_pid(child->proc->ppid);
        if(!parent) {
            g_debug("parent missing, second try: force child update %d parent (%d)", child->pid, child->proc->ppid);
            process_update_pid(child->proc->ppid);
            parent = proc_by_pid(child->proc->ppid);
        }
    }
    if (parent) {
        g_debug("child %d parent found: %d", child->pid, parent->pid);
        return parent;
    } else {
        g_warning("pid: %d parent %d missing. attaching to pid 1", child->pid, parent_pid);
        return proc_by_pid(1);
    }
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

  // could this ever happen?
  g_critical("Process tree is desynchronized, rebuilding.");

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
      parent = parent_proc_by_pid(proc->proc->ppid, proc, FALSE);

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

static int detect_changed(proc_t *old, proc_t *new)
{
  int changed = 0;

  if(old->euid != new->euid || old->session != new->session ||
     old->egid != new->egid || old->pgrp != new->pgrp ||
     old->sched != new->sched || old->rtprio != new->rtprio)
     changed = 1;

  //! [Invoking hooks.]
  if (changed && u_hook_list_is_setup (U_HOOK_TYPE_PROCESS_CHANGED_MAJOR))
    {
      UHookDataProcessChangedMajor *data;

      data = (UHookDataProcessChangedMajor *) u_hook_list_get_data (
          U_HOOK_TYPE_PROCESS_CHANGED_MAJOR);
      data->proc_old = old;
      data->proc_new = new;
      data->changed = changed;
      u_hook_list_invoke (U_HOOK_TYPE_PROCESS_CHANGED_MAJOR);
      changed = data->changed;
      DEC_REF (data);
    }
  //! [Invoking hooks.]

  return changed;
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
  fake_var_fix(fake_sid, session);
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
  gboolean new_proc = FALSE;
  
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
    // skip tasks
    if(p->tid != p->tgid)
      continue;
    proc = proc_by_pid(p->tid);
    if(proc) {
      new_proc = FALSE;
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
      proc->ensured_props = 0;
    } else {
      new_proc = TRUE;
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
    proc->ensured_props |= TASKS;
    // remove invalid (not re-added) tasks
    if (! new_proc) {
      for(i = 0; i < proc->tasks->len;) {
          task = g_ptr_array_index(proc->tasks, i);
          if(U_TASK_IS_INVALID(task)) {
              u_trace("remove task %d", task->tid);
              g_ptr_array_remove_index_fast(proc->tasks, i);
          } else {
            i++;
          }
      }
    }

    if(rrt != proc->received_rt)
      proc->changed = 1;

    if((proctab->flags & OPENPROC_FLAGS) == OPENPROC_FLAGS) {
        /*
         * Test for kernel threads and zombies or dead processes
         */
        U_PROC_SET_STATE(proc, UPROC_BASIC);
        proc->ensured_props |= BASIC;
        if (proc->proc->state == 'Z')
          U_PROC_SET_STATE(proc, UPROC_ZOMBIE);
        else if (proc->proc->vsize == 0) {
          if (proc->proc->euid != 0) {
            /* a zombie or dying */
            U_PROC_SET_STATE(proc, UPROC_ZOMBIE);
          } else {
            /*
             * It may still be a dead or zombie non-kernel process with EUID 0,
             * but it will spook for at most one iteration, so better to live
             * with it.
             */
            U_PROC_SET_STATE(proc, UPROC_KERNEL);
          }
        }
    } else
        U_PROC_UNSET_STATE(proc, UPROC_BASIC);

    if (! new_proc) u_flag_clear_timeout(proc, timeout, -1);
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
          if (proc->node->parent)
            u_trace ("Parent of pid %d changed from %d to %d.",
                     proc->pid, ((u_proc *) proc->node->parent->data)->pid,
                     ((u_proc *) parent->node->data)->pid);
          g_node_unlink(proc->node);
          g_node_append(parent->node, proc->node);
        }
        process_workarrounds(proc, parent);
      } else if (new_proc) {
        parent = parent_proc_by_pid(proc->proc->ppid, proc, TRUE);
        U_PROC_SET_STATE(proc, UPROC_HAS_PARENT);
        g_assert(parent != proc);
        g_assert(parent && parent->node);
        g_node_unlink(proc->node);
        g_node_append(parent->node, proc->node);
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
    // remove vanished processes
    g_hash_table_foreach_remove(processes, 
                                processes_is_last_changed,
                                &run);
  } else {
    // mark vanished processes
    while (*pids) {
      proc = proc_by_pid(*pids);
      if (proc && !g_list_find(updated, proc)) {
        U_PROC_SET_STATE(proc, UPROC_VANISHED);
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
      /*
       * PROC_EVENT_FORK event from netlink
       * or new process from netlink_fallback
       */
      proc = u_proc_new(NULL);
      proc->pid = pid;
      proc->proc->tid = pid;
      proc->proc->ppid = parent;
      U_PROC_SET_STATE(proc, UPROC_HAS_PARENT);
      // put it into the lists
      proc_parent = parent_proc_by_pid(parent, proc, FALSE);
      g_node_append(proc_parent->node, proc->node);
      g_hash_table_insert(processes, GUINT_TO_POINTER(pid), proc);
    } else {
      /*
       * PROC_EVENT_EXEC event from netlink
       */
      if(!process_update_pid(pid))
        return FALSE;  // already dead
      proc = proc_by_pid(pid);
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
    /*
     * PROC_EVENT_EXEC event from netlink
     */
    // we got a exec event, so the process changed daramaticly.
    // clear all filter blocks that requested rerun on exec
    clear_process_skip_filters(proc, FILTER_RERUN_EXEC);
    // force update on basic data, they will be invalid anyway
    int old_changed = proc->changed;

    proc->ensured_props = 0;
    proc->invalid_props |= BASIC | CMDLINE | EXE | CMDLINE;
    u_proc_ensure(proc, BASIC, UPDATE_NOW); //runs process_update_pid()

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
  if(noupdate && proc_by_pid(pid))
      return FALSE;
  // if the process is already dead we can exit
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
  for(i = 0; i < list->len; i++) {
    if(update || !proc_by_pid(g_array_index(list,pid_t,i))) {
      pids[j] = g_array_index(list,pid_t,i);
      j++;
    }
  }
  if (j>0) {
    pids[j] = 0;
    process_update_pids(pids);
  }
  for(i=0; i < list->len; i++) {
    proc = proc_by_pid(g_array_index(list,pid_t,i));
    if(proc) {
      process_run_one(proc, FALSE, instant);
    }
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

  // we must ensure BASIC properties are set and not schedule vanished processes
  if (!u_proc_ensure(proc, BASIC, UPDATE_DEFAULT)
      || U_PROC_HAS_STATE(proc, UPROC_VANISHED))
    goto remove;

  if (instant) {
    filter_for_proc(proc, filter_fast_list);
    if (U_PROC_HAS_STATE(proc, UPROC_VANISHED))
      goto remove;
  }

  filter_for_proc(proc, filter_list);

  if (!U_PROC_HAS_STATE(proc, UPROC_VANISHED)) {
    scheduler_run_one(proc);
    return TRUE;
  }

remove:
  process_remove(proc);
  return FALSE;
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
  rv->urgent = 1;

  if(name) {
    rv->name = g_strdup(name);
  }

  return rv;
}

/**
 * add flag to process or system flags
 * @param proc #u_proc to add the flag to, or NULL for system flags
 * @param flag #u_flag to add
 * @param set_changed If 1, the `system_flags_changed` or `u_proc.changed`
 * variable will be set. If 0, it won't. If -1 the behavior is determined by
 * `u_flag.urgent` value.
 *
 * Adds a new flag to the u_proc or system flag list.
 *
 * @return boolean. TRUE on success.
 */
int u_flag_add(u_proc *proc, u_flag *flag, gint set_changed) {
  if(proc) {
    if(!g_list_find(proc->flags, flag)) {
      proc->flags = g_list_insert(proc->flags, flag, 0);
      INC_REF(flag);
    }
    if (set_changed == 1 || flag->urgent) {
      proc->changed = 1;
      if (flag->inherit) {
        u_proc_set_changed_flag_recursive(proc);
      }
    }
  } else {
    if(!g_list_find(system_flags, flag)) {
      system_flags = g_list_insert(system_flags, flag, 0);
      INC_REF(flag);
      if (set_changed == 1 || flag->urgent) {
        system_flags_changed = 1;
      }
    }
  }
  return TRUE;
}

/**
 * delete flag from process or system flags
 * @param proc #u_proc to remove the flag from, or NULL for system flags
 * @param flag #u_flag to remove
 * @param set_changed If 1, the `system_flags_changed` or `u_proc.changed`
 * variable will be set. If 0, it won't. If -1 the behavior is determined by
 * `u_flag.urgent` value.
 *
 * Removes a flag from a process or system flags.
 *
 * @return boolean. TRUE on success.
 */
int u_flag_del(u_proc *proc, u_flag *flag, gint set_changed) {
  if(proc) {
    if(g_list_index(proc->flags, flag) == -1) {
      return FALSE;
    }
    if (set_changed == 1 || flag->urgent) {
      proc->changed = 1;
      if (flag->inherit) {
        u_proc_set_changed_flag_recursive(proc);
      }
    }
    proc->flags = g_list_remove(proc->flags, flag);
    DEC_REF(flag);
    return TRUE;
  } else {
    if(g_list_index(system_flags, flag) == -1) {
      return FALSE;
    }
    if (set_changed == 1 || flag->urgent) {
      system_flags_changed = 1;
    }
    system_flags = g_list_remove(system_flags, flag);
    DEC_REF(flag);
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

// helper for u_proc_set_changed_flag_recursive / u_proc_clear_changed_flag_recursive
static gboolean _g_node_proc_set_changed_flag(GNode *node, gpointer changed) {
  u_proc *proc = node->data;
  proc->changed = GPOINTER_TO_INT(changed);
  return FALSE;
}

void u_proc_set_changed_flag_recursive(u_proc *proc) {
  g_node_traverse(proc->node, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
      _g_node_proc_set_changed_flag, GUINT_TO_POINTER(1));
}

void u_proc_clear_changed_flag_recursive(u_proc *proc) {
  g_node_traverse(proc->node, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
      _g_node_proc_set_changed_flag, GUINT_TO_POINTER(0));
}

#define CLEAR_BUILD(NAME, ARG, CMP) \
int NAME (u_proc *proc, ARG, gint set_changed) { \
  GList *item; \
  int rv = 0; \
  while((item = CMP ) != NULL) { \
    if(proc) { \
      if (set_changed == 1 || ((u_flag *)item->data)->urgent) { \
        proc->changed = 1; \
        if (((u_flag *)item->data)->inherit) { \
            u_proc_set_changed_flag_recursive(proc); \
        } \
      } \
      proc->flags = g_list_remove_link (proc->flags, item); \
      DEC_REF(item->data); \
      item->data = NULL; \
      rv++; \
      g_list_free(item); \
    } else { \
      system_flags = g_list_remove_link (system_flags, item); \
      DEC_REF(item->data); \
      item->data = NULL; \
      if (set_changed == 1) { \
        system_flags_changed = 1; \
      } \
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

int u_flag_clear_all(u_proc *proc, gint set_changed) {
  GList *item;
  int rv = 0;
  gboolean change_children = FALSE;
  if(proc) {
    while((item = g_list_first(proc->flags)) != NULL) {
      if (set_changed == 1 || ((u_flag *)item->data)->urgent) {
        proc->changed = 1;
        if (((u_flag *)item->data)->inherit) {
          change_children = TRUE;
        }
      }
      proc->flags = g_list_remove_link (proc->flags, item);
      DEC_REF(item->data);
      item->data = NULL;
      rv++;
      g_list_free(item);
    }
    if (change_children) {
      u_proc_set_changed_flag_recursive(proc);
    }
    g_list_free(proc->flags);
  } else {
    while((item = g_list_first(system_flags)) != NULL) {
      system_flags = g_list_remove_link(system_flags, item);
      DEC_REF(item->data);
      item->data = NULL;
      g_list_free(item);
      rv++;
      if (set_changed == 1) {
        system_flags_changed = 1;
      }
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


// iteration requests

static guint iteration_request_id = 0;
static gboolean iteration_request_forced = FALSE;

/**
 * Request iteration.
 *
 * @param priority      the priority of the timeout source. Typically this will
 *                      be `G_PRIORITY_DEFAULT`.
 * @param milliseconds  delay before `iterate()`
 * @param force         If TRUE, further requests will be ignored
 *
 * Use this to request new iteration rather than calling `g_timoute_add_*()`
 * directly. Each request will replace the previous one, unless the previous one
 * was 'forced'.
 *
 * If you do 'forced' request, further requests will be dropped until
 * the forced one is dispatched.
 *
 * @return FALSE if the request was ignored because a pending forced request,
 * otherwise TRUE.
 */
gboolean iteration_request_full(gint priority, guint milliseconds, gboolean force) {
  if (iteration_request_id) {
    if (iteration_request_forced && g_main_context_find_source_by_id(g_main_context_default(), iteration_request_id)) {
      return FALSE;
    }
    // remove scheduled iterations
    g_source_remove(iteration_request_id);
  }
  iteration_request_id = g_timeout_add_full(priority, milliseconds, iterate, GUINT_TO_POINTER(0), NULL);
  iteration_request_forced = force;
  return TRUE;
}

//! Schedule iteration with seconds granularity delay. See `iteration_request_full()`.
gboolean iteration_request_seconds_full(gint priority, guint seconds) {
  if (iteration_request_id) {
    if (iteration_request_forced && g_main_context_find_source_by_id(g_main_context_default(), iteration_request_id)) {
      return FALSE;
    }
    g_source_remove(iteration_request_id);
  }
  iteration_request_id = g_timeout_add_seconds_full(priority, seconds, iterate, GUINT_TO_POINTER(0), NULL);
  iteration_request_forced = FALSE;
  return TRUE;
}

int iterate(gpointer ignored) {
  time_t timeout = time(NULL);
  GTimer *timer = g_timer_new();
  gdouble last, current, tparse, tfilter, tscheduler, thooks;
  gulong dump;

  if (iteration_request_id
      && g_main_context_find_source_by_id (g_main_context_default(),
                                           iteration_request_id))
    {
      g_source_remove (iteration_request_id);
      iteration_request_id = 0;
      iteration_request_forced = FALSE;
    }

  tparse = g_timer_elapsed(timer_parse.timer, &dump);
  tfilter = g_timer_elapsed(timer_filter.timer, &dump);
  tscheduler = g_timer_elapsed(timer_scheduler.timer, &dump);
  thooks = g_timer_elapsed(timer_hooks.timer, &dump);

  g_debug("spend between iterations: update=%0.2F filter=%0.2F scheduler=%0.2F "
          "total=%0.2F (thereof hooks=%0.2F)",
          tparse, tfilter, tscheduler, (tparse + tfilter + tscheduler), thooks);

  g_timer_start(timer);
  u_flag_clear_timeout(NULL, timeout, -1);
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
  u_timer_stop_clear(&timer_hooks);

  // try the make current memory non swapalbe
  if(mlockall(MCL_CURRENT) && getuid() == 0)
    g_debug("can't mlock memory");

  iteration_request_seconds(iteration_interval);
  return FALSE;
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
 * rules handling
 **************************************************************************/

int load_rule_directory(const char *path, const char *load_pattern, int fatal) {
  char rpath[PATH_MAX+1];
  gsize  disabled_len;
  int i, j;
  char **disabled;
  char *rule_name = NULL;
  struct stat sb;
  int errsv;

  disabled = g_key_file_get_string_list(config_data, CONFIG_CORE,
                                        "disabled_rules", &disabled_len, NULL);


  g_message("load rule directory: %s", path);


  struct dirent **namelist;
  int n;

  n = scandir(path, &namelist, 0, versionsort);
  if (n < 0) {
     errsv = errno;
     perror("scandir");
     g_log(G_LOG_DOMAIN, fatal ? G_LOG_LEVEL_ERROR : G_LOG_LEVEL_WARNING,
         "cannot load rule directory '%s': %s", path, g_strerror(errsv));
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

        if(load_lua_file(lua_main_state, rpath) && fatal)
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

LUALIB_API int luaopen_ulatency  (lua_State *L);
LUALIB_API int luaopen_u_proc    (lua_State *L);
LUALIB_API int luaopen_u_task    (lua_State *L);
LUALIB_API int luaopen_u_session (lua_State *L);
LUALIB_API int luaopen_u_flag    (lua_State *L);

int u_dbus_setup();


int core_init() {
  // load config
  int i;
  iteration = 0;
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
  if (lua_main_state) {
      luaL_openlibs(lua_main_state);

      lua_pushcfunction(lua_main_state, luaopen_ulatency);
      lua_pushstring(lua_main_state, "ulatency");
      lua_call(lua_main_state, 1, 0);

      lua_pushcfunction(lua_main_state, luaopen_u_proc);
      lua_pushstring(lua_main_state, "U_PROC");
      lua_call(lua_main_state, 1, 0);

      lua_pushcfunction(lua_main_state, luaopen_u_task);
      lua_pushstring(lua_main_state, "U_TASK");
      lua_call(lua_main_state, 1, 0);

      lua_pushcfunction(lua_main_state, luaopen_u_session);
      lua_pushstring(lua_main_state, "U_SESSION");
      lua_call(lua_main_state, 1, 0);

      lua_pushcfunction(lua_main_state, luaopen_u_flag);
      lua_pushstring(lua_main_state, "U_FLAG");
      lua_call(lua_main_state, 1, 0);
  } else {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't open lua libraries");
  }



  // FIXME make it configurable
  scheduler_set(&LUA_SCHEDULER);

  if(load_lua_file(lua_main_state, QUOTEME(LUA_CORE_DIR) "/bootstrap.lua"))
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR,
        "Can't load " QUOTEME(LUA_CORE_DIR) "/bootstrap.lua");

  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "core initialized");
  if(delay)
    g_timeout_add((int)(delay / 3), run_new_pid, NULL);
  // we save delay as ns for easier comparison
  delay = delay * 1000000;

  //subsystems initialization
  u_hook_init();
  u_session_init();

  return 1;
}

void core_unload() {
  if(lua_main_state) {
    lua_gc (lua_main_state, LUA_GCCOLLECT, 0);
  }
}

