/*
    Copyright 2013 ulatencyd developers

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
 *  \file usession.c
 *  \ingroup USession
 */

#include "config.h"

#include "usession-agent.h"

#include "ulatency.h"
#include <glib.h>


/* --- global variables --- */

/**
 * Pointer to the first `USession` instance.
 * You can traverse all the sessions using `USession.next` property.
 *
 * Once a new user session detected, an `USession` instance is created
 * and inserted into the `sessions` list and into the internal hash table that
 * is indexed by the assigned session id. Also the internal table that maps
 * process sgrp to session id is updated.
 *
 * \attention Don't add/delete sessions manually! Use corresponding
 * function from u_session_* family.
 */
USession *U_sessions = NULL;


/* --- private variables --- */

static USession      *session_last    = NULL;  // pointer to last added session
static GHashTable    *sessions_table  = NULL;  // sess_id => USession instance
static GHashTable    *sessid_by_sid   = NULL;  // sid => sess_id
static USessionAgent *u_session_agent = NULL;  // agent in charge


/* --- private functions --- */

// frees all memory of a USession instance, called if the ref counter drops 0
void
u_session_free (void *ptr)
{
  USession *sess = ptr;
  g_assert (sess->ref == 0);

  g_object_unref (sess->proxy);
  g_free (sess->name);
  g_free (sess->X11Display);
  g_free (sess->X11Device);
  g_free (sess->dbus_session);
  g_free (sess->consolekit_cookie);
  if(sess->lua_data) {
    luaL_unref(lua_main_state, LUA_REGISTRYINDEX, sess->lua_data);
  }
  g_free (sess);
}

// called when a USession is freed from the `sessions_table`
// this means that the session is not valid anymore and is
// marked as such, also associated processes are marked as changed
// and forget their session
void
u_session_destroy (USession *sess)
{
  if (sess->id >= USESSION_USER_FIRST)
    u_session_invalidate_by_id (sess->id);

  if (sess->prev)
    sess->prev->next = sess->next;
  else
    {
      g_assert (U_sessions == sess);
      U_sessions = sess->next;
    }

  if (sess->next)
    sess->next->prev = sess->prev;
  else
    {
      g_assert (session_last == sess);
      session_last = sess->prev;
    }

  sess->next = NULL;
  sess->prev = NULL;

  sess->is_valid = FALSE;
  DEC_REF (sess);
}


// return id for the new session, 0 if full
static guint
u_session_generate_id()
{
  static guint last = USESSION_USER_FIRST - 1;
  guint next;

  next = last;
  do
    {
      next++;
      if (next < USESSION_USER_FIRST)
        next = USESSION_USER_FIRST;
    }
  while (G_LIKELY (next != last) &&
         g_hash_table_contains (sessions_table, GUINT_TO_POINTER (next)));

  if G_UNLIKELY (next == last) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "u_session_generate_id() failed: too much sessions");
    return 0;
  }

  last = next;
  return next;
}


/* --- global functions --- */

/**
 * Get #u_proc session identifier
 * @param proc a #u_proc
 *
 * @return session identifier used by ulatencyd
 *
 * @retval #USESSION_UNKNOWN (= 0) on failure or if `proc` is dead
 * @retval #USESSION_KERNEL     if `proc` is a kernel thread
 * @retval #USESSION_INIT       if `proc` is init
 * @retval #USESSION_NONE       if `proc` does not belong to any user session
 * @retval #USESSION_USER_FIRST (or greaer) if `proc` belongs to user session,
 * same as corresponding `USession.id` property.
 */
guint
u_session_id_find_by_proc (u_proc *proc)
{
  guint sess_id; // retval
  pid_t sid;

  if (!u_proc_ensure (proc, BASIC, NOUPDATE) ||
      U_PROC_HAS_STATE (proc, UPROC_DEAD))
    return USESSION_UNKNOWN;

  sid = proc->proc->session;

  sess_id = GPOINTER_TO_UINT (g_hash_table_lookup (sessid_by_sid, GUINT_TO_POINTER(sid)));
  if (sess_id)
    return sess_id;

  if (sid == 0)
    sess_id = USESSION_KERNEL;
  else {
    if (sid == 1)
      sess_id = USESSION_INIT;
  }

  if (!sess_id && sid != proc->pid) /* we want to be in the same session with our sgrp leader */
    {
      u_proc *leader;
      pid_t pgrp;

      leader = proc_by_pid (sid);
      if (leader)
        /* recursive call will add this to the hashtable, so just return */
        return u_session_id_find_by_proc (leader);

      /* if no sgrp leader, try pgrp leader */
      pgrp = proc->proc->pgrp;
      if (pgrp != proc->pid)
        {
          leader = proc_by_pid (pgrp);
          if (leader)
            {
              sess_id = u_session_id_find_by_proc (leader);
            }
          else /* if no pgrp leader, traverse up the process tree */
            {
              GNode *parent_node;

              parent_node = proc->node->parent;
              leader = parent_node->data;
              if (parent_node != processes_tree && /* unless we are init */
                  leader->pid != 1)                /* or its direct child */
                sess_id = u_session_id_find_by_proc (leader);
            }
        }
    }

  if (!sess_id && /* proc is session leader or init child */
        u_session_agent &&
        u_session_agent->u_proc_get_session_id_func)
    sess_id = u_session_agent->u_proc_get_session_id_func (proc);

  g_hash_table_insert (sessid_by_sid, GUINT_TO_POINTER(sid), GINT_TO_POINTER(sess_id));

  return sess_id;
}

/**
 * Returns #USession instance the process belongs to.
 * @param proc #u_proc instance
 *
 * @return user session or NULL
 */
inline USession*
u_session_find_by_proc (u_proc *proc)
{
  guint sess_id;

  sess_id = u_session_id_find_by_proc (proc);
  if (sess_id >= USESSION_USER_FIRST)
    return u_session_find_by_id (sess_id);
  else
    return NULL;
}

/**
 * Returns `USession` instance with given ID.
 * This is faster than walking through the `#sessions` list because it lookups
 * internal hash table indexed by session IDs.
 *
 * @param sess_id `USession.id` of the session which should be returned.
 * @return `USession` instance if found, or NULL if does not exist.
 */
USession *
u_session_find_by_id (guint sess_id)
{
  return (USession *) g_hash_table_lookup (sessions_table,
                                            GUINT_TO_POINTER (sess_id));
}

// GHFunc
static void
change_processs_by_sid (gpointer _pid, gpointer _proc, gpointer sid)
{
  u_proc *proc;

  proc = (u_proc *)_proc;
  if (proc->proc->session == GPOINTER_TO_UINT(sid))
    proc->changed = 1; //FIXME: proc->changed |= U_PROC_CHANGED_?
}

// GHRFunc
static gboolean
change_sgrp_by_session_id (gpointer _sid, gpointer _sess_id, gpointer sess_id)
{
  if (GPOINTER_TO_UINT (_sess_id) == GPOINTER_TO_UINT (sess_id)) {
    g_hash_table_foreach (processes, change_processs_by_sid, _sid);
    return TRUE;
  }

  return FALSE;
}

/**
 * Change all processes that belong to given session.
 *
 * @param sess_id Session ID, any of `USESSION_KERNEL`, `USESSION_INIT`,
 * `USESSION_UNKNOWN`, `USESSION_NONE`,`USESSION_USER_UNKNOWN`,
 * >= `USESSION_USER_FIRST`.
 *
 * Processes that belong to the session will be marked as changed.
 *
 * Usually you want call this with #sess_id >= `USESSION_NONE`
 * for sessions that becomes active or inactive.
 */
void
u_proc_set_changed_by_session_id (guint sess_id)
{
  g_hash_table_foreach (
      sessid_by_sid,
      (GHFunc) change_sgrp_by_session_id,
      GUINT_TO_POINTER (sess_id));
}

/**
 * Invalidate session.
 *
 * @param sess_id Session ID, any of `#USESSION_UNKNOWN`, `#USESSION_NONE`,
 * `#USESSION_USER_UNKNOWN` or >= `#USESSION_USER_FIRST`.
 *
 * Processes that belong to the session will be marked as changed and forget
 * about their session. Next invocation of `u_session_id_find_by_proc()` or
 * one of `u_session_find_by_*()` functions will redetect the process session.
 * `#USession` instances are not affected.
 *
 * Usually you don't want to call this directly.
 */
void
u_session_invalidate_by_id (guint sess_id)
{
  g_hash_table_foreach_remove (
      sessid_by_sid,
      change_sgrp_by_session_id,
      GUINT_TO_POINTER (sess_id));
}

/**
 * Get session leader `u_proc` and ensure `USession.leader_pid` is set.
 *
 * @param session USession instance which leader should be returned.
 *
 * This function stores the leader PID into 'USession.leader_pid' property - if
 * not already set, and if the leader is known and is valid and alive process,
 * returns the corresponding `u_proc` instance.
 *
 * @return leader `u_proc` if known and alive, otherwise NULL
 *
 * @note If a `consolekit` based session tracking agent used, NULL is always
 * returned.
 */
u_proc *
u_session_get_leader (USession *session)
{
  if (!session->leader_pid && u_session_agent &&
      u_session_agent->session_get_leader_pid_func)
    {
      session->leader_pid =
          u_session_agent->session_get_leader_pid_func (session->name);
    }

  if (session->leader_pid)
    {
      u_proc *leader;

      leader = proc_by_pid (session->leader_pid);
      if (leader &&
          U_PROC_IS_VALID (leader) && ! U_PROC_HAS_STATE(leader, UPROC_DEAD))
        {
          return leader;
        }
    }

  return NULL;
}

/* --- functions for agents ---  */

/**
 * Register the session tracking agent to \ref USession subsystem.
 *
 * @param agent_definition Agent definition.
 *
 * Because only one agent may be registered, every agent should check if
 * it is wanted and usable before trying to register. Once an agent is
 * registered, subsequent attempts will fail.
 *
 * @return TRUE on success or FALSE in event of other agent already registered
 * or erroneous definition given.
 */
gboolean
u_session_agent_register (const USessionAgent *agent_definition)
{
  g_return_val_if_fail (agent_definition != NULL &&
                        agent_definition->name != NULL, FALSE);
  if (u_session_agent)
  {
    g_warning ("Cannot register \"%s\" USession agent, "
               "\"%s\" agent already registered.",
               agent_definition->name, u_session_agent->name);
    return FALSE;
  }
  g_return_val_if_fail (sessid_by_sid == NULL &&
                        sessions_table == NULL &&
                        U_sessions == NULL &&
                        session_last == NULL,
                        FALSE);

  u_session_agent = g_new0 (USessionAgent, 1);
  u_session_agent->name = g_strdup (agent_definition->name);
  u_session_agent->session_get_leader_pid_func =
                                agent_definition->session_get_leader_pid_func;
  if (agent_definition->u_proc_get_session_id_func != NULL)
    {
      u_session_agent->u_proc_get_session_id_func =
                                agent_definition->u_proc_get_session_id_func;
    }
  else
    {
    g_warning ("%s: u_session_agent->u_proc_get_session_id_func missing: "
               "processes will not be scheduled according their session.",
               u_session_agent->name);
    }

  sessions_table = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                    NULL, (GDestroyNotify) u_session_destroy);
  sessid_by_sid = g_hash_table_new (g_direct_hash, g_direct_equal);

  return TRUE;
}

/**
 * Register new user session.
 *
 * @param name Unique string the agent will use for identifying the new session,
 * e.g. dbus path to the session object.
 *
 * The session agent **MUST** fill the returned instance of `USession` structure
 * immediately, otherwise the processes may be wrongly scheduled.
 *
 * @return Pointer to new allocated `USession` instance or NULL on failure or
 * if the session already exists.
 */
USession *
u_session_add (const gchar *name)
{
  USession *sess;
  u_proc *leader; // session leader

  if (u_session_find_by_name (name))
    return NULL;

  sess = g_new0 (USession, 1);
  sess->id = u_session_generate_id ();
  if (!sess->id)
    {
      g_free (sess);
      return NULL;
    }
  sess->free_fnk = u_session_free;
  sess->ref = 1;
  sess->name = g_strdup (name);

  if (session_last)
    {
      g_assert (session_last->next == NULL);
      session_last->next = sess;
      sess->prev = session_last;
    }
  else
   {
      g_assert (U_sessions == NULL);
      U_sessions = sess;
   }
  session_last = sess;

  g_hash_table_insert (sessions_table, GUINT_TO_POINTER (sess->id), sess);

  sess->is_valid = TRUE;

  leader = u_session_get_leader (sess);
  if (leader)
    {
      g_hash_table_foreach (processes, change_processs_by_sid,
                            GUINT_TO_POINTER (leader->proc->session));
      //FIXME: leader->changed |= U_PROC_CHANGED_SESSION
      leader->changed = 1;
    }
  else
    {
      u_session_invalidate_by_id (USESSION_NONE);
    }

  return sess;
}

/**
 * Find a `USession` instance which matches the given name.
 * @param name Value of the \ref #USession.name "name" property the `USession`
 * instance must have to be returned.
 * @return `USession` instance or NULL
 */
USession *
u_session_find_by_name (const gchar *name)
{
  USession *sess;

  g_return_val_if_fail (name != NULL, NULL);

  sess = U_sessions;
  while (sess &&
      g_strcmp0 (name, sess->name) != 0)
    sess = sess->next;

  return sess;
}

/**
 * Remove a `USession` which matches the given name from the #sessions list
 * and related hash tables.
 *
 * @param name Value of the \ref #USession.name "name" property the `USession`
 * instance must have to be removed.
 *
 * @note The session will be invalidated (see `u_session_invalidate_by_id()`),
 * which means all left processes will have `u_proc.changed` set and will forget
 * about the session.
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean
u_session_remove_by_name (const gchar *name)
{
  USession *sess;

  sess = u_session_find_by_name (name);
  if (sess)
    return u_session_remove (sess);
  else
    return FALSE;
}

/**
 * Remove given `USession` instance from the #session list and related hash
 * tables.
 *
 * @param `USession` instance to be removed.
 *
 * @note The session will be invalidated (see `u_session_invalidate_by_id()`),
 * which means all left processes will have `u_proc.changed` set and will forget
 * about the session.
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean
u_session_remove (USession *sess)
{
  return g_hash_table_remove (sessions_table, GUINT_TO_POINTER (sess->id));
}

/**
 * Remove a `USession` instance which matches the given ID from the #sessions
 * list and related hash tables.
 *
 * @param name Value of the \ref #USession.id "id" property the `USession`
 * instance must have to be removed.
 *
 * @note The session will be invalidated (see `u_session_invalidate_by_id()`),
 * which means all left processes will have `u_proc.changed` set and will forget
 * about the session.
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean
u_session_remove_by_id (guint sess_id)
{
  return g_hash_table_remove (sessions_table, GUINT_TO_POINTER (sess_id));
}

/**
 * Update active hint for given session.
 *
 * @param sess `USession` instance which \ref #USession.active "active hint"
 * should be updated.
 * @param active New hint value.
 *
 * Beside the own property change other related actions are performed:
 * - disable/enable active list and xwatch polling for affected session.
 * - processes that belongs to the session are marked as changed
 * (#u_proc.changed set)
 * - if the `active` is TRUE, new iteration is scheduled
 */
void
u_session_active_changed (USession *sess,
                         gboolean    active)
{
  sess->active = active;

  // Disable (and clear) or enable list of this user active processes.
  // xwatch will not update X servers of disabled (inactive) users. This is needed
  // to avoid freezes while requesting active atom from Xorg where some application
  // is frozen.

  //FIXME: make xwatch working on real sessions

  GHashTableIter iter;
  gpointer key;
  USession *s;
  gboolean act;

  g_hash_table_iter_init (&iter, sessions_table);
  act = FALSE;
  while (g_hash_table_iter_next (&iter, &key, (gpointer *) &s))
    {
      if(s->uid == sess->uid)
        {
          if(s->active)
            act = TRUE;
        }
    }

  enable_active_list(sess->uid, act);

  //FIXME: u_proc->changed |= U_PROC_CHANGED_SESSION_ACTIVE
  u_proc_set_changed_by_session_id (sess->id);

  if (active)
    {
      g_message ("Active session changed to %s (ID: %d, UID: %d)",
                 sess->name, sess->id, sess->uid);
      // iteration must be run before xwatch poll to avoid freezes on my system
      iteration_request_full(G_PRIORITY_HIGH, 0, TRUE);
    }
  else
    {
      g_message ("Session %s (ID: %d, UID: %d) became inactive.",
                 sess->name, sess->id, sess->uid);
    }
}

/**
 * Update idle hint for given session.
 *
 * @param sess `USession` instance which \ref #USession.idle "idle hint"
 * should be updated.
 * @param active New hint value.
 *
 * Beside the own property change other related actions are performed:
 * - processes that belongs to the session are marked as changed
 * (#u_proc.changed set)
 * - new iteration is scheduled
 */
void
u_session_idle_hint_changed (USession *sess,
                             gboolean   hint)
{
  sess->idle = hint;
  //FIXME: u_proc->changed |= U_PROC_CHANGED_SESSION_IDLE
  u_proc_set_changed_by_session_id (sess->id);
  iteration_request(0);
}
