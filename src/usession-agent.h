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
 *  \file usession-agent.h
 *  \ingroup USession-agent-api
 *  \brief \ref USession interface session tracking for agents.
 *
 *  The purpose of this header is to allow session tracking agents such as
 *  `consolekit` or `systemd-logind` to use and register with
 *  \ref USession system.
 */

#ifndef __U_SESSION_AGENT_H__
#define __U_SESSION_AGENT_H__

#include "ulatency.h"
#include <glib.h>

/*! \addtogroup USession-agent-api
 *  @{
 */

/**
 * Session agent function that should return \ref #USession.id "session id"
 * of given process.
 *
 * @param proc Process for which the session ID is requested.
 *
 * @return Session ID
 * @retval #USESSION_UNKNOWN (= 0) on failure or if `proc` is dead
 * @retval #USESSION_KERNEL     if `proc` is a kernel thread
 * @retval #USESSION_INIT       if `proc` is init
 * @retval #USESSION_NONE       if `proc` does not belong to any user session
 * @retval #USESSION_USER_FIRST (or greaer) if `proc` belongs to user session
 *
 * Should the process belong to a user session, this function must found out
 * whether the #USession instance already exists (inside #U_sessions list) and
 * return its \ref #USession.id "id".
 * In the event the #USession instance does not exist, new one must be
 * created with `u_session_add()` and its id returned.
 *
 * Existence of the corresponding USession instance may be checked by passing
 * the session `name` to `u_session_find_by_name()` function. `Name` is the
 * unique session identification your agent uses. It may be DBUS object path,
 * e.g. `/org/freedesktop/ConsoleKit/Session145`.
 */
typedef guint  (*USessionAgentIdProcFunc)        (u_proc      *proc);

/**
 * Session agent function that should return the
 * \ref #USession.leader_pid "PID of given session leader".
 *
 * @param session_name
 * @return PID of the session leader on success; 0 on failure
 */
typedef pid_t  (*USessionAgentIdLeaderFunc)      (const gchar *session_name);

/**
 * \interface USessionAgent
 */
typedef struct
{
  const gchar              *name; //!< Human readable name of the agent
                                  //!< to be used in log messages.
  USessionAgentIdProcFunc   u_proc_get_session_id_func;
  USessionAgentIdLeaderFunc session_get_leader_pid_func;;
} USessionAgent;


gboolean    u_session_agent_register      (const USessionAgent *agent_definition);

USession*   u_session_new                 ();
gboolean    u_session_add                 (USession *sess);

USession*   u_session_find_by_name        (const gchar *name);
gboolean    u_session_remove              (USession *sess);
gboolean    u_session_remove_by_id        (guint        sess_id);
gboolean    u_session_remove_by_name      (const gchar *name);

void        u_session_active_changed      (USession   *sess,
                                           gboolean     active);

void        u_session_idle_hint_changed   (USession    *sess,
                                           gboolean      hint);

/*! @} End of "addtogroup USession-agent-api" */

#endif /* __U_SESSION_AGENT_H__ */
