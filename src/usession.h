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
 *  \file usession.h
 *  \ingroup USession
 */


#ifndef __U_SESSION_H__
#define __U_SESSION_H__

#include "config.h"

#include "ulatency.h"

#include <glib.h>
#include <sys/types.h>

#ifdef ENABLE_DBUS
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#endif /* ENABLE_DBUS */

/*! \addtogroup USession
 *  @{
 */


/* --- typedefs ---*/
typedef struct _USession USession;

//! process session values
enum U_SESSION_ID
{
  USESSION_UNKNOWN      = 0, //!< could not be determined, process already dead
                             //!< or consolekit/logind error
  USESSION_INIT         = 1, //!< init
  USESSION_KERNEL       = 2, //!< kernel threads, including e.g. cgroups
                             //!< release_agents
  USESSION_NONE         = 3, //!< process not belonging to any user session
  USESSION_USER_UNKNOWN = 5, //!< unknown user session
                             //!< (wrong consolekit cookie or ck error)
  USESSION_USER_FIRST   = 10 //!< first user session
};

gboolean       u_session_init                   ();
USession*      u_session_find_by_proc           (u_proc      *proc);
USession*      u_session_find_by_id             (guint        sess_id);
guint          u_session_id_find_by_proc        (u_proc      *proc);
u_proc *       u_session_get_leader             (USession    *session);
void           u_session_invalidate_by_id       (guint        sess_id);
void           u_proc_set_changed_by_session_id (guint        sess_id);


/* --- variables --- */
extern USession* U_sessions;


/* --- structures --- */
//! Structure containing information about **user** session.
struct _USession
{
  U_HEAD;
  gboolean  is_valid; //!< FALSE if the session was closed and removed from
                      //!< the `sessions` list and friends. It's kept around
                      //!< just because its ref count > 0. Release it!

  guint     id;       //!< Generated unique session ID (>= #USESSION_USER_FIRST)
  gchar     *name;    //!< Unique session name specific to the used backend.

  pid_t     leader_pid; //!< PID of the session leader; may be 0 - unknown (always
                        //!< for consolekit) or the process may be already dead.
                        //!< You should use `u_session_get_leader()` if you want
                        //!< real `u_proc`.
  gchar     *session_type; //!< session-type, e.g. "x11"
  gchar     *X11Display;
  gchar     *X11Device;
  // most likely dbus session
  gchar     *dbus_session; //!< N/A
  uid_t     uid;
  uint32_t  idle;
  uint32_t  active;
  gchar     *consolekit_cookie; //!< value of XDG_SESSION_COOKIE environment
                                //!< variable; specific to consolekit backend
  int       lua_data;          //!< id for per session lua storage
#ifdef ENABLE_DBUS
  DBusGProxy *proxy;
#endif
  USession *prev;
  USession *next;
};

/*! @} End of "addtogroup USession" */



#endif /* __U_SESSION_H__ */
