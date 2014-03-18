/*
    Copyright 2013, 2014 ulatencyd developers

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
 *  \file uhook.h
 *  \ingroup UHook
 */

#ifndef __U_HOOK_H__
#define __U_HOOK_H__

#include "ulatency.h"
#include "usession.h"

#include <glib.h>

//! \addtogroup UHook
//! @{

/* --- typedefs ---*/
typedef struct _UHookData                    UHookData;
typedef struct _UHookDataSession             UHookDataSession;
typedef struct _UHookDataProcessChangedMajor UHookDataProcessChangedMajor;
typedef struct _UHookDataProcessExit         UHookDataProcessExit;

/**
 * Enumeration of hook lists. Each hook list is identified by its type, which is
 * index to opaque array of hook lists.
 *
 * @attention If you add new hook list type, don't forget to define
 * corresponding structure derived from #UHookData and add the new hook
 * definition into `_hook_lists` array defined at top of uhook.c.
 */
typedef enum
{
  //! Invoked by \ref USession subsystem when new user session is added.
  //! When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataSession filled by
  //! an invoker.
  U_HOOK_TYPE_SESSION_ADDED = 0,
  //! Invoked by \ref USession subsystem when user session is removed.
  //! When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataSession filled by
  //! an invoker.
  U_HOOK_TYPE_SESSION_REMOVED,
  //! Invoked by \ref USession subsystem when the user session active property
  //! has changed.
  //! When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataSession filled by
  //! an invoker.
  U_HOOK_TYPE_SESSION_ACTIVE_CHANGED,
  //! Invoked by \ref USession subsystem when the user session idle hint
  //! property has changed.
  //! When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataSession filled by
  //! an invoker.
  U_HOOK_TYPE_SESSION_IDLE_CHANGED,
  //! Invoked by \ref USession subsystem when the session focus agent changed.
  //! Also called when new session has been added, getting opportunity for focus
  //! trackers to register themselves with the session.
  //! When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataSession filled by
  //! an invoker.
  //! \note
  //! A focus tracking agent may register a hook to this list, wait for
  //! a session with field #USession->focus_tracker changed to \c NULL, either
  //! because new session was created or some other tracker released it. Then
  //! the new tracker may attach itself with #u_session_set_focus_tracker().
  //! \sa UFocusStack
  U_HOOK_TYPE_SESSION_FOCUS_TRACKER_CHANGED,
  //! Invoked by \ref UFocus subsystem when another focus agent wants to
  //! register. When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataSession filled by
  //! an invoker.
  U_HOOK_TYPE_SESSION_UNSET_FOCUS_TRACKER,
  //! Invoked inside `detect_changed()` from core.c if detected changed values
  //! of a #u_proc.proc structure are sufficient enough for the #u_proc.changed
  //! flag to be set.
  //! When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataProcessChangedMajor
  //! filled by an invoker.
  U_HOOK_TYPE_PROCESS_CHANGED_MAJOR,
  //! Invoked when the process no more exist and is being removed from
  //! #processes table.
  //! When triggered, #UHookFunc of hooks added to this list may call
  //! #u_hook_list_get_data() to access structure #UHookDataProcessExit filled by
  //! an invoker.
  U_HOOK_TYPE_PROCESS_EXIT,
  //! Invoked when all modules loaded.
  U_HOOK_TYPE_ALL_MODULES_LOADED,

  U_HOOK_TYPE_COUNT // type count, must stay last
} UHookType;

/**
 * Function called when the hook is invoked.
 * @param user_data Pointer to data passed to #u_hook_add_full()
 * @return FALSE, if the hook should be removed from the list; otherwise TRUE.
 *
 * Function may call #u_hook_list_get_data() to get access to data structure
 * filled by the hook list invoker.
 */
typedef gboolean (*UHookFunc) (gpointer user_data);  //GHookCheckFunc

static inline gulong    u_hook_add                      (UHookType      type,
                                                         const gchar   *owner,
                                                         UHookFunc      func);
gulong                  u_hook_add_full                 (UHookType      type,
                                                         const gchar   *owner,
                                                         UHookFunc      func,
                                                         gpointer       user_data,
                                                         GDestroyNotify notify);
gboolean                u_hook_list_is_setup            (UHookType      type);
UHookData              *u_hook_list_get_data            (UHookType      type);
void                    u_hook_list_invoke              (UHookType      type);
void                    u_hook_list_invoke_owner        (UHookType      type,
                                                         const gchar   *owner);
void                    u_hook_list_invoke_except_owner (UHookType      type,
                                                         const gchar   *owner);
void                    u_hook_list_clear               (UHookType      type);
void                    u_hook_init                     ();


/* --- variables --- */
extern struct u_timer    timer_hooks;

/**
 *  Prototype of data structure accessible by hooks.
 *  On hook list invocation, a pointer to the structure derived from this
 *  (depending on the invoked hooks type) is accessible by each #UHookFunc
 *  via calling #u_hook_list_get_data().
 *  Data structures are shared with all hooks of same type.
 */
struct _UHookData
{
  U_HEAD;
  //! FALSE if correspondent hook list is empty. Structure is still allocated
  //! just because its ref count > 0. You should neve keep reference to it,
  //! release it!
  gboolean  is_valid;
  //! Hook list type (probably useless as you already need to know the hook list
  //! type to get its data)
  UHookType type;
};

/**
 *  Data accessible to invoked hooks of type #U_HOOK_TYPE_SESSION_ADDED,
 *  #U_HOOK_TYPE_SESSION_REMOVED, #U_HOOK_TYPE_SESSION_ACTIVE_CHANGED,
 *  #U_HOOK_TYPE_SESSION_IDLE_CHANGED.
 *  \extends #UHookData
 */
struct _UHookDataSession
{
  UHookData base;
  USession *session; //!< affected session
};

//! Data accessible to invoked hooks of type  #U_HOOK_TYPE_PROCESS_CHANGED_MAJOR.
//! \extends #UHookData
struct _UHookDataProcessChangedMajor
{
  UHookData  base;
  proc_t    *proc_old;
  proc_t    *proc_new;
  gboolean   changed; //!< If you unset this inside the hook, the process will be
                      //!< no more treated as changed. Note that remaining hooks
                      //!< may reset this to TRUE again.
};

//! Data accessible to invoked hooks of type #U_HOOK_TYPE_PROCESS_EXIT.
//! \extends #UHookData
struct _UHookDataProcessExit
{
  UHookData base;
  u_proc *  proc;     //!< process that died
};

/* --- implementation --- */

/**
 * Add hook to the list of specified type.
 * @param type    defines to the which list of hooks should this hook be added
 * @param owner   pointer to unique, statically allocated string which
 *                identifies the hook source; must be obtain by
 *                `g_intern_string()` or `g_intern_static_string()`
 * @param func    function to call when the hook list is invoked
 *
 * @return Identifier, that can be used to find the hook inside the list.
 */
static inline gulong
u_hook_add (UHookType    type,
            const gchar *owner,
            UHookFunc    func)
{
  return u_hook_add_full(type, owner, func, NULL, NULL);
}



//! @} End of "addtogroup UHook"

#endif /* __U_HOOK_H__ */
