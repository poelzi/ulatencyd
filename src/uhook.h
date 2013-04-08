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
 * Enumeration of hook lists. Each value is used as index into
 * #U_hook_list array.
 *
 * @attention If you add new enumeration, don't forget to define corresponding
 * structure derived from #UHookData and allocate it inside `u_hook_add()`.
 */
typedef enum
{
  //! Invoked by \ref USession subsystem when user session is added. Pointer to
  //! #UHookDataSession is passed to #UHookFunc.
  U_HOOK_TYPE_SESSION_ADDED,
  //! Invoked by \ref USession subsystem when user session is removed. Pointer
  //! to #UHookDataSession is passed to #UHookFunc.
  U_HOOK_TYPE_SESSION_REMOVED,
  //! Invoked by \ref USession subsystem when the user session active property
  //! has changed. Pointer to #UHookDataSession is passed to #UHookFunc.
  U_HOOK_TYPE_SESSION_ACTIVE_CHANGED,
  //! Invoked by \ref USession subsystem when the user session idle hint
  //! property has changed. Pointer to #UHookDataSession is passed to
  //! #UHookFunc.
  U_HOOK_TYPE_SESSION_IDLE_CHANGED,
  //! Invoked inside `detect_changed()` from core.c if detected changed values
  //! of a #u_proc.proc structure are sufficient enough for the #u_proc.changed
  //! flag to be set.
  //! Pointer to struct #_UHookDataProcessChangedMajor is passed to #UHookFunc.
  U_HOOK_TYPE_PROCESS_CHANGED_MAJOR,
  //! Invoked when the process no more exist and is being removed from
  //! #processes table. Pointer to struct #_UHookDataProcessExit is
  //! passed to #UHookFunc.
  U_HOOK_TYPE_PROCESS_EXIT,

  U_HOOK_TYPE_COUNT // type count, must stay last
} UHookType;

/**
 * Function called when the hook is invoked.
 * @param data Pointer to data structure shared with all hooks of same type.
 * @return TRUE, if the hook should be removed from the list; otherwise FALSE.
 */
typedef gboolean (*UHookFunc) (UHookData *data);

gulong      u_hook_add           (UHookType          type,
                                  const gchar       *owner,
                                  UHookFunc          func);
void        u_hook_list_invoke   (UHookType          type);
void        u_hook_init          ();


/* --- variables --- */
extern GHookList        *U_hook_list[U_HOOK_TYPE_COUNT];
extern UHookData        *U_hook_data[U_HOOK_TYPE_COUNT];
extern struct u_timer    timer_hooks;

/* --- structures --- */
/**
 *  Prototype of data structure which is passed to the hooks of any type.
 *  On hook list invocation, a pointer to the structure derived from this
 *  prototype is passed to each #UHookFunc, depending on the hook type. Same
 *  structure is shared with all hooks of same type.
 */
struct _UHookData
{
  guint     ref;            //!< Reference count, one for each hook in the list.
  gboolean  in_destruction; //!< TRUE if the hook will be removed after this run.
  UHookType type;           //!< Hook list identification.
};

/**
 *  Data passed to hooks of type #U_HOOK_TYPE_SESSION_ADDED,
 *  #U_HOOK_TYPE_SESSION_REMOVED, #U_HOOK_TYPE_SESSION_ACTIVE_CHANGED,
 *  #U_HOOK_TYPE_SESSION_IDLE_CHANGED.
 */
struct _UHookDataSession
{
  UHookData base;
  USession *session; //!< affected session
};

//! Data passed to hooks of type #U_HOOK_TYPE_PROCESS_CHANGED_MAJOR.
struct _UHookDataProcessChangedMajor
{
  UHookData  base;
  proc_t    *proc_old;
  proc_t    *proc_new;
  gboolean   changed; //!< If you unset this inside the hook, the process will be
                      //!< no more treated as changed. Note that remaining hooks
                      //!< may reset this to TRUE again.
};

//! Data passed to hooks of type #U_HOOK_TYPE_PROCESS_EXIT.
struct _UHookDataProcessExit
{
  UHookData base;
  u_proc *  proc;     //!< process that died
};


//! @} End of "addtogroup UHook"

#endif /* __U_HOOK_H__ */
