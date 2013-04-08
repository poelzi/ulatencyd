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
 *  \file uhook.c
 *  \ingroup UHook
 */

/**
 * \addtogroup UHook
 * \details
 * Examples
 * --------
 * Define hooks functions: \snippet usession.c Define hooks functions.
 * Register hooks functions: \snippet usession.c Adding hooks.
 * Invoking hooks:
 * \snippet core.c Invoking hooks.
 * \snippet core.c Invoking hooks with feedback.
 *
 * @todo
 * - implement hook lists finalizing
 * - free data when all hooks finalized
 * - missing functions such as u_hook_remove(), u_hook_remove_by_name()
 * - bindings to lua
 * @todo maybe:
 * - implement ordering (1-10, 5 default) of hooks
 * - implement hooks precedence
 */

#include "uhook.h"

#include "ulatency.h"
#include "usession.h"

#include <glib.h>


/* --- global variables --- */
//! Array of pointers to hook lists. Pointer to specific list is stored at
//! the index defined by its type (#UHookType enumeration value).
GHookList *U_hook_list[U_HOOK_TYPE_COUNT];
//! Array of pointers to data structures specific to each hook list type.
//! When a hook list is invoked, correspondent structure is passed to
//! #UHookFunc of each hook within the list.
UHookData *U_hook_data[U_HOOK_TYPE_COUNT];
//! Timer counting the time spent inside hooks.
struct u_timer timer_hooks;


/* --- private structures --- */
typedef struct _UHook
{
  GHook hook;
  const gchar *owner;
} UHook;
#define U_HOOK(hook)       ((UHook*) (hook))

/**
 * Add hook to the list of specified type.
 * @param type  Define to the which list of hooks should this hook be added.
 * @param owner Pointer to unique, statically allocated string which identifies
 *              the hook source.
 * @param func  Function to be call when the hook list is invoked.
 *
 * @return Identifier, that can be used to find the hook inside the list.
 */
gulong
u_hook_add (UHookType          type,
            const gchar       *owner,
            UHookFunc          func)
{
  GHookList *hook_list;
  GHook     *g_hook;
  UHook     *u_hook;
  UHookData *hook_data;

  g_return_val_if_fail (owner && func, 0);

  hook_list = U_hook_list[type];
  if (!hook_list)
    {
      gsize hook_data_size;

      switch (type)
        {
          case U_HOOK_TYPE_SESSION_ADDED:
          case U_HOOK_TYPE_SESSION_REMOVED:
          case U_HOOK_TYPE_SESSION_ACTIVE_CHANGED:
          case U_HOOK_TYPE_SESSION_IDLE_CHANGED:
            hook_data_size = sizeof (UHookDataSession);
            break;

          case U_HOOK_TYPE_PROCESS_CHANGED_MAJOR:
            hook_data_size = sizeof (UHookDataProcessChangedMajor);
            break;

          case U_HOOK_TYPE_PROCESS_EXIT:
            hook_data_size = sizeof (UHookDataProcessExit);
            break;

          default:
            g_return_val_if_reached (0);
        }
      hook_data = (UHookData *) g_malloc0 (hook_data_size);
      hook_data->type = type;
      U_hook_data[type] = hook_data;

      hook_list = g_new (GHookList, 1);
      g_hook_list_init (hook_list, sizeof (UHook));
      U_hook_list[type] = hook_list;
      g_debug ("Hook list %d initialized by %s.", type, owner); //debug

    }

  hook_data = U_hook_data[type];
  hook_data->ref++;
  g_hook = g_hook_alloc (hook_list);
  g_hook->data = hook_data;
  g_hook->func = func;

  u_hook = U_HOOK (g_hook);
  u_hook->owner = owner;

  g_hook_append (hook_list, g_hook);
  g_debug ("%s registered a hook to hook list %d.", owner, type); //debug

  return g_hook->hook_id;
}

/**
 * Invokes hooks from list of given type.
 *
 * @param type Type identifying the list.
 *
 * This is similar to call
 * \code g_hook_list_invoke_check (U_hook_list[U_HOOK_TYPE_?], FALSE); \endcode
 * except this measures time spent in hooks.
 */
void
u_hook_list_invoke (UHookType type)
{
  if (U_hook_list[type])
    {
      u_timer_start (&timer_hooks);
      g_hook_list_invoke_check (U_hook_list[type], FALSE);
      u_timer_stop (&timer_hooks);
    }
}

void
u_hook_init ()
{
  // initialize profiling timer
  timer_hooks.timer = g_timer_new ();
  timer_hooks.count = 0;
  g_timer_stop (timer_hooks.timer);
}
