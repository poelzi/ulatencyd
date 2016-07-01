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
 * - bindings to lua
 * - missing functions such as u_hook_remove(), u_hook_remove_by_owner()
 * @todo maybe:
 * - implement ordering (1-10, 5 default) of hooks
 * - implement hooks precedence
 */

#include "uhook.h"

#include "ulatency.h"
#include "usession.h"

#include <glib.h>


struct u_timer timer_hooks;

struct hook_list
{
  const gchar *log_name;
  gint         log_level;
  GHookList   *hooks;     //!< List of hooks.
  gsize        data_size; //!< Size of \a hook_data
  UHookData   *data;      //!< Pointer to data structure; passed to hooks.
};

static struct hook_list _hook_lists[U_HOOK_TYPE_COUNT] = {
    {
        .log_name  = "SESSION_ADDED",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookDataSession),
    },
    {
        .log_name  = "SESSION_REMOVED",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookDataSession),
    },
    {
        .log_name  = "SESSION_ACTIVE_CHANGED",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookDataSession),
    },
    {
        .log_name  = "SESSION_IDLE_CHANGED",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookDataSession),
    },
    {
        .log_name  = "SESSION_FOCUS_TRACKER_CHANGED",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookDataSession),
    },
    {
        .log_name  = "SESSION_FOCUS_TRACKER_CHANGE_REQUEST",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookDataSession),
    },
    {
        .log_name  = "PROCESS_CHANGED_MAJOR",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookDataProcessChangedMajor),
    },
    {
        .log_name  = "PROCESS_EXIT",
        .log_level = U_LOG_LEVEL_TRACE,
        .data_size = sizeof(UHookDataProcessExit),
    },
    {
        .log_name  = "ALL_MODULES_LOADED",
        .log_level = G_LOG_LEVEL_DEBUG,
        .data_size = sizeof(UHookData),
    },
};

/* --- private structures --- */
typedef struct _UHook
{
  GHook hook;
  const gchar *owner;
} UHook;
#define U_HOOK(hook)       ((UHook*) (hook))

/**
 * Return TRUE if hook list of given \a type is initialized.
 * @param type #UHookType
 * @retval TRUE if hook list is initialized (contains at least one hook)
 * @retval FALSE if hook list is not initialized (does not contain any hook)
 */
gboolean
u_hook_list_is_setup (UHookType type)
{
  return _hook_lists[type].hooks ? TRUE : FALSE;
}

/**
 * Return pointer to data field of hook list determined by \a type.
 * @param type #UHookType
 * @return data pointer to #UHookData
 * @retval NULL if hook list was not initialized (does not contain any hook)
 *
 * The #UHoodData and derived structures may be filled before invoking hooks
 * or retrieved by invoked hooks. They are valid only only during single
 * invoking of hook lists.
 * \attention
 * It is error to store reference to returned data as this structure is shared
 * with all hooks of same type. To ensure this, reference counting is enforced.
 * this function increases \a data ref counter and you must call DEC_REF()
 * before leaving the #UHookFunc; if the ref counter will not be same as
 * before #UHookFunc was called, warning is printed.
 */
UHookData *
u_hook_list_get_data (UHookType type)
{
  INC_REF (_hook_lists[type].data);
  return _hook_lists[type].data;
}

/**
 * Add hook to the list of specified type.
 * @param type    defines to the which list of hooks should this hook be added
 * @param owner   pointer to unique, statically allocated string which
 *                identifies the hook source; must be obtain by
 *                `g_intern_string()` or `g_intern_static_string()`
 * @param func    function to call when the hook list is invoked
 * @param data    data which is passed to \a func when this hook is invoked
 * @param destroy function to call when the hook is being removed; this
 *                should free \a data
 *
 * @return Identifier, that can be used to find the hook inside the list.
 */
gulong
u_hook_add_full (UHookType          type,
                 const gchar       *owner,
                 UHookFunc          func,
                 gpointer           user_data,
                 GDestroyNotify     destroy)
{
  struct hook_list *hook_list;
  GHook            *g_hook;
  UHook            *u_hook;

  g_return_val_if_fail (owner && func, 0);

  hook_list = &_hook_lists[type];
  if (!hook_list->hooks)
    {
      hook_list->data = (UHookData *) g_malloc0 (hook_list->data_size);
      hook_list->data->free_fnk = g_free;
      hook_list->data->type = type;
      hook_list->data->ref = 1;

      hook_list->hooks = g_new (GHookList, 1);
      g_hook_list_init (hook_list->hooks, sizeof (UHook));
      g_debug ("Hook list %s initialized by %s.", hook_list->log_name, owner);
    }

  g_hook = g_hook_alloc (hook_list->hooks);
  g_hook->func = func;
  g_hook->data = user_data;
  g_hook->destroy = destroy;

  u_hook = U_HOOK (g_hook);
  u_hook->owner = owner;

  g_hook_append (hook_list->hooks, g_hook);
  g_debug ("%s registered a hook to list %s.",
           owner, hook_list->log_name);

  return g_hook->hook_id;
}

/**
 * Invokes all hooks from a hook list determined by \a type.
 *
 * @param type an #UHookType
 *
 * Calls all #UHook functions in corresponding hook list. Any function which
 * returns \c FALSE will be removed from the hooks.
 */
void
u_hook_list_invoke (UHookType type)
{
  struct hook_list *hook_list;

  g_return_if_fail(type >= 0 && type < U_HOOK_TYPE_COUNT);
  hook_list = &_hook_lists[type];
  if (hook_list->hooks)
    {
      gint old_ref;

      u_timer_start (&timer_hooks);
      g_log (G_LOG_DOMAIN, hook_list->log_level,
             "Invoke %s hooks.", hook_list->log_name);
      old_ref = hook_list->data->ref;
      g_hook_list_invoke_check (hook_list->hooks, FALSE);
      g_return_if_fail(hook_list->data->ref == old_ref);
      u_timer_stop (&timer_hooks);
    }
}

static gboolean //(*GHookCheckMarshaller)
marshal_owner (GHook *hook, gpointer marshal_data)
{
  g_return_val_if_fail (marshal_data != NULL, TRUE);

  if ((const gchar *) marshal_data == U_HOOK (hook)->owner)
    return ((GHookCheckFunc) hook->func) (hook->data);
  else
    return TRUE;
}

static gboolean //(*GHookCheckMarshaller)
marshal_except_owner (GHook *hook, gpointer marshal_data)
{
  g_return_val_if_fail (marshal_data != NULL, TRUE);

  if ((const gchar *) marshal_data != U_HOOK (hook)->owner)
    return ((GHookCheckFunc) hook->func) (hook->data);
  else
    return TRUE;
}

/**
 * Invokes hooks owned by \a owner from a hook list determined by \a type.
 *
 * @param type an #UHookType
 * @param owner an owner to be match
 *
 * Calls #UHook functions in corresponding hook list which are owned by
 * \a owner. Any function which returns \c FALSE will be removed from the hooks.
 */
void
u_hook_list_invoke_owner (UHookType   type,
                          const gchar *owner)
{
  struct hook_list *hook_list;

  g_return_if_fail(type >= 0 && type < U_HOOK_TYPE_COUNT);
  hook_list = &_hook_lists[type];
  if (hook_list->hooks)
    {
      gint old_ref;

      u_timer_start (&timer_hooks);
      g_log (G_LOG_DOMAIN, hook_list->log_level,
             "Invoke %s hooks owned by %s.", hook_list->log_name, owner);
      old_ref = hook_list->data->ref;
      g_hook_list_marshal_check (hook_list->hooks, FALSE,
                                 (gpointer) marshal_owner, (gpointer) owner);
      g_return_if_fail(hook_list->data->ref == old_ref);
      u_timer_stop (&timer_hooks);
    }
}

/**
 * Invokes hooks from a hook list determined by \a type except hooks owned
 * by \a owner.
 *
 * @param type an #UHookType
 * @param owner an owner to be excluded
 *
 * Calls #UHook functions in corresponding hook list except those owned by
 * \a owner. Any function which returns \c FALSE will be removed from the hooks.
 */
void
u_hook_list_invoke_except_owner (UHookType    type,
                                 const gchar *owner)
{
  struct hook_list *hook_list;

  g_return_if_fail(type >= 0 && type < U_HOOK_TYPE_COUNT);
  hook_list = &_hook_lists[type];
  if (hook_list->hooks)
    {
      gint old_ref;

      u_timer_start (&timer_hooks);
      g_log (G_LOG_DOMAIN, hook_list->log_level,
             "Invoke %s hooks not owned by %s.", hook_list->log_name, owner);
      old_ref = hook_list->data->ref;
      g_hook_list_marshal_check (hook_list->hooks, FALSE,
                                 (gpointer) marshal_except_owner,
                                 (gpointer) owner);
      g_return_if_fail(hook_list->data->ref == old_ref);
      u_timer_stop (&timer_hooks);
    }
}

/**
 * Clears hook list determined by \a type.
 * @param type #UHookType
 */
void
u_hook_list_clear (UHookType type)
{
  struct hook_list *hook_list;

  g_return_if_fail(type >= 0 && type < U_HOOK_TYPE_COUNT);
  hook_list = &_hook_lists[type];
  if (hook_list->hooks)
    {
      g_hook_list_clear (hook_list->hooks);
      g_assert (hook_list->data->ref == 1);
      DEC_REF (hook_list->data);
    }
}

/**
 * Initializes profiling timer.
 */
void
u_hook_init ()
{
  timer_hooks.timer = g_timer_new ();
  timer_hooks.count = 0;
  g_timer_stop (timer_hooks.timer);
}
