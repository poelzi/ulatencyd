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
 *  \file ufocusstack.c
 *  \ingroup UFocus
 */

#include "config.h"

#include "ufocusstack.h"

#include "ulatency.h"

#include <glib.h>
#include <time.h>



/* --- focus stack --- */
static GList *
update_stack_list (GList *list, guint16 position, gint max_position)
G_GNUC_WARN_UNUSED_RESULT;

UFocusStack *
u_focus_stack_new ()
{
  UFocusStack *stack;
  GError      *error;
  gint        t_max_count; // because there is no g_key_file_get_uint16()

  stack = g_new0 (UFocusStack, 1);

  error = NULL;
  t_max_count = g_key_file_get_integer (config_data, "user",
                                             "default_active_list", &error);
  if (error || t_max_count < 0 || t_max_count > G_MAXUINT16)
    {
      t_max_count = 5;
      g_error_free (error);
    }
  stack->max_count = (guint16) t_max_count;
  return stack;
}

void
u_focus_stack_free (UFocusStack *stack)
{
  stack->items = update_stack_list (stack->items, 0, -1);
  g_assert (g_list_length(stack->items) == 0);
  g_list_free(stack->items);
  g_free (stack);
}

static gint
cmp_pid(gconstpointer a, gconstpointer b)
{
  const pid_t pid = *(pid_t *)b;
  const UFocusStackItem *up = a;

  return !(up->pid == pid);
}

static gint
cmp_last_change(gconstpointer a, gconstpointer b)
{
  const UFocusStackItem *u1 = a;
  const UFocusStackItem *u2 = b;
  return (u2->last_change - u1->last_change);
}

/**
 * Update process flags according their position and trim the list.
 * @param list #GList of #UFocusStackItem which order changed
 * @param position position of the #UFocusStackItem to which the `list` points.
 * @param max_position All items that would have greater position will be
 * removed; pass -1 to remove all items.
 * @return new #GList `list` start

 */
static GList *
update_stack_list (GList   *list,
                   guint16  position,
                   gint  max_position)
{
  GList *current;

  current = list;
  while (current)
    {
      pid_t pid;
      u_flag *flg;
      GList* next;
      u_proc *proc;

      next = g_list_next (current);
      pid = ((UFocusStackItem *) current->data)->pid;
      if (position > max_position) {
        g_free (current->data);
        list = g_list_delete_link (list, current);
        current = NULL;
      }
      proc = proc_by_pid (pid);
      if (proc) {
        u_flag_clear_source(proc, (void *)update_stack_list, TRUE);
        if (current) {
          flg = u_flag_new((void *)update_stack_list, "active");
          flg->priority = position;
          flg->inherit = 1;
          u_flag_add(proc, flg, TRUE);
          DEC_REF(flg);
        }
      }
      current = next;
      position++;
    }
  return list;
}

/**
 * Set new length of focus \a stack.
 */
void
u_focus_stack_set_length (UFocusStack *stack,
                          guint16      new_length)
{
  g_return_if_fail (stack);

  if (stack->max_count > new_length)
    {
      guint16 index;
      GList *llink;

      index = MIN (new_length - 1, 0);
      llink = g_list_nth (stack->items, index);
      if (llink)
        {
          llink = update_stack_list (llink, index, new_length - 1);
          if (llink->prev)
            llink->prev = llink;
          else
            stack->items = llink;
        }
    }

  stack->max_count = new_length;
}

/**
 * Add process with \a pid to \a stack.
 *
 * @param stack #UFocusStack
 * @param pid process PID
 * @param timestamp (optional) time when the process was focused. If 0, current
 * time will be used.
 *
 * This function adds passed process to focus stack on position determined by
 * \a timestamp.
 *
 * @return TRUE on success; FALSE if the process was not added to the stack
 * because its position would be after the #UFocusStack->max_count
 */
gboolean
u_focus_stack_add_pid (UFocusStack *stack,
                       pid_t        pid,
                       time_t       timestamp)
{
  gboolean        order_changed;
  GList           *list;      //stack
  GList           *llink;
  UFocusStackItem *item;
  guint16          pos;
  guint16          old_pos;

  /* checks */
  g_return_val_if_fail (pid, FALSE);

  if (!timestamp) timestamp = time(NULL);

  /* add or update item in focus stack */
  order_changed = FALSE;
  list = stack->items;
  llink = g_list_find_custom (list, &pid, cmp_pid);
  if(!llink)
    {
      item = g_new (UFocusStackItem, 1);
      item->pid = pid;
      item->last_change = timestamp;
      list = g_list_insert_sorted (list, item, cmp_last_change);
      llink = g_list_find (list, item);
      pos = g_list_position (list, llink);
      if (pos >= stack->max_count)
        {
          // too late
          list = g_list_delete_link (list, llink);
          g_free (item);
          stack->items = list;
          return FALSE;
        }
      order_changed = TRUE;
    }
  else
    {
      item = llink->data;
      if (item->last_change >= timestamp) // strayed bullet
        return FALSE;
      item->last_change = timestamp;
      old_pos = g_list_position (list, llink);
      list = g_list_sort(list, cmp_last_change);
      pos = g_list_position (list, llink);
      if (pos != old_pos)
        order_changed = TRUE;
    }
  stack->items = list;

  if (!order_changed)
      return TRUE;
  stack->last_change = time (NULL);

  /* update process flags according their position and trim the list */
  llink = update_stack_list (llink, pos, stack->max_count - 1);
  g_assert (llink); // the list must contain at least the currently added PID
  if (llink->prev)
    llink->prev = llink;
  else
    stack->items = llink;

  iteration_request(0); //FIXME: schedule only changed processes
  return TRUE;
}

/**
 * Returns \a pid position in focus \a stack.
 *
 * @param pid of process which position should be returned
 *
 * @return Process position (>0) or 0 if process is not in focus \a stack.
 */
guint16
u_focus_stack_get_pid_position (UFocusStack *stack,
                                pid_t        pid)
{
  guint16   pos;
  GList    *cur;

  pos = 0;
  cur = stack->items;
  while (cur)
    {
      pos++;
      if (((UFocusStackItem *)cur->data)->pid == pid)
        return pos;
      cur = g_list_next(cur);
    }
  return 0;
}
