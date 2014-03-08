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
 *  \file ufocusstack.h
 *  \ingroup UFocus
 */


#ifndef __U_FOCUSSTACK_H__
#define __U_FOCUSSTACK_H__

#include "config.h"

#include "ulatency.h"

#include <glib.h>
#include <sys/types.h>
#include <time.h>

#ifdef ENABLE_DBUS
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#endif /* ENABLE_DBUS */

/*! \addtogroup UFocus
 *  @{
 */


/* --- typedefs ---*/
typedef struct _UFocusStack     UFocusStack;
typedef struct _UFocusStackItem UFocusStackItem;

UFocusStack*   u_focus_stack_new                      ();
void           u_focus_stack_free                     (UFocusStack *stack);
gboolean       u_focus_stack_add_pid                  (UFocusStack *stack,
                                                       pid_t        pid,
                                                       time_t       timestamp);
guint16        u_focus_stack_get_pid_position         (UFocusStack *stack,
                                                       pid_t        pid);
void           u_focus_stack_set_length               (UFocusStack *stack,
                                                       guint16      new_length);



/* --- structures --- */
struct _UFocusStackItem {
  pid_t pid;
  time_t last_change;
};

struct _UFocusStack {
  guint16 max_count;
  time_t last_change;   //!< time when the last change happened
  GList *items;         //!< list of #UFocusStackItem
  gboolean enabled;     //1< if false, ignore this user active list - useful if the user is not active (or frozen)
};

/*! @} End of "addtogroup UFocus" */

#endif /* __U_FOCUSSTACK_H__ */
