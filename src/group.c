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

#include "config.h"
#include "ulatency.h"
#include <glib.h>
#include <time.h>

// active user pid storage

GList* active_users;

static gint cmp_user(gconstpointer a,gconstpointer b) {
  const guint uid = *(guint *)b;
  const struct user_active *ua = a;

  return (ua->uid - uid);
}

static gint cmp_pid(gconstpointer a, gconstpointer b) {
  const guint pid = *(guint *)b;
  const struct user_active_process *up = a;

  return !(up->pid == pid);
}


struct user_active* get_userlist(guint uid, gboolean create) {
  struct user_active *ua;
  GError *error = NULL;

  GList* gls = g_list_find_custom(active_users, &uid, cmp_user);
  if(gls)
    return (struct user_active *)gls->data;
  if(create) {
    ua = g_malloc0(sizeof(struct user_active));
    ua->uid = uid;
    ua->active_agent = USER_ACTIVE_AGENT_NONE;
    ua->max_processes = g_key_file_get_integer(config_data, "user", "default_active_list", &error);
    if(error && error->code) {
      ua->max_processes = 5;
    }
    ua->last_change = time(NULL);
    ua->actives = NULL; //g_list_alloc();
    ua->enabled = FALSE; // skip the user until his session becomes active
    active_users = g_list_append(active_users, ua);
    return ua;
  }
  return NULL;
}

/*
  mark a process as active
*/

static gint cmp_last_change(gconstpointer a,gconstpointer b) {
  const struct user_active_process *u1 = a;
  const struct user_active_process *u2 = b;
  return (u2->last_change - u1->last_change);
}

void clear_active_list(guint uid)
{
  struct user_active *ua = get_userlist(uid, TRUE);
  struct user_active_process *up;
  u_proc *proc;

  ua->actives = g_list_sort(ua->actives, cmp_last_change);

  while(g_list_length(ua->actives) > 0) {
      up = g_list_last(ua->actives)->data;
      proc = proc_by_pid(up->pid);
      ua->actives = g_list_remove(ua->actives, up);
      g_free(up);
      if(proc) {
        proc->changed = 1;
        process_run_one(proc, FALSE, FALSE);
      }
  }
}

void enable_active_list(guint uid, gboolean enable)
{
  struct user_active *ua = get_userlist(uid, TRUE);
  ua->enabled = enable;
  if (! enable) {
      clear_active_list(uid);
  }
}

void set_active_pid(guint uid, guint pid) 
{
  u_proc *proc;
  struct user_active_process *up;
  struct user_active *ua = get_userlist(uid, TRUE);
  GList* ups = g_list_find_custom(ua->actives, &pid, cmp_pid);

  if(!ups) {
    up = g_malloc(sizeof(struct user_active_process));
    up->pid = pid;
    ua->actives = g_list_prepend(ua->actives, up);
    proc = proc_by_pid(pid);
    if(proc) {
      proc->changed = 1;
      process_run_one(proc, FALSE, FALSE);
    }
  } else {
    up = ups->data;
  }
  // remove the entries to much
  up->last_change = time(NULL);

  ua->actives = g_list_sort(ua->actives, cmp_last_change);

  while(g_list_length(ua->actives) > ua->max_processes) {
      up = g_list_last(ua->actives)->data;
      proc = proc_by_pid(up->pid);
      ua->actives = g_list_remove(ua->actives, up);
      g_free(up);
      if(proc) {
        proc->changed = 1;
        process_run_one(proc, FALSE, FALSE);
      }
  }

}

int is_active_pid(u_proc *proc) {
  GList* ups;
  struct user_active *ua = get_userlist(proc->proc->ruid, FALSE);

  if(!ua)
    return FALSE;

  ups = g_list_find_custom(ua->actives, &proc->pid, cmp_pid);

  if(!ups)
    return FALSE;
  return TRUE;
}

int get_active_pos(u_proc *proc) {
  int rv = 0;
  GList *cur;
  struct user_active *ua = get_userlist(proc->proc->ruid, FALSE);

  if(!ua)
    return 0;

  cur = ua->actives;
  while(cur) {
    rv++;
    if(((struct user_active_process *)cur->data)->pid == proc->pid)
      return rv;
    cur = g_list_next(cur);
  }
  return 0;
}

// cgroups 
//void set_active_pid(guint uid, guint pid);


