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
  const struct user_process *up = a;

  return (up->pid - pid);
}


struct user_active* get_userlist(guint uid, gboolean create) {
  struct user_active *ua;

  GList* gls = g_list_find_custom(active_users, &uid, cmp_user);
  if(gls)
    return (struct user_active *)gls->data;
  if(create) {
    ua = g_malloc(sizeof(struct user_active));
    ua->uid = uid;
    ua->max_processes = 5; // FIXME default_active_processes;
    ua->last_change = time(NULL);
    ua->actives = NULL; //g_list_alloc();
    active_users = g_list_append(active_users, ua);
    return ua;
  }
  return NULL;
}

/*
  mark a process as active
*/

static gint cmp_last_change(gconstpointer a,gconstpointer b) {
  const struct user_process *u1 = a;
  const struct user_process *u2 = b;
  return (u2->last_change - u1->last_change);
}

void set_active_pid(guint uid, guint pid) 
{
  u_proc *proc;
  struct user_process *up;
  struct user_active *ua = get_userlist(uid, TRUE);
  GList* ups = g_list_find_custom(ua->actives, &pid, cmp_pid);

  if(!ups) {
    up = g_malloc(sizeof(struct user_process));
    up->pid = pid;
    ua->actives = g_list_prepend(ua->actives, up);
    proc = proc_by_pid(pid);
    if(proc)
      proc->changed = 1;
  } else {
    up = ups->data;
  }
  // remove the entries to much
  up->last_change = time(NULL);

  ua->actives = g_list_sort(ua->actives, cmp_last_change);

  while(g_list_length(ua->actives) > ua->max_processes) {
      up = g_list_last(ua->actives)->data;
      proc = proc_by_pid(up->pid);
      if(proc)
        proc->changed = 1;
      ua->actives = g_list_remove(ua->actives, up);
  }

}

int is_active_pid(u_proc *proc) {
  GList* ups;
  struct user_active *ua = get_userlist(proc->proc.ruid, FALSE);

  if(!ua)
    return FALSE;

  ups = g_list_find_custom(ua->actives, &proc->pid, cmp_pid);

  if(!ups)
    return FALSE;
  return TRUE;
}

// cgroups 
//void set_active_pid(guint uid, guint pid);


