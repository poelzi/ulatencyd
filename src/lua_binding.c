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
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <proc/procps.h>
#include <proc/sysinfo.h>
#include <proc/pwcache.h>
#include <proc/readproc.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <signal.h>
#include <time.h>
#include <bits/signum.h>
//#include <errno.h>
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <sched.h>
#include <linux/sched.h>
//#include <sys/ptrace.h>

#define UL_META "ulatency"
#define LUA_TABLE_INT(NAME) \
  lua_pushliteral(L, #NAME); \
  lua_pushinteger(L,   NAME); \
  lua_settable(L, -3);


//static proc_t *push_proc_t (lua_State *L);
static u_proc *push_u_proc (lua_State *L, u_proc *proc);
static int docall (lua_State *L, int narg, int nresults);
int load_lua_rule_file(lua_State *L, const char *name);

void stackdump_g(lua_State* l)
{
    int i;
    int top = lua_gettop(l);

    printf("total in stack %d\n",top);

    for (i = 1; i <= top; i++)
    {  /* repeat for each level */
        int t = lua_type(l, i);
        switch (t) {
            case LUA_TSTRING:  /* strings */
                printf("string: '%s'\n", lua_tostring(l, i));
                break;
            case LUA_TBOOLEAN:  /* booleans */
                printf("boolean %s\n",lua_toboolean(l, i) ? "true" : "false");
                break;
            case LUA_TNUMBER:  /* numbers */
                printf("number: %g\n", lua_tonumber(l, i));
                break;
            default:  /* other values */
                printf("%s\n", lua_typename(l, t));
                break;
        }
        printf("  ");  /* put a separator */
    }
    printf("\n");  /* end the listing */
}

static void l_hash_to_table(lua_State *L, GHashTable *table) {
    GHashTableIter iter;
    gpointer key, value;
    lua_newtable(L);

    g_hash_table_iter_init (&iter, table);
    while (g_hash_table_iter_next (&iter, &key, &value)) 
    {
      lua_pushstring(L, (char *)key);
      lua_pushstring(L, (char *)value);
      lua_settable(L, -3);
    }
}

static void l_ptrarray_to_table(lua_State *L, GPtrArray *array) {
    int i = 0;
    lua_newtable(L);

    for (; i < array->len; i++) 
    {
      lua_pushinteger(L, i+1);
      lua_pushstring(L, (char *)g_ptr_array_index(array, i));
      lua_settable(L, -3);
    }
}

static void l_vstr_to_table(lua_State *L, char **vec, int len) {
    int i = 0;
    lua_newtable(L);
    for(i = 0; i < len; i++) {
        lua_pushinteger(L, i+1);
        lua_pushstring(L, (char *)vec[i]);
        lua_settable(L, -3);
    }
}

static int get_load (lua_State *L) {
  double av1, av5, av15;
  loadavg(&av1, &av5, &av15);
  lua_pushnumber(L, av1);
  lua_pushnumber(L, av5);
  lua_pushnumber(L, av15);
  return 3;
}

static int get_uptime (lua_State *L) {
  double uptime_secs, idle_secs;
  uptime(&uptime_secs, &idle_secs);
  lua_pushnumber(L, uptime_secs);
  lua_pushnumber(L, idle_secs);
  return 2;
}

static int l_get_last_load(lua_State *L) {
  lua_pushnumber(L, get_last_load());
  return 1;
}

static int l_get_last_percent(lua_State *L) {
  lua_pushnumber(L, get_last_percent());
  return 1;
}



static int get_meminfo (lua_State *L) {
  lua_createtable (L, 10, 0);
  meminfo();
  LUA_TABLE_INT(kb_active)
  LUA_TABLE_INT(kb_main_shared)
  LUA_TABLE_INT(kb_main_buffers)
  LUA_TABLE_INT(kb_main_cached)
  LUA_TABLE_INT(kb_main_free)
  LUA_TABLE_INT(kb_main_total)
  LUA_TABLE_INT(kb_swap_free)
  LUA_TABLE_INT(kb_swap_total)
  LUA_TABLE_INT(kb_high_free)
  LUA_TABLE_INT(kb_high_total)
  LUA_TABLE_INT(kb_low_free)
  LUA_TABLE_INT(kb_low_total)
  LUA_TABLE_INT(kb_active)
  LUA_TABLE_INT(kb_inact_laundry)
  LUA_TABLE_INT(kb_inact_dirty)
  LUA_TABLE_INT(kb_inact_clean)
  LUA_TABLE_INT(kb_inact_target)
  LUA_TABLE_INT(kb_swap_cached)
  LUA_TABLE_INT(kb_swap_used)
  LUA_TABLE_INT(kb_main_used)
  LUA_TABLE_INT(kb_writeback)
  LUA_TABLE_INT(kb_slab)
  LUA_TABLE_INT(kb_committed_as)
  LUA_TABLE_INT(kb_dirty)
  LUA_TABLE_INT(kb_inactive)
  LUA_TABLE_INT(kb_mapped)
  LUA_TABLE_INT(kb_pagetables)
  return 1;
}

static int get_vminfo (lua_State *L) {
  lua_createtable (L, 10, 0);
  vminfo();
  LUA_TABLE_INT(vm_nr_dirty)
  LUA_TABLE_INT(vm_nr_writeback)
  LUA_TABLE_INT(vm_nr_pagecache)
  LUA_TABLE_INT(vm_nr_page_table_pages)
  LUA_TABLE_INT(vm_nr_reverse_maps)
  LUA_TABLE_INT(vm_nr_mapped)
  LUA_TABLE_INT(vm_nr_slab)
  LUA_TABLE_INT(vm_pgpgin)
  LUA_TABLE_INT(vm_pgpgout)
  LUA_TABLE_INT(vm_pswpin)
  LUA_TABLE_INT(vm_pswpout)
  LUA_TABLE_INT(vm_pgalloc)
  LUA_TABLE_INT(vm_pgfree)
  LUA_TABLE_INT(vm_pgactivate)
  LUA_TABLE_INT(vm_pgdeactivate)
  LUA_TABLE_INT(vm_pgfault)
  LUA_TABLE_INT(vm_pgmajfault)
  LUA_TABLE_INT(vm_pgscan)
  LUA_TABLE_INT(vm_pgrefill)
  LUA_TABLE_INT(vm_pgsteal)
  LUA_TABLE_INT(vm_kswapd_steal)
  LUA_TABLE_INT(vm_pageoutrun)
  LUA_TABLE_INT(vm_allocstall)
  return 1;
}

static int l_get_pid_digits (lua_State *L) {
  lua_pushinteger(L, get_pid_digits());
  return 1;
}

static int l_user_from_uid (lua_State *L) {
  int uid = luaL_checkint (L, 1);
  lua_pushstring(L, user_from_uid(uid));
  return 1;
}

static int l_group_from_guid (lua_State *L) {
  int gid = luaL_checkint (L, 1);
  lua_pushstring(L, group_from_gid(gid));
  return 1;
}

static int l_filter_rv (lua_State *L) {
  int flags = lua_tointeger(L, 1);
  int timeout = lua_tointeger(L, 2);
  lua_pushnumber(L, FILTER_MIX(flags, timeout));
  return 1;
}


static int l_get_pid (lua_State *L) {
  int pid;
  u_proc *proc;

  pid = luaL_checkint (L, 1);
  proc = proc_by_pid(pid);

  if(!proc)
    return 0;

  push_u_proc(L, proc);
  return 1;
}

static int l_get_config (lua_State *L) {
  const char *group, *key;
  char *tmp;

  group = luaL_checkstring (L, 1);
  key = luaL_checkstring (L, 2);
  //proctab = openproc(PROC_PID, pid);
  tmp = g_key_file_get_string(config_data, group, key, NULL);
  if(tmp) {
    lua_pushstring(L, tmp);
    free(tmp);
    return 1;
  }

  return 0;
}

static int l_list_keys (lua_State *L) {
  const char *group;
  gchar **tmp;
  gsize len;
  int i;

  group = luaL_checkstring (L, 1);
  //proctab = openproc(PROC_PID, pid);
  tmp = g_key_file_get_keys(config_data, group, &len, NULL);
  if(len) {
    lua_newtable(L);
    for(i = 0; i < len; i++) {
      lua_pushinteger(L, i);
      lua_pushstring(L, tmp[i]);
      lua_settable (L, -3);
    }
    return 1;
  }

  return 0;
}



static int l_list_pids (lua_State *L) {
  int i = 1;
  GHashTableIter iter;
  gpointer ikey, value;
  u_proc *proc;


  lua_newtable (L);
  g_hash_table_iter_init (&iter, processes);
  while (g_hash_table_iter_next (&iter, &ikey, &value)) 
  {
    proc = (u_proc *)value;
    lua_pushinteger(L, i);
    lua_pushinteger(L, proc->pid);
    lua_settable(L, -3);
    i++;
  }
  return 1;
}

static int l_list_processes (lua_State *L) {
  int i = 1;
  GHashTableIter iter;
  gpointer ikey, value;
  u_proc *proc;
  int changed = lua_toboolean(L, 1);


  lua_newtable (L);
  g_hash_table_iter_init (&iter, processes);
  while (g_hash_table_iter_next (&iter, &ikey, &value)) 
  {
    proc = (u_proc *)value;
    if(changed) {
      if(!proc->changed) {
        continue;
      }
    }
    lua_pushinteger(L, i);
    push_u_proc(L, proc);
    lua_settable(L, -3);
    i++;
  }
  return 1;
}


static int l_set_active_pid(lua_State *L) {
  lua_Integer uid = luaL_checkinteger (L, 1);
  lua_Integer pid = luaL_checkinteger (L, 2);

  set_active_pid((guint)uid, (guint)pid);

  return 0;
}

static int l_get_active_uids(lua_State *L) {
  GList *cur = g_list_first(active_users);
  struct user_active *ua = NULL;
  int i = 1;
  
  lua_newtable(L);
  while(cur) {
    ua = cur->data;
    lua_pushinteger(L, i);
    lua_newtable(L);
    lua_pushstring(L, "uid");
    lua_pushinteger(L, ua->uid);
    lua_settable (L, -3);
    lua_pushstring(L, "max_processes");
    lua_pushinteger(L, ua->max_processes);
    lua_settable (L, -3);
    lua_pushstring(L, "last_change");
    lua_pushinteger(L, ua->last_change);
    lua_settable (L, -3);
    lua_settable (L, -3);
    i++;
    cur = g_list_next (cur);
  }

  return 1;
}

static int l_get_active_pids(lua_State *L) {
  lua_Integer uid = luaL_checkinteger (L, 1);
  struct user_active *ua = get_userlist((guint)uid, FALSE);
  struct user_active_process *up;
  GList *cur;
  int i = 1;

  if(!ua)
    return 0;

  cur = g_list_first(ua->actives);
  lua_newtable(L);
  while(cur) {
    up = cur->data;
    lua_pushinteger(L, i);
    lua_newtable(L);
    lua_pushstring(L, "pid");
    lua_pushinteger(L, up->pid);
    lua_settable (L, -3);
    lua_pushstring(L, "last_change");
    lua_pushinteger(L, up->last_change);
    lua_settable (L, -3);
    lua_settable (L, -3);
    i++;
    cur = g_list_next (cur);
  }

  return 1;
}

static int l_log (lua_State *L) {
  int level = luaL_checkint (L, 1);
  const char *str = luaL_checkstring(L, 2);

  g_log(G_LOG_DOMAIN, level, "%s", str);
  return 0;
}

static int l_quit (lua_State *L) {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "%s", "quit called from script");
  if(g_main_loop_is_running(main_loop))
    g_main_loop_quit(main_loop);
  else
    exit(0);
  return 0;
}

gboolean l_call_function(gpointer data) {
  gboolean rv;
  struct lua_callback *cd = (struct lua_callback *)data;

  lua_rawgeti (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_func);
  lua_rawgeti (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_data);
  //stackdump_g(cd->lua_state);
  rv = docall(cd->lua_state, 1, 1);
  //stackdump_g(cd->lua_state);
  if(rv) {
    // FIXME case of errror, stop the filter ???
    return TRUE;
  }
  rv = lua_toboolean (cd->lua_state, -1);
  lua_pop(cd->lua_state, 1);

  if(rv) {
    return TRUE;
  }
  luaL_unref (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_data);
  luaL_unref (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_func);
  luaL_unref (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_state_id);
  free(data);
  
  return FALSE;
}


static int l_add_interval (lua_State *L) {
  luaL_checktype(L, 1, LUA_TFUNCTION);
  guint interval = luaL_checkint(L, 2);
  struct lua_callback *cd = malloc(sizeof(struct lua_callback));
  memset(cd, 0, sizeof(struct lua_callback));

  cd->lua_state = lua_newthread (L);
  cd->lua_state_id = luaL_ref(L, LUA_REGISTRYINDEX);
  cd->lua_data = luaL_ref(L, LUA_REGISTRYINDEX);
  cd->lua_func = luaL_ref(L, LUA_REGISTRYINDEX);

  g_timeout_add(interval,l_call_function, cd);

  return 0;
}

// type checks and pushes

#define U_PROC "U_PROC"
#define U_PROC_META "U_PROC_META"

static u_proc *check_u_proc (lua_State *L, int index)
{
  u_proc **p;
  luaL_checktype(L, index, LUA_TUSERDATA);
  p = (u_proc **)luaL_checkudata(L, index, U_PROC_META);
  if (p == NULL) luaL_typerror(L, index, U_PROC);
  return *p;
}

static u_proc *push_u_proc (lua_State *L, u_proc *upr)
{
  u_proc *proc;
  //u_proc *p = (u_proc*)lua_newuserdata(L, sizeof(u_proc));
  u_proc **p = (u_proc **)lua_newuserdata(L, sizeof(u_proc *));
  if(!upr) {
    proc = u_proc_new(NULL);
  } else {
    proc = upr;
    INC_REF(proc);
  }
  *p = proc;
  //proc->in_lua = 1;
  //DEC_REF(proc);
  luaL_getmetatable(L, U_PROC_META);
  lua_setmetatable(L, -2);

  //up = 
/*
  memset(p, 0, sizeof(proc_t));
  return p;
*/
  return proc;
}

#define U_FLAG "U_FLAG"
#define U_FLAG_META "U_FLAG_META"

static u_flag *check_u_flag (lua_State *L, int index)
{
  u_flag **p;
  luaL_checktype(L, index, LUA_TUSERDATA);
  p = (u_flag **)luaL_checkudata(L, index, U_FLAG_META);
  if (p == NULL) luaL_typerror(L, index, U_FLAG);
  return *p;
}

static u_flag *push_u_flag (lua_State *L, u_flag *upr, void *source, const char *name)
{
  u_flag *flag;
  //u_proc *p = (u_proc*)lua_newuserdata(L, sizeof(u_proc));
  u_flag **p = (u_flag **)lua_newuserdata(L, sizeof(u_flag *));
  if(!upr) {
    flag = u_flag_new(source, name);
  } else {
    flag = upr;
    INC_REF(flag);
  }
  *p = flag;

  luaL_getmetatable(L, U_FLAG_META);
  lua_setmetatable(L, -2);

  return flag;
}


// bindings to u_proc


static int u_proc_gc (lua_State *L)
{
  u_proc *proc = check_u_proc(L, 1);
  //printf("goodbye proc_t (%p)\n", proc);
  DEC_REF(proc);
  return 0;
}


static int u_proc_tostring (lua_State *L)
{
  u_proc **proc = lua_touserdata(L, 1);
  lua_pushfstring(L, "u_proc: <%p> pid:%d %s", (*proc), (*proc)->pid, &(*proc)->proc.cmd);
  return 1;
}


static int u_proc_get_parent (lua_State *L)
{
  u_proc *proc = check_u_proc(L, 1);
  u_proc *parent;
  
  if(U_PROC_IS_INVALID(proc) || !proc->node || !proc->node->parent || 
     !proc->node->parent->data)
    return 0;

  parent = (u_proc *)proc->node->parent->data;
  push_u_proc(L, parent);
  
  return 1;
}

static int u_proc_get_children (lua_State *L)
{
  int i = 1, max;
  u_proc *child;
  u_proc *proc = check_u_proc(L, 1);

  if(!proc->node)
    return 0;

  max = g_node_n_children(proc->node);

  lua_newtable (L);

  for(i = 0; i < max; i++) {
    child = g_node_nth_child(proc->node, i)->data;
    lua_pushinteger(L, i+1);
    push_u_proc(L, child);
    lua_settable(L, -3);
  }
  return 1;

}

static int u_proc_list_flags (lua_State *L) {
  int i = 1;
  u_proc *proc = check_u_proc(L, 1);
  int recr = lua_toboolean(L, 2);
  u_flag *fl;
  GList *cur;

  lua_newtable(L);
  do {
    cur = g_list_first(proc->flags);
    while(cur) {
      fl = cur->data;
      if(recr == 2 && !fl->inherit) {
        cur = g_list_next (cur);
        continue;
      }
      lua_pushinteger(L, i);
      push_u_flag(L, fl, NULL, NULL);
      lua_settable(L, -3);
      i++;
      cur = g_list_next (cur);
    }
    if(recr) {
      if(!proc->node || !proc->node->parent || proc->node->parent == processes_tree) {
        proc = NULL;
        break;
      }
      proc = (u_proc *)(proc->node->parent->data);
      if(recr == 1)
        recr = 2;
    }
  } while (recr && proc);
  return 1;
}

static int u_proc_add_flag (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  u_flag *flag = check_u_flag(L, 2);

  lua_pushinteger(L, u_flag_add(proc, flag));

  return 1;
}

static int u_proc_del_flag (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  u_flag *flag = check_u_flag(L, 2);

  lua_pushinteger(L, u_flag_del(proc, flag));

  return 1;
}

static int u_proc_clear_flag_name (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  const char *name = luaL_checkstring(L, 2);

  u_flag_clear_name(proc, name);

  return 0;
}

static int u_proc_clear_flag_source (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);

  u_flag_clear_source(proc, L);

  return 0;
}

static int u_proc_clear_flag_all (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);

  u_flag_clear_all(proc);

  return 0;
}

static int u_proc_clear_changed (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);

  proc->changed = 0;

  return 0;
}



static int u_proc_kill (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  int signal = SIGTERM;
  
  if(lua_isnumber(L, 2)) {
    signal = lua_tointeger(L, 2);
  }
  
  if(U_PROC_IS_VALID(proc)) {
    kill(proc->proc.tgid, signal);
  }
  
  return 0;
}


static int u_proc_get_n_children (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);

  if(U_PROC_IS_INVALID(proc))
    return 0;

  lua_pushinteger(L, g_node_n_children(proc->node));

  return 1;
}

static int u_proc_get_n_nodes (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);

  if(U_PROC_IS_INVALID(proc))
    return 0;

  lua_pushinteger(L, g_node_n_nodes(proc->node, G_TRAVERSE_ALL));

  return 1;
}

static int u_proc_set_block_scheduler (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  int value = luaL_checkint(L, 2);

  if(U_PROC_IS_INVALID(proc))
    return 0;

  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "block_scheduler set to: %d by %s", value, "(FIXME)");
  proc->block_scheduler = value;
  
  return 0;
}

static int u_proc_set_rtprio (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  struct sched_param param = {0};
  int value = luaL_checkint(L, 2);
  if(lua_isnumber(L, 3))
    param.sched_priority = lua_tointeger(L, 3);


  if(U_PROC_IS_INVALID(proc))
    return 0;


  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "rtprio set to: %d by %s", value, "(FIXME)");

  sched_setscheduler(proc->pid, value, &param);
  
  return 1;
}
/*

disabled due bug (or at least i think it's one):

https://bugzilla.kernel.org/show_bug.cgi?id=27092


static int u_proc_set_pgid (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  int value = luaL_checkint(L, 2);
  long pt;
  int rv;

  if(U_PROC_IS_INVALID(proc))
    return 0;
  pt = ptrace (PTRACE_ATTACH, proc->pid, NULL, NULL);
  printf("ptrace: %d %ld\n", proc->pid, pt);
  wait();
  rv = setpgid(proc->pid, 0);
  if (rv != 0)
    perror("setpgid() error");

  lua_pushinteger(L, rv);
  lua_pushinteger(L, errno);

  if(!pt)
    pt = ptrace (PTRACE_DETACH, proc->pid, NULL, NULL);
  printf("ptrace2: %ld\n", pt);

  return 2;
}

*/

static int u_proc_set_pgid (lua_State *L) {
  u_proc *proc = check_u_proc(L, 1);
  int value = luaL_checkint(L, 2);

  if(U_PROC_IS_INVALID(proc))
    return 0;

  proc->fake_pgrp_old = proc->proc.pgrp;
  proc->fake_pgrp = value;
  proc->changed = 1;

  lua_pushinteger(L, 0);
  lua_pushinteger(L, 0);

  return 2;
}

#define PUSH_INT(name) \
  if(!strcmp(key, #name )) { \
    lua_pushinteger(L, (lua_Integer)proc->proc.name); \
    return 1; \
  }

#define PUSH_STR(name) \
  if(!strcmp(key, #name )) { \
    lua_pushstring(L, proc->proc.name); \
    return 1; \
  }


static int u_proc_index (lua_State *L)
{
  //char        path[PROCPATHLEN];
  char path[PROCPATHLEN];
  u_proc *proc = check_u_proc(L, 1);
  const char *key = luaL_checkstring(L, 2);

/*

  //FIXME this should be handled by u_proc_methods somehow

  //lua_getmetatable (L, 1);
  lua_pushvalue(L, 2);
  stackdump_g(L);

  lua_rawget(L, 1);
  stackdump_g(L);
  
  if(lua_isnil(L, 1)) {
    lua_pop(L, 1);
  } else {
    return 1;
  }
  stackdump_g(L);
*/  
/*  if(luaL_getmetafield (L, 1, key)) {
    //lua_insert (L, 1);
    //lua_call (L, lua_gettop(L)-1, LUA_MULTRET);
    printf("got something\n");
    return 1;
  }
*/
  if(!strcmp(key, "get_parent" )) { \
    lua_pushcfunction(L, u_proc_get_parent);
    return 1;
  }
  if(!strcmp(key, "get_children" )) { \
    lua_pushcfunction(L, u_proc_get_children);
    return 1;
  }

  if(!strcmp(key, "list_flags" )) { \
    lua_pushcfunction(L, u_proc_list_flags);
    return 1;
  }
  if(!strcmp(key, "add_flag" )) { \
    lua_pushcfunction(L, u_proc_add_flag);
    return 1;
  } else if(!strcmp(key, "del_flag" )) { \
    lua_pushcfunction(L, u_proc_del_flag);
    return 1;
  } else if(!strcmp(key, "clear_flag_name" )) { \
    lua_pushcfunction(L, u_proc_clear_flag_name);
    return 1;
  } else if(!strcmp(key, "clear_flag_source" )) { \
    lua_pushcfunction(L, u_proc_clear_flag_source);
    return 1;
  } else if(!strcmp(key, "clear_flag_all" )) { \
    lua_pushcfunction(L, u_proc_clear_flag_all);
    return 1;
  } else if(!strcmp(key, "clear_changed" )) { \
    lua_pushcfunction(L, u_proc_clear_changed);
    return 1;
  } else if(!strcmp(key, "kill" )) {
    lua_pushcfunction(L, u_proc_kill);
    return 1;
  } else if(!strcmp(key, "get_n_children" )) {
    lua_pushcfunction(L, u_proc_get_n_children);
    return 1;
  } else if(!strcmp(key, "get_n_nodes" )) {
    lua_pushcfunction(L, u_proc_get_n_nodes);
    return 1;
  } else if(!strcmp(key, "set_block_scheduler" )) {
    lua_pushcfunction(L, u_proc_set_block_scheduler);
    return 1;
  } else if(!strcmp(key, "set_rtprio" )) {
    lua_pushcfunction(L, u_proc_set_rtprio);
    return 1;
  } else if(!strcmp(key, "set_pgid" )) {
    lua_pushcfunction(L, u_proc_set_pgid);
    return 1;
  }
  
  

  if(!strcmp(key, "is_valid" )) { \
    lua_pushboolean(L, U_PROC_IS_VALID(proc));
    return 1;
  } else if(!strcmp(key, "is_invalid" )) {
    lua_pushboolean(L, U_PROC_IS_INVALID(proc));
    return 1;
  } else if(!strcmp(key, "pid" )) {
    lua_pushinteger(L, proc->pid);
    return 1;
  } else if(!strcmp(key, "changed" )) {
    lua_pushboolean(L, proc->changed);
    return 1;
  } else if(!strcmp(key, "block_scheduler" )) {
    lua_pushinteger(L, proc->block_scheduler);
    return 1;
  } else if(!strcmp(key, "data" )) {
    if(!proc->lua_data) {
      lua_newtable(L);
      lua_pushvalue(L, -1);
      proc->lua_data = luaL_ref(L, LUA_REGISTRYINDEX);
      return 1;
    } else {
      lua_rawgeti(L, LUA_REGISTRYINDEX, proc->lua_data);
      return 1;
    }
    return 0;
  } else if(!strcmp(key, "is_active" )) {
    lua_pushboolean(L, is_active_pid(proc));
    return 1;
  }



  // data of proc.proc must be invalidated as the process is already dead
  if(U_PROC_IS_INVALID(proc)) {
    lua_pushliteral(L, "u_proc state is invalid");
    lua_error(L);
  }
  
  PUSH_INT(tid) //         tid,		// (special)       task id, the POSIX thread ID (see also: tgid)
  PUSH_INT(ppid) //     	ppid;		// stat,status     pid of parent process
  PUSH_INT(state) // stat (special)  %CPU usage (is not filled in by readproc!!!)
  PUSH_INT(utime) 
  PUSH_INT(stime) 
  PUSH_INT(cutime) 
  PUSH_INT(cstime)
  // FIXME need bc lib here
  PUSH_INT(start_time) 
#ifdef SIGNAL_STRING
  PUSH_STR(signal)
  PUSH_STR(blocked)
  PUSH_STR(sigignore)
  PUSH_STR(sigcatch)
  PUSH_STR(_sigpnd)
#endif
//     unsigned KLONG
  PUSH_INT(start_code)
  PUSH_INT(end_code)
  PUSH_INT(start_stack)
  PUSH_INT(kstk_esp)
  PUSH_INT(kstk_eip)
  PUSH_INT(wchan)

  PUSH_INT(priority)
  PUSH_INT(nice)
  PUSH_INT(rss)
  PUSH_INT(alarm)
  PUSH_INT(size)
  PUSH_INT(resident)
  PUSH_INT(share)
  PUSH_INT(trs)
  PUSH_INT(lrs)
  PUSH_INT(drs)
  PUSH_INT(dt)


  PUSH_INT(vm_size)
  PUSH_INT(vm_lock)
  PUSH_INT(vm_rss)
  PUSH_INT(vm_data)
  PUSH_INT(vm_stack)
  PUSH_INT(vm_exe)
  PUSH_INT(vm_lib)
  PUSH_INT(rtprio)
  PUSH_INT(sched)
  PUSH_INT(vsize)
  PUSH_INT(rss_rlim)
  PUSH_INT(flags)
  PUSH_INT(min_flt)
  PUSH_INT(maj_flt)
  PUSH_INT(cmin_flt)
  PUSH_INT(cmaj_flt)
  /*PUSH_INT(flags)
  PUSH_INT(flags)
  PUSH_INT(flags)
  PUSH_INT(flags)
  */
  //FIXME
// 	**environ,	// (special)       environment string vector (/proc/#/environ)
// 	**cmdline;	// (special)       command line string vector (/proc/#/cmdline)
  if(!strcmp(key, "environ" )) {
    // lazy read
    u_proc_ensure(proc, ENVIRONMENT, TRUE);
    if(proc->environ) {
      l_hash_to_table(L, proc->environ);
      return 1;
    }
    return 0;
  }
  if(!strcmp(key, "cmdline" )) {
    if(u_proc_ensure(proc, CMDLINE, FALSE) && proc->cmdline) {
      l_ptrarray_to_table(L, proc->cmdline);
      return 1;
    } else {
      return 0;
    }
  }
  if(!strcmp(key, "cmdline_match" )) {
    if(u_proc_ensure(proc, CMDLINE, FALSE) && proc->cmdline_match) {
      lua_pushstring(L, proc->cmdline_match);
      return 1;
    } else {
      return 0;
    }
  }
  if(!strcmp(key, "cmdfile" )) {
    if(u_proc_ensure(proc, CMDLINE, FALSE) && proc->cmdfile) {
      lua_pushstring(L, proc->cmdfile);
      return 1;
    } else {
      return 0;
    }
  }
  if(!strcmp(key, "exe" )) {
    if(u_proc_ensure(proc, EXE, FALSE) && proc->exe) {
      lua_pushstring(L, proc->exe);
      return 1;
    } else {
      return 0;
    }
  }

  PUSH_STR(euser)
  PUSH_STR(ruser)
  PUSH_STR(suser)
  PUSH_STR(fuser)
  PUSH_STR(rgroup)
  PUSH_STR(egroup)
  PUSH_STR(sgroup)
  PUSH_STR(fgroup)

//     	**supgrp, // status        supplementary groups
  if(!strcmp(key, "groups")) {
      if(proc->proc.supgrp) {
          l_vstr_to_table(L, proc->proc.supgrp, proc->proc.nsupgid);
          return 1;
      } else {
          return 0;
      }
  }
  PUSH_STR(cmd)

//     struct proc_t
// 	*ring,		// n/a             thread group ring
// 	*next;		// n/a             various library uses

  //PUSH_INT(pgrp)
  if(!strcmp(key, "pgrp" )) {
    lua_pushinteger(L, proc->fake_pgrp ? proc->fake_pgrp : (lua_Integer)proc->proc.pgrp);
    return 1;
  }
  PUSH_INT(session)
  PUSH_INT(nlwp)
  PUSH_INT(tgid)
  PUSH_INT(tty)
  PUSH_INT(euid)
  PUSH_INT(egid)
  PUSH_INT(ruid)
  PUSH_INT(rgid)
  PUSH_INT(suid)
  PUSH_INT(sgid)
  PUSH_INT(fuid)
  PUSH_INT(fgid)
  PUSH_INT(tpgid)
  PUSH_INT(nsupgid)
// 	*supgid,	// status        supplementary gid's
  PUSH_INT(exit_signal)
  PUSH_INT(processor)

  if(!strcmp(key, "cgroup_name" )) {
    sprintf(path, "/proc/%d", proc->proc.tgid);
    proc->proc.cgroup = file2strvec(path, "cgroup"); 	/* read /proc/#/cgroup */
    if(proc->proc.cgroup && *proc->proc.cgroup) {
      int i = strlen(*proc->proc.cgroup);
      if( (*proc->proc.cgroup)[i-1]=='\n' )
        (*proc->proc.cgroup)[i-1] = ' '; //little hack to remove trailing \n
      lua_pushstring(L, *proc->proc.cgroup);
      return 1;
    }
    return 0;
  }


  return 0;
}

#undef PUSH_INT
#undef PUSH_STR

// u_flag

static int u_flag_gc (lua_State *L)
{
  u_flag *flag = check_u_flag(L, 1);
  //printf("goodbye proc_t (%p)\n", proc);
  DEC_REF(flag);
  return 0;
}


static int u_flag_tostring (lua_State *L)
{
  u_flag **flag = lua_touserdata(L, 1);
  u_flag *flg = *flag;
  lua_pushfstring(L, "u_flag: <%p> %s ", flg, flg->name ? flg->name : "(no name)");
  return 1;
}

#define PUSH_INT(name) \
  if(!strcmp(key, #name )) { \
    lua_pushinteger(L, (lua_Integer)flag->name); \
    return 1; \
  }

#define PUSH_BOOL(name) \
  if(!strcmp(key, #name )) { \
    lua_pushboolean(L, flag->name); \
    return 1; \
  }


#define PUSH_CHR(name) \
  if(!strcmp(key, #name )) { \
    lua_pushstring(L, flag->name); \
    return 1; \
  }

#define PULL_INT(name) \
  if(!strcmp(key, #name )) { \
    flag->name = luaL_checkinteger(L, 3); \
    return 0; \
  }

#define PULL_CHR(name) \
  if(!strcmp(key, #name)) { \
    if(flag->name) \
      free(flag->name); \
    flag->name = g_strdup(luaL_checkstring(L, 3)); \
    return 0; \
  }


static int u_flag_index (lua_State *L)
{
  u_flag *flag = check_u_flag(L, 1);
  const char *key = luaL_checkstring(L, 2);

  PUSH_CHR(name)
  PUSH_BOOL(inherit)
  PUSH_INT(priority)
  PUSH_INT(timeout)
  PUSH_CHR(reason)
  PUSH_INT(value)
  PUSH_INT(threshold)
  if(!strcmp(key, "is_source")) {
    lua_pushboolean(L, flag->source == L);
  }
  return 0;
}

static int u_flag_newindex (lua_State *L)
{
  u_flag *flag = check_u_flag(L, 1);
  const char *key = luaL_checkstring(L, 2);

  PULL_CHR(name)
  PULL_CHR(reason)

  PULL_INT(inherit)
  PULL_INT(priority)
  PULL_INT(timeout)
  //PULL_INT(reason)
  PULL_INT(value)
  PULL_INT(threshold)
  return 0;
}

#define CHK_N_SET(name, conv) \
  lua_getfield (L, 1, #name ); \
  if(!lua_isnil (L, -1)) { \
    flag-> name = conv ; \
  } \
  lua_pop(L, 1);


static int l_flag_new (lua_State *L)
{
  //u_flag *flag = check_u_filter(L, 1);
  u_flag *flag = NULL;
  //luaL_checktype(L, 1, LUA_TTABLE);
  const char *name = NULL;
  //void *source = NULL;

  if(lua_istable(L, 1)) {
    lua_getfield (L, 1, "name");
    if(lua_isstring(L, -1)) {
      name = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    flag = push_u_flag(L, NULL, L, name);

    CHK_N_SET(inherit, lua_toboolean(L, -1))
    CHK_N_SET(priority, lua_tointeger(L, -1))
    CHK_N_SET(timeout, lua_tointeger(L, -1))
    CHK_N_SET(reason, g_strdup(lua_tostring(L, -1)) )
    CHK_N_SET(value, lua_tointeger(L, -1))
    CHK_N_SET(threshold, lua_tointeger(L, -1))
    return 1;
  }
  
  if(lua_isstring(L, 1)) {
    name = lua_tostring(L, 1);
  }

  //lua_getfield(L, 1, "__u_source");
  //if(!lua_islightuserdata(L, -1))
  //  luaL_typerror(L, 2, "source instance not found");
  //source = lua_touserdata(L, -1);

  push_u_flag(L, NULL, L, name);
  return 1;
}

#undef CHK_N_SET

static int u_flag_eq (lua_State *L)
{
  u_flag *flag = check_u_flag(L, 1);
  u_flag *flag2 = check_u_flag(L, 2);

  lua_pushboolean(L, flag == flag2);
  return 1;
}


static const luaL_reg u_flag_meta[] = {
  {"__gc",       u_flag_gc},
  {"__tostring", u_flag_tostring},
  {"__index",    u_flag_index},
  {"__newindex", u_flag_newindex},
  {"__eq",       u_flag_eq},
  {NULL, NULL}
};

static const luaL_reg u_flag_methods[] = {
  {NULL,NULL}
};


// system flags
static int u_sys_list_flags (lua_State *L) {
  int i = 1;
  u_flag *fl;
  GList *cur;

  lua_newtable(L);
  cur = g_list_first(system_flags);
  while(cur) {
    fl = cur->data;
    lua_pushinteger(L, i);
    push_u_flag(L, fl, NULL, NULL);
    lua_settable(L, -3);
    i++;
    cur = g_list_next (cur);
  }
  return 1;
}

static int u_sys_add_flag (lua_State *L) {
  u_flag *flag = check_u_flag(L, 1);

  lua_pushinteger(L, u_flag_add(NULL, flag));

  return 1;
}

static int u_sys_del_flag (lua_State *L) {
  u_flag *flag = check_u_flag(L, 1);

  lua_pushinteger(L, u_flag_del(NULL, flag));

  return 1;
}

static int u_sys_clear_flag_name (lua_State *L) {
  const char *name = luaL_checkstring(L, 1);

  u_flag_clear_name(NULL, name);

  return 0;
}

static int u_sys_clear_flag_source (lua_State *L) {

  u_flag_clear_source(NULL, L);

  return 0;
}

static int u_sys_clear_flag_all (lua_State *L) {

  u_flag_clear_all(NULL);

  return 0;
}

static int u_sys_get_flags_changed(lua_State *L) {

  lua_pushboolean(L, system_flags_changed);

  return 1;
}

static int u_sys_set_flags_changed(lua_State *L) {

  system_flags_changed = luaL_checkint(L, 1);

  return 0;
}


int l_scheduler_run(lua_State *L, u_proc *proc) {
  int base = lua_gettop(L);
  char *key = "all";
  int args = 1;
  int rv = 1;
  lua_getfield(L, LUA_GLOBALSINDEX, "ulatency"); /* function to be called */
  lua_getfield(L, -1, "scheduler");
  lua_remove(L, 1);
  if(lua_istable(L, 1)) {
    if(proc) {
      key = "one";
    }
    lua_getfield(L, 1, key);
    if(!lua_isfunction(L, 2)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "can't find lua scheduling handling function: %s", key);
      goto error;
    }
    lua_pushvalue(L, 1);
    if(proc) {
      push_u_proc(L, proc);
      args = 2;
    }
    if(docall(L, args, 1)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "lua scheduler failed");
      goto error;
    }
    if(!lua_toboolean(L, -1)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "lua scheduler returned false");
    } else {
      rv = 0;
    }
  }

error:
  lua_pop(L, lua_gettop(L)-base);
  return rv;
  //stackdump_g(L);
}

static int wrap_l_scheduler_run() {
  return l_scheduler_run(lua_main_state, NULL);
}

static int wrap_l_scheduler_run_one(u_proc *proc) {
  return l_scheduler_run(lua_main_state, proc);
}

static int l_scheduler_set_config(char *name) {
  lua_State *L = lua_main_state;
  int base = lua_gettop(lua_main_state);
  int rv = FALSE;

  lua_getfield(L, LUA_GLOBALSINDEX, "ulatency"); /* function to be called */
  lua_getfield(L, -1, "scheduler");
  lua_remove(L, 1);

  if(lua_istable(L, 1) && name) {
    lua_getfield(L, 1, "set_config");
    if(!lua_isfunction(L, 2)) {
      goto out;
    }
    lua_pushvalue(L, 1);
    lua_pushstring(L, name);
    if(docall(L, 2, 1)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "lua scheduler.set_config failed");
      goto out;
    }
    if(!lua_toboolean(L, -1)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "lua scheduler.set_config returned false");
    } else {
      rv = TRUE;
    }
  }

out:
  lua_pop(L, lua_gettop(L)-base);
  return rv;
}

static GPtrArray *l_scheduler_list_configs() {
  lua_State *L = lua_main_state;
  int base = lua_gettop(lua_main_state);
  GPtrArray *rv = NULL;
  int len, i;

  lua_getfield(L, LUA_GLOBALSINDEX, "ulatency"); /* function to be called */
  lua_getfield(L, -1, "scheduler");
  lua_remove(L, 1);

  if(lua_istable(L, 1)) {
    lua_getfield(L, 1, "list_configs");
    if(!lua_isfunction(L, 2)) {
      goto out;
    }
    lua_pushvalue(L, 1);
    lua_pushstring(L, "list_configs");
    if(docall(L, 2, 1)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "lua scheduler.list_configs failed");
      goto out;
    }
    if(!lua_istable(L, -1)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "lua scheduler.list_configs did't return a table");
    } else {
      len = lua_objlen (L, -1);
      if(len)
        rv = g_ptr_array_new();
      for(i = 1; i <= len; i++) {
        lua_pushinteger(L, i);
        lua_gettable(L, -2);
        g_ptr_array_add(rv, g_strdup(lua_tostring(L, -1)));
        lua_pop(L, 1);
      }
    }
  }

out:
  lua_pop(L, lua_gettop(L)-base);
  return rv;
}

char *l_scheduler_get_description(char *name) {
  lua_State *L = lua_main_state;
  int base = lua_gettop(lua_main_state);
  char *rv = NULL;

  lua_getfield(L, LUA_GLOBALSINDEX, "ulatency"); /* function to be called */
  lua_getfield(L, -1, "scheduler");
  lua_remove(L, 1);

  if(lua_istable(L, 1) && name) {
    lua_getfield(L, 1, "get_config_description");
    if(!lua_isfunction(L, 2)) {
      goto out;
    }
    lua_pushvalue(L, 1);
    lua_pushstring(L, name);
    if(docall(L, 2, 1)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "lua scheduler.get_description failed");
      goto out;
    }
    if(!lua_isnil(L, -1))
      rv = g_strdup(lua_tostring(L, -1));
  }

out:
  lua_pop(L, lua_gettop(L)-base);
  return rv;
}


u_scheduler LUA_SCHEDULER = {
  .all=wrap_l_scheduler_run,
  .one=wrap_l_scheduler_run_one,
  .list_configs = l_scheduler_list_configs,
  .set_config = l_scheduler_set_config,
  .get_config_description = l_scheduler_get_description,
};


// FILTER mappings

int l_filter_callback(u_proc *proc, u_filter *flt) {
  gint rv;
  lua_State *L;
  u_proc *nproc;
  struct lua_filter *lf = (struct lua_filter *)flt->data;

  g_assert(flt->type == FILTER_LUA);

  L = lf->lua_state;

  lua_rawgeti (L, LUA_REGISTRYINDEX, lf->lua_func);
  //lua_pushstring(lf->lua_state, "check")
  lua_getfield (L, -1, "check");
  if(!lua_isfunction(L, -1)) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "filter does not have a check method, disable %s", flt->name);
    lua_pop(L, 2);
    return FILTER_STOP;
  }
  lua_pushvalue(L, -2);
  nproc = push_u_proc(L, proc);
  //cp_proc_t(proc, nproc);
  if(docall(L, 2, 1)) {
    // execution error.
    lua_pop(L, 1);
    return 0;
  }
  //stackdump_g(L);
  rv = lua_tointeger(L, -1);
  lua_pop(L, 2);
  return rv;
}

int l_filter_run_table(u_filter *flt, char *key) {
  gint rv;
  lua_State *L;
  struct lua_filter *lf = (struct lua_filter *)flt->data;

  g_assert(flt->type == FILTER_LUA);

  L = lf->lua_state;

  if(lf->min_percent && lf->min_percent >= get_last_percent())
    return TRUE;

  lua_rawgeti (L, LUA_REGISTRYINDEX, lf->lua_func);
  //lua_pushstring(lf->lua_state, "check")
  lua_getfield (L, -1, key);
  if(!lua_isfunction(L, -1)) {
    lua_pop(L, 2);
    return TRUE;
  }
  lua_pushvalue(L, -2);
  if(docall(L, 1, 1)) {
    // execution error.
    lua_pop(L, 1);
    return FALSE;
  }

  rv = lua_toboolean(L, -1);
  lua_pop(L, 2);

  return rv;
}

inline int l_filter_precheck(u_filter *flt) {
  return l_filter_run_table(flt, "precheck");
}

inline int l_filter_postcheck(u_filter *flt) {
  return l_filter_run_table(flt, "postcheck");
}


int l_filter_check(u_proc *proc, u_filter *flt) {
  struct lua_filter *lft = (struct lua_filter *)flt->data;

  if(lft->regexp_basename && proc->proc.cmd[0]) {
    if(g_regex_match(lft->regexp_basename, &proc->proc.cmd[0], 0, NULL))
      return TRUE;
  }
  if(lft->regexp_cmdline) {
    u_proc_ensure(proc, CMDLINE, FALSE);
    if(proc->cmdline_match) {
      if(g_regex_match(lft->regexp_cmdline, proc->cmdline_match, 0, NULL))
        return TRUE;
    }
  }
 
/*  lua_rawgeti (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_func);
  lua_rawgeti (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_data);
  //stackdump_g(cd->lua_state);
  lua_call (cd->lua_state, 1, 1);
  rv = lua_toboolean (cd->lua_state, -1);

  if(rv)
    return TRUE;

  luaL_unref (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_func);
  free(data);
  return FALSE;
*/
  return FALSE;
}

static GRegex *map_reg(lua_State *L, char *key) {
  GError *error = NULL;
  const char *tmp;
  GRegex *rv = NULL;
  lua_getfield (L, 1, key);
  //stackdump_g(L);
  if(lua_isstring(L, -1)) {
    rv = g_regex_new(lua_tostring(L, -1), G_REGEX_OPTIMIZE, 0, &error);
    if(error && error->code) {
      rv = NULL;
      luaL_where (L, 1);
      tmp = lua_tostring(L, -1);
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Error compiling filter in %s: %s", tmp, error->message );
      g_error_free(error);
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);
  return rv;
}

static int l_register_filter (lua_State *L) {
  lua_Debug ar;
  luaL_checktype(L, 1, LUA_TTABLE);
  //guint interval = luaL_checkint(L, 2);
  struct lua_filter *lf = malloc(sizeof(struct lua_filter));
  u_filter *flt = filter_new();
  memset(lf, 0, sizeof(struct lua_filter));

  //lf->lua_state = L;
  lf->lua_state = lua_newthread (L);
  lf->lua_state_id = luaL_ref(L, LUA_REGISTRYINDEX);

  //lua_pushlightuserdata (L, flt);
  //lua_setfield (L, 1, "__u_source");
  lua_pushvalue(L, 1);
  lf->lua_func = luaL_ref(L, LUA_REGISTRYINDEX);

  lua_pushlightuserdata (L, flt);
  lf->filter = luaL_ref(L, LUA_REGISTRYINDEX);

  lf->regexp_cmdline = map_reg(L, "re_cmdline");
  lf->regexp_basename = map_reg(L, "re_basename");
  lua_getfield (L, 1, "min_percent");
  if (lua_isnumber(L, -1)) {
    lf->min_percent = lua_tonumber (L, 1);
  } else {
    lf->min_percent = 0.0;
    lua_pop(L, 1);
  }

  if(lf->regexp_cmdline || lf->regexp_basename || lf->min_percent)
    flt->check = l_filter_check;

  // construct a filter name if missing
  lua_getfield (L, 1, "name");
  lua_getstack(L, 1, &ar);
  lua_getinfo(L, "Sl", &ar);
  if (lua_isstring(L, -1)) {
    lua_pushfstring(L, "%s: %s", ar.short_src, lua_tostring(L, -1));
  } else {
    if (ar.currentline > 0)  /* is there info? */
      lua_pushfstring(L, "%s:%d (unknown)", ar.short_src, ar.currentline);
    else
      lua_pushstring(L, "(unknown)");
  }
  flt->name = g_strdup(lua_tostring(L, -1));
  // remove name strings
  lua_pop(L, 2);

  // finish data structures

  flt->data = lf;
  flt->callback = l_filter_callback;
  flt->precheck = l_filter_precheck;
  flt->postcheck = l_filter_postcheck;
  filter_register(flt);

  return 0;
}


static int u_proc_eq (lua_State *L)
{
  u_proc *proc = check_u_proc(L, 1);
  u_proc *proc2 = check_u_proc(L, 2);

  lua_pushboolean(L, proc == proc2);
  return 1;
}


static const luaL_reg u_proc_meta[] = {
  {"__gc",       u_proc_gc},
  {"__tostring", u_proc_tostring},
  {"__index",    u_proc_index},
  {"__eq",       u_proc_eq},
  {NULL, NULL}
};

static const luaL_reg u_proc_methods[] = {
  {NULL,NULL}
};

static int l_process_update (lua_State *L) {
  // DANGEROUS: can cause endless loop
  int pid = lua_tointeger(L, 1);
  if(pid) {
    process_update_pid(pid);
  } else {
    process_update_all();
  }
  return 0;
}


static int l_run_interation (lua_State *L) {
  // DANGEROUS: can cause endless loop
  g_debug("run iteration from lua");

  g_timeout_add(0, iterate, GUINT_TO_POINTER(0));
  return 0;
}

static int l_get_uid (lua_State *L) {
  lua_pushinteger(L, getuid());
  return 1;
}

static int l_get_time (lua_State *L) {
  time_t t = time(NULL);
  
  if(lua_isnumber(L, 1)) {
    t += lua_tointeger(L, 1);
  }
  
  lua_pushinteger(L, t);
  return 1;
}


static int user_load_lua_rule_file(lua_State *L) {
  char *full;
  const char *name = luaL_checkstring(L, 1);
  int abs = lua_toboolean(L, 2);

  if(!abs) {
    full = g_strconcat(QUOTEME(RULES_DIRECTORY), "/", name, NULL);
    lua_pushboolean(L, !load_lua_rule_file(L, full));
    g_free(full);
  } else {
    lua_pushboolean(L, !load_lua_rule_file(L, name));
  }
  return 1;
}

static int l_uid_stats(lua_State *L) {
    GList *cur = U_session_list;
    u_session *sess;
    uid_t uid = luaL_checkinteger(L, 1);
    int act = 0;
    int idle = 1;
    while(cur) {
        sess = cur->data;
        if(sess->uid == uid) {
            if(sess->active)
                act = 1;
            if(!sess->idle)
                idle = 0;
        }
        cur = g_list_next(cur);
    }
    lua_pushboolean(L, act);
    lua_pushboolean(L, idle);
    return 2;
}

static int l_search_uid_env(lua_State *L) {
    uid_t uid = luaL_checkinteger(L, 1);
    const char *key = luaL_checkstring(L, 2);
    int update = FALSE;
    GPtrArray* data;
    
    if(lua_isnumber(L, 3))
        update = lua_tointeger(L, 3);
    
    data = search_user_env(uid, key, update);
    l_ptrarray_to_table(L, data);
    
    g_ptr_array_unref(data);
    return 1;
}

static int l_get_sessions(lua_State *L) {
    GList *cur = U_session_list;
    u_session *sess;
    lua_newtable(L);
    int i = 1;
    while(cur) {
        sess = cur->data;
        lua_pushinteger(L, i);
        lua_newtable(L);
        lua_pushstring(L, sess->name);
        lua_setfield (L, -2, "name");
        lua_pushstring(L, sess->X11Display);
        lua_setfield (L, -2, "X11Display");
        lua_pushstring(L, sess->X11Device);
        lua_setfield (L, -2, "X11Device");
        lua_pushstring(L, sess->dbus_session);
        lua_setfield (L, -2, "dbus_session");
        lua_pushinteger(L, sess->uid);
        lua_setfield (L, -2, "uid");
        lua_pushboolean(L, sess->idle);
        lua_setfield (L, -2, "idle");
        lua_pushboolean(L, sess->active);
        lua_setfield (L, -2, "active");
        lua_settable(L, -3);
        i++;
        cur = g_list_next(cur);
    }
    return 1;
}
/* object table */
static const luaL_reg R[] = {
  // system load
  {"get_load",  get_load},
  {"get_uptime",  get_uptime},
  {"get_meminfo",  get_meminfo},
  {"get_vminfo",  get_vminfo},
  {"get_pid_digits",  l_get_pid_digits},

  {"get_last_load",  l_get_last_load},
  {"get_last_percent",  l_get_last_percent},

  // converts
  {"group_from_gid",  l_group_from_guid},
  {"user_from_uid",  l_user_from_uid},
  // pid receive
  {"get_pid",  l_get_pid},
  {"list_pids",  l_list_pids},
  {"list_processes",  l_list_processes},
  {"add_timeout", l_add_interval},
  {"register_filter", l_register_filter},
  // flag code
  {"new_flag", l_flag_new},
  // system flag manipulation
  {"list_flags", u_sys_list_flags},
  {"add_flag", u_sys_add_flag},
  {"del_flag", u_sys_del_flag},
  {"clear_flag_name", u_sys_clear_flag_name},
  {"clear_flag_source", u_sys_clear_flag_source},
  {"clear_flag_all", u_sys_clear_flag_all},
  {"get_flags_changed", u_sys_get_flags_changed},
  {"set_flags_changed", u_sys_set_flags_changed},

  // group code
  {"set_active_pid", l_set_active_pid},
  {"get_active_uids", l_get_active_uids},
  {"get_active_pids", l_get_active_pids},
  // config
  {"get_config",  l_get_config},
  {"list_keys",  l_list_keys},
  // system & user querying
  {"get_sessions", l_get_sessions},
  {"get_uid_stats", l_uid_stats},
  {"search_uid_env", l_search_uid_env},
  // misc
  {"filter_rv",  l_filter_rv},
  {"log",  l_log},
  {"get_uid", l_get_uid},
  {"get_time", l_get_time},
  {"quit_daemon", l_quit},
  {"load_rule", user_load_lua_rule_file},
  {"process_update", l_process_update},
  {"run_iteration", l_run_interation},
	{NULL,        NULL}
};


#undef PUSH_INT
#undef PUSH_STR

#define PUSH_INT(NAME, SYMBOLE)\
	lua_pushinteger(L, SYMBOLE); \
	lua_setfield(L, -2, #NAME);

#define PUSH_STR(NAME, SYMBOLE)\
	lua_pushstring(L, SYMBOLE); \
	lua_setfield(L, -2, #NAME);

int luaopen_ulatency(lua_State *L) {


	/* create metatable */
	luaL_newmetatable(L, UL_META);

	/* metatable.__index = metatable */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	/* register module */
	luaL_register(L, "ulatency", R);

	/* register metatable as socket_meta */
	lua_pushvalue(L, -2);
	lua_setfield(L, -2, "meta_ulatency");

	/* module version */
  PUSH_STR(version, QUOTEME(VERSION))
  PUSH_STR(release_agent, QUOTEME(RELEASE_AGENT))

  //PUSH_INT(hertz, Hertz)
  PUSH_INT(smp_num_cpus, smp_num_cpus)


  // glib log level
  PUSH_INT(LOG_LEVEL_ERROR, G_LOG_LEVEL_ERROR)
  PUSH_INT(LOG_LEVEL_CRITICAL, G_LOG_LEVEL_CRITICAL)
  PUSH_INT(LOG_LEVEL_WARNING, G_LOG_LEVEL_WARNING)
  PUSH_INT(LOG_LEVEL_MESSAGE, G_LOG_LEVEL_MESSAGE)
  PUSH_INT(LOG_LEVEL_INFO, G_LOG_LEVEL_INFO)
  PUSH_INT(LOG_LEVEL_DEBUG, G_LOG_LEVEL_DEBUG)
  
  PUSH_INT(FILTER_STOP, FILTER_STOP)
  PUSH_INT(FILTER_SKIP_CHILD, FILTER_SKIP_CHILD)

  PUSH_INT(IOPRIO_CLASS_NONE, IOPRIO_CLASS_NONE)
  PUSH_INT(IOPRIO_CLASS_RT, IOPRIO_CLASS_RT)
  PUSH_INT(IOPRIO_CLASS_BE, IOPRIO_CLASS_BE)
  PUSH_INT(IOPRIO_CLASS_IDLE, IOPRIO_CLASS_IDLE)

  // realtime priority stuff
  PUSH_INT(SCHED_OTHER, SCHED_OTHER)
  PUSH_INT(SCHED_FIFO, SCHED_FIFO)
  PUSH_INT(SCHED_RR, SCHED_RR)
  PUSH_INT(SCHED_BATCH, SCHED_BATCH)
  PUSH_INT(SCHED_IDLE, SCHED_IDLE)

  PUSH_INT(UPROC_NEW, UPROC_NEW)
  PUSH_INT(UPROC_INVALID, UPROC_INVALID)
  PUSH_INT(UPROC_ALIVE, UPROC_ALIVE)

  /* remove meta table */
	lua_remove(L, -2);

  // map u_proc
  luaL_register(L, U_PROC, u_proc_methods); 
  luaL_newmetatable(L, U_PROC_META);
  luaL_register(L, NULL, u_proc_meta);
  //lua_pushliteral(L, "__index");
  //lua_pushvalue(L, -3);
  //lua_rawset(L, -3);                  /* metatable.__index = methods */
  lua_pushliteral(L, "__metatable");
  lua_pushvalue(L, -2);               /* dup methods table*/
  lua_rawset(L, -4);
  lua_pop(L, 1);

  // map u_filter
  luaL_register(L, U_FLAG, u_flag_methods); 
  luaL_newmetatable(L, U_FLAG_META);
  luaL_register(L, NULL, u_flag_meta);
  //lua_pushliteral(L, "__index");
  //lua_pushvalue(L, -3);
  //lua_rawset(L, -3);                  /* metatable.__index = methods */
  lua_pushliteral(L, "__metatable");
  lua_pushvalue(L, -2);               /* dup methods table*/
  lua_rawset(L, -4);
  lua_pop(L, 1);

  luaL_ref(L, LUA_REGISTRYINDEX);
  luaL_ref(L, LUA_REGISTRYINDEX);
  luaL_ref(L, LUA_REGISTRYINDEX);
  luaL_ref(L, LUA_REGISTRYINDEX);

	return 1;
}

// misc functions

static int report (lua_State *L, int status) {
  if (status && !lua_isnil(L, -1)) {
    const char *msg = lua_tostring(L, -1);
    if (msg == NULL) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, 
            "(status: %d, error object is not a string. it is: %s)", 
            status, lua_typename(L, -1));
    } else {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "%d: %s", status, msg);
    }
    lua_pop(L, 1);
  }
  //stackdump_g(L);
  return status;
}

static int traceback (lua_State *L) {
  //if (!lua_isstring(L, 1))  /* 'message' not a string? */
  //  return 1;  /* keep it intact */
  //lua_tostring(L, 1);
  if (!lua_isstring(L, 1)) {
    lua_getfield(L, LUA_GLOBALSINDEX, "tostring");
    //lua_pushvalue(L, 1);  /* pass error message */
    lua_call(L, 1, 1); 
  }
  
  lua_getfield(L, LUA_GLOBALSINDEX, "debug");
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    return 1;
  }
  lua_getfield(L, -1, "traceback");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  //lua_pushliteral(L, "bla");
  lua_pushvalue(L, 1);  /* pass error message */
  lua_pushinteger(L, 2);  /* skip this function and traceback */
  lua_call(L, 2, 1);  /* call debug.traceback */
  return 1;
}

static int docall (lua_State *L, int narg, int nresults) {
  int status;
  int base = lua_gettop(L) - narg;  /* function index */
  //printf("docall\n");
  lua_pushcfunction(L, traceback);  /* push traceback function */
  lua_insert(L, base);  /* put it under chunk and args */
  //stackdump_g(L);
  status = lua_pcall(L, narg, nresults, base);
  //printf("--- %d\n", status);
  //stackdump_g(L);
  lua_remove(L, base);  /* remove traceback function */
  /* force a complete garbage collection in case of errors */
  if (status != 0) {
    report(L, status);
    lua_gc(L, LUA_GCCOLLECT, 0);
  }
  //stackdump_g(L);
  return status;
}



int load_lua_rule_file(lua_State *L, const char *name) {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "load %s", name);
  if(luaL_loadfile(L, name)) {
    report(L, 1);
    return 1;
  }
  if(lua_pcall(L, 0, LUA_MULTRET, 0)) {
    report(L, 1);
  }
  return 0;

}

