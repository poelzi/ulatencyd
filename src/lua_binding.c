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

#define UL_META "ulatency"
#define LUA_TABLE_INT(NAME) \
  lua_pushliteral(L, #NAME); \
  lua_pushinteger(L,   NAME); \
  lua_settable(L, -3);

#define OPENPROC_FLAGS PROC_FILLMEM | \
  PROC_FILLUSR | PROC_FILLGRP | PROC_FILLSTATUS | PROC_FILLSTAT | \
  PROC_FILLWCHAN | PROC_FILLCGROUP | PROC_FILLSUPGRP


//static proc_t *push_proc_t (lua_State *L);
static u_proc *push_u_proc_new (lua_State *L);
static u_proc *push_u_proc (lua_State *L, u_proc *proc);

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

static int l_get_pid (lua_State *L) {
  int pid;
  proc_t buf;
  proc_t *out;
  PROCTAB *proctab;
  //FIXME
/*
  pid = luaL_checkint (L, 1);
  //proctab = openproc(PROC_PID, pid);
  memset(&buf, 0, sizeof(proc_t));
  proctab = openproc(OPENPROC_FLAGS);
  if(!proctab)
    return luaL_error (L, "Error: can not access /proc.");
  while(readproc(proctab,&buf)){
    if(buf.tgid == pid) {
       //out = push_proc_t(L);
       out = push_u_proc_new(L);
       //memcpy(out, &buf, sizeof(proc_t));
       //cp_proc_t(&buf, out);
       closeproc(proctab);
       return 1;
    }
  }
  closeproc(proctab);
*/
  return 0;
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
  int i = 0;
  char key[20];
  proc_t buf;
  proc_t *out;
  PROCTAB *proctab;

  lua_newtable (L);
  //proctab = openproc(PROC_PID, pid);
  proctab = openproc(0);
  if(!proctab)
    return luaL_error (L, "Error: can not access /proc.");
  while(readproc(proctab,&buf)){
    sprintf(key, "%d", i);
    lua_pushinteger(L, buf.tgid);
    lua_setfield(L, -2, &key[0]);
    i++;
  }
  closeproc(proctab);
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
  struct user_process *up;
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
}

static int l_quit (lua_State *L) {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "%s", "quit called from script");
  if(g_main_loop_is_running(main_loop))
    g_main_loop_quit(main_loop);
  else
    exit(0);
}

gboolean l_call_function(gpointer data) {
  gboolean rv;
  struct lua_callback *cd = (struct lua_callback *)data;

  lua_rawgeti (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_func);
  lua_rawgeti (cd->lua_state, LUA_REGISTRYINDEX, cd->lua_data);
  //stackdump_g(cd->lua_state);
  lua_call (cd->lua_state, 1, 1);
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


// bindings to proc_t
#define U_PROC "u_proc"

static proc_t *check_proc_t (lua_State *L, int index)
{
  proc_t *p;
  luaL_checktype(L, index, LUA_TUSERDATA);
  p = (proc_t *)luaL_checkudata(L, index, U_PROC);
  if (p == NULL) luaL_typerror(L, index, U_PROC);
  return p;
}

static u_proc *push_u_proc (lua_State *L, u_proc *proc)
{
  //u_proc *p = (u_proc*)lua_newuserdata(L, sizeof(u_proc));
  u_proc **p = (u_proc **)lua_newuserdata(L, sizeof(u_proc *));
  *p = proc;
  proc->in_lua = 1;
  luaL_getmetatable(L, U_PROC);
  lua_setmetatable(L, -2);

  //up = u_proc_new();
/*
  memset(p, 0, sizeof(proc_t));
  return p;
*/
  return proc;
}

static u_proc *push_u_proc_new (lua_State *L)
{
  u_proc *proc;
  //u_proc *p = (u_proc*)lua_newuserdata(L, sizeof(u_proc));
  u_proc **p = (u_proc **)lua_newuserdata(L, sizeof(u_proc *));
  proc = u_proc_new();
  *p = proc;
  proc->in_lua = 1;
  DEC_REF(proc);
  luaL_getmetatable(L, U_PROC);
  lua_setmetatable(L, -2);

  //up = 
/*
  memset(p, 0, sizeof(proc_t));
  return p;
*/
  return proc;
}


static int proc_t_gc (lua_State *L)
{
  proc_t *proc = check_proc_t(L, 1);
  //printf("goodbye proc_t (%p)\n", proc);
  if (proc) {
    freesupgrp(proc);
    freeproc_light(proc);
  }
  return 0;
}


static int proc_t_tostring (lua_State *L)
{
  proc_t *proc = lua_touserdata(L, 1);
  lua_pushfstring(L, "proc_t: <%p> pid:%d", proc, proc->tid);
  return 1;
}


#define PUSH_INT(name) \
  if(!strcmp(key, #name )) { \
    lua_pushinteger(L, (lua_Integer)proc->name); \
    return 1; \
  }
#define PUSH_STR(name) \
  if(!strcmp(key, #name )) { \
    lua_pushlstring(L, proc->name, sizeof(proc->name)); \
    return 1; \
  }

static int proc_t_index (lua_State *L)
{
  //char        path[PROCPATHLEN];
  char path[PROCPATHLEN];
  proc_t *proc = check_proc_t(L, 1);
  const char *key = luaL_checkstring(L, 2);
  
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
  PUSH_INT(flags)
  PUSH_INT(flags)
  PUSH_INT(flags)
  PUSH_INT(flags)
  //FIXME
// 	**environ,	// (special)       environment string vector (/proc/#/environ)
// 	**cmdline;	// (special)       command line string vector (/proc/#/cmdline)
  if(!strcmp(key, "environ" )) {
    // lazy read
    if(!proc->environ) {
        sprintf(path, "/proc/%d", proc->tgid);
      	proc->environ = file2strvec(path, "environ"); /* often permission denied */
    }
    if(!proc->environ)
      return 0;
    lua_pushstring(L, *proc->environ);
    return 1;
  }
  if(!strcmp(key, "cmdline" )) {
    if(!proc->cmdline) {
        sprintf(path, "/proc/%d", proc->tgid);
        proc->cmdline = file2strvec(path, "cmdline");
    }
    if(proc->cmdline) {
      lua_pushstring(L, *proc->cmdline);
      return 1;
    }
    return 0;
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
  PUSH_STR(cmd)

//     struct proc_t
// 	*ring,		// n/a             thread group ring
// 	*next;		// n/a             various library uses

  PUSH_INT(pgrp)
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
    sprintf(path, "/proc/%d", proc->tgid);
    proc->cgroup = file2strvec(path, "cgroup"); 	/* read /proc/#/cgroup */
    if(proc->cgroup && *proc->cgroup) {
      int i = strlen(*proc->cgroup);
      if( (*proc->cgroup)[i-1]=='\n' )
        (*proc->cgroup)[i-1] = ' '; //little hack to remove trailing \n
      lua_pushstring(L, *proc->cgroup);
      return 1;
    }
    return 0;
  }


  return 0;
}

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

  lua_call(L, 2, 1);
  rv = lua_tointeger(L, -1);
  lua_pop(L, 2);
  //stackdump_g(L);
  return rv;
}

int l_filter_check(u_proc *proc, u_filter *flt) {
  gboolean rv;
  struct lua_filter *lft = (struct lua_filter *)flt->data;

  if(lft->regexp_basename && proc->proc.cmd[0]) {
    if(g_regex_match(lft->regexp_basename, &proc->proc.cmd[0], 0, NULL))
      return TRUE;
  }
  if(lft->regexp_cmdline && proc->proc.cmdline) {
    if(g_regex_match(lft->regexp_cmdline, *proc->proc.cmdline, 0, NULL))
      return TRUE;
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

  lua_pushvalue(L, 1);
  lf->lua_func = luaL_ref(L, LUA_REGISTRYINDEX);

  lf->regexp_cmdline = map_reg(L, "re_cmdline");
  lf->regexp_basename = map_reg(L, "re_basename");
  if(lf->regexp_cmdline || lf->regexp_basename)
    flt->check = l_filter_check;

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
  lua_pop(L, 2);

  flt->data = lf;
  flt->callback = l_filter_callback;
  filter_register(flt);

  return 0;
}



static const luaL_reg proc_t_meta[] = {
  {"__gc",       proc_t_gc},
  {"__tostring", proc_t_tostring},
  {"__index", proc_t_index},
  {0, 0}
};

static const luaL_reg proc_t_methods[] = {
  {NULL,NULL}
};




/* object table */
static const luaL_reg R[] = {
  // system load
  {"get_load",  get_load},
  {"get_uptime",  get_uptime},
  {"get_meminfo",  get_meminfo},
  {"get_vminfo",  get_vminfo},
  {"get_pid_digits",  l_get_pid_digits},
  // converts
  {"group_from_gid",  l_group_from_guid},
  {"user_from_uid",  l_user_from_uid},
  // pid receive
  {"get_pid",  l_get_pid},
  {"list_pids",  l_list_pids},
  {"add_timeout", l_add_interval},
  {"register_filter", l_register_filter},
  //
  {"set_active_pid", l_set_active_pid},
  {"get_active_uids", l_get_active_uids},
  {"get_active_pids", l_get_active_pids},
  // misc
  {"get_config",  l_get_config},
  {"list_keys",  l_list_keys},
  {"log",  l_log},
  {"quit_daemon", l_quit},
	{NULL,        NULL}
};


#undef PUSH_INT

#define PUSH_INT(NAME, SYMBOLE)\
	lua_pushinteger(L, SYMBOLE); \
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
  PUSH_INT(version, VERSION)

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

  PUSH_INT(IOPRIO_CLASS_NONE, IOPRIO_CLASS_NONE)
  PUSH_INT(IOPRIO_CLASS_RT, IOPRIO_CLASS_RT)
  PUSH_INT(IOPRIO_CLASS_BE, IOPRIO_CLASS_BE)
  PUSH_INT(IOPRIO_CLASS_IDLE, IOPRIO_CLASS_IDLE)


  /* remove meta table */
	lua_remove(L, -2);
    
    // map proc_t
    luaL_register(L, U_PROC, proc_t_methods); 
    luaL_newmetatable(L, U_PROC);
    luaL_register(L, NULL, proc_t_meta);
    //lua_pushliteral(L, "__index");
    //lua_pushvalue(L, -3);
    //lua_rawset(L, -3);                  /* metatable.__index = methods */
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);               /* dup methods table*/
    lua_rawset(L, -3);
    lua_pop(L, 1);

	return 1;
}

// misc functions

static int report (lua_State *L, int status) {
  if (status && !lua_isnil(L, -1)) {
    const char *msg = lua_tostring(L, -1);
    if (msg == NULL) msg = "(error object is not a string)";
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "%s", msg);
    lua_pop(L, 1);
  }
  return status;
}


int load_lua_rule_file(lua_State *L, char *name) {
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
