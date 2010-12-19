#include "ulatency.h"
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proc/sysinfo.h"
#include "proc/readproc.h"
#include <libcgroup.h>


int full_check;

lua_State *lua_main_state;
GMainContext *main_context;
GMainLoop *main_loop;

GList *filter_list;

filter* filter_new() {
  filter *rv = malloc(sizeof(filter));
  memset(rv, 0, sizeof(filter));
  rv->skip_filter = g_hash_table_new(g_int_hash, g_int_equal);
  return rv;
}

void filter_register(filter *filter) {
  filter_list = g_list_append(filter_list, filter);
}

int filter_cleanup(gpointer data) {
  // cleanup the filter lists
  // we have to remove all skip_filter entries of processes that do not exist
  // anymore
  GSequence *pids;

  pids = g_sequence_new(NULL);


  g_sequence_free(pids);

}

int l_filter_run_for_proc(gpointer data, gpointer user_data) {


}

void filter_run_for_proc(gpointer data, gpointer user_data) {
  proc_t *proc = user_data;
  filter *flt = data;
  struct filter_block *flt_block =NULL;
  int rv;
  time_t ttime = 0;
  


  flt_block = (struct filter_block *)g_hash_table_lookup(flt->skip_filter, GUINT_TO_POINTER(proc->tgid));
  if(flt_block) {
    time (&ttime);
    if(flt_block->skip)
      return;
    if(flt_block->timeout > ttime)
      return;
  }

  if(flt->type == FILTER_LUA) {
    rv = l_filter_run_for_proc(flt, proc);
  }
  if(rv == 0)
    return;

  if(!flt_block)
    flt_block = malloc(sizeof(struct filter_block));

  if(rv > 0) {
    if(!ttime)
      time (&ttime);
    flt_block->timeout = ttime + rv;

  } else if(rv == FILTER_STOP) {
    flt_block->skip = TRUE;  
  }

  g_hash_table_insert(flt->skip_filter, GUINT_TO_POINTER(proc->tgid), flt_block);

}

int filter_run(gpointer data) {
  int pid;
  proc_t buf;
  PROCTAB *proctab;

  proctab = openproc(OPENPROC_FLAGS);
  if(!proctab)
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't open /proc");

  while(readproc(proctab,&buf)){
    g_list_foreach(filter_list, filter_run_for_proc, &buf);
  }
  return TRUE;
}


int init() {
  // load config
  full_check = 10000; // FIXME: config

  filter_list = g_list_alloc();

  // configure lua
  lua_main_state = luaL_newstate();
  luaL_openlibs(lua_main_state);
  luaopen_bc(lua_main_state);
  luaopen_ulatency(lua_main_state);
  // FIXME
  if(load_rule_file("src/core.lua"))
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't load core library");
}

void cleanup() {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "cleanup daemon");
  cgroup_unload_cgroups();
  
}

static void
cleanup_on_signal (int signal)
{
  // we have to make sure cgroup_unload_cgroups is called
  printf("abort cleanup\n");
  cgroup_unload_cgroups();
  exit(1);
}


static int report (lua_State *L, int status) {
  if (status && !lua_isnil(L, -1)) {
    const char *msg = lua_tostring(L, -1);
    if (msg == NULL) msg = "(error object is not a string)";
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "%s", msg);
    lua_pop(L, 1);
  }
  return status;
}


int load_rule_file(char *name) {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "load %s", name);
  if(luaL_loadfile(lua_main_state, name)) {
    report(lua_main_state, 1);
    return 1;
  }
  if(lua_pcall(lua_main_state, 0, LUA_MULTRET, 0)) {
    report(lua_main_state, 1);
  }
  return 0;

}

int load_rules() {
  DIR             *dip;
  struct dirent   *dit;
  char *path = "rules";
  char rpath[PATH_MAX+1];

  if ((dip = opendir(path)) == NULL)
  {
    perror("opendir");
    return 0;
  }
  while ((dit = readdir(dip)) != NULL)
  {
    if(fnmatch ("*.lua", dit->d_name, 0))
      continue;
    snprintf(rpath, PATH_MAX, "%s/%s",path, dit->d_name);
    load_rule_file(rpath);
  }

}

int main (int argc, char *argv[])
{

  main_context = g_main_context_default();
  main_loop = g_main_loop_new(main_context, FALSE);

  if(cgroup_init()) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "could not init libcgroup");
  }

  g_atexit(cleanup);
  
  if (signal (SIGABRT, cleanup_on_signal) == SIG_IGN)
    signal (SIGABRT, SIG_IGN);
  if (signal (SIGINT, cleanup_on_signal) == SIG_IGN)
    signal (SIGINT, SIG_IGN);
  if (signal (SIGTERM, cleanup_on_signal) == SIG_IGN)
    signal (SIGTERM, SIG_IGN);


  
  //signal (SIGABRT, cleanup_on_abort);
  init();
  load_rules();
  // small hack

  if(g_main_loop_is_running(main_loop));
    g_main_loop_run(main_loop);
}
