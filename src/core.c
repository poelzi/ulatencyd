#include "ulatency.h"

#include "proc/procps.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>


GList *filter_list;

/*************************************************************
 * u_proc code
 ************************************************************/


u_proc* u_proc_new(void) {
  u_proc *rv;
  
  rv = g_new0(u_proc, 1);
  rv->ref = 1;
  return rv;
}


void cp_proc_t(const struct proc_t *src, struct proc_t *dst) {
  memcpy(dst, src, sizeof(struct proc_t));
  allocsupgrp(dst);
  int i;
  for (i=0; i < src->nsupgid; i++)
      memcpy(dst->supgrp[i], src->supgrp[i], P_G_SZ);
  if (src->cmdline)
    dst->cmdline = g_strdupv(src->cmdline);
  if (src->environ)
    dst->environ = g_strdupv(src->environ);
  if (src->cgroup)
    dst->cgroup = g_strdupv(src->cgroup);
}


/*************************************************************
 * filter code
 ************************************************************/



u_filter* filter_new() {
  u_filter *rv = malloc(sizeof(u_filter));
  memset(rv, 0, sizeof(u_filter));
  rv->skip_filter = g_hash_table_new(g_direct_hash, g_direct_equal);
  return rv;
}

void filter_register(u_filter *filter) {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "register new filter: %s", filter->name ? filter->name : "unknown");
  filter_list = g_list_append(filter_list, filter);
}


void filter_run_for_proc(gpointer data, gpointer user_data) {
  u_proc *proc = user_data;
  u_filter *flt = data;
  struct filter_block *flt_block =NULL;
  int rv = 0;
  time_t ttime = 0;

  if(data == NULL)
    return;

  flt_block = (struct filter_block *)g_hash_table_lookup(flt->skip_filter, GUINT_TO_POINTER(proc->proc.tgid));
  if(flt_block) {
    time (&ttime);
    if(flt_block->skip)
      return;
    if(flt_block->timeout > ttime)
      return;
  }

  if(flt->check) {
    // if return 0 the real callback will be skipped
    if(!flt->check(proc, flt))
      return;
  }

  rv = flt->callback(proc, flt);

  if(rv == 0)
    return;

  if(!flt_block)
    flt_block = malloc(sizeof(struct filter_block));

  flt_block->pid = proc->proc.tgid;

  if(rv > 0) {
    if(!ttime)
      time (&ttime);
    flt_block->timeout = ttime + rv;

  } else if(rv == FILTER_STOP) {
    flt_block->skip = TRUE;  
  }

  g_hash_table_insert(flt->skip_filter, GUINT_TO_POINTER(flt_block->pid), flt_block);

}

int filter_run(gpointer data) {
  int pid;
  proc_t buf;
  PROCTAB *proctab;

  proctab = openproc(OPENPROC_FLAGS);
  if(!proctab)
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't open /proc");

  while(readproc(proctab, &buf)){
    g_list_foreach(filter_list, filter_run_for_proc, &buf);
    freesupgrp(&buf);
  }
  closeproc(proctab);
  return TRUE;
}


/***************************************************************************
 * rules and modules handling
 **************************************************************************/

lua_State *lua_main_state;


int load_rule_directory(char *path, char *load_pattern) {
  DIR             *dip;
  struct dirent   *dit;
  char rpath[PATH_MAX+1];

  if ((dip = opendir(path)) == NULL)
  {
    perror("opendir");
    return 0;
  }

  while ((dit = readdir(dip)) != NULL)
  {
    if(fnmatch("*.lua", dit->d_name, 0))
      continue;
    if(load_pattern && (fnmatch(load_pattern, dit->d_name, 0) != 0))
      continue;

    snprintf(rpath, PATH_MAX, "%s/%s", path, dit->d_name);
    load_lua_rule_file(lua_main_state, rpath);
  }
  free(dip);
}


int load_modules(char *modules_directory) {
  DIR             *dip;
  struct dirent   *dit;
  char rpath[PATH_MAX+1];
  char *minit_name, *module_name, *error;
  char **disabled;
  gsize  disabled_len, i;
  gboolean skip;
  void *handle;
  int (*minit)(void);

  if ((dip = opendir(modules_directory)) == NULL)
  {
    perror("opendir");
    return 0;
  }

  disabled = g_key_file_get_string_list(config_data, CONFIG_CORE,
                                        "disabled_modules", &disabled_len, NULL);

  while ((dit = readdir(dip)) != NULL)
  {
    skip = FALSE;
    if(fnmatch("*.so", dit->d_name, 0))
      continue;

    module_name = g_strndup(dit->d_name,strlen(dit->d_name)-3);

    for(i = 0; i < disabled_len; i++) {
      if(!g_strcasecmp(disabled[i], module_name)) {
        skip = TRUE;
        break;
      }
    }
    if(!skip) {
      snprintf(rpath, PATH_MAX, "%s/%s", modules_directory, dit->d_name);
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "load module %s", dit->d_name);

      handle = dlopen(rpath, RTLD_LAZY);
      if (!handle) {
        //fprintf(stderr, "%s\n", dlerror());
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't load module %s", rpath);
      }
      dlerror();

      minit_name = g_strconcat(module_name, "_init", NULL);
      *(void **) (&minit) = dlsym(handle, minit_name);

      if ((error = dlerror()) != NULL)  {
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't load module %s: %s", module_name, error);
      }

      if(minit())
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "module %s returned error", module_name);

      free(minit_name);
    } else
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "skip module %s", module_name);

    free(module_name);
  }
  g_free(disabled);
  free(dip);
}

int core_init() {
  // load config
  filter_list = g_list_alloc();

  // configure lua
  lua_main_state = luaL_newstate();
  luaL_openlibs(lua_main_state);
  luaopen_bc(lua_main_state);
  luaopen_ulatency(lua_main_state);
  luaopen_cgroup(lua_main_state);
  // FIXME
  if(load_lua_rule_file(lua_main_state, "src/core.lua"))
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't load core library");
}

void core_unload() {
  lua_gc (lua_main_state, LUA_GCCOLLECT, 0);
}
