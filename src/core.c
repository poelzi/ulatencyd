#include "ulatency.h"

#include "proc/procps.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>


lua_State *lua_main_state;
GList *filter_list;
GNode *processes_tree;
GHashTable *processes;


/*************************************************************
 * u_proc code
 ************************************************************/

void filter_block_free(gpointer fb) {
  free(fb);
}




u_proc* u_proc_new(proc_t *proc) {
  u_proc *rv;
  
  rv = g_new0(u_proc, 1);
  
  rv->ref = 1;
  rv->skip_filter = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                         NULL, filter_block_free);

  if(proc) {
    rv->pid = proc->tgid;
    U_PROC_SET_STATE(rv,UPROC_ALIVE);
    memcpy(&(rv->proc), proc, sizeof(proc_t));
  } else {
    U_PROC_SET_STATE(rv,UPROC_NEW);
  }

  return rv;
}

int u_proc_free(u_proc *proc) {
  DEC_REF(proc);
  if(proc->ref)
    return;
  
  g_hash_table_remove_all (proc->skip_filter);
  g_node_destroy(proc->node);
  free(proc);
}

void processes_free_value(gpointer data) {
  u_proc *proc = data;
  U_PROC_SET_STATE(proc, UPROC_INVALID);
  g_node_unlink(proc->node);
  u_proc_free(proc);
}

// rebuild the node tree from content of the hash table
void rebuild_tree() {
//  processes_tree
  GHashTableIter iter;
  gpointer key, value;
  u_proc *proc, *parent;

  // clear root node
  g_node_destroy(processes_tree);
  processes_tree = g_node_new(NULL);

  // create nodes first
  g_hash_table_iter_init (&iter, processes);
  while (g_hash_table_iter_next (&iter, &key, &value)) 
  {
    proc = (u_proc *)value;
    proc->node = g_node_new(proc);
    g_node_append(processes_tree, proc->node);
  }

  // now we can lookup the parents and attach the node to the parent
  g_hash_table_iter_init (&iter, processes);
  while (g_hash_table_iter_next (&iter, &key, &value)) 
  {
    proc = (u_proc *)value;
    if(proc->proc.ppid) {
      parent = proc_by_pid(proc->proc.ppid);
      g_assert(parent && parent->node);
      g_node_unlink(proc->node);
      g_node_append(parent->node, proc->node);
    }
  }


}


int update_processes() {
  PROCTAB *proctab;
  proc_t buf;
  u_proc *proc;
  u_proc *parent;
  gboolean full_update = FALSE;

  proctab = openproc(OPENPROC_FLAGS);
  if(!proctab)
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "can't open /proc");

  while(readproc(proctab, &buf)){
    proc = proc_by_pid(buf.tgid);
    if(proc) {
      // free all changable allocated buffers
      freesupgrp(&buf);
    } else {
      proc = u_proc_new(&buf);
      g_hash_table_insert(processes, GUINT_TO_POINTER(proc->pid), proc);
    }
    // we can simply steal the pointer of the current allocated buffer
    //memcpy(&(proc->proc), &buf, sizeof(proc_t));

    if(!proc->node) {
      proc->node = g_node_new(proc);
      if(proc->proc.ppid) {
        parent = g_hash_table_lookup(processes, GUINT_TO_POINTER(proc->proc.ppid));
        // the parent should exist. in case it is missing we have to run a full
        // tree rebuild then
        if(parent) {
          g_node_append(parent->node, proc->node);
        } else {
          full_update = TRUE;
        }
      }
    }
    //g_list_foreach(filter_list, filter_run_for_proc, &buf);
    //freesupgrp(&buf);
  }
  closeproc(proctab);
  if(full_update) {
    rebuild_tree();
  }

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
  int timeout, flags;

  if(data == NULL)
    return;

  flt_block = (struct filter_block *)g_hash_table_lookup(proc->skip_filter, GUINT_TO_POINTER(proc->pid));
  //g_hash_table_lookup
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

  timeout = FILTER_TIMEOUT(rv);
  flags = FILTER_FLAGS(rv);

  if(timeout) {
    if(!ttime)
      time (&ttime);
    flt_block->timeout = ttime + abs(timeout);
  } else if(rv == FILTER_STOP) {
    flt_block->skip = TRUE;
  }

  g_hash_table_insert(proc->skip_filter, GUINT_TO_POINTER(flt_block->pid), flt_block);

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

int load_rule_directory(char *path, char *load_pattern) {
  DIR             *dip;
  struct dirent   *dit;
  char rpath[PATH_MAX+1];

  if ((dip = opendir(path)) == NULL)
  {
    perror("opendir");
    return 0;
  }

  if(load_pattern)
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "load pattern: %s", load_pattern);

  while ((dit = readdir(dip)) != NULL)
  {
    if(fnmatch("*.lua", dit->d_name, 0))
      continue;
    if(load_pattern && (fnmatch(load_pattern, dit->d_name, 0) != 0)) {
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "skip rule: %s", dit->d_name);
      continue;
    }

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
  processes_tree = g_node_new(NULL);
  processes = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, 
                                    processes_free_value);

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
