#include "ulatency.h"
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proc/sysinfo.h"
#include "proc/readproc.h"
#include <libcgroup.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <error.h>

#ifdef DEVELOP_MODE
static gchar *config_file = "ulatencyd.conf";
static gchar *rules_directory = "rules";
static gchar *modules_directory = "modules";
#else
// FIXME need usage of PREFIX
static gchar *config_file = CONFIG_PREFI "/ulatency/ulatencyd.conf";
static gchar *rules_directory = CONFIG_PREFIX "/ulatency/rules";
static gchar *modules_directory = INSTALL_PREFIX "/lib/ulatency/modules";
#endif
static gchar *load_pattern = NULL;
static gint verbose = 1<<4;
GKeyFile *config_data;

/*
static gint max_size = 8;

static gboolean beep = FALSE;
*/
//static gboolean rand = FALSE;

static gboolean opt_verbose(const gchar *option_name, const gchar *value, gpointer data, GError **error) {
  verbose = verbose << 1;
}

static GOptionEntry entries[] =
{
  { "config", 'c', 0, G_OPTION_ARG_FILENAME, &config_file, "Use config file", NULL},
  { "rules-directory", 'r', 0, G_OPTION_ARG_FILENAME, &rules_directory, "Path with ", NULL},
  { "rule-pattern", 0, 0, G_OPTION_ARG_STRING, &load_pattern, "Load only rules matching the pattern", NULL},
  { "verbose", 'v', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, &opt_verbose, "More verbose. Can be passed multiple times", NULL },

//  { "max-size", 'm', 0, G_OPTION_ARG_INT, &max_size, "Test up to 2^M items", "M" },
//  { "beep", 'b', 0, G_OPTION_ARG_NONE, &beep, "Beep when done", NULL },
//  { "rand", 0, 0, G_OPTION_ARG_NONE, &rand, "Randomize the data", NULL },
  { NULL }
};


int filter_interval;

lua_State *lua_main_state;
GMainContext *main_context;
GMainLoop *main_loop;

GList *filter_list;

filter* filter_new() {
  filter *rv = malloc(sizeof(filter));
  memset(rv, 0, sizeof(filter));
  rv->skip_filter = g_hash_table_new(g_direct_hash, g_direct_equal);
  return rv;
}

void filter_register(filter *filter) {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "register new filter: %s", filter->name ? filter->name : "unknown");
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

int timeout_long(gpointer data) {

  // try the make current memory non swapalbe
  if(mlockall(MCL_CURRENT))
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "can't mlock memory");
}

void inline cp_proc_t(const struct proc_t *src, struct proc_t *dst) {
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

void filter_run_for_proc(gpointer data, gpointer user_data) {
  proc_t *proc = user_data;
  filter *flt = data;
  struct filter_block *flt_block =NULL;
  int rv = 0;
  time_t ttime = 0;

  if(data == NULL)
    return;

  flt_block = (struct filter_block *)g_hash_table_lookup(flt->skip_filter, GUINT_TO_POINTER(proc->tgid));
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

  flt_block->pid = proc->tgid;

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


int init() {
  // load config
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
  // for valgrind
  lua_gc (lua_main_state, LUA_GCCOLLECT, 0);
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
  char rpath[PATH_MAX+1];

  if ((dip = opendir(rules_directory)) == NULL)
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

    snprintf(rpath, PATH_MAX, "%s/%s", rules_directory, dit->d_name);
    load_rule_file(rpath);
  }
  free(dip);
}


int load_modules() {
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


static void filter_log_handler(const gchar *log_domain, GLogLevelFlags log_level,
                        const gchar *message, gpointer unused_data) {

  printf("%d\n", verbose);
  if(log_level <= verbose) {
      g_log_default_handler(log_domain, log_level, message, unused_data);
  }
}

void load_config() {
  GError *error = NULL;

  if(!g_key_file_load_from_file(config_data, config_file, 
                                G_KEY_FILE_KEEP_COMMENTS|G_KEY_FILE_KEEP_TRANSLATIONS,
                                &error)) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "could not load config file: %s: %s", config_file, error->message);
  }

  filter_interval = g_key_file_get_integer(config_data, CONFIG_CORE, "interval", NULL);
  if(!filter_interval)
    filter_interval = 60;

}

int main (int argc, char *argv[])
{
  GError *error = NULL;
  GOptionContext *context;
  config_data = g_key_file_new();

  context = g_option_context_new ("- latency optimizing daemon");
  g_option_context_add_main_entries (context, entries, /*GETTEXT_PACKAGE*/NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_print ("option parsing failed: %s\n", error->message);
      exit (1);
    }

  load_config();

  g_log_set_default_handler(filter_log_handler, NULL);

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
  load_modules();
  load_rules();
  // small hack
  timeout_long(NULL);
  g_timeout_add_seconds(60*5, timeout_long, NULL);

  g_timeout_add_seconds(filter_interval, filter_run, NULL);

  if(g_main_loop_is_running(main_loop));
    g_main_loop_run(main_loop);
}
