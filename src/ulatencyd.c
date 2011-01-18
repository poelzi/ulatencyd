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

#include "ulatency.h"
#include "config.h"
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifdef ENABLE_DBUS
#include <dbus/dbus-glib.h>

DBusGConnection *U_dbus_connection;
#endif

#include <glib.h>
#include "proc/sysinfo.h"
#include "proc/readproc.h"
#ifdef LIBCGROUP
#include <libcgroup.h>
#endif
#include <sys/mman.h>
#include <error.h>

static gchar *config_file = QUOTEME(CONFIG_FILE);
static gchar *rules_directory = QUOTEME(RULES_DIRECTORY);
static gchar *modules_directory = QUOTEME(MODULES_DIRECTORY);
static gchar *load_pattern = NULL;
static gint verbose = 1<<4;
static char *mount_point;

GKeyFile *config_data;

/*
static gint max_size = 8;

static gboolean beep = FALSE;
*/
//static gboolean rand = FALSE;


int init_netlink(GMainLoop *loop);

static gboolean opt_verbose(const gchar *option_name, const gchar *value, gpointer data, GError **error) {
  int i = 1;
  if(value) {
    i = atoi(value);
  }
  verbose = verbose << i;
  return TRUE;
}

static GOptionEntry entries[] =
{
  { "config", 'c', 0, G_OPTION_ARG_FILENAME, &config_file, "Use config file", NULL},
  { "rules-directory", 'r', 0, G_OPTION_ARG_FILENAME, &rules_directory, "Path with ", NULL},
  { "rule-pattern", 0, 0, G_OPTION_ARG_STRING, &load_pattern, "Load only rules matching the pattern", NULL},
  { "verbose", 'v', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, &opt_verbose, "More verbose. Can be passed multiple times", NULL },

//  { "max-size", 'm', 0, G_OPTION_ARG_INT, &max_size, "Test up to 2^M items", "M" },
//  { "beep", 'b', 0, G_OPTION_ARG_NONE, &beep, "Beep when done", NULL },
//  { "rand", 0, 0, G_OPTION_ARG_NONE, &rand, "Randomize the data", NULL },
  { NULL }
};


int filter_interval;

GMainContext *main_context;
GMainLoop *main_loop;

int timeout_long(gpointer data) {

  // try the make current memory non swapalbe
  if(mlockall(MCL_CURRENT))
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "can't mlock memory");
  return TRUE;
}


void cleanup() {
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "cleanup daemon");
#ifdef LIBCGROUP
  cgroup_unload_cgroups();
#endif
  // for valgrind
  core_unload();
}

static void
cleanup_on_signal (int signal)
{
  // we have to make sure cgroup_unload_cgroups is called
  printf("abort cleanup\n");
#ifdef LIBCGROUP
  cgroup_unload_cgroups();
#endif
  exit(1);
}

static void avoid_oom_killer(void)
{
  int oomfd;

  oomfd = open("/proc/self/oom_adj", O_NOFOLLOW | O_WRONLY);
  if (oomfd >= 0) {
    (void)write(oomfd, "-17", 3);
    close(oomfd);
    return;
  }
  // Old style kernel...perform another action here
}


static void filter_log_handler(const gchar *log_domain, GLogLevelFlags log_level,
                        const gchar *message, gpointer unused_data) {

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

  mount_point = g_key_file_get_string(config_data, CONFIG_CORE, "mount_point", NULL);
  if(!mount_point)
    mount_point = "/dev/cgroups";
}


#define DEFAULT_CGROUPS "cpu,memory"

int mount_cgroups() {
  gchar   *argv[10];
  gint    i, rv;
  gint    result;
  GError  *error = NULL;
  char    *sub = g_key_file_get_string(config_data, CONFIG_CORE, "cgroup_subsys", NULL);
  
  if (!sub) {
    sub = DEFAULT_CGROUPS;
  }
  
  argv[i=0] = "/bin/mount";
  argv[++i] = "-t";
  argv[++i] = "cgroup";
  argv[++i] = "-o";
  argv[++i] = sub;
  argv[++i] = "none";
  argv[++i] = mount_point;
  argv[++i] = NULL;
  rv = g_spawn_sync(NULL, argv, NULL, 0, NULL, NULL, NULL, NULL, &result, &error);
  if(rv && !result) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "mounted cgroups on %s", mount_point);
  } else {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "error mounting cgroups on %s: %s", mount_point, (error && error->message) ? error->message : "");
    return FALSE;
  }
  return TRUE;
}
/*
 
gboolean            g_spawn_sync                        ("/",
                                                         gchar **argv,
                                                         gchar **envp,
                                                         GSpawnFlags flags,
                                                         GSpawnChildSetupFunc child_setup,
                                                         gpointer user_data,
                                                         gchar **standard_output,
                                                         gchar **standard_error,
                                                         gint *exit_status,
                                                         GError **error);

}

*/

#ifdef ENABLE_DBUS
static int do_dbus_init() {
  GError *error = NULL;
  U_dbus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM,
                               &error);
  if (U_dbus_connection == NULL)
    {
      g_warning("Failed to open connection to bus: %s\n",
                  error->message);
      g_error_free (error);
      return FALSE;
    }
  return TRUE;
}
#endif


int main (int argc, char *argv[])
{
  GError *error = NULL;
  GOptionContext *context;
  config_data = g_key_file_new();

  g_type_init ();

#ifdef ENABLE_DBUS
  do_dbus_init();
#endif 

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

#if LIBCGROUP
  if(cgroup_init()) {
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "could not init libcgroup. try mounting cgroups...");
    g_mkdir_with_parents(mount_point, 0755);
    if(!mount_cgroups() || cgroup_init()) {
#ifdef DEVELOP_MODE
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "give up init libcgroup");
      //g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "give up init libcgroup");
#else
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR, "give up init libcgroup");
#endif
    }
  }
#else
  //mount_cgroups();
#endif

  g_atexit(cleanup);
  
  if (signal (SIGABRT, cleanup_on_signal) == SIG_IGN)
    signal (SIGABRT, SIG_IGN);
  if (signal (SIGINT, cleanup_on_signal) == SIG_IGN)
    signal (SIGINT, SIG_IGN);
  if (signal (SIGTERM, cleanup_on_signal) == SIG_IGN)
    signal (SIGTERM, SIG_IGN);


  
  //signal (SIGABRT, cleanup_on_abort);
  core_init();
  avoid_oom_killer();
  load_modules(modules_directory);
  load_rule_directory(rules_directory, load_pattern, TRUE);

  process_update_all();
  init_netlink(main_loop);

  // small hack
  timeout_long(NULL);
  iterate(GUINT_TO_POINTER(0));
  g_timeout_add_seconds(60*5, timeout_long, GUINT_TO_POINTER(1));

  g_timeout_add_seconds(filter_interval, iterate, GUINT_TO_POINTER(1));

  if(g_main_loop_is_running(main_loop));
    g_main_loop_run(main_loop);
  return 0;
}
