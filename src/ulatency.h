#ifndef __ulatency__

#include <glib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proc/procps.h"
#include "proc/readproc.h"


#define VERSION 0.1

#define OPENPROC_FLAGS PROC_FILLMEM | \
  PROC_FILLUSR | PROC_FILLGRP | PROC_FILLSTATUS | PROC_FILLSTAT | \
  PROC_FILLWCHAN | PROC_FILLCGROUP | PROC_FILLSUPGRP

extern GMainLoop *main_loop;

enum FILTER_TYPES {
  FILTER_LUA,
  FILTER_C
};

enum FILTER_SKIP {
  FILTER_STOP=-1,
};


struct lua_callback {
  lua_State *lua_state;
  int lua_func;
  int lua_data;
};

struct lua_filter {
  lua_State *lua_state;
  int lua_func;
  int lua_data;
  GRegex *filter_cmd;
};

struct filter_block {
  GTime timeout;
  gboolean skip;
};


typedef struct _filter {
  enum FILTER_TYPES type;
  int (*check)(struct proc_t *proc, void *filter);
  int (*callback)(struct proc_t *proc, void *filter);
  void *data;
  GHashTable *skip_filter;
} filter;




filter *filter_new();
void filter_free(filter *filter);

void filter_register(filter *filter);
void filter_unregister(filter *filter);

#endif