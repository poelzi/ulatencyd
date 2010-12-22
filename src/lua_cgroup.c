// lua bindings to libcgroups
#include "ulatency.h"
#include <stdlib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>


#define CGROUP "cgroup_cgroup"
#define CGROUP_CONTROLLER "cgroup_controller"
#define CGROUP_META "cgroup"

//typedef struct cgroup *cgroup_ptr;
//typedef struct cgroup_controller *cgroup_controller_ptr;

// init
static int l_cgroup_get_subsys_mount_point (lua_State *L) {
  const char *cnt = luaL_checkstring(L, 1);
  char *out = NULL;
  cgroup_get_subsys_mount_point(cnt, &out);
  if(!out)
    return 0;
  lua_pushstring(L, out);
  free(out);
  return 1;
}

// configuration
static int l_cgroup_config_load_config(lua_State *L) {
  lua_pushinteger(L, cgroup_config_load_config(luaL_checkstring(L, 1)));
  return 1;
}


// error handling
static int l_cgroup_strerror (lua_State *L) {
  int eint = 0;
  const char *out = NULL;
  if(lua_isnumber(L, 1))
    eint = lua_tointeger(L, 1);
  else
    eint = cgroup_get_last_errno();
  out = cgroup_strerror(eint);
  if(out) {
    lua_pushstring(L, out);
    return 1;
  }
  return 0;
}

static int l_cgroup_get_last_errno(lua_State *L) {
  lua_pushinteger(L, cgroup_get_last_errno());
  return 1;
}

// group manipulation

// workaround structs to handle bad 

static struct u_cgroup *check_cgroup (lua_State *L, int index)
{
  struct u_cgroup *p;
  luaL_checktype(L, index, LUA_TUSERDATA);
  p = (struct u_cgroup *)luaL_checkudata(L, index, CGROUP);
  if (p == NULL) luaL_typerror(L, index, CGROUP);
  return p;
}

static struct u_cgroup *push_cgroup(lua_State *L)
{
//         proc_t *p = (proc_t*)lua_newuserdata(L, sizeof(proc_t));
  struct u_cgroup *p = /*(struct cproc *)*/lua_newuserdata(L, sizeof(struct u_cgroup));
  //struct cgroup *p = (struct cproc *)lua_newuserdata(L, sizeof(struct cgroup *));
  memset(p, 0, sizeof(struct u_cgroup));
  luaL_getmetatable(L, CGROUP);
  lua_setmetatable(L, -2);
  return p;
}

static int cgroup_tostring (lua_State *L)
{
  struct u_cgroup *group = lua_touserdata(L, 1);
  lua_pushfstring(L, "cgroup: %s <%p>", group->name, group->group);
  return 1;
}

/*static int proc_t_gc (lua_State *L)
{
  proc_t *proc = check_proc_t(L, 1);
  //printf("goodbye proc_t (%p)\n", proc);
  if (proc) {
    freesupgrp(proc);
    freeproc_light(proc);
  }
  return 0;
}
*/

static struct u_cgroup_controller *check_cgroup_controller (lua_State *L, int index)
{
  struct u_cgroup_controller *p;
  luaL_checktype(L, index, LUA_TUSERDATA);
  p = (struct u_cgroup_controller *)luaL_checkudata(L, index, CGROUP_CONTROLLER);
  if (p == NULL) luaL_typerror(L, index, CGROUP_CONTROLLER);
  return p;
}

static struct u_cgroup_controller *push_cgroup_controller(lua_State *L)
{
  struct u_cgroup_controller *p = lua_newuserdata(L, sizeof(struct u_cgroup_controller));
  memset(p, 0, sizeof(struct u_cgroup_controller));
  luaL_getmetatable(L, CGROUP_CONTROLLER);
  lua_setmetatable(L, -2);
  return p;
}

static int cgroup_controller_tostring (lua_State *L)
{
  struct u_cgroup *group = lua_touserdata(L, 1);
  lua_pushfstring(L, "cgroup_controller: %s <%p>", group->name, group->group);
  return 1;
}

static int l_cgroup_new_cgroup (lua_State *L)
{
  //struct cgroup_controller *cc, *cc2 = NULL;
  struct u_cgroup *cgp;
  struct cgroup *cg;
  const char *name = luaL_checkstring(L, 1);
  cg = cgroup_new_cgroup(name);
  if(cg) {
    cgp = push_cgroup(L);
    cgp->group = cg;
    cgp->name = g_strdup(name);
    cgp->ref = 1;
    return 1;
  }
  return 0;
}


static int l_cgroup_add_controller (lua_State *L)
{
  struct cgroup_controller *cc;
  struct u_cgroup_controller *uc = NULL;
  struct u_cgroup *cg = check_cgroup(L, 1);
  const char *name = luaL_checkstring(L, 2);

  if (cg) {
    cc = cgroup_add_controller (cg->group, name);
    if(cc) {
      uc = push_cgroup_controller(L);
      uc->controller = cc;
      uc->name = g_strdup(name);
      uc->ref = 1;
    }
    return 1;
  }

  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

static int l_cgroup_get_controller (lua_State *L)
{
  struct cgroup_controller *cc;
  struct u_cgroup_controller *uc = NULL;
  struct u_cgroup *cg = check_cgroup(L, 1);
  const char *name = luaL_checkstring(L, 2);

  if (cg) {
    cc = cgroup_get_controller (cg->group, name);
    if(cc) {
      uc = push_cgroup_controller(L);
      uc->controller = cc;
      uc->name = g_strdup(name);
      uc->ref = 1;
    }
    return 1;
  }

  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

/*
static int l_cgroup_get_controller (lua_State *L)
{
  struct cgroup_controller *cc, *cc2 = NULL;
  struct cgroup *cg = check_cgroup(L, 1);
  const char *name = luaL_checkstring(L, 2);

  if (cg) {
    cc = cgroup_get_controller (cg, name);
    if(cc) {
      cc2 = push_cgroup_controller(L);
      cc2 = cc;
    }
    return 1;
  }

  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}
*/
static int l_cgroup_free_controllers (lua_State *L)
{
  struct u_cgroup *cg = check_cgroup(L, 1);
  if (cg) {
    cgroup_free_controllers (cg->group);
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

#define CGROUP_INT(NAME, ARGS) \
static int l_##NAME (lua_State *L) \
{ \
  struct u_cgroup *cg = check_cgroup(L, 1); \
  int para = lua_tointeger(L, 2); \
  int rv = 0; \
  if (cg) { \
    rv =  NAME ARGS ; \
    lua_pushinteger(L, rv); \
    return 1; \
  } \
  lua_pushstring(L, "Not a valid cgroup"); \
  lua_error (L); \
  return 0; \
}

CGROUP_INT(cgroup_create_cgroup,(cg->group, para));
CGROUP_INT(cgroup_create_cgroup_from_parent,(cg->group, para));
CGROUP_INT(cgroup_modify_cgroup,(cg->group));
CGROUP_INT(cgroup_delete_cgroup,(cg->group, para));
CGROUP_INT(cgroup_delete_cgroup_ext,(cg->group, para));

CGROUP_INT(cgroup_get_cgroup,(cg->group));

static int l_cgroup_attach_task_pid(lua_State *L)
{
  struct u_cgroup *uc = check_cgroup(L, 1);
  int pid = luaL_checkinteger(L, 2);

  lua_pushinteger(L, cgroup_attach_task_pid(uc->group, pid));
  return 1;
}

static int l_cgroup_copy_cgroup (lua_State *L)
{
  struct u_cgroup *usrc = check_cgroup(L, 1);
  struct u_cgroup *udst = check_cgroup(L, 2);
  int rv;
  
  if(udst && usrc) {
    rv = cgroup_copy_cgroup(udst->group, usrc->group);
    lua_pushinteger(L, rv);
    return 1;
  }
  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

static int l_cgroup_compare_cgroup (lua_State *L)
{
  struct u_cgroup *usrc = check_cgroup(L, 1);
  struct u_cgroup *udst = check_cgroup(L, 2);
  int rv;
  
  if(udst && usrc) {
    rv = cgroup_compare_cgroup(udst->group, usrc->group);
    lua_pushinteger(L, rv);
    return 1;
  }
  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

static int l_cgroup_compare_controllers (lua_State *L)
{
  struct u_cgroup_controller *usrc = check_cgroup_controller(L, 1);
  struct u_cgroup_controller *udst = check_cgroup_controller(L, 2);
  int rv;
  
  if(udst && usrc) {
    rv = cgroup_compare_controllers(udst->controller, usrc->controller);
    lua_pushinteger(L, rv);
    return 1;
  }
  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

static int l_cgroup_set_uid_gid(lua_State *L)
{
  struct u_cgroup *usrc = check_cgroup(L, 1);
  int tuid = luaL_checkinteger(L, 2);
  int tgid = luaL_checkinteger(L, 3);
  int cuid = luaL_checkinteger(L, 4);
  int cgid = luaL_checkinteger(L, 5);
  int rv;
  
  if(usrc) {
    rv = cgroup_set_uid_gid(usrc->group, tuid, tgid, cuid, cgid);
    lua_pushinteger(L, rv);
    return 1;
  }
  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

static int l_cgroup_get_uid_gid(lua_State *L)
{
  struct u_cgroup *usrc = check_cgroup(L, 1);
  int tuid, tgid, cuid, cgid;
  int rv;
  
  if(usrc) {
    rv = cgroup_get_uid_gid(usrc->group, &tuid, &tgid, &cuid, &cgid);
    lua_pushinteger(L, rv);
    lua_pushinteger(L, tuid);
    lua_pushinteger(L, tgid);
    lua_pushinteger(L, cuid);
    lua_pushinteger(L, cgid);
    return 5;
  }
  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}

static int l_cgroup_add_value(lua_State *L)
{
  struct u_cgroup_controller *uc = check_cgroup_controller(L, 1);
  const char *key = lua_tostring(L, 2);
  int rv;
  
  if(!uc) {
    lua_pushstring(L, "Not a valid cgroup");
    lua_error (L);
    return 0;
  }

  if(lua_isstring(L, 3)) {
    rv = cgroup_add_value_string(uc->controller, key, lua_tostring(L, 3));
  } else if(lua_isnumber(L, 3)) {
    rv = cgroup_add_value_int64(uc->controller, key, lua_tointeger(L, 3));
  } else if(lua_isboolean(L, 3)) {
    rv = cgroup_add_value_bool(uc->controller, key, lua_toboolean(L, 3));
  } else {
    lua_pushstring(L, "Not a valid type");
    lua_error (L);
  }

  lua_pushinteger(L, rv);
  return 1;
}

static int l_cgroup_set_value(lua_State *L)
{
  struct u_cgroup_controller *uc = check_cgroup_controller(L, 1);
  const char *key = lua_tostring(L, 2);
  int rv;
  
  if(!uc) {
    lua_pushstring(L, "Not a valid cgroup");
    lua_error (L);
    return 0;
  }

  if(lua_isstring(L, 3)) {
    rv = cgroup_set_value_string(uc->controller, key, lua_tostring(L, 3));
  } else if(lua_isnumber(L, 3)) {
    rv = cgroup_set_value_int64(uc->controller, key, lua_tointeger(L, 3));
  } else if(lua_isboolean(L, 3)) {
    rv = cgroup_set_value_bool(uc->controller, key, lua_toboolean(L, 3));
  } else {
    lua_pushstring(L, "Not a valid type");
    lua_error (L);
  }

  lua_pushinteger(L, rv);
  return 1;
}

static int l_cgroup_get_value_int(lua_State *L)
{
  struct u_cgroup_controller *uc = check_cgroup_controller(L, 1);
  const char *key = lua_tostring(L, 2);
  int64_t rv;
  if(!cgroup_get_value_int64 (uc->controller, key, &rv)) {
    lua_pushinteger(L, rv);
    return 1;
  }
  return 0;
}
static int l_cgroup_get_value_bool(lua_State *L)
{
  struct u_cgroup_controller *uc = check_cgroup_controller(L, 1);
  const char *key = lua_tostring(L, 2);
  bool rv;
  if(!cgroup_get_value_bool(uc->controller, key, &rv)) {
    lua_pushboolean(L, rv);
    return 1;
  }
  return 0;
}

static int l_cgroup_get_value_str(lua_State *L)
{
  struct u_cgroup_controller *uc = check_cgroup_controller(L, 1);
  const char *key = lua_tostring(L, 2);
  char *rv;
  if(!cgroup_get_value_string(uc->controller, key, &rv)) {
    lua_pushstring(L, rv);
    return 1;
  }
  return 0;
}


static int l_cgroup_get_names(lua_State *L)
{
  struct u_cgroup_controller *uc = check_cgroup_controller(L, 1);
  int count = cgroup_get_value_name_count(uc->controller);
  int i;
  
  if(count == -1)
    return 0;
  
  count++;
  lua_createtable(L, count, 0);
  for(i = 1; i < count; i++) {
    lua_pushinteger(L, i);
    lua_pushstring(L, cgroup_get_value_name(uc->controller, i-1));
    lua_settable(L, -3);
  }
  
  return 1;
}


/*
cgroup_copy_cgroup (struct cgroup *dst, struct cgroup *src)
static int l_cgroup_copy_cgroup (lua_State *L)
{
  struct cgroup_controller *cc, *cc2 = NULL;
  struct cgroup *cg = check_cgroup(L, 1);

  if (cg) {
    cgroup_free_controllers (cg);
    lua_pushboolean(L, 1);
    return 1;
  }

  lua_pushstring(L, "Not a valid cgroup");
  lua_error (L);
  return 0;
}
*/

static const luaL_reg cgroup_meta[] = {
  //{"__gc",       proc_t_gc},
  {"__tostring", cgroup_tostring},
  //{"__index", proc_t_index},
  {NULL, NULL}
};

static const luaL_reg cgroup_methods[] = {
  {"add_controller", l_cgroup_add_controller},
  {"get_controller", l_cgroup_get_controller},
  {"free_controller", l_cgroup_free_controllers},
  {"create_cgroup", l_cgroup_create_cgroup},
  {"create_cgroup_from_parent", l_cgroup_create_cgroup_from_parent},
  {"modify_cgroup", l_cgroup_modify_cgroup},
  {"delete_cgroup", l_cgroup_delete_cgroup},
  {"delete_cgroup_ext", l_cgroup_delete_cgroup_ext},
  {"get_cgroup", l_cgroup_get_cgroup},
  {"attach_pid", l_cgroup_attach_task_pid},
  {NULL,NULL}
};

static const luaL_reg cgroup_controller_meta[] = {
  //{"__gc",       proc_t_gc},
  {"__tostring", cgroup_controller_tostring},
  //{"__index", proc_t_index},
  {NULL, NULL}
};

static const luaL_reg cgroup_controller_methods[] = {
  {"add_value", l_cgroup_add_value},
  {"set_value", l_cgroup_set_value},
  {"get_value_int", l_cgroup_get_value_int},
  {"get_value_bool", l_cgroup_get_value_bool},
  {"get_value_string", l_cgroup_get_value_str},
  {"get_names", l_cgroup_get_names},
  {NULL,NULL}
};


/* object table */
static const luaL_reg R[] = {
  // system load
  {"get_errorno",  l_cgroup_get_last_errno},
  {"get_strerror",  l_cgroup_strerror},
  {"get_subsys_mount_point",  l_cgroup_get_subsys_mount_point},
  {"load_config",  l_cgroup_config_load_config},
  {"new_cgroup", l_cgroup_new_cgroup},
  
	{NULL,        NULL}
};

#undef PUSH_INT

#define PUSH_INT(NAME, SYMBOLE)\
	lua_pushinteger(L, SYMBOLE); \
	lua_setfield(L, -2, #NAME);

int luaopen_cgroup(lua_State *L) {


	/* create metatable */
	luaL_newmetatable(L, CGROUP_META);

	/* metatable.__index = metatable */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	/* register module */
	luaL_register(L, "cgroups", R);

	/* register metatable as socket_meta */
	lua_pushvalue(L, -2);
	lua_setfield(L, -2, "meta_cgroups");

	/* module version */
//  PUSH_INT(version, VERSION)

	PUSH_INT(CGFLAG_DELETE_IGNORE_MIGRATION, CGFLAG_DELETE_IGNORE_MIGRATION)
  PUSH_INT(CGFLAG_DELETE_RECURSIVE, CGFLAG_DELETE_RECURSIVE)

// error ints
  PUSH_INT(ECGMOUNTNAMESPACE, ECGMOUNTNAMESPACE)
  PUSH_INT(ECGNAMESPACECONTROLLER, ECGNAMESPACECONTROLLER)
  PUSH_INT(ECGNAMESPACEPATHS, ECGNAMESPACEPATHS)
  PUSH_INT(ECGCONFIGPARSEFAIL, ECGCONFIGPARSEFAIL)
  PUSH_INT(ECGEOF, ECGEOF)
  PUSH_INT(ECGSENTINEL, ECGSENTINEL)
  PUSH_INT(ECGMOUNTFAIL, ECGMOUNTFAIL)
  PUSH_INT(ECGROUPNORULES, ECGROUPNORULES)
  PUSH_INT(ECGROUPPARSEFAIL, ECGROUPPARSEFAIL)
  PUSH_INT(ECGCONTROLLERNOTEQUAL, ECGCONTROLLERNOTEQUAL)
  PUSH_INT(ECGROUPNOTEQUAL, ECGROUPNOTEQUAL)
  PUSH_INT(ECGOTHER, ECGOTHER)
  PUSH_INT(ECGROUPVALUENOTEXIST, ECGROUPVALUENOTEXIST)
  PUSH_INT(ECGROUPNOTINITIALIZED, ECGROUPNOTINITIALIZED)
  PUSH_INT(ECGFAIL, ECGFAIL)
  PUSH_INT(ECGCONTROLLERCREATEFAILED, ECGCONTROLLERCREATEFAILED)
  PUSH_INT(ECGINVAL, ECGINVAL)
  PUSH_INT(ECGVALUEEXISTS, ECGVALUEEXISTS)
  PUSH_INT(ECGCONTROLLEREXISTS, ECGCONTROLLEREXISTS)
  PUSH_INT(ECGMAXVALUESEXCEEDED, ECGMAXVALUESEXCEEDED)
  PUSH_INT(ECGROUPNOTALLOWED, ECGROUPNOTALLOWED)
  PUSH_INT(ECGROUPMULTIMOUNTED, ECGROUPMULTIMOUNTED)
  PUSH_INT(ECGROUPNOTOWNER, ECGROUPNOTOWNER)
  PUSH_INT(ECGROUPSUBSYSNOTMOUNTED, ECGROUPSUBSYSNOTMOUNTED)
  PUSH_INT(ECGROUPNOTCREATED, ECGROUPNOTCREATED)
  PUSH_INT(ECGROUPNOTEXIST, ECGROUPNOTEXIST)
  PUSH_INT(ECGROUPNOTMOUNTED, ECGROUPNOTMOUNTED)
  PUSH_INT(ECGROUPNOTCOMPILED, ECGROUPNOTCOMPILED)

  /* remove meta table */
  lua_remove(L, -2);

  // map cgroup
  luaL_register(L, CGROUP, cgroup_methods); 
  luaL_newmetatable(L, CGROUP);
  luaL_register(L, NULL, cgroup_meta);
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -3);
  lua_rawset(L, -3);                  /* metatable.__index = methods */
  lua_pushliteral(L, "__metatable");
  lua_pushvalue(L, -3);               /* dup methods table*/
  lua_rawset(L, -3);
  lua_pop(L, 1);

  // map cgroup_controller
  luaL_register(L, CGROUP_CONTROLLER, cgroup_controller_methods); 
  luaL_newmetatable(L, CGROUP_CONTROLLER);
  luaL_register(L, NULL, cgroup_controller_meta);
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -3);
  lua_rawset(L, -3);                  /* metatable.__index = methods */
  lua_pushliteral(L, "__metatable");
  lua_pushvalue(L, -3);               /* dup methods table*/
  lua_rawset(L, -3);
  lua_pop(L, 1);


	return 1;
}
