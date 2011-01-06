cmake_minimum_required(VERSION 2.8)
#add_library(efence STATIC IMPORTED)
#set_property(TARGET efence PROPERTY
#               IMPORTED_LOCATION /usr/lib/libefence.a)

add_definitions(-DHAVE_INLINE)
#add_definitions(-DINSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DCONFIG_PREFIX=${CONFIG_PREFIX})

IF(LIBCGROUPS)
  list(APPEND, EXTRA_C, "lua_cgroups.c")
ENDIF(LIBCGROUPS)

add_executable(ulatencyd core.c ulatencyd.c group.c sysinfo.c sysctl.c
               coreutils/readutmp.c coreutils/xalloc-die.c ${EXTRA_C} 
               lua_binding.c)
target_link_libraries (ulatencyd proc lbc dl ${MY_LUA_LIBRARIES} 
                       ${LIBCGROUP_LIBRARIES} ${GLIB2_LIBRARIES})

