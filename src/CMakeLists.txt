cmake_minimum_required(VERSION 2.8)
#add_library(efence STATIC IMPORTED)
#set_property(TARGET efence PROPERTY
#               IMPORTED_LOCATION /usr/lib/libefence.a)

add_definitions(-DHAVE_INLINE)
#add_definitions(-DINSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DCONFIG_PREFIX=${CONFIG_PREFIX})

#set_directory_properties(PROPERTIES COMPILE_DEFINITIONS_DEBUG BLUBB=1)
#set_directory_properties(PROPERTIES COMPILE_FLAGS "-pg -Wall")
#set_directory_properties(APPEND PROPERTY COMPILE_FLAGS -Wall)


IF(LIBCGROUPS)
  list(APPEND, EXTRA_C, "lua_cgroups.c")
ENDIF(LIBCGROUPS)

add_executable(ulatencyd core.c ulatencyd.c group.c sysinfo.c sysctl.c
               coreutils/readutmp.c coreutils/xalloc-die.c linux_netlink.c
               ${EXTRA_C} lua_binding.c)
target_link_libraries (ulatencyd proc lbc dl ${MY_LUA_LIBRARIES} 
                       ${LIBCGROUP_LIBRARIES} ${DBUS_LIBRARIES} ${GLIB2_LIBRARIES} ${GIO_LIBRARIES})

SET_TARGET_PROPERTIES(ulatencyd PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS}")

install(TARGETS ulatencyd 
        RUNTIME DESTINATION sbin)
install(FILES core.lua
        DESTINATION lib/ulatencyd)
install(FILES ulatencyd_cleanup.lua
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ 
                    GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        DESTINATION lib/ulatencyd)


