cmake_minimum_required(VERSION 2.8)
#add_library(efence STATIC IMPORTED)
#set_property(TARGET efence PROPERTY
#               IMPORTED_LOCATION /usr/lib/libefence.a)

add_definitions(-DHAVE_INLINE)
#add_definitions(-DINSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DCONFIG_PREFIX=${CONFIG_PREFIX})

#set_directory_properties(PROPERTIES COMPILE_DEFINITIONS_DEBUG BLUBB=1)
#set_directory_properties(PROPERTIES COMPILE_FLAGS "-pg -Wall")
#set_directory_properties(APPEND PROPERTY COMPILE_FLAGS -Wall)


IF(DBUS_FOUND AND ENABLE_DBUS)
  list(APPEND EXTRA_C "dbus.c")
  IF(POLKIT_FOUND)
    list(APPEND EXTRA_C "polkit.c")
  ENDIF(POLKIT_FOUND)
ENDIF(DBUS_FOUND AND ENABLE_DBUS)

add_executable(ulatencyd core.c ulatencyd.c group.c sysinfo.c sysctl.c
               linux_netlink.c umodule.c
               ${EXTRA_C} lua_binding.c tools.c)

target_link_libraries (ulatencyd dl ${MY_LUA_LIBRARIES}
                       ${DBUS_LIBRARIES}
                       ${GLIB2_LIBRARIES} ${GIO_LIBRARIES} ${GTHREAD_LIBRARIES}
                       ${POLKIT_LIBRARIES} ${PROCPS_LIBRARIES} )

SET_TARGET_PROPERTIES(ulatencyd PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS}")

configure_file(ulatencyd_cleanup.sh.tmpl ulatencyd_cleanup.sh)

install(TARGETS ulatencyd 
        RUNTIME DESTINATION sbin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ulatencyd_cleanup.sh
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ 
                    GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        DESTINATION lib/ulatencyd)
install(DIRECTORY lua
        DESTINATION lib/ulatencyd
        FILES_MATCHING PATTERN "*.lua")
