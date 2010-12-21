
#add_library(efence STATIC IMPORTED)
#set_property(TARGET efence PROPERTY
#               IMPORTED_LOCATION /usr/lib/libefence.a)


add_definitions(-DINSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DCONFIG_PREFIX=${CONFIG_PREFIX})

add_executable(ulatencyd ulatencyd.c lua_binding.c group.c)
target_link_libraries (ulatencyd proc lbc dl ${LUA_LIBRARIES} 
                       ${LIBCGROUP_LIBRARIES} ${GLIB2_LIBRARIES})
