
add_executable(ulatencyd ulatencyd.c lua_binding.c)
target_link_libraries (ulatencyd proc lbc ${LUA_LIBRARIES} ${LIBCGROUP_LIBRARIES} ${GLIB2_LIBRARIES})
