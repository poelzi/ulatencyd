add_executable(memleak memleak.c)
SET_TARGET_PROPERTIES(memleak PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS}")


add_executable(forkbomb forkbomb.c)
SET_TARGET_PROPERTIES(forkbomb PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS}")


if(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
  # FIXME needs rework
  #add_executable(test_xwatch test_xwatch.c)
  include_directories(${XCB_INCLUDE_DIRS} ${XAU_INCLUDE_DIRS} ${DBUS_INCLUDE_DIRS})
  #target_link_libraries(test_xwatch ${GLIB2_LIBRARIES} ${XCB_LIBRARIES} 
  #                       ${XAU_LIBRARIES} ${DBUS_LIBRARIES})
  #SET_TARGET_PROPERTIES(test_xwatch PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS} -O0")
else(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
  message("xcb, xau or dbus headers missing. disable xwatch module")
endif(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
