add_executable(memleak memleak.c)
add_executable(forkbomb forkbomb.c)

if(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
  # FIXME needs rework
  #add_executable(test_xwatch test_xwatch.c)
  include_directories(${XCB_INCLUDE_DIRS} ${XAU_INCLUDE_DIRS} ${DBUS_INCLUDE_DIRS})
  #target_link_libraries(test_xwatch ${GLIB2_LIBRARIES} ${XCB_LIBRARIES} 
  #                       ${XAU_LIBRARIES} ${DBUS_LIBRARIES})
else(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
  message("xcb, xau or dbus headers missing. disable xwatch module")
endif(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
