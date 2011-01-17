add_executable(memleak memleak.c)
SET_TARGET_PROPERTIES(memleak PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS}")

if(ENABLE_DBUS)
  add_executable(test_xwatch test_xwatch.c)
  target_link_libraries (test_xwatch ${GLIB2_LIBRARIES} ${DBUS_LIBRARIES}
                         ${XCB_LIBRARIES} ${XCB_EVENT_LIBRARIES} ${XCB_PROP_LIBRARIES})

  SET_TARGET_PROPERTIES(test_xwatch PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS} -O0")
endif(ENABLE_DBUS)
