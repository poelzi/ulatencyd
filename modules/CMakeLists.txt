# some macros
macro(add_module LNAME)
  add_library(${LNAME} MODULE
              ${ARGV})
  set_target_properties(${LNAME} PROPERTIES PREFIX "")
  if(NOT "${LNAME}" STREQUAL "test_module")
    install(TARGETS ${LNAME} LIBRARY DESTINATION lib/ulatencyd/modules) 
  endif(NOT "${LNAME}" STREQUAL "test_module")
  SET_TARGET_PROPERTIES(${LNAME} PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS}")
endmacro(add_module)

# test
add_module(test_module test_module.c)
target_link_libraries(test_module ${GLIB2_LIBRARIES} ${GMODULE_LIBRARIES})

# simplerules
add_module(simplerules simplerules.c)
target_link_libraries(simplerules ${GMODULE_LIBRARIES})

# netlink_fallback
add_module(netlink_fallback netlink_fallback.c)
target_link_libraries(netlink_fallback ${GMODULE_LIBRARIES})


if (DBUS_FOUND AND ENABLE_DBUS)
  include_directories (${DBUS_INCLUDE_DIRS})

  # consolekit
  add_module (consolekit consolekit.c)
  target_link_libraries (consolekit ${GLIB2_LIBRARIES} ${GMODULE_LIBRARIES} ${DBUS_LIBRARIES})

  # logind
  add_module (logind logind.c)
  target_link_libraries (logind ${GLIB2_LIBRARIES} ${GMODULE_LIBRARIES} ${DBUS_LIBRARIES})


  pkg_check_modules(XCB xcb)
  pkg_check_modules(XAU xau)

  if (XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
    include_directories(${XCB_INCLUDE_DIRS} ${XAU_INCLUDE_DIRS})

    # xwatch
    option(DEBUG_XWATCH "debug xwatch module" FALSE)
    add_module(xwatch xwatch.c)
    target_link_libraries (xwatch ${GLIB2_LIBRARIES} ${GMODULE_LIBRARIES} ${DBUS_LIBRARIES} 
                           ${XCB_LIBRARIES} ${XAU_LIBRARIES})
    if (DEBUG_XWATCH)
      SET_TARGET_PROPERTIES(xwatch PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS} -DDEBUG_XWATCH")
    endif (DEBUG_XWATCH)
  else (XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
    message("xcb, xau or dbus headers missing. disable xwatch module")
  endif (XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)

else (DBUS_FOUND AND ENABLE_DBUS)
  message("DBUS headers missing. Modules xwatch, consolekit and logind modules disabled.")
endif (DBUS_FOUND AND ENABLE_DBUS)