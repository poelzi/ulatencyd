# some macros
macro(add_module LNAME)
  add_library(${LNAME} MODULE
              ${ARGV})
  set_target_properties(${LNAME} PROPERTIES PREFIX "")
  if(NOT "${LNAME}" STREQUAL "test")
    install(TARGETS ${LNAME} LIBRARY DESTINATION lib/ulatencyd/modules) 
  endif(NOT "${LNAME}" STREQUAL "test")
  SET_TARGET_PROPERTIES(${LNAME} PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS}")
endmacro(add_module)

add_module(test test.c)

pkg_check_modules(XCB xcb)
pkg_check_modules(XAU xau)
option(DEBUG_XWATCH "debug xwatch module" FALSE)

if(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
  add_module(xwatch xwatch.c)
  include_directories(${XCB_INCLUDE_DIRS} ${XAU_INCLUDE_DIRS} ${DBUS_INCLUDE_DIRS})
  target_link_libraries (xwatch ${GLIB2_LIBRARIES} ${XCB_LIBRARIES} ${XAU_LIBRARIES} ${DBUS_LIBRARIES})
  if(DEBUG_XWATCH)
    SET_TARGET_PROPERTIES(xwatch PROPERTIES COMPILE_FLAGS "${ADD_COMPILE_FLAGS} -DDEBUG_XWATCH")
  endif(DEBUG_XWATCH)
else(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
  message("xcb, xau or dbus headers missing. disable xwatch module")
endif(XCB_FOUND AND XAU_FOUND AND DBUS_FOUND AND ENABLE_DBUS)
