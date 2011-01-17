# some macros
macro(add_module LNAME)
  add_library(${LNAME} MODULE
              ${ARGV})
  set_target_properties(${LNAME} PROPERTIES PREFIX "")
endmacro(add_module)

add_module(test test.c)

pkg_check_modules(XCB xcb)
pkg_check_modules(XCB_EVENT xcb-event)
pkg_check_modules(XCB_PROP xcb-property)

if(XCB_FOUND)
  add_module(xwatch xwatch.c)
  include_directories(${XCB_INCLUDE_DIRS} ${XCB_EVENT_INCLUDE_DIRS} ${XCB_PROP_INCLUDE_DIRS})
  target_link_libraries (xwatch ${GLIB2_LIBRARIES} ${XCB_LIBRARIES} ${XCB_EVENT_LIBRARIES} ${XCB_PROP_LIBRARIES})
else(XCB_FOUND)
  message("xcb headers not found, disable xwatch module")
endif(XCB_FOUND)
