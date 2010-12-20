# some macros
macro(add_module LNAME)
  add_library(${LNAME} MODULE
              ${ARGV})
  set_target_properties(${LNAME} PROPERTIES PREFIX "")
endmacro(add_module)

add_module(test test.c)

