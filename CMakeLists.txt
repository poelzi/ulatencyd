cmake_minimum_required(VERSION 2.8)
project(ulatency)

INCLUDE(FindPkgConfig)
INCLUDE(FindGettext)

option(CONFIG_PREFIX "config prefix" "/etc")

option(DEVELOP_MODE "build for development" FALSE)

pkg_check_modules(LIBCGROUP libcgroup REQUIRED)

pkg_check_modules(GLIB2 glib-2.0 REQUIRED)
#pkg_check_modules(GMODULE gmodule-2.0 REQUIRED)

pkg_check_modules(DBUS dbus-glib-1 REQUIRED)


# FIXME: libproc should export more symbols
# find libproc
#FIND_PATH(LIBPROC_INCLUDE_DIR readproc.h /usr/include/proc /usr/local/include/proc)

#FIND_LIBRARY(LIBPROC_LIBRARY NAMES proc PATH /usr/lib /usr/local/lib)

#IF (LIBPROC_INCLUDE_DIR AND LIBPROC_LIBRARY)
#   SET(LIBPROC_FOUND TRUE)
#ENDIF (LIBPROC_INCLUDE_DIR AND LIBPROC_LIBRARY)


#IF (NOT LIBPROC_FOUND)
#   MESSAGE(FATAL_ERROR "Could not find libproc")
#ENDIF (NOT LIBPROC_FOUND)

# use own libproc copy
SET(CONFIG_PREFIX "/etc/" CACHE STRING
      "Config prefix"
      FORCE)

set(LIBPROC_INCLUDE_DIRS src)
#set(LIBPROC_LIBRARY src/proc/libproc.a)

IF(DEVELOP_MODE)
  add_definitions(-DDEVELOP_MODE)
ENDIF(DEVELOP_MODE)

#find_package(lua51)
INCLUDE(FindLua51)

IF(NOT LUA51_FOUND)
  message(FATAL_ERROR "lua 5.1 not found")
ENDIF(NOT LUA51_FOUND)

# config.h checks
#include(ConfigureChecks.cmake)
#MACRO(INSERT_INTO_MAP _TYPE _KEY _VALUE)
#  SET("SYS_${_TYPE}_${_KEY}" "${_VALUE}")
#ENDMACRO(INSERT_INTO_MAP)

#FIXME check this

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "alpha")
  SET("SYS_ioprio_set" "442")
  SET("SYS_ioprio_get" "443")
endif(CMAKE_SYSTEM_PROCESSOR STREQUAL "alpha")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "i.*86")
  SET("SYS_ioprio_set" "289")
  SET("SYS_ioprio_get" "290")
endif(CMAKE_SYSTEM_PROCESSOR MATCHES "i.*86")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "ia64.*")
  SET("SYS_ioprio_set" "1274")
  SET("SYS_ioprio_get" "1275")
endif(CMAKE_SYSTEM_PROCESSOR MATCHES "ia64.*")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "powerpc.*")
  SET("SYS_ioprio_set" "273")
  SET("SYS_ioprio_get" "274")
endif(CMAKE_SYSTEM_PROCESSOR MATCHES "powerpc.*")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "s390.*")
  SET("SYS_ioprio_set" "282")
  SET("SYS_ioprio_get" "283")
endif(CMAKE_SYSTEM_PROCESSOR MATCHES "s390.*")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "sparc.*")
  SET("SYS_ioprio_set" "196")
  SET("SYS_ioprio_get" "218")
endif(CMAKE_SYSTEM_PROCESSOR MATCHES "sparc.*")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "sh.*")
  SET("SYS_ioprio_set" "288")
  SET("SYS_ioprio_get" "289")
endif(CMAKE_SYSTEM_PROCESSOR MATCHES "sh.*")
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  SET("SYS_ioprio_set" "252")
  SET("SYS_ioprio_get" "251")
endif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")


if(GETTEXT_FOUND)
  set(ENABLE_NLS 1)
endif(GETTEXT_FOUND)

configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)


include_directories (${CMAKE_CURRENT_BINARY_DIR} ${LUA_INCLUDE_DIR} ${LIBCGROUP_INCLUDE_DIRS} ${LIBPROC_INCLUDE_DIRS} ${GLIB2_INCLUDE_DIRS})


set(CMAKE_CXX_FLAGS "-g -Wall")
add_subdirectory(src/bc)
add_subdirectory(src/proc)
add_subdirectory(src)
add_subdirectory(modules)


#add_custom_command(OUTPUT "runtest"
#                     echo "cool"
#                     MAIN_DEPENDENCY src/ulatencyd
#                     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

enable_testing()
set(CMAKE_CTEST_COMMAND "ctest -V")

add_test(lua_tests src/ulatencyd -r tests --rule-pattern test.lua -v -v -v)
