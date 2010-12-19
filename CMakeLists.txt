cmake_minimum_required(VERSION 2.8)
project(ulatency)

INCLUDE(FindPkgConfig)

pkg_check_modules(LIBCGROUP libcgroup REQUIRED)

pkg_check_modules(GLIB2 glib-2.0 REQUIRED)

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

set(LIBPROC_INCLUDE_DIRS src)
#set(LIBPROC_LIBRARY src/proc/libproc.a)



#find_package(lua51)
INCLUDE(FindLua51)

IF(NOT LUA51_FOUND)
  message(FATAL_ERROR "lua 5.1 not found")
ENDIF(NOT LUA51_FOUND)

include_directories (${LUA_INCLUDE_DIR} ${LIBCGROUP_INCLUDE_DIRS} ${LIBPROC_INCLUDE_DIRS} ${GLIB2_INCLUDE_DIRS})




set(CMAKE_CXX_FLAGS "-g -Wall")
add_subdirectory(src/bc)
add_subdirectory(src/proc)
add_subdirectory(src)
