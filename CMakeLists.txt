cmake_minimum_required(VERSION 2.8)
project(ulatency C)

INCLUDE(FindPkgConfig)
INCLUDE(FindGettext)
INCLUDE (CheckIncludeFiles)


option(CONFIG_PREFIX "config prefix" "/etc")
option(DEVELOP_MODE "build for development" FALSE)
option(DEVELOP_DBUS_SESSION "export to session dbus" FALSE)
option(LIBCGROUPS "add libcgroups support (BROKEN)" FALSE)
option(LUA_JIT "enable luajit support when available" FALSE)
option(ENABLE_DBUS "enable dbus" TRUE)
option(STATIC_LINK_LIBPROCPS "statically link to libprocps" TRUE)

SET(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})


if(LIBCGROUPS)
  pkg_check_modules(LIBCGROUP libcgroup OPTIONAL)
endif(LIBCGROUPS)

pkg_check_modules(GLIB2 glib-2.0 REQUIRED)

#pkg_check_modules(GMODULE gmodule-2.0 REQUIRED)
if(ENABLE_DBUS)
  pkg_check_modules(DBUS dbus-glib-1 REQUIRED)
  if(DBUS_FOUND)
    set(ENABLE_DBUS 1)
    pkg_check_modules(GTHREAD gthread-2.0 REQUIRED)
    pkg_check_modules(POLKIT polkit-gobject-1)
  endif(DBUS_FOUND)
endif(ENABLE_DBUS)

pkg_check_modules(GIO gio-2.0 REQUIRED)

if(POLKIT_FOUND)
  INCLUDE (CheckLibraryExists)
  CHECK_LIBRARY_EXISTS(polkit-gobject-1 polkit_authority_get_sync "" POLKIT_HAVE_GET_SYNC)
endif(POLKIT_FOUND)

# libproc (static or dynamic linking)

pkg_check_modules(LIBPROC libprocps REQUIRED)
if(STATIC_LINK_LIBPROCPS)
  set(STATIC_LINK_LIBPROCPS_PATH ${LIBPROC_LIBDIR}/libprocps.a CACHE STRING "Full path to libprocps.a for static linking" FORCE)
  if(NOT EXISTS ${STATIC_LINK_LIBPROCPS_PATH})
    message(FATAL_ERROR "Static procps library not found: ${STATIC_LINK_LIBPROCPS_PATH}")
  endif(NOT EXISTS ${STATIC_LINK_LIBPROCPS_PATH})
  add_library(procps STATIC IMPORTED)
  set_target_properties( procps PROPERTIES IMPORTED_LOCATION ${STATIC_LINK_LIBPROCPS_PATH} )
else(STATIC_LINK_LIBPROCPS)
  set(procps ${LIBPROC_LIBRARIES})
endif(STATIC_LINK_LIBPROCPS)

SET(CONFIG_PREFIX "/etc" CACHE STRING
      "Config prefix"
      FORCE)
SET(SYSTEMD_DIR "/lib/systemd/system" CACHE STRING
      "systemd service file directory")

if(DEVELOP_MODE)
  message("don't forget to copy conf/org.quamquam.ulatencyd.conf to /etc/dbus-1/system.d and reload dbus")
  SET(CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/conf")
else(DEVELOP_MODE)
  SET(CONFIG_DIR "${CONFIG_PREFIX}/ulatencyd")
endif(DEVELOP_MODE)



IF(LUA_JIT)
  pkg_check_modules(LUAJIT luajit)
ENDIF(LUA_JIT)


IF(NOT LUAJIT_FOUND)

  #find_package(lua51)
  INCLUDE(FindLua51)

  IF(NOT LUA51_FOUND)
    message(FATAL_ERROR "lua 5.1 not found")
  ENDIF(NOT LUA51_FOUND)

ENDIF(NOT LUAJIT_FOUND)
# config.h checks
#include(ConfigureChecks.cmake)
#MACRO(INSERT_INTO_MAP _TYPE _KEY _VALUE)
#  SET("SYS_${_TYPE}_${_KEY}" "${_VALUE}")
#ENDMACRO(INSERT_INTO_MAP)

#FIXME check this

CHECK_INCLUDE_FILES (locale.h HAVE_LOCALE_H)

if(GETTEXT_FOUND)
  set(ENABLE_NLS 1)
endif(GETTEXT_FOUND)

configure_file(src/config.h.tmpl ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)


include_directories (${CMAKE_CURRENT_BINARY_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src
                     ${LIBCGROUP_INCLUDE_DIRS}
                     ${LIBPROC_INCLUDE_DIRS} ${GLIB2_INCLUDE_DIRS} ${DBUS_INCLUDE_DIRS}
                     ${GIO_INCLUDE_DIRS} ${POLKIT_INCLUDE_DIRS})

IF(LUA_JIT AND LUAJIT_FOUND)
  include_directories (${LUAJIT_INCLUDE_DIRS})
  set(MY_LUA_LIBRARIES ${LUAJIT_LIBRARIES})
ELSE(LUA_JIT AND LUAJIT_FOUND)
  include_directories (${LUA_INCLUDE_DIR})
  set(MY_LUA_LIBRARIES ${LUA_LIBRARIES})
ENDIF(LUA_JIT AND LUAJIT_FOUND)


if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(ADD_COMPILE_FLAGS "-g -pg -Wall -Wformat -Werror=format-security")
endif("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")

add_subdirectory(src/bc)
add_subdirectory(src)
add_subdirectory(modules)
add_subdirectory(tests)
add_subdirectory(docs)


#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall")
#SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -pg -Wall")

#SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS  "-Wall")
SET_PROPERTY(GLOBAL APPEND PROPERTY CMAKE_C_FLAGS "-Wall -uiaeiaue")


# FIXME make distclean recrusive
set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)

ADD_CUSTOM_TARGET (distclean @echo cleaning for source distribution)
SET(DISTCLEANED
 cmake.depends
 cmake.check_depends
 CMakeCache.txt
 cmake.check_cache
 *.cmake
 Makefile
 core core.*
 gmon.out
 *~
 GPATH
 GRTAGS
 GSYMS
 GTAGS
)

ADD_CUSTOM_COMMAND(
  DEPENDS src/distclean clean
  COMMENT "distribution clean"
  COMMAND rm
  ARGS    -Rf CMakeTmp ${DISTCLEANED}
  TARGET  distclean
)

install(FILES conf/ulatencyd.conf 
        DESTINATION ${CONFIG_PREFIX}/ulatencyd)
install(FILES conf/cgroups.conf 
        DESTINATION ${CONFIG_PREFIX}/ulatencyd)
install(FILES conf/simple.conf
        DESTINATION ${CONFIG_PREFIX}/ulatencyd)
install(DIRECTORY rules 
        DESTINATION ${CONFIG_PREFIX}/ulatencyd 
        FILES_MATCHING PATTERN "*.lua"
        PATTERN "test.lua" EXCLUDE)
install(DIRECTORY conf/simple.d
        DESTINATION ${CONFIG_PREFIX}/ulatencyd
        PATTERN "*~" EXCLUDE)
install(DIRECTORY conf/scheduler
        DESTINATION ${CONFIG_PREFIX}/ulatencyd
        PATTERN "*~" EXCLUDE)

# install client files
FILE(GLOB cl RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "client/ulatency*")
SET(client "${cl}" "${client}")
FILE(GLOB cl RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "client/run-*")
SET(client "${cl}" "${client}")

install(PROGRAMS ${client}
        DESTINATION bin)

if(NOT "${SYSTEMD_DIR}" STREQUAL "")
  install(FILES scripts/service/systemd/ulatencyd.service
          DESTINATION ${SYSTEMD_DIR})
endif (NOT "${SYSTEMD_DIR}" STREQUAL "")

# FIXME how to find out where to put it ???
IF(DBUS_FOUND AND ENABLE_DBUS)
  install(FILES conf/org.quamquam.ulatencyd.conf
        DESTINATION /etc/dbus-1/system.d)
ENDIF(DBUS_FOUND AND ENABLE_DBUS)

if(POLKIT_FOUND)
  install(FILES conf/org.quamquam.ulatencyd.policy
          DESTINATION ${POLKIT_PREFIX}/share/polkit-1/actions)
endif(POLKIT_FOUND)

#
# update the applications rule file
#

install(FILES scripts/cron.daily/99ulatencyd
        DESTINATION /etc/cron.daily)
install(FILES scripts/update-user-apps.sh
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ
                    GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        DESTINATION lib/ulatencyd)

#install(TARGETS mySharedLib DESTINATION /some/full/path)

#
#
# add_custom_target(dist-clean 
#                      COMMAND rm -rf CMakeCache.txt CMakeFiles/ CTestTestfile.cmake cmake_install.cmake Makefile
#                      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

enable_testing()
set(CMAKE_CTEST_COMMAND "ctest -V")

add_test(lua_tests src/ulatencyd -c tests/conf/ulatencyd.conf -r tests --rule-pattern test.lua -v -v -v)
# dbus dtd is outdated :-(
#add_test(dbus_config CONFIGURATIONS Debug 
#         COMMAND xmllint --loaddtd --valid conf/org.quamquam.ulatencyd.conf)
