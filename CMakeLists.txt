cmake_minimum_required(VERSION 2.8)
set(CMAKE_USER_MAKE_RULES_OVERRIDE
    "${CMAKE_SOURCE_DIR}/cmake/InitialFlags.cmake")

project(ulatency C)

INCLUDE(FindPkgConfig)
INCLUDE(FindGettext)
INCLUDE(CheckIncludeFiles)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")


option(DEVELOP_MODE "build for development" FALSE)
option(DEVELOP_DBUS_SESSION "export to session dbus" FALSE)
option(LUA_JIT "enable luajit support when available" FALSE)
option(ENABLE_DBUS "enable dbus" TRUE)

SET(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})


pkg_check_modules(GLIB2 glib-2.0 REQUIRED)
pkg_check_modules(GMODULE gmodule-2.0 REQUIRED)

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



# -----------------------------------------------------------------------------
#  Begin finding procps
# -----------------------------------------------------------------------------

# list of required libprocps symbols
set(PROCPS_CHECK_SYMBOLS
      "readtask" "readproc"
      "openproc" "closeproc" "freeproc"
      "uptime" "loadavg" "smp_num_cpus"
      "user_from_uid" "group_from_gid"
      "get_pid_digits"

      "meminfo"
      #grep -o 'kb_[a-zA-Z0-9_]*' src/lua_binding.c | tr '\n' ' ' | sed "s%\b%\"%g" | fmt
      "kb_active" "kb_main_shared" "kb_main_buffers" "kb_main_cached"
      "kb_main_free" "kb_main_total" "kb_swap_free" "kb_swap_total"
      "kb_high_free" "kb_high_total" "kb_low_free" "kb_low_total" "kb_active"
      "kb_inact_laundry" "kb_inact_dirty" "kb_inact_clean" "kb_inact_target"
      "kb_swap_cached" "kb_swap_used" "kb_main_used" "kb_writeback" "kb_slab"
      "kb_committed_as" "kb_dirty" "kb_inactive" "kb_mapped" "kb_pagetables"

      "vminfo"
      #grep -o 'vm_[a-zA-Z0-9_]*' src/lua_binding.c | tr '\n' ' ' | sed "s%\b%\"%g" | fmt
      "vm_nr_dirty" "vm_nr_writeback" "vm_nr_pagecache" "vm_nr_page_table_pages"
      "vm_nr_reverse_maps" "vm_nr_mapped" "vm_nr_slab" "vm_pgpgin" "vm_pgpgout"
      "vm_pswpin" "vm_pswpout" "vm_pgalloc" "vm_pgfree" "vm_pgactivate"
      "vm_pgdeactivate" "vm_pgfault" "vm_pgmajfault" "vm_pgscan" "vm_pgrefill"
      "vm_pgsteal" "vm_kswapd_steal" "vm_pageoutrun" "vm_allocstall"
  )
set(PROCPS_REQUIRE_SYMBOLS ${PROCPS_CHECK_SYMBOLS}) # require all
# list of required proc_t structure members
set(PROCPS_CHECK_PROC_T_MEMBERS
      "tid" "ppid" "state" "utime" "stime" "cutime" "cstime" "start_time"
      "signal" "blocked" "sigignore" "sigcatch" "_sigpnd" "start_code"
      "end_code" "start_stack" "kstk_esp" "kstk_eip" "wchan" "priority"
      "nice" "rss" "alarm" "size" "resident" "share" "trs" "lrs" "drs" "dt"
      "vm_size" "vm_lock" "vm_rss" "vm_data" "vm_stack" "vm_swap" "vm_exe"
      "vm_lib" "rtprio" "sched" "vsize" "rss_rlim" "flags" "min_flt" "maj_flt"
      "cmin_flt" "cmaj_flt" "euser" "ruser" "suser" "fuser" "rgroup" "egroup"
      "sgroup" "fgroup" "cmd" "nlwp" "tgid" "tty" "euid" "egid" "ruid" "rgid"
      "suid" "sgid" "fuid" "fgid" "tpgid" "exit_signal" "processor"
  )
set(PROCPS_REQUIRE_PROC_T_MEMBERS ${PROCPS_CHECK_PROC_T_MEMBERS}) # require all
set(Procps_VERBOSE ON)

set(PROCPS_REQUIRE_NG ON) # set OFF if you want to try older procps;
                          # proc_t->vm_swap will be probably missing and
                          # the legacy library was never tested with ulatencyd
find_package(Procps "3.3.0" REQUIRED) # not sure by version, 3.3.3 tested

# -----------------------------------------------------------------------------
#  End finding procps
# -----------------------------------------------------------------------------



SET(CONFIG_PREFIX "/etc" CACHE PATH
      "Config prefix")
SET(SYSTEMD_DIR "/lib/systemd/system" CACHE PATH
      "systemd service file directory")
SET(UPSTART_DIR "/etc/init" CACHE PATH
      "Upstart job configuration directory")

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

include_directories (${CMAKE_CURRENT_BINARY_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src
                     ${GLIB2_INCLUDE_DIRS} ${DBUS_INCLUDE_DIRS}
                     ${GIO_INCLUDE_DIRS} ${POLKIT_INCLUDE_DIRS}
                     ${PROCPS_INCLUDE_DIRS} )

IF(LUA_JIT AND LUAJIT_FOUND)
  include_directories (${LUAJIT_INCLUDE_DIRS})
  set(MY_LUA_LIBRARIES ${LUAJIT_LIBRARIES})
ELSE(LUA_JIT AND LUAJIT_FOUND)
  include_directories (${LUA_INCLUDE_DIR})
  set(MY_LUA_LIBRARIES ${LUA_LIBRARIES})
ENDIF(LUA_JIT AND LUAJIT_FOUND)



# -----------------------------------------------------------------------------
#  Begin handling compile / linker flags
# -----------------------------------------------------------------------------

string(TOUPPER "${CMAKE_BUILD_TYPE}" U_BUILD_TYPE)

# Add warnings to CMAKE_C_FLAGS
string(STRIP
       "-Wall -Wformat -Werror=format-security ${CMAKE_C_FLAGS}"
       CMAKE_C_FLAGS)

# Make linker use same flags used by compiler (mainly due LTO)
if(CMAKE_BUILD_TYPE)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS_${U_BUILD_TYPE}} ${CMAKE_EXE_LINKER_FLAGS}")
  set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_C_FLAGS_${U_BUILD_TYPE}} ${CMAKE_MODULE_LINKER_FLAGS}")
endif()
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_EXE_LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_MODULE_LINKER_FLAGS}")

#
# Create U_*_FLAGS variables containing all compile and link flags for
# current CMAKE_BUILD_TYPE and pass them to config.h, so we may print them
# in --version
#
set(U_C_FLAGS "${CMAKE_C_FLAGS}")
set(U_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
set(U_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS}")

if(CMAKE_BUILD_TYPE)
    set(U_C_FLAGS "${U_C_FLAGS} ${CMAKE_C_FLAGS_${U_BUILD_TYPE}}")
    set(U_EXE_LINKER_FLAGS "${U_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${U_BUILD_TYPE}}")
    set(U_MODULE_LINKER_FLAGS "${U_MODULE_LINKER_FLAGS} ${CMAKE_MODULE_LINKER_FLAGS_${U_BUILD_TYPE}}")
endif()

string(STRIP "${U_C_FLAGS}" U_C_FLAGS)
string(STRIP "${U_EXE_LINKER_FLAGS}" U_EXE_LINKER_FLAGS)
string(STRIP "${U_MODULE_LINKER_FLAGS}" U_MODULE_LINKER_FLAGS)

# -----------------------------------------------------------------------------
#  End handling compile / linker flags
# -----------------------------------------------------------------------------


configure_file(src/config.h.tmpl ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)

add_subdirectory(src)
add_subdirectory(modules)
add_subdirectory(tests)
add_subdirectory(docs)


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

if(NOT "${UPSTART_DIR}" STREQUAL "")
  if(ENABLE_DBUS)
    install(FILES scripts/service/upstart/ulatencyd-dbus.conf
            DESTINATION ${UPSTART_DIR}
            RENAME ulatencyd.conf)
  else(ENABLE_DBUS)
    install(FILES scripts/service/upstart/ulatencyd.conf
            DESTINATION ${UPSTART_DIR})
  endif(ENABLE_DBUS)
endif(NOT "${UPSTART_DIR}" STREQUAL "")

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
