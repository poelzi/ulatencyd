# - Try to find procps
# Once done this will be defined
#  PROCPS_FOUND         - System has libprocps
#  PROCPS_INCLUDE_DIRS  - The libprocps include directories
#  PROCPS_LIBRARIES     - The libraries needed to use libprocps
#  PROCPS_VERSION_STRING - libprocps version
#  PROCPS_MISSING_SYMBOLS - list of missing symbols (see PROCPS_CHECK_SYMBOLS)
#  PROCPS_MISSING_PROC_T_MEMBERS - list of missing proc_t members (see PROCPS_CHECK_PROC_T_MEMBERS)
#
# Options you can set before calling find_package(Procps ...)
#  PROCPS_STATIC        - force static linkage
#  PROCPS_REQUIRE_NG    - if set, require libprocps-ng
#  PROCPS_CHECK_SYMBOLS - list of symbols to check
#  PROCPS_CHECK_PROC_T_MEMBERS - list of proc_t members to check
#  PROCPS_REQUIRE_SYMBOLS - list of required symbols from PROCPS_CHECK_SYMBOLS
#  PROCPS_REQUIRE_PROC_T_MEMBERS - list of required proc_t members from PROCPS_CHECK_PROC_T_MEMBERS
#  Procps_VERBOSE         - be more verbose
#
# -----------------------------------------------------------------------------
#  Example usage
# -----------------------------------------------------------------------------
#
# set(PROCPS_CHECK_SYMBOLS             # list of required libprocps symbols
#       "readtask" "readproc"
#       "openproc" "closeproc" "freeproc"
#       "uptime" "loadavg" "smp_num_cpus"
#       "user_from_uid" "group_from_gid"
#       "get_pid_digits"
#
#       "meminfo"
#       "kb_active" "kb_main_shared" "kb_main_buffers" "kb_main_cached"
#       "kb_main_free" "kb_main_total" "kb_swap_free" "kb_swap_total"
#       "kb_high_free" "kb_high_total" "kb_low_free" "kb_low_total" "kb_active"
#       "kb_inact_laundry" "kb_inact_dirty" "kb_inact_clean" "kb_inact_target"
#       "kb_swap_cached" "kb_swap_used" "kb_main_used" "kb_writeback" "kb_slab"
#       "kb_committed_as" "kb_dirty" "kb_inactive" "kb_mapped" "kb_pagetables"
#
#       "vminfo"
#       "vm_nr_dirty" "vm_nr_writeback" "vm_nr_pagecache" "vm_nr_page_table_pages"
#       "vm_nr_reverse_maps" "vm_nr_mapped" "vm_nr_slab" "vm_pgpgin" "vm_pgpgout"
#       "vm_pswpin" "vm_pswpout" "vm_pgalloc" "vm_pgfree" "vm_pgactivate"
#       "vm_pgdeactivate" "vm_pgfault" "vm_pgmajfault" "vm_pgscan" "vm_pgrefill"
#       "vm_pgsteal" "vm_kswapd_steal" "vm_pageoutrun" "vm_allocstall"
#   )
# set(PROCPS_REQUIRE_SYMBOLS ${PROCPS_CHECK_SYMBOLS}) # require all
#
# set(PROCPS_CHECK_PROC_T_MEMBERS	    # list of required proc_t structure members
#       "tid" "ppid" "state" "utime" "stime" "cutime" "cstime" "start_time"
#       "signal" "blocked" "sigignore" "sigcatch" "_sigpnd" "start_code"
#       "end_code" "start_stack" "kstk_esp" "kstk_eip" "wchan" "priority"
#       "nice" "rss" "alarm" "size" "resident" "share" "trs" "lrs" "drs" "dt"
#       "vm_size" "vm_lock" "vm_rss" "vm_data" "vm_stack" "vm_swap" "vm_exe"
#       "vm_lib" "rtprio" "sched" "vsize" "rss_rlim" "flags" "min_flt" "maj_flt"
#       "cmin_flt" "cmaj_flt" "euser" "ruser" "suser" "fuser" "rgroup" "egroup"
#       "sgroup" "fgroup" "cmd" "nlwp" "tgid" "tty" "euid" "egid" "ruid" "rgid"
#       "suid" "sgid" "fuid" "fgid" "tpgid" "exit_signal" "processor"
#   )
# set(PROCPS_REQUIRE_PROC_T_MEMBERS ${PROCPS_CHECK_PROC_T_MEMBERS}) # require all
# set(Procps_VERBOSE ON)
#
# set(PROCPS_REQUIRE_NG ON) # set OFF if you want to try legacy non-forked procps;
#                           # proc_t->vm_swap will be probably missing
# find_package(Procps REQUIRED "3.3.0")
#
# if(PROCPS_STATIC)
#   # static linkage to procps
#   include_directories(${PROCPS_STATIC_INCLUDE_DIRS})
#   set(MY_PROCPS_LIBRARIES ${PROCPS_STATIC_LIBRARIES})
# else()
#   # dynamic linkage to shared procps
#   include_directories(${PROCPS_INCLUDE_DIRS})
#   set(MY_PROCPS_LIBRARIES ${PROCPS_LIBRARIES})
# endif()
#
#
#=============================================================================
# Copyright 2014 Petr Gajdůšek <gajdusek.petr@centrum.cz>
#
# Distributed under the OSI-approved BSD License (the "License")
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================

message(STATUS "Finding procps library and headers...")

INCLUDE(FindPkgConfig)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckStructHasMember)
INCLUDE(FindPackageHandleStandardArgs)

# -----------------------------------------------------------------------------
#  Options and help messages
# -----------------------------------------------------------------------------

set(desc_PROCPS_STATIC      # list will be displayed joined with semi-colon
  "Do static linkage to libprocps"
  " this is usually required because procps API is not standardized"
  " turn this OFF only if you have patched libprocps to export all needed symbols.")

option(PROCPS_STATIC "${desc_PROCPS_STATIC}" TRUE)

set(help_PROCPS_STATIC_LOCATION
  "You can override location of libprocps library and the include directory by"
  " setting PROCPS_STATIC_LIBRARY and PROCPS_STATIC_INCLUDE_DIR cmake"
  " variables.\n"
  "   PROCPS_STATIC_LIBRARY       specifies full path to the library\n"
  "                               (i.e. path to the libprocps.a file)\n"
  "   PROCPS_STATIC_INCLUDE_DIR   specifies directory which contains\n"
  "                               the proc/procps.h header.\n"
  "You may achieve this e.g. by running\n"
  " ## cmake -D PROCPS_STATIC_LIBRARY:FILEPATH=/path/to/libprocps.a"
  " -D PROCPS_STATIC_INCLUDE_DIR:PATH=/path/to/include/dir .\n" )

set(help_PROCPS_SHARED
  "If you insist on dynamic linkage to shared libprocps, update or patch"
  " libprocps to export all symbols that application needs. If you"
  " manage your solution to be persistent, future proof (in sense of"
  " API changes) and officially accepted by your GNU/Linux"
  " distribution, please contact authors."
  "\n"
  "Otherwise consider static linkage to libprocps by setting cmake"
  " variable PROCPS_STATIC, e.g. by running\n"
  " ## cmake -D PROCPS_STATIC:BOOL=ON .\n" )

set(help_PROCPS_SHARED_LOCATION
  "You can override location of shared libprocps library and the include"
  " directory by setting PROCPS_LIBRARY and PROCPS_INCLUDE_DIR cmake"
  " variables.\n"
  "   PROCPS_LIBRARY              specifies full path to the library\n"
  "                               (i.e. path to the libprocps.so file)\n"
  "   PROCPS_INCLUDE_DIR          specifies directory which contains\n"
  "                               the proc/procps.h header.\n"
  "You may achieve this e.g. by running\n"
  " ## cmake -D PROCPS_LIBRARY:FILEPATH=/path/to/libprocps.so"
  " -D PROCPS_INCLUDE_DIR:PATH=/path/to/include/dir .\n" )



# -----------------------------------------------------------------------------
#  Miscellaneous macros
# -----------------------------------------------------------------------------

macro(print_procps_variables)
 foreach(_varname LIBRARY STATIC_LIBRARY INCLUDE_DIR STATIC_INCLUDE_DIR
                  VERSION_STRING STATIC_VERSION_STRING)
   message(STATUS "\${_PROCPS_SAVED_${_varname}} = ${_PROCPS_SAVED_${_varname}} "
           "    \${PROCPS_${_varname}} = ${PROCPS_${_varname}}" )
 endforeach()
endmacro()

macro(verbose_message)
  if(Procps_VERBOSE AND NOT Procps_FIND_QUIETLY)
    message(STATUS "  " ${ARGV})
  endif()
endmacro()

#
# fail
#
macro(fail)
  if(PROCPS_STATIC)
    if(NOT _found_lib)
      set(_msg "Suitable ${_log_libname} static library not found.\n" )
    elseif(NOT _found_headers)
      set(_msg "Suitable ${_log_libname} include directory not found.\n" )
    endif()
    set(_msg ${_msg} ${help_PROCPS_STATIC_LOCATION} )
  else(PROCPS_STATIC)
    if(NOT _found_lib)
      set(_msg "Suitable ${_log_libname} shared library not found.\n" )
    elseif(NOT _found_headers)
      set(_msg "Suitable ${_log_libname} include directory not found.\n" )
    endif()
    set(_msg ${_msg} ${help_PROCPS_SHARED_LOCATION} "\n" ${help_PROCPS_SHARED} )
  endif()

  if(Procps_FIND_REQUIRED)
    message(SEND_ERROR "Unable to find procps.\nREASON: " ${ARGV} "\n" ${_msg})
  elseif(NOT Procps_FIND_QUIETLY)
    message(STATUS "  W: " ${ARGV} )
  endif()
  return()
endmacro()


# -----------------------------------------------------------------------------
#  Begin finding procps library and headers
# -----------------------------------------------------------------------------

find_package(PkgConfig)

unset(PC_PROCPS_FOUND CACHE)
pkg_check_modules(PC_PROCPS QUIET libprocps)

if(PROCPS_REQUIRE_NG)
  message(STATUS "  ... (libprocps-ng required, legacy libproc will be ignored) ...")
  set(_log_libname "procps-ng") # for logs
  set(lib_names "procps")
  set(ver_rexp
    # 's/^\.\{0,\}procps-ng version \([0-9\.]\{1,\}\)\.\{0,\}$/\1/p'
    "s/^\\.\\{0,\\}procps-ng version \\([0-9\\.]\\{1,\\}\\)\\.\\{0,\\}$/\\1/p" )
else()
  set(_log_libname "procps") # for logs
  set(lib_names "procps" "proc")
  set(ver_rexp
    # 's/^\.\{0,\}procps\(-ng\|\) version \([0-9\.]\{1,\}\)\.\{0,\}$/\2/p'
    "s/^\\.\\{0,\\}procps\\(-ng\\|\\) version \\([0-9\\.]\\{1,\\}\\)\\.\\{0,\\}$/\\2/p" )
endif()

# -----------------------------------------------------------------------------
#  Finding static procps library and headers
# -----------------------------------------------------------------------------

unset(_found_lib)
unset(_found_headers)

if (PROCPS_STATIC)
  message(STATUS "  ... for static linkage.")
  set(desc_PROCPS_STATIC_LIBRARY # list will be displayed joined with semi-colon
    "Full path to libprocps.a for static linkage"
    " leave empty for auto detection.")

  set(desc_PROCPS_STATIC_INCLUDE_DIR # list will be displayed joined with semi-colon
    "Directory that contains proc/procps.h header for static linkage"
    " leave empty for auto detection.")

  ## headers

  find_path(PROCPS_STATIC_INCLUDE_DIR proc/procps.h
            HINTS ${PC_PROCPS_STATIC_INCLUDEDIR}
                  ${PC_PROCPS_STATIC_INCLUDE_DIRS}
            PATH_SUFFIXES libprocps procps
            DOC "${desc_PROCPS_STATIC_INCLUDE_DIR}" )

  if(EXISTS "${PROCPS_STATIC_INCLUDE_DIR}/proc/procps.h")
    verbose_message("I: include directory found: ${PROCPS_STATIC_INCLUDE_DIR}")
  else()
    verbose_message("W: proc/procps.h not found in include directory: "
                    "${PROCPS_STATIC_INCLUDE_DIR}")
    fail("Include directory not found.")
  endif()

  ## static library

  set(CMAKE_FIND_LIBRARY_PREFIXES ${CMAKE_STATIC_LIBRARY_PREFIX})
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})

  find_library(PROCPS_STATIC_LIBRARY NAMES ${lib_names}
               HINTS ${PC_PROCPS_STATIC_LIBDIR}
                     ${PC_PROCPS_STATIC_LIBRARY_DIRS}
                     DOC "${desc_PROCPS_STATIC_LIBRARY}" )

  if(EXISTS ${PROCPS_STATIC_LIBRARY})
    verbose_message("I: static library found: "
                    ${PROCPS_STATIC_LIBRARY} )
  else()
    fail("Static library not found.")
  endif()

  ## library version

  if(PROCPS_STATIC_LIBRARY)
    execute_process(
                COMMAND "strings" "${PROCPS_STATIC_LIBRARY}"
                COMMAND "sed" "-n" "${ver_rexp}"
                OUTPUT_VARIABLE PROCPS_STATIC_VERSION_STRING )
    # trim EOL
    STRING(REGEX REPLACE "(\r?\n)+$" ""
           PROCPS_STATIC_VERSION_STRING "${PROCPS_STATIC_VERSION_STRING}")
  endif()

  if(PROCPS_STATIC_VERSION_STRING)
    verbose_message("I: version string of ${_log_libname} found: "
                    "${PROCPS_STATIC_VERSION_STRING}")
  else()
    set(_err "Version string of ${_log_libname} not found.")
    if(PROCPS_REQUIRE_NG)
      set(_err ${_err} " The found library may be legacy procps but"
                       " procps-ng is required.")
    endif()
    fail(${_err})
  endif()

  ## store result

  if(PROCPS_STATIC_VERSION_STRING AND PROCPS_STATIC_LIBRARY)
    set(_found_lib ON)
  endif()
  if(PROCPS_STATIC_INCLUDE_DIR)
    set(_found_headers ON)
  endif()

  set(PROCPS_STATIC_LIBRARIES ${PROCPS_STATIC_LIBRARY} )
  set(PROCPS_STATIC_INCLUDE_DIRS ${PROCPS_STATIC_INCLUDE_DIR} )

  mark_as_advanced(PROCPS_VERSION_STRING)

  ## setup for test compilations (CHECK_SYMBOL_EXISTS)

  if(PROCPS_REQUIRE_SYMBOLS)
    set(CMAKE_REQUIRED_INCLUDES ${PROCPS_STATIC_INCLUDE_DIRS})
    set(CMAKE_REQUIRED_LIBRARIES ${PROCPS_STATIC_LIBRARIES})
  endif()

# -----------------------------------------------------------------------------
#  Finding shared procps library and headers
# -----------------------------------------------------------------------------

else(PROCPS_STATIC)
  message(STATUS "  ... for dynamic linkage.")

  ## headers

  find_path(PROCPS_INCLUDE_DIR proc/procps.h
            HINTS ${PC_PROCPS_INCLUDEDIR} ${PC_PROCPS_INCLUDE_DIRS}
            PATH_SUFFIXES libprocps procps)

  if(EXISTS "${PROCPS_INCLUDE_DIR}/proc/procps.h")
    verbose_message("I: include directory found: ${PROCPS_INCLUDE_DIR}")
  else()
    verbose_message("W: proc/procps.h not found in include directory: "
                    "${PROCPS_INCLUDE_DIR}")
    fail("Include directory not found.")
  endif()

  ## shared library

  find_library(PROCPS_LIBRARY NAMES ${lib_names}
               HINTS ${PC_PROCPS_LIBDIR} ${PC_PROCPS_LIBRARY_DIRS} )

  if(EXISTS "${PROCPS_LIBRARY}")
    verbose_message("I: shared library found: "
                    ${PROCPS_LIBRARY} )
  else()
    fail("Shared library not found.")
  endif()

  ## library version

  if(PROCPS_LIBRARY)
    execute_process(
                COMMAND "strings" "${PROCPS_LIBRARY}"
                COMMAND "sed" "-n" "${ver_rexp}"
                OUTPUT_VARIABLE PROCPS_VERSION_STRING )
    # trim EOL
    STRING(REGEX REPLACE "(\r?\n)+$" ""
           PROCPS_VERSION_STRING "${PROCPS_VERSION_STRING}")
  endif()

  if(PROCPS_VERSION_STRING)
    verbose_message("I: version string of ${_log_libname} found: "
                    "${PROCPS_VERSION_STRING}" )
  else()
    set(_err "Version string of ${_log_libname} not found.")
    if(PROCPS_REQUIRE_NG)
      set(_err ${_err} " The found library may be legacy procps but"
                       " procps-ng is required.")
    endif()
    fail(${_err})
  endif()

  ## store result

  if(PROCPS_VERSION_STRING AND PROCPS_LIBRARY)
    set(_found_lib ON)
  endif()
  if(PROCPS_INCLUDE_DIR)
    set(_found_headers ON)
  endif()

  set(PROCPS_LIBRARIES ${PROCPS_LIBRARY} )
  set(PROCPS_INCLUDE_DIRS ${PROCPS_INCLUDE_DIR} )

  mark_as_advanced(PROCPS_INCLUDE_DIR PROCPS_LIBRARY PROCPS_VERSION_STRING)

  ## setup for test compilations (CHECK_SYMBOL_EXISTS)

  if(PROCPS_REQUIRE_SYMBOLS)
    set(CMAKE_REQUIRED_INCLUDES ${PROCPS_INCLUDE_DIRS})
    set(CMAKE_REQUIRED_LIBRARIES ${PROCPS_LIBRARIES})
  endif()

endif(PROCPS_STATIC)

# -----------------------------------------------------------------------------
#  End finding procps library and headers
# -----------------------------------------------------------------------------



# -----------------------------------------------------------------------------
#  Begin checking for symbols and structures
# -----------------------------------------------------------------------------

## rerun checks if changes detected in include_dir or library path ##

#print_procps_variables()

# clean PROCPS_HAS_* variables if changes detected include_dir or library path
if( (NOT "${_PROCPS_SAVED_LIBRARY}"
         STREQUAL "${PROCPS_LIBRARY}") OR
    (NOT "${_PROCPS_SAVED_INCLUDE_DIR}"
         STREQUAL "${PROCPS_INCLUDE_DIR}") OR
    (NOT "${_PROCPS_SAVED_VERSION_STRING}"
         STREQUAL "${PROCPS_VERSION_STRING}") OR
    (NOT "${_PROCPS_SAVED_STATIC_LIBRARY}"
         STREQUAL "${PROCPS_STATIC_LIBRARY}") OR
    (NOT "${_PROCPS_SAVED_STATIC_INCLUDE_DIR}"
         STREQUAL "${PROCPS_STATIC_INCLUDE_DIR}") OR
    (NOT "${_PROCPS_SAVED_STATIC_VERSION_STRING}"
         STREQUAL "${PROCPS_STATIC_VERSION_STRING}") )
  verbose_message("I: cleaning list of missing symbols; tests will be run.")
  foreach(_symbol ${PROCPS_REQUIRE_SYMBOLS})
    unset(PROCPS_HAS_${_symbol} CACHE)
  endforeach()
endif()

# clean PROCPS_PROC_T_HAS_MEMBER_* variables if detected changes in include_dir
if( (NOT "${_PROCPS_SAVED_INCLUDE_DIR}"
         STREQUAL "${PROCPS_INCLUDE_DIR}") OR
    (NOT "${_PROCPS_SAVED_VERSION_STRING}"
         STREQUAL "${PROCPS_VERSION_STRING}") OR
    (NOT "${_PROCPS_SAVED_STATIC_INCLUDE_DIR}"
         STREQUAL "${PROCPS_STATIC_INCLUDE_DIR}") OR
    (NOT "${_PROCPS_SAVED_STATIC_VERSION_STRING}"
         STREQUAL "${PROCPS_STATIC_VERSION_STRING}") )
  verbose_message("I: cleaning list of missing proc_t members;"
                  " tests will be run.")
  foreach(_member ${PROCPS_REQUIRE_PROC_T_MEMBERS})
    unset(PROCPS_PROC_T_HAS_MEMBER_${_member} CACHE)
  endforeach()
endif()

# save variables so we can detect changes
set(_PROCPS_SAVED_LIBRARY "${PROCPS_LIBRARY}" CACHE INTERNAL "")
set(_PROCPS_SAVED_INCLUDE_DIR "${PROCPS_INCLUDE_DIR}" CACHE INTERNAL "")
set(_PROCPS_SAVED_VERSION_STRING "${PROCPS_VERSION_STRING}" CACHE INTERNAL "")
set(_PROCPS_SAVED_STATIC_LIBRARY "${PROCPS_STATIC_LIBRARY}" CACHE INTERNAL "")
set(_PROCPS_SAVED_STATIC_INCLUDE_DIR "${PROCPS_STATIC_INCLUDE_DIR}"
    CACHE INTERNAL "")
set(_PROCPS_SAVED_STATIC_VERSION_STRING "${PROCPS_STATIC_VERSION_STRING}"
    CACHE INTERNAL "")

# test required symbols
unset(PROCPS_MISSING_SYMBOLS)
unset(PROCPS_MISSING_REQUIRED_SYMBOLS)

if(PROCPS_CHECK_SYMBOLS)
  verbose_message("I: checking libprocps for missing symbols.")
  foreach(_symbol ${PROCPS_CHECK_SYMBOLS})
    CHECK_SYMBOL_EXISTS("${_symbol}"
            "proc/procps.h;proc/sysinfo.h;proc/pwcache.h;proc/readproc.h"
            PROCPS_HAS_${_symbol} )
    if(NOT PROCPS_HAS_${_symbol})
      set(PROCPS_MISSING_SYMBOLS "${PROCPS_MISSING_SYMBOLS} ${_symbol}")
      foreach(_required_symbol ${PROCPS_REQUIRE_SYMBOLS})
        if(${_required_symbol} STREQUAL ${_symbol})
          set(PROCPS_MISSING_REQUIRED_SYMBOLS
              "${PROCPS_MISSING_REQUIRED_SYMBOLS} ${_symbol}" )
        endif()
      endforeach()
    endif()
  endforeach()
endif()

# test required struct proc_t memberes
unset(PROCPS_MISSING_PROC_T_MEMBERS)
unset(PROCPS_MISSING_REQUIRED_PROC_T_MEMBERS)

if(PROCPS_CHECK_PROC_T_MEMBERS)
  verbose_message("I: checking libprocps for missing members of proc_t.")
  foreach(_member ${PROCPS_CHECK_PROC_T_MEMBERS})
    CHECK_STRUCT_HAS_MEMBER("proc_t" "${_member}"
            "proc/procps.h;proc/sysinfo.h;proc/pwcache.h;proc/readproc.h"
            PROCPS_PROC_T_HAS_MEMBER_${_member} )
    if(NOT PROCPS_PROC_T_HAS_MEMBER_${_member})
      set(PROCPS_MISSING_PROC_T_MEMBERS
              "${PROCPS_MISSING_PROC_T_MEMBERS} ${_member}")
      foreach(_required_member ${PROCPS_REQUIRE_PROC_T_MEMBERS})
        if(${_required_member} STREQUAL ${_member})
          set(PROCPS_MISSING_REQUIRED_PROC_T_MEMBERS
              "${PROCPS_MISSING_REQUIRED_PROC_T_MEMBERS} ${_member}" )
        endif()
      endforeach()
    endif()
  endforeach()
endif()

# Output missing symbols and structures.
# Send error and help message if required symbols and structures not found.

if(PROCPS_MISSING_PROC_T_MEMBERS OR PROCPS_MISSING_SYMBOLS)
  if(PROCPS_MISSING_PROC_T_MEMBERS)
    message(WARNING "libprocps struct proc_t missing members: "
            "${PROCPS_MISSING_PROC_T_MEMBERS}" )
  endif()
  if(PROCPS_MISSING_SYMBOLS)
    message(WARNING "libprocps missing symbols: ${PROCPS_MISSING_SYMBOLS}")
  endif()
endif()

if(PROCPS_MISSING_REQUIRED_PROC_T_MEMBERS OR PROCPS_MISSING_REQUIRED_SYMBOLS)
  if(PROCPS_MISSING_REQUIRED_PROC_T_MEMBERS)
    message(WARNING "libprocps struct proc_t MISSING REQUIRED MEMBERS: "
            "${PROCPS_MISSING_REQUIRED_PROC_T_MEMBERS}" )
  endif()
  if(PROCPS_MISSING_REQUIRED_SYMBOLS)
    message(WARNING "libprocps MISSING REQUIRED SYMBOLS: "
            "${PROCPS_MISSING_REQUIRED_SYMBOLS}" )
  endif()
  if(NOT PROCPS_STATIC)
    fail("Required symbols missing in libprocps.")
  else()
    fail("Required symbols missing in libprocps.\n"
         "Update libprocps to version that contains all required symbols.")
  endif()
endif()

# -----------------------------------------------------------------------------
#  End checking for symbols and structures
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
#  Return results
# -----------------------------------------------------------------------------

if(PROCPS_STATIC)
  find_package_handle_standard_args(Procps
                                    REQUIRED_VARS PROCPS_STATIC_LIBRARY
                                                  PROCPS_STATIC_INCLUDE_DIR
                                                  PROCPS_STATIC_VERSION_STRING
                                    VERSION_VAR PROCPS_STATIC_VERSION_STRING )
else()
  find_package_handle_standard_args(Procps
                                    REQUIRED_VARS PROCPS_LIBRARY
                                                  PROCPS_INCLUDE_DIR
                                                  PROCPS_VERSION_STRING
                                    VERSION_VAR PROCPS_VERSION_STRING )
endif()
