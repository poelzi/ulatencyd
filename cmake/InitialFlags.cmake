if(__COMPILER_GNU)
  # Debug build
  set(CMAKE_C_FLAGS_DEBUG_INIT "-g3 -pg")
  # Release build
  set(CMAKE_C_FLAGS_RELEASE_INIT "-O3 -fomit-frame-pointer -flto -DNDEBUG")
  # RelWithDebInfo build
  set(CMAKE_C_FLAGS_RELWITHDEBINFO_INIT "-g -O2 -finline-functions -flto")
  # MinSizeRel build
  set(CMAKE_C_FLAGS_MINSIZEREL_INIT "-Os -flto -DNDEBUG")
else()
  message(FATAL_ERROR
          "You seem not using GCC compiler, please add compiler flags to"
          " InitialFlags.cmake")
endif()

set(CMAKE_BUILD_TYPE_INIT "Release")