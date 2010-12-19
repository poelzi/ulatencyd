#-DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"
add_definitions(-DVERSION=\"3\" -DSUBVERSION=\"2\" -DMINORVERSION=\"8\")
add_library(proc STATIC
            alloc.c  devname.c  escape.c  ksym.c  pwcache.c  readproc.c  sig.c  slab.c  smaps.c  sysinfo.c  version.c  whattime.c)
