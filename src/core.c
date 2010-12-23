#include "ulatency.h"

u_proc* u_proc_new(void) {
  u_proc *rv;
  
  rv = g_new0(u_proc, 1);
  rv->ref = 1;
  return rv;
}