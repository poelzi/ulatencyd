/*
    Copyright 2014 ulatencyd developers

    This file is part of ulatencyd.

    ulatencyd is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the
    Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    ulatencyd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ulatencyd. If not, see http://www.gnu.org/licenses/.
*/

/**
 *  \file uassert.h
 *  \ingroup UAssert
 */

#ifndef _U_ASSERT_H__
#define _U_ASSERT_H__

#include "config.h"
#include "ulatency.h"

//! \addtogroup UAssert
//! @{

/**
 * Prints critical warning if process exists in /proc/ directory and is not
 * a zombie
 * @param proc an #u_proc
 *
 * \note
 * If DEVELOP_MODE defined, this assertion is called everytime some process
 * is marked as dead, specifically on each U_PROC_STATE(P, UPROC_VANISHED) or
 * U_PROC_STATE(P, UPROC_ZOMBIE) macro call. Assertion failure in this case is
 * a symptom that ulatencyd core is making false assumptions about /proc/<pid>/
 * files behaviour, i.e. it falsely assumes some process disappeared or is
 * a zombie, instead it is still alive.
 *
 */
#define u_assert_process_dead(proc) u_assert_process_dead_real (proc,     \
                                                                G_STRLOC)

/*! @} End of "addtogroup UAssert" */

void  u_assert_process_dead_real (u_proc      *proc,
                                  const gchar *strloc);

#ifdef DEVELOP_MODE

#undef U_PROC_SET_STATE
#define U_PROC_SET_STATE(P,STATE) \
  do { \
    if (STATE == UPROC_VANISHED || STATE == UPROC_ZOMBIE) \
      u_assert_process_dead (P); \
    ( P ->ustate = ( P ->ustate | STATE )); \
  } while (0)

#else
define u_assert_process_dead(proc)
#endif /* DEVELOP_MODE */


#endif /* _U_ASSERT_H__ */
