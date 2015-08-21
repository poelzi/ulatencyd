#include "config.h"
#include "ulatency.h"
#include <stdio.h>
#include "fts.h"
#include <unistd.h>
#include <glib.h>


void recursive_rmdir(const char *path, int add_level) {
    FTS *fts;
    FTSENT *ftsent;
    char *const paths[] = { (char *)path, NULL };

    /*
     * This means there can't be any autofs mounts yet, so
     * this is the first time we're being run since a reboot.
     * Clean out any stuff left in /Network from the reboot.
     */
    fts = fts_open(paths, FTS_NOCHDIR|FTS_PHYSICAL,
        NULL);
    if (fts != NULL) {
      while ((ftsent = fts_read(fts)) != NULL) {
        /*
         * We only remove directories - if
         * there are files, we assume they're
         * there for a purpose.
         *
         * We remove directories after we've
         * removed their children, so we want
         * to process directories visited in
         * post-order.
         */
        if (ftsent->fts_info == FTS_DP &&
            ftsent->fts_level >= FTS_ROOTLEVEL + add_level)
          rmdir(ftsent->fts_accpath);
      }
      fts_close(fts);
    }
}


void u_timer_start(struct u_timer *t) {
    if(!t->count) {
        g_timer_continue(t->timer);
    };
    t->count++;
}

void u_timer_stop(struct u_timer *t) {
    t->count--;
    g_assert(t->count >= 0);
    if(!t->count) {
        g_timer_stop(t->timer);
    };
}

void u_timer_stop_clear(struct u_timer *t) {
    g_timer_start(t->timer);
    g_timer_stop(t->timer);
}
