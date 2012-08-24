/**
 * @file netlink_fallback.c
 * The `netlink_fallback` module:
 * Monitors starting of dynamically linked executables and adds them to new delay queue.
 * Stops monitoring if linux_netlink module does this job.
 */

/*
    Copyright 2012 Petr Gajdusek <gajdusek@centrum.cz>

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

#define _GNU_SOURCE

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "netlink_fallback"
#endif

#include "ulatency.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <sys/inotify.h>

static int netlink_fallback_id;
static int netlink_fallback_debug;

/*
 * test
 * uncomment TEST_NETLINK_FALLBACK definition for standalone testing binary, compile this with:
 * ulatencyd/modules$ gcc -I../src $(pkg-config --cflags --libs glib-2.0 lua5.1) -o netlink_fallback netlink_fallback.c
 */
//#define TEST_NETLINK_FALLBACK //standolane binary test
#ifdef TEST_NETLINK_FALLBACK
#define g_debug(...) { printf(__VA_ARGS__); printf("\n"); }
#define u_trace(...) g_debug(__VA_ARGS__)
#define proc_by_pid(pid) FALSE
#define process_new_delay(pid, parent) nlf_debug("process_new_delay(%d)", pid)
#define get_plugin_id() 0
gboolean netlink_proc_listening = FALSE;
#endif


#define nlf_debug(...) \
    if(netlink_fallback_debug) g_debug(__VA_ARGS__);
#define nlf_trace(...) \
    if(netlink_fallback_debug) u_trace(__VA_ARGS__);

static int get_recent_pid() {
    gboolean    res;
    char       *contents = NULL;
    gsize       length;
    GError     *error = NULL;
    pid_t         pid = 0;

    res = g_file_get_contents ("/proc/loadavg",
                               &contents,
                               &length,
                               &error);
    if (! res) {
        nlf_debug("Couldn't read %s: %s", "/proc/loadavg", error->message);
        g_error_free (error);
        goto out;
    }
    if (sscanf(contents, "%*s %*s %*s %*s %d", &pid) < 1) {
        nlf_debug("Error parsing /proc/loadavg");
    }
out:
    g_free (contents);
    return pid;
}

/**
 * Parse `tgid` and `ppid` of process/thread with PID `pid`.
 */
static gboolean get_pids(pid_t pid, pid_t *tgid, pid_t *ppid) {
    char       *path;
    gboolean   rv = FALSE;
    FILE       *f;
    int        count;

    *tgid = 0; *ppid = 0;
    path = g_strdup_printf ("/proc/%u/status", (guint)pid);

    f = fopen(path, "r");
    if (!f)
        goto out; // process is already dead

    count = fscanf(f, "%*[^\n]\n%*[^\n]\nTgid: %d\n%*[^\n]\nPPid: %d\n", tgid, ppid);
    if (count < 2) {
        nlf_debug("Error parsing Tgid and PPid from %s, parsed %d values.", path, count);
    }
    rv = TRUE;
out:
    g_free (path);
    if (f)
       fclose(f);
    return rv;
}

static pid_t old_recent_pid = 0;

static gboolean cb_inotify(GIOChannel *ch, GIOCondition condition, gpointer data) {
    char buf[1024];
    gsize length = 0;
    GError *err = NULL;
    GIOStatus stat;
    pid_t recent_pid = 0;
    pid_t pid;
    pid_t tgid, ppid;
    gboolean ret = TRUE;

    if (netlink_proc_listening) {
        nlf_debug("netlink is working: stopping the netlink_fallback module");
        ret = FALSE;
        goto out;
    }

    stat = g_io_channel_read_chars(ch, buf, sizeof(buf), &length, &err);
    if (stat != G_IO_STATUS_NORMAL) {
        g_warning("inotify event read failed (GIOStatus = %d)", stat);
        if (err) {
            g_warning("inotify event read failed (GIOChannelError: %s)", err->message);
            g_error_free(err);
        }
        goto out;
    }

    if (length > 0) {
        if ((recent_pid = get_recent_pid()) == 0) goto out; //recent_pid get failed
        // fixme: PIDs missed if pid_max have just been overflowed, probably not fixable if we want avoid looping over
        // near all processes (as the number of total processes approaches to pid_max)
        for (pid = old_recent_pid + 1; pid <= recent_pid; pid++) {
            // we get both processes (thread leaders) and threads
            if (proc_by_pid(pid)) continue;
            // throw away threads
            if (get_pids(pid, &tgid, &ppid)) {
                if (tgid != pid) {
                    nlf_debug("New thread detected (pid=%d, tgid=%d, ppid=%d), discarding it.", pid, tgid, ppid);
                    continue;
                }
                nlf_debug("New process detected (pid=%d, tgid=%d, ppid=%d)", pid, tgid, ppid);
                process_new_delay(pid, ppid);
            }
        }
        old_recent_pid = recent_pid;
    }

out:
    return ret;
}

int netlink_fallback_init() {

    #ifndef TEST_NETLINK_FALLBACK
    netlink_fallback_debug = g_key_file_get_boolean(config_data, "netlink_fallback", "debug", NULL);
    #endif

    netlink_fallback_id = get_plugin_id();

    int fd, wd;
    GIOChannel *ch;

    old_recent_pid = get_recent_pid();

    fd=inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        g_warning("inotify instance couldn't be initialized: (%d): %s", errno, strerror(errno));
        return 1;
    }
    wd=inotify_add_watch(fd, "/etc/ld.so.cache", IN_OPEN);
    if (wd == -1) {
        g_warning("inotify watch couldn't be added: (%d): %s", errno, strerror(errno));
        close(fd);
        return 1;
    }
    nlf_debug("Watching for starting dynamically linked executables, wd is %x", wd);

    ch = g_io_channel_unix_new(fd);
    g_io_channel_set_encoding(ch, NULL, NULL);
    g_io_channel_set_buffered(ch, FALSE); // important
    g_io_channel_set_close_on_unref(ch, TRUE);
    g_io_add_watch(ch, G_IO_IN, cb_inotify, NULL);
    g_io_channel_unref(ch);

    return 0;
}



#ifdef TEST_NETLINK_FALLBACK
gint main (void)
{
    netlink_fallback_debug = TRUE;

    gboolean ret;
    GMainLoop *loop;

    loop = g_main_loop_new (NULL, FALSE);

    netlink_fallback_init();

    g_debug ("running main loop");
    g_main_loop_run (loop);

    if (loop != NULL)
        g_main_loop_unref (loop);
    return 0;
}
#endif
