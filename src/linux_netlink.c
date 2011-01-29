/* -*- Mode: C; tab-width: 4; indent-tabs-mode: s; c-basic-offset: 4 -*-
 *
 * Copyright (C) 2010 Richard Hughes <richard@hughsie.com>
 *
 * Licensed under the GNU Lesser General Public License Version 2.1
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <glib.h>
#include <gio/gio.h>
//#include <gio/gsocket.h>
//#include <gio/gunixsocketaddress.h>
//#include <linux/netlink.h>
#include <errno.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <string.h>
#include <stdlib.h>
#include "ulatency.h"
#include <sys/types.h>
#include <unistd.h>


#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
	sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
	sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define BUFF_SIZE (MAX(MAX(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (MIN(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))


enum WHAT {
	WHAT_NEW,
	WHAT_DEL
};

struct new_proc {
	struct timespec when;
	pid_t  pid;
	enum WHAT what;
};
static long int delay;
static long int del_delay;

static GPtrArray *stack;

/* remove the pid from the stack if it is scheduled for run.
   if the process is found and removed the user_data pointer, which
   is the pid will be set to 0 to mark it as removed
*/
static void remove_pid_from_stack(gpointer data, gpointer user_data) {
	struct new_proc *cur = data;
	int rv;
	int *pid = (int *)user_data;
	if (cur->pid == *pid) {
		rv = g_ptr_array_remove_fast(stack, data);
		*pid = 0;
	}
}

// calculated the difference between two timespec values
static struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}


// order with oldest first
static gint order_new_stack(gconstpointer a, gconstpointer b) {
	const struct new_proc *na = a;
	const struct new_proc *nb = b;
	int rv = na->when.tv_sec - nb->when.tv_sec;
	if(rv) return rv;
	return na->when.tv_nsec - nb->when.tv_nsec;
}

/* 
 *	timeout function that is called periodicy to run the todo stack
 */
static int run_new_pid(gpointer ign) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	struct new_proc *cur;
	struct timespec td;
	int i;
	char path[32];

	GArray *targets = NULL;
	
	if(!stack->len)
		return TRUE;
	
	targets = g_array_new(TRUE, TRUE, sizeof(pid_t));
	
	// we have to sort the stack first. the oldest pids to the top so they get 
	// updated in the correct order and the parents of maybe new clients scheduled
	// for addition are added first
	g_ptr_array_sort(stack, order_new_stack);

	/*
	printf("list: ");
	for(i = 0; i < stack->len; i++) {
		cur = g_ptr_array_index(stack, i);
		printf("%d %d ", cur->pid, cur->what);
	}
	*/

	//printf("\nrun_new_pid: ");

	// add new processes first
	for(i = 0; i < stack->len;) {
		cur = g_ptr_array_index(stack, i);
		if(cur->what != WHAT_NEW) {
			i++;
			continue;
		}
		td = diff(cur->when, now);
		//printf("%d ", cur->pid);
		if((td.tv_sec * 1000000000 + td.tv_nsec) >= delay) {
			//process_new(cur->pid);
			g_array_append_val(targets, cur->pid);
			g_ptr_array_remove(stack, cur);
		} else {
			i++;
		}
	}
	if(targets->len)
		process_new_list(targets, FALSE);
	//printf("\nremove list:");
	// now we can remove pending remove events
	for(i = 0; i < stack->len;) {
		cur = g_ptr_array_index(stack, i);
		if(cur->what != WHAT_DEL) {
			i++;
			continue;
		}
		td = diff(cur->when, now);
		//printf("%d ", cur->pid);
		if((td.tv_sec * 1000000000 + td.tv_nsec) >= del_delay) {
			//process_new(cur->pid);
			snprintf(path, sizeof path, "/proc/%u", cur->pid);

			if(access((const char *)&path, F_OK)) {
				//process_remove_by_pid(cur->pid);
				g_ptr_array_remove(stack, cur);
			}
		} else {
			i++;
		}
	}
	
	//printf("\n");

	g_array_unref(targets);
	return TRUE;
}


/**
 * Handle a netlink message.  In the event of PROC_EVENT_UID or PROC_EVENT_GID,
 * we put the new events on the new event stack for processing when they exist a
 * given time
 * other events are ignored.
 * 	@param cn_hdr The netlink message
 * 	@return 0 on success, > 0 on error
 */

static int nl_handle_msg(struct cn_msg *cn_hdr)
{
	/* The event to consider */
	struct proc_event *ev;
	struct new_proc *np;

	/* Return codes */
	int ret = 0;
	int i;
	int what;
	pid_t pid = 0;

	/* Get the event data.  We only care about two event types. */
	ev = (struct proc_event*)cn_hdr->data;
	switch (ev->what) {
	// quite seldom events on old processes changing important parameters
	case PROC_EVENT_UID:
		g_trace("UID Event: PID = %d, tGID = %d, rUID = %d,"
				" eUID = %d", ev->event_data.id.process_pid,
				ev->event_data.id.process_tgid,
				ev->event_data.id.r.ruid,
				ev->event_data.id.e.euid);
		//process_update_pid(ev->event_data.id.process_pid);
		process_new(ev->event_data.id.process_pid, FALSE);
		break;
	case PROC_EVENT_GID:
		g_trace("GID Event: PID = %d, tGID = %d, rGID = %d,"
				" eGID = %d", ev->event_data.id.process_pid,
				ev->event_data.id.process_tgid,
				ev->event_data.id.r.rgid,
				ev->event_data.id.e.egid);
		//process_update_pid(ev->event_data.id.process_pid);
		process_new(ev->event_data.id.process_pid, FALSE);
		break;
	case PROC_EVENT_EXIT:
		pid = ev->event_data.exit.process_pid;
		g_trace("EXIT Event: PID = %d",ev->event_data.exit.process_pid);
		g_ptr_array_foreach(stack, remove_pid_from_stack, &pid);
		// if the pid was found in the new stack, pid is set to 0 to indicate
		// the removal
		if(pid == 0)
			return 0;
		else
			what = WHAT_DEL;
		break;
	case PROC_EVENT_EXEC:
		g_trace("EXEC Event: PID = %d, tGID = %d",
				ev->event_data.exec.process_pid,
				ev->event_data.exec.process_tgid);
		pid = ev->event_data.exec.process_pid;
		what = WHAT_NEW;
		break;
	case PROC_EVENT_FORK:
		g_trace("FORK Event: PARENT = %d PID = %d",
			ev->event_data.fork.parent_pid, ev->event_data.fork.child_pid);
		pid = ev->event_data.fork.child_pid;
		what = WHAT_NEW;
		break;
	default:
		return 0;
	}

	// in case of new events
	if(pid) {
		if(!delay) {
			process_new(pid, TRUE);
		} else {
			for(i=0; i < stack->len; i++) {
				np = g_ptr_array_index(stack, i);
				// we can skip pids that already put into the stack
				// a fork event is often followed by a exec event which would
				// cause a duplicated entry.
				if(np->pid == pid && np->what == what)
					return 0;
			}
			np = malloc(sizeof(struct new_proc));
			np->what = what;
			np->pid = pid;
			clock_gettime(CLOCK_MONOTONIC, &(np->when));
			g_ptr_array_add(stack, np);
		}
	}

	return ret;
}


static gboolean
nl_connection_handler (GSocket *socket, GIOCondition condition, gpointer user_data)
{
	GError *error = NULL;
	gsize len;
	gboolean ret = TRUE;

	char buff[BUFF_SIZE];
	size_t recv_len;
	struct sockaddr_nl from_nla;
	socklen_t from_nla_len;
	struct nlmsghdr *nlh;
	struct sockaddr_nl kern_nla;
	struct cn_msg *cn_hdr;

	kern_nla.nl_family = AF_NETLINK;
	kern_nla.nl_groups = CN_IDX_PROC;
	kern_nla.nl_pid = 1;
	kern_nla.nl_pad = 0;

	memset(buff, 0, sizeof(buff));
	from_nla_len = sizeof(from_nla);
	memcpy(&from_nla, &kern_nla, sizeof(from_nla));

	/* the helper process exited */
	// this should not happen to netlink
	if ((condition & G_IO_HUP) > 0) {
		g_warning ("socket was disconnected");
		ret = FALSE;
		goto out;
	}

	/* there is data */
	if ((condition & G_IO_IN) > 0) {

		len = g_socket_receive (socket, buff, sizeof(buff), NULL, &error);

		if (error != NULL) {
			g_warning ("failed to get data: %s", error->message);
			g_error_free (error);
			// no reason to stop
			goto out;
		}
		if (len == ENOBUFS) {
			g_warning("NETLINK BUFFER FULL, MESSAGE DROPPED!");
			return 0;
		}
		if (len == 0)
			goto out;
		nlh = (struct nlmsghdr *)buff;
		while (NLMSG_OK(nlh, len)) {
			cn_hdr = NLMSG_DATA(nlh);
			if (nlh->nlmsg_type == NLMSG_NOOP) {
				nlh = NLMSG_NEXT(nlh, recv_len);
				continue;
			}
			if ((nlh->nlmsg_type == NLMSG_ERROR) ||
					(nlh->nlmsg_type == NLMSG_OVERRUN))
				break;
			if (nl_handle_msg(cn_hdr) < 0)
				return 1;
			if (nlh->nlmsg_type == NLMSG_DONE)
				break;
			nlh = NLMSG_NEXT(nlh, recv_len);
		}
	}
out:
	return ret;
}


int init_netlink(GMainLoop *loop) {
	GSocket *gsocket = NULL;
	int socket_fd = 0;
	GError *error = NULL;
	GSource *source;
	struct sockaddr_nl my_nla;
	struct nlmsghdr *nl_hdr;
	char buff[BUFF_SIZE];
	struct cn_msg *cn_hdr;
	enum proc_cn_mcast_op *mcop_msg;


	// the stack holds new pids scheduled for run
	stack = g_ptr_array_new_with_free_func(free);

	delay = g_key_file_get_integer(config_data, CONFIG_CORE, "delay_new_pid", NULL);

	g_type_init ();

	/* create socket */
	/*
	 * Create an endpoint for communication. Use the kernel user
	 * interface device (PF_NETLINK) which is a datagram oriented
	 * service (SOCK_DGRAM). The protocol used is the connector
	 * protocol (NETLINK_CONNECTOR)
	 */
	socket_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

	if (socket == NULL) {
		g_warning ("failed to create socket: %s", error->message);
		g_error_free (error);
		return 1;
	}

	my_nla.nl_family = AF_NETLINK;
	my_nla.nl_groups = CN_IDX_PROC;
	my_nla.nl_pid = getpid();
	my_nla.nl_pad = 0;

	if (bind(socket_fd, (struct sockaddr *)&my_nla, sizeof(my_nla)) < 0) {
		g_warning("binding sk_nl error: %s\n", strerror(errno));
		goto out;
	}

	gsocket = g_socket_new_from_fd(socket_fd, NULL);
	if(gsocket == NULL) {
		g_warning("can't create socket");	
		goto out;
	}

	nl_hdr = (struct nlmsghdr *)buff;
	cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
	mcop_msg = (enum proc_cn_mcast_op*)&cn_hdr->data[0];
	g_debug("sending proc connector: PROC_CN_MCAST_LISTEN... ");
	memset(buff, 0, sizeof(buff));
	*mcop_msg = PROC_CN_MCAST_LISTEN;

	/* fill the netlink header */
	nl_hdr->nlmsg_len = SEND_MESSAGE_LEN;
	nl_hdr->nlmsg_type = NLMSG_DONE;
	nl_hdr->nlmsg_flags = 0;
	nl_hdr->nlmsg_seq = 0;
	nl_hdr->nlmsg_pid = getpid();

	/* fill the connector header */
	cn_hdr->id.idx = CN_IDX_PROC;
	cn_hdr->id.val = CN_VAL_PROC;
	cn_hdr->seq = 0;
	cn_hdr->ack = 0;
	cn_hdr->len = sizeof(enum proc_cn_mcast_op);
	g_debug("sending netlink message len=%d, cn_msg len=%d\n",
		nl_hdr->nlmsg_len, (int) sizeof(struct cn_msg));
	if (send(socket_fd, nl_hdr, nl_hdr->nlmsg_len, 0) != nl_hdr->nlmsg_len) {
		g_warning("failed to send proc connector mcast ctl op!: %s\n",
			strerror(errno));
	}
	g_debug("sent\n");

	/* socket has data */
	source = g_socket_create_source (gsocket, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, NULL);
	g_source_set_callback (source, (GSourceFunc) nl_connection_handler, loop, NULL);
	g_source_attach (source, NULL);

	// add timeout function
	if(delay) {
		g_timeout_add((int)(delay / 3), run_new_pid, NULL);
		
		// delay is stored in milli secound
		delay = delay * 1000000;
		// the del delay must be higher to prevent failures when parents
		// die quickly and init did not yet change the parent
		del_delay = MAX(delay * 10, 2000000000);
	}

	return 0;
out:
	return 1;

}

#if 0
gint
main (void)
{
	gboolean ret;
	GSocket *gsocket = NULL;
	int socket_fd = 0;
	GSocketAddress *address = NULL;
	GError *error = NULL;
	gsize wrote;
	GSource *source;
	GMainLoop *loop;
	struct sockaddr_nl my_nla;
	struct nlmsghdr *nl_hdr;
	char buff[BUFF_SIZE];
	struct cn_msg *cn_hdr;
	enum proc_cn_mcast_op *mcop_msg;

	g_type_init ();
	loop = g_main_loop_new (NULL, FALSE);

	init_netlink(loop);

	g_debug ("running main loop");
	g_main_loop_run (loop);
out:
	if (loop != NULL)
		g_main_loop_unref (loop);
	if (socket != NULL)
		g_object_unref (socket);
	if (address != NULL)
		g_object_unref (address);
	return 0;
}

#endif