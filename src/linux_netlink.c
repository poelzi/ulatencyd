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

static GMainContext *nl_context;
static GThread *nl_thread;

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

	/* Return codes */
	int ret = 0;


	/* Get the event data.  We only care about two event types. */
	ev = (struct proc_event*)cn_hdr->data;
	switch (ev->what) {
	// quite seldom events on old processes changing important parameters
	case PROC_EVENT_UID:
		u_trace("UID Event: PID = %d, tGID = %d, rUID = %d,"
				" eUID = %d", ev->event_data.id.process_pid,
				ev->event_data.id.process_tgid,
				ev->event_data.id.r.ruid,
				ev->event_data.id.e.euid);
		//process_update_pid(ev->event_data.id.process_pid);
		process_new_delay(ev->event_data.id.process_pid, 0);
		break;
	case PROC_EVENT_GID:
		u_trace("GID Event: PID = %d, tGID = %d, rGID = %d,"
				" eGID = %d", ev->event_data.id.process_pid,
				ev->event_data.id.process_tgid,
				ev->event_data.id.r.rgid,
				ev->event_data.id.e.egid);
		//process_update_pid(ev->event_data.id.process_pid);
		process_new_delay(ev->event_data.id.process_pid, 0);
		break;
	case PROC_EVENT_EXIT:
		u_trace("EXIT Event: PID = %d", ev->event_data.exit.process_pid);
		//g_ptr_array_foreach(stack, remove_pid_from_stack, &pid);
		// if the pid was found in the new stack, pid is set to 0 to indicate
		// the removal
		process_remove_by_pid(ev->event_data.exit.process_pid);
		break;
	case PROC_EVENT_EXEC:
		u_trace("EXEC Event: PID = %d, tGID = %d",
				ev->event_data.exec.process_pid,
				ev->event_data.exec.process_tgid);
		process_new_delay(ev->event_data.exec.process_tgid, 0);
		break;
	case PROC_EVENT_FORK:
		u_trace("FORK Event: PARENT = %d PID = %d tGID = %d",
			ev->event_data.fork.parent_tgid, ev->event_data.fork.child_pid, ev->event_data.fork.child_tgid);

		// we skip new threads for now
		// FIXME need filter block to get those events
		if(ev->event_data.fork.parent_tgid != ev->event_data.fork.child_pid)
			break;
		// parent does not mean the parent of the new proc, but the parent of
		// the forking process. so we lookup the parent of the forking process
		// first

		u_proc *rparent = proc_by_pid(ev->event_data.fork.parent_tgid);
		if(rparent) {
			u_proc_ensure(rparent, BASIC, FALSE);
			process_new_delay(ev->event_data.fork.child_tgid, rparent->proc.ppid); //ev->event_data.fork.parent_pid);
		} else
			process_new_delay(ev->event_data.fork.child_tgid, 0);
		break;
	default:
		return 0;
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


static gpointer nl_thread_run(gpointer data) {
	while(TRUE){
		g_main_context_iteration(nl_context, TRUE);
		printf("nl iter\n");
	}
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
		g_warning("realtime monitoring disabled. compile kernel with PROC_EVENTS enabled");
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

	nl_context = g_main_context_new();

	/* socket has data */
	source = g_socket_create_source (gsocket, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, NULL);
	g_source_set_callback (source, (GSourceFunc) nl_connection_handler, loop, NULL);
	g_source_attach (source, nl_context);
	nl_thread = g_thread_create(nl_thread_run, NULL, FALSE, &error);
	if(error) {
		g_warning("can't create nl thread\n");
		goto out;
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