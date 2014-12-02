/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/tree.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/utsname.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <syslog.h>

#include <dnet.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "update.h"

extern struct event_base *honeyd_base_ev;
char *security_update = NULL;

static int update_ev_initialized;
static struct event *update_ev;
static struct event *update_connect_ev;

int make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type, char *address, uint16_t port);
static void update_cb(evutil_socket_t, short, void *);
static void update_connect_cb(int, short, void *);
static void update_parse_information(char *data, size_t length);

void
update_check(void)
{
	static int host_resolved;
	static struct addr host_addr;
	struct timeval tv;
	int fd;

	if (!update_ev_initialized) {
		update_ev_initialized = 1;

		update_ev = evtimer_new(honeyd_base_ev, update_cb, NULL);
	}

	if (!host_resolved) {
		if (addr_pton("www.honeyd.org", &host_addr) == -1) {
			syslog(LOG_WARNING, "%s: failed to resolve host.", __func__);
			goto reschedule;
		}

		host_resolved = 1;
	}

	fd = make_socket(connect, SOCK_STREAM, addr_ntoa(&host_addr), 80);
	if (fd == -1) {
		syslog(LOG_WARNING, "%s: failed to connect: %m", __func__);
		goto reschedule;
	}

	update_connect_ev = event_new(honeyd_base_ev, fd, EV_WRITE, update_connect_cb, NULL); 
	event_add(update_connect_ev, NULL);

 reschedule:
	timerclear(&tv);
	tv.tv_sec = 24 * 60 * 60;
	evtimer_add(update_ev, &tv);
}

static void
update_parse_information(char *data, size_t length)
{
	/* No security update for us? */
	if (!length)
		return;

	if (security_update != NULL)
		free(security_update);
	if ((security_update = malloc(length) + 1) == NULL)
		err(1, "%s: malloc");
	memcpy(security_update, data, length);
	security_update[length] = '\0';

	/* Warn the user that their version is vulnerable and needs update */
	syslog(LOG_WARNING, "SECURITY INFO: %s", security_update);
}

static void
update_cb(evutil_socket_t fd, short what, void *arg)
{
	update_check();
}

static void
update_readcb(struct bufferevent *bev, void *parameter)
{
	struct evbuffer *input = bufferevent_get_input(bev);

	size_t len;
	/* 
	 * If we did not receive the complete request and we have
	 * waited for too long already, then we drop the request.
	 */
	if ((len = evbuffer_get_length(input)) > 32000) {
		syslog(LOG_NOTICE, "Dropping update reply with size %lu", len);
		bufferevent_free(bev);
		return;
	}

	/* We just need to wait now for the end of the transmission */
}

static void
update_writecb(struct bufferevent *bev, void *parameter)
{
	/* We are done writing - no wait for the response */
	bufferevent_disable(bev, EV_WRITE);
	bufferevent_enable(bev, EV_READ);
}

static void
update_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	struct evbuffer *input  = bufferevent_get_input(bev);
	struct evbuffer_ptr end = evbuffer_search(input, "\r\n\r\n", 4, NULL);

	if (!(what & BEV_EVENT_EOF) || end.pos == -1)
		goto error;

	/* now wearch for the http response code, it will be on the first line
	 * if it follows the standard HTTP protocol. If we found the input string
	 * this cannot return a -1 for end.pos!
	 */
	end = evbuffer_search_eol(input, NULL, NULL, EVBUFFER_EOL_CRLF);
	char * data = malloc(end.pos + 1);
	if (data == NULL)
		goto error;

	evbuffer_copyout(input, data, end.pos);
	data[end.pos] = '\0';
	
	char * q = data;
	strsep(&q, " ");
	if (q == NULL || *q == '\0')
		goto error;
	
	char *code = strsep(&q, " ");
	if (code == NULL || q == NULL || *q == '\0')
		goto error;
	
	if (strcmp(code, "200") != 0)
		goto error;
	
	free(data);

	end = evbuffer_search(input, "\r\n\r\n", 4, NULL);
	evbuffer_drain(input, end.pos + 4);

	size_t len = evbuffer_get_length(input);
	data = (char *)malloc(len+1);
	if (data == NULL)
		goto error;

	evbuffer_copyout(input, data, len);
	data[len] = '\0';
	update_parse_information(data, len);

	free(data);

	bufferevent_free(bev);
	return;

 error:
	syslog(LOG_WARNING, "%s: failed to get security update information", __func__);
	bufferevent_free(bev);
	return;
}

static void
update_make_request(struct bufferevent *bev)
{
	char *request =
	    "GET /check.php?version=%s&os=%s HTTP/1.0\r\n"
	    "Host: www.honeyd.org\r\n"
	    "User-Agent: %s/%s\r\n"
	    "\r\n";
	static char buf[1024];
	static char os[64];
	struct utsname name;

	/* Find the operating system */
	if (uname(&name) == -1)
		snprintf(os, sizeof(os), "unknown");
	else
		snprintf(os, sizeof(os), "%s+%s", name.sysname, name.release);

	snprintf(buf, sizeof(buf), request, VERSION, os, PACKAGE, VERSION);
	bufferevent_write(bev, buf, strlen(buf));
}

static void
update_connect_cb(evutil_socket_t fd, short what, void *arg)
{
	struct bufferevent *bev = NULL;
	int error;
	socklen_t errsz = sizeof(error);

	/* Check if the connection completed */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errsz) == -1 || error) {
		syslog(LOG_WARNING, "%s: connection failed: %m", __func__);
		close(fd);
		return;
	}

	/* We successfully connected to the host */
	bev = bufferevent_socket_new(honeyd_base_ev, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
	if (bev == NULL) {
		syslog(LOG_WARNING, "%s: bufferevent_new: %m", __func__);
		close(fd);
		return;
	}
	bufferevent_setcb(bev, update_readcb, update_writecb, update_errorcb, NULL);

	struct timeval tout = { 60, 0 };
	bufferevent_set_timeouts(bev, &tout, &tout);

	update_make_request(bev);
}
