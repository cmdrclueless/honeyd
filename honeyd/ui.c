/*
 * Copyright (c) 2001, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

#include "config.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <dnet.h>

#include "ui.h"
#include "parser.h"
#ifdef HAVE_PYTHON
#include "pyextend.h"
#endif

extern struct event_base *honeyd_base_ev; /* allocated in honeyd.c */

static char *ui_file = UI_FIFO;

#define PROMPT		"honeydctl> "
#define WHITESPACE	" \t"

char *strnsep(char **, char *);

static int ui_command_help(struct evbuffer *, char *);
static int ui_command_python(struct evbuffer *, char *);

struct command {
	char *cmd;
	char *short_help;
	char *long_help;
	int (*func)(struct evbuffer *, char *);
};

struct command commands[] = {
	{
		"help",
		"help\t\t outputs a command help\n",
		"help [command]\n",
		ui_command_help
	},
	{
		"!",
		"!\t\t runs a Python command in the Honeyd environment\n",
		"! <command >",
		ui_command_python
	},
	{
		"delete",
		"delete\t\t removes configured templates and ports\n",
		"delete <template|template proto port number>\n",
	},
	{
		"list",
		"list\t\t lists configured templates or subsystems\n",
		"list <template [pattern]|subsystem [pattern]>\n",
	},
	{
		NULL, NULL, NULL, NULL
	}
};

static struct event *ev_accept;

static char *
make_prompt(void)
{
	static char tmp[128];
	extern int honeyd_nconnects;
	extern int honeyd_nchildren;

	snprintf(tmp, sizeof(tmp), "%dC %dP %s",
	    honeyd_nconnects, honeyd_nchildren,
	    PROMPT);

	return (tmp);
}

static int
ui_write_prompt(struct uiclient *client)
{
	char *tmp = make_prompt();

	evbuffer_add(client->outbuf, (void *)tmp, strlen(tmp));
	event_add(client->ev_write, NULL);

	return (0);
}

static void
ui_dead(struct uiclient *client)
{
	syslog(LOG_NOTICE, "%s: ui on fd %d is gone", __func__, client->fd);

	event_del(client->ev_read);
	event_del(client->ev_write);

	close(client->fd);
	evbuffer_free(client->inbuf);
	evbuffer_free(client->outbuf);
	free(client);
}

static int
ui_command_python(struct evbuffer *buf, char *line)
{
#ifndef HAVE_PYTHON
	const char *error_python = 
	    "Error: Honeyd has been compiled without Python support.\n";
	evbuffer_add(buf, error_python, strlen(error_python));
#else
	pyextend_run(buf, line);
#endif
	return (0);
}

static int
ui_command_help(struct evbuffer *buf, char *line)
{
	char output[1024];
	struct command *cmd;
	char *command;

	command = strnsep(&line, WHITESPACE);
	if (command != NULL && strlen(command)) {
		for (cmd = commands; cmd->cmd; cmd++) {
			/* Find out what command was sent.  */
			if (strcasecmp(cmd->cmd, command) == 0)
				break;
		}
		if (cmd->cmd == NULL) {
			snprintf(output, sizeof(output),
			    "Error: unknown command \"%s\"\n", command);
			evbuffer_add(buf, output, strlen(output));
			return (0);
		}
		evbuffer_add(buf, cmd->long_help, strlen(cmd->long_help));
	
	} else {
		for (cmd = commands; cmd->cmd; cmd++)
			evbuffer_add(buf,
			    cmd->short_help, strlen(cmd->short_help));
	}

	return (0);
}

static void
ui_handle_command(struct evbuffer *buf, char *original)
{
	char output[1024];
	char *command, *line = original;
	struct command *cmd;

	command = strnsep(&line, WHITESPACE);
	if (!strlen(command))
		return;

	for (cmd = commands; cmd->cmd; cmd++) {
		/* Find out what command was sent.  */
		if (strcasecmp(cmd->cmd, command) == 0)
			break;
	}
	
	if (cmd->func == NULL) {
		/* Restore the original line and send it to the parser */
		if (line != NULL)
			original[strlen(command)] = ' ';
		parse_line(buf, original);
		return;
	}

	if ((*cmd->func)(buf, line) == -1) {
		snprintf(output, sizeof(output), "%s%s",
			 "ui_handle_command: missing arguments\n",
			 cmd->short_help);
		evbuffer_add(buf, output, strlen(output));
	}

	return;
}

static void
ui_writer(evutil_socket_t fd, short what, void *arg)
{
	struct uiclient *client = arg;

	int n = evbuffer_write_atmost(client->outbuf, fd, -1);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN)
			goto schedule;
		ui_dead(client);
		return;
	} else if (n == 0) {
		ui_dead(client);
		return;
	}

 schedule:
 	if (evbuffer_get_length(client->outbuf))
		event_add(client->ev_write, NULL);
}

static void
ui_handler(evutil_socket_t fd, short what, void *arg)
{
	struct uiclient *client = arg;

	if (evbuffer_read(client->inbuf, fd, -1) <= 0) {
		ui_dead(client);
		return;
	}

	for (;;) {
		size_t eol_len;
		struct evbuffer_ptr line = evbuffer_search_eol(client->inbuf, NULL, &eol_len, EVBUFFER_EOL_LF);
		if (line.pos == -1)
			break;

		char *p = (char *)malloc(line.pos + 1);
		if (p != NULL) {
			evbuffer_remove(client->inbuf, (void *)p, line.pos);
			p[line.pos] = '\0'; /* ensure termination */

			evbuffer_drain(client->inbuf, eol_len);

			ui_handle_command(client->outbuf, p);
			free(p);
		}
	}

	ui_write_prompt(client);

	event_add(client->ev_read, NULL);
}

static void
ui_greeting(struct uiclient *client)
{
	struct timeval tv;
	extern struct timeval honeyd_uptime;

	gettimeofday(&tv, NULL);
	timersub(&tv, &honeyd_uptime, &tv);
	evbuffer_add_printf(client->outbuf,
	    "Honeyd %s Management Console\n"
	    "Copyright (c) 2004 Niels Provos.  All rights reserved.\n"
	    "See LICENSE for licensing information.\n"
	    "Up for %ld seconds.\n",
	    VERSION, tv.tv_sec);
}

static void
ui_new(evutil_socket_t fd, short what, void *arg)
{
	int newfd;
	struct uiclient *client;

	if ((newfd = accept(fd, NULL, NULL)) == -1) {
		warn("%s: accept");
		return;
	}

	if ((client = calloc(1, sizeof(struct uiclient))) == NULL) {
		warn("%s: calloc", __func__);
		close(newfd);
		return;
	}

	client->fd = newfd;
	client->inbuf = evbuffer_new();
	client->outbuf = evbuffer_new();

	if (client->inbuf == NULL || client->outbuf == NULL)
		err(1, "%s: evbuffer_new");

	syslog(LOG_NOTICE, "%s: New ui connection on fd %d", __func__, newfd);

	client->ev_read = event_new(honeyd_base_ev, newfd, EV_READ, ui_handler, client);
	event_priority_set(client->ev_read, 0);
	event_add(client->ev_read, NULL);

	client->ev_write = event_new(honeyd_base_ev, newfd, EV_WRITE, ui_writer, client);
	event_priority_set(client->ev_write, 0);
	/* event_add(client->ev_write, NULL); -- is this missing? */

	ui_greeting(client);
	ui_write_prompt(client);
}

void
ui_init(void)
{
        struct stat st;
        struct sockaddr_un ifsun;
	int ui_socket;

        /* Don't overwrite a file */
        if (lstat(ui_file, &st) == 0) {
                if ((st.st_mode & S_IFMT) == S_IFREG) {
                        errno = EEXIST;
                        err(1, "%s: could not create FIFO: %s",
			    __func__, ui_file);
                }
	}

        /* No need to know about errors.  */
        unlink(ui_file);

        ui_socket = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ui_socket == -1)
                err(1, "%s: socket", __func__);
        if (setsockopt(ui_socket, SOL_SOCKET, SO_REUSEADDR,
                       &ui_socket, sizeof (ui_socket)) == -1)
                err(1, "%s: setsockopt", __func__);

        memset(&ifsun, 0, sizeof (ifsun));
        ifsun.sun_family = AF_UNIX;
        strlcpy(ifsun.sun_path, ui_file, sizeof(ifsun.sun_path));
#ifdef HAVE_SUN_LEN
        ifsun.sun_len = strlen(ifsun.sun_path);
#endif /* HAVE_SUN_LEN */
        if (bind(ui_socket, (struct sockaddr *)&ifsun, sizeof (ifsun)) == -1)
                err(1, "%s: bind", __func__);

        if (listen(ui_socket, 5) == -1)
                err(1, "%s: listen, __func__");

	ev_accept = event_new(honeyd_base_ev, ui_socket, EV_READ|EV_PERSIST, ui_new, NULL);
	event_priority_set(ev_accept, 0);
	event_add(ev_accept, NULL);
}
