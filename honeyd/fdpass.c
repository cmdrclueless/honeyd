/*
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <err.h>
#include <string.h>

#include "fdpass.h"

int
send_fd(int socket, int fd, void *base, size_t len)
{
#if defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	char ch = '\0';
	ssize_t n;
	int *pfd;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	pfd = (int *)CMSG_DATA(cmsg);
	*pfd = fd;
#endif

	if (base == NULL) {
		vec.iov_base = &ch;
		vec.iov_len = 1;
	} else {
		vec.iov_base = base;
		vec.iov_len = len;
	}
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	if ((n = sendmsg(socket, &msg, 0)) == -1) {
		if (errno == EAGAIN)
			return (-1);
		err(1, "%s: sendmsg(%d): %s", __func__, fd, strerror(errno));
	}
	if (n == 0)
		errx(1, "%s: sendmsg: expected sent >0 got %ld",
		    __func__, (long)n);
#else
	errx(1, "%s: subsystems not supported due to lack of fd passing",
	    __func__);
#endif

	return (0);
}

int
receive_fd(int socket, void *base, size_t *len)
{
#if defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	ssize_t n;
	char ch;
	int fd;
        int *pfd;

#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
	if (base == NULL) {
		vec.iov_base = &ch;
		vec.iov_len = 1;
	} else {
		vec.iov_base = base;
		vec.iov_len = *len;
	}
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = tmp;
	msg.msg_controllen = sizeof(tmp);
#endif

	while ((n = recvmsg(socket, &msg, 0)) == -1) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return (-1);
		err(1, "%s: recvmsg: %s", __func__, strerror(errno));
	}
	if (n == 0)
		errx(1, "%s: recvmsg: expected received >0 got %ld",
		    __func__, (long)n);
	if (len != 0)
		*len = n;

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	if (msg.msg_accrightslen != sizeof(fd))
		errx(1, "%s: no fd", __func__);
#else
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg->cmsg_type != SCM_RIGHTS)
		errx(1, "%s: expected type %d got %d", __func__,
		    SCM_RIGHTS, cmsg->cmsg_type);
	pfd = (int *)CMSG_DATA(cmsg);
	fd = *pfd;
#endif
	return fd;
#else
	errx(1, "%s: subsystems not supported due to lack of fd passing",
	    __func__);
#endif
}
