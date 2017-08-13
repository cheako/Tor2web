/*  tor2web
 *  Copyright (C) 2017  Michael Mestnik <cheako+github_com@mikemestnik.net>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __TOR2WEB_SOCKETS_H
#define __TOR2WEB_SOCKETS_H

/**
 * @file sockets.h
 * @brief API for socket handling routines
 * @author Mike Mestnik
 */

typedef struct fd_closure *fd_closure_h;

#include "gnutls.h"
#include "http.h"

#include <stdbool.h>
#include <sys/socket.h>

extern int sockets_maxfd;
extern fd_set sockets_read_fdset;

typedef void
(*sockets_in_f) (void *, void *, size_t);
typedef void
(*fd_can_f) (fd_closure_h, bool);
struct fd_closure
{
  int fd;
  int instanceid;
  fd_can_f can;
  void *closure;
};
void
sockets_init ();
void
sockets_create_listener (const struct sockaddr*, socklen_t);
fd_closure_h
sockets_connect_socks ();
void
sockets_close (fd_closure_h);
void
sockets_can (int, bool);

#endif
