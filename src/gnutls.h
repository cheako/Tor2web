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

#ifndef __TOR2WEB_GNUTLS_H
#define __TOR2WEB_GNUTLS_H

/**
 * @file gnutls.h
 * @brief Encryption
 * @author Mike Mestnik
 */

#include <stdbool.h>

#include "sendbuf.h"

typedef struct tlssession *tlssession_h;
typedef struct response *response_h;

typedef struct response
{
  response_h next;
  tlssession_h tls;
  bool eof;
  sendbuf_h sendbuf;
} response_t;

#include "sockets.h"

#include <sys/socket.h>

void
_gnutls_init ();
void
tlssession_start (fd_closure_h, struct sockaddr*, socklen_t);
void
gnutls_close (tlssession_h);
void
gnutls_close_on_fin (tlssession_h);
void
response_attach (response_h);
void
response_send (response_h, const void*, size_t);

#endif
