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

#ifndef __TOR2WEB_HTTP_H
#define __TOR2WEB_HTTP_H

/**
 * @file http.h
 * @brief http client interface
 * @author Mike Mestnik
 */

#include "gnutls.h"
#include "sendbuf.h"

#include <stdbool.h>
#include <regex.h>

typedef struct
{
  long int handle; // Some of this is not known, use this handle.
  tlssession_h tls;
  bool http_subversion;
  char *hostname;
  sendbuf_h retrybuf;
} http_request_t;

extern regex_t regex_onion;
void
http_init ();

typedef struct http *http_h;
http_h
http_new (const char*, size_t, http_request_t, const void*, size_t);
void
http_detach (http_h, bool, size_t);
void
http_write (http_h, const void*, size_t);
void
http_request_update (http_h, http_request_t);

#endif
