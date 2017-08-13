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

#ifndef __TOR2WEB_HTTPSD_H
#define __TOR2WEB_HTTPSD_H

/**
 * @file httpsd.h
 * @brief List variables available everywhere
 * @author Mike Mestnik
 */

typedef struct httpsd *httpsd_h;

#include "gnutls.h"

httpsd_h
httpsd_new (tlssession_h, struct sockaddr*, socklen_t);
void
httpsd_close (httpsd_h);
void
httpsd_in (httpsd_h, const void*, size_t);

#endif
