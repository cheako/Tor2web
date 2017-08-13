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

#ifndef __TOR2WEB_SENDBUF_H
#define __TOR2WEB_SENDBUF_H

/**
 * @file sendbuf.h
 * @brief Buffer interface
 * @author Mike Mestnik
 */

#include <glob.h>

typedef struct sendbuf *sendbuf_h;
sendbuf_h
sendbuf_new (const void*, size_t);
void
sendbuf_append (sendbuf_h*, const void*, size_t);
typedef size_t
(*sendbuf_send_func_f) (void*, const void*, size_t);
void
sendbuf_send (void*, sendbuf_h*, sendbuf_send_func_f);
void
sendbuf_skip (sendbuf_h*, size_t);
size_t
get_sendbuf_size (sendbuf_h);
const void *
get_sendbuf_buf (sendbuf_h);
void
sendbuf_clear (sendbuf_h *h);

#endif
