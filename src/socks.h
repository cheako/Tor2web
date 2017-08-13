/*
 * socks.h -- API for SOCKS4/5 protocol.
 *
 * Copyright (c) 2000-2006, 2012 Shun-ichi Goto
 * Copyright (c) 2002, J. Grant (English Corrections)
 * Copyright (c) 2017, Mike Mestnik <cheako+Atlassian_Cloud@mikemestnik.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *  Created on: Sep 1, 2017
 */

#ifndef SOCKS_H_
#define SOCKS_H_

#include <sys/types.h>
#include <stdbool.h>

#ifdef __CYGWIN32__
#undef _WIN32
#endif

#ifdef _WIN32
#include <windows.h>
#include <winsock.h>
#include <iphlpapi.h>
#include <sys/stat.h>
#include <io.h>
#include <conio.h>
#else /* !_WIN32 */
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !_WIN32 */

struct socksapi;
typedef struct socksapi *socksapi_h;

/* socket related definitions */
#ifndef _WIN32
#define SOCKET int
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifdef _WIN32
#define socket_errno() WSAGetLastError()
#else /* !_WIN32 */
#define closesocket close
#define socket_errno() (errno)
#endif /* !_WIN32 */

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif /* WIN32 */

socksapi_h new_socksapi();

void free_socksapi( socksapi_h );

typedef void(*atomic_out_f)(void *, const void *, size_t, bool);

void set_socksapi_atomic_out(socksapi_h h, atomic_out_f);

void set_socksapi_debug( socksapi_h, bool );

void set_socksapi_noerror( socksapi_h, bool );

void set_socksapi_closure( socksapi_h, void * );

bool get_socksapi_debug( socksapi_h );

bool get_socksapi_noerror( socksapi_h );

void *get_socksapi_closure( socksapi_h );

size_t get_socksapi_can_read( socksapi_h );

int socksapi_atomic_in( socksapi_h, const char*, size_t );

int
begin_socks4_relay( socksapi_h, const char*, const char*, const struct sockaddr_in*, const char*, u_short );

#endif /* SOCKS_H_ */
