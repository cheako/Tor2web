/*
 * socks.c -- Handler for SOCKS4/5 protocol.
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

#include "socks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <memory.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>

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
#include <unistd.h>
#include <pwd.h>
#include <termios.h>
#include <sys/time.h>
#ifndef __hpux
#include <sys/select.h>
#endif /* __hpux */
#include <sys/socket.h>
#include <netdb.h>
#if !defined(_WIN32) && !defined(__CYGWIN32__) && !defined(__INTERIX)
#define WITH_RESOLVER 1
#include <arpa/nameser.h>
#include <resolv.h>
#else  /* not ( not _WIN32 && not __CYGWIN32__) */
#undef WITH_RESOLVER
#endif /* not ( not _WIN32 && not __CYGWIN32__) */
#endif /* !_WIN32 */

/* Older Solaris doesn't define INADDR_NONE so we may need to */
#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

#ifdef _WIN32
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif	/* not ECONNRESET */
#endif /* _WI32 */



/* Microsoft Visual C/C++ has _snprintf() and _vsnprintf() */
#ifdef _MSC_VER
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#endif

/* consider Borland C */
#ifdef __BORLANDC__
#define _kbhit kbhit
#define _setmode setmode
#endif

/* Utility types, pair holder of number and string */
typedef struct {
    int num;
    const char *str;
} LOOKUP_ITEM;

/* informations for SOCKS */
#define SOCKS4_REP_SUCCEEDED    90      /* rquest granted (succeeded) */
#define SOCKS4_REP_REJECTED     91      /* request rejected or failed */
#define SOCKS4_REP_IDENT_FAIL   92      /* cannot connect identd */
#define SOCKS4_REP_USERID       93      /* user id not matched */

extern LOOKUP_ITEM socks4_rep_names[];

/* packet operation macro */
#define PUT_BYTE(ptr,data) (*(unsigned char *)(ptr) = (unsigned char)(data))

LOOKUP_ITEM socks4_rep_names[] = {
    { SOCKS4_REP_SUCCEEDED,  "request granted (succeeded)"},
    { SOCKS4_REP_REJECTED,   "request rejected or failed"},
    { SOCKS4_REP_IDENT_FAIL, "cannot connect identd"},
    { SOCKS4_REP_USERID,     "user id not matched"},
    { -1, NULL }
};

typedef int (*atomic_in_f)(socksapi_h, const void *);
typedef struct socksapi {
  bool f_debug;
  bool f_noerror;
  atomic_out_f atomic_out;
  void *closure;
  size_t can_read;
  atomic_in_f atomic_in;
  char *relay_user;
  char *relay_host;
  struct sockaddr_in dest_addr;
  char *dest_host;
  u_short dest_port;
} socksapi_t;

socksapi_h new_socksapi() {
  socksapi_h h = NULL;
  h = malloc(sizeof(socksapi_t));
  if(h == NULL) return NULL;
  h->f_debug = false;
  h->f_noerror = false;
  h->atomic_out = NULL;
  h->closure = NULL;
  h->can_read = 0;
  h->atomic_in = NULL;
  h->relay_user = NULL;
  h->relay_host = NULL;
  h->dest_host = NULL;
  h->dest_port = 0;
  return h;
}

void free_socksapi( socksapi_h h ) {
  if(NULL != h->relay_user) free(h->relay_user);
  if(NULL != h->relay_host) free(h->relay_host);
  if(NULL != h->dest_host) free(h->dest_host);
  free(h);
}

void set_socksapi_atomic_out(socksapi_h h, atomic_out_f f) {
  h->atomic_out = f;
}

void set_socksapi_debug( socksapi_h h, bool b ) {
  h->f_debug = b;
}

void set_socksapi_noerror( socksapi_h h, bool b ) {
  h->f_noerror = b;
}

void set_socksapi_closure( socksapi_h h, void *p ) {
  h->closure = p;
}

bool get_socksapi_debug( socksapi_h h ) {
  return h->f_debug;
}

bool get_socksapi_noerror( socksapi_h h ) {
  return h->f_noerror;
}

void *get_socksapi_closure( socksapi_h h ) {
  return h->closure;
}

size_t get_socksapi_can_read( socksapi_h h ) {
  return h->can_read;
}

static void
debug( socksapi_h h, const char *fmt, ... )                  /* without prefix */
{
    if(!h->f_debug) return;
    va_list args;
    va_start( args, fmt );
    fprintf(stderr, "DEBUG: ");
    vfprintf( stderr, fmt, args );
    va_end( args );
}

/* error message output */
static void
error( socksapi_h h, const char *fmt, ... )
{
    if(h->f_noerror) return;
    va_list args;
    va_start( args, fmt );
    fprintf(stderr, "ERROR: ");
    vfprintf( stderr, fmt, args );
    va_end( args );
}

int
socksapi_atomic_in (socksapi_h h, const char *buf, size_t size)
{

  if (NULL == buf)
    return -2;

  if (h->can_read != size)
    return -3;

  if (h->atomic_in == NULL)
    return -4;

  return h->atomic_in (h, buf);
}

static const char *
lookup(int num, LOOKUP_ITEM *items)
{
    int i = 0;
    while (0 <= items[i].num) {
        if (items[i].num == num)
            return items[i].str;
        i++;
    }
    return "(unknown)";
}

static int process_begin_socks4_relay(socksapi_h h, const void *p) {
    const char *buf = p;
    if ( (buf[1] != SOCKS4_REP_SUCCEEDED) ) {   /* check reply code */
        error(h, "Got error response: %d: '%s'.\n",
              buf[1], lookup(buf[1], socks4_rep_names));
        return -1;                              /* failed */
    }

    h->can_read = 0;
    h->atomic_in = NULL;

    /* Conguraturation, connected via SOCKS4 server! */
    return 0;
}

/* begin SOCKS protocol 4 relaying
   And no authentication is supported.

   There's SOCKS protocol version 4 and 4a. Protocol version
   4a has capability to resolve hostname by SOCKS server, so
   we don't need resolving IP address of destination host on
   local machine.

   Environment variable SOCKS_RESOLVE directs how to resolve
   IP addess. There's 3 keywords allowed; "local", "remote"
   and "both" (case insensitive). Keyword "local" means taht
   target host name is resolved by localhost resolver
   (usualy with gethostbyname()), "remote" means by remote
   SOCKS server, "both" means to try resolving by localhost
   then remote.

   SOCKS4 protocol and authentication of SOCKS5 protocol
   requires user name on connect request.
   User name is determined by following method.

   1. If server spec has user@hostname:port format then
      user part is used for this SOCKS server.

   2. Get user name from environment variable LOGNAME, USER
      (in this order).

*/
int
begin_socks4_relay( socksapi_h h, const char *relay_user, const char *relay_host, const struct sockaddr_in *dest_addr, const char *dest_host, u_short dest_port )
{
    char buf[256], *ptr;

    debug( h, "begin_socks_relay()\n");

    if(h->atomic_out == NULL) return -2;

    /* make connect request packet
       protocol v4:
         VN:1, CD:1, PORT:2, ADDR:4, USER:n, NULL:1
       protocol v4a:
         VN:1, CD:1, PORT:2, DUMMY:4, USER:n, NULL:1, HOSTNAME:n, NULL:1
    */
    ptr = buf;
    PUT_BYTE( ptr++, 4);                        /* protocol version (4) */
    PUT_BYTE( ptr++, 1);                        /* CONNECT command */
    PUT_BYTE( ptr++, dest_port>>8);     /* destination Port */
    PUT_BYTE( ptr++, dest_port&0xFF);
    /* destination IP */
    memcpy(ptr, &dest_addr->sin_addr, sizeof(dest_addr->sin_addr));
    ptr += sizeof(dest_addr->sin_addr);
    if ( dest_addr->sin_addr.s_addr == 0 )
        *(ptr-1) = 1;                           /* fake, protocol 4a */
    /* username */
    if (relay_user == NULL)
        return -2;
    strcpy( ptr, relay_user );
    ptr += strlen( relay_user ) +1;
    /* destination host name (for protocol 4a) */
    if ( (dest_addr->sin_addr.s_addr == 0)) {
        strcpy( ptr, dest_host );
        ptr += strlen( dest_host ) +1;
    }
    /* send command and get response
       response is: VN:1, CD:1, PORT:2, ADDR:4 */
    h->atomic_out( h->closure, buf, ptr-buf, false);      /* send request */
    h->can_read = 8;
    h->atomic_in = &process_begin_socks4_relay;
    h->relay_user = strdup(relay_user);
    h->relay_host = strdup(relay_host);
    h->dest_addr = *dest_addr;
    h->dest_host = strdup(dest_host);
    h->dest_port = dest_port;
    return 16;
}
