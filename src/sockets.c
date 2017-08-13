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

/**
 * @file sockets.c
 * @brief Handle sockets
 * @author Mike Mestnik
 */

#include "sockets.h"
#include "globals.h"
#include "schedule.h"
#include "conf.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <errno.h>

int sockets_maxfd = 3;
fd_set sockets_read_fdset;

static fd_set init_new_fd_set;

typedef struct fd_closure fd_closure_t;
static fd_closure_t fd_closures[FD_SETSIZE];

void
sockets_init ()
{
  FD_ZERO(&sockets_read_fdset);
  FD_ZERO(&init_new_fd_set);
}

static void
init_new_fd (int fd)
{
  if (!FD_ISSET(fd, &init_new_fd_set))
    {
      fd_closures[fd].fd = fd;
      fd_closures[fd].instanceid = 0;
      FD_SET(fd, &init_new_fd_set);
    }
  fd_closures[fd].can = NULL;
  fd_closures[fd].closure = NULL;
  fcntl (fd, F_SETFL, O_NONBLOCK);
  FD_SET(fd, &sockets_read_fdset);
  if (fd >= sockets_maxfd)
    sockets_maxfd = fd + 1;
}

void
listener_can (fd_closure_h h, bool write)
{
  assert(!write);
  static const struct sockaddr_storage sockaddr_storage_blank;
  struct sockaddr_storage addr = sockaddr_storage_blank;
  socklen_t len = sizeof(addr);
  int fd;

  if ((fd = accept (h->fd, (struct sockaddr*) &addr, &len)) == -1)
    perror ("Warning accepting one new connection"); // LCOV_EXCL_LINE

  /**TODO: if(fork()){for(int i = 3; i <= sockets_maxfd; i++){close(i)}; dup(fd)};
   * The parent should close all the other connections and wipe it's state.
   * The child should close this fd and the listener and eventually exit.
   * Perhaps we could even do this at say ((FD_SETSIZE / 4) * 3) + 50
   */
  assert(FD_SETSIZE > fd);

  init_new_fd (fd);

  tlssession_start (&fd_closures[fd], (struct sockaddr*) &addr, len);
}

void
sockets_create_listener (const struct sockaddr *s, socklen_t len)
{
  int yes = 1;
  int fd;
  fd = socket (s->sa_family, SOCK_STREAM, 0);
  if (0 > fd)
    {
      // LCOV_EXCL_START
      perror ("socket");
      return;
      // LCOV_EXCL_STOP
    }

  init_new_fd (fd);

  /*"address already in use" error message */
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    perror ("SO_REUSEADDR"); // LCOV_EXCL_LINE

#ifdef SO_REUSEPORT
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int)) == -1)
    perror ("SO_REUSEPORT"); // LCOV_EXCL_LINE
#endif

  if (bind (fd, s, len) == -1)
    perror ("bind"); // LCOV_EXCL_LINE

  if (listen (fd, SOMAXCONN) == -1)
    perror ("Error opening listener"); // LCOV_EXCL_LINE

  fd_closures[fd].can = &listener_can;
  fd_closures[fd].closure = NULL;
}

fd_closure_h
sockets_connect_socks ()
{
  int fd;
  fd = socket (CONF.sockshost.ss_family, SOCK_STREAM, 0);
  if (0 > fd)
    perror ("socks socket"); // LCOV_EXCL_LINE

  init_new_fd (fd);

  if (-1
      == connect (fd, (struct sockaddr *) &CONF.sockshost,
		  sizeof(CONF.sockshost)))
    {
      if (EINPROGRESS == errno)
	{
	  fd_closures[fd].closure = &fd_closures[fd];
	  FD_SET(fd, &WRITE_FDSET);
	}
      else
	perror ("socks connect"); // LCOV_EXCL_LINE
    }

  return &fd_closures[fd];
}

void
sockets_close (fd_closure_h h)
{
  FD_CLR(h->fd, &sockets_read_fdset);
  FD_CLR(h->fd, &WRITE_FDSET);
  close (h->fd);
  h->can = NULL;
  h->closure = NULL;
  ++h->instanceid;
}

void
sockets_can (int i, bool write)
{
  assert(NULL != fd_closures[i].can);
  fd_closures[i].can (&fd_closures[i], write);
}
