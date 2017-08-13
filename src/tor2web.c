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
 * @file tor2web.c
 * @brief Code main and such
 * @author Mike Mestnik
 */

#include "tor2web.h"
#include "globals.h"
#include "conf.h"
#include "gnutls.h"
#include "sockets.h"
#include "http.h"
#include "schedule.h"

#include <stdio.h>
#include <unistd.h>

void
write_pid ()
{
  FILE *f;
  int fd;

  // TODO: CONF.pidfile
  if (((fd = open ("t/var/run/test/test.pid", O_RDWR | O_CREAT, 0644)) == -1)
      || ((f = fdopen (fd, "r+")) == NULL))
    {
      // LCOV_EXCL_START
      perror ("Can't open or create pidfile");
      return;
      // LCOV_EXCL_STOP
    }

  if (!fprintf (f, "%d\n", getpid ()))
    perror ("Writing pidfile"); // LCOV_EXCL_LINE

  fflush (f);
  close (fd);
}

int
main (int argc, char *argv[])
{
  int ret;
  globals_init ();
  http_init ();
  ret = conf_init (argc, argv);
  if (ret != 0)
    return ret;
  write_pid ();
  _gnutls_init ();
  sockets_init ();
  schedule_init ();
  sockets_create_listener ((void *) &CONF.listen_ipv4,
			   sizeof(CONF.listen_ipv4));
  schedule_run ();
  return 0;
}
