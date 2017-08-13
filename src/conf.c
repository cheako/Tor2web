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
 * @file config.c
 * @brief Configuration
 * @author Mike Mestnik
 */

#include "conf.h"
#include "ini.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

CONF_T CONF =
  { "/var/run/tor2web/t2w.pid", -1, -1,
  false, "/var/run/tor2web/", "start", "tor2web", "/home/tor2web",
      "/usr/share/tor2web/data",
      NULL,
      NULL,
      NULL,
      NULL,
      false,
      false,
      false, 1, 1000000,
	{ AF_INET, 0,
	  { 0 } },
	{ AF_INET6, 0, 0,
	IN6ADDR_ANY_INIT, 0 }, "AUTO",
	{ .ss_family = AF_INET },
      true, 5, 240,
      true, "NORMAL:%COMPAT", 100, "BLOCKLIST",
      NULL,
      true, "jpg:png:gif",
      NULL,
      false,
      false,
      false,
      false,
      false, "hey_you_should_change_me", "yes_you_really_should_change_me",
      "notification@demo.globaleaks.org", "stackexception@lists.tor2web.org",
      "tor2web-abuse@lists.tor2web.org",
	{ }, "TLS", 600, "", 600, "MERGE",
      false, "",
      NULL, 4096, };

typedef int
(*handle_f) (void*, const char*);

int
set_uid (void *c, const char *o)
{
  struct passwd *pwd;
  char *ret;
  uid_t uid;
  uid = strtoul (o, &ret, 10);
  if (o != ret)
    {
      pwd = getpwuid (uid);
    }
  else
    {
      pwd = getpwnam (o);
    }
  if (NULL == pwd)
    return 0;
  CONF.uid = pwd->pw_uid;
  return 1;
}

int
set_gid (void *c, const char *o)
{
  struct group *grp;
  char *ret;
  gid_t gid;
  gid = strtoul (o, &ret, 10);
  if (o != ret)
    {
      grp = getgrgid (gid);
    }
  else
    {
      grp = getgrnam (o);
    }
  if (NULL == grp)
    return 0;
  CONF.gid = grp->gr_gid;
  return 1;
}

int
set_addr (void *p, const char *o)
{
  // struct sockaddr_storage test;
  return 0;
}

int
set_port (void *p, const char *o)
{
  char *ret;
  int h;
  h = strtoul (o, &ret, 10);
  if (o == ret)
    return 0; // TODO: Warn about non-numeric port.
  if (((struct sockaddr *) p)->sa_family == AF_INET)
    {
      ((struct sockaddr_in *) p)->sin_port = htons (h);
    }
  else if (((struct sockaddr *) p)->sa_family == AF_INET6)
    {
      ((struct sockaddr_in6 *) p)->sin6_port = htons (h);
    }
  else
    assert(0);
  return 1;
}

struct
{
  const char *n;
  bool allocated;
  char **s;
  bool *b;
  int *i;
  handle_f f;
  void *c;
} handles[] =
      {
	{ "pidfile", false, &CONF.pidfile, NULL, NULL, NULL, NULL },
	{ "uid", false, NULL, NULL, NULL, &set_uid, NULL },
	{ "gid", false, NULL, NULL, NULL, &set_gid, NULL },
	{ "nodaemon", false, NULL, &CONF.nodaemon, NULL, NULL, NULL },
	{ "rundir", false, &CONF.rundir,
	NULL, NULL, NULL, NULL },
	{ "command", false, &CONF.command, NULL, NULL, NULL, NULL },
	{ "nodename", false, &CONF.nodename, NULL, NULL, NULL, NULL },
	{ "datadir", false, &CONF.datadir, NULL, NULL,
	NULL, NULL },
	{ "sysdatadir", false, &CONF.sysdatadir,
	NULL, NULL, NULL, NULL },
	{ "ssl_key", false, &CONF.ssl_key, NULL, NULL, NULL, NULL },
	{ "ssl_cert", false, &CONF.ssl_cert, NULL, NULL, NULL, NULL },
	{ "ssl_intermediate", false, &CONF.ssl_intermediate, NULL, NULL, NULL,
	NULL },
	{ "ssl_dh", false, &CONF.ssl_dh, NULL, NULL, NULL, NULL },
	{ "logreqs", false, NULL, &CONF.logreqs, NULL, NULL, NULL },
	{ "debugmode", false, NULL, &CONF.debugmode, NULL, NULL, NULL },
	{ "debugtostdout", false, NULL, &CONF.debugtostdout, NULL, NULL, NULL },
	{ "processes", false, NULL, NULL, &CONF.processes, NULL, NULL },
	{ "requests_per_process", false, NULL, NULL, &CONF.requests_per_process,
	NULL, NULL },
//  { "transport", false, NULL, NULL, NULL, &depreciated, "transport" },
	    { "listen_ipv4", false, NULL, NULL, NULL, &set_addr,
		&CONF.listen_ipv4 },
	    { "listen_ipv6", false, NULL, NULL, NULL, &set_addr,
		&CONF.listen_ipv6 },
//  { "listen_port_http", false, NULL, NULL, NULL, &depreciated, "listen_port_http" },
	    { "listen_port_https", false, NULL, NULL, NULL, &set_port,
		&CONF.listen_ipv4 },
	    { "sockshost", false, NULL, NULL, NULL, &set_addr, &CONF.sockshost },
	    { "socksport", false, NULL, NULL, NULL, &set_port, &CONF.sockshost },

//  { "cipher_list", false, NULL, NULL, NULL, &depreciated, "cipher_list" },
      };

static int
handler (void* user, const char* section, const char* name, const char* value)
{

  if (0 == strcmp (section, "") || 0 == strcmp (section, "main"))
    {
      size_t i;
      for (i = 0; i < sizeof(handles) / sizeof(handles[0]); i++)
	{
	  int ret;
	  ret = strcmp (name, handles[i].n);
	  if (ret == 0)
	    {
	      if (NULL != handles[i].s)
		{
		  if (handles[i].allocated)
		    {
		      free (*handles[i].s);
		    }
		  else
		    handles[i].allocated = true;
		  *handles[i].s = strdup (value);
		}
	      if (NULL != handles[i].b)
		*handles[i].b = true; // TODO: Support storing false.
	      if (NULL != handles[i].i)
		{
		  int ret;
		  char *p;
		  ret = strtol (value, &p, 10);
		  if (value != p)
		    {
		      *handles[i].i = ret;
		    }
		  else
		    ; // TODO: Handle malformed numbers.
		}
	      if (NULL != handles[i].f)
		return handles[i].f (handles[i].c, value);
	      return 1;
	    }
	  // if(ret == -1) return 0;
	}
    }
  return 1;
}

int
conf_init (int argc, char *argv[])
{
  int c;
  char *file = "/etc/tor2web.conf";
  while (1)
    {
      int option_index = 0;
      static struct option long_options[] =
	{
	  { "con", required_argument,
	  NULL, 'c' },
	  { "p", required_argument, NULL, 'p' },
	  { "u",
	  required_argument, NULL, 'u' },
	  { "g", required_argument, NULL, 'g' },
	  { "n", no_argument, NULL, 'n' },
	  { "r",
	  required_argument, NULL, 'd' },
	  { "com", required_argument,
	  NULL, 'x' },
	  { 0, 0, NULL, 0 } };

      c = getopt_long (argc, argv, "c:p:u:g:nr:x:", long_options,
		       &option_index);
      if (c == -1)
	break;

      switch (c)
	{
	case 0:
	  // TODO: Bail on unknowen arg?
	  break;

	case 'c':
	  file = optarg;
	  break;

	case 'p':
	  CONF.pidfile = optarg;
	  handles[0].s = NULL;
	  break;

	case 'u':
	  if (0 == set_uid (NULL, optarg))
	    handles[1].f = NULL;
	  break;

	case 'g':
	  if (0 == set_gid (NULL, optarg))
	    handles[2].f = NULL;
	  break;

	case 'n':
	  CONF.nodaemon = true;
	  handles[3].b = NULL;
	  break;

	case 'd':
	  CONF.rundir = optarg;
	  handles[4].s = NULL;
	  break;

	case 'x':
	  CONF.command = optarg;
	  handles[5].s = NULL;
	  break;

	case '?':
	  break;

	default:
	  printf ("?? getopt returned character code 0%o ??\n", c);
	}
    }

  /* Some calculated defaults. */
  CONF.listen_ipv4.sin_port = htons (443);
  inet_pton (AF_INET, "127.0.0.1", &CONF.listen_ipv4.sin_addr);
  CONF.listen_ipv6.sin6_port = htons (443);
  inet_pton (AF_INET, "127.0.0.1",
	     &((struct sockaddr_in*) &CONF.sockshost)->sin_addr);
  ((struct sockaddr_in*) &CONF.sockshost)->sin_port = htons (9050);
  /* "demo.globaleaks.org",
   CONF.smtpdomain.sin_port = htons(9267); */

  if (ini_parse (file, handler, NULL) < 0)
    {
      printf ("Can't load %s\n", file);
      return 1;
    }

  return 0;
}
