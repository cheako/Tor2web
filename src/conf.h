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

#ifndef __TOR2WEB_CONF_H
#define __TOR2WEB_CONF_H

/**
 * @file conf.h
 * @brief Configuration
 * @author Mike Mestnik
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdbool.h>
#include <arpa/inet.h>

typedef struct
{
  char *pidfile;
  uid_t uid;
  gid_t gid;
  bool nodaemon;
  char *rundir;
  char *command;
  char *nodename;
  char *datadir;
  char *sysdatadir;
  char *ssl_key;
  char *ssl_cert;
  char *ssl_intermediate;
  char *ssl_dh;
  bool logreqs;
  bool debugmode;
  bool debugtostdout;
  int processes;
  int requests_per_process;
  struct sockaddr_in listen_ipv4;
  struct sockaddr_in6 listen_ipv6;
  char *basehost;
  struct sockaddr_storage sockshost;
  bool socksoptimisticdata;
  int sockmaxpersistentperhost;
  int sockcachedconnectiontimeout;
  bool sockretryautomatically;
  char *cipher_directs;
  int ssl_tofu_cache_size;
  char *mode;
  char *onion;
  bool blockhotlinking;
  char *blockhotlinking_exts;
  char *extra_http_response_headers;
  bool disable_disclaimer;
  bool disable_banner;
  bool disable_tor_redirection;
  bool disable_gettor;
  bool avoid_rewriting_visible_content;
  char *smtpuser;
  char *smtppass;
  char *smtpmail;
  char *smtpmailto_exceptions;
  char *smtpmailto_notifications;
  struct sockaddr_storage smtpdomain;
  char *smtpsecurity;
  int exit_node_list_refresh;
  char *automatic_blocklist_updates_source;
  int automatic_blocklist_updates_refresh;
  char *automatic_blocklist_updates_mode;
  bool publish_lists;
  char *mirror;
  char *dummyproxy;
  size_t bufsize;
} CONF_T;
extern CONF_T CONF;

int
conf_init (int, char**);

#endif
