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
 * @file gnutls.c
 * @brief SSL/TLS
 * @author Mike Mestnik
 */

#include "gnutls.h"
#include "sendbuf.h"
#include "conf.h"
#include "globals.h"
#include "httpsd.h"
#include "schedule.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <gnutls/gnutls.h>

typedef struct tlssession
{
  gnutls_session_t session;
  fd_closure_h fd_c;
  sendbuf_h sendbuf;
  void
  (*can) (tlssession_h);
  httpsd_h httpsd;
  int ctra;
  bool close_on_fin;
} tlssession_t;

static gnutls_certificate_credentials_t x509_cred;
static gnutls_dh_params_t dh_params;
static gnutls_priority_t priority_cache;

// LCOV_EXCL_START
static void
log_f (int l, const char *m)
{
  fprintf (stderr, "[%d] %s", l, m);
}
// LCOV_EXCL_STOP

void
_gnutls_init ()
{
  int ret;
  gnutls_global_init ();
  gnutls_global_set_log_function (log_f);
  gnutls_global_set_log_level (0);
  ret = gnutls_certificate_allocate_credentials (&x509_cred);
  if (0 != ret)
    {
      // TODO: Bail
    }
  if (NULL != CONF.ssl_intermediate)
    {
      ret = gnutls_certificate_set_x509_trust_file (x509_cred,
						    CONF.ssl_intermediate,
						    GNUTLS_X509_FMT_PEM);
    }
  ret = gnutls_certificate_set_x509_key_file (x509_cred, CONF.ssl_cert,
					      CONF.ssl_key,
					      GNUTLS_X509_FMT_PEM);
  if (0 != ret)
    {
      // TODO: Bail
    }
  ret = gnutls_dh_params_init (&dh_params);
  // TODO: Other stuff for dh_params CONF.ssl_dh
  gnutls_certificate_set_dh_params (x509_cred, dh_params);
  ret = gnutls_priority_init (&priority_cache, CONF.cipher_directs, NULL);
}

static void
can_send (tlssession_h);
static void
record_send (tlssession_h h, const void *d, size_t s)
{
  ssize_t ret;
  ret = gnutls_record_send (h->session, d, s);
  assert(ret != GNUTLS_E_INTERRUPTED); // Ctrl-C or other signal, unlikely.
  if (ret == GNUTLS_E_AGAIN)
    {
      if (gnutls_record_get_direction (h->session) == 1)
	FD_SET(h->fd_c->fd, &WRITE_FDSET);
      if (NULL != d)
	sendbuf_append (&h->sendbuf, d, s);
      h->can = &can_send;
      return;
    }
  else if (ret < 0)
    {
      assert(!ret); // TODO: Close connection.

    }
  else if (ret < s)
    {
      if (NULL != h->sendbuf)
	{
	  sendbuf_skip (&h->sendbuf, ret);
	}
      else if (NULL != d)
	h->sendbuf = sendbuf_new (d + ret, s - ret);
      if (NULL != h->sendbuf)
	{
	  h->can = &can_send;
	  return;
	}
    }
  h->can = NULL;
}

static void
can_send (tlssession_h h)
{
  record_send (h, NULL, 0);
}

void
gnutls_send (tlssession_h h, const void *d, size_t s)
{
  if (NULL == h)
    return; // LCOV_EXCL_LINE
  if (NULL == h->session)
    return;
  if (NULL == h->can)
    {
      record_send (h, d, s);
    }
  else
    sendbuf_append (&h->sendbuf, d, s);
}

static void
_close (tlssession_h h)
{
  if (NULL != h->session)
    gnutls_deinit (h->session);
  h->session = NULL;
  if (NULL != h->httpsd)
    httpsd_close (h->httpsd);
  h->httpsd = NULL;
  if (NULL != h->sendbuf)
    free (h->sendbuf);
  h->sendbuf = NULL;
  if (NULL != h->fd_c)
    sockets_close (h->fd_c);
  h->fd_c = NULL;
}

void
gnutls_close (tlssession_h h)
{
  _close (h);
  free (h);
}

static void
can_read (tlssession_h h)
{
  ssize_t ret = -443;
  do
    {
      char in[4096];
      ret = gnutls_record_recv (h->session, in, 4096);
      assert(ret != GNUTLS_E_INTERRUPTED); // Ctrl-C or other signal, unlikely.

      if (ret == GNUTLS_E_AGAIN)
	{
	  if (gnutls_record_get_direction (h->session) == 1)
	    FD_SET(h->fd_c->fd, &WRITE_FDSET);
	  h->can = &can_read;
	  return;
	}
      else if (ret == 0)
	{
	  0 == h->ctra ? gnutls_close (h) : _close (h);
	  return;
	}
      else if (ret < 0 && gnutls_error_is_fatal (ret) == 0)
	{
	  fprintf (stderr, "non fatal error from %d, %zd\n", h->fd_c->fd, ret); // LCOV_EXCL_LINE
	}
      else if (ret < 0)
	{
	  // TODO: Close connection!
	  return;
	}
      else if (ret > 0)
	httpsd_in (h->httpsd, in, ret);
    }
  while (0 < (ret = gnutls_record_check_pending (h->session)));
  h->can = NULL;
}

static void
schedule_event (void *c)
{
  fd_closure_h h = c;
  gnutls_close ((tlssession_h) h->closure);
}

static void
tlssession_can (fd_closure_h c, bool write)
{
  tlssession_h h = c->closure;
  FD_CLR(c->fd, &WRITE_FDSET);
  if (NULL != h->can)
    {
      h->can (h);
    }
  else
    can_read (h);
}

static void
can_handshake (tlssession_h h)
{
  int ret;
  do
    {
      ret = gnutls_handshake (h->session);
      assert(ret != GNUTLS_E_INTERRUPTED); // Ctrl-C or other signal, unlikely.
      if (GNUTLS_E_AGAIN == ret)
	{
	  if (gnutls_record_get_direction (h->session) == 1)
	    FD_SET(h->fd_c->fd, &WRITE_FDSET);
	  h->can = &can_handshake;
	  return;
	}
    }
  while (ret < 0 && gnutls_error_is_fatal (ret) == 0);
  if (ret < 0)
    {
      fprintf (stderr, "FATAL: handshake on %d\n", h->fd_c->fd);
      sockets_close (h->fd_c);
      gnutls_deinit (h->session);
      free (h);
    }
  else
    h->can = NULL;
}

void
tlssession_start (fd_closure_h fd_c, struct sockaddr *addr, socklen_t alen)
{
  uintptr_t ptr = fd_c->fd;
  tlssession_h h = NULL;
  while (NULL == h)
    h = malloc (sizeof(tlssession_t));
  *h = (tlssession_t
	)
	  { .session = NULL, .fd_c = fd_c, .sendbuf = NULL, .can = NULL, .ctra =
	      0, .close_on_fin = false, };
  h->httpsd = httpsd_new (h, addr, alen);
  int ret;
  ret = gnutls_init (&h->session, GNUTLS_SERVER);
  if (0 > ret)
    {
      // Bail
    }
  ret = gnutls_priority_set (h->session, priority_cache);
  ret = gnutls_credentials_set (h->session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  gnutls_certificate_server_set_request (h->session, GNUTLS_CERT_IGNORE);

  ret = gnutls_set_default_priority (h->session);
  const char *errpos = NULL;
  ret = gnutls_priority_set_direct (h->session, CONF.cipher_directs, &errpos);
  gnutls_transport_set_ptr (h->session, (gnutls_transport_ptr_t) ptr);
  can_handshake (h);
  fd_c->can = &tlssession_can;
  fd_c->closure = h;
  return;
}

void
gnutls_a_ctra (tlssession_h h)
{
  if (0 == h->ctra++ && NULL != h->fd_c)
    ++h->fd_c->instanceid;
}

void
gnutls_b_ctra (tlssession_h h)
{
  assert(0 < h->ctra);
  if (0 == --h->ctra)
    {
      if (h->close_on_fin)
	gnutls_close (h);
      if (!h->close_on_fin && NULL != h->fd_c)
	schedule_timer (schedule_event, h->fd_c, &h->fd_c->instanceid, 5);
    }
}

void
gnutls_close_on_fin (tlssession_h h)
{
  h->close_on_fin = true;
  if (0 == h->ctra)
    gnutls_close (h);
}
