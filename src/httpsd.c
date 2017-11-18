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
 * @file httpsd.c
 * @brief Manage variables available everywhere
 * @author Mike Mestnik
 */

#include "httpsd.h"
#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct httpsd
{
  struct sockaddr_storage addr;
  socklen_t alen;
  http_request_t http_request;
  sendbuf_h sendbuf;
  sendbuf_h lover;
  http_h http;
  bool have_request_line;
  bool have_eoh;
  size_t body_length;
  struct
  {
    unsigned short begin;
    unsigned short end;
  }*request_line_clip;
  bool http_close;
  tlssession_h tls;
} httpsd_t;

static void
write_http (httpsd_h h, const void *b, size_t s)
{
  if (NULL == h->http)
    {
      sendbuf_append (&h->sendbuf, b, s);
    }
  else
    {
      http_write (h->http, b, s);
    }
}

static void
new_request (httpsd_h h)
{
  if (h->http_close)
    gnutls_close_on_fin (h->tls);
  h->body_length = 0;
  h->have_request_line = false;
  if (NULL != h->http)
    {
      http_detach (h->http, h->have_eoh, h->body_length);
      h->http = NULL;
    }
  if (NULL != h->request_line_clip)
    {
      free (h->request_line_clip);
      h->request_line_clip = NULL;
    }
  h->have_eoh = false;
  // Try and make sure we don't get the same one twice.
  h->http_request.handle = random () ^ random () ^ random ();
  h->http_request.http_subversion = true;
  h->http_request.hostname = NULL;
}

httpsd_h
httpsd_new (tlssession_h tls, struct sockaddr *addr, socklen_t alen)
{
  httpsd_h h = NULL;
  while (NULL == h)
    h = malloc (sizeof(httpsd_t));
  memcpy (&h->addr, addr, alen);
  *h = (httpsd_t
	)
	  { .alen = alen, .tls = tls, .sendbuf = NULL, .lover =
	  NULL, .http = NULL, .request_line_clip = NULL, .tls = tls,
	      .http_close = false, };
  new_request (h);
  return h;
}

void
httpsd_close (httpsd_h h)
{
  new_request (h);
  if (NULL != h->lover)
    free (h->lover);
  free (h);
}

static size_t
process_func (void*, const void*, size_t);
static inline size_t
process_request_line (httpsd_h h, const char *d[], size_t s,
bool *done)
{
  size_t ret = 0;
  unsigned short len;
  len = strcspn (*d, "\n");
  if (NULL == h->http)
    {
      unsigned short plen;
      plen = strcspn (*d, "/");
      if (s > plen + 20 && (' ' == (*d)[plen - 1] || ':' == (*d)[plen - 1])
	  && '/' == (*d)[plen++] && '/' == (*d)[plen++])
	{
	  int reti;
	  regmatch_t regmatch;
	  const char *hstart = *d + plen;
	  reti = regexec (&regex_onion, hstart, 1, &regmatch, 0);
	  if (!reti)
	    {
	      unsigned short hlen;
	      hlen = strcspn (hstart, " /");
	      if (hlen > regmatch.rm_so)
		{
		  if (hlen > regmatch.rm_eo)
		    {
		      while (NULL == h->request_line_clip)
			h->request_line_clip = malloc (
			    sizeof(*h->request_line_clip));
		      h->request_line_clip->begin = regmatch.rm_eo + plen;
		      h->request_line_clip->end = hlen + plen;
		    }
		  while (NULL == h->http_request.hostname)
		    h->http_request.hostname =
			strndup (
			    hstart + regmatch.rm_so,
			    strspn (
				hstart + regmatch.rm_so,
				"qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890._-"));
		}
	    }
	  else if (reti != REG_NOMATCH)
	    {
	      char msgbuf[100];
	      // LCOV_EXCL_START
	      regerror (reti, &regex_onion, msgbuf, sizeof(msgbuf));
	      fprintf (stderr, "Regex onion request line match failed: %s\n",
		       msgbuf);
	      // LCOV_EXCL_STOP
	    }
	}
    }
  if ('\n' == (*d)[len++])
    {
      bool one_byte;
      h->have_request_line = true;
      if ((one_byte = '0' == (*d)[len - 3]) || '0' == (*d)[len - 2])
	h->http_request.http_subversion = false;
      switch (((NULL != h->request_line_clip) << 2)
	  | (!h->http_request.http_subversion << 1) | !one_byte)
	{
	case 0:
	case 1:
	  write_http (h, *d, len);
	  break;
	case 1 << 2:
	case 1 << 2 | 1:
	  write_http (h, *d, h->request_line_clip->begin);
	  write_http (h, *d + h->request_line_clip->end,
		      len - h->request_line_clip->end);
	  free (h->request_line_clip);
	  h->request_line_clip = NULL;
	  break;
	case 1 << 1:
	  write_http (h, *d, len - 3);
	  write_http (h, "1\r\n", 3);
	  break;
	case 1 << 1 | 1:
	  write_http (h, *d, len - 2);
	  write_http (h, "1\n", 2);
	  break;
	case 1 << 2 | 1 << 1:
	  write_http (h, *d, h->request_line_clip->begin);
	  write_http (h, *d + h->request_line_clip->end,
		      len - h->request_line_clip->end - 3);
	  free (h->request_line_clip);
	  h->request_line_clip = NULL;
	  write_http (h, "1\r\n", 3);
	  break;
	case 1 << 2 | 1 << 1 | 1:
	  write_http (h, *d, h->request_line_clip->begin);
	  write_http (h, *d + h->request_line_clip->end,
		      len - h->request_line_clip->end - 2);
	  free (h->request_line_clip);
	  h->request_line_clip = NULL;
	  write_http (h, "1\n", 2);
	  break;
	default:
	  // LCOV_EXCL_START
	  fprintf (stderr, "Invalid switch\n");
	  write_http (h, *d, len);
	  // LCOV_EXCL_STOP
	}
      ret += len;
      *d += len;
      one_byte = false;
      if (!((s > ret && (one_byte = ('\n' == (*d)[0])))
	  || (s > ret + 1 && '\r' == (*d)[0] && '\n' == (*d)[1])))
	return ret;
      // TODO: No headers.
      write_http (h, one_byte ? "\n" : "\r\n", one_byte ? 1 : 2);
      *d += one_byte ? 1 : 2;
      ret += one_byte ? 1 : 2;
      // This automatically means no body, so the request is done.
      h->have_eoh = true;
      new_request (h);
      // Loop to next request.
      if (0 < s - ret)
	{
	  fprintf (stderr, "Got %zu bytes after request line.\n%s\n", s - ret,
		   *d);
	  ret += process_func (h, *d, s - ret);
	}
    }
  *done = true;
  return ret;
}

static size_t
process_func (void *c, const void *v, size_t s)
{
  httpsd_h h = c;
  const char *d = v, *hstart;
  unsigned short hlen = 0;
  size_t ret = 0;
  bool done = false;
  if (!h->have_request_line)
    ret += process_request_line (h, &d, s, &done);
  if (done)
    return ret;
  hstart = d;
  while (!h->have_eoh)
    {
      bool one_byte;
      unsigned short len;
      len = strcspn (d, "\n");
      // Need to be able to read first byte on next line.
      if ('\n' != d[len++] || s <= ret + len)
	return ret;
      hlen += len;
      if (' ' != d[len] && '\t' != d[len])
	{
	  unsigned short klen;
	  klen = strcspn (hstart, ": \t\n");
	  if (':' == hstart[klen])
	    {
	      if (4 == klen && NULL == h->http
		  && 0 == strncasecmp (hstart, "Host", 4))
		{
		  int reti;
		  regmatch_t regmatch;
		  const char *dstart = hstart + klen + 1;
		  reti = regexec (&regex_onion, dstart, 1, &regmatch, 0);
		  if (!reti)
		    {
		      if (hlen - klen - 1 > regmatch.rm_so)
			{
			  bool one_byte;
			  write_http (h, hstart, klen + 1 + regmatch.rm_eo);
			  one_byte = '\r' == hstart[hlen - 2];
			  write_http (h, !one_byte ? "\n" : "\r\n",
				      !one_byte ? 1 : 2);
			  while (NULL == h->http_request.hostname)
			    h->http_request.hostname =
				strndup (
				    dstart + regmatch.rm_so,
				    strspn (
					dstart + regmatch.rm_so,
					"qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890._-"));
			}
		    }
		  else if (reti != REG_NOMATCH)
		    {
		      char msgbuf[100];
		      // LCOV_EXCL_START
		      regerror (reti, &regex_onion, msgbuf, sizeof(msgbuf));
		      fprintf (stderr, "Regex onion header match failed: %s\n",
			       msgbuf);
		      write_http (h, hstart, hlen);
		      // LCOV_EXCL_STOP

		    }
		  else
		    {
		      fprintf (stderr, "Regex onion header no match\n");
		      write_http (h, hstart, hlen);
		    }
		}
	      else if (14 == klen
		  && 0 == strncasecmp (hstart, "ConTent-Length", 14))
		{
		  size_t len = 0;
		  if (1 == sscanf (&hstart[15], "%zu", &len))
		    h->body_length = len;
		  write_http (h, hstart, hlen);
		}
	      else
		{
		  write_http (h, hstart, hlen);
		}
	    }
	  else
	    fprintf (stderr, "Skipping response header: %s\n", hstart);
	  ret += hlen;
	  hstart += hlen;
	  hlen = 0;
	}
      d += len;
      one_byte = false;
      if ((s > ret && (one_byte = ('\n' == d[0])))
	  || (s > ret + 1 && '\r' == d[0] && '\n' == d[1]))
	{
	  // TODO: This is the last header.
	  h->have_eoh = true;
	  h->http_request.output = (response_t
		)
		  { .next = NULL, .tls = h->tls, .eof = false, .sendbuf =
		  NULL, };
	  write_http (h, one_byte ? "\n" : "\r\n", one_byte ? 1 : 2);
	  h->http = http_new (h->http_request, get_sendbuf_buf (h->sendbuf),
			      get_sendbuf_size (h->sendbuf));
	  sendbuf_clear (&h->sendbuf);
	  d += one_byte ? 1 : 2;
	  ret += one_byte ? 1 : 2;
	}
    }
  if (h->have_eoh)
    {
      if (0 == h->body_length)
	{
	  new_request (h);
	}
      else if (s < ret + h->body_length)
	{
	  unsigned short len = s - ret;
	  ret = s; // Simple mathematics
	  h->body_length -= len;
	  write_http (h, d, len);
	}
      else
	{
	  write_http (h, d, h->body_length);
	  ret += h->body_length;
	  d += h->body_length;
	  new_request (h);
	  // Loop to next request.
	  if (0 < s - ret)
	    {
	      fprintf (stderr, "Got %zu bytes after request.\n%s\n", s - ret,
		       d);
	      ret += process_func (h, d, s - ret);
	    }
	}
    }
  return ret;
}

void
httpsd_in (httpsd_h h, const void *d, size_t s)
{
  sendbuf_append (&h->lover, d, s);
  sendbuf_send (h, &h->lover, &process_func);
}
