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
 * @file http.c
 * @brief http client
 * @author Mike Mestnik
 */

#include "http.h"
#include "sockets.h"
#include "socks.h"
#include "vector.h"
#include "hextree.h"
#include "globals.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

static const unsigned char base32_values[128] =
  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, // 1
      0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff,
      0xff, // A
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, // a
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff };

static inline int
base32_decode (unsigned char *out, unsigned short outlen,
	       const unsigned char *in, unsigned short inlen)
{

  long long i, j = 0;
  unsigned char u;
  unsigned long long v = 0, vbits = 0;

  for (i = 0; i < inlen; ++i)
    {
      if (in[i] & 0x80)
	return 0; // LCOV_EXCL_LINE
      u = base32_values[in[i]];
      if (u > 0x1f)
	return 0;
      v |= u << vbits;
      vbits += 5;

      if (vbits >= 8)
	{
	  if (j >= outlen)
	    return 0; // LCOV_EXCL_LINE
	  out[j++] = v;
	  vbits -= 8;
	  v >>= 8;
	}
    }
  // LCOV_EXCL_START
  if (vbits)
    {
      if (j >= outlen)
	return 0;
      out[j++] = v;
    }
  return 1;
  // LCOV_EXCL_STOP
}

regex_t regex_onion;
regex_t regex_domain_av;
static hexnode_h hexnode;

void
http_init ()
{
  int reti;

  /* Compile regular expressions */
  reti = regcomp (&regex_onion, "[a-z2-7]{16}\\.onion",
  REG_EXTENDED | REG_ICASE);
  if (reti)
    {
      fprintf (stderr, "Could not compile onion regex\n");
      exit (1);
    }
  reti = regcomp (&regex_domain_av, "; Domain=[^;\r\n]+",
  REG_EXTENDED | REG_ICASE);
  if (reti)
    {
      fprintf (stderr, "Could not compile domain_av regex\n");
      exit (1);
    }
  hexnode = hexnode_new (0, NULL);
}

typedef struct http
{
  fd_closure_h fd;
  const char *hostname;
  sendbuf_h client_sendbuf;
  sendbuf_h out_sendbuf;
  sendbuf_h in_sendbuf;
  sendbuf_h chunked_sendbuf;
  Vector request_v;
  socksapi_h socksapi;
  bool have_connect;
  bool have_socks_connect;
  bool have_status_line;
  bool is_html;
  bool have_eoh;
  size_t body_length;
  bool chunked;
  bool inuse;
} http_t;

static size_t
out_send_func (void *c, const void *b, size_t s)
{
  http_h h = c;
  size_t size = 0;
  ssize_t ret;
  do
    {
      ret = send (h->fd->fd, b + size, s - size, 0);
      if (ret == -1)
	{
	  if (EAGAIN == errno)
	    {
	      FD_SET(h->fd->fd, &WRITE_FDSET);
	      return size;
	    }
	  else
	    perror ("out_send_func() failed to send()");
	}
      size += ret;
    }
  while (s > size);
  return s;
}

static void
atomic_out (void *c, const void *b, size_t s, bool ignore)
{
  http_h h = c;
  if (NULL == h->out_sendbuf)
    {
      size_t size = 0;
      ssize_t ret;
      do
	{
	  ret = send (h->fd->fd, b + size, s - size, 0);
	  if (ret == -1)
	    {
	      if (EAGAIN == errno)
		{
		  sendbuf_append (&h->out_sendbuf, b + size, s - size);
		  FD_SET(h->fd->fd, &WRITE_FDSET);
		  return;
		}
	      else
		perror ("atomic_out() failed to send()");
	    }
	  size += ret;
	}
      while (s > size);
    }
  else
    sendbuf_append (&h->out_sendbuf, b, s);
}

void
http_write (http_h h, const void *b, size_t s)
{
  http_request_t *p;
  // Just guessing here.
  p = (http_request_t*) vector_back (&h->request_v);
  sendbuf_append (&p->retrybuf, b, s);
  if (!h->have_socks_connect)
    {
      sendbuf_append (&h->client_sendbuf, b, s);
    }
  else if (h->out_sendbuf)
    {
      sendbuf_append (&h->out_sendbuf, b, s);
    }
  else
    {
      size_t size = 0;
      ssize_t ret;
      do
	{
	  ret = send (h->fd->fd, b + size, s - size, 0);
	  if (ret == -1)
	    {
	      if (EAGAIN == errno)
		{
		  sendbuf_append (&h->out_sendbuf, b + size, s - size);
		  FD_SET(h->fd->fd, &WRITE_FDSET);
		  return;
		}
	      else
		perror ("http_write() failed to send()");
	    }
	  size += ret;
	}
      while (s > size);
    }
}

static void
responce_end (http_h h)
{
  h->have_status_line = false;
  h->have_eoh = false;
  h->body_length = 0;
  h->chunked = false;
  assert(h->chunked_sendbuf == NULL);
  if (h->request_v.size)
    {
      http_request_t *request;
      request = (http_request_t*) vector_front (&h->request_v);
      if (NULL != request->hostname)
	free (request->hostname);
      if (NULL != request->retrybuf)
	free (request->retrybuf);
      request->output.eof = true;
      response_send (&request->output, NULL, 0);
      vector_pop_front (&h->request_v);
    }
}

static size_t
process_func (void*, const void*, size_t);
static inline size_t
process_status_line (http_h h, http_request_t *request, const char **d,
		     size_t s,
		     bool *done)
{
  size_t ret = 0;
  bool one_byte;
  unsigned short len;
  len = strcspn (*d, "\n");
  if ('\n' != (*d)[len++])
    {
      *done = true;
      return 0;
    }
  h->have_status_line = true;
  response_send (&request->output, *d, len);
  ret += len;
  *d += len;
  if ((s > ret && (one_byte = ('\n' == (*d)[0])))
      || (s > ret + 1 && '\r' == (*d)[0] && '\n' == (*d)[1]))
    {
      // TODO: No headers.
      response_send (&request->output, one_byte ? "\n" : "\r\n",
		     one_byte ? 1 : 2);
      *d += one_byte ? 1 : 2;
      ret += one_byte ? 1 : 2;
      // This automatically means no body, so the response is done.
      responce_end (h);
      if (0 < s - ret)
	{
	  fprintf (stderr, "Got %zu bytes after status line.\n%s\n", s - ret,
		   *d);
	  ret += process_func (h, *d, s - ret);
	}
      *done = true;
    }
  return ret;
}

static inline void
clip_domain_from_cookie (response_h output, const char *hstart, size_t hlen)
{
  int reti;
  regmatch_t regmatch;
  reti = regexec (&regex_domain_av, hstart, 1, &regmatch, 0);
  if (!reti)
    {
      if (hlen > regmatch.rm_so)
	{
	  response_send (output, hstart, regmatch.rm_so);
	  // Should be a \n at least.
	  assert(hlen > regmatch.rm_eo);
	  response_send (output, hstart + regmatch.rm_eo,
			 hlen - regmatch.rm_eo);
	}
      else
	{
	  // The regex is incorrect if we somehow get here.
	  fprintf ( stderr, "%s %zu, at %d.  In: <<EOR\n%s\nEOR",
		   "Regex domain_av start past end of header", hlen,
		   regmatch.rm_so, hstart);
	  response_send (output, hstart, hlen);
	}
    }
  else if (reti != REG_NOMATCH)
    {
      char msgbuf[100];
      regerror (reti, &regex_onion, msgbuf, sizeof(msgbuf));
      fprintf (stderr, "Regex domain_av request line match failed: %s\n",
	       msgbuf);
      response_send (output, hstart, hlen);
    }
  else
    // This is normal, the server didn't send domain-av.
    response_send (output, hstart, hlen);
}

static inline void
process_one_header (http_h h, http_request_t *request, const char *hstart,
		    size_t hlen)
{
  size_t klen;
  klen = strcspn (hstart, ": \t\n");
  if (':' == hstart[klen])
    {
      switch (klen)
	{
	case 17:
	  if (0 == strncasecmp (hstart, "Transfer-Encoding", 17)
	      && 1 /* TODO: ": chunked" */)
	    {
	      h->chunked = true;
	      // gnutls_send (request->tls, hstart, hlen);
	    }
	  else
	    response_send (&request->output, hstart, hlen);
	  break;
	case 10:
	  if (0 == strncasecmp (hstart, "Set-Cookie", 10))
	    {
	      clip_domain_from_cookie (&request->output, hstart, hlen);
	    }
	  else
	    response_send (&request->output, hstart, hlen);
	  break;
	case 14:
	  if (0 == strncasecmp (hstart, "ConTent-Length", 14))
	    {
	      size_t len = 0;
	      if (1 == sscanf (&hstart[15], "%zu", &len))
		h->body_length = len;
	    }
	  response_send (&request->output, hstart, hlen);
	  break;
	case 12:
	  if (0 == strncasecmp (hstart, "Content-Type", 12))
	    {
	      const char *p = &hstart[13];
	      while (*p == ' ' || *p == '\t')
		p++;
	      if (0 != strncasecmp (p, "text/html", 9))
		goto NOT_HTML;
	      p += 9;
	      while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	      h->is_html = p[-1] == '\n';
	    }
	  NOT_HTML: response_send (&request->output, hstart, hlen);
	  break;
	default:
	  response_send (&request->output, hstart, hlen);
	}
    }
  else
    fprintf (stderr, "Skipping header: %s\n", hstart);
}

static inline size_t
process_one_chunk (http_h h, http_request_t *request, const char **d, size_t s)
{
  size_t clen = 0;
  unsigned short pos = 0;
  bool l = true;
  while (l)
    {
      if (s < pos)
	return 0;
      switch ((*d)[pos++])
	{
	case 0:
	  // This can happen if we try to read past end of string.
	  fprintf ( stderr, "%s ('\\0', %zu); \\\n\t\tpos = %d;\n",
		   "ERROR: http: process_chunked_body", s, pos);
	  break;
	case '\r':
	case '\n':
	  l = false;
	  break;
	case '0':
	  clen = clen << 4;
	  break;
	case '1':
	  clen = (clen << 4) + 1;
	  break;
	case '2':
	  clen = (clen << 4) + 2;
	  break;
	case '3':
	  clen = (clen << 4) + 3;
	  break;
	case '4':
	  clen = (clen << 4) + 4;
	  break;
	case '5':
	  clen = (clen << 4) + 5;
	  break;
	case '6':
	  clen = (clen << 4) + 6;
	  break;
	case '7':
	  clen = (clen << 4) + 7;
	  break;
	case '8':
	  clen = (clen << 4) + 8;
	  break;
	case '9':
	  clen = (clen << 4) + 9;
	  break;
	case 'a':
	case 'A':
	  clen = (clen << 4) + 0xa;
	  break;
	case 'b':
	case 'B':
	  clen = (clen << 4) + 0xb;
	  break;
	case 'c':
	case 'C':
	  clen = (clen << 4) + 0xc;
	  break;
	case 'd':
	case 'D':
	  clen = (clen << 4) + 0xd;
	  break;
	case 'e':
	case 'E':
	  clen = (clen << 4) + 0xe;
	  break;
	case 'f':
	case 'F':
	  clen = (clen << 4) + 0xf;
	  break;
	default:
	  fprintf (stderr, "Skipping unknown char 0x%x\n", (*d)[pos - 1]);
	}
    }
  // TODO: Don't assume two byte line ends.
  if (s < pos + 1 + clen + 2)
    return 0;
  // TODO: Don't assume two byte line ends.
  *d += pos + 1;
  if (0 == clen) // Last chunk.
    {
      // TODO: Make this a function.
      char buf[100];
      size_t slen;
      // TODO: Process headers.
      *d += 2;
      slen = get_sendbuf_size (h->chunked_sendbuf);
      response_send (
	  &request->output, buf,
	  snprintf (buf, sizeof(buf), "Content-Length: %zu\r\n\r\n", slen));
      response_send (&request->output, get_sendbuf_buf (h->chunked_sendbuf),
		     slen);
      sendbuf_clear (&h->chunked_sendbuf);
      responce_end (h);
      return pos + 1 + 2;
    }
  // TODO: Don't assume two byte line ends.
  sendbuf_append (&h->chunked_sendbuf, *d, clen);
  *d += clen + 2;
  return pos + 1 + clen + 2;
}

static size_t
process_func (void *c, const void *v, size_t s)
{
  http_h h = c;
  const char *d = v, *hstart;
  size_t ret = 0;
  size_t hlen = 0;
  bool done = false;
  if (vector_is_empty (&h->request_v))
    return (0);
  http_request_t *request;
  request = (http_request_t*) vector_front (&h->request_v);
  if (!h->have_status_line)
    ret += process_status_line (h, request, &d, s, &done);
  if (done)
    return ret;
  hstart = d;
  while (!h->have_eoh)
    {
      bool one_byte;
      size_t len;
      len = strcspn (d, "\n");
      // Need to be able to read first byte on next line.
      if ('\n' != d[len++] || s <= ret + len)
	return ret;
      hlen += len;
      if (' ' != d[len] && '\t' != d[len])
	{
	  process_one_header (h, request, hstart, hlen);
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
	  // Except for the content length added after un-chunking.
	  if (!h->chunked)
	    response_send (&request->output, one_byte ? "\n" : "\r\n",
			   one_byte ? 1 : 2);
	  d += one_byte ? 1 : 2;
	  ret += one_byte ? 1 : 2;
	}
    }

  if (!h->have_eoh)
    return ret;

  if (h->chunked)
    {
      while (s > ret && !done)
	{
	  size_t len;
	  ret += len = process_one_chunk (h, request, &d, s - ret);
	  done = 0 == len;
	}
      return ret;
    }

  if (0 == h->body_length)
    {
      responce_end (h);
    }
  else if (s < ret + h->body_length)
    {
      size_t len = s - ret;
      ret += len;
      assert(s == ret);
      response_send (&request->output, d, len);
      h->body_length -= len;
    }
  else
    {
      response_send (&request->output, d, h->body_length);
      ret += h->body_length;
      d += h->body_length;
      responce_end (h);
      // Loop to next response.
      if (0 < s - ret)
	ret += process_func (h, d, s - ret);
    }
  return ret;
}

static void
send_begin_socks (http_h h)
{
  h->have_connect = true;
  int i = begin_socks4_relay (h->socksapi, "", "", &(struct sockaddr_in
	)
	  { .sin_addr =
	    { .s_addr = 0 } },
			      h->hostname, 80);
  switch (i)
    {
    case 0:
      h->have_socks_connect = true;
      assert(NULL == h->out_sendbuf);
      h->out_sendbuf = h->client_sendbuf;
      h->client_sendbuf = NULL;
      sendbuf_send (h, &h->out_sendbuf, &out_send_func);
      break;
    case -1:
      fprintf (stderr, "Begin_socks failure on fd %d\n", h->fd->fd);
      sockets_close (h->fd);
      break;
    case 16:
      break;
    default:
      fprintf (stderr, "Begin_socks status on fd %d, no %d\n", h->fd->fd, i);
    }
}

static void
reinit (http_h);
static void
http_can (fd_closure_h c, bool write)
{
  http_h h = c->closure;
  if (!write)
    {
      if (!h->have_connect)
	return;
      if (!h->have_socks_connect)
	{
	  size_t size;
	  char *buf = NULL;
	  ssize_t ret = 0;
	  do
	    {
	      if (NULL != buf && 0 < ret)
		{
		  sendbuf_append (&h->in_sendbuf, buf, ret);
		  free (buf);
		  buf = NULL;
		}
	      size = get_socksapi_can_read (h->socksapi)
		  - get_sendbuf_size (h->in_sendbuf);
	      while (NULL == buf)
		buf = malloc (size);
	      ret = recv (h->fd->fd, buf, size, 0);
	      if (0 == ret)
		{
		  sockets_close (h->fd);
		  return;
		}
	      else if (-1 == ret)
		{

		  if (EAGAIN == errno)
		    {
		      sendbuf_append (&h->in_sendbuf, buf, ret);
		      free (buf);
		      return;
		    }
		  else if (ECONNRESET == errno)
		    {
		      free (buf);
		      sockets_close (h->fd);
		      perror ("*socks_in() failed to recv()");
		      // reinit (h);
		      return;
		    }
		  else
		    perror ("socks_in() failed to recv()");
		}
	      size -= ret;
	    }
	  while (0 < size);
	  int i;
	  if (NULL != h->in_sendbuf)
	    {
	      sendbuf_append (&h->in_sendbuf, buf, ret);
	      i = socksapi_atomic_in (h->socksapi,
				      get_sendbuf_buf (h->in_sendbuf),
				      get_sendbuf_size (h->in_sendbuf));
	      sendbuf_clear (&h->in_sendbuf);
	    }
	  else
	    i = socksapi_atomic_in (h->socksapi, buf, ret);
	  free (buf);
	  switch (i)
	    {
	    case 0:
	      h->have_socks_connect = true;
	      assert(NULL == h->out_sendbuf);
	      h->out_sendbuf = h->client_sendbuf;
	      h->client_sendbuf = NULL;
	      sendbuf_send (h, &h->out_sendbuf, &out_send_func);
	      break;
	    case -1:
	      fprintf (stderr, "Socks failure on fd %d\n", h->fd->fd);
	      sockets_close (h->fd);
	      break;
	    case 16:
	      break;
	    default:
	      fprintf (stderr, "Socks status on fd %d, no %d\n", h->fd->fd, i);
	    }
	}
      else
	{
	  char buf[4096];
	  ssize_t ret;
	  do
	    {
	      ret = recv (h->fd->fd, buf, sizeof(buf), 0);
	      if (-1 == ret)
		{
		  if (EAGAIN == errno)
		    {
		      sendbuf_send (h, &h->in_sendbuf, &process_func);
		      return;
		    }
		  else
		    // TODO: Handle errors
		    perror ("client_in() failed to recv()");
		}
	      sendbuf_append (&h->in_sendbuf, buf, ret);
	    }
	  while (0 != ret);
	  sendbuf_send (h, &h->in_sendbuf, &process_func);
	  sockets_close (h->fd);
	  reinit (h);
	  VECTOR_FOR_EACH(&h->request_v, i)
	    {
	      http_request_t *resend;
	      resend = (http_request_t*) iterator_get (&i);
	      // TODO: better than hope client_sendbuf is current.
	      sendbuf_append (&h->client_sendbuf,
			      get_sendbuf_buf (resend->retrybuf),
			      get_sendbuf_size (resend->retrybuf));
	    }
	}
    }
  else
    {
      FD_CLR(h->fd->fd, &WRITE_FDSET);
      if (!h->have_connect)
	{
	  int optval;
	  socklen_t optlen = sizeof(int);
	  if (-1 != getsockopt (c->fd,
	  SOL_SOCKET,
				SO_ERROR, &optval, &optlen))
	    {
	      if (0 == optval)
		{
		  send_begin_socks (h);
		}
	      else if (ECONNREFUSED == optval)
		{
		  sockets_close (h->fd);
		  // reinit (h);
		  fprintf (stderr, "*Connect to socks failed: %s\n",
			   strerror (optval));
		}
	      else
		{
		  // TODO: Close socket and retry.
		  fprintf (stderr, "Connect to socks failed: %s\n",
			   strerror (optval));
		}
	    }
	  else
	    perror ("http getsockopt"); // LCOV_EXCL_LINE
	}
      else
	sendbuf_send (h, &h->out_sendbuf, &out_send_func);
    }
}

static void
reinit (http_h h)
{
  h->have_connect = false;
  h->have_socks_connect = false;
  if (NULL != h->socksapi)
    free (h->socksapi);
  h->socksapi = new_socksapi ();
  set_socksapi_noerror (h->socksapi, true);
  set_socksapi_atomic_out (h->socksapi, &atomic_out);
  set_socksapi_closure (h->socksapi, h);
  h->fd = sockets_connect_socks ();
// Special signal from sockets_connect_socks not to expect is connected read.
  if (NULL == h->fd->closure)
    send_begin_socks (h);
  h->fd->can = &http_can;
  h->fd->closure = h;
}

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
http_h
http_new (http_request_t request, const void *b, size_t s)
{
  Vector **services_h_h;
  unsigned char out[10];
  http_h h = NULL;
  request.retrybuf = NULL;
  if (!base32_decode (out, 10, (const unsigned char*) request.hostname, 16))
    {
      fprintf (stderr, "Couldn't parse hostname\n");
      services_h_h = (Vector **) &hexnode_lookup (
	  hexnode, strnlen (request.hostname, 9) + 1,
	  (const unsigned char*) request.hostname,
	  true)->data;
    }
  else
    services_h_h = (Vector **) &hexnode_lookup (hexnode, 10, out, true)->data;
  if ( NULL == *services_h_h)
    {
      while ( NULL == *services_h_h)
	*services_h_h = malloc (sizeof(Vector));
      **services_h_h = (Vector
	    )VECTOR_INITIALIZER;
      vector_setup (*services_h_h, 3, sizeof(http_h));
    }
  VECTOR_FOR_EACH(*services_h_h, i)
    {
      http_h try;
      try = ITERATOR_GET_AS(http_h, &i);
      if (!try->inuse && 1000000 >= try->body_length
	  && 7 >= try->request_v.size)
	{
	  h = try;
	  break;
	}
    }
  if (NULL != h)
    {
      vector_push_back (&h->request_v, &request);
      h->inuse = true;
      http_write (h, b, s);
      return h;
    }
  while (NULL == h)
    h = malloc (sizeof(http_t));
  *h = (http_t
	)
	  { .hostname = NULL, .client_sendbuf = NULL, .out_sendbuf =
	  NULL, .in_sendbuf = NULL, .chunked_sendbuf = NULL, .socksapi =
	  NULL, .inuse = true, .is_html = false, };
  while (NULL == h->hostname)
    h->hostname = strdup (request.hostname);
  while (VECTOR_SUCCESS
      != vector_setup (&h->request_v, 5, sizeof(http_request_t)))
    ;
  responce_end (h);
  vector_push_back (&h->request_v, &request);
  reinit (h);
  http_write (h, b, s);
  vector_push_back (*services_h_h, &h);
  return h;
}

void
http_detach (http_h h, bool have_eof, size_t body_length)
{
  if (!have_eof)
    http_write (h, "\r\n", 2);
  if (0 != body_length)
    {
      void *b = NULL;
      b = calloc (1, body_length);
      http_write (h, b, body_length);
      free (b);
    }
  h->inuse = false;
}

void
http_request_update (http_h h, http_request_t r)
{
  http_request_t *p;
  if (NULL == h)
    return; // LCOV_EXCL_LINE
// Because of the inuse flag, can only be the last.
  p = (http_request_t*) vector_back (&h->request_v);
  assert(p->handle == r.handle);
  r.retrybuf = p->retrybuf;
  *p = r;
}
