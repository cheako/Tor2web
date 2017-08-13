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
 * @file sendbuf.c
 * @brief Buffer helper
 * @author Mike Mestnik
 */

#include "sendbuf.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct sendbuf
{
  size_t len;
  size_t skip;
  char data[];
} sendbuf_t;

sendbuf_h
sendbuf_new (const void *d, size_t s)
{
  static const sendbuf_t b;
  sendbuf_h h = NULL;
  while (NULL == h)
    h = malloc (sizeof(sendbuf_t));
  *h = b;
  sendbuf_append (&h, d, s);
  return h;
}

void
sendbuf_append (sendbuf_h *b, const void *d, size_t s)
{
  size_t old_size, new_size;
  if (d == NULL || s == 0)
    return;
  if (*b == NULL)
    {
      *b = sendbuf_new (d, s);
      return;
    }
  old_size = (*b)->len - (*b)->skip;
  new_size = old_size + s;
  sendbuf_h h = NULL;
  while (NULL == h) // TODO: Block allocations.
    h = malloc (sizeof(sendbuf_t) + new_size + 1);
  *h = (sendbuf_t
	)
	  { .len = new_size, .skip = 0, };
  memcpy (h->data, &(*b)->data[(*b)->skip], old_size);
  memcpy (&h->data[old_size], d, s);
  h->data[new_size] = 0;
  free (*b);
  *b = h;
}

void
sendbuf_send (void *closure, sendbuf_h *b, sendbuf_send_func_f f)
{
  if (*b == NULL)
    return; // LCOV_EXCL_LINE
  size_t ret, len;
  len = (*b)->len - (*b)->skip;
  ret = f (closure, &(*b)->data[(*b)->skip], len);
  if (len == ret)
    {
      free (*b);
      *b = NULL;
    }
  else if (len > ret)
    {
      (*b)->skip += ret;
    }
  else
    assert(len >= ret); // LCOV_EXCL_LINE
}

void
sendbuf_skip (sendbuf_h *b, size_t ret)
{
  if (*b == NULL)
    return;
  size_t len;
  len = (*b)->len - (*b)->skip;
  if (len == ret)
    {
      free (*b);
      *b = NULL;
    }
  else if (len > ret)
    {
      (*b)->skip += ret;
    }
  else
    assert(len >= ret);
}

size_t
get_sendbuf_size (sendbuf_h h)
{
  return NULL == h ? 0 : h->len - h->skip;
}

const void *
get_sendbuf_buf (sendbuf_h h)
{
  return NULL == h ? NULL : &h->data[h->skip];
}

void
sendbuf_clear (sendbuf_h *h)
{
  if (NULL != *h)
    {
      free (*h);
      *h = NULL;
    }
}
