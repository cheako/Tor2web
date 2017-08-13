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
 * @file hextree.c
 * @brief Create and Destroy trees of 16 branches per node
 * @author Mike Mestnik
 */

#include "hextree.h"
#include "vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static inline bool
depthhaspartial (unsigned short d)
{
  return d & 1;
}

static inline unsigned short
depthtolen (unsigned short d)
{
  return (d + 1) >> 1;
}

static inline unsigned short
depthtoindex (unsigned short d)
{
  return depthtolen (d) - 1;
}

static inline unsigned char
hextreetoindex (unsigned short d, const unsigned char n[])
{
  return
      depthhaspartial (d) ?
	  (n[depthtoindex (d)] & 0xF0) >> 4 : (n[depthtoindex (d)] & 0x0F);
}

hexnode_h
hexnode_new (unsigned short depth, const unsigned char node[])
{
  hexnode_h ret = NULL;
  unsigned short len = depthtolen (depth);
  while (ret == NULL) /* This might be a place we wish to bail? */
    ret = malloc (sizeof(struct hexnode) + len);
  *ret = (hexnode_t
	)
	  { .data = NULL, .next =
	    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	    NULL, NULL, NULL, NULL, NULL }, .depth = depth, };
  memcpy (&ret->node, node, len);
  if (depthhaspartial (depth))
    ret->node[depthtoindex (depth)] &= 0xF0;
  fprintf (stderr, "creating   : %p->%d\n", ret, depth);
  return ret;
}

typedef struct hexnode_iterator
{
  hexnode_h root;
  Vector d;
} hexnode_iterator_t;

typedef struct
{
  hexnode_h hexnode;
  unsigned char ctr;
} iterator_node_t;

static int
_hexnode_lookup (hexnode_h root, Vector *ret, unsigned short depth,
		 const unsigned char n[],
		 bool create)
{
  hexnode_h *lastptr;
  unsigned char *node = NULL;
  iterator_node_t this =
    { .hexnode = root, .ctr = 0, };
  while (VECTOR_SUCCESS != vector_setup (ret, 16, sizeof(iterator_node_t)))
    ;
  if (root->depth >= depth)
    { // LCOV_EXCL_START
      vector_push_back (ret, &this);
      return -1;
    } // LCOV_EXCL_STOP
  while (NULL == node)
    node = malloc (depthtolen (depth));
  memcpy (node, n, depthtolen (depth));
  if (depthhaspartial (depth))
    node[depthtoindex (depth)] &= 0xF0;
  this.ctr = hextreetoindex (root->depth + 1, node);
  lastptr = &root->next[this.ctr++];
  vector_push_back (ret, &this);
  this = (iterator_node_t
	)
	  { .hexnode = *lastptr, .ctr = 0, };
  while (1)
    {
      if (NULL == this.hexnode)
	{
	  if (create)
	    {
	      hexnode_h new = hexnode_new (depth, node);
	      *lastptr = new;
	      this = (iterator_node_t
		    )
		      { .hexnode = new, .ctr = 0, };
	      vector_push_back (ret, &this);
	    }
	  free (node);
	  return 2;
	}
      if (depth < this.hexnode->depth)
	{
	  if (create)
	    {
	      hexnode_h new = hexnode_new (depth, node);
	      new->next[hextreetoindex (this.hexnode->depth, this.hexnode->node)] =
		  this.hexnode;
	      *lastptr = new;
	      this = (iterator_node_t
		    )
		      { .hexnode = new, .ctr = 0, };
	      vector_push_back (ret, &this);
	    }
	  free (node);
	  return 1;
	}
      if (depth == this.hexnode->depth)
	{
	  unsigned short i;
	  unsigned short len = depthtolen (depth);
	  for (i = 0; i < len && node[i] == this.hexnode->node[i]; i++)
	    ;
	  if (i != len)
	    {
	      if (create)
		{
		  unsigned short new_depth = (i << 1)
		      + ((node[i] & 0xF0) == (this.hexnode->node[i] & 0xF0))
		      - 1;
		  vector_destroy (ret);
		  _hexnode_lookup (root, ret, new_depth, node, true);
		  iterator_node_t *it = (iterator_node_t*) vector_back (ret);
		  hexnode_h new = hexnode_new (depth, node);
		  it->ctr = hextreetoindex (new_depth, node);
		  it->hexnode->next[it->ctr++] = new;
		  this = (iterator_node_t
			)
			  { .hexnode = new, .ctr = 0, };
		  vector_push_back (ret, &this);
		}
	      free (node);
	      return 3;
	    }
	  this.ctr = 0;
	  vector_push_back (ret, &this);
	  free (node);
	  return 0;
	}
      this.ctr = hextreetoindex (this.hexnode->depth, node);
      lastptr = &(*lastptr)->next[this.ctr++];
      vector_push_back (ret, &this);
      this.hexnode = *lastptr;
    }
}

#define VECTOR_BACK_AS(type, vector_pointer) \
  (*((type*)vector_back((vector_pointer))))

hexnode_h
hexnode_lookup (hexnode_h root, unsigned short size, const unsigned char node[],
bool create)
{
  hexnode_h ret = NULL;
  Vector temp;
  int i = _hexnode_lookup (root, &temp, size << 1, node, create);
  if (0 == i || create)
    ret = (VECTOR_BACK_AS(iterator_node_t, &temp)).hexnode;
  vector_destroy (&temp);
  return ret;
}

// TODO: Delete parent as well
int
hexnode_delete (hexnode_h root, unsigned short depth,
		const unsigned char node[])
{
  int ret = 0;
  unsigned short i;
  hexnode_h t, found = NULL;
  Vector temp;
  iterator_node_t a;
  assert(0 != depth);
  if (0 != _hexnode_lookup (root, &temp, depth, node, false))
    {
      ret = 1;
      goto SKIP;
    }
  t = (VECTOR_BACK_AS(iterator_node_t, &temp)).hexnode;
  if (NULL != t->data)
    { // LCOV_EXCL_START
      ret = -1;
      goto SKIP;
    } // LCOV_EXCL_STOP
  for (i = 0; i < 16; i++)
    if (NULL != t->next[i])
      {
	if (NULL != found)
	  {
	    ret = 2;
	    goto SKIP;
	  }
	found = t->next[i];
      }
  a = VECTOR_GET_AS(iterator_node_t, &temp, temp.size - 2);
  a.hexnode->next[a.ctr - 1] = found;
  free (t);
  SKIP: vector_destroy (&temp);
  return ret;
}

hexnode_iterator_h
hexnode_iterator (hexnode_h h)
{
  hexnode_iterator_h ret = NULL;
  iterator_node_t t =
    { .hexnode = h, .ctr = 0, };
  while (ret == NULL)
    ret = malloc (sizeof(hexnode_iterator_t));
  *ret = (hexnode_iterator_t
	)
	  { .root = h, };
  while (VECTOR_SUCCESS != vector_setup (&ret->d, 16, sizeof(iterator_node_t)))
    ;
  vector_push_back (&ret->d, &t);
  return ret;
}

int
hexnode_iterator_set (hexnode_iterator_h h, unsigned short depth,
		      const unsigned char node[])
{
  vector_destroy (&h->d);
  return _hexnode_lookup (h->root, &h->d, depth, node, false);
}

hexnode_h
hexnode_next (hexnode_iterator_h h)
{
  iterator_node_t *ai;
  while (!vector_is_empty (&h->d))
    {
      ai = vector_back (&h->d);
      if (16 > ai->ctr)
	{
	  hexnode_h canidate = ai->hexnode->next[ai->ctr++];
	  if (NULL != canidate)
	    {
	      iterator_node_t new =
		{ .hexnode = canidate, .ctr = 0 };
	      vector_push_back (&h->d, &new);
	    }
	}
      else
	{
	  if (16 == ai->ctr++)
	    return ai->hexnode;
	  if (VECTOR_ERROR == vector_pop_back (&h->d))
	    break; // LCOV_EXCL_LINE
	}
    }
  return NULL;
}

hexnode_h // LCOV_EXCL_START
hexnode_iterator_get (hexnode_iterator_h h)
{
  iterator_node_t *a = vector_back (&h->d);
  return a->hexnode;
}

void
hexnode_iterator_destroy (hexnode_iterator_h h)
{
  vector_destroy (&h->d);
  free (h);
} // LCOV_EXCL_STOP
