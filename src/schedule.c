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
 * @file schedule.c
 * @brief Magic from the abyss
 * @author Mike Mestnik
 */

#include "schedule.h"
#include "globals.h"
#include "sockets.h"
#include "hextree.h"
#include "vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <assert.h>

typedef struct timeval timeval_t;

// TODO: Prior to prod, fixup exit condition.
#define TESTING_TIMEOUT ((timeval_t) { .tv_sec = 120, .tv_usec = 0, })

#ifdef CLOCK_MONOTONIC_COARSE
static clockid_t clock_id = CLOCK_MONOTONIC_COARSE;
#else
#ifdef CLOCK_MONOTONIC
static clockid_t clock_id = CLOCK_MONOTONIC;
#else
#ifdef CLOCK_REALTIME_COARSE
static clockid_t clock_id = CLOCK_REALTIME_COARSE;
#else
static clockid_t clock_id = CLOCK_REALTIME;
#endif /* CLOCK_REALTIME_COARSE */
#endif /* CLOCK_MONOTONIC */
#endif /* CLOCK_MONOTONIC_COARSE */

static inline void
probe_clock_id ()
{
  if (0 == clock_getres (clock_id, NULL))
    return;

// LCOV_EXCL_START
#ifdef CLOCK_MONOTONIC
  clock_id = CLOCK_MONOTONIC;
  if (0 == clock_getres (clock_id, NULL))
    return;
#endif /* CLOCK_MONOTONIC */

#ifdef CLOCK_REALTIME_COARSE
  clock_id = CLOCK_REALTIME_COARSE;
  if (0 == clock_getres (clock_id, NULL))
    return;
#endif /* CLOCK_REALTIME_COARSE */

  clock_id = CLOCK_REALTIME;
// LCOV_EXCL_STOP
}

#define __AMACRO(x, y) ((data[(x)] + (uint64_t)0) << (y))
static inline uint64_t
chars_to_time (unsigned char data[])
{
  return __AMACRO(7, 0) | __AMACRO(6, 8) | __AMACRO(5, 16) | __AMACRO(4, 24)
      | __AMACRO(3, 32) | __AMACRO(2, 40) | __AMACRO(1, 48) | __AMACRO(0, 56);
}

#define __BMACRO(x, y) data[(x)] = (t >> (y)) & 0xff
static inline void
time_to_chars (unsigned char *data, uint64_t t)
{
  __BMACRO(7, 0);
  __BMACRO(6, 8);
  __BMACRO(5, 16);
  __BMACRO(4, 24);
  __BMACRO(3, 32);
  __BMACRO(2, 40);
  __BMACRO(1, 48);
  __BMACRO(0, 56);
}

static uint64_t time_ptr;

static inline void
set_time_ptr ()
{
  struct timespec t;
  if (0 != clock_gettime (clock_id, &t))
    {
      // LCOV_EXCL_START
      perror ("set_time_ptr: clock_gettime");
      time_ptr++;
      // LCOV_EXCL_STOP
    }
  else
    time_ptr = t.tv_sec;
}

static hexnode_h hexnode;
static hexnode_iterator_h iterator;

void
schedule_init ()
{
  hexnode = hexnode_new (0, NULL);
  iterator = hexnode_iterator (hexnode);
  probe_clock_id ();
  time_ptr = 0;
  set_time_ptr ();
}

typedef struct
{
  schedule_event_t e;
  void *d;
  int *instanceid;
  int sequance_num;
} a_t;
typedef a_t *a_h;

void
schedule_timer (schedule_event_t e, void *d, int *instanceid, int s)
{
  a_t t;
  unsigned char buf[8];
  Vector **events_h_h;
  time_to_chars (buf, time_ptr + s);
  events_h_h = (Vector **) &hexnode_lookup (hexnode, 8, buf, true)->data;
  if ( NULL == *events_h_h)
    {
      while ( NULL == *events_h_h)
	*events_h_h = malloc (sizeof(Vector));
      // TODO: Dynamically scale this based on number of fds.
      while (VECTOR_SUCCESS != vector_setup (*events_h_h, 64, sizeof(a_t)))
	;
    }
  t = (a_t
	)
	  { .e = e, .d = d, .instanceid = instanceid, .sequance_num =
	  NULL != instanceid ? ++*instanceid : 0, };
  vector_push_back (*events_h_h, &t);
}

void
process_pending_timers (uint64_t prev, timeval_t *ret, bool *_sleep)
{
  hexnode_h last = NULL;
  unsigned char buf[8];
  if (prev == time_ptr)
    return;
  time_to_chars (buf, prev);
  hexnode_iterator_set (iterator, 8 << 1, buf);
  fprintf (stderr, "begin(%d)\n", prev);
  do
    {
      hexnode_h b;
      uint64_t btime;
      b = hexnode_next (iterator);
      if (NULL != last)
	{
	  int i;
	  if (last == b)
	    { // This is odd!
	      hexnode_next (iterator);
	      continue;
	    }

	  if (NULL != last->data)
	    {
	      assert(8 << 1 == last->depth); // If not true then the following is way bad.
	      vector_destroy (last->data);
	      free (last->data);
	      last->data = NULL;
	    }
	  fprintf (stderr, "deleting   : %p->%d\n", last, last->depth);
	  i = hexnode_delete (hexnode, last->depth, last->node);

	  if (NULL == b || hexnode == b)
	    break; // returns, pushing last oos.

	  last = NULL;
	  if (0 == i)
	    {
	      int ret = hexnode_iterator_set (iterator, b->depth, b->node);
	      fprintf (stderr, "reset == %d : %p->%d\n", ret, b, b->depth);
	    }
	}
      else if (NULL == b || hexnode == b)
	break;

      if (8 << 1 != b->depth || NULL == b->data)
	{
	  if (hexnode != b)
	    last = b;
	  continue;
	}

      btime = chars_to_time (b->node);
      if (time_ptr >= btime)
	{
	  while (!vector_is_empty (b->data))
	    {
	      a_h try = (a_h) vector_get (b->data, 0);
	      if (NULL == try->instanceid
		  || try->sequance_num == *try->instanceid)
		try->e (try->d);
	      vector_pop_front (b->data);
	    }
	}
      else
	{
	  while (!vector_is_empty (b->data))
	    {
	      a_h try = (a_h) vector_get (b->data, 0);
	      if (try->sequance_num == *try->instanceid)
		break;
	      vector_pop_front (b->data);
	    }
	  if (!vector_is_empty (b->data))
	    {
	      *ret = (timeval_t
		    )
		      { btime - time_ptr, 0 };
	      *_sleep = true;
	      return;
	    }
	}
      last = b;
    }
  while (1);
  *_sleep = false;
}

#ifdef GCOV_FLUSH
void __gcov_flush(void);
#endif

void
schedule_run ()
{
  bool running = true;
  uint64_t prev = time_ptr;
  bool _sleep = false;
  timeval_t sleep_time;
  while (running)
    {
      int nready, i;
      timeval_t timeout = TESTING_TIMEOUT;
      fd_set _read_fdset = sockets_read_fdset, _write_fdset = WRITE_FDSET;
      process_pending_timers (prev, &sleep_time, &_sleep);
#ifdef GCOV_FLUSH
      __gcov_flush ();
#endif
      if (-1 == (nready = select (sockets_maxfd, &_read_fdset, &_write_fdset,
      NULL,
				  (_sleep ? &sleep_time : &timeout))))
	perror ("select"); // LCOV_EXCL_LINE
      prev = time_ptr;
      set_time_ptr ();
      for (i = 0; i <= sockets_maxfd && nready > 0; i++)
	{
	  if (FD_ISSET(i, &_read_fdset))
	    {
	      nready--;
	      sockets_can (i, false);
	    }
	  if (FD_ISSET(i, &_write_fdset))
	    {
	      nready--;
	      sockets_can (i, true);
	    }
	}
      running = _sleep ? 1 : (0 != timeout.tv_sec || 0 != timeout.tv_usec);
    }
}
