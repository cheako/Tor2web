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

#ifndef __TOR2WEB_HEXTREE_H
#define __TOR2WEB_HEXTREE_H

/**
 * @file hextree.h
 * @brief Find value by hash
 * @author Mike Mestnik
 */

#include <stdbool.h>

typedef struct hexnode *hexnode_h;
typedef struct hexnode
{
  void *data;
  hexnode_h next[16];
  unsigned short depth;
  unsigned char node[];
} hexnode_t;

typedef struct hexnode_iterator *hexnode_iterator_h;

hexnode_iterator_h
hexnode_iterator (hexnode_h);
hexnode_h
hexnode_next (hexnode_iterator_h);
int
hexnode_iterator_set (hexnode_iterator_h, unsigned short,
		      const unsigned char[]);
hexnode_h
hexnode_iterator_get (hexnode_iterator_h);
void
hexnode_iterator_destroy (hexnode_iterator_h);
hexnode_h
hexnode_new (unsigned short, const unsigned char*);
hexnode_h
hexnode_lookup (hexnode_h, unsigned short, const unsigned char[], bool);
int
hexnode_delete (hexnode_h, unsigned short, const unsigned char[]);

#endif
