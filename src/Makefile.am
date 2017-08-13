## @start 1
## Makefile.am -- Process this file with automake to produce Makefile.in
## @end 1
## Copyright (C) 2017 Mike Mestnik
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License as
## published by the Free Software Foundation, either version 3 of the
## License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License for more details.
##
## You should have received a copy of the GNU Affero General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.

MAINTAINERCLEANFILES	= Makefile.in

@CODE_COVERAGE_RULES@

## @start 1
bin_PROGRAMS = tor2web
tor2web_SOURCES  = tor2web.c globals.c conf.c gnutls.c sockets.c
tor2web_SOURCES += ini.c sendbuf.c httpsd.c http.c socks.c vector.c
tor2web_SOURCES += hextree.c schedule.c
if CODE_COVERAGE_ENABLED
tor2web_CFLAGS = -rdynamic -DGCOV_FLUSH $(CODE_COVERAGE_CFLAGS) ${LIBGNUTLS_CFLAGS}
else
tor2web_CFLAGS = -rdynamic $(CODE_COVERAGE_CFLAGS) ${LIBGNUTLS_CFLAGS}
endif
tor2web_LDFLAGS = -rdynamic
tor2web_LIBS = $(CODE_COVERAGE_LIBS)
tor2web_LDADD = ${LIBGNUTLS_LIBS}
## @end 1
