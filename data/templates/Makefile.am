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

SUFFIXES = .html.in .html

M4       = m4
M4FLAGS  =
M4SCRIPT = common.m4

%.html: %.html.in
	${M4} ${M4FLAGS} ${M4SCRIPT} $< > $*.html

ttwdir = $(datadir)/ttw

ttw_DATA = banner.html error_generic.html error_sock.html disclaimer.html error_gettor.html error_blocked_page.html error_invalid_hostname.html

regular_depends = common.m4 tor2web.css tor2web.js tor2web.png
tos.html: ${regular_depends}
banner.html: tos.html ${regular_depends}
error_generic.html: ${regular_depends}
error_sock.html: ${regular_depends}
disclaimer.html: ${regular_depends}
error_gettor.html: ${regular_depends}
error_blocked_page.html: ${regular_depends}
error_invalid_hostname.html: ${regular_depends}

EXTRA_DIST = common.m4 banner.html.in error_generic.html.in error_sock.html.in disclaimer.html.in error_gettor.html.in error_blocked_page.html.in error_invalid_hostname.html.in decoy.html tor2web-big.png tor2web.css tor2web.js tor2web.min.js tor2web.png tor2web-small.png tos.html.in

clean:
	rm -f $(ttw_DATA)
	rm -f tos.html
