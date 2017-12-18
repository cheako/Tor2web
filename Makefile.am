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

SUBDIRS = src data/templates

NOCAREFUNC=stat,close,brk,mprotect,mmap,getuid,geteuid,getgid,getegid,fstat,lseek,ioctl,rt_sigprocmask,rt_sigaction
check:
	head --lines=-0 --verbose /dev/null $(sort $(wildcard data/templates/*.html)) | xz | uuencode --base64 templates.txt.xz
#	head --lines=-0 --verbose /dev/null $(sort $(wildcard t/*.t.log t/tx/*.t.log t/test-suite.log t/tx/test-suite.log))
	for ech in t/tx/*.t; do echo $$ech .; perl $$ech; done || true
#	prove -v -f t/tx || true
#	strace -e trace=\!$(NOCAREFUNC) -f -s 200 prove -v -f t/tx || true
#	{ TTW_STRACE="strace -f -s 200" perl t/tx/A0*.t; perl t/tx/A3*.t; perl t/tx/Db*.t; perl t/tx/Z*.t; } || true
#	{ TTW_STRACE=" " strace -e trace=\!$(NOCAREFUNC) -f -s 200 perl t/tx/A0*.t& perl t/tx/A3*.t; perl t/tx/Db*.t; perl t/tx/Z*.t; wait; } || true
#	perl t/tx/A*.t || true
#	strace -e trace=\!$(NOCAREFUNC) -f -s 200 perl t/tx/D*.t || true
#	strace -e trace=\!$(NOCAREFUNC) -f -s 200 perl t/tx/A0*.t & disown
#	perl t/tx/A3*.t || true
#	perl t/tx/Db*.t || true
#	perl t/tx/Z*.t || true
#	prove -f
