#
# Pseudonymizer for Solaris BSM Audit Logs, http://www.roqe.org/bsmpseu
# Copyright 2002, 2003 Konrad Rieck <kr@roqe.org> - All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU Library General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU Library General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# $Id: Makefile.am,v 3.1 2003/02/27 17:11:31 kr Exp $
#

CFLAGS = @CFLAGS@

sbin_PROGRAMS = bsmpseu
bsmpseu_SOURCES = main.c main.h pseu.c pseu.h bsm.c bsm.h rand.c rand.h \
                  hash.c hash.h misc.c misc.h

 
beautify: $(bsmpseu_SOURCES)
	indent -i3 -kr -l77 -lc77 $(bsmpseu_SOURCES)
	rm -f *~
