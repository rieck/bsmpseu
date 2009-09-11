/*
 * Pseudonymizer for Solaris BSM Audit Logs, http://www.roqe.org/bsmpseu
 * Copyright 2002, 2003 Konrad Rieck <kr@roqe.org> - All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: rand.h,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

/**
 * @file rand.h Collection of random functions header. 
 *
 * @author Konrad Rieck
 * @version $Id: rand.h,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

#ifndef _RAND_H
#define _RAND_H

uid_t uid_rand(uid_t min, uid_t max);
pid_t pid_rand(pid_t min, pid_t max);
gid_t gid_rand(gid_t min, gid_t max);
uchar_t *addr_rand(int af, uchar_t * addr);
char *str_rand(char *target, int n);

#endif				/* _RAND_H */
