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
 * $Id: rand.c,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

/**
 * @file rand.c Collection of random functions.
 * These functions are used to create random uids, gids, etc... each
 * identifier has its own random function so that special conditions can be
 * added separatly.
 *
 * @author Konrad Rieck
 * @version $Id: rand.c,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "config.h"

/**
 * Create a random uid within the given interval.
 * @param min minimum uid
 * @param max maximum uid
 * @return uid between min and max
 */
uid_t uid_rand(uid_t min, uid_t max)
{
   return (uid_t) lrand48() % (max - min) + min;
}

/**
 * Create a random gid within the given interval.
 * @param min minimum gid
 * @param max maximum gid
 * @return gid between min and max
 */
gid_t gid_rand(gid_t min, gid_t max)
{
   return (gid_t) lrand48() % (max - min) + min;
}

/*
 * Create a random pid within the given interval.
 * @param min minimum pid
 * @param max maximum pid
 * @return pid between min and max
 */
pid_t pid_rand(pid_t min, pid_t max)
{
   return (pid_t) lrand48() % (max - min) + min;
}

/**
 * Create a random string at the location provided by the given pointer of n
 * length excluding the terminating NULL char.
 * @param str string to randomize
 * @param n length of character to modify
 * @return randomized string
 */
char *str_rand(char *str, int n)
{
   int i;
   double d;
   uchar_t c;

   for (i = 0; i < n; i++) {
      d = drand48();

      if (d > 0.80 && i != 0 && i < (n - 2) && str[i - 1] != '/')
	 c = '/';
      else if (d > 0.35 && str[i - 1] < 'Z')
	 c = lrand48() % ('Z' - 'A') + 'A';
      else
	 c = lrand48() % ('z' - 'a') + 'a';
      str[i] = c;
   }

   return str;
}

/**
 * Create a random inet address for either IPv4 or IPv6. Keep an eye on
 * the first and last byte and avoid using broadcast IPs, etc...
 * @param len size of addr
 * @param addr buffer with address
 * @return randomized inet address
 */
uchar_t *addr_rand(int len, uchar_t * addr)
{
   int i;
   uchar_t c;

   for (i = 0; i < len; i++) {
      c = lrand48();
      if ((i == 0 && (c > 200 || c < 60)) ||
	  (i == len - 1 && (c == 255 || c == 0)))
	 i--;
      else
	 addr[i] = c;
   }

   return addr;
}
