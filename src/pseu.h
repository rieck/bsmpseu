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
 * $Id: pseu.h,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

/**
 * @file pseu.h Pseudonymize header.
 * 
 * @author Konrad Rieck
 * @version $Id: pseu.h,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

#ifndef _PSEU_H
#define _PSEU_H

#define UID_HASH_SIZE   10000		/**< Maximum number of uids */
#define GID_HASH_SIZE   1000		/**< Maximum number of gids */
#define PID_HASH_SIZE   32768		/**< Maximum number of pids */
#define PATH_HASH_SIZE  131072		/**< Maximum number of paths */
#define ADDR_HASH_SIZE  32768		/**< Maximum number of addresses */

int pseu_init(int, int, int, int, int, int, char **, long);
void pseu_deinit();
int pseu_token(gzFile *, gzFile *, FILE *);

#endif /* _PSEU_H */
