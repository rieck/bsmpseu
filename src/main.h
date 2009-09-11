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
 * $Id: main.h,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

/**
 * @file main.h Main header.
 * 
 * @author Konrad Rieck
 * @version $Id: main.h,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

#ifndef _MAIN_H
#define _MAIN_H

#define D_UID_MIN       200		/**< Minimum uid (above system uids) */
#define D_UID_MAX       60000		/**< Maximum uid (below nobody) */
#define D_GID_MIN       10		/**< Minimum uid (above system gids) */
#define D_GID_MAX       60000		/**< Maximum uid (below nogroup) */
#define D_PID_MIN       500		/**< Minimum uid (above system pids) */
#define D_PID_MAX       65535		/**< Maximum pid. The largest? */
#define D_SHIFT_MAX     604800		/**< Maximum time shift (7 days) */

char *default_prefixes[] = {
   "/export/home/",
   "/home/",
   "/var/mail/",
   "/tmp/",
   "/var/tmp/",
   NULL
};

#endif	/* _MAIN_H */
