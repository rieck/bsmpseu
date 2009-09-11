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
 * $Id: bsm.h,v 3.1 2003/02/27 17:11:31 kr Exp $
 */

/**
 * @file bsm.h BSM token header. 
 * 
 * @author Konrad Rieck
 * @version $Id: bsm.h,v 3.1 2003/02/27 17:11:31 kr Exp $
 */

#ifndef _BSM_H
#define _BSM_H

#define BUFFER_SIZE             32768
#define BUFFER_SEGMENTS         4
#define BUFFER_SEG_SIZE         (BUFFER_SIZE / BUFFER_SEGMENTS)
#define TRACE_SIZE              5
int bsm_read(gzFile *in, char *buf, int *len);
int bsm_write(gzFile *zout, FILE *out, char *buf, int len);
void bsm_reset(gzFile *in);
int bsm_check(gzFile *in, char *filename);
int bsm_eof(gzFile *in);

#endif				/* _BSM_H */
