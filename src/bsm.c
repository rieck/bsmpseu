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
 * $Id: bsm.c,v 3.1 2003/02/27 17:11:31 kr Exp $
 */

/** 
 * @file bsm.c BSM token functions
 * Function dealing with the reading and writing of BSM tokens. The Solaris
 * OS comes with a lot of functions to write audit events to an audit log,
 * but lacks functions for reading events.
 *
 * @author Konrad Rieck
 * @version $Id: bsm.c,v 3.1 2003/02/27 17:11:31 kr Exp $
 */

#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "misc.h"
#include "bsm.h"
#include "config.h"

static int errnum;
static uchar_t buffer[BUFFER_SIZE];
static uchar_t trace[TRACE_SIZE];
static uchar_t trace_ptr = 0;
static int bufptr = 0, eof_flag = 0;
static int bufseg = BUFFER_SEGMENTS - 1;

uchar_t read_char(gzFile *in, int pos)
{
   uchar_t ret;
   int bufpos, i;
   
   bufpos = (bufptr + pos)%BUFFER_SIZE; 
   check_buffer(in, bufpos);
   
   for(i = 0; i  < sizeof(uchar_t) ; i++) {
      bufpos = (bufptr + i + pos)%BUFFER_SIZE;
      check_buffer(in, bufpos);
      ((uchar_t *)&ret)[i] = buffer[bufpos];
   }   

   return ret;
}

ushort_t read_short(gzFile *in, int pos)
{
   ushort_t ret;
   int bufpos, i;
   
   bufpos = (bufptr + pos)%BUFFER_SIZE; 
   check_buffer(in, bufpos);
   
   for(i = 0; i  < sizeof(ushort_t) ; i++) {
      bufpos = (bufptr + i + pos)%BUFFER_SIZE;
      check_buffer(in, bufpos);
      ((uchar_t *)&ret)[i] = buffer[bufpos];
   }   

   return ret;
}


uint32_t read_int(gzFile *in, int pos)
{
   uint32_t ret;
   int bufpos, i;
   
   bufpos = (bufptr + pos)%BUFFER_SIZE; 
   check_buffer(in, bufpos);
   
   for(i = 0; i  < sizeof(uint32_t) ; i++) {
      bufpos = (bufptr + i + pos)%BUFFER_SIZE;
      check_buffer(in, bufpos);
      ((uchar_t *)&ret)[i] = buffer[bufpos];
   }   

   return ret;
}


/**
 * Return the size of the audit unit. The given audit unit number is
 * interpreted according to the following definitions: AUR_CHAR, AUR_SHORT,
 * AUR_INT32 and AUR_INT64. The size of the unit is returned, if an invalid
 * unit number has been provided, the functions returns 0. 
 * @param unit number of unit
 * @return size of audit unit
 */
uchar_t get_unit_size(uchar_t unit)
{
   switch (unit) {
   case AUR_CHAR:
      return sizeof(uchar_t);
   case AUR_SHORT:
      return sizeof(ushort_t);
   case AUR_INT32:
      return sizeof(uint32_t);
   case AUR_INT64:
      return sizeof(uint64_t);
   default:
      err_msg("Invalid audit unit.");
      return 0;
   }
}

/** 
 * Retrieve the size of the strings within the stream. The function looks
 * for num strings within the stream at the given position. The function
 * counts all used bytes and returns the space used by the strings and their
 * terminating null-characters.
 * @param in stream
 * @param pos position
 * @param num number of strings
 * @return size of strings within the stream
 */
uint32_t strings_size(gzFile * in, int pos, int num)
{
   int bufpos, i, bytes = 0;

   bufpos = (bufptr + pos)%BUFFER_SIZE;
   check_buffer(in, bufpos);

   for (i = 0; i < num; i++) {
      do {
	 bufpos = (bufptr + pos + bytes)%BUFFER_SIZE;
	 check_buffer(in, bufpos);
	 bytes++;
      } while (buffer[bufpos] != 0);
   }

   return bytes;
}

/**
 * Calculate the size of the given token. In case of a fixed size token the
 * size is returned, in case of dynamic tokens such as the path token, the
 * size of the dynamic parts are determined by reading information from the
 * screen. The sizes have been taken from audit.log(4).
 * @param id token id
 * @param in stream
 * @return size of token or -1 if no token could be found
 */
int get_token_size(gzFile *in, uchar_t id)
{
   int token_size, tmp;

   switch (id) {

   case AUT_HEADER32:
      token_size = 1 + 4 + 1 + 2 + 2 + 4 + 4;
      break;
   case AUT_HEADER32_EX:
      token_size = 1 + 4 + 1 + 2 + 2 + 2 + 4 + 4;
      tmp = read_short(in, 10);
      if (tmp == 16)
	 token_size += 16;
      else
	 token_size += 4;
      break;
   case AUT_HEADER64:
      token_size = 1 + 4 + 1 + 2 + 2 + 8 + 8;
      break;
   case AUT_HEADER64_EX:
      token_size = 1 + 4 + 1 + 2 + 2 + 2 + 8 + 8;
      tmp = read_short(in, 10);
      if (tmp == 16)
	 token_size += 16;
      else
	 token_size += 4;
      break;
   case AUT_OTHER_FILE64:
   case AUT_OTHER_FILE32:
      token_size = 1 + 4 + 4 + 2;
      token_size += read_short(in, token_size - 2);
      break;
   case AUT_ATTR:
      token_size = 1 + 4 + 4 + 4 + 8 + 4;
      break;
   case AUT_ATTR32:
      token_size = 1 + 4 + 4 + 4 + 4 + 8 + 4;
      break;
   case AUT_ATTR64:
      token_size = 1 + 4 + 4 + 4 + 4 + 8 + 8;
      break;
   case AUT_PROCESS32:
   case AUT_SUBJECT32:
      token_size = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4;
      break;
   case AUT_PROCESS32_EX:
   case AUT_SUBJECT32_EX:
      token_size = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 2;
      tmp = read_short(in, token_size - 2);
      if (tmp == 16)
	 token_size += 16;
      else
	 token_size += 4;
      break;
   case AUT_PROCESS64:
   case AUT_SUBJECT64:
      token_size = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + 4;
      break;
   case AUT_PROCESS64_EX:
   case AUT_SUBJECT64_EX:
      token_size = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + 2;
      tmp = read_short(in, token_size - 2);
      if (tmp == 16)
	 token_size += 16;
      else
	 token_size += 4;
      break;
   case AUT_RETURN32:
      token_size = 1 + 1 + 4;
      break;
   case AUT_RETURN64:
      token_size = 1 + 1 + 8;
      break;
   case AUT_TRAILER:
      token_size = 1 + 2 + 4;
      break;
   case AUT_ARG32:
      token_size = 1 + 1 + 4 + 2;
      token_size += read_short(in, token_size - 2);
      break;
   case AUT_ARG64:
      token_size = 1 + 1 + 8 + 2;
      token_size += read_short(in, token_size - 2);
      break;
   case AUT_PATH:
   case AUT_TEXT:
      token_size = 1 + 2;
      token_size += read_short(in, token_size - 2);
      break;
   case AUT_EXEC_ARGS:
   case AUT_EXEC_ENV:
      token_size = 1 + 4;
      tmp = read_int(in, token_size - 4);
      token_size += strings_size(in, token_size, tmp);
      break;
   case AUT_SEQ:
   case AUT_IN_ADDR:
      token_size = 1 + 4;
      break;
   case AUT_IN_ADDR_EX:
      token_size = 1 + 2;
      tmp = read_short(in, token_size - 2);
      if (tmp == 16)
	 token_size += 16;
      else
	 token_size += 4;
      break;
   case AUT_IPORT:
      token_size = 1 + 2;
      break;
   case AUT_SOCKET:
      token_size = 1 + 2 + 2 + 4;
      break;
   case AUT_SOCKET_EX:
      token_size = 1 + 2 + 2 + 2 + 2 + 2;
      tmp = read_short(in, 5);
      if (tmp == 16)
	 token_size += 16 * 2;
      else
	 token_size += 4 * 2;
      break;
   case AUT_IP:
      token_size = 1 + 1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 4;
      break;
   case AUT_GROUPS:
      token_size = 1 + 2;
      token_size += read_short(in, token_size - 2) * 4;
      break;
   case AUT_EXIT:
      token_size = 1 + 4 + 4;
      break;
   case AUT_IPC_PERM:
      token_size = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4;
      break;
   case AUT_IPC:
      token_size = 1 + 1 + 4;
      break;
   case AUT_DATA:
      token_size = 1 + 1 + 1 + 1;
      tmp = read_char(in, token_size - 1);
      token_size += tmp * get_unit_size(read_char(in, token_size - 2));
      break;
   default:
      err_msg("Unknown token ID 0x%.2x at %ld.", id, gztell(in));
      fprintf(stderr, "Token ID trace: ");
      for(tmp = 0; tmp < TRACE_SIZE ; tmp++) {
         fprintf(stderr, " ID 0x%2.x ", trace[(trace_ptr + tmp)%TRACE_SIZE]);
         if(tmp <  TRACE_SIZE - 1) 
            fprintf(stderr, "->");
      }
      fprintf(stderr, "\n");
      exit(0);
      token_size = -1;
   }
   return token_size;
}

int check_buffer(gzFile *in, int pos)
{
   int bufpos, r, ret;

   if(pos/BUFFER_SEG_SIZE <= bufseg && 
      bufseg - pos/BUFFER_SEG_SIZE < BUFFER_SEGMENTS - 1)
      return 1;

   if(pos/BUFFER_SEG_SIZE == BUFFER_SEGMENTS - 1 &&
      bufseg == 0)
      return 1; 

   r = 0;
   
   while(pos/BUFFER_SEG_SIZE != bufseg) {
      bufseg = (bufseg + 1) % BUFFER_SEGMENTS;
      r++;

      ret = gzread(in, buffer + bufseg * BUFFER_SEG_SIZE, BUFFER_SEG_SIZE);
      if(ret == -1) {
         err_msg("gzread: %s", gzerror(in, &errnum));
         return 0;
      }
      
      if(r > BUFFER_SEGMENTS) {
         err_msg("Read beyond buffer space. Oops.");
         return 0;
      }
      
      if(ret != BUFFER_SEG_SIZE || gzeof(in))
         eof_flag = 1;
   }
   
   return 1;
}

void bsm_reset(gzFile *in)
{
   gzseek(in, 0, SEEK_SET);
   bufptr = 0;
   bufseg = BUFFER_SEGMENTS - 1;
   eof_flag = 0;
}

/**
 * Read a token from the stream and place it in the buffer. The argument
 * len initially contains the length of the given buffer. If the buffer
 * is too small the function aborts, otherwise the token is read into
 * the buffer and the actual token size is written into the len argument.
 * @param in stream
 * @param buf buffer for token
 * @param len length of buffer
 * @return 1 on success or 0 on failure
 */
int bsm_read(gzFile * in, char *buf, int *len)
{
   uchar_t token_id;
   int size, i;

   if(bsm_eof(in)) 
      return 1;
   
   check_buffer(in, bufptr);
   token_id = buffer[bufptr];
   trace[trace_ptr] = token_id;
   trace_ptr = (trace_ptr + 1) % TRACE_SIZE;
   size = get_token_size(in, token_id);

   if (size > *len) {
      err_msg("Buffer of size %d to small for event of size %d.",
	      *len, size);
      return 0;
   }
   
   for(i = 0; i < size; i++) {
      check_buffer(in, bufptr);
      buf[i] = buffer[bufptr];
      bufptr = (bufptr + 1) % BUFFER_SIZE;
   }
   *len = size;

   return 1;
}

/**
 * Write a token from the buffer to a stream
 * @param zout compressed stream
 * @param out stream
 * @param buf buffer containing token
 * @param len length of token
 * @return 1 on success or 0 on failure
 */
int bsm_write(gzFile * zout, FILE * out, char *buf, int len)
{

   if (len == 0)
      return 1;

   if (zout) {
      if (gzwrite(zout, buf, len) != len) {
	 err_msg("gzwrite: %s", gzerror(zout, &errnum));
	 return 0;
      }
   }

   if (out) {
      if (fwrite(buf, len, 1, out) != 1) {
	 err_msg("fwrite");
	 return 0;
      }
   }

   return 1;
}

int bsm_check(gzFile *in, char *filename) 
{
   int len;
   char buf[128];   

   len = 128;

   bsm_read(in, buf, &len);  

   gzseek(in, 0, SEEK_SET);
   if (buf[0] != AUT_OTHER_FILE32 && buf[0] != AUT_OTHER_FILE64) {
      err_msg("Skipping %s, not a Solaris BSM audit log", filename);
      return 0;
   }

   return 1;
}

int bsm_eof(gzFile *in) 
{
   if(gzeof(in) || eof_flag)
      return 1;
      
   return 0;   
}
