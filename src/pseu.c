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
 * $Id: pseu.c,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

/** 
 * @file pseu.c Anonymize functions. 
 * This file contains routines to pseudonymize uids, gids, pids, pathnames and
 * inet addresses. The mapping is kept within hash tables and might be saved
 * to a file in order to reconstruct the original audit logs.
 *
 * @author Konrad Rieck
 * @version $Id: pseu.c,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>

#include "misc.h"
#include "hash.h"
#include "pseu.h"
#include "bsm.h"
#include "rand.h"
#include "config.h"

extern int verbose;
extern int pseudonymize_pids, pseudonymize_uids, pseudonymize_gids;
extern int pseudonymize_time, pseudonymize_paths, pseudonymize_addrs;
extern int pseudonymize_args;

/*
 * Global and static variables
 */
static hash_table_t *uid_hash;		/**< Hash table for uid mapping */
static hash_table_t *gid_hash;		/**< Hash table for gid mapping */
static hash_table_t *pid_hash;		/**< Hash table for pid mapping */
static hash_table_t *path_hash;		/**< Hash table for path mapping */
static hash_table_t *addr_hash;		/**< Hash table for address mapping */

static uid_t uid_min, uid_max;		/**< Minimum and maximum uid */
static gid_t gid_min, gid_max;		/**< Minimum and maximum gid */
static pid_t pid_min, pid_max;		/**< Minimum and maximum pid */
static char **pathnames;		/**< List of pathname prefixes */
static long shift_max;			/**< Maximum time shift */

static long byte_count;			/**< Counts written bytes */


/**
 * Init the pseudonymize routines. Allocate memory for the different hash
 * tables used. The return value indicates if the initialing process and
 * allocation process was successful. All hash tables use the move to front
 * heuristic, due to the fact that uids, pids, etc... often appear in
 * redudant blocks.
 * @param umi uid minimum
 * @param uma uid maximum
 * @param gmi gid minimum
 * @param gma gid maximum
 * @param pmi pid mimimum
 * @param pma pid maximum
 * @param list list of pathname prefixes
 * @param timeshift maximum time shift
 * @return 1 on success or 0 on failure.
 */
int pseu_init(int umi, int uma, int gmi, int gma, int pmi, int pma,
	      char **list, long timeshift)
{
   uid_hash = hash_create(UID_HASH_SIZE, NULL, HEU_MOVE_TO_FRONT);
   gid_hash = hash_create(GID_HASH_SIZE, NULL, HEU_MOVE_TO_FRONT);
   pid_hash = hash_create(PID_HASH_SIZE, NULL, HEU_MOVE_TO_FRONT);

   path_hash = hash_create(PATH_HASH_SIZE, NULL, HEU_MOVE_TO_FRONT);
   addr_hash = hash_create(ADDR_HASH_SIZE, NULL, HEU_MOVE_TO_FRONT);

   uid_min = umi;
   uid_max = uma;
   gid_min = gmi;
   gid_max = gma;
   pid_min = pmi;
   pid_max = pma;

   pathnames = list;

   if (!uid_hash || !gid_hash || !path_hash || !addr_hash)
      return 0;

   byte_count = 0;

   if (timeshift != 0)
      shift_max = lrand48() % timeshift;

   

   return 1;
}

/** 
 * Deinit the pseudonymize routines. Free the memory allocated 
 * for the hash tables and their entries. 
 */
void pseu_deinit()
{
   hash_iterator_t i;
   void *p;

   for (p = hash_first(uid_hash, &i); p; p = hash_next(uid_hash, &i)) {
      free(p);
   }
   hash_finalize(uid_hash);

   for (p = hash_first(gid_hash, &i); p; p = hash_next(gid_hash, &i)) {
      free(p);
   }
   hash_finalize(gid_hash);

   for (p = hash_first(path_hash, &i); p; p = hash_next(path_hash, &i)) {
      free(p);
   }
   hash_finalize(path_hash);

   for (p = hash_first(addr_hash, &i); p; p = hash_next(addr_hash, &i)) {
      free(p);
   }
   hash_finalize(addr_hash);

   for (p = hash_first(pid_hash, &i); p; p = hash_next(pid_hash, &i)) {
      free(p);
   }
   hash_finalize(pid_hash);
}

/**
 * Anonymize the given uid. The functions checks if the given uid has
 * already been mapped to an pseudonymous uid. If no mapping has been done a
 * new random uid is created and the mapping is saved to the uid hash table.
 * @param u Pointer to a uid of type uid_t
 */
void pseu_uid(uchar_t * u)
{
   uid_t *uid_ptr, uid, tuid;

#if defined(_BIG_ENDIAN) || defined(WORDS_BIGENDIAN)
   tuid = (u[0] << 24) + (u[1] << 16) + (u[2] << 8) + u[3];
#else
   tuid = (u[3] << 24) + (u[2] << 16) + (u[1] << 8) + u[0];
#endif

   if (tuid < uid_min || tuid > uid_max)
      return;

   uid_ptr = hash_get(uid_hash, sizeof(uid_t), u);
   if (!uid_ptr) {

      uid = uid_rand(uid_min, uid_max);

      /*
       * Insert new uid into hash
       */
      uid_ptr = (uid_t *) malloc(sizeof(uid_t));
      memcpy(uid_ptr, &uid, sizeof(uid_t));
      hash_insert(uid_hash, uid_ptr, sizeof(uid_t), u);

      if (verbose)
	 fprintf(stderr, "[map] uid %6ld -> %6lu (%u of %u)\n", tuid, uid,
		 uid_hash->i_items, uid_hash->i_size);

   }

   memcpy(u, uid_ptr, sizeof(uid_t));
}

/**
 * Anonymize the given gid. The functions checks if the given gid has
 * already been mapped to an pseudonymous gid. If no mapping has been done a
 * new random gid is created and the mapping is saved to the gid hash table
 * @param g Pointer to a gid of type gid_t
 */
void pseu_gid(uchar_t * g)
{
   gid_t *gid_ptr, gid, tgid;

#if defined(_BIG_ENDIAN) || defined(WORDS_BIGENDIAN)
   tgid = (g[0] << 24) + (g[1] << 16) + (g[2] << 8) + g[3];
#else
   tgid = (g[3] << 24) + (g[2] << 16) + (g[1] << 8) + g[0];
#endif

   if (tgid < gid_min || tgid > gid_max)
      return;

   gid_ptr = hash_get(gid_hash, sizeof(gid_t), g);
   if (!gid_ptr) {
      gid = gid_rand(gid_min, gid_max);

      /*
       * Insert new gid into hash
       */
      gid_ptr = (gid_t *) malloc(sizeof(gid_t));
      memcpy(gid_ptr, &gid, sizeof(gid_t));
      hash_insert(gid_hash, gid_ptr, sizeof(gid_t), g);

      if (verbose)
	 fprintf(stderr, "[map] gid %6ld -> %6lu (%u of %u)\n", tgid, gid,
		 gid_hash->i_items, gid_hash->i_size);
   }

   memcpy(g, gid_ptr, sizeof(gid_t));
}

/**
 * Anonymize the given pid. The functions checks if the given pid has
 * already been mapped to an pseudonymous pid. If no mapping has been done a
 * new random pid is created and the mapping is saved to the pid hash table.
 * @param p Pointer to a pid of type pid_t
 */
void pseu_pid(uchar_t * p)
{
   pid_t *pid_ptr, pid, tpid;

#if defined(_BIG_ENDIAN) || defined(WORDS_BIGENDIAN)
   tpid = (p[0] << 24) + (p[1] << 16) + (p[2] << 8) + p[3];
#else
   tpid = (p[3] << 24) + (p[2] << 16) + (p[1] << 8) + p[0];
#endif

   if (tpid < pid_min || tpid > pid_max)
      return;

   pid_ptr = hash_get(pid_hash, sizeof(pid_t), p);
   if (!pid_ptr) {
      pid = pid_rand(pid_min, pid_max);

      /*
       * Insert new pid into hash
       */
      pid_ptr = (pid_t *) malloc(sizeof(pid_t));
      memcpy(pid_ptr, &pid, sizeof(pid_t));
      hash_insert(pid_hash, pid_ptr, sizeof(pid_t), p);

      if (verbose)
	 fprintf(stderr, "[map] pid %6ld -> %6lu (%u of %u)\n", tpid, pid,
		 pid_hash->i_items, pid_hash->i_size);

   }

   memcpy(p, pid_ptr, sizeof(pid_t));
}

/**
 * Anonymize all types of ids in the given buffer. The buffer contains a BSM
 * token that can be identified by interpreting the first byte of the
 * buffer. According to the type of token ids within the buffer are replaced
 * by randomized ids.
 * @param buf Buffer containing a BSM token.
 */
void pseu_ids(uchar_t * buf)
{
   uchar_t token_id;
   uchar_t i;

   token_id = buf[0];

   switch (token_id) {

      /*
       * Tokens that contain ids in the following order, the size of each
       * component is added in brackts.  token_id(1), audit_id(4), euid(4),
       * egid(4), uid(4), gid(4), pid(4). The audit_id often represents a uid,
       * that why it is also mapped to an pseudonym uid.
       */
   case AUT_SUBJECT32:
   case AUT_SUBJECT64:
   case AUT_PROCESS32:
   case AUT_PROCESS64:
   case AUT_SUBJECT32_EX:
   case AUT_SUBJECT64_EX:
   case AUT_PROCESS32_EX:
   case AUT_PROCESS64_EX:
      if (pseudonymize_uids)
         pseu_uid(buf + 1);
         
      if (pseudonymize_uids)
         pseu_uid(buf + 5);
      if (pseudonymize_gids)
         pseu_gid(buf + 9);
      if (pseudonymize_uids)
         pseu_uid(buf + 13);
      if (pseudonymize_gids)      
         pseu_gid(buf + 17);

      if (pseudonymize_pids)
	 pseu_pid(buf + 21);

      break;

      /*
       * Tokens that contain file owner ids. The ids appear in the following
       * order, the size of each component is added in brackts. token_id(1),
       * file_mode(4), owner_uid(4), owner_gid(4).
       */
   case AUT_ATTR32:
   case AUT_ATTR64:

      if (pseudonymize_uids)
         pseu_uid(buf + 5);
      if (pseudonymize_gids)
         pseu_gid(buf + 9);

      break;

      /*
       * The interprocess communication permission are one of the rather
       * seldom tokens, but anyway ... The ids appear in the following
       * order, the size of each component is added in brackts. token_id(1),
       * euid(4), egid(4), uid(4), gid(4).
       */
   case AUT_IPC_PERM:

      if (pseudonymize_uids)
         pseu_uid(buf + 1);
      if (pseudonymize_gids)
         pseu_gid(buf + 5);
      if (pseudonymize_uids)
         pseu_uid(buf + 9);
      if (pseudonymize_gids)      
         pseu_gid(buf + 13);

      break;
   }
}

/**
 * Anonymize the internet address. The address can be IPv4 or IPv6 as
 * long as the correct size is supplied. The address 0.0.0.0 is not
 * pseudonymized since it refers to the local host.
 * @see addr_rand
 * @param addr Buffer for internet address
 * @param len Length of address, usually 4 or 16.
 */
void pseu_addr(uchar_t * addr, ushort_t * len)
{
   uchar_t *addr_ptr, buf1[46], buf2[46];
   ushort_t length = *len, i, c;

   c = 0;
   for (i = 0; i < length; i++)
      c += addr[i];

   if (c == 0)
      return;

   addr_ptr = hash_get(addr_hash, length, addr);
   if (!addr_ptr) {
      /*
       * Insert new inet addr into hash
       */
      addr_ptr = (uchar_t *) malloc(length);
      addr_ptr = addr_rand(length, addr_ptr);
      hash_insert(addr_hash, addr_ptr, length, addr);

      if (verbose) {
	 if (length == 16)
	    i = AF_INET6;
	 else
	    i = AF_INET;

	 inet_ntop(i, addr, buf1, 46);
	 inet_ntop(i, addr_ptr, buf2, 46);

	 fprintf(stderr, "[map] addr %s -> %s (%u of %u)\n", buf1, buf2,
		 addr_hash->i_items, addr_hash->i_size);
      }
   }
   memcpy(addr, addr_ptr, length);
}

/**
 * Anonymize all inet addresses in the given buffer.  The buffer contains a
 * BSM token that can be identified by interpreting the first byte of the
 * buffer. According to the type of token inet addresses within the buffer are replaced
 * by randomized inet addresses.
 * @param buf Buffer containing a BSM token.
 */
void pseu_addrs(uchar_t * buf)
{
   uchar_t token_id;
   ushort_t tmp;

   token_id = buf[0];

   switch (token_id) {

   case AUT_HEADER32_EX:
   case AUT_HEADER64_EX:
      fprintf(stderr, "Extended header support not implemented\n");
      exit(EXIT_FAILURE);

      pseu_addr(buf + 12, (ushort_t *) buf + 10);
      break;
   case AUT_IP:
      break;
   case AUT_PROCESS32:
   case AUT_SUBJECT32:
      tmp = 4;
      pseu_addr(buf + 33, &tmp);
      break;
   case AUT_PROCESS64:
   case AUT_SUBJECT64:
      tmp = 4;
      pseu_addr(buf + 37, &tmp);
      break;
   case AUT_PROCESS32_EX:
   case AUT_SUBJECT32_EX:
      fprintf(stderr, "Extended subject(32) support not implemented\n");
      exit(EXIT_FAILURE);

      pseu_addr(buf + 35, (ushort_t *) buf + 33);
      break;
   case AUT_PROCESS64_EX:
   case AUT_SUBJECT64_EX:
      fprintf(stderr, "Extended subject(64) support not implemented\n");
      exit(EXIT_FAILURE);

      pseu_addr(buf + 39, (ushort_t *) buf + 37);
      break;
   case AUT_SOCKET:
      tmp = 4;
      pseu_addr(buf + 5, &tmp);
      break;
   case AUT_SOCKET_EX:
      tmp = *(buf + 7);
      pseu_addr(buf + 9, &tmp);
      pseu_addr(buf + 9 + tmp, &tmp);
      break;
   }
}

/**
 * Anonymize a path. Leading slashes are removed from the path, then the
 * function checks if the path matches on of the prefixes in pathnames[]. 
 * If it matches the matching path is pseudonymized
 * @see str_rand
 * @param tpath buffer containg pathname
 */
void pseu_path(uchar_t * tpath)
{
   uchar_t *path_ptr, *path;
   ushort_t i;
   int j;

   path = tpath;
   while (path[0] == '/' && path[1] == '/')
      path++;

   j = -1;
   for (i = 0; j == -1 && pathnames[i]; i++) {
      if (!strncmp(pathnames[i], path, strlen(pathnames[i]))) {
	 j = i;
      }
   }

   if (j == -1)
      return;

   path_ptr = hash_get(path_hash, strlen(path) + 1, path);
   if (!path_ptr) {
      /*
       * Insert new path into hash
       */
      path_ptr = strdup(path);
      str_rand(path_ptr + strlen(pathnames[j]), strlen(path) -
	       strlen(pathnames[j]));
      hash_insert(path_hash, path_ptr, strlen(path) + 1, path);

      if (verbose) {
	 fprintf(stderr, "[map] path %s -> %s (%u of %u)\n", path, path_ptr,
		 path_hash->i_items, path_hash->i_size);

      }
   }
   memcpy(path, path_ptr, strlen(path) + 1);
}


/**
 * Anonymize all pathnames in the given buffer.  The buffer contains a BSM
 * token that can be identified by interpreting the first byte of the
 * buffer. According to the type of token pathnames within the buffer are
 * replaced by randomized pathnames.
 * @param buf Buffer containing a BSM token.
 */
void pseu_paths(uchar_t * buf)
{
   uchar_t token_id;

   token_id = buf[0];

   switch (token_id) {
   case AUT_TEXT:
   case AUT_PATH:
      pseu_path(buf + 3);
      break;
   }
}

void pseu_time(uchar_t * b)
{
   long time;
#if defined(_BIG_ENDIAN) || defined(WORDS_BIGENDIAN)
   time = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3];
#else
   time = (b[3] << 24) + (b[2] << 16) + (b[1] << 8) + b[0];
#endif

   time -= shift_max;

   memcpy(b, &time, 4);
}

/**
 * Anonymize all timestamps in the given buffer.  The buffer contains a BSM
 * token that can be identified by interpreting the first byte of the
 * buffer. According to the type of token timestamps within the buffer are
 * replaced by randomly shifted timestamps.
 * @param buf Buffer containing a BSM token.
 */
void pseu_times(uchar_t * buf)
{
   uchar_t token_id;

   token_id = buf[0];

   switch (token_id) {
   case AUT_OTHER_FILE32:
   case AUT_OTHER_FILE64:
      pseu_time(buf + 1);
      break;
   case AUT_HEADER32:
      pseu_time(buf + 10);
      break;
   case AUT_HEADER64:
      pseu_time(buf + 14);
      break;
   case AUT_HEADER32_EX:
      fprintf(stderr, "Extended header(32) support not implemented\n");
      exit(EXIT_FAILURE);
      break;
   case AUT_HEADER64_EX:
      fprintf(stderr, "Extended header(64) support not implemented\n");
      exit(EXIT_FAILURE);
      break;
   }
}

/**
 * Clear the content of the exex args/env. 
 * @param buf buffer containg args/env
 * @param s pointer to the number of strings (4 byte).
 */
void pseu_arg(uchar_t * buf, uchar_t * s)
{
   uint32_t count, i, j;

#if defined(_BIG_ENDIAN) || defined(WORDS_BIGENDIAN)
   count = (s[0] << 24) + (s[1] << 16) + (s[2] << 8) + s[3];
#else
   count = (s[3] << 24) + (s[2] << 16) + (s[1] << 8) + s[0];
#endif

   j = 0;
   for (i = 0; i < count; i++, j++) {
      while (buf[j])
	 buf[j++] = ' ';
   }
}

/**
 * Anonymize all exec arguments and environment in the given buffer.  The
 * buffer contains a BSM token that can be identified by interpreting the
 * first byte of the buffer. According to the type of token arguments
 * and environment are filled with spaces.
 * @param buf Buffer containing a BSM token.
 */
void pseu_args(uchar_t * buf)
{
   uchar_t token_id;

   token_id = buf[0];

   switch (token_id) {
   case AUT_EXEC_ENV:
   case AUT_EXEC_ARGS:
      pseu_arg(buf + 5, buf + 1);
      break;
   }
}

/**
 * Read token from stream, pseudonymize the token and write it the output
 * stream. Tokens that contain data to be pseudonymized are passed to the
 * corresponding functions and are then written the output streams.
 * @param in input stream
 * @param zout compressed output stram
 * @param out output stream
 * @return 1 on success or 0 on failure.
 */
int pseu_token(gzFile * in, gzFile * zout, FILE * out)
{
   uchar_t buf[BUFFER_SEG_SIZE];
   int len;

   len = BUFFER_SEG_SIZE;
   if (!bsm_read(in, buf, &len))
      return 0;

   if (pseudonymize_uids || pseudonymize_gids || pseudonymize_pids)
      pseu_ids(buf);

   if (pseudonymize_addrs)
      pseu_addrs(buf);

   if (pseudonymize_paths)
      pseu_paths(buf);

   if (pseudonymize_time)
      pseu_times(buf);

   if (pseudonymize_args)
      pseu_args(buf);

   if (!bsm_write(zout, out, buf, len))
      return 0;

   byte_count += len;
   if (byte_count >= 5000000) {
      if (out)
	 fflush(out);

      if (zout)
	 gzflush(zout, Z_SYNC_FLUSH);
	 
      byte_count = 0;
   }

   return 1;
}
