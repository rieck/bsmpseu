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
 * $Id: main.c,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

/**
 * @file main.c Main file of the bsmpseu tool.
 * 
 * @author Konrad Rieck
 * @version $Id: main.c,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "main.h"
#include "misc.h"
#include "rand.h"
#include "pseu.h"
#include "config.h"

/*
 * These variables are exported to other functions
 */
int zlib = 0, verbose = 0, blank_exec = 0, read_stdin = 0;
int pseudonymize_pids = 1, pseudonymize_uids = 1, pseudonymize_gids = 1;
int pseudonymize_time = 1, pseudonymize_paths = 1, pseudonymize_addrs = 1;
int pseudonymize_args = 1;

static uid_t uid_min = D_UID_MIN, uid_max = D_UID_MAX;
static gid_t gid_min = D_GID_MIN, gid_max = D_GID_MAX;
static pid_t pid_min = D_PID_MIN, pid_max = D_PID_MAX;
static long time_shift = D_SHIFT_MAX;
static char **path_patterns = default_prefixes;

extern char *optarg;
extern int optind, opterr;

/**
 * Boring function.
 */
void print_version()
{
   fprintf(stderr, "%s %s\n"
                   "Pseudonymizer for Solaris BSM Audit Logs, http://www.roqe.org/bsmpseu\n"
                   "Copyright 2002, 2003 Konrad Rieck <kr@roqe.org>\n", 
                   PACKAGE, VERSION);
}

/**
 * Guess what this functions does...
 */
void print_usage()
{
   int i;
   fprintf(stderr, "Usage: bsmpseu [options] [audit-trail-file...]\n"
	   "Options:\n"
	   "  -d list     Pseudonymize pathnames that match one of the prefixes from the\n"
	   "              colon-separated list. Trailing slashes are not appended.\n"
	   "              [Default:");
   for (i = 0; default_prefixes[i]; i++)
      fprintf(stderr, "%s:", default_prefixes[i]);
   fprintf(stderr, "\b]\n");

   fprintf(stderr,
           "  -D          Don't pseudonymize pathnames.\n"
	   "  -u min:max  Pseudonymize user IDs within the interval from min to max. \n"
	   "              [Default: %d:%d uid]\n"
	   "  -U          Don't pseudonymize user IDs.\n"
	   "  -g min:max  Pseudonymize group IDs within the interval from min to max. \n"
	   "              [Default: %d:%d gid]\n"
	   "  -G          Don't pseudonymize group IDs.\n"
	   "  -p min:max  Pseudonymize process IDs within the interval from min to max.\n"
	   "              [Default: %d:%d pid]\n"
	   "  -P          Don't pseudonymize process IDs.\n"
	   "  -s shift    Pseudonymize timestamps of audit records by shifting upto a\n"
	   "              maximum of seconds. [Default: %d seconds]\n"
	   "  -S          Don't pseudonymize timestamps of audit records.\n"
	   "  -A          Don't pseudonymize internet IPv4/IPv6 addresses.\n"
	   "  -E          Don't pseudonymize exec arguments and exec environment tokens.\n"
	   "  -z          Compress output stream using the zlib(3).\n"
	   "  -v          Display verbose information during pseudonymizing to stderr.\n"
	   "  -V          Display version information.\n", D_UID_MIN,
	   D_UID_MAX, D_GID_MIN, D_GID_MAX, D_PID_MIN, D_PID_MAX,
	   D_SHIFT_MAX);
}

/**
 * Parse options from the commandline.
 * @param argc Number of arguments
 * @param argv Array of arguments
 */
void parse_options(int argc, char **argv)
{
   char *str;
   int c, i;

   /*
    * Parse commandline options.
    */
   while ((c = getopt(argc, argv, "Dd:Uu:Gg:Pp:s:AEhvzV")) != EOF)
      switch (c) {
      case 'd':
	 c = 0;
	 for (i = 0; i < strlen(optarg); i++)
	    if (optarg[i] == ':')
	       c++;

	 path_patterns = (char **) malloc(sizeof(char *) * (c + 2));

	 i = 0;
	 str = strtok(optarg, ":");
	 while (str) {
	    path_patterns[i++] = strdup(str);
	    str = strtok(NULL, ":");
	 }
	 path_patterns[i] = NULL;
	 break;
      case 'D':
         pseudonymize_paths = 0;
         break;
      case 'p':
	 pid_min = atol(optarg);
	 str = strrchr(optarg, ':');
	 if (!str)
	    goto err;
	 pid_max = atol(str + 1);
	 break;
      case 'P':
         pseudonymize_pids = 0;	 
         break;
      case 'g':
	 gid_min = atol(optarg);
	 str = strrchr(optarg, ':');
	 if (!str)
	    goto err;
	 gid_max = atol(str + 1);
	 break;
      case 'G':
         pseudonymize_gids = 0;	 
         break;
      case 'u':
	 uid_min = atol(optarg);
	 str = strrchr(optarg, ':');
	 if (!str)
	    goto err;
	 uid_max = atol(str + 1);
	 break;
      case 'U':
         pseudonymize_uids = 0;	
         break;
      case 's':
	 time_shift = atol(optarg);
	 break;
      case 'S':
         pseudonymize_time = 0;	 
         break;
      case 'A':
	 pseudonymize_addrs = 0;
	 break;
      case 'E':
	 pseudonymize_args = 0;
	 break;
      case 'v':
	 verbose = 1;
	 break;
      case 'z':
	 zlib = 1;
	 break;
      case 'V':
	 print_version();
	 exit(EXIT_SUCCESS);
	 break;
       err:
      case 'h':
      default:
	 print_usage();
	 exit(EXIT_FAILURE);
      }

   /*
    * Do sanity checks, etc...
    */
   if (uid_min >= uid_max)
      pseudonymize_uids = 0;

   if (gid_min >= gid_max)
      pseudonymize_gids = 0;

   if (pid_min >= pid_max)
      pseudonymize_pids = 0;

   if (time_shift <= 0)
      pseudonymize_time = 0;
}

void print_config()
{
   int i;
   fprintf(stderr, "[pseudonymize]\n");
   fprintf(stderr, "   Pathnames:      %s", pseudonymize_paths ? "Yes" : "No ");

   fprintf(stderr, " [");
   for (i = 0; path_patterns[i]; i++)
      fprintf(stderr, "%s:", path_patterns[i]);
   fprintf(stderr, "\b]\n");

   fprintf(stderr, "   Process IDs:    %s", pseudonymize_pids ? "Yes" : "No ");
   fprintf(stderr, " [%ld:%ld pid]\n", pid_min, pid_max);

   fprintf(stderr, "   User IDs:       %s", pseudonymize_uids ? "Yes" : "No ");
   fprintf(stderr, " [%ld:%ld uid]\n", uid_min, uid_max);

   fprintf(stderr, "   Group IDs:      %s", pseudonymize_gids ? "Yes" : "No ");
   fprintf(stderr, " [%ld:%ld gid]\n", gid_min, gid_max);

   fprintf(stderr, "   Timestamps:     %s", pseudonymize_time ? "Yes" : "No ");
   fprintf(stderr, " [%ld seconds]\n", time_shift);

   fprintf(stderr, "   Inet addresses: %s\n",
	   pseudonymize_addrs ? "Yes" : "No ");
   fprintf(stderr, "   Exec args/anv:  %s\n",
	   pseudonymize_args ? "Yes" : "No ");
   fprintf(stderr, "\n");
}

/**
 * Another boring main function
 * @param argc the usual count
 * @param argv probably some overflowing strings
 * @return if we are lucky
 */
int main(int argc, char **argv)
{
   int ret;
   gzFile *in, *zout;
   FILE *out;

   parse_options(argc, argv);
   if (verbose)
      print_config();

   srand48(time(NULL));
   ret = pseu_init(uid_min, uid_max, gid_min, gid_max, pid_min,
		   pid_max, path_patterns, time_shift);
   if (!ret) {
      err_msg("Failed to allocate memory");
      exit(EXIT_FAILURE);
   }

   if (optind == argc) {
      read_stdin = 1;
      in = gzdopen(0, "rb");
   }

   if (zlib) {
      zout = gzdopen(1, "wb9");
      out = NULL;
   } else {
      zout = NULL;
      out = fdopen(1, "wb");
   }

   for (; read_stdin || optind < argc; optind++) {

      if (!read_stdin)
	 in = gzopen(argv[optind], "rb");

      if (!in) {
	 err_msg("Could not open %s", argv[optind] ? argv[optind] : "stdin");
	 exit(EXIT_FAILURE);
      }

      if(!bsm_check(in, !read_stdin ? argv[optind] : "stdin"))
         continue;

      bsm_reset(in);
      while (!bsm_eof(in))
	 pseu_token(in, zout, out);

      if(read_stdin)
         break;
   }

   pseu_deinit();

   for (ret = 0; path_patterns[ret]; ret++)
      free(path_patterns[ret]);

   free(path_patterns);

   return EXIT_SUCCESS;
}
