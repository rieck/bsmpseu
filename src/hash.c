/*
 * Copyright (C) 2001-2002,  Simon Kagstrom
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
 * $Id: hash.c,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

#include <stdlib.h>		/* malloc */
#include <stdio.h>		/* perror */
#include <errno.h>		/* errno */
#include <string.h>		/* memcmp */
#include <assert.h>		/* assert */

#include "hash.h"

/* Flags for the elements. This is currently unused. */
#define FLAGS_NONE     0	/* No flags */
#define FLAGS_NORMAL   0	/* Normal item. All user-inserted stuff is normal */
#define FLAGS_INTERNAL 1	/* The item is internal to the hash table */

/* Prototypes */
static void transpose(hash_table_t * p_ht, unsigned int l_bucket,
		      hash_entry_t * p_entry);
static void move_to_front(hash_table_t * p_ht, unsigned int l_bucket,
			  hash_entry_t * p_entry);
static void free_entry_chain(hash_table_t * p_ht, hash_entry_t * p_entry);
static hash_entry_t *search_in_bucket(hash_table_t * p_ht,
				      unsigned int l_bucket,
				      hash_entry_t * p_entry,
				      hash_key_t * p_key,
				      unsigned char i_heuristics);

static void hk_fill(hash_key_t * p_hk, int i_size, void *p_key);
static hash_entry_t *he_create(hash_table_t * p_ht, void *p_data,
			       unsigned int i_key_size, void *p_key_data);
static void he_finalize(hash_table_t * p_ht, hash_entry_t * p_he);
static int ht_insert_internal(hash_table_t * p_ht, void *p_entry_data,
			      unsigned int i_key_size, void *p_key_data,
			      unsigned char i_flags);

/* --- private methods --- */

/* One-at-a-time hash (found in a web article from ddj), this is the
 * standard hash function.
 *
 * See http://burtleburtle.net/bob/hash/doobs.html
 * for the hash functions used here.
 */
unsigned int hash_one_at_a_time_hash(hash_key_t * p_key)
{
   unsigned int i_hash = 0;
   int i;

   assert(p_key);

   for (i = 0; i < p_key->i_size; ++i) {
      i_hash += ((unsigned char *) p_key->p_key)[i];
      i_hash += (i_hash << 10);
      i_hash ^= (i_hash >> 6);
   }
   i_hash += (i_hash << 3);
   i_hash ^= (i_hash >> 11);
   i_hash += (i_hash << 15);

   return i_hash;
}

/* Rotating hash function. */
unsigned int hash_rotating_hash(hash_key_t * p_key)
{
   unsigned int i_hash = 0;
   int i;

   assert(p_key);

   for (i = 0; i < p_key->i_size; ++i) {
      i_hash =
	  (i_hash << 4) ^ (i_hash >> 28) ^ ((unsigned char *) p_key->
					    p_key)[i];
   }

   return i_hash;
}

/* Move p_entry one up in its list. */
static void transpose(hash_table_t * p_ht, unsigned int l_bucket,
		      hash_entry_t * p_entry)
{
   /*
    *  __    __    __    __
    * |A_|->|X_|->|Y_|->|B_|
    *             /
    * =>        p_entry
    *  __    __/   __    __
    * |A_|->|Y_|->|X_|->|B_|
    */
   if (p_entry->p_prev) {	/* Otherwise p_entry is already first. */
      hash_entry_t *p_x = p_entry->p_prev;
      hash_entry_t *p_a = p_x ? p_x->p_prev : NULL;
      hash_entry_t *p_b = p_entry->p_next;

      if (p_a) {
	 p_a->p_next = p_entry;
      } else {			/* This element is now placed first */

	 p_ht->pp_entries[l_bucket] = p_entry;
      }

      if (p_b) {
	 p_b->p_prev = p_x;
      }
      if (p_x) {
	 p_x->p_next = p_entry->p_next;
	 p_x->p_prev = p_entry;
      }
      p_entry->p_next = p_x;
      p_entry->p_prev = p_a;
   }
}

/* Move p_entry first */
static void move_to_front(hash_table_t * p_ht, unsigned int l_bucket,
			  hash_entry_t * p_entry)
{
   /*
    *  __    __    __
    * |A_|->|B_|->|X_|
    *            /
    * =>  p_entry
    *  __/   __    __
    * |X_|->|A_|->|B_|
    */
   if (p_entry == p_ht->pp_entries[l_bucket]) {
      return;
   }

   /* Link p_entry out of the list. */
   p_entry->p_prev->p_next = p_entry->p_next;
   if (p_entry->p_next) {
      p_entry->p_next->p_prev = p_entry->p_prev;
   }

   /* Place p_entry first */
   p_entry->p_next = p_ht->pp_entries[l_bucket];
   p_entry->p_prev = NULL;
   p_ht->pp_entries[l_bucket]->p_prev = p_entry;
   p_ht->pp_entries[l_bucket] = p_entry;
}

/* Search for an element in a bucket */
static hash_entry_t *search_in_bucket(hash_table_t * p_ht,
				      unsigned int l_bucket,
				      hash_entry_t * p_entry,
				      hash_key_t * p_key,
				      unsigned char i_heuristics)
{
   if (p_entry == NULL) {
      return NULL;		/* Entry not in hash table. */
   }

   if ((p_entry->p_key->i_size == p_key->i_size) &&
       (memcmp(p_entry->p_key->p_key, p_key->p_key, p_entry->p_key->i_size)
	== 0)) {
      /* Matching entry found - Apply heuristics, if any */
      switch (i_heuristics) {
      case HEU_MOVE_TO_FRONT:
	 move_to_front(p_ht, l_bucket, p_entry);
	 break;
      case HEU_TRANSPOSE:
	 transpose(p_ht, l_bucket, p_entry);
	 break;
      default:
	 break;
      }

      return p_entry;
   }

   return search_in_bucket(p_ht, l_bucket, p_entry->p_next, p_key,
			   i_heuristics);
}

/* Free a chain of entries (in a bucket) */
static void free_entry_chain(hash_table_t * p_ht, hash_entry_t * p_entry)
{
   if (p_entry == NULL) {
      return;
   }
   free_entry_chain(p_ht, p_entry->p_next);

   /* Free the actual entry. */
   he_finalize(p_ht, p_entry);
}


/* Fill in the data to a existing hash key */
static void hk_fill(hash_key_t * p_hk, int i_size, void *p_key)
{
   assert(p_hk);

   p_hk->i_size = i_size;
   p_hk->p_key = p_key;
}

/* Create an hash entry */
static hash_entry_t *he_create(hash_table_t * p_ht, void *p_data,
			       unsigned int i_key_size, void *p_key_data)
{
   hash_entry_t *p_he;

   /*
    * An element like the following is allocated:
    *        elem->p_key
    *       /   elem->p_key->p_key_data
    *  ____|___/________
    * |elem|key|key data|
    * |____|___|________|
    *
    * That is, the key and the key data is stored "inline" within the
    * hash entry.
    *
    * This saves space since malloc only is called once and thus avoids
    * some fragmentation. Thanks to Dru Lemley for this idea.
    */
   if (!
       (p_he =
	p_ht->fn_alloc(sizeof(hash_entry_t) + sizeof(hash_key_t) +
		       i_key_size))) {
      fprintf(stderr, "fn_alloc failed!\n");
      return NULL;
   }

   p_he->p_data = p_data;
   p_he->p_next = NULL;
   p_he->p_prev = NULL;

   /* Create the key */
   p_he->p_key = (hash_key_t *) (p_he + 1);
   p_he->p_key->i_size = i_key_size;
   p_he->p_key->p_key = (void *) (p_he->p_key + 1);
   memcpy(p_he->p_key->p_key, p_key_data, i_key_size);

   return p_he;
}

/* Finalize (free) a hash entry */
static void he_finalize(hash_table_t * p_ht, hash_entry_t * p_he)
{
   assert(p_he);

   p_he->p_next = NULL;
   p_he->p_prev = NULL;

   /* Free the entry */
   p_ht->fn_free(p_he);
}

static int ht_insert_internal(hash_table_t * p_ht,
			      void *p_entry_data,
			      unsigned int i_key_size, void *p_key_data,
			      unsigned char i_flags)
{
   hash_entry_t *p_entry;
   unsigned int l_key;
   hash_key_t key;

   assert(p_ht);

   hk_fill(&key, i_key_size, p_key_data);
   l_key = p_ht->fn_hash(&key) & p_ht->i_size_mask;
   if (search_in_bucket(p_ht, l_key, p_ht->pp_entries[l_key], &key, 0)) {
      /* Don't insert if the key is already present. */
      return -1;
   }
   if (!(p_entry = he_create(p_ht, p_entry_data, i_key_size, p_key_data))) {
      return -2;
   }
   p_entry->i_flags = i_flags;

   /* Rehash if the number of items inserted is too high. */
   if (p_ht->i_automatic_rehash && p_ht->i_items > 2 * p_ht->i_size) {
      hash_rehash(p_ht, 2 * p_ht->i_size);
   }

   /* Place the entry first in the list. */
   p_entry->p_next = p_ht->pp_entries[l_key];
   p_entry->p_prev = NULL;
   if (p_ht->pp_entries[l_key]) {
      p_ht->pp_entries[l_key]->p_prev = p_entry;
   }
   p_ht->pp_entries[l_key] = p_entry;
   p_ht->p_nr[l_key]++;

   assert(p_ht->pp_entries[l_key] ? p_ht->pp_entries[l_key]->p_prev ==
	  NULL : 1);

   return 0;
}



/* --- Exported methods --- */
/* Create a new hash table */
hash_table_t *hash_create(unsigned int i_size, hash_fn_hash_t fn_hash,
			  int i_flags)
{
   hash_table_t *p_ht;
   int i = 0;

   if (!(p_ht = malloc(sizeof(hash_table_t)))) {
      perror("malloc");
      return NULL;
   }

   /* Set the size of the hash table to the nearest 2^i higher then i_size */
   p_ht->i_size = 0;
   while (p_ht->i_size < i_size) {
      p_ht->i_size = 1 << i++;
   }

   p_ht->i_size_mask = (1 << (i - 1)) - 1;	/* Mask to & with */
   p_ht->i_items = 0;

   if (!fn_hash) {
      p_ht->fn_hash = hash_one_at_a_time_hash;
   } else {
      p_ht->fn_hash = fn_hash;
   }

   /* Standard values for allocations */
   p_ht->fn_alloc = malloc;
   p_ht->fn_free = free;

   /* Parse flags */
   p_ht->i_heuristics = HEU_NONE;
   if (i_flags & HEU_TRANSPOSE) {
      p_ht->i_heuristics = HEU_TRANSPOSE;
   } else if (i_flags & HEU_MOVE_TO_FRONT) {
      p_ht->i_heuristics = HEU_MOVE_TO_FRONT;
   }
   p_ht->i_automatic_rehash = i_flags & AUTO_REHASH;

   /* Create an empty bucket list. */
   if (!(p_ht->pp_entries = malloc(p_ht->i_size * sizeof(hash_entry_t *)))) {
      perror("malloc");
      free(p_ht);
      return NULL;
   }
   memset(p_ht->pp_entries, 0, p_ht->i_size * sizeof(hash_entry_t *));

   /* Initialise the number of entries in each bucket to zero */
   if (!(p_ht->p_nr = malloc(p_ht->i_size * sizeof(int)))) {
      perror("malloc");
      free(p_ht->pp_entries);
      free(p_ht);
      return NULL;
   }
   memset(p_ht->p_nr, 0, p_ht->i_size * sizeof(int));

   return p_ht;
}

/* Set the allocation/deallocation function to use */
void hash_set_alloc(hash_table_t * p_ht, hash_fn_alloc_t fn_alloc,
		    hash_fn_free_t fn_free)
{
   p_ht->fn_alloc = fn_alloc;
   p_ht->fn_free = fn_free;
}

/* Set the hash function to use */
void hash_set_hash(hash_table_t * p_ht, hash_fn_hash_t fn_hash)
{
   p_ht->fn_hash = fn_hash;
}

/* Set the heuristics to use. */
void hash_set_heuristics(hash_table_t * p_ht, int i_heuristics)
{
   p_ht->i_heuristics = i_heuristics;
}

/* Set the rehashing status of the table. */
void hash_set_rehash(hash_table_t * p_ht, int b_rehash)
{
   p_ht->i_automatic_rehash = b_rehash;
}


/* Insert an entry into the hash table */
int hash_insert(hash_table_t * p_ht,
		void *p_entry_data,
		unsigned int i_key_size, void *p_key_data)
{
   int i_ret = ht_insert_internal(p_ht,
				  p_entry_data,
				  i_key_size, p_key_data,
				  FLAGS_NORMAL);
   if (!i_ret) {
      p_ht->i_items++;
   }
   return i_ret;
}

/* Get an entry from the hash table. The entry is returned, or NULL if it wasn't found */
void *hash_get(hash_table_t * p_ht,
	       unsigned int i_key_size, void *p_key_data)
{
   hash_entry_t *p_e;
   hash_key_t key;
   unsigned int l_key;

   assert(p_ht);

   hk_fill(&key, i_key_size, p_key_data);

   l_key = p_ht->fn_hash(&key) & p_ht->i_size_mask;
   p_e = p_ht->pp_entries[l_key];

   /* Check that the first element in the list really is the first. */
   assert(p_ht->pp_entries[l_key] ? p_ht->pp_entries[l_key]->p_prev ==
	  NULL : 1);

   p_e = search_in_bucket(p_ht, l_key, p_e, &key, p_ht->i_heuristics);
   return (p_e ? p_e->p_data : NULL);
}

/* Remove an entry from the hash table. The removed entry, or NULL, is
   returned (and NOT free'd). */
void *hash_remove(hash_table_t * p_ht,
		  unsigned int i_key_size, void *p_key_data)
{
   hash_entry_t *p_e;
   hash_entry_t *p_out;
   hash_key_t key;
   unsigned int l_key;
   void *p_ret = NULL;

   assert(p_ht);

   hk_fill(&key, i_key_size, p_key_data);
   l_key = p_ht->fn_hash(&key) & p_ht->i_size_mask;
   p_e = p_ht->pp_entries[l_key];

   /* Check that the first element really is the first */
   assert((p_ht->pp_entries[l_key] ? p_ht->pp_entries[l_key]->p_prev ==
	   NULL : 1));

   p_out = search_in_bucket(p_ht, l_key, p_e, &key, 0);

   /* Link p_out out of the list. */
   if (p_out) {
      if (p_out->p_prev) {
	 p_out->p_prev->p_next = p_out->p_next;
      } else {			/* first in list */

	 p_ht->pp_entries[l_key] = p_out->p_next;
      }
      if (p_out->p_next) {
	 p_out->p_next->p_prev = p_out->p_prev;
      }

      if (p_out->i_flags == FLAGS_NORMAL) {
	 p_ht->i_items--;
      }
      p_ht->p_nr[l_key]--;
      p_out->p_next = NULL;
      p_out->p_prev = NULL;

      p_ret = p_out->p_data;
      he_finalize(p_ht, p_out);
   }

   return p_ret;
}

/* Get the first entry in an iteration */
void *hash_first(hash_table_t * p_ht, hash_iterator_t * p_iterator)
{
   assert(p_ht && p_iterator);

   /* Fill the iterator */
   p_iterator->p_entry = p_ht->pp_entries[0];
   p_iterator->i_curr_bucket = 0;

   /* Step until non-empty bucket */
   for (; (p_iterator->i_curr_bucket < p_ht->i_size)
	&& !p_ht->pp_entries[p_iterator->i_curr_bucket];
	p_iterator->i_curr_bucket++);
   if (p_iterator->i_curr_bucket < p_ht->i_size) {
      p_iterator->p_entry = p_ht->pp_entries[p_iterator->i_curr_bucket];
   }

   return (p_iterator->p_entry ? p_iterator->p_entry->p_data : NULL);	/* Might be 0. */
}

/* Get the next entry in an iteration. You have to call hash_first
   once initially before you use this function */
void *hash_next(hash_table_t * p_ht, hash_iterator_t * p_iterator)
{
   assert(p_ht && p_iterator);

   if (p_iterator->p_entry && p_iterator->p_entry->p_next) {
      /* More entries in the current bucket */
      p_iterator->p_entry = p_iterator->p_entry->p_next;
      return p_iterator->p_entry->p_data;	/* We know that this is non-NULL */
   } else if (p_iterator->p_entry) {
      p_iterator->p_entry = NULL;
      p_iterator->i_curr_bucket++;
   }

   /* Step until non-empty bucket */
   for (; (p_iterator->i_curr_bucket < p_ht->i_size)
	&& !p_ht->pp_entries[p_iterator->i_curr_bucket];
	p_iterator->i_curr_bucket++);

   /* FIXME: Add someplace here:
    *  if (p_iterator->p_entry->i_flags & FLAGS_INTERNAL)
    *     return hash_next(p_ht, p_iterator);
    */
   if (p_iterator->i_curr_bucket < p_ht->i_size) {
      p_iterator->p_entry = p_ht->pp_entries[p_iterator->i_curr_bucket];
      return p_iterator->p_entry->p_data;
   } else {
      /* Last entry */
      p_iterator->i_curr_bucket = 0;
      p_iterator->p_entry = NULL;
      return NULL;
   }
}

/* Finalize (free) a hash table */
void hash_finalize(hash_table_t * p_ht)
{
   int i;

   assert(p_ht);

   if (p_ht->pp_entries) {
      /* For each bucket, free all entries */
      for (i = 0; i < p_ht->i_size; i++) {
	 free_entry_chain(p_ht, p_ht->pp_entries[i]);
	 p_ht->pp_entries[i] = NULL;
      }
      free(p_ht->pp_entries);
      p_ht->pp_entries = NULL;
   }
   if (p_ht->p_nr) {
      free(p_ht->p_nr);
      p_ht->p_nr = NULL;
   }

   free(p_ht);
}

/* Rehash the hash table (i.e. change its size and reinsert all
 * items). This operation is slow and should not be used frequently.
 *
 * FIXME: Does this work correctly? I think so, but I cannot give any
 * guarantees.
 */
void hash_rehash(hash_table_t * p_ht, unsigned int i_size)
{
   hash_table_t *p_tmp;
   hash_iterator_t iterator;
   void *p;
   int i;

   assert(p_ht);

   /* Recreate the hash table with the new size */
   p_tmp = hash_create(i_size, p_ht->fn_hash, 0);
   assert(p_tmp);

   /* Walk through all elements in the table and insert them into the temporary one. */
   for (p = hash_first(p_ht, &iterator); p; p = hash_next(p_ht, &iterator)) {
      assert(iterator.p_entry && iterator.p_entry->p_key);

      /* Insert the entry into the new table */
      if (ht_insert_internal(p_tmp,
			     iterator.p_entry->p_data,
			     iterator.p_entry->p_key->i_size,
			     iterator.p_entry->p_key->p_key,
			     iterator.p_entry->i_flags) < 0) {
	 fprintf(stderr,
		 "hash_table.c ERROR: Out of memory error or entry already in hash table\n"
		 "when rehashing (internal error)\n");
      }
      p_tmp->i_items++;
   }

   /* Remove the old table... */
   for (i = 0; i < p_ht->i_size; i++) {
      if (p_ht->pp_entries[i]) {
	 /* Delete the entries in the bucket */
	 free_entry_chain(p_ht, p_ht->pp_entries[i]);
	 p_ht->pp_entries[i] = NULL;
      }
   }

   free(p_ht->pp_entries);
   free(p_ht->p_nr);

   /* ... and replace it with the new */
   p_ht->i_size = p_tmp->i_size;
   p_ht->i_size_mask = p_tmp->i_size_mask;
   p_ht->i_items = p_tmp->i_items;
   p_ht->pp_entries = p_tmp->pp_entries;
   p_ht->p_nr = p_tmp->p_nr;

   /* Clean up */
   p_tmp->pp_entries = NULL;
   p_tmp->p_nr = NULL;
   free(p_tmp);
}

#ifdef USE_PROFILING
void hash_print(hash_table_t * p_ht)
{
   int i;
   int i_highest = 0;
   int i_cnt = 0;

   printf("Number of elements: %d\n", p_ht->i_items);
   for (i = 0; i < p_ht->i_size; i++) {
      if (p_ht->p_nr[i] > i_highest) {
	 i_highest = p_ht->p_nr[i];
      }
   }
   printf("Number of buckets: %d\n", p_ht->i_size);
   printf("Highest number of elements in bucket: %d\n", i_highest);
   printf("Elements per bucket: %.2f\n",
	  (double) p_ht->i_items / (double) p_ht->i_size);

   if (p_ht->i_size > 500) {
      return;
   }

   for (i = 1; i < p_ht->i_size; i++) {
      char tmp[80];
      sprintf(tmp, "%d ", p_ht->p_nr[i]);
      printf("%s", tmp);
      i_cnt += strlen(tmp);
      if (i_cnt >= 80) {
	 printf("\n");
	 i_cnt = 0;
      }
   }
   printf("\n");
}
#endif
