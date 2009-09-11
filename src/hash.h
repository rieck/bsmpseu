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
 * $Id: hash.h,v 3.1 2003/02/27 17:11:32 kr Exp $
 */

/**
 * @file
 * libghthash is a generic hash table used for storing arbitrary
 * data.
 *
 * Libghthash really stores pointers to data - the hash
 * table knows nothing about the actual type of the data.
 *
 * A simple example to get started can be found in the
 * <TT>example/simple.c</TT> file found in the distribution.
 * <TT>hash_test.c</TT> provides a more comlpete example.
 *
 * Some basic properties of the hash table are:
 *
 * - Both the data stored and the keys are of void type, which
 *   means that you can store any kind of data.
 *
 * - The only functions you probably will need to start is:
 *   - hash_create(), which creates a new hash table.d
 *   - hash_insert(), which inserts a new entry into a table.
 *   - hash_get(), which searches for an entry.
 *   - hash_remove(), which removes and entry.
 *   - hash_finalize(), which destroys a hash table.
 *
 * - Inserting entries is done without first creating a key,
 *   i.e. you insert with the data, the datasize, the key and the
 *   key size directly.
 *
 * - The hash table copies the key data when inserting new
 *   entries. This means that you should <I>not</I> malloc() the key
 *   before inserting a new entry.
 *
 */
#ifndef _HASH_H
#define _HASH_H

#include <stdlib.h>		/* size_t */

#define HEU_NONE          0
#define HEU_TRANSPOSE     1
#define HEU_MOVE_TO_FRONT 2
#define AUTO_REHASH         4

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/**
 * The structure for hash keys. You should not care about this
 * structure unless you plan to write your own hash functions.
 */
typedef struct s_hash_key {
   unsigned int i_size;	     /**< The size in bytes of the key p_key */
   void *p_key;		     /**< A pointer to the key. */
} hash_key_t;

/*
 * The structure for hash entries.
 */
typedef struct s_hash_entry {
   void *p_data;
   hash_key_t *p_key;

   struct s_hash_entry *p_next;
   struct s_hash_entry *p_prev;
   unsigned char i_flags;
} hash_entry_t;

/*
 * The structure used in iterations. You should not care about the
 * contents of this, it will be filled and updated by hash_first() and
 * hash_next().
 */
typedef struct {
   int i_curr_bucket;		/* The current bucket */
   hash_entry_t *p_entry;	/* The current entry */
} hash_iterator_t;

/**
 * Definition of the hash function pointers. @c hash_fn_hash_t should be
 * used when implementing new hash functions. Look at the supplied
 * hash functions, like @c hash_one_at_a_time_hash(), for examples of hash
 * functions.
 *
 * @param p_key the key to calculate the hash value for.
 *
 * @return a 32 bit hash value.
 *
 * @see @c hash_one_at_a_time_hash(), @c hash_rotating_hash(),
 *      @c hash_crc_hash()
 */
typedef unsigned int (*hash_fn_hash_t) (hash_key_t * p_key);

/**
 * Definition of the allocation function pointers. This is simply the
 * same definition as @c malloc().
 *
 * @param size the size to allocate. This will always be
 *        <TT>sizeof(hash_entry_t) + sizeof(hash_key_t) +
 *        key_size</TT>.
 *
 * @return a pointer to the allocated region, or NULL if the
 *         allocation failed.
 */
typedef void *(*hash_fn_alloc_t) (size_t size);

/**
 * Definition of the deallocation function pointers. This is simply the
 * same definition as @c free().
 *
 * @param ptr a pointer to the region to free.
 */
typedef void (*hash_fn_free_t) (void *ptr);


/**
 * The hash table structure.
 */
typedef struct {
   unsigned int i_items;	     /**< The current number of items in the table */
   unsigned int i_size;		     /**< The number of buckets */
   hash_fn_hash_t fn_hash;	      /**< The hash function used */
   hash_fn_alloc_t fn_alloc;	      /**< The function used for allocating entries */
   hash_fn_free_t fn_free;	      /**< The function used for freeing entries */
   int i_heuristics;		     /**< The type of heuristics used */
   int i_automatic_rehash;	     /**< TRUE if automatic rehashing is used */

   /* private: */
   hash_entry_t **pp_entries;
   int *p_nr;			/* The number of entries in each bucket */
   int i_size_mask;		/* The number of bits used in the size */
} hash_table_t;

/**
 * Create a new hash table. The number of buckets should be about as
 * big as the number of elements you wish to store in the table for
 * good performance. The number of buckets is rounded to the next
 * higher power of two.
 *
 * The possible flags are:
 *
 * - <TT>HEU_TRANSPOSE</TT>: Use transposing heuristics. An accessed
 *   element will move one step up in the bucket-list with this
 *   method. Cannot be combined with HEU_MOVE_TO_FRONT.
 * - <TT>HEU_MOVE_TO_FRONT</TT>: Use move-to-front heuristics. An
 *   accessed element will be moved the front of the bucket list
 *   with this method. Cannot be combined with HEU_TRANSPOSE.
 * - <TT>AUTO_REHASH</TT>: Perform automatic rehashing when
 *   the number of elements in the table are twice as many as the
 *   number of buckets. You should note that automatic rehashing
 *   will cause your application to be really slow when the table is
 *   rehashing (which might happen at times when you need speed),
 *   you should therefore be careful with this in time-constrainted
 *   applications.
 *
 * @param i_size the number of buckets in the hash table. Giving a
 *        non-power of two here will round the size up to the next
 *        power of two.
 * @param fn_hash the hash function to use (NULL for default). You can
 *        define own hash functions to use here, see the
 *        implementation of hash_one_at_a_time_hash() in
 *        <TT>hash_table.c</TT> for an example.
 * @param i_flags specify the flags to use. This should be bitwise or:ed.
 *        note that some options are mutually exclusive.
 *
 * @see hash_one_at_a_time_hash(), hash_rotating_hash(), hash_crc_hash()
 *
 * @return a pointer to the hash table or NULL upon error.
 */
hash_table_t *hash_create(unsigned int i_size, hash_fn_hash_t fn_hash,
			  int i_flags);

/**
 * Set the allocation/freeing functions to use for a hash table. The
 * allocation function will only be called when a new entry is
 * inserted.
 *
 * The allocation size will always be <TT>sizeof(hash_entry_t) +
 * sizeof(hash_key_t) + key_size</TT>. The actual size varies with
 * the key size.
 *
 * If this function is <I>not</I> called, @c malloc() and @c free()
 * will be used for allocation and freeing.
 *
 * @warning Always call this function before any entries are inserted
 *          into the table. Otherwise, the new free() might be called on
 *          something that were allocated with another allocation function.
 *
 * @param p_ht the hash table to set the memory management functions
 *        for.
 * @param fn_alloc the allocation function to use.
 * @param fn_free the deallocation function to use.
 */
void hash_set_alloc(hash_table_t * p_ht, hash_fn_alloc_t fn_alloc,
		    hash_fn_free_t fn_free);

/**
 * Set the hash function to use for a hash table.
 *
 * @warning Always call this function before any entries are inserted
 *          into the table. Otherwise, it will not be possible to find entries
 *          that were inserted before this function was called.
 *
 * @param p_ht the hash table set the hash function for.
 * @param fn_hash the hash function.
 */
void hash_set_hash(hash_table_t * p_ht, hash_fn_hash_t fn_hash);

/**
 * Set the heuristics to use for the hash table. The possible values are:
 *
 * - <TT>HEU_NONE</TT>: Don't use any heuristics.
 * - <TT>0</TT>: Same as above.
 * - <TT>HEU_TRANSPOSE</TT>: Use transposing heuristics. An
 *   accessed element will move one step up in the bucket-list with this
 *   method.
 * - <TT>HEU_MOVE_TO_FRONT</TT>: Use move-to-front
 *   heuristics. An accessed element will be moved the front of the
 *   bucket list with this method.
 *
 * @param p_ht the hash table set the heuristics for.
 * @param i_heuristics the heuristics to use.
 */
void hash_set_heuristics(hash_table_t * p_ht, int i_heuristics);

/**
 * Enable or disable automatic rehashing.
 *
 * With automatic rehashing, the table will rehash itself when the
 * number of elements in the table are twice as many as the number of
 * buckets. You should note that automatic rehashing will cause your
 * application to be really slow when the table is rehashing (which
 * might happen at times when you need speed), you should therefore be
 * careful with this in time-constrainted applications.
 *
 * @param p_ht the hash table to set rehashing for.
 * @param b_rehash TRUE if rehashing should be used or FALSE if it
 *        should not be used.
 */
void hash_set_rehash(hash_table_t * p_ht, int b_rehash);


/**
 * Insert an entry into the hash table. Prior to inserting anything,
 * make sure that the table is created with hash_create(). If an
 * element with the same key as this one already exists in the table,
 * the insertion will fail and -1 is returned.
 *
 * A typical example is shown below, where the string "blabla" is used
 * as a key for the integer 15.
 *
 * <PRE>
 * hash_table_t *p_table;
 * char *p_key_data;
 * int *p_data;
 *
 * [Create p_table etc...]
 * p_data = malloc(sizeof(int));
 * p_key_data = "blabla";
 * *p_data = 15;
 *
 * hash_insert(p_table,
 *            p_data,
 *            sizeof(char)*strlen(p_key_data), p_key_data);
 * </PRE>
 *
 * @param p_ht the hash table to insert into.
 * @param p_entry_data the data to insert.
 * @param i_key_size the size of the key to associate the data with (in bytes).
 * @param p_key_data the key to use. The value will be copied, and it
 *                   is therefore OK to use a stack-allocated entry here.
 *
 * @return 0 if the element could be inserted, -1 otherwise.
 */
int hash_insert(hash_table_t * p_ht,
		void *p_entry_data,
		unsigned int i_key_size, void *p_key_data);

/**
 * Lookup an entry in the hash table. The entry is <I>not</I> removed from
 * the table.
 *
 * @param p_ht the hash table to search in.
 * @param i_key_size the size of the key to search with (in bytes).
 * @param p_key_data the key to search for.
 *
 * @return a pointer to the found entry or NULL if no entry could be found.
 */
void *hash_get(hash_table_t * p_ht,
	       unsigned int i_key_size, void *p_key_data);

/**
 * Remove an entry from the hash table. The entry is removed from the
 * table, but not freed (that is, the data stored is not freed).
 *
 * @param p_ht the hash table to use.
 * @param i_key_size the size of the key to search with (in bytes).
 * @param p_key_data the key to search for.
 *
 * @return a pointer to the removed entry or NULL if the entry could be found.
 */
void *hash_remove(hash_table_t * p_ht,
		  unsigned int i_key_size, void *p_key_data);

/**
 * Return the first entry in the hash table. This function should be
 * used for iteration and is used together with hash_next(). Note that
 * you cannot assume anything about the order in which the entries are
 * accessed. If an entry is inserted during an iteration, the entry
 * might or might not occur in the iteration.
 *
 * The use of the hash_iterator_t allows for several concurrent
 * iterations, where you would use one hash_iterator_t for each
 * iteration. In threaded environments, you should still lock access
 * to the hash table for insertion and removal.
 *
 * A typical example might look as follows:
 * <PRE>
 * hash_table_t *p_table;
 * hash_iterator_t iterator;
 * void *p_e;
 *
 * [Create table etc...]
 * for(p_e = hash_first(p_table, &iterator); p_e; p_e = hash_next(p_table, &iterator))
 *   {
 *      [Do something with the current entry p_e]
 *   }
 * </PRE>
 *
 * @param p_ht the hash table to iterate through.
 *
 * @param p_iterator the iterator to use. The value of the structure
 * is filled in by this function and may be stack allocated.
 *
 * @return a pointer to the first entry in the table or NULL if there
 * are no entries.
 *
 *
 * @see hash_next()
 */
void *hash_first(hash_table_t * p_ht, hash_iterator_t * p_iterator);

/**
 * Return the next entry in the hash table. This function should be
 * used for iteration, and must be called after hash_first().
 *
 * @warning calling this without first having called hash_first will
 * give undefined results (probably a crash), since p_iterator isn't
 * filled correctly.
 *
 * @param p_ht the hash table to iterate through.
 *
 * @param p_iterator the iterator to use.
 *
 * @return a pointer to the next entry in the table or NULL if there
 * are no more entries in the table.
 *
 * @see hash_first()
 */
void *hash_next(hash_table_t * p_ht, hash_iterator_t * p_iterator);

/**
 * Rehash the hash table.
 *
 * Rehashing will change the size of the hash table, retaining all
 * elements. This is very costly and should be avoided unless really
 * needed. If <TT>AUTO_REHASH</TT> is specified in the flag
 * parameter when hash_create() is called, the hash table is
 * automatically rehashed when the number of stored elements exceeds
 * two times the number of buckets in the table (making calls to this
 * function unessessary).
 *
 * @param p_ht the hash table to rehash.
 * @param i_size the new size of the table.
 *
 * @see hash_create()
 */
void hash_rehash(hash_table_t * p_ht, unsigned int i_size);

/**
 * Free the hash table. hash_finalize() should typically be called
 * at the end of the program. Note that only the metadata and the keys
 * of the table is freed, not the entries. If you want to free the
 * entries when removing the table, the entries will have to be
 * manually freed before hash_finalize() is called like:
 *
 * <PRE>
 * hash_iterator_t iterator;
 * void *p_e;
 *
 * for(p_e = hash_first(p_table, &iterator); p_e; p_e = hash_next(p_table, &iterator))
 *   {
 *     free(p_e);
 *   }
 *
 * hash_finalize(p_table);
 * </PRE>
 *
 * @param p_ht the table to remove.
 */
void hash_finalize(hash_table_t * p_ht);

/* exported hash functions */

/**
 * One-at-a-time-hash. One-at-a-time-hash is a good hash function, and
 * is the default when hash_create() is called with NULL as the
 * fn_hash parameter. This was found in a DrDobbs article, see
 * http://burtleburtle.net/bob/hash/doobs.html
 *
 * @warning Don't call this function directly, it is only meant to be
 * used as a callback for the hash table.
 *
 * @see hash_fn_hash_t
 * @see hash_rotating_hash(), hash_crc_hash()
 */
unsigned int hash_one_at_a_time_hash(hash_key_t * p_key);

/**
 * Rotating hash. Not so good hash function. This was found in a
 * DrDobbs article, see http://burtleburtle.net/bob/hash/doobs.html
 *
 * @warning Don't call this function directly, it is only meant to be
 * used as a callback for the hash table.
 *
 * @see hash_fn_hash_t
 * @see hash_one_at_a_time_hash(), hash_crc_hash()
 */
unsigned int hash_rotating_hash(hash_key_t * p_key);

/**
 * CRC32 hash. CRC32 hash is a good hash function. This came from Dru
 * Lemley <spambait@lemley.net>.
 *
 * @warning Don't call this function directly, it is only meant to be
 * used as a callback for the hash table.
 *
 * @see hash_fn_hash_t
 * @see hash_one_at_a_time_hash(), hash_rotating_hash()
 */
unsigned int hash_crc_hash(hash_key_t * p_key);

#ifdef USE_PROFILING
/**
 * Print some statistics about the table. Only available if the
 * library was compiled with <TT>USE_PROFILING</TT> defined.
 */
void hash_print(hash_table_t * p_ht);
#endif

#endif				/* _HASH_H */
