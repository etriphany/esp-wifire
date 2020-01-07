#ifndef _HASHTABLE_H
#define _HASHTABLE_H

/**
 *  Adapted from:
 *
 *  https://rosettacode.org/wiki/Associative_arrays/Creation/C
 */

typedef struct {
    int size;
    void **keys;
    void **values;
} hash_t;

hash_t *hash_create (int size);
int hash_index(hash_t *h, void *key);
void hash_insert (hash_t *h, void *key, void *value);
void* hash_lookup (hash_t *h, void *key);
void hash_delete(hash_t *h, void *key);

#endif