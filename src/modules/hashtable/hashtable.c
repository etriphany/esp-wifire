#include <mem.h>

#include "modules/hashtable/hashtable.h"

/**
 *  Adapted from:
 *
 *  https://rosettacode.org/wiki/Associative_arrays/Creation/C
 */

hash_t * ICACHE_FLASH_ATTR
hash_create(int size) {
    hash_t *h = os_calloc(1, sizeof (hash_t));
    h->keys = os_calloc(size, sizeof (void *));
    h->values = os_calloc(size, sizeof (void *));
    h->size = size;
    return h;
}

int ICACHE_FLASH_ATTR
hash_index(hash_t *h, void *key)
{
    int i = (int) key % h->size;
    while (h->keys[i] && h->keys[i] != key)
        i = (i + 1) % h->size;
    return i;
}

void ICACHE_FLASH_ATTR
hash_insert(hash_t *h, void *key, void *value)
{
    int i = hash_index(h, key);
    h->keys[i] = key;
    h->values[i] = value;
}

void* ICACHE_FLASH_ATTR
hash_lookup(hash_t *h, void *key)
{
    int i = hash_index(h, key);
    return h->values[i];
}

void ICACHE_FLASH_ATTR
hash_delete(hash_t *h, void *key)
{
    int i = hash_index(h, key);
    if(h->values[i] != NULL)
    {
      h->keys[i] = NULL;
      h->values[i] = NULL;
    }
}