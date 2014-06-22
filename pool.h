#ifndef DLNG_POOL_H
#define DLNG_POOL_H

#include "list.h"

typedef struct {
	struct list_head  pool;
} pool_item_t;


void pool_init(size_t prealloc, size_t structsize);
void pool_fini();

pool_item_t *pool_alloc();
void pool_free(pool_item_t *);




#endif // DLNG_POOL_H
