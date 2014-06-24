#ifndef DLNG_POOL_H
#define DLNG_POOL_H

#include "list.h"

typedef struct pool_s pool_t;
 
pool_t *pool_new(size_t prealloc, size_t structsize);

void  *pool_alloc(pool_t *);
void   pool_free(pool_t *, void *);
size_t pool_slabsize(pool_t *);




#endif // DLNG_POOL_H
