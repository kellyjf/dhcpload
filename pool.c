
#include <pthread.h> 
#include <stdlib.h>  // calloc
#include "list.h"
#include "pool.h"


typedef struct {
	struct list_head   list;
	void              *data;
} pool_node_t;

struct pool_s {
	pthread_mutex_t   mutex;
	struct list_head  free_list;
	struct list_head  inuse_list;
	size_t            item_size;
	size_t            chunk;
	size_t            pool_size;
} ;

static void pool_extend(pool_t *pool) {
	int           i;
	void         *base  = calloc(pool->chunk, pool->item_size);
	pool_node_t  *node  = calloc(pool->chunk, sizeof(pool_node_t));

	for(i=0; i<pool->chunk; i++) {
		list_add(&node[i].list, &pool->free_list);	
		node[i].data = (void *)(((char *)base)+(i*pool->item_size));
	}
	pool->pool_size += pool->chunk;
}

pool_t *pool_new(size_t prealloc, size_t strsize) {
	int           i;
	pool_t       *ret   = calloc(1, sizeof(pool_t));

	ret->free_list.next = &ret->free_list;
	ret->free_list.prev = &ret->free_list;
	ret->inuse_list.next = &ret->free_list;
	ret->inuse_list.prev = &ret->free_list;

	ret->chunk = prealloc;
	ret->item_size = strsize;

	pthread_mutex_init(&ret->mutex, NULL);

	return ret;
}

size_t pool_slabsize(pool_t *pool) {
	return pool->item_size;
}

void pool_fini() {
}

void *pool_alloc(pool_t *pool) {
	pool_node_t *ret;
	pthread_mutex_lock(&pool->mutex);
	if(list_empty(&pool->free_list)) {
		pool_extend(pool);
	}
	ret = list_first_entry(&pool->free_list, pool_node_t, list);
	list_del(&ret->list);
	list_add(&ret->list, &pool->inuse_list);
	pthread_mutex_unlock(&pool->mutex);
	return ret->data;
}	
void pool_free(pool_t *pool, void *ret){
	struct list_head *curr, *safe;

	pthread_mutex_lock(&pool->mutex);
	list_for_each_safe(curr, safe, &pool->inuse_list) {
		pool_node_t * node = container_of(curr, pool_node_t, list);
		if(node->data == ret) {
			list_del(curr);
			list_add(curr, &pool->free_list);
			break;
		}
	}
	pthread_mutex_unlock(&pool->mutex);
}



#ifdef TEST
#include <stdio.h>  // calloc
void pool_list(pool_t *pool, void *usr) {
	int           i=0;
	static  int   cnt;

	pool_node_t  *curr;
	pthread_mutex_lock(&pool->mutex);
	list_for_each_entry(curr, &pool->free_list, list) {
		i++;
		//printf("%p;", curr);
	}
	log_printf("[%02x] %05d = %05d %05lu\n",usr, cnt++, i, pool->pool_size);
	pthread_mutex_unlock(&pool->mutex);
}

typedef struct {
	struct list_head user;
} user_t;

pool_t *the_pool;

void *thread_main(void *user) {
	user_t           *curr;
	struct list_head *here, *safe;
	long              i;
	LIST_HEAD(borrow_head);
	for(i=0; i<24; i++) {
		curr  = (user_t *)pool_alloc(the_pool);
		list_add(&curr->user, &borrow_head);
		pool_list(the_pool, user);
	}
	list_for_each_safe(here, safe, &borrow_head) {
		user_t *pi = container_of(here, user_t, user);
		list_del(here);
		pool_free(the_pool, pi);
		pool_list(the_pool, user);
	}

	return NULL;
}

int pool_main(int argc, char **argv) {
	int i;
	size_t num_thread = 40;
	pthread_t *p = calloc(num_thread, sizeof(pthread_t) );
	void *res;
	log_init();
	the_pool = pool_new(160, 64);

	for(i=0; i<num_thread; i++) {
		if(pthread_create(&p[i], NULL, thread_main, (void*)i)) {
			perror("thread_create");
			exit(1);
		}
	}
	for(i=0; i<num_thread; i++) pthread_join(p[i], &res);
	
	return 0;
}	
#endif
