
#include <pthread.h> 
#include <stdlib.h>  // calloc
#include "list.h"
#include "pool.h"

pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;

LIST_HEAD(pool_head);
static int POOL_CHUNK = 8;
static int POOL_ITEM_SIZE = 2048;
static int pool_size;


void pool_init(size_t prealloc, size_t strsize) {
	int  i;
	pool_item_t   *base  = calloc(prealloc, strsize);
	for(i=0; i<prealloc; i++) {
		pool_item_t   *curr = (pool_item_t *)(((char *)base)+(i*strsize));
		list_add(&curr->pool, &pool_head);	
	}
	pool_size += prealloc;
	
}

void pool_fini() {
}

pool_item_t *pool_alloc() {
	pool_item_t *ret;
	pthread_mutex_lock(&pool_mutex);
	if(list_empty(&pool_head)) {
		pool_init(POOL_CHUNK, POOL_ITEM_SIZE);
	}
	ret = list_first_entry(&pool_head, pool_item_t, pool);
	list_del(&ret->pool);
	pthread_mutex_unlock(&pool_mutex);
	return ret;
}	
void pool_free(pool_item_t *ret){

	pthread_mutex_lock(&pool_mutex);
	list_add(&ret->pool, &pool_head);
	pthread_mutex_unlock(&pool_mutex);
}


#include <stdio.h>  // calloc
void pool_list() {
	int           i=0;
	static  int   cnt;

	pool_item_t  *curr;
	pthread_mutex_lock(&pool_mutex);
	list_for_each_entry(curr, &pool_head, pool) {
		i++;
		//printf("%p;", curr);
	}
	printf(" %05d = %05d %05d\n",cnt++, i, pool_size);
	pthread_mutex_unlock(&pool_mutex);
}

typedef struct {
	pool_item_t  pool;
	struct list_head user;
} user_t;

void *thread_main(void *user) {
	user_t      *curr;
	struct list_head *here, *safe;
	int          i;
	LIST_HEAD(borrow_head);
	for(i=0; i<24; i++) {
		curr  = (user_t *)pool_alloc();
		list_add(&curr->user, &borrow_head);
		pool_list();
	}
	list_for_each_safe(here, safe, &borrow_head) {
		pool_item_t *pi = container_of(here, pool_item_t, pool);
		list_del(here);
		pool_free(pi);
		pool_list();
	}

	return NULL;
}

int main() {
	int i;
	size_t num_thread = 40;
	pthread_t *p = calloc(num_thread, sizeof(pthread_t) );
	void *res;

	for(i=0; i<num_thread; i++) {
		if(pthread_create(&p[i], NULL, thread_main, NULL)) {
			perror("thread_create");
			exit(1);
		}
	}
	for(i=0; i<num_thread; i++) pthread_join(p[i], &res);
	
	return 0;
}	
