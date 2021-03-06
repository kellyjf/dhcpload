#include <pthread.h> 
#include <stdlib.h> //calloc
#include "queue.h"
#include "pool.h"
#include "log.h"

pool_t *msg_pool;

msg_queue_t *msg_queue_new() 
{

	msg_queue_t  *ret;
	

	if((ret=calloc(1, sizeof(msg_queue_t)))==NULL) {
		return NULL;
	}

	pthread_mutex_init(&ret->mutex, NULL);
	pthread_cond_init(&ret->cond, NULL);
	ret->list.next = &ret->list;
	ret->list.prev = &ret->list;

	if(msg_pool==NULL) {
		msg_pool = pool_new(2, sizeof(msg_t));
	}
	return ret;
}

void msg_queue_free(msg_queue_t *ret)
{
	pthread_mutex_destroy(&ret->mutex);
	pthread_cond_destroy(&ret->cond);
	free(ret);
}


msg_t *msg_queue_get(msg_queue_t *q, struct timeval *tv)
{
	msg_t  *ret = NULL;
	int     rc  = 0;

	pthread_mutex_lock(&q->mutex);
	if(list_empty(&q->list)) {
		if(tv) {
			struct timespec abstime;
			clock_gettime(CLOCK_REALTIME, &abstime);
			abstime.tv_sec += tv->tv_sec;
			abstime.tv_nsec += 1000* tv->tv_usec;
			if(abstime.tv_nsec>1000000000) {
				abstime.tv_sec += 1;
				abstime.tv_nsec %= 1000000000;
			}
			rc = pthread_cond_timedwait(&q->cond, &q->mutex, &abstime);
		} else {
			rc = pthread_cond_wait(&q->cond, &q->mutex);
		}
	}
	if(rc==0) {
		ret=list_first_entry(&q->list, msg_t, list);
		list_del(&ret->list);
	}
	pthread_mutex_unlock(&q->mutex);
	return ret;
}

void msg_queue_put(msg_queue_t *q, msg_t *msg)
{
	pool_free(msg_pool, msg);
}

msg_error_t msg_queue_send(msg_queue_t *q, void *data)
{
	msg_error_t   ret  = E_QUEUE_OK;
	msg_t        *msg  = NULL;

	msg  = pool_alloc(msg_pool);
	msg->data = data;
	pthread_mutex_lock(&q->mutex);
	list_add_tail(&msg->list, &q->list);	
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->mutex);

	return ret;
	
}

#ifdef TEST

msg_queue_t *the_queue;

void *queue_thread_main(void *user) {
	int  *pi = (int *)user;
	int    i;
	msg_t *msg;

	for(i=0; i<1000; i++) {
		struct timeval tv = { 1, 0 };
		msg = msg_queue_get(the_queue, &tv);
		log_printf("Thread %3d (%4d) gets msg %d\n", *pi,i, *(int *)&msg->data);
		msg_queue_put(the_queue, msg);
	}
	return NULL;
}

void *gen_thread(void *user) {
	long  i;
	for(i=0; i<10000; i++) {
		msg_queue_send(the_queue, (void *)i);
	}
}
int queue_main(int argc, char **argv) {
	size_t         num_threads = 10;
	int            i;
	pthread_t     *pt, pgen;
		void *ret;
	
	log_init();
	pt = calloc(num_threads, sizeof(pthread_t));

	the_queue = msg_queue_new();
	
	for(i=0; i<num_threads; i++) {
		int *pi = malloc(sizeof(int));
		*pi = i;
		pthread_create(&pt[i], NULL, queue_thread_main, (void *)pi);
	}

	pthread_create(&pgen, NULL, gen_thread, NULL);
	pthread_join(pgen, &ret);
	for(i=0; i<num_threads; i++) {
		pthread_join(pt[i], &ret);
	}
	return 0;
}

#endif
	
