#ifndef DLNG_QUEUE_H
#define DLNG_QUEUE_H

#include <pthread.h>
#include <sys/time.h>
#include "list.h"

typedef struct {
	pthread_mutex_t   mutex;
	pthread_cond_t    cond;
	struct list_head  list;
	size_t            list_size;
} msg_queue_t;

typedef struct {
	struct list_head  list;
	void             *data;
} msg_t;

typedef enum {
	E_QUEUE_OK  = 0,
} msg_error_t;

msg_queue_t *msg_queue_new();
void msg_queue_free(msg_queue_t *);

msg_t *msg_queue_get(msg_queue_t *q, struct timeval *);
void   msg_queue_put(msg_queue_t *q, msg_t *);
msg_error_t msg_queue_send(msg_queue_t *q, void*);

	
#endif // DLNG_QUEUE_H
