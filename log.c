#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/types.h>  //gettid

#include "log.h"

enum {
	E_LOG_SUCCESS = 0,
	E_LOG_UNINIT,
};

int              log_initialized   = 0;
pthread_mutex_t *log_mutex;
FILE            *log_fp;

int log_init() {
	int rc;

	if(log_fp==NULL) log_fp=stdout;
	log_mutex=calloc(1,sizeof(pthread_mutex_t));

	if(rc=pthread_mutex_init(log_mutex, NULL)) {
		perror("mutex");
		return rc;
	}	
	log_initialized = 1;
	return 0;
}

int log_option_set(log_option_t key, void *value) {
	return 0;
}
int log_printf(char *format, ...){
	va_list ap;
	if(!log_initialized) return E_LOG_UNINIT; 
	va_start(ap, format);
	pthread_mutex_lock(log_mutex);
	vfprintf(log_fp, format, ap);
	pthread_mutex_unlock(log_mutex);
	va_end(ap);
	return 0;
}



#ifdef TEST
#include <sys/wait.h>
void *log_thread_main(void *user) {
	pthread_t self = pthread_self();
	int    i;
	for(i=0; i<1000; i++) log_printf("[%lu] Testing %5d\n", self, i);
}

int log_threaded_main(int argc, char **argv) {
	int i;
	size_t num_thread = 40;
	pthread_t *p = calloc(num_thread, sizeof(pthread_t) );
	void *res;

	for(i=0; i<num_thread; i++) {
		if(pthread_create(&p[i], NULL, log_thread_main, NULL)) {
			perror("thread_create");
			exit(1);
		}
	}
	for(i=0; i<num_thread; i++) {
		void *status;
		pthread_join(p[i],&status);
	}
	
	return 0;
}	
int log_main(int argc, char **argv) {
	log_init();
	log_threaded_main(argc, argv);
}

#endif
