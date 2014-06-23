#include <pthread.h>

#include "log.h"


pthread_mutex_t log_mutex;


int log_init() {
	int rc;

	if(rc=pthread_mutex_init(&log_mutex, NULL)) {
		perror("mutex");
		return rc;
	}	
	return 0;
}

int log_output(FILE *fp) {
	return 0;
}

int log_option_set(log_option_t key, void *value) {
	return 0;
}
int log_printf(char *format, ...){
	return 0;
}



