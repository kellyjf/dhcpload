#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/time.h>  
#include <sys/stat.h>  
#include <sys/syscall.h>  //gettid

#include "log.h"

enum {
	E_LOG_SUCCESS = 0,
	E_LOG_UNINIT,
};

int              log_initialized   = 0;
pthread_mutex_t  log_mutex         = PTHREAD_MUTEX_INITIALIZER;
FILE            *log_fp;
FILE            *_fp;
log_level_t      log_level_min     = LOG_LEVEL_INFO;

#define LOG_MAXFILENAME 256
#define LOG_MAXLINENAME 64 

size_t           maxsize = 1000000;
size_t           maxnum  = 5;
char             namefmt[LOG_MAXFILENAME];
char             linefmt[LOG_MAXLINENAME];

int log_init() {
	log_fp = stdout;
	return 0;
}



int log_printf(char *format, ...){
	va_list ap;
	va_start(ap, format);
	pthread_mutex_lock(&log_mutex);
	vfprintf(log_fp?log_fp:stdout, format, ap);
	pthread_mutex_unlock(&log_mutex);
	va_end(ap);
	return 0;
}

void log_rotate() {
	int         i;

	for(i=maxnum; i>0; i--) {
		struct stat sb;
		static char oldname[LOG_MAXFILENAME];
		static char newname[LOG_MAXFILENAME];
		sprintf(newname, namefmt, i);
		sprintf(oldname, namefmt, i-1);
		unlink(newname);
		if(stat(oldname, &sb)==0) {
			rename(oldname, newname);
		}
		if(log_fp && log_fp != stdout) fclose(log_fp);
		if((log_fp=fopen(oldname, "w+"))==NULL) {
			perror(oldname);
			namefmt[0]=0;
			log_fp = stdout;
		}
	}
}

int log_file_options(char *nfmt, size_t s, size_t n) {
	if(nfmt==0) { log_fp = stdout;  return ; }
	strncpy(namefmt, nfmt, sizeof(namefmt));
	if(strchr(namefmt,'%')==NULL) strcat(namefmt, ".%d");
	maxsize = s;
	maxnum = n;
	pthread_mutex_lock(&log_mutex);
	log_rotate();
	pthread_mutex_unlock(&log_mutex);
}

char *log_label(log_level_t level) {
	switch(level) {
#define CASE(x)  case LOG_LEVEL_##x: return #x
	CASE(DEBUG); CASE(INFO); CASE(WARNING); CASE(ERROR); CASE(FATAL);
	default: return "";
	}
	return "";
}
int log_message(log_level_t level, char *format, ...){
	va_list ap;
	struct  timeval tv;
	if(level<log_level_min) return 0;
	va_start(ap, format);
	pthread_mutex_lock(&log_mutex);
	if(log_fp==NULL) {
		if(namefmt[0]) log_rotate();
		else log_fp = stdout;
	}
	if(namefmt[0]&&maxsize>0&&ftell(log_fp)>maxsize) {
		log_rotate();
	}
	gettimeofday(&tv, NULL);
	fprintf(log_fp, "%010lu.%06lu |%05d|%05ld|%-8.8s ",
		tv.tv_sec, tv.tv_usec, getpid(), 
		syscall(SYS_gettid),
		log_label(level));
	vfprintf(log_fp, format, ap);
	pthread_mutex_unlock(&log_mutex);
	va_end(ap);
	return 0;
}



#ifdef TEST
#include <sys/wait.h>
void *log_thread_main(void *user) {
	pthread_t self = pthread_self();
	int    i;
	//for(i=0; i<1000; i++) log_printf("[%lu] Testing %5d\n", self, i);
	for(i=0; i<1000; i++) log_message(LOG_LEVEL_INFO , "Testing %5d\n", i);
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
 	log_file_options("dhcpload.log", 40000, 5) ;
	log_threaded_main(argc, argv);
}

#endif
