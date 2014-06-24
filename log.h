#ifndef DLNG_LOG_H
#define DLNG_LOG_H

typedef enum {LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERROR, LOG_FATAL} log_level_t;
typedef enum {
	LOG_OPT_MAXFILESIZE,
	LOG_OPT_MAXNUMFILES,
} log_option_t;

/* Call log_init() before starting threads */
int log_init();
int log_option_set(log_option_t, void *value);

int log_printf(char *, ...);

#endif // DLNG_LOG_H

