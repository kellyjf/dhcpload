#ifndef DLNG_LOG_H
#define DLNG_LOG_H


typedef enum {
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_FATAL,
} log_level_t;

/* Call log_init() before starting threads */
int log_init();

int log_printf(char *, ...);
int log_message(log_level_t level, char *, ...);
int log_file_options(char *namefmt, size_t maxsize, size_t numfiles);
int log_line_options(char *linefmt);

#endif // DLNG_LOG_H

