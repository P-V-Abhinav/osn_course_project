#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>

/* Log Levels */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3,
    LOG_CRITICAL = 4
} LogLevel;

/* Log Component */
typedef enum {
    COMP_NS = 0,
    COMP_SS = 1,
    COMP_CLIENT = 2
} LogComponent;

/* Global log file handles */
static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static LogLevel min_log_level = LOG_INFO;
static LogComponent current_component = COMP_NS;

/* Log level names */
static const char* log_level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"
};

/* Component names */
static const char* component_names[] = {
    "NS", "SS", "CLIENT"
};

/* Initialize logging system */
int init_logging(LogComponent component, const char *log_dir) {
    pthread_mutex_lock(&log_mutex);
    
    current_component = component;
    
    /* Create log directory if it doesn't exist */
    mkdir(log_dir, 0755);
    
    /* Construct log filename */
    char log_filename[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    snprintf(log_filename, sizeof(log_filename), 
             "%s/%s_%04d%02d%02d_%02d%02d%02d.log",
             log_dir, component_names[component],
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
    
    log_file = fopen(log_filename, "a");
    if (!log_file) {
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    /* Write header */
    fprintf(log_file, "========================================\n");
    fprintf(log_file, "Log started: %s", ctime(&now));
    fprintf(log_file, "Component: %s\n", component_names[component]);
    fprintf(log_file, "========================================\n");
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
    return 0;
}

/* Close logging system */
void close_logging() {
    pthread_mutex_lock(&log_mutex);
    if (log_file) {
        time_t now = time(NULL);
        fprintf(log_file, "========================================\n");
        fprintf(log_file, "Log ended: %s", ctime(&now));
        fprintf(log_file, "========================================\n");
        fclose(log_file);
        log_file = NULL;
    }
    pthread_mutex_unlock(&log_mutex);
}

/* Set minimum log level */
void set_log_level(LogLevel level) {
    min_log_level = level;
}

/* Get current timestamp string */
void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(buffer, size, "%04d-%02d-%02d %02d:%02d:%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
}

/* Core logging function */
void write_log(LogLevel level, const char *function, int line, 
               const char *format, ...) {
    if (level < min_log_level) return;
    
    pthread_mutex_lock(&log_mutex);
    
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    /* Format message */
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    /* Write to file */
    if (log_file) {
        fprintf(log_file, "[%s] [%s] [%s:%d] %s\n",
                timestamp, log_level_names[level], function, line, message);
        fflush(log_file);
    }
    
    /* Also write to console for WARN and above */
    if (level >= LOG_WARN) {
        printf("[%s] [%s] [%s] %s\n",
               timestamp, log_level_names[level], 
               component_names[current_component], message);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

/* Log a request */
void log_request(const char *from, const char *operation, 
                 const char *filename, const char *username) {
    pthread_mutex_lock(&log_mutex);
    
    if (!log_file) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(log_file, "[%s] [REQUEST] From=%s Op=%s File=%s User=%s\n",
            timestamp, from, operation, 
            filename ? filename : "N/A", 
            username ? username : "N/A");
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

/* Log a response */
void log_response(const char *to, const char *operation, 
                  int status_code, const char *message) {
    pthread_mutex_lock(&log_mutex);
    
    if (!log_file) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(log_file, "[%s] [RESPONSE] To=%s Op=%s Code=%d Msg=%s\n",
            timestamp, to, operation, status_code, 
            message ? message : "N/A");
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

/* Log network activity */
void log_network(const char *action, const char *ip, int port, 
                 const char *details) {
    pthread_mutex_lock(&log_mutex);
    
    if (!log_file) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    fprintf(log_file, "[%s] [NETWORK] Action=%s IP=%s Port=%d Details=%s\n",
            timestamp, action, ip, port, details ? details : "");
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

/* Convenience macros */
#define LOG_DEBUG(...) write_log(LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...) write_log(LOG_INFO, __func__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...) write_log(LOG_WARN, __func__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) write_log(LOG_ERROR, __func__, __LINE__, __VA_ARGS__)
#define LOG_CRITICAL(...) write_log(LOG_CRITICAL, __func__, __LINE__, __VA_ARGS__)

#endif /* LOGGING_H */
