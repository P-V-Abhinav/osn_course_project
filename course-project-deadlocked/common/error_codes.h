#ifndef ERROR_CODES_H
#define ERROR_CODES_H

/* Error Code System for Distributed File System */

typedef enum {
    /* Success */
    ERR_SUCCESS = 0,
    
    /* General Errors (1-99) */
    ERR_UNKNOWN = 1,
    ERR_INVALID_OPERATION = 2,
    ERR_INVALID_PARAMETERS = 3,
    ERR_BUFFER_OVERFLOW = 4,
    ERR_MEMORY_ALLOCATION = 5,
    
    /* Network Errors (100-199) */
    ERR_CONNECTION_FAILED = 100,
    ERR_CONNECTION_LOST = 101,
    ERR_SEND_FAILED = 102,
    ERR_RECV_FAILED = 103,
    ERR_TIMEOUT = 104,
    ERR_INVALID_MESSAGE = 105,
    
    /* File Errors (200-299) */
    ERR_FILE_NOT_FOUND = 200,
    ERR_FILE_ALREADY_EXISTS = 201,
    ERR_FILE_CREATE_FAILED = 202,
    ERR_FILE_OPEN_FAILED = 203,
    ERR_FILE_READ_FAILED = 204,
    ERR_FILE_WRITE_FAILED = 205,
    ERR_FILE_DELETE_FAILED = 206,
    ERR_FILE_TOO_LARGE = 207,
    ERR_INVALID_FILENAME = 208,
    
    /* Access Control Errors (300-399) */
    ERR_ACCESS_DENIED = 300,
    ERR_NO_READ_PERMISSION = 301,
    ERR_NO_WRITE_PERMISSION = 302,
    ERR_NOT_OWNER = 303,
    ERR_USER_NOT_FOUND = 304,
    ERR_INVALID_ACCESS_TYPE = 305,
    
    /* Lock Errors (400-499) */
    ERR_SENTENCE_LOCKED = 400,
    ERR_LOCK_FAILED = 401,
    ERR_UNLOCK_FAILED = 402,
    ERR_TOO_MANY_LOCKS = 403,
    ERR_INVALID_LOCK = 404,
    
    /* Write/Edit Errors (500-599) */
    ERR_SENTENCE_OUT_OF_RANGE = 500,
    ERR_WORD_OUT_OF_RANGE = 501,
    ERR_INVALID_UPDATE_FORMAT = 502,
    ERR_UPDATE_CAPACITY_EXCEEDED = 503,
    ERR_INVALID_INDEX = 504,
    
    /* Server Errors (600-699) */
    ERR_SS_NOT_AVAILABLE = 600,
    ERR_SS_REGISTRATION_FAILED = 601,
    ERR_SS_MAX_LIMIT_REACHED = 602,
    ERR_NS_NOT_AVAILABLE = 603,
    ERR_CLIENT_REGISTRATION_FAILED = 604,
    
    /* Cache Errors (700-799) */
    ERR_CACHE_FULL = 700,
    ERR_CACHE_MISS = 701,
    ERR_CACHE_UPDATE_FAILED = 702,
    
    /* Undo Errors (800-899) */
    ERR_NO_UNDO_HISTORY = 800,
    ERR_UNDO_FAILED = 801,
    ERR_BACKUP_NOT_FOUND = 802,
    
    /* Execution Errors (900-999) */
    ERR_EXEC_FAILED = 900,
    ERR_COMMAND_NOT_FOUND = 901,
    ERR_EXEC_PERMISSION_DENIED = 902,
    ERR_EXEC_TIMEOUT = 903
} ErrorCode;

/* Error code to string mapping */
const char* error_code_to_string(ErrorCode code) {
    switch(code) {
        case ERR_SUCCESS: return "Success";
        
        /* General */
        case ERR_UNKNOWN: return "Unknown error occurred";
        case ERR_INVALID_OPERATION: return "Invalid operation";
        case ERR_INVALID_PARAMETERS: return "Invalid parameters provided";
        case ERR_BUFFER_OVERFLOW: return "Buffer overflow detected";
        case ERR_MEMORY_ALLOCATION: return "Memory allocation failed";
        
        /* Network */
        case ERR_CONNECTION_FAILED: return "Connection failed";
        case ERR_CONNECTION_LOST: return "Connection lost";
        case ERR_SEND_FAILED: return "Failed to send data";
        case ERR_RECV_FAILED: return "Failed to receive data";
        case ERR_TIMEOUT: return "Operation timed out";
        case ERR_INVALID_MESSAGE: return "Invalid message format";
        
        /* File */
        case ERR_FILE_NOT_FOUND: return "File not found";
        case ERR_FILE_ALREADY_EXISTS: return "File already exists";
        case ERR_FILE_CREATE_FAILED: return "Failed to create file";
        case ERR_FILE_OPEN_FAILED: return "Failed to open file";
        case ERR_FILE_READ_FAILED: return "Failed to read file";
        case ERR_FILE_WRITE_FAILED: return "Failed to write file";
        case ERR_FILE_DELETE_FAILED: return "Failed to delete file";
        case ERR_FILE_TOO_LARGE: return "File size exceeds limit";
        case ERR_INVALID_FILENAME: return "Invalid filename";
        
        /* Access Control */
        case ERR_ACCESS_DENIED: return "Access denied";
        case ERR_NO_READ_PERMISSION: return "No read permission";
        case ERR_NO_WRITE_PERMISSION: return "No write permission";
        case ERR_NOT_OWNER: return "Not file owner";
        case ERR_USER_NOT_FOUND: return "User not found";
        case ERR_INVALID_ACCESS_TYPE: return "Invalid access type";
        
        /* Lock */
        case ERR_SENTENCE_LOCKED: return "Sentence is locked by another user";
        case ERR_LOCK_FAILED: return "Failed to acquire lock";
        case ERR_UNLOCK_FAILED: return "Failed to release lock";
        case ERR_TOO_MANY_LOCKS: return "Too many active locks";
        case ERR_INVALID_LOCK: return "Invalid lock";
        
        /* Write/Edit */
        case ERR_SENTENCE_OUT_OF_RANGE: return "Sentence index out of range";
        case ERR_WORD_OUT_OF_RANGE: return "Word index out of range";
        case ERR_INVALID_UPDATE_FORMAT: return "Invalid update format";
        case ERR_UPDATE_CAPACITY_EXCEEDED: return "Update capacity exceeded";
        case ERR_INVALID_INDEX: return "Invalid index";
        
        /* Server */
        case ERR_SS_NOT_AVAILABLE: return "Storage server not available";
        case ERR_SS_REGISTRATION_FAILED: return "Storage server registration failed";
        case ERR_SS_MAX_LIMIT_REACHED: return "Maximum storage servers reached";
        case ERR_NS_NOT_AVAILABLE: return "Name server not available";
        case ERR_CLIENT_REGISTRATION_FAILED: return "Client registration failed";
        
        /* Cache */
        case ERR_CACHE_FULL: return "Cache is full";
        case ERR_CACHE_MISS: return "Cache miss";
        case ERR_CACHE_UPDATE_FAILED: return "Cache update failed";
        
        /* Undo */
        case ERR_NO_UNDO_HISTORY: return "No undo history available";
        case ERR_UNDO_FAILED: return "Undo operation failed";
        case ERR_BACKUP_NOT_FOUND: return "Backup file not found";
        
        /* Execution */
        case ERR_EXEC_FAILED: return "Command execution failed";
        case ERR_COMMAND_NOT_FOUND: return "Command not found";
        case ERR_EXEC_PERMISSION_DENIED: return "Execute permission denied";
        case ERR_EXEC_TIMEOUT: return "Execution timeout";
        
        default: return "Unknown error code";
    }
}

/* Helper function to create error message with code */
void format_error_message(char *buffer, size_t size, ErrorCode code, const char *details) {
    if (details && strlen(details) > 0) {
        snprintf(buffer, size, "TYPE:RESP\nSTATUS:ERROR\nCODE:%d\nMSG:%s - %s\n\n",
                 code, error_code_to_string(code), details);
    } else {
        snprintf(buffer, size, "TYPE:RESP\nSTATUS:ERROR\nCODE:%d\nMSG:%s\n\n",
                 code, error_code_to_string(code));
    }
}

/* Helper function to create success message */
void format_success_message(char *buffer, size_t size, const char *msg) {
    snprintf(buffer, size, "TYPE:RESP\nSTATUS:OK\nCODE:0\nMSG:%s\n\n", msg);
}

#endif /* ERROR_CODES_H */
