#include "../common/protocol.h"
#include "../common/error_codes.h"
#include "../common/logging.h"
#include "lru_cache.h"
#include "trie.h"
#include <pthread.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#define PORT 8080
#define MAX_USERS 100
#define MAX_SS 5  // Up to 5 storage servers

// Forward declaration
void trigger_async_replication(int ss_idx, const char *msg);

// Forward declaration
void trigger_async_replication(int ss_idx, const char *msg);

LRUCache *file_cache;
Trie *file_trie;  /* Trie for O(k) filename lookups where k = filename length */

typedef struct {
    char ss_name[64];
    char ip[64];
    int client_port;
    int ctrl_port;
    int active;  // 1 if registered, 0 if not
    int is_replica_of;  // Index of primary SS (-1 if this is primary)
    time_t last_heartbeat;  // Last heartbeat timestamp
    int file_count; // Number of files stored (primary)
} StorageServerInfo;

StorageServerInfo storage_servers[MAX_SS];
int ss_count = 0;
pthread_mutex_t ss_lock = PTHREAD_MUTEX_INITIALIZER;

/* Heartbeat monitoring thread */
pthread_t heartbeat_thread;
int heartbeat_running = 1;

/* Simple hash function for load balancing */
static unsigned int hash_filename(const char *s) {
    unsigned int h = 0;
    while (*s) h = (h * 31 + *s++);
    return h;
}

/* Select the active storage server with the least number of cached files.
 * Returns SS index or -1 if none available. O(N) where N=ss_count. */
static int select_least_loaded_ss() {
    pthread_mutex_lock(&ss_lock);
    int chosen = -1;
    int min_files = -1;

    for (int i = 0; i < ss_count; i++) {
        if (storage_servers[i].active) {
            if (chosen == -1 || storage_servers[i].file_count < min_files) {
                chosen = i;
                min_files = storage_servers[i].file_count;
            }
        }
    }
    pthread_mutex_unlock(&ss_lock);

    if (chosen >= 0) {
        printf("[NS] Least-loaded selection: SS#%d (files=%d)\n", chosen, min_files);
    }
    return chosen;
}

/* Helper: trim trailing whitespace from mutable buffer */
static void rstrip(char *s) {
    if (!s) return;
    int len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

/* Helper: extract FIELD:value into output buffer, returns 1 if found */
static int extract_field_value(const char *buf, const char *field, char *out, size_t out_size) {
    if (!buf || !field || !out || out_size == 0) return 0;
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s:", field);
    char *ptr = strstr(buf, pattern);
    if (!ptr) return 0;
    ptr += strlen(pattern);
    while (*ptr == ' ' || *ptr == '\t') ptr++;

    size_t i = 0;
    while (*ptr && *ptr != '\n' && i < out_size - 1) {
        out[i++] = *ptr++;
    }
    out[i] = '\0';
    rstrip(out);
    return (i > 0);
}

/* Mark a storage server inactive after connection failures */
static void mark_ss_inactive(int idx, const char *reason) {
    pthread_mutex_lock(&ss_lock);
    if (idx >= 0 && idx < ss_count && storage_servers[idx].active) {
        storage_servers[idx].active = 0;
        pthread_mutex_unlock(&ss_lock);
        
        printf("\n========================================\n");
        printf("[NS] STORAGE SERVER DISCONNECTED\n");
        printf("[NS] SS#%d (%s) at %s:%d is now INACTIVE\n",
               idx, storage_servers[idx].ss_name,
               storage_servers[idx].ip, storage_servers[idx].ctrl_port);
        printf("[NS] Reason: %s\n", reason ? reason : "unknown");
        printf("========================================\n\n");
        
        LOG_ERROR("Storage Server SS#%d (%s) disconnected - %s", 
                 idx, storage_servers[idx].ss_name, reason ? reason : "unknown");
        
        // Remove all cached data from this SS (also removes from trie)
        printf("[NS] Processing failover for SS#%d...\n", idx);
        cache_invalidate_by_ss(file_cache, idx, file_trie);
        
        printf("[NS] SS#%d failure processing complete.\n", idx);
    } else {
        pthread_mutex_unlock(&ss_lock);
    }
}

/* Attempt to open a control connection to the specified SS index */
static int open_ss_connection(int idx, int *out_fd, StorageServerInfo *out_info) {
    int fd = -1;
    StorageServerInfo info;

    pthread_mutex_lock(&ss_lock);
    if (idx < 0 || idx >= ss_count || !storage_servers[idx].active) {
        pthread_mutex_unlock(&ss_lock);
        return -1;
    }
    info = storage_servers[idx];
    pthread_mutex_unlock(&ss_lock);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in ss_addr = {0};
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(info.ctrl_port);
    inet_pton(AF_INET, info.ip, &ss_addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        printf("[NS] Failed to connect to SS#%d (%s:%d): %s\n",
               idx, info.ip, info.ctrl_port, strerror(errno));
        close(fd);
        mark_ss_inactive(idx, "connect failed");
        return -1;
    }

    if (out_fd) *out_fd = fd; else close(fd);
    if (out_info) *out_info = info;
    return 0;
}

/* Path normalization - converts relative paths to absolute */
void normalize_path(const char *path, char *normalized) {
    if (path[0] == '/') {
        strncpy(normalized, path, 255);
    } else {
        snprintf(normalized, 256, "/%s", path);
    }
    // Remove trailing slash if present (except for root)
    int len = strlen(normalized);
    if (len > 1 && normalized[len-1] == '/') {
        normalized[len-1] = '\0';
    }
}

/* Get active SS (single server) */
int get_active_ss_for_file(const char *filename) {
    (void)filename;
    pthread_mutex_lock(&ss_lock);
    int available = (ss_count > 0 && storage_servers[0].active);
    pthread_mutex_unlock(&ss_lock);
    return available ? 0 : -1;
}


/* User tracking */
typedef struct {
    char username[64];
    int active;
} UserEntry;

UserEntry registered_users[MAX_USERS];
int user_count = 0;
pthread_mutex_t user_lock = PTHREAD_MUTEX_INITIALIZER;

/* Access Request tracking */
#define MAX_ACCESS_REQUESTS 500
typedef struct {
    char filename[64];
    char requester[64];
    char owner[64];
    char access_type;  // 'R' or 'W'
    int pending;  // 1 if pending, 0 if processed
    time_t request_time;
} AccessRequest;

AccessRequest access_requests[MAX_ACCESS_REQUESTS];
int request_count = 0;
pthread_mutex_t request_lock = PTHREAD_MUTEX_INITIALIZER;

/* Add access request */
int add_access_request(const char *filename, const char *requester, const char *owner, char access_type) {
    pthread_mutex_lock(&request_lock);
    
    // Check if request already exists
    for (int i = 0; i < request_count; i++) {
        if (strcmp(access_requests[i].filename, filename) == 0 &&
            strcmp(access_requests[i].requester, requester) == 0 &&
            access_requests[i].pending == 1) {
            pthread_mutex_unlock(&request_lock);
            return -1;  // Already exists
        }
    }
    
    if (request_count >= MAX_ACCESS_REQUESTS) {
        pthread_mutex_unlock(&request_lock);
        return -2;  // Too many requests
    }
    
    strncpy(access_requests[request_count].filename, filename, 63);
    strncpy(access_requests[request_count].requester, requester, 63);
    strncpy(access_requests[request_count].owner, owner, 63);
    access_requests[request_count].access_type = access_type;
    access_requests[request_count].pending = 1;
    access_requests[request_count].request_time = time(NULL);
    request_count++;
    
    pthread_mutex_unlock(&request_lock);
    return 0;
}

/* Add or update user */
void register_user(const char *username) {
    pthread_mutex_lock(&user_lock);
    
    // Check if user already exists
    for (int i = 0; i < user_count; i++) {
        if (strcmp(registered_users[i].username, username) == 0) {
            registered_users[i].active = 1;
            pthread_mutex_unlock(&user_lock);
            return;
        }
    }
    
    // Add new user
    if (user_count < MAX_USERS) {
        strncpy(registered_users[user_count].username, username, 63);
        registered_users[user_count].active = 1;
        user_count++;
    }
    
    pthread_mutex_unlock(&user_lock);
}

/* Helper: Check if file exists in cache (no lazy loading with multi-SS) */
static int ensure_file_in_cache(const char *filename) {
    CacheNode *cached = cache_get(file_cache, filename);
    return (cached != NULL);  // File exists only if in cache
}

void *handle_client(void *arg) {
    int fd = *(int *)arg; 
    free(arg);
    // Increased buffer to handle large REGISTER_SS messages carrying full metadata
    char buf[16384];
    
    if (recv_message(fd, buf, sizeof(buf)) != 0) {
        close(fd);
        return NULL;
    }
    
    printf("[NS] Received:\n%s\n", buf);

    // REGISTER_SS
    if (strstr(buf, "OP:REGISTER_SS")) {
        printf("[NS] Storage Server registration request received\n");
        char ss_name[64] = "unknown";
        int ss_client_port = 0, ss_ctrl_port = 0;
        // Increased file_list capacity to accommodate expanded metadata payload
        char file_list[12288] = "";

        // Parse registration message
        char *ss_name_ptr = strstr(buf, "SS_NAME:");
        if (ss_name_ptr)
            sscanf(ss_name_ptr, "SS_NAME:%63s", ss_name);

        char *ss_client_port_ptr = strstr(buf, "SS_CLIENT_PORT:");
        if (ss_client_port_ptr)
            sscanf(ss_client_port_ptr, "SS_CLIENT_PORT:%d", &ss_client_port);

        char *ss_ctrl_port_ptr = strstr(buf, "SS_CTRL_PORT:");
        if (ss_ctrl_port_ptr)
            sscanf(ss_ctrl_port_ptr, "SS_CTRL_PORT:%d", &ss_ctrl_port);
        
        if (strstr(buf, "FILES:")) {
            char *files_start = strstr(buf, "FILES:") + 6;
            char *files_end = strchr(files_start, '\n');
            if (files_end) {
                int len = files_end - files_start;
                if (len > 0 && len < (int)sizeof(file_list)) {
                    strncpy(file_list, files_start, len);
                    file_list[len] = '\0';
                }
            }
        }

        printf("[NS DEBUG] Parsed: name=%s client_port=%d ctrl_port=%d files=%s\n",
            ss_name, ss_client_port, ss_ctrl_port, file_list);

        // Get SS IP from socket
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getpeername(fd, (struct sockaddr *)&addr, &len);
        char ss_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ss_ip, sizeof(ss_ip));

        // Check if SS already registered (allow re-registration for recovery)
        pthread_mutex_lock(&ss_lock);
        int ss_idx = -1;
        for (int i = 0; i < ss_count; i++) {
            // Check if same name exists - re-register it
            if (strcmp(storage_servers[i].ss_name, ss_name) == 0) {
                ss_idx = i;
                printf("[NS] Re-registering existing SS#%d '%s' (recovery)\n", i, ss_name);
                break;
            }
            // Check for duplicate by IP+port combination
            if (strcmp(storage_servers[i].ip, ss_ip) == 0 && 
                storage_servers[i].ctrl_port == ss_ctrl_port) {
                // If IP+Port matches but name is different, it's a conflict
                // But if name matches (handled above), it's a recovery
                pthread_mutex_unlock(&ss_lock);
                char err_msg[256];
                snprintf(err_msg, sizeof(err_msg), 
                         "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server at %s:%d already registered\n\n", 
                         ss_ip, ss_ctrl_port);
                send_message(fd, err_msg);
                printf("[NS] Rejected duplicate SS registration: %s:%d (IP+port conflict)\n", 
                       ss_ip, ss_ctrl_port);
                close(fd);
                return NULL;
            }
        }
        
        // New SS registration
        if (ss_idx == -1) {
            if (ss_count >= MAX_SS) {
                pthread_mutex_unlock(&ss_lock);
                send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Maximum storage servers reached\n\n");
                close(fd);
                return NULL;
            }
            ss_idx = ss_count++;
        }
        
        // Store SS info
        strcpy(storage_servers[ss_idx].ss_name, ss_name);
        strcpy(storage_servers[ss_idx].ip, ss_ip);
        storage_servers[ss_idx].client_port = ss_client_port;
        storage_servers[ss_idx].ctrl_port = ss_ctrl_port;
        storage_servers[ss_idx].active = 1;
        storage_servers[ss_idx].is_replica_of = -1;  // Primary by default
        storage_servers[ss_idx].last_heartbeat = time(NULL);
        storage_servers[ss_idx].file_count = 0;
        
        // Single SS mode: no replica assignment
        pthread_mutex_unlock(&ss_lock);

        printf("[NS] Registered SS#%d '%s' at %s (client:%d, ctrl:%d)\n",
               ss_idx, ss_name, ss_ip, ss_client_port, ss_ctrl_port);

        // Parse and register files (new format: filename:owner:words:chars:modified:access_list|...)
        if (strlen(file_list) > 0) {
            char *file_token = strtok(file_list, "|");
            int file_count = 0;
            while (file_token) {
                char fname[64], owner[64], modified[64], access_list[512];
                int words = 0, chars = 0;
                
                // Parse: filename:owner:words:chars:modified:access_list
                int parsed = sscanf(file_token, "%63[^:]:%63[^:]:%d:%d:%63[^:]:%511[^\n]",
                                   fname, owner, &words, &chars, modified, access_list);
                
                if (parsed >= 5) {  // At least filename, owner, words, chars, modified
                    if (parsed < 6) strcpy(access_list, "");  // No access list
                    
                    CacheNode *existing = cache_get(file_cache, fname);
                    int is_primary_active = 0;
                    int current_primary_idx = -1;
                    int replicas[MAX_REPLICAS];
                    for(int k=0; k<MAX_REPLICAS; k++) replicas[k] = -1;

                    if (existing) {
                        pthread_mutex_lock(&ss_lock);
                        current_primary_idx = existing->ss_id;
                        if (current_primary_idx >= 0 && current_primary_idx < ss_count && storage_servers[current_primary_idx].active) {
                            is_primary_active = 1;
                        }
                        pthread_mutex_unlock(&ss_lock);
                        
                        // Copy existing replicas
                        for(int k=0; k<MAX_REPLICAS; k++) replicas[k] = existing->replica_ss_ids[k];
                    }

                    if (existing && is_primary_active && current_primary_idx != ss_idx) {
                        // Case 1: Primary is active, this is a replica/returning backup.
                        
                        // Trigger Sync
                        pthread_mutex_lock(&ss_lock);
                        StorageServerInfo primary_info = storage_servers[current_primary_idx];
                        pthread_mutex_unlock(&ss_lock);

                        printf("[NS] Syncing stale file '%s' on SS#%d from primary SS#%d\n", 
                               fname, ss_idx, current_primary_idx);
                        
                        int sfd = -1;
                        if (open_ss_connection(ss_idx, &sfd, NULL) == 0) {
                            char sync_msg[512];
                            snprintf(sync_msg, sizeof(sync_msg), 
                                     "TYPE:REQ\nOP:SYNC_FILE\nFILENAME:%s\nSRC_IP:%s\nSRC_PORT:%d\n\n",
                                     fname, primary_info.ip, primary_info.ctrl_port);
                            send_message(sfd, sync_msg);
                            char resp[256];
                            recv_message(sfd, resp, sizeof(resp));
                            close(sfd);
                        }

                        // Add this SS to replicas
                        int found = 0;
                        for(int k=0; k<MAX_REPLICAS; k++) {
                            if (replicas[k] == ss_idx) { found = 1; break; }
                        }
                        if (!found) {
                            for(int k=0; k<MAX_REPLICAS; k++) {
                                if (replicas[k] == -1) { replicas[k] = ss_idx; break; }
                            }
                        }
                        
                        // Update cache: Keep current primary, update replicas
                        cache_put(file_cache, fname, existing->owner, current_primary_idx, replicas, 
                                  existing->words, existing->chars, existing->last_modified, existing->access_list);

                    } else if (existing && !is_primary_active && current_primary_idx != ss_idx) {
                        // Case 2: Primary is INACTIVE, but this SS has the file.
                        // Promote this SS to primary.
                        
                        // Keep existing replicas (excluding this SS if it was one)
                        int new_replicas[MAX_REPLICAS];
                        int r_idx = 0;
                        for(int k=0; k<MAX_REPLICAS; k++) {
                            if (replicas[k] != -1 && replicas[k] != ss_idx) {
                                new_replicas[r_idx++] = replicas[k];
                            }
                        }
                        while(r_idx < MAX_REPLICAS) new_replicas[r_idx++] = -1;
                        
                        printf("[NS] Promoting SS#%d to primary for '%s' (previous primary SS#%d inactive)\n", 
                               ss_idx, fname, current_primary_idx);
                        
                        cache_put(file_cache, fname, owner, ss_idx, new_replicas, words, chars, modified, access_list);
                    } else {
                        // Case 3: New file OR This is the primary
                        // We become (or stay) primary.
                        cache_put(file_cache, fname, owner, ss_idx, replicas, words, chars, modified, access_list);
                    }
                    
                    // Also insert into trie for O(k) lookups
                    CacheNode *node = cache_get(file_cache, fname);
                    if (node) {
                        trie_insert(file_trie, fname, node);
                    }
                    
                    file_count++;
                }
                file_token = strtok(NULL, "|");
            }
            pthread_mutex_lock(&ss_lock);
            storage_servers[ss_idx].file_count = file_count;
            pthread_mutex_unlock(&ss_lock);
            printf("[NS] Loaded %d files from SS#%d\n", file_count, ss_idx);
            LOG_INFO("Loaded %d files from SS#%d (%s)", file_count, ss_idx, ss_name);
        }

        send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:SS Registered Successfully\n\n");
    }


    // REGISTER_CLIENT
    else if (strstr(buf, "OP:REGISTER_CLIENT")) {
        char username[64];
        char *user_ptr = strstr(buf, "USER:");
        if (!user_ptr) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing USER field\n\n");
            close(fd);
            return NULL;
        }
        sscanf(user_ptr, "USER:%63s", username);
        printf("[NS] Registered client: %s\n", username);
        register_user(username);
        send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:Client Registered\n\n");
    }

    // REGISTER_FILE (deprecated - files now registered during SS initialization)
    else if (strstr(buf, "OP:REGISTER_FILE")) {
        send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:Files registered during SS startup\n\n");
    }

    // HEARTBEAT - Update SS last_heartbeat timestamp
    else if (strstr(buf, "OP:HEARTBEAT")) {
        char ss_name[64] = "";
        char *ss_name_ptr = strstr(buf, "SS_NAME:");
        if (ss_name_ptr)
            sscanf(ss_name_ptr, "SS_NAME:%63s", ss_name);
        
        int ss_idx = -1;
        pthread_mutex_lock(&ss_lock);
        for (int i = 0; i < ss_count; i++) {
            if (strcmp(storage_servers[i].ss_name, ss_name) == 0) {
                storage_servers[i].last_heartbeat = time(NULL);
                // If SS was inactive, reactivate it
                if (!storage_servers[i].active) {
                    storage_servers[i].active = 1;
                    printf("[NS] SS%d (%s) recovered and reactivated\n", i, ss_name);
                }
                ss_idx = i;
                break;
            }
        }
        pthread_mutex_unlock(&ss_lock);
        
        if (send_message(fd, "TYPE:RESP\nSTATUS:OK\n\n") != 0) {
            if (ss_idx != -1) {
                printf("\n========================================\n");
                printf("[NS] HEARTBEAT RESPONSE FAILED\n");
                printf("[NS] Failed to send heartbeat ACK to SS#%d (%s)\n", ss_idx, ss_name);
                printf("[NS] Storage Server likely disconnected\n");
                printf("========================================\n\n");
                mark_ss_inactive(ss_idx, "heartbeat response failed - socket write error");
            }
        }
    }

    // CREATE
    else if (strstr(buf, "OP:CREATE")) {
        char fname[64] = {0}, owner[64] = {0};
        char *fname_ptr = strstr(buf, "FILENAME:");
        char *owner_ptr = strstr(buf, "USER:");
        if (!fname_ptr || !owner_ptr) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing required fields\n\n");
            close(fd);
            return NULL;
        }
        sscanf(fname_ptr, "FILENAME:%63s", fname);
        sscanf(owner_ptr, "USER:%63s", owner);

        // Check if file already exists in cache
        if (ensure_file_in_cache(fname)) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File already exists\n\n");
            close(fd);
            return NULL;
        }

        // Choose least-loaded active storage server
        int ss_idx = select_least_loaded_ss();
        if (ss_idx < 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:No storage servers available\n\n");
            close(fd);
            return NULL;
        }
        
        // Select backup SSs
        int backup_ids[MAX_REPLICAS] = {-1, -1};
        int backup_count = 0;
        pthread_mutex_lock(&ss_lock);
        for (int i = 0; i < ss_count; i++) {
            if (i != ss_idx && storage_servers[i].active && backup_count < MAX_REPLICAS) {
                backup_ids[backup_count++] = i;
            }
        }
        pthread_mutex_unlock(&ss_lock);

        int sfd = -1;
        if (open_ss_connection(ss_idx, &sfd, NULL) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Selected storage server unreachable\n\n");
            close(fd);
            return NULL;
        }

        if (ss_idx < 0 || sfd < 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:No reachable storage servers\n\n");
            close(fd);
            return NULL;
        }

        // Construct backup string
        char backup_str[512] = "";
        pthread_mutex_lock(&ss_lock);
        for (int i = 0; i < backup_count; i++) {
            char entry[128];
            StorageServerInfo *bss = &storage_servers[backup_ids[i]];
            // Use control port for inter-SS communication (replication)
            snprintf(entry, sizeof(entry), "%s:%d", bss->ip, bss->ctrl_port);
            if (strlen(backup_str) > 0) strcat(backup_str, ",");
            strcat(backup_str, entry);
        }
        pthread_mutex_unlock(&ss_lock);

        char msg[1024];
        snprintf(msg, sizeof(msg),
                 "TYPE:REQ\nOP:CREATE\nFILENAME:%s\nOWNER:%s\nBACKUPS:%s\n\n", fname, owner, backup_str);
        send_message(sfd, msg);
        
        char resp[512];
        if (recv_message(sfd, resp, sizeof(resp)) != 0 || strstr(resp, "STATUS:ERROR")) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server failed\n\n");
            close(sfd);
            close(fd);
            return NULL;
        }
        close(sfd);

        // Add to cache with SS mapping and initial metadata
        cache_put(file_cache, fname, owner, ss_idx, backup_ids, 0, 0, "N/A", "");
        CacheNode *new_node = cache_get(file_cache, fname);
        if (new_node) {
            trie_insert(file_trie, fname, new_node);
        }
        
        // Increment file count
        pthread_mutex_lock(&ss_lock);
        storage_servers[ss_idx].file_count++;
        pthread_mutex_unlock(&ss_lock);
        
        // Async replication
        for (int i = 0; i < backup_count; i++) {
            trigger_async_replication(backup_ids[i], msg);
            printf("[NS] Replicating CREATE %s to SS#%d\n", fname, backup_ids[i]);
        }
        
        printf("[NS] Created file %s on SS#%d (backups: %d)\n", fname, ss_idx, backup_count);
        LOG_INFO("Created file %s on SS#%d for user %s", fname, ss_idx, owner);
        log_request(owner, "CREATE", fname, owner);
        format_success_message(msg, sizeof(msg), "File Created Successfully");
        send_message(fd, msg);
        log_response(owner, "CREATE", ERR_SUCCESS, "Success");
    }

    // DELETE
    else if (strstr(buf, "OP:DELETE")) {
        char fname[64] = {0}, user[64] = {0};
        char *fname_ptr = strstr(buf, "FILENAME:");
        char *user_ptr = strstr(buf, "USER:");
        if (!fname_ptr || !user_ptr) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing required fields\n\n");
            close(fd);
            return NULL;
        }
        sscanf(fname_ptr, "FILENAME:%63s", fname);
        sscanf(user_ptr, "USER:%63s", user);

        // Ensure file exists in cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }

        // Check ownership
        if (strcmp(file_node->owner, user) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Unauthorized - Only owner can delete\n\n");
            close(fd);
            return NULL;
        }

        // Get SS info
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        int ss_available = (ss_idx >= 0 && ss_idx < ss_count && storage_servers[ss_idx].active);
        pthread_mutex_unlock(&ss_lock);

        if (!ss_available) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available\n\n");
            close(fd);
            return NULL;
        }

        int sfd = -1;
        if (open_ss_connection(ss_idx, &sfd, NULL) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot reach storage server\n\n");
            close(fd);
            return NULL;
        }

        char msg[256];
        snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:DELETE\nFILENAME:%s\n\n", fname);
        send_message(sfd, msg);
        
        char resp[512];
        if (recv_message(sfd, resp, sizeof(resp)) != 0 || strstr(resp, "STATUS:ERROR")) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage delete failed\n\n");
            close(sfd);
            close(fd);
            return NULL;
        }
        close(sfd);

        // Async replication for DELETE
        for (int i = 0; i < MAX_REPLICAS; i++) {
            if (file_node->replica_ss_ids[i] >= 0) {
                trigger_async_replication(file_node->replica_ss_ids[i], msg);
                printf("[NS] Replicating DELETE %s to SS#%d\n", fname, file_node->replica_ss_ids[i]);
            }
        }

        // Decrement file count
        pthread_mutex_lock(&ss_lock);
        if (storage_servers[ss_idx].file_count > 0)
            storage_servers[ss_idx].file_count--;
        pthread_mutex_unlock(&ss_lock);

        // Remove from cache and trie
        cache_remove(file_cache, fname);
        trie_delete(file_trie, fname);
        
        LOG_INFO("Deleted file %s for user %s", fname, user);
        log_request(user, "DELETE", fname, user);
        format_success_message(msg, sizeof(msg), "File deleted successfully");
        send_message(fd, msg);
        log_response(user, "DELETE", ERR_SUCCESS, "Success");
    }

    // VIEW - Serve directly from cache (supports -a, -l, -al flags)
    else if (strstr(buf, "OP:VIEW\n")) {
        char user[64] = {0}, flags[16] = "none";
        if (strstr(buf, "USER:")) sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        if (strstr(buf, "FLAGS:")) sscanf(strstr(buf, "FLAGS:"), "FLAGS:%15s", flags);

        int show_all = strstr(flags, "a") != NULL;   // include other users' files
        int show_long = strstr(flags, "l") != NULL;  // include metadata columns

        char response[8192];
        strcpy(response, "TYPE:RESP\nSTATUS:OK\nMSG:\n");
        int file_count = 0;

        // Iterate through cache and list files (only from ACTIVE storage servers)
        for (int i = 0; i < TABLE_SIZE; i++) {
            pthread_rwlock_rdlock(&file_cache->buckets[i].lock);
            CacheNode *cur = file_cache->buckets[i].head;
            while (cur) {
                // Check if the storage server is active before showing the file
                pthread_mutex_lock(&ss_lock);
                int ss_active = (cur->ss_id >= 0 && cur->ss_id < ss_count && 
                                storage_servers[cur->ss_id].active);
                pthread_mutex_unlock(&ss_lock);
                
                if (ss_active && (show_all || strcmp(cur->owner, user) == 0)) {
                    char file_line[256];
                    if (show_long) {
                        // Format expected by client_main display_view_response() for long view:
                        // filename|words|chars|last_modified|owner
                        snprintf(file_line, sizeof(file_line),
                                 "%s|%d|%d|%s|%s\n",
                                 cur->filename,
                                 cur->words,
                                 cur->chars,
                                 strlen(cur->last_modified) ? cur->last_modified : "N/A",
                                 cur->owner);
                    } else {
                        // Short view: keep previous simple format
                        snprintf(file_line, sizeof(file_line), "%s (owner: %s)\n",
                                 cur->filename, cur->owner);
                    }
                    strncat(response, file_line, sizeof(response) - strlen(response) - 1);
                    file_count++;
                }
                cur = cur->bucket_next;
            }
            pthread_rwlock_unlock(&file_cache->buckets[i].lock);
        }

        strncat(response, "\n", sizeof(response) - strlen(response) - 1);
        send_message(fd, response);
        printf("[NS] Served VIEW from cache (%d files, long=%d, all=%d)\n", file_count, show_long, show_all);
    }

    // READ - Return SS info for direct connection
    else if (strstr(buf, "OP:READ")) {
        char fname[64] = {0}, user[64] = {0};
        char *fname_ptr = strstr(buf, "FILENAME:");
        char *user_ptr = strstr(buf, "USER:");
        if (!fname_ptr || !user_ptr) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing required fields\n\n");
            close(fd);
            return NULL;
        }
        sscanf(fname_ptr, "FILENAME:%63s", fname);
        sscanf(user_ptr, "USER:%63s", user);

        // Check if file exists in cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }

        // Get SS info for this file
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        int target_idx = -1;
        
        if (ss_idx >= 0 && ss_idx < ss_count && storage_servers[ss_idx].active) {
            target_idx = ss_idx;
        } else {
            // Try replicas
            for (int i = 0; i < MAX_REPLICAS; i++) {
                int replica_idx = file_node->replica_ss_ids[i];
                if (replica_idx >= 0 && replica_idx < ss_count && storage_servers[replica_idx].active) {
                    target_idx = replica_idx;
                    printf("[NS] Primary SS#%d down, failing over to Replica SS#%d for %s\n", 
                           ss_idx, target_idx, fname);
                    break;
                }
            }
        }
        
        if (target_idx == -1) {
            pthread_mutex_unlock(&ss_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available (all replicas down)\n\n");
            close(fd);
            return NULL;
        }
        StorageServerInfo target_ss = storage_servers[target_idx];
        pthread_mutex_unlock(&ss_lock);

        // Return SS IP and client port for direct connection
        char response[256];
        snprintf(response, sizeof(response),
                 "TYPE:RESP\nSTATUS:OK\nMSG:IP=%s,CLIENT_PORT=%d,CTRL_PORT=%d\n\n",
                 target_ss.ip, target_ss.client_port, target_ss.ctrl_port);
        send_message(fd, response);
        printf("[NS] Directed READ request for %s to SS#%d at %s:%d\n", 
               fname, target_idx, target_ss.ip, target_ss.ctrl_port);
    }

    // LIST - Return all registered users
    else if (strstr(buf, "OP:LIST")) {
        // Build response with all registered users
        char response[8192];
        snprintf(response, sizeof(response), "TYPE:RESP\nSTATUS:OK\nMSG:\n");
        
        pthread_mutex_lock(&user_lock);
        for (int i = 0; i < user_count; i++) {
            strncat(response, registered_users[i].username, sizeof(response) - strlen(response) - 1);
            strncat(response, "\n", sizeof(response) - strlen(response) - 1);
        }
        pthread_mutex_unlock(&user_lock);
        
        strncat(response, "\n", sizeof(response) - strlen(response) - 1);
        send_message(fd, response);
        printf("[NS] Served LIST: %d registered users\n", user_count);
    }

    // INFO - Serve directly from cache (NS handles without contacting SS)
    else if (strstr(buf, "OP:INFO")) {
        char fname[64] = {0}, user[64] = {0};
        char *fname_ptr = strstr(buf, "FILENAME:");
        char *user_ptr = strstr(buf, "USER:");
        if (!fname_ptr || !user_ptr) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing required fields\n\n");
            close(fd);
            return NULL;
        }
        sscanf(fname_ptr, "FILENAME:%63s", fname);
        sscanf(user_ptr, "USER:%63s", user);

        // Get file from cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }

        // Build response from cached metadata
        char response[2048];
        snprintf(response, sizeof(response),
                 "TYPE:RESP\nSTATUS:OK\nMSG:\n"
                 "Filename: %s\n"
                 "Owner: %s\n"
                 "Words: %d\n"
                 "Characters: %d\n"
                 "Last Modified: %s\n"
                 "Access List: %s\n\n",
                 file_node->filename,
                 file_node->owner,
                 file_node->words,
                 file_node->chars,
                 file_node->last_modified,
                 strlen(file_node->access_list) > 0 ? file_node->access_list : "None");
        
        send_message(fd, response);
        printf("[NS] Served INFO for %s from cache\n", fname);
    }

    // ADDACCESS - Forward to the specific SS that has the file
    else if (strstr(buf, "OP:ADDACCESS")) {
        char fname[64] = {0}, user[64] = {0}, target_user[64] = {0};
        char access_type = 'R';
        char *fname_ptr = strstr(buf, "FILENAME:");
        char *user_ptr = strstr(buf, "USER:");
        char *target_user_ptr = strstr(buf, "TARGET_USER:");
        if (!fname_ptr || !user_ptr || !target_user_ptr) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing required fields\n\n");
            close(fd);
            return NULL;
        }
        sscanf(fname_ptr, "FILENAME:%63s", fname);
        sscanf(user_ptr, "USER:%63s", user);
        sscanf(target_user_ptr, "TARGET_USER:%63s", target_user);
        char *access_type_ptr = strstr(buf, "ACCESS_TYPE:");
        if (access_type_ptr)
            sscanf(access_type_ptr, "ACCESS_TYPE:%c", &access_type);

        // Get file from cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }

        // Check ownership
        if (strcmp(file_node->owner, user) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Unauthorized - Only owner can grant access\n\n");
            close(fd);
            return NULL;
        }

        // Get SS info
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        int ss_available = (ss_idx >= 0 && ss_idx < ss_count && storage_servers[ss_idx].active);
        pthread_mutex_unlock(&ss_lock);

        if (!ss_available) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available\n\n");
            close(fd);
            return NULL;
        }

        int sfd = -1;
        if (open_ss_connection(ss_idx, &sfd, NULL) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot reach storage server\n\n");
            close(fd);
            return NULL;
        }

        char msg[256];
        snprintf(msg, sizeof(msg), 
                 "TYPE:REQ\nOP:ADDACCESS\nFILENAME:%s\nTARGET_USER:%s\nACCESS_TYPE:%c\n\n", 
                 fname, target_user, access_type);
        send_message(sfd, msg);
        
        char resp[1024];
        if (recv_message(sfd, resp, sizeof(resp)) != 0 || strstr(resp, "STATUS:ERROR")) {
            send_message(fd, resp);
            close(sfd);
            close(fd);
            return NULL;
        }
        close(sfd);

        send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:Access granted\n\n");
    }

    // REMACCESS - Forward to the specific SS that has the file
    else if (strstr(buf, "OP:REMACCESS")) {
        char fname[64] = {0}, user[64] = {0}, target_user[64] = {0};
        char *fname_ptr = strstr(buf, "FILENAME:");
        char *user_ptr = strstr(buf, "USER:");
        char *target_user_ptr = strstr(buf, "TARGET_USER:");
        if (!fname_ptr || !user_ptr || !target_user_ptr) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing required fields\n\n");
            close(fd);
            return NULL;
        }
        sscanf(fname_ptr, "FILENAME:%63s", fname);
        sscanf(user_ptr, "USER:%63s", user);
        sscanf(target_user_ptr, "TARGET_USER:%63s", target_user);

        // Get file from cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }

        // Check ownership
        if (strcmp(file_node->owner, user) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Unauthorized - Only owner can remove access\n\n");
            close(fd);
            return NULL;
        }

        // Get SS info
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        int ss_available = (ss_idx >= 0 && ss_idx < ss_count && storage_servers[ss_idx].active);
        pthread_mutex_unlock(&ss_lock);

        if (!ss_available) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available\n\n");
            close(fd);
            return NULL;
        }

        int sfd = -1;
        if (open_ss_connection(ss_idx, &sfd, NULL) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot reach storage server\n\n");
            close(fd);
            return NULL;
        }

        char msg[256];
        snprintf(msg, sizeof(msg), 
                 "TYPE:REQ\nOP:REMACCESS\nFILENAME:%s\nTARGET_USER:%s\n\n", 
                 fname, target_user);
        send_message(sfd, msg);
        
        char resp[1024];
        if (recv_message(sfd, resp, sizeof(resp)) != 0 || strstr(resp, "STATUS:ERROR")) {
            send_message(fd, resp);
            close(sfd);
            close(fd);
            return NULL;
        }
        close(sfd);

        send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:Access removed\n\n");
    }

    else if (strstr(buf, "OP:GET_SS_INFO")) {
        char fname[64] = {0};
        if (strstr(buf, "FILENAME:"))
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);

        // If filename provided, get specific SS for that file
        if (strlen(fname) > 0) {
            CacheNode *file_node = cache_get(file_cache, fname);
            if (!file_node) {
                send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
                close(fd);
                return NULL;
            }

            pthread_mutex_lock(&ss_lock);
            int ss_idx = file_node->ss_id;
            if (ss_idx < 0 || ss_idx >= ss_count || !storage_servers[ss_idx].active) {
                pthread_mutex_unlock(&ss_lock);
                send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available\n\n");
                close(fd);
                return NULL;
            }
            
            char response[256];
            snprintf(response, sizeof(response),
                     "TYPE:RESP\nSTATUS:OK\nMSG:IP=%s,CLIENT_PORT=%d,CTRL_PORT=%d\n\n",
                     storage_servers[ss_idx].ip,
                     storage_servers[ss_idx].client_port,
                     storage_servers[ss_idx].ctrl_port);
            pthread_mutex_unlock(&ss_lock);
            send_message(fd, response);
        } else {
            // No filename - return first available SS (backward compatibility)
            pthread_mutex_lock(&ss_lock);
            if (ss_count == 0) {
                pthread_mutex_unlock(&ss_lock);
                send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:No Storage Server registered\n\n");
                close(fd);
                return NULL;
            }

            char response[256];
            snprintf(response, sizeof(response),
                     "TYPE:RESP\nSTATUS:OK\nMSG:IP=%s,CLIENT_PORT=%d,CTRL_PORT=%d\n\n",
                     storage_servers[0].ip,
                     storage_servers[0].client_port,
                     storage_servers[0].ctrl_port);
            pthread_mutex_unlock(&ss_lock);
            send_message(fd, response);
        }
    }


    // WRITE_START - Return SS info for direct connection
    else if (strstr(buf, "OP:WRITE_START")) {
        char fname[64] = {0}, user[64] = {0};
        int sentence_num = 0;
        sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
        sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        sscanf(strstr(buf, "SENTENCE:"), "SENTENCE:%d", &sentence_num);

        // Check if file exists in cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }

        // Get SS info for this file
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        if (ss_idx < 0 || ss_idx >= ss_count || !storage_servers[ss_idx].active) {
            pthread_mutex_unlock(&ss_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available\n\n");
            close(fd);
            return NULL;
        }
        StorageServerInfo target_ss = storage_servers[ss_idx];
        pthread_mutex_unlock(&ss_lock);

        // Return SS IP and ctrl port for direct connection
        char response[256];
        snprintf(response, sizeof(response),
                 "TYPE:RESP\nSTATUS:OK\nMSG:IP=%s,CLIENT_PORT=%d,CTRL_PORT=%d\n\n",
                 target_ss.ip, target_ss.client_port, target_ss.ctrl_port);
        send_message(fd, response);
        printf("[NS] Directed WRITE_START request for %s to SS#%d at %s:%d\n", 
               fname, ss_idx, target_ss.ip, target_ss.ctrl_port);
    }

    // WRITE_COMMIT - Return SS info for direct connection
    else if (strstr(buf, "OP:WRITE_COMMIT")) {
        char fname[64] = {0}, user[64] = {0};
        int sentence_num = 0;
        sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
        sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        sscanf(strstr(buf, "SENTENCE:"), "SENTENCE:%d", &sentence_num);

        // Check if file exists in cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }

        // Get SS info for this file
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        if (ss_idx < 0 || ss_idx >= ss_count || !storage_servers[ss_idx].active) {
            pthread_mutex_unlock(&ss_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available\n\n");
            close(fd);
            return NULL;
        }
        StorageServerInfo target_ss = storage_servers[ss_idx];
        pthread_mutex_unlock(&ss_lock);

        // Return SS IP and ctrl port for direct connection
        char response[256];
        snprintf(response, sizeof(response),
                 "TYPE:RESP\nSTATUS:OK\nMSG:IP=%s,CLIENT_PORT=%d,CTRL_PORT=%d\n\n",
                 target_ss.ip, target_ss.client_port, target_ss.ctrl_port);
        send_message(fd, response);
        printf("[NS] Directed WRITE_COMMIT request for %s to SS#%d at %s:%d\n", 
               fname, ss_idx, target_ss.ip, target_ss.ctrl_port);
    }

    // EXEC - Execute file content as shell commands
    else if (strstr(buf, "OP:EXEC")) {
        char fname[64] = {0}, user[64] = {0};
        sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
        sscanf(strstr(buf, "USER:"), "USER:%63s", user);

        LOG_INFO("EXEC request for %s by user %s", fname, user);
        log_request(user, "EXEC", fname, user);

        // Check if file exists in cache (using trie for O(k) lookup)
        void *trie_result = trie_search(file_trie, fname);
        CacheNode *file_node = trie_result ? (CacheNode*)trie_result : cache_get(file_cache, fname);
        
        if (!file_node) {
            char err_msg[256];
            format_error_message(err_msg, sizeof(err_msg), ERR_FILE_NOT_FOUND, fname);
            send_message(fd, err_msg);
            LOG_WARN("EXEC: File %s not found", fname);
            log_response(user, "EXEC", ERR_FILE_NOT_FOUND, fname);
            close(fd);
            return NULL;
        }

        // Get SS info for this file
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        if (ss_idx < 0 || ss_idx >= ss_count || !storage_servers[ss_idx].active) {
            pthread_mutex_unlock(&ss_lock);
            char err_msg[256];
            format_error_message(err_msg, sizeof(err_msg), ERR_SS_NOT_AVAILABLE, "");
            send_message(fd, err_msg);
            LOG_ERROR("EXEC: SS not available for %s", fname);
            log_response(user, "EXEC", ERR_SS_NOT_AVAILABLE, "");
            close(fd);
            return NULL;
        }
        StorageServerInfo target_ss = storage_servers[ss_idx];
        pthread_mutex_unlock(&ss_lock);

        // Request file content from SS (use control port where READ lives)
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in ss_addr = {0};
        ss_addr.sin_family = AF_INET;
        ss_addr.sin_port = htons(target_ss.ctrl_port);
        inet_pton(AF_INET, target_ss.ip, &ss_addr.sin_addr);
        
        if (connect(sfd, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
            char err_msg[256];
            format_error_message(err_msg, sizeof(err_msg), ERR_CONNECTION_FAILED, "SS");
            send_message(fd, err_msg);
            LOG_ERROR("EXEC: Cannot connect to SS for %s", fname);
            log_response(user, "EXEC", ERR_CONNECTION_FAILED, "SS");
            close(fd);
            return NULL;
        }

        // Send READ request to SS
        char msg[256];
        snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:READ\nUSER:%s\nFILENAME:%s\n\n", user, fname);
        send_message(sfd, msg);
        
        char resp[8192];
        if (recv_message(sfd, resp, sizeof(resp)) != 0 || strstr(resp, "STATUS:ERROR")) {
            close(sfd);
            char err_msg[256];
            format_error_message(err_msg, sizeof(err_msg), ERR_FILE_READ_FAILED, fname);
            send_message(fd, err_msg);
            LOG_ERROR("EXEC: Failed to read %s from SS", fname);
            log_response(user, "EXEC", ERR_FILE_READ_FAILED, fname);
            close(fd);
            return NULL;
        }
        close(sfd);

        // Extract content
        char *content = strstr(resp, "MSG:");
        if (!content) {
            char err_msg[256];
            format_error_message(err_msg, sizeof(err_msg), ERR_INVALID_MESSAGE, "");
            send_message(fd, err_msg);
            LOG_ERROR("EXEC: Invalid response from SS for %s", fname);
            log_response(user, "EXEC", ERR_INVALID_MESSAGE, "");
            close(fd);
            return NULL;
        }
        content += 4;
        while (*content == '\n') content++;

        LOG_INFO("EXEC: Executing commands from %s", fname);

        // Create temporary script file
        char temp_script[128];
        snprintf(temp_script, sizeof(temp_script), "/tmp/exec_%s_%d.sh", fname, (int)time(NULL));
        FILE *script = fopen(temp_script, "w");
        if (!script) {
            char err_msg[256];
            format_error_message(err_msg, sizeof(err_msg), ERR_FILE_CREATE_FAILED, "temp script");
            send_message(fd, err_msg);
            LOG_ERROR("EXEC: Cannot create temp script for %s", fname);
            log_response(user, "EXEC", ERR_FILE_CREATE_FAILED, "script");
            close(fd);
            return NULL;
        }
        fprintf(script, "#!/bin/bash\n%s\n", content);
        fclose(script);
        chmod(temp_script, 0700);

        // Execute script and capture output
        char exec_cmd[256];
        snprintf(exec_cmd, sizeof(exec_cmd), "%s 2>&1", temp_script);
        FILE *pipe = popen(exec_cmd, "r");
        if (!pipe) {
            remove(temp_script);
            char err_msg[256];
            format_error_message(err_msg, sizeof(err_msg), ERR_EXEC_FAILED, "");
            send_message(fd, err_msg);
            LOG_ERROR("EXEC: popen failed for %s", fname);
            log_response(user, "EXEC", ERR_EXEC_FAILED, "popen");
            close(fd);
            return NULL;
        }

        char output[8192] = "";
        char line[512];
        while (fgets(line, sizeof(line), pipe)) {
            strncat(output, line, sizeof(output) - strlen(output) - 1);
        }
        int status = pclose(pipe);
        remove(temp_script);

        // Send output back to client
        char response[16384];
        snprintf(response, sizeof(response),
                 "TYPE:RESP\nSTATUS:OK\nCODE:0\nEXIT_CODE:%d\nMSG:\n%s\n",
                 WEXITSTATUS(status), output);
        send_message(fd, response);
        
        LOG_INFO("EXEC: Successfully executed %s, exit code: %d", fname, WEXITSTATUS(status));
        log_response(user, "EXEC", ERR_SUCCESS, "Success");
        printf("[NS] Executed file %s for user %s (exit: %d)\n", fname, user, WEXITSTATUS(status));
    }

    // UPDATE_CACHE - SS notifies NS to update cached metadata
    else if (strstr(buf, "OP:UPDATE_CACHE")) {
        char fname[64] = {0}, owner[64] = {0}, modified[64] = {0}, access_list[512] = {0};
        int words = 0, chars = 0, ss_id = -1;
        
        if (strstr(buf, "FILENAME:")) sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
        if (strstr(buf, "OWNER:")) sscanf(strstr(buf, "OWNER:"), "OWNER:%63s", owner);
        if (strstr(buf, "WORDS:")) sscanf(strstr(buf, "WORDS:"), "WORDS:%d", &words);
        if (strstr(buf, "CHARS:")) sscanf(strstr(buf, "CHARS:"), "CHARS:%d", &chars);
        if (strstr(buf, "MODIFIED:")) sscanf(strstr(buf, "MODIFIED:"), "MODIFIED:%63s", modified);
        if (strstr(buf, "SS_ID:")) sscanf(strstr(buf, "SS_ID:"), "SS_ID:%d", &ss_id);
        
        // Parse ACCESS_LIST (may contain commas)
        if (strstr(buf, "ACCESS_LIST:")) {
            char *access_start = strstr(buf, "ACCESS_LIST:") + 12;
            char *access_end = strchr(access_start, '\n');
            if (access_end) {
                int len = access_end - access_start;
                if (len > 0 && len < (int)sizeof(access_list)) {
                    strncpy(access_list, access_start, len);
                    access_list[len] = '\0';
                }
            }
        }
        
        // Update cache entry
        CacheNode *node = cache_get(file_cache, fname);
        if (node) {
            cache_put(file_cache, fname, owner, (ss_id >= 0 ? ss_id : node->ss_id), NULL,
                     words, chars, modified, access_list);
            printf("[NS] Updated cache for %s (words=%d, chars=%d, access=%s)\n", 
                   fname, words, chars, access_list);
            send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:Cache updated\n\n");
        } else {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not in cache\n\n");
        }
    }

    // REQUESTACCESS - User requests access to a file
    else if (strstr(buf, "OP:REQUESTACCESS")) {
        char fname[64] = {0}, user[64] = {0};
        char access_type = 'R';
        
        sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
        sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        if (strstr(buf, "ACCESS_TYPE:"))
            sscanf(strstr(buf, "ACCESS_TYPE:"), "ACCESS_TYPE:%c", &access_type);
        
        // Get file owner from cache
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }
        
        // Check if user is already owner
        if (strcmp(file_node->owner, user) == 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:You are the owner\n\n");
            close(fd);
            return NULL;
        }
        
        // Add request
        int result = add_access_request(fname, user, file_node->owner, access_type);
        if (result == -1) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Request already pending\n\n");
        } else if (result == -2) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Too many requests\n\n");
        } else {
            char response[256];
            snprintf(response, sizeof(response), 
                    "TYPE:RESP\nSTATUS:OK\nMSG:Access request sent to %s\n\n", 
                    file_node->owner);
            send_message(fd, response);
            printf("[NS] Access request: %s requesting %c access to %s (owner: %s)\n", 
                   user, access_type, fname, file_node->owner);
        }
    }

    // VIEWREQUESTS - Owner views pending access requests
    else if (strstr(buf, "OP:VIEWREQUESTS")) {
        char user[64] = {0};
        sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        
        char response[4096];
        snprintf(response, sizeof(response), "TYPE:RESP\nSTATUS:OK\nMSG:\n");
        
        pthread_mutex_lock(&request_lock);
        int found = 0;
        for (int i = 0; i < request_count; i++) {
            if (strcmp(access_requests[i].owner, user) == 0 && access_requests[i].pending == 1) {
                const char *access_label = (access_requests[i].access_type == 'W') ? "WRITE" : "READ";
                char line[256];
                snprintf(line, sizeof(line),
                        "ID: %d | %s requests %s access to %s\n",
                        i, access_requests[i].requester,
                        access_label, access_requests[i].filename);
                strncat(response, line, sizeof(response) - strlen(response) - 1);
                found = 1;
            }
        }
        pthread_mutex_unlock(&request_lock);

        if (!found) {
            strncat(response, "No pending requests\n", sizeof(response) - strlen(response) - 1);
        } else {
            strncat(response,
                    "Use APPROVEREQUEST <ID> or DENYREQUEST <ID> to act.\n",
                    sizeof(response) - strlen(response) - 1);
        }
        strncat(response, "\n", sizeof(response) - strlen(response) - 1);
        send_message(fd, response);
        printf("[NS] %s viewed access requests\n", user);
    }

    // APPROVEREQUEST - Owner approves access request
    else if (strstr(buf, "OP:APPROVEREQUEST")) {
        int request_id = -1;
        char user[64] = {0};
        
        if (strstr(buf, "USER:"))
            sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        if (strstr(buf, "REQUEST_ID:"))
            sscanf(strstr(buf, "REQUEST_ID:"), "REQUEST_ID:%d", &request_id);
        
        pthread_mutex_lock(&request_lock);
        
        if (request_id < 0 || request_id >= request_count) {
            pthread_mutex_unlock(&request_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Invalid request ID\n\n");
            close(fd);
            return NULL;
        }
        
        AccessRequest *req = &access_requests[request_id];
        
        // Verify ownership and pending status
        if (strcmp(req->owner, user) != 0) {
            pthread_mutex_unlock(&request_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Not your file\n\n");
            close(fd);
            return NULL;
        }
        
        if (req->pending == 0) {
            pthread_mutex_unlock(&request_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Request already processed\n\n");
            close(fd);
            return NULL;
        }
        
        // Mark as processed
        req->pending = 0;
        
        // Save request details before unlocking
        char fname[64], requester[64];
        char access_type = req->access_type;
        strncpy(fname, req->filename, 63);
        strncpy(requester, req->requester, 63);
        
        pthread_mutex_unlock(&request_lock);
        
        // Now grant access via ADDACCESS to SS
        CacheNode *file_node = cache_get(file_cache, fname);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            close(fd);
            return NULL;
        }
        
        // Get SS info
        pthread_mutex_lock(&ss_lock);
        int ss_idx = file_node->ss_id;
        if (ss_idx < 0 || ss_idx >= ss_count || !storage_servers[ss_idx].active) {
            pthread_mutex_unlock(&ss_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server not available\n\n");
            close(fd);
            return NULL;
        }
        StorageServerInfo target_ss = storage_servers[ss_idx];
        pthread_mutex_unlock(&ss_lock);
        
        // Forward ADDACCESS to SS
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in ss_addr = {0};
        ss_addr.sin_family = AF_INET;
        ss_addr.sin_port = htons(target_ss.ctrl_port);
        inet_pton(AF_INET, target_ss.ip, &ss_addr.sin_addr);
        
        if (connect(sfd, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot connect to SS\n\n");
            close(sfd);
            close(fd);
            return NULL;
        }
        
        char ss_msg[512];
        snprintf(ss_msg, sizeof(ss_msg), 
            "TYPE:REQ\nOP:ADDACCESS\nFILENAME:%s\nTARGET_USER:%s\nACCESS_TYPE:%c\n\n",
                fname, requester, access_type);
        send_message(sfd, ss_msg);
        
        char ss_response[1024];
        recv_message(sfd, ss_response, sizeof(ss_response));
        close(sfd);
        
        if (strstr(ss_response, "STATUS:OK")) {
            char response[256];
            snprintf(response, sizeof(response),
                    "TYPE:RESP\nSTATUS:OK\nMSG:Access granted to %s\n\n", requester);
            send_message(fd, response);
            printf("[NS] Approved: %s granted %c access to %s for %s\n", 
                   user, access_type, fname, requester);
        } else {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Failed to grant access\n\n");
        }
    }

    // DENYREQUEST - Owner denies access request
    else if (strstr(buf, "OP:DENYREQUEST")) {
        int request_id = -1;
        char user[64] = {0};
        
        if (strstr(buf, "USER:"))
            sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        if (strstr(buf, "REQUEST_ID:"))
            sscanf(strstr(buf, "REQUEST_ID:"), "REQUEST_ID:%d", &request_id);
        
        pthread_mutex_lock(&request_lock);
        
        if (request_id < 0 || request_id >= request_count) {
            pthread_mutex_unlock(&request_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Invalid request ID\n\n");
            close(fd);
            return NULL;
        }
        
        AccessRequest *req = &access_requests[request_id];
        
        // Verify ownership and pending status
        if (strcmp(req->owner, user) != 0) {
            pthread_mutex_unlock(&request_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Not your file\n\n");
            close(fd);
            return NULL;
        }
        
        if (req->pending == 0) {
            pthread_mutex_unlock(&request_lock);
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Request already processed\n\n");
            close(fd);
            return NULL;
        }
        
        // Mark as processed (denied)
        req->pending = 0;
        char requester[64];
        strncpy(requester, req->requester, 63);
        
        pthread_mutex_unlock(&request_lock);
        
        char response[256];
        snprintf(response, sizeof(response),
                "TYPE:RESP\nSTATUS:OK\nMSG:Request denied\n\n");
        send_message(fd, response);
        printf("[NS] Denied: %s rejected access request from %s\n", user, requester);
    }

    // CREATEFOLDER - Create a new folder
    else if (strstr(buf, "OP:CREATEFOLDER")) {
        char foldername[256] = "";
        char user[64] = "";

        char *folder_ptr = strstr(buf, "FOLDERNAME:");
        if (folder_ptr) sscanf(folder_ptr, "FOLDERNAME:%255[^\n]", foldername);
        
        char *user_ptr = strstr(buf, "USER:");
        if (user_ptr) sscanf(user_ptr, "USER:%63[^\n]", user);
        
        // Trim trailing newlines/CRs from sscanf result
        rstrip(foldername);
        rstrip(user);
        
        printf("[NS] CREATEFOLDER request: folder='%s' user='%s'\n", foldername, user);
        
        // Validate required fields
        if (strlen(foldername) == 0 || strlen(user) == 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing required fields\n\n");
            printf("[NS] CREATEFOLDER rejected: missing foldername or user\n");
            close(fd);
            return NULL;
        }
        
        // Normalize path
        char normalized[256];
        normalize_path(foldername, normalized);
        
        // Check if folder already exists
        if (ensure_file_in_cache(normalized)) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Folder already exists\n\n");
            printf("[NS] CREATEFOLDER failed: folder '%s' already exists\n", normalized);
            close(fd);
            return NULL;
        }
        
        // Choose least-loaded active storage server
        int ss_idx = select_least_loaded_ss();
        if (ss_idx < 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:No storage server available\n\n");
            close(fd);
            return NULL;
        }
        
        // Select backup SSs
        int backup_ids[MAX_REPLICAS] = {-1, -1};
        int backup_count = 0;
        pthread_mutex_lock(&ss_lock);
        for (int i = 0; i < ss_count; i++) {
            if (i != ss_idx && storage_servers[i].active && backup_count < MAX_REPLICAS) {
                backup_ids[backup_count++] = i;
            }
        }
        pthread_mutex_unlock(&ss_lock);

        int ss_sock = -1;
        if (open_ss_connection(ss_idx, &ss_sock, NULL) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot reach storage server\n\n");
            close(fd);
            return NULL;
        }
        
        char ss_msg[512];
        snprintf(ss_msg, sizeof(ss_msg),
                "TYPE:REQ\nOP:CREATEFOLDER\nFOLDERNAME:%s\nOWNER:%s\n\n",
                normalized, user);
        
        send_message(ss_sock, ss_msg);
        
        char ss_resp[1024];
        recv_message(ss_sock, ss_resp, sizeof(ss_resp));
        close(ss_sock);
        
        if (strstr(ss_resp, "STATUS:OK")) {
            // Add folder to cache with special marker
            cache_put(file_cache, normalized, user, ss_idx, backup_ids, 0, 0, "folder", "type:folder");
            CacheNode *new_node = cache_get(file_cache, normalized);
            if (new_node) trie_insert(file_trie, normalized, new_node);
            
            // Async replication
            for (int i = 0; i < backup_count; i++) {
                trigger_async_replication(backup_ids[i], ss_msg);
                printf("[NS] Replicating CREATEFOLDER %s to SS#%d\n", normalized, backup_ids[i]);
            }
            
            // Single SS mode: no replication
            
            send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:Folder created successfully\n\n");
            printf("[NS] CREATEFOLDER success: '%s' created on SS%d\n", normalized, ss_idx);
        } else {
            send_message(fd, ss_resp);
            printf("[NS] CREATEFOLDER failed: SS returned error\n");
        }
    }

    // VIEWFOLDER - List contents of a folder
    else if (strstr(buf, "OP:VIEWFOLDER")) {
        char foldername[256] = "";
        
        char *folder_ptr = strstr(buf, "FOLDERNAME:");
        if (folder_ptr) sscanf(folder_ptr, "FOLDERNAME:%255[^\n]", foldername);
        rstrip(foldername);
        
        if (strlen(foldername) == 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Missing folder name\n\n");
            close(fd);
            return NULL;
        }

        printf("[NS] VIEWFOLDER request: folder=%s\n", foldername);
        
        // Normalize path
        char normalized[256];
        normalize_path(foldername, normalized);
        
        // Search cache for files starting with this folder path
        char result[8192] = "";
        int count = 0;
        
        // Iterate through cache to find matching paths
        for (int i = 0; i < TABLE_SIZE; i++) {
            pthread_rwlock_rdlock(&file_cache->buckets[i].lock);
            CacheNode *node = file_cache->buckets[i].head;
            while (node) {
                // Check if file path starts with folder path
                if (strncmp(node->filename, normalized, strlen(normalized)) == 0 &&
                    node->filename[strlen(normalized)] == '/') {
                    // Extract just the immediate child (not grandchildren)
                    const char *child = node->filename + strlen(normalized) + 1;
                    if (strchr(child, '/') == NULL) {
                        char line[128];
                        // Determine type from access_list metadata (contains "type:folder" for folders)
                        const char *type = strstr(node->access_list, "type:folder") ? "folder" : "file";
                        snprintf(line, sizeof(line), "%s|%s\n", child, type);
                        strncat(result, line, sizeof(result) - strlen(result) - 1);
                        count++;
                    }
                }
                node = node->bucket_next;
            }
            pthread_rwlock_unlock(&file_cache->buckets[i].lock);
        }
        
        if (count == 0) {
            char response[512];
            snprintf(response, sizeof(response),
                    "TYPE:RESP\nSTATUS:OK\nMSG:Folder is empty\nFILES:\n\n");
            send_message(fd, response);
        } else {
            char response[16384];
            snprintf(response, sizeof(response),
                    "TYPE:RESP\nSTATUS:OK\nMSG:Folder contents\nFILES:%s\n", result);
            send_message(fd, response);
        }
        
        printf("[NS] VIEWFOLDER: found %d items in '%s'\n", count, normalized);
    }

    // MOVE - Move file to a folder
    else if (strstr(buf, "OP:MOVE")) {
        char filename[256] = "";
        char foldername[256] = "";
        char user[64] = "";
        
        char *filename_ptr = strstr(buf, "FILENAME:");
        if (filename_ptr)
            sscanf(filename_ptr, "FILENAME:%255s", filename);
        char *folder_ptr = strstr(buf, "FOLDERNAME:");
        if (folder_ptr)
            sscanf(folder_ptr, "FOLDERNAME:%255s", foldername);
        if (strstr(buf, "USER:"))
            sscanf(strstr(buf, "USER:"), "USER:%63s", user);
        
        printf("[NS] MOVE request: file=%s to folder=%s by user=%s\n", filename, foldername, user);
        
        // Check if source file exists
        CacheNode *file_node = cache_get(file_cache, filename);
        if (!file_node) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
            return NULL;
        }
        
        // Check if user is owner
        if (strcmp(file_node->owner, user) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Only owner can move files\n\n");
            return NULL;
        }
        
        // Normalize folder path and create destination
        char norm_folder[256];
        normalize_path(foldername, norm_folder);
        
        char *basename = strrchr(filename, '/');
        if (basename) basename++; // Skip '/'
        else basename = filename;
        
        char dest_path[512];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", norm_folder, basename);
        
        // Check if destination already exists
        if (ensure_file_in_cache(dest_path)) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Destination already exists\n\n");
            return NULL;
        }
        
        // Get SS for file
        int ss_idx = file_node->ss_id;
        if (ss_idx < 0 || ss_idx >= ss_count || !storage_servers[ss_idx].active) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Storage server unavailable\n\n");
            return NULL;
        }
        
        int ss_sock = -1;
        if (open_ss_connection(ss_idx, &ss_sock, NULL) != 0) {
            send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot reach storage server\n\n");
            close(fd);
            return NULL;
        }
        
        char ss_msg[1024];
        snprintf(ss_msg, sizeof(ss_msg),
                "TYPE:REQ\nOP:MOVE\nFILENAME:%s\nDEST:%s\n\n",
                filename, dest_path);
        
        send_message(ss_sock, ss_msg);
        
        char ss_resp[1024];
        recv_message(ss_sock, ss_resp, sizeof(ss_resp));
        close(ss_sock);
        
        if (strstr(ss_resp, "STATUS:OK")) {
            // Update cache: remove old entry, add new entry
            // Need to copy metadata before removing
            char owner_copy[64], modified_copy[64], access_copy[512];
            int words = file_node->words;
            int chars = file_node->chars;
            int ss_id = file_node->ss_id;
            int replica_ids[MAX_REPLICAS];
            for(int i=0; i<MAX_REPLICAS; i++) replica_ids[i] = file_node->replica_ss_ids[i];
            
            strcpy(owner_copy, file_node->owner);
            strcpy(modified_copy, file_node->last_modified);
            strcpy(access_copy, file_node->access_list);
            
            cache_remove(file_cache, filename);
            trie_delete(file_trie, filename);
            
            cache_put(file_cache, dest_path, owner_copy, ss_id, replica_ids,
                     words, chars, modified_copy, access_copy);
            CacheNode *moved_node = cache_get(file_cache, dest_path);
            if (moved_node) trie_insert(file_trie, dest_path, moved_node);
            
            // Async replication
            for (int i = 0; i < MAX_REPLICAS; i++) {
                if (replica_ids[i] >= 0) {
                    trigger_async_replication(replica_ids[i], ss_msg);
                    printf("[NS] Replicating MOVE %s to SS#%d\n", filename, replica_ids[i]);
                }
            }
            
            send_message(fd, "TYPE:RESP\nSTATUS:OK\nMSG:File moved successfully\n\n");
            printf("[NS] MOVE success: '%s' -> '%s'\n", filename, dest_path);
        }
    }
    else {
        send_message(fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Unknown Operation\n\n");
    }

    close(fd);
    return NULL;
}

/* Heartbeat monitoring thread */
void *heartbeat_monitor(void *arg) {
    (void)arg;
    printf("[NS] Heartbeat monitor thread started\n");
    
    while (heartbeat_running) {
        sleep(5);  // Check every 5 seconds for faster detection
        
        time_t now = time(NULL);
        pthread_mutex_lock(&ss_lock);
        
        for (int i = 0; i < ss_count; i++) {
            if (storage_servers[i].active) {
                // Check SS heartbeat (timeout: 10 seconds for immediate detection)
                if (now - storage_servers[i].last_heartbeat > 10) {
                    pthread_mutex_unlock(&ss_lock);
                    
                    // Use mark_ss_inactive for consistent logging and cleanup
                    char reason[128];
                    snprintf(reason, sizeof(reason), "heartbeat timeout (%ld seconds)",
                            (long)(now - storage_servers[i].last_heartbeat));
                    mark_ss_inactive(i, reason);
                    
                    pthread_mutex_lock(&ss_lock);
                }
            }
        }
        
        pthread_mutex_unlock(&ss_lock);
    }
    
    printf("[NS] Heartbeat monitor thread stopped\n");
    return NULL;
}

/* Async task for replication */
typedef struct {
    int ss_idx;
    char msg[1024];
} AsyncTask;

void *async_send_task(void *arg) {
    AsyncTask *task = (AsyncTask *)arg;
    int fd;
    if (open_ss_connection(task->ss_idx, &fd, NULL) == 0) {
        send_message(fd, task->msg);
        // Don't wait for response for async replication
        // But maybe read to clear buffer?
        char resp[512];
        recv_message(fd, resp, sizeof(resp));
        close(fd);
    }
    free(task);
    return NULL;
}

void trigger_async_replication(int ss_idx, const char *msg) {
    AsyncTask *task = malloc(sizeof(AsyncTask));
    task->ss_idx = ss_idx;
    strncpy(task->msg, msg, sizeof(task->msg) - 1);
    
    pthread_t tid;
    if (pthread_create(&tid, NULL, async_send_task, task) == 0) {
        pthread_detach(tid);
    } else {
        free(task);
    }
}

/* Single SS mode: replication disabled */

int main() {
    // Ignore SIGPIPE so abrupt client disconnects don't kill the NS process
    signal(SIGPIPE, SIG_IGN);

    // Initialize logging
    if (init_logging(COMP_NS, "logs") != 0) {
        printf("[NS] Warning: Failed to initialize logging\n");
    }
    LOG_INFO("Name Server starting up...");
    
    // Initialize LRU cache
    file_cache = cache_init(CACHE_CAPACITY);
    printf("[NS] Initialized LRU cache (capacity: %d)\n", CACHE_CAPACITY);
    LOG_INFO("Initialized LRU cache with capacity %d", CACHE_CAPACITY);
    
    // Initialize Trie for efficient filename search
    file_trie = trie_init();
    printf("[NS] Initialized Trie for efficient file search\n");
    LOG_INFO("Initialized Trie for O(k) filename lookups");
    
    // Start heartbeat monitoring thread
    if (pthread_create(&heartbeat_thread, NULL, heartbeat_monitor, NULL) != 0) {
        printf("[NS] Warning: Failed to start heartbeat monitor\n");
    } else {
        printf("[NS] Heartbeat monitor started\n");
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0}, cli;
    socklen_t cli_len = sizeof(cli);
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 10);
    printf("[NS] Listening on port %d...\n", PORT);
    LOG_INFO("Name Server listening on port %d", PORT);
    log_network("LISTEN", "0.0.0.0", PORT, "NS ready for connections");

    while (1) {
        int client_fd = accept(server_fd, (struct sockaddr *)&cli, &cli_len);
        
        // Log connection
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli.sin_addr, client_ip, sizeof(client_ip));
        log_network("ACCEPT", client_ip, ntohs(cli.sin_port), "New connection");
        
        int *p = malloc(sizeof(int));
        *p = client_fd;
        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, p);
        pthread_detach(tid);
    }
    
    // Cleanup (unreachable in infinite loop, but good practice)
    LOG_INFO("Name Server shutting down");
    cache_destroy(file_cache);
    trie_destroy(file_trie);
    close_logging();
    return 0;
}