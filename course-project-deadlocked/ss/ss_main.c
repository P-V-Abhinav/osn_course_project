#include "../common/protocol.h"
#include "../common/error_codes.h"
#include "../common/logging.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>

#define NS_PORT 8080

/* Global SS configuration - set at runtime */
char NS_IP[64] = "127.0.0.1";  // Can be overridden by environment variable or command-line
char SS_NAME[64] = "ss1";
int SS_CLIENT_PORT = 6000;
int SS_CTRL_PORT = 6001;
char FILES_DIR[128] = "ss/files";  // Base directory for this SS's files

/* Per-file locks using a hash table of reader-writer locks */
#define FILE_LOCK_BUCKETS 64
pthread_rwlock_t file_locks[FILE_LOCK_BUCKETS];

/* Max words in a sentence (used by parse/updates) */
#define MAX_WORDS 500

/* Sentence lock structure with client tracking */
typedef struct {
    char filename[64];
    int sentence_num;
    char user[64];
    time_t lock_time;
    int active;
} SentenceLock;

#define MAX_SENTENCE_LOCKS 100
#define LOCK_TIMEOUT_SECONDS 300  // 5 minutes timeout for stale locks
SentenceLock sentence_locks[MAX_SENTENCE_LOCKS];
pthread_mutex_t sentence_lock_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MAX_WRITE_UPDATES 512

/* Hash function for file-level locking */
static unsigned int hash_for_lock(const char *fname) {
    unsigned int h = 0;
    while (*fname) h = (h * 31 + *fname++) % FILE_LOCK_BUCKETS;
    return h;
}

/* Lock specific file for reading (shared lock) */
static void lock_file_read(const char *fname) {
    pthread_rwlock_rdlock(&file_locks[hash_for_lock(fname)]);
}

/* Lock specific file for writing (exclusive lock) */
static void lock_file_write(const char *fname) {
    pthread_rwlock_wrlock(&file_locks[hash_for_lock(fname)]);
}

/* Unlock specific file (works for both read and write locks) */
static void unlock_file(const char *fname) {
    pthread_rwlock_unlock(&file_locks[hash_for_lock(fname)]);
}

/* Utility: get current UTC time as string */
void get_time_str(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(buf, size, "%Y-%m-%d-%H:%M", tm);
}

/* Helper: add a username into users array if not already present */
static void add_unique_user(char users[][64], int *ucount, const char *user) {
    if (!user || user[0] == '\0') return;
    for (int i = 0; i < *ucount; i++) {
        if (strcmp(users[i], user) == 0) return;
    }
    if (*ucount < 512) {
        strncpy(users[*ucount], user, 63);
        users[*ucount][63] = '\0';
        (*ucount)++;
    }
}

/* Count words and characters in a file */
void count_file_stats(const char *filepath, int *words, int *chars) {
    *words = 0;
    *chars = 0;
    
    FILE *f = fopen(filepath, "r");
    if (!f) return;
    
    int in_word = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        (*chars)++;
        
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            in_word = 0;
        } else {
            if (!in_word) {
                (*words)++;
                in_word = 1;
            }
        }
    }
    
    fclose(f);
}

/* Update metadata file with current stats */
void update_metadata(const char *fname) {
    char data_path[256], meta_path[256], temp_path[256];
    snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
    snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
    snprintf(temp_path, sizeof(temp_path), "%s/%s.meta.tmp", FILES_DIR, fname);
    
    // Count words and chars
    int words = 0, chars = 0;
    count_file_stats(data_path, &words, &chars);
    
    // Read existing metadata
    char owner[64] = "unknown", created[64] = "N/A", access_list[1024] = "";
    char backups[512] = "";
    FILE *meta = fopen(meta_path, "r");
    if (meta) {
        char line[256];
        while (fgets(line, sizeof(line), meta)) {
            if (strncmp(line, "OWNER:", 6) == 0)
                sscanf(line, "OWNER:%63s", owner);
            else if (strncmp(line, "CREATED:", 8) == 0)
                sscanf(line, "CREATED:%63s", created);
            else if (strncmp(line, "ACCESS:", 7) == 0) {
                // Accumulate all ACCESS lines
                strncat(access_list, line, sizeof(access_list) - strlen(access_list) - 1);
            } else if (strncmp(line, "BACKUPS:", 8) == 0) {
                char *p = line + 8;
                char *nl = strchr(p, '\n');
                if (nl) *nl = '\0';
                strncpy(backups, p, sizeof(backups) - 1);
            }
        }
        fclose(meta);
    }
    
    // Write updated metadata
    FILE *temp = fopen(temp_path, "w");
    if (temp) {
        char time_str[64];
        get_time_str(time_str, sizeof(time_str));
        
        fprintf(temp, "OWNER:%s\n", owner);
        fprintf(temp, "CREATED:%s\n", created);
        fprintf(temp, "MODIFIED:%s\n", time_str);
        fprintf(temp, "WORDS:%d\n", words);
        fprintf(temp, "CHARS:%d\n", chars);
        if (strlen(access_list) > 0)
            fprintf(temp, "%s", access_list);
        else
            fprintf(temp, "ACCESS:%s:RW\n", owner);
            
        if (strlen(backups) > 0) {
            fprintf(temp, "BACKUPS:%s\n", backups);
        }
        
        fclose(temp);
        
        // Set secure permissions on temp file before renaming
        chmod(temp_path, 0600);  // Owner read+write only
        
        rename(temp_path, meta_path);
        
        // Ensure final file has correct permissions
        chmod(meta_path, 0600);
    }
}

/* Notify NS to update cache after metadata changes */
void notify_ns_cache_update(const char *fname) {
    char meta_path[128];
    snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
    
    FILE *meta = fopen(meta_path, "r");
    if (!meta) return;
    
    char owner[64] = "unknown";
    int words = 0, chars = 0;
    char modified[64] = "N/A";
    char access_list[512] = "";
    
    char line[256];
    while (fgets(line, sizeof(line), meta)) {
        if (strncmp(line, "OWNER:", 6) == 0) {
            sscanf(line, "OWNER:%63s", owner);
        } else if (strncmp(line, "WORDS:", 6) == 0) {
            sscanf(line, "WORDS:%d", &words);
        } else if (strncmp(line, "CHARS:", 6) == 0) {
            sscanf(line, "CHARS:%d", &chars);
        } else if (strncmp(line, "MODIFIED:", 9) == 0) {
            sscanf(line, "MODIFIED:%63s", modified);
        } else if (strncmp(line, "ACCESS:", 7) == 0) {
            // Parse access line: "ACCESS: user:R user:W"
            char *access_start = line + 7;
            while (*access_start == ' ') access_start++;
            char *newline = strchr(access_start, '\n');
            if (newline) *newline = '\0';
            
            // Convert "user:R user:W" to "user:R,user:W"
            char temp[512];
            strncpy(temp, access_start, sizeof(temp) - 1);
            char *token = strtok(temp, " ");
            while (token) {
                if (strlen(access_list) > 0) strcat(access_list, ",");
                strncat(access_list, token, sizeof(access_list) - strlen(access_list) - 1);
                token = strtok(NULL, " ");
            }
        }
    }
    fclose(meta);
    
    // Send UPDATE_CACHE to NS
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ns_addr = {0};
    ns_addr.sin_family = AF_INET;
    ns_addr.sin_port = htons(NS_PORT);
    inet_pton(AF_INET, NS_IP, &ns_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&ns_addr, sizeof(ns_addr)) == 0) {
        char msg[2048];
        snprintf(msg, sizeof(msg),
                 "TYPE:REQ\nOP:UPDATE_CACHE\nFILENAME:%s\nOWNER:%s\nWORDS:%d\nCHARS:%d\nMODIFIED:%s\nACCESS_LIST:%s\n\n",
                 fname, owner, words, chars, modified, access_list);
        send_message(sock, msg);
        
        char resp[256];
        recv_message(sock, resp, sizeof(resp));
        printf("[SS] Notified NS to update cache for %s\n", fname);
    }
    close(sock);
}

/* Check if user has access to file */
int check_access(const char *fname, const char *user, char required_access) {
    char meta_path[128];
    snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
    
    FILE *meta = fopen(meta_path, "r");
    if (!meta) return 0;
    
    char owner[64] = "unknown";
    char line[256];
    int has_access = 0;
    
    while (fgets(line, sizeof(line), meta)) {
        if (strncmp(line, "OWNER:", 6) == 0) {
            sscanf(line, "OWNER:%63s", owner);
            // Owner always has full access
            if (strcmp(owner, user) == 0) {
                has_access = 1;
                break;
            }
        } else if (strncmp(line, "ACCESS:", 7) == 0) {
            // Parse ACCESS line: ACCESS:username:RW or ACCESS:username:R
            char access_user[64], access_type[8];
            if (sscanf(line, "ACCESS:%63[^:]:%7s", access_user, access_type) == 2) {
                if (strcmp(access_user, user) == 0) {
                    // Check if user has required access
                    if (required_access == 'R' && (strchr(access_type, 'R') || strchr(access_type, 'W'))) {
                        has_access = 1;
                        break;
                    } else if (required_access == 'W' && strchr(access_type, 'W')) {
                        has_access = 1;
                        break;
                    }
                }
            }
        }
    }
    
    fclose(meta);
    return has_access;
}

// Replace these functions in ss_main.c

/* Parse file into sentences (split by . ! ?) */
int parse_sentences(const char *content, char sentences[][2048], int max_sentences) {
    int sent_count = 0;
    int char_idx = 0;
    
    // Handle empty or NULL content
    if (!content || strlen(content) == 0) {
        sentences[0][0] = '\0';
        return 1;
    }
    
    for (int i = 0; content[i] && sent_count < max_sentences; i++) {
        char c = content[i];
        
        if (c == '.' || c == '!' || c == '?') {
            // Include delimiter
            sentences[sent_count][char_idx++] = c;
            sentences[sent_count][char_idx] = '\0';
            
            // Trim leading/trailing spaces from sentence
            char trimmed[2048];
            int start = 0, end = char_idx - 1;
            
            // Find first non-space
            while (start < char_idx && sentences[sent_count][start] == ' ') start++;
            // Find last non-space (before delimiter)
            while (end > start && (sentences[sent_count][end] == ' ' || 
                   sentences[sent_count][end] == '.' || 
                   sentences[sent_count][end] == '!' || 
                   sentences[sent_count][end] == '?')) end--;
            
            // Copy trimmed content
            int trim_idx = 0;
            for (int j = start; j <= end; j++) {
                trimmed[trim_idx++] = sentences[sent_count][j];
            }
            // Re-add delimiter
            if (c == '.' || c == '!' || c == '?') {
                trimmed[trim_idx++] = c;
            }
            trimmed[trim_idx] = '\0';
            
            strcpy(sentences[sent_count], trimmed);
            sent_count++;
            char_idx = 0;
            
            // Skip trailing whitespace after delimiter
            while (content[i+1] == ' ' || content[i+1] == '\n' || 
                   content[i+1] == '\t' || content[i+1] == '\r') {
                i++;
            }
        } else {
            sentences[sent_count][char_idx++] = c;
            if (char_idx >= 2047) {
                sentences[sent_count][char_idx] = '\0';
                sent_count++;
                char_idx = 0;
            }
        }
    }
    
    // Last sentence if no delimiter at end
    if (char_idx > 0) {
        sentences[sent_count][char_idx] = '\0';
        sent_count++;
    }
    
    return sent_count > 0 ? sent_count : 1;
}

/* Parse sentence into words (space-separated) */
int parse_words(const char *sentence, char words[][256], int max_words) {
    int word_count = 0;
    int char_idx = 0;
    int in_word = 0;
    
    if (!sentence || strlen(sentence) == 0) {
        return 0;
    }
    
    for (int i = 0; sentence[i] && word_count < max_words; i++) {
        char c = sentence[i];
        
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            if (in_word) {
                words[word_count][char_idx] = '\0';
                word_count++;
                char_idx = 0;
                in_word = 0;
            }
        } else {
            if (!in_word) in_word = 1;
            words[word_count][char_idx++] = c;
            if (char_idx >= 255) {
                words[word_count][char_idx] = '\0';
                word_count++;
                char_idx = 0;
                in_word = 0;
            }
        }
    }
    
    if (in_word && char_idx > 0) {
        words[word_count][char_idx] = '\0';
        word_count++;
    }
    
    return word_count;
}

/* Reconstruct sentence from words with proper spacing */
void reconstruct_sentence(char words[][256], int word_count, char *output, size_t output_size) {
    output[0] = '\0';
    
    for (int i = 0; i < word_count; i++) {
        char *w = words[i];
        if (i == 0) {
            /* first word */
            strncat(output, w, output_size - strlen(output) - 1);
        } else {
            /* If the current word starts with a punctuation delimiter, attach it to previous without space */
            if (w[0] == '.' || w[0] == '!' || w[0] == '?') {
                strncat(output, w, output_size - strlen(output) - 1);
            } else {
                /* Normal word: prepend a single space */
                strncat(output, " ", output_size - strlen(output) - 1);
                strncat(output, w, output_size - strlen(output) - 1);
            }
        }
    }
}
/* Lock sentence for writing with timeout check and client tracking */
int lock_sentence(const char *fname, int sentence_num, const char *user) {
    pthread_mutex_lock(&sentence_lock_mutex);
    
    time_t current_time = time(NULL);
    
    // Check if sentence already locked and clean up stale locks
    for (int i = 0; i < MAX_SENTENCE_LOCKS; i++) {
        if (sentence_locks[i].active && 
            strcmp(sentence_locks[i].filename, fname) == 0 &&
            sentence_locks[i].sentence_num == sentence_num) {
            
            // Check if lock is stale (timeout exceeded)
            if ((current_time - sentence_locks[i].lock_time) > LOCK_TIMEOUT_SECONDS) {
                LOG_WARN("Lock timeout: Releasing stale lock on %s sentence %d held by %s for %ld seconds",
                        fname, sentence_num, sentence_locks[i].user, 
                        (long)(current_time - sentence_locks[i].lock_time));
                sentence_locks[i].active = 0;  // Release stale lock
                break;  // Continue to acquire lock
            } else {
                pthread_mutex_unlock(&sentence_lock_mutex);
                LOG_INFO("Lock denied: Sentence %d in %s already locked by %s", 
                        sentence_num, fname, sentence_locks[i].user);
                return -1; // Active lock exists
            }
        }
    }
    
    // Find free slot
    for (int i = 0; i < MAX_SENTENCE_LOCKS; i++) {
        if (!sentence_locks[i].active) {
            strncpy(sentence_locks[i].filename, fname, 63);
            sentence_locks[i].filename[63] = '\0';
            sentence_locks[i].sentence_num = sentence_num;
            strncpy(sentence_locks[i].user, user, 63);
            sentence_locks[i].user[63] = '\0';
            sentence_locks[i].lock_time = current_time;
            sentence_locks[i].active = 1;
            pthread_mutex_unlock(&sentence_lock_mutex);
            LOG_INFO("Lock acquired: %s sentence %d by user %s", fname, sentence_num, user);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&sentence_lock_mutex);
    LOG_ERROR("No free lock slots available");
    return -2; // No free slots
}


/* Unlock sentence */
void unlock_sentence(const char *fname, int sentence_num) {
    pthread_mutex_lock(&sentence_lock_mutex);
    
    for (int i = 0; i < MAX_SENTENCE_LOCKS; i++) {
        if (sentence_locks[i].active && 
            strcmp(sentence_locks[i].filename, fname) == 0 &&
            sentence_locks[i].sentence_num == sentence_num) {
            LOG_INFO("Unlocking %s sentence %d (was held by %s)", 
                    fname, sentence_num, sentence_locks[i].user);
            sentence_locks[i].active = 0;
            break;
        }
    }
    
    pthread_mutex_unlock(&sentence_lock_mutex);
}

/* Check if a sentence lock is currently held by the specified user */
int is_sentence_locked_by(const char *fname, int sentence_num, const char *user) {
    int result = 0;
    pthread_mutex_lock(&sentence_lock_mutex);

    for (int i = 0; i < MAX_SENTENCE_LOCKS; i++) {
        if (sentence_locks[i].active &&
            strcmp(sentence_locks[i].filename, fname) == 0 &&
            sentence_locks[i].sentence_num == sentence_num) {
            if (user && strcmp(sentence_locks[i].user, user) == 0) {
                result = 1;
            }
            break;
        }
    }

    pthread_mutex_unlock(&sentence_lock_mutex);
    return result;
}

/* Heartbeat sender thread - sends periodic heartbeats to NS */
void *heartbeat_sender(void *arg) {
    (void)arg;
    printf("[SS] Heartbeat sender thread started\n");
    
    // Wait initial delay to let NS settle after registration
    sleep(5);
    
    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            printf("[SS] Failed to create heartbeat socket\n");
            sleep(15);
            continue;
        }
        
        struct sockaddr_in ns_addr = {0};
        ns_addr.sin_family = AF_INET;
        ns_addr.sin_port = htons(NS_PORT);
        inet_pton(AF_INET, NS_IP, &ns_addr.sin_addr);
        
        if (connect(sock, (struct sockaddr *)&ns_addr, sizeof(ns_addr)) < 0) {
            // Connection failed - NS might be down, retry after delay
            close(sock);
            sleep(15);
            continue;
        }
        
        char msg[256];
        snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:HEARTBEAT\nSS_NAME:%s\n\n", SS_NAME);
        
        if (send_message(sock, msg) == 0) {
            // Wait for ACK from NS to ensure connection is healthy
            char resp[128];
            if (recv_message(sock, resp, sizeof(resp)) != 0) {
                // printf("[SS] Warning: Heartbeat ACK not received\n");
            }
        } else {
            printf("[SS] Failed to send heartbeat message\n");
        }
        
        close(sock);
        sleep(5);  // Wait 5 seconds before next heartbeat (faster detection)
    }
    
    return NULL;
}

void *control_listener(void *arg) {
    int ctrl_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0}, cli;
    socklen_t cli_len = sizeof(cli);

    int opt = 1;
    setsockopt(ctrl_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SS_CTRL_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(ctrl_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(ctrl_fd, 5);

    printf("[SS] Control listener running on %d...\n", SS_CTRL_PORT);
    
    while (1) {
        int client_fd = accept(ctrl_fd, (struct sockaddr *)&cli, &cli_len);
        // Increased buffer size to handle large WRITE_COMMIT messages
        char buf[16384];
        
        if (recv_message(client_fd, buf, sizeof(buf)) != 0) {
            close(client_fd);
            continue;
        }

        printf("[SS] Received control:\n%s\n", buf);

        char op[64] = {0};
        char *op_ptr = strstr(buf, "OP:");
        if (!op_ptr || sscanf(op_ptr, "OP:%63s", op) != 1) {
            send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Invalid operation\n\n");
            close(client_fd);
            continue;
        }

        // --- CREATE ---
        if (strcmp(op, "CREATE") == 0) {
            char fname[64] = {0}, owner[64] = {0}, backups[512] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "OWNER:"))
                sscanf(strstr(buf, "OWNER:"), "OWNER:%63s", owner);
            else
                strcpy(owner, "unknown");
            
            if (strstr(buf, "BACKUPS:")) {
                char *backups_ptr = strstr(buf, "BACKUPS:") + 8;
                char *newline = strchr(backups_ptr, '\n');
                if (newline) {
                    int len = newline - backups_ptr;
                    if (len > 0 && len < sizeof(backups)) {
                        strncpy(backups, backups_ptr, len);
                        backups[len] = '\0';
                    }
                }
            }

            char data_path[128], meta_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
            snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);

            lock_file_write(fname);
            
            if (access(data_path, F_OK) == 0) {
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File already exists\n\n");
                unlock_file(fname);
                close(client_fd);
                continue;
            }

            FILE *f = fopen(data_path, "w");
            if (!f) {
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot Create Data File\n\n");
                unlock_file(fname);
                close(client_fd);
                continue;
            }
            fclose(f);

            FILE *meta = fopen(meta_path, "w");
            if (meta) {
                char time_str[64];
                get_time_str(time_str, sizeof(time_str));
                fprintf(meta, "OWNER:%s\nCREATED:%s\nMODIFIED:%s\nWORDS:0\nCHARS:0\nACCESS:%s:RW\n",
                        owner, time_str, time_str, owner);
                if (strlen(backups) > 0) {
                    fprintf(meta, "BACKUPS:%s\n", backups);
                }
                fclose(meta);
                // Set secure permissions: owner read+write only
                chmod(meta_path, 0600);
            }
            
            unlock_file(fname);
            printf("[SS] Created file %s and metadata\n", fname);
            send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:File Created\n\n");
        }

        // --- DELETE ---
        else if (strcmp(op, "DELETE") == 0) {
            char fname[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);

            char data_path[128], meta_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
            snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
            
            lock_file_write(fname);
            int result1 = unlink(data_path);
            int result2 = unlink(meta_path);
            unlock_file(fname);
            
            if (result1 == 0 || result2 == 0) {
                printf("[SS] Deleted file %s\n", fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:File Deleted\n\n");
            } else {
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found or cannot delete\n\n");
            }
        }

        // --- GET META ---
        else if (strcmp(op, "GET_META") == 0) {
            char fname[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            
            // Update metadata before returning
            lock_file_write(fname);
            update_metadata(fname);
            
            char meta_path[128];
            snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);

            FILE *f = fopen(meta_path, "r");
            if (!f) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:No metadata\n\n");
            } else {
                char line[1024] = "";
                char temp[256];
                while (fgets(temp, sizeof(temp), f)) 
                    strncat(line, temp, sizeof(line) - strlen(line) - 1);
                fclose(f);
                unlock_file(fname);
                
                char msg[1536];
                snprintf(msg, sizeof(msg), "TYPE:RESP\nSTATUS:OK\nMSG:%s\n", line);
                send_message(client_fd, msg);
            }
        }

        // --- LIST ---
        else if (strcmp(op, "LIST") == 0) {
            char users[512][64];
            int ucount = 0;

            DIR *d = opendir(FILES_DIR);
            if (d) {
                struct dirent *entry;
                while (entry = readdir(d)) {
                    if (!strstr(entry->d_name, ".meta")) continue;
                    char meta_path[256];
                    snprintf(meta_path, sizeof(meta_path), "%s/%s", FILES_DIR, entry->d_name);
                    FILE *m = fopen(meta_path, "r");
                    if (!m) continue;
                    char line[512];
                    while (fgets(line, sizeof(line), m)) {
                        if (strncmp(line, "OWNER:", 6) == 0) {
                            char owner[64];
                            if (sscanf(line, "OWNER:%63s", owner) == 1) add_unique_user(users, &ucount, owner);
                        } else if (strncmp(line, "ACCESS:", 7) == 0) {
                            char access_user[64], access_type[16];
                            if (sscanf(line, "ACCESS:%63[^:]:%15s", access_user, access_type) >= 1) add_unique_user(users, &ucount, access_user);
                        }
                    }
                    fclose(m);
                }
                closedir(d);
            }

            char response[8192];
            snprintf(response, sizeof(response), "TYPE:RESP\nSTATUS:OK\nMSG:\n");
            for (int i = 0; i < ucount; i++) {
                strncat(response, users[i], sizeof(response) - strlen(response) - 1);
                strncat(response, "\n", sizeof(response) - strlen(response) - 1);
            }
            strncat(response, "\n", sizeof(response) - strlen(response) - 1);
            send_message(client_fd, response);
        }

        // --- VIEW ---
        else if (strcmp(op, "VIEW") == 0) {
            char user[64] = {0}, flags[16] = "none";
            if (strstr(buf, "USER:")) sscanf(strstr(buf, "USER:"), "USER:%63s", user);
            if (strstr(buf, "FLAGS:")) sscanf(strstr(buf, "FLAGS:"), "FLAGS:%15s", flags);

            int show_all = strstr(flags, "a") != NULL;
            int show_long = strstr(flags, "l") != NULL;

            char response[8192];
            strcpy(response, "TYPE:RESP\nSTATUS:OK\nMSG:\n");

            DIR *d = opendir(FILES_DIR);
            if (d) {
                struct dirent *entry;
                while ((entry = readdir(d))) {
                    if (!strstr(entry->d_name, ".data")) continue;
                    char fname[64];
                    strncpy(fname, entry->d_name, sizeof(fname));
                    fname[strlen(fname) - 5] = '\0'; // remove .data

                    // Read metadata
                    update_metadata(fname);
                    char meta_path[256];
                    snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
                    FILE *m = fopen(meta_path, "r");
                    char owner[64] = "unknown";
                    int words = 0, chars = 0;
                    char modified[64] = "N/A";
                    if (m) {
                        char line[256];
                        while (fgets(line, sizeof(line), m)) {
                            if (strncmp(line, "OWNER:", 6) == 0) sscanf(line, "OWNER:%63s", owner);
                            else if (strncmp(line, "WORDS:", 6) == 0) sscanf(line, "WORDS:%d", &words);
                            else if (strncmp(line, "CHARS:", 6) == 0) sscanf(line, "CHARS:%d", &chars);
                            else if (strncmp(line, "MODIFIED:", 9) == 0) sscanf(line, "MODIFIED:%63s", modified);
                        }
                        fclose(m);
                    }

                    if (!show_all && strcmp(owner, user) != 0) continue;

                    char line[256];
                    if (show_long) {
                        snprintf(line, sizeof(line), "%s|%d|%d|%s|%s\n", fname, words, chars, modified, owner);
                    } else {
                        snprintf(line, sizeof(line), "%s|0|0|N/A|%s\n", fname, owner);
                    }
                    strncat(response, line, sizeof(response) - strlen(response) - 1);
                }
                closedir(d);
            }

            strncat(response, "\n", sizeof(response) - strlen(response) - 1);
            send_message(client_fd, response);
        }

        // --- READ ---
        else if (strcmp(op, "READ") == 0) {
            char fname[64] = {0}, user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);

            LOG_INFO("READ request for %s by user %s", fname, user);
            log_request(user, "READ", fname, user);

            // Check access
            if (!check_access(fname, user, 'R')) {
                char err_msg[256];
                format_error_message(err_msg, sizeof(err_msg), ERR_NO_READ_PERMISSION, fname);
                send_message(client_fd, err_msg);
                LOG_WARN("READ denied for %s by user %s", fname, user);
                log_response(user, "READ", ERR_NO_READ_PERMISSION, fname);
                close(client_fd);
                continue;
            }

            char data_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);

            lock_file_read(fname);
            FILE *f = fopen(data_path, "r");
            if (!f) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot read file\n\n");
                close(client_fd);
                continue;
            }

            // Read file content
            char content[8192] = "";
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                strncat(content, line, sizeof(content) - strlen(content) - 1);
            }
            fclose(f);
            unlock_file(fname);

            // Send response
            char response[8192];
            snprintf(response, sizeof(response), "TYPE:RESP\nSTATUS:OK\nMSG:\n%s\n", content);
            send_message(client_fd, response);
            printf("[SS] Read file %s for user %s\n", fname, user);
        }

        // --- INFO ---
        else if (strcmp(op, "INFO") == 0) {
            char fname[64] = {0}, user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);

            // Check if file exists
            char data_path[128], meta_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
            snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);

            lock_file_write(fname);
            
            if (access(data_path, F_OK) != 0) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
                close(client_fd);
                continue;
            }

            // Update metadata
            update_metadata(fname);

            // Read metadata
            FILE *meta = fopen(meta_path, "r");
            if (!meta) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot read metadata\n\n");
                close(client_fd);
                continue;
            }

            char owner[64] = "unknown", created[64] = "N/A", modified[64] = "N/A";
            int words = 0, chars = 0;
            char access_lines[1024] = "";
            char line[256];

            while (fgets(line, sizeof(line), meta)) {
                if (strncmp(line, "OWNER:", 6) == 0)
                    sscanf(line, "OWNER:%63s", owner);
                else if (strncmp(line, "CREATED:", 8) == 0)
                    sscanf(line, "CREATED:%63s", created);
                else if (strncmp(line, "MODIFIED:", 9) == 0)
                    sscanf(line, "MODIFIED:%63s", modified);
                else if (strncmp(line, "WORDS:", 6) == 0)
                    sscanf(line, "WORDS:%d", &words);
                else if (strncmp(line, "CHARS:", 6) == 0)
                    sscanf(line, "CHARS:%d", &chars);
                else if (strncmp(line, "ACCESS:", 7) == 0) {
                    strncat(access_lines, line, sizeof(access_lines) - strlen(access_lines) - 1);
                }
            }
            fclose(meta);
            
            // Get file size
            struct stat st;
            stat(data_path, &st);
            long size = st.st_size;
            
            unlock_file(fname);

            // Format response
            char response[4096];
            snprintf(response, sizeof(response),
                     "TYPE:RESP\nSTATUS:OK\nMSG:\n"
                     "--> File: %s\n"
                     "--> Owner: %s\n"
                     "--> Created: %s\n"
                     "--> Last Modified: %s\n"
                     "--> Size: %ld bytes\n"
                     "--> Words: %d\n"
                     "--> Characters: %d\n"
                     "--> Access:\n",
                     fname, owner, created, modified, size, words, chars);

            // Parse and display access list
            char *ptr = access_lines;
            while (*ptr) {
                char *line_end = strchr(ptr, '\n');
                if (!line_end) break;
                
                char access_user[64], access_type[8];
                if (sscanf(ptr, "ACCESS:%63[^:]:%7s", access_user, access_type) == 2) {
                    char temp[128];
                    snprintf(temp, sizeof(temp), "    %s (%s)\n", access_user, access_type);
                    strncat(response, temp, sizeof(response) - strlen(response) - 1);
                }
                ptr = line_end + 1;
            }

            strcat(response, "\n");
            send_message(client_fd, response);
            printf("[SS] Sent info for %s to user %s\n", fname, user);
        }

        // --- ADDACCESS ---
        else if (strcmp(op, "ADDACCESS") == 0) {
            char fname[64] = {0}, target_user[64] = {0};
            char access_type = 'R';
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            sscanf(strstr(buf, "TARGET_USER:"), "TARGET_USER:%63s", target_user);
            if (strstr(buf, "ACCESS_TYPE:"))
                sscanf(strstr(buf, "ACCESS_TYPE:"), "ACCESS_TYPE:%c", &access_type);

            char meta_path[128], temp_path[128];
            snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
            snprintf(temp_path, sizeof(temp_path), "%s/%s.meta.tmp", FILES_DIR, fname);

            lock_file_write(fname);

            // Read existing metadata
            FILE *meta = fopen(meta_path, "r");
            if (!meta) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
                close(client_fd);
                continue;
            }

            // Write to temp file, updating or adding access
            FILE *temp = fopen(temp_path, "w");
            if (!temp) {
                fclose(meta);
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot update metadata\n\n");
                close(client_fd);
                continue;
            }

            char line[256];
            int found_user = 0;
            while (fgets(line, sizeof(line), meta)) {
                // Check if this is an ACCESS line for the target user
                if (strncmp(line, "ACCESS:", 7) == 0) {
                    char access_user[64];
                    if (sscanf(line, "ACCESS:%63[^:]:", access_user) == 1) {
                        if (strcmp(access_user, target_user) == 0) {
                            // Update existing access
                            fprintf(temp, "ACCESS:%s:%s\n", target_user, 
                                    access_type == 'W' ? "RW" : "R");
                            found_user = 1;
                            continue;
                        }
                    }
                }
                fprintf(temp, "%s", line);
            }

            // If user not found, add new access line
            if (!found_user) {
                fprintf(temp, "ACCESS:%s:%s\n", target_user, 
                        access_type == 'W' ? "RW" : "R");
            }

            fclose(meta);
            fclose(temp);
            rename(temp_path, meta_path);
            unlock_file(fname);

            printf("[SS] Added %c access for %s on %s\n", access_type, target_user, fname);
            
            // Notify NS to update cache
            notify_ns_cache_update(fname);
            
            send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:Access added\n\n");
        }

        // --- UNDO ---
        else if (strcmp(op, "UNDO") == 0) {
            char fname[64] = {0}, user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);

            LOG_INFO("UNDO request for %s by user %s", fname, user);
            log_request(user, "UNDO", fname, user);

            // Check if backup exists
            char backup_path[128], data_path[128];
            snprintf(backup_path, sizeof(backup_path), "%s/%s.backup", FILES_DIR, fname);
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);

            lock_file_write(fname);

            if (access(backup_path, F_OK) != 0) {
                unlock_file(fname);
                char err_msg[256];
                format_error_message(err_msg, sizeof(err_msg), 
                                   ERR_NO_UNDO_HISTORY, fname);
                send_message(client_fd, err_msg);
                LOG_WARN("No backup found for %s", fname);
                log_response(user, "UNDO", ERR_NO_UNDO_HISTORY, "No backup");
                close(client_fd);
                continue;
            }

            // Read backup content
            FILE *backup = fopen(backup_path, "r");
            if (!backup) {
                unlock_file(fname);
                char err_msg[256];
                format_error_message(err_msg, sizeof(err_msg), 
                                   ERR_FILE_READ_FAILED, "backup");
                send_message(client_fd, err_msg);
                LOG_ERROR("Failed to open backup for %s", fname);
                log_response(user, "UNDO", ERR_FILE_READ_FAILED, "Open backup failed");
                close(client_fd);
                continue;
            }

            char backup_content[8192] = "";
            char line[512];
            while (fgets(line, sizeof(line), backup)) {
                strncat(backup_content, line, sizeof(backup_content) - strlen(backup_content) - 1);
            }
            fclose(backup);

            // Write backup content to main file
            FILE *data = fopen(data_path, "w");
            if (!data) {
                unlock_file(fname);
                char err_msg[256];
                format_error_message(err_msg, sizeof(err_msg), 
                                   ERR_FILE_WRITE_FAILED, fname);
                send_message(client_fd, err_msg);
                LOG_ERROR("Failed to write restored content for %s", fname);
                log_response(user, "UNDO", ERR_FILE_WRITE_FAILED, "Write failed");
                close(client_fd);
                continue;
            }
            fprintf(data, "%s", backup_content);
            fclose(data);

            // Update metadata
            update_metadata(fname);

            // Remove backup file after successful restore
            remove(backup_path);

            unlock_file(fname);

            printf("[SS] UNDO successful for %s by user %s\n", fname, user);
            LOG_INFO("UNDO successful for %s", fname);
            
            // Notify NS to update cache
            notify_ns_cache_update(fname);
            
            char success_msg[256];
            format_success_message(success_msg, sizeof(success_msg), "Undo successful");
            send_message(client_fd, success_msg);
            log_response(user, "UNDO", ERR_SUCCESS, "Success");
        }

        // --- CHECKPOINT ---
        else if (strcmp(op, "CHECKPOINT") == 0) {
            char fname[64] = {0}, tag[64] = {0}, user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            sscanf(strstr(buf, "TAG:"), "TAG:%63s", tag);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);

            char data_path[128], checkpoint_path[256];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
            snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/%s.checkpoint.%s", FILES_DIR, fname, tag);

            lock_file_read(fname);
            
            // Check if file exists
            if (access(data_path, F_OK) != 0) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
                close(client_fd);
                continue;
            }

            // Copy file to checkpoint
            FILE *src = fopen(data_path, "r");
            if (!src) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot read file\n\n");
                close(client_fd);
                continue;
            }

            FILE *dst = fopen(checkpoint_path, "w");
            if (!dst) {
                fclose(src);
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot create checkpoint\n\n");
                close(client_fd);
                continue;
            }

            char line[512];
            while (fgets(line, sizeof(line), src)) {
                fputs(line, dst);
            }
            fclose(src);
            fclose(dst);
            chmod(checkpoint_path, 0600);
            
            unlock_file(fname);

            printf("[SS] Created checkpoint '%s' for %s\n", tag, fname);
            send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:Checkpoint created\n\n");
        }

        // --- VIEWCHECKPOINT ---
        else if (strcmp(op, "VIEWCHECKPOINT") == 0) {
            char fname[64] = {0}, tag[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            sscanf(strstr(buf, "TAG:"), "TAG:%63s", tag);

            char checkpoint_path[256];
            snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/%s.checkpoint.%s", FILES_DIR, fname, tag);

            FILE *f = fopen(checkpoint_path, "r");
            if (!f) {
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Checkpoint not found\n\n");
                close(client_fd);
                continue;
            }

            char content[8192] = "";
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                strncat(content, line, sizeof(content) - strlen(content) - 1);
            }
            fclose(f);

            char response[8192];
            snprintf(response, sizeof(response), "TYPE:RESP\nSTATUS:OK\nMSG:\n%s\n", content);
            send_message(client_fd, response);
        }

        // --- REVERT ---
        else if (strcmp(op, "REVERT") == 0) {
            char fname[64] = {0}, tag[64] = {0}, user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            sscanf(strstr(buf, "TAG:"), "TAG:%63s", tag);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);

            char data_path[128], checkpoint_path[256], backup_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
            snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/%s.checkpoint.%s", FILES_DIR, fname, tag);
            snprintf(backup_path, sizeof(backup_path), "%s/%s.backup", FILES_DIR, fname);

            lock_file_write(fname);

            // Check if checkpoint exists
            if (access(checkpoint_path, F_OK) != 0) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Checkpoint not found\n\n");
                close(client_fd);
                continue;
            }

            // Backup current file
            FILE *current = fopen(data_path, "r");
            if (current) {
                FILE *backup = fopen(backup_path, "w");
                if (backup) {
                    char line[512];
                    while (fgets(line, sizeof(line), current)) {
                        fputs(line, backup);
                    }
                    fclose(backup);
                }
                fclose(current);
            }

            // Copy checkpoint to data file
            FILE *src = fopen(checkpoint_path, "r");
            FILE *dst = fopen(data_path, "w");
            if (!src || !dst) {
                if (src) fclose(src);
                if (dst) fclose(dst);
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot revert to checkpoint\n\n");
                close(client_fd);
                continue;
            }

            char line[512];
            while (fgets(line, sizeof(line), src)) {
                fputs(line, dst);
            }
            fclose(src);
            fclose(dst);
            
            update_metadata(fname);
            unlock_file(fname);

            printf("[SS] Reverted %s to checkpoint '%s'\n", fname, tag);
            notify_ns_cache_update(fname);
            send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:Reverted to checkpoint\n\n");
        }

        // --- LISTCHECKPOINTS ---
        else if (strcmp(op, "LISTCHECKPOINTS") == 0) {
            char fname[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);

            // List all checkpoint files for this file
            DIR *dir = opendir(FILES_DIR);
            if (!dir) {
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot list checkpoints\n\n");
                close(client_fd);
                continue;
            }

            char checkpoint_list[4096] = "";
            char prefix[128];
            snprintf(prefix, sizeof(prefix), "%s.checkpoint.", fname);
            int prefix_len = strlen(prefix);

            char checkpoint_names[512][64];
            int checkpoint_count = 0;
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (strncmp(entry->d_name, prefix, prefix_len) == 0) {
                    const char *raw_tag = entry->d_name + prefix_len;
                    char sanitized[64];
                    strncpy(sanitized, raw_tag, sizeof(sanitized) - 1);
                    sanitized[sizeof(sanitized) - 1] = '\0';

                    // Remove trailing whitespace/newlines
                    size_t slen = strlen(sanitized);
                    while (slen > 0 && isspace((unsigned char)sanitized[slen - 1])) {
                        sanitized[--slen] = '\0';
                    }

                    if (slen == 0) continue;

                    // Avoid duplicates
                    int exists = 0;
                    for (int i = 0; i < checkpoint_count; i++) {
                        if (strcmp(checkpoint_names[i], sanitized) == 0) {
                            exists = 1;
                            break;
                        }
                    }
                    if (!exists && checkpoint_count < (int)(sizeof(checkpoint_names)/sizeof(checkpoint_names[0]))) {
                        strcpy(checkpoint_names[checkpoint_count++], sanitized);
                    }
                }
            }
            closedir(dir);

            char response[4096];
            if (checkpoint_count == 0) {
                snprintf(response, sizeof(response), "TYPE:RESP\nSTATUS:OK\nMSG:No checkpoints found\n\n");
            } else {
                checkpoint_list[0] = '\0';
                for (int i = 0; i < checkpoint_count; i++) {
                    strncat(checkpoint_list, checkpoint_names[i], sizeof(checkpoint_list) - strlen(checkpoint_list) - 1);
                    strncat(checkpoint_list, "\n", sizeof(checkpoint_list) - strlen(checkpoint_list) - 1);
                }
                snprintf(response, sizeof(response), "TYPE:RESP\nSTATUS:OK\nMSG:\n%s\n", checkpoint_list);
            }
            send_message(client_fd, response);
        }

        // --- REMACCESS ---
        else if (strcmp(op, "REMACCESS") == 0) {
            char fname[64] = {0}, target_user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            sscanf(strstr(buf, "TARGET_USER:"), "TARGET_USER:%63s", target_user);

            char meta_path[128], temp_path[128];
            snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
            snprintf(temp_path, sizeof(temp_path), "%s/%s.meta.tmp", FILES_DIR, fname);

            lock_file_write(fname);

            FILE *meta = fopen(meta_path, "r");
            if (!meta) {
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:File not found\n\n");
                close(client_fd);
                continue;
            }

            FILE *temp = fopen(temp_path, "w");
            if (!temp) {
                fclose(meta);
                unlock_file(fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot update metadata\n\n");
                close(client_fd);
                continue;
            }

            // Copy all lines except ACCESS line for target user
            char line[256];
            int removed = 0;
            while (fgets(line, sizeof(line), meta)) {
                if (strncmp(line, "ACCESS:", 7) == 0) {
                    char access_user[64];
                    if (sscanf(line, "ACCESS:%63[^:]:", access_user) == 1) {
                        if (strcmp(access_user, target_user) == 0) {
                            removed = 1;
                            continue;  // Skip this line
                        }
                    }
                }
                fprintf(temp, "%s", line);
            }

            fclose(meta);
            fclose(temp);
            rename(temp_path, meta_path);
            unlock_file(fname);

            if (removed) {
                printf("[SS] Removed access for %s on %s\n", target_user, fname);
                
                // Notify NS to update cache
                notify_ns_cache_update(fname);
                
                send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:Access removed\n\n");
            } else {
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:User not found in access list\n\n");
            }
        }

        // --- STREAM (Enhanced with robust error handling) ---
        else if (strcmp(op, "STREAM") == 0) {
            char fname[64] = {0}, user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);

            LOG_INFO("STREAM request for file '%s' from user '%s'", fname, user);

            // Validate filename
            if (strlen(fname) == 0) {
                LOG_ERROR("STREAM: Invalid filename");
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nCODE:ERR_INVALID_FILENAME\nMSG:Invalid filename\n\n");
                close(client_fd);
                continue;
            }

            // Check access permission (read access)
            if (!check_access(fname, user, 'R')) {
                LOG_WARN("STREAM: Access denied for user '%s' on file '%s'", user, fname);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nCODE:ERR_ACCESS_DENIED\nMSG:Access denied - no read permission\n\n");
                close(client_fd);
                continue;
            }

            // Construct file path
            char data_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);

            // Check if file exists before opening
            if (access(data_path, F_OK) != 0) {
                LOG_WARN("STREAM: File not found: '%s'", data_path);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nCODE:ERR_FILE_NOT_FOUND\nMSG:File not found for streaming\n\n");
                close(client_fd);
                continue;
            }

            // Try to read file
            FILE *f = fopen(data_path, "r");
            if (!f) {
                LOG_ERROR("STREAM: Cannot open file '%s' - %s", data_path, strerror(errno));
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nCODE:ERR_FILE_OPEN_FAILED\nMSG:Cannot open file for streaming\n\n");
                close(client_fd);
                continue;
            }

            // Read file content
            char content[8192] = "";
            char line[512];
            size_t total_bytes = 0;
            while (fgets(line, sizeof(line), f)) {
                size_t line_len = strlen(line);
                if (total_bytes + line_len < sizeof(content) - 1) {
                    strncat(content, line, sizeof(content) - strlen(content) - 1);
                    total_bytes += line_len;
                } else {
                    LOG_WARN("STREAM: File content truncated (size exceeded %zu bytes)", sizeof(content));
                    break;
                }
            }
            fclose(f);
            LOG_INFO("STREAM: Read %zu bytes from file '%s'", total_bytes, fname);

            // Send content back
            char response[9000];
            snprintf(response, sizeof(response),
                     "TYPE:RESP\nSTATUS:OK\nCODE:0\nMSG:\n%s\n", content);
            if (send_message(client_fd, response) != 0) {
                LOG_ERROR("STREAM: Failed to send response");
            } else {
                LOG_INFO("STREAM: Successfully sent %zu bytes to client for file '%s'", total_bytes, fname);
            }
        }


        // --- WRITE_START (Enhanced with comprehensive error handling) ---
        else if (strcmp(op, "WRITE_START") == 0) {
            char fname[64] = {0}, user[64] = {0};
            int sentence_num = 0;
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);
            if (strstr(buf, "SENTENCE:"))
                sscanf(strstr(buf, "SENTENCE:"), "SENTENCE:%d", &sentence_num);

            LOG_INFO("WRITE_START request: file='%s', user='%s', sentence=%d", fname, user, sentence_num);

            // Validate inputs
            if (strlen(fname) == 0) {
                LOG_ERROR("WRITE_START: Invalid filename");
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_INVALID_FILENAME, "Invalid filename");
                send_message(client_fd, err_buf);
                close(client_fd);
                continue;
            }

            if (strlen(user) == 0) {
                LOG_ERROR("WRITE_START: Missing user");
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_INVALID_PARAMETERS, "Missing user");
                send_message(client_fd, err_buf);
                close(client_fd);
                continue;
            }

            // Check write access
            if (!check_access(fname, user, 'W')) {
                LOG_WARN("WRITE_START: Access denied for user '%s' on file '%s'", user, fname);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_ACCESS_DENIED, "Access denied - no write permission");
                send_message(client_fd, err_buf);
                close(client_fd);
                continue;
            }

            // Check if file exists
            char data_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
            
            if (access(data_path, F_OK) != 0) {
                LOG_ERROR("WRITE_START: File not found: '%s'", data_path);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_FILE_NOT_FOUND, "File not found");
                send_message(client_fd, err_buf);
                close(client_fd);
                continue;
            }

            // Validate sentence exists
            lock_file_read(fname);
            FILE *f = fopen(data_path, "r");
            if (!f) {
                unlock_file(fname);
                LOG_ERROR("WRITE_START: Cannot read file '%s'", data_path);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_FILE_OPEN_FAILED, "Cannot read file");
                send_message(client_fd, err_buf);
                close(client_fd);
                continue;
            }

            char content[8192] = "";
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                strncat(content, line, sizeof(content) - strlen(content) - 1);
            }
            fclose(f);
            
            // Parse sentences to validate index
            char sentences[100][2048];
            int sent_count = parse_sentences(content, sentences, 100);
            LOG_INFO("WRITE_START: File '%s' has %d sentences", fname, sent_count);

            // Determine whether appending a new sentence is allowed: only when
            // the file is empty or the last non-whitespace character is a
            // sentence delimiter (.,!,?)
            int allow_append = 0;
            int clen = strlen(content);
            int i = clen - 1;
            while (i >= 0 && isspace((unsigned char)content[i])) i--;
            if (i < 0) {
                allow_append = 1; // empty file
                LOG_INFO("WRITE_START: Empty file - append allowed");
            } else if (content[i] == '.' || content[i] == '!' || content[i] == '?') {
                allow_append = 1;
                LOG_INFO("WRITE_START: Last char is delimiter - append allowed");
            } else {
                LOG_INFO("WRITE_START: Last char is not delimiter - append NOT allowed");
            }

            unlock_file(fname);

            // Check sentence index validity. Allow sentence_num == sent_count
            // only when append is permitted (file ends with delimiter or is empty).
            if (sentence_num < 0 || sentence_num > sent_count ||
                (sentence_num == sent_count && !allow_append)) {
                char err_msg[256];
                if (allow_append) {
                    snprintf(err_msg, sizeof(err_msg),
                        "TYPE:RESP\nSTATUS:ERROR\nCODE:%d\nMSG:Sentence index out of range (valid: 0-%d)\n\n",
                        ERR_SENTENCE_OUT_OF_RANGE, sent_count);
                } else {
                    snprintf(err_msg, sizeof(err_msg),
                        "TYPE:RESP\nSTATUS:ERROR\nCODE:%d\nMSG:Sentence index out of range (valid: 0-%d)\n\n",
                        ERR_SENTENCE_OUT_OF_RANGE, sent_count - 1);
                }
                LOG_ERROR("WRITE_START: Invalid sentence index %d (sent_count=%d, allow_append=%d)", 
                         sentence_num, sent_count, allow_append);
                send_message(client_fd, err_msg);
                close(client_fd);
                continue;
            }

            // Try to lock sentence
            int lock_result = lock_sentence(fname, sentence_num, user);
            if (lock_result == -1) {
                LOG_WARN("WRITE_START: Sentence %d already locked by another user", sentence_num);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_LOCK_FAILED, "Sentence is locked by another user");
                send_message(client_fd, err_buf);
                close(client_fd);
                continue;
            } else if (lock_result == -2) {
                LOG_ERROR("WRITE_START: Too many active locks");
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_LOCK_FAILED, "Too many active locks");
                send_message(client_fd, err_buf);
                close(client_fd);
                continue;
            }

            LOG_INFO("WRITE_START: Successfully locked sentence %d of '%s' for user '%s'", sentence_num, fname, user);
            char succ_buf[512];
            format_success_message(succ_buf, sizeof(succ_buf), "Sentence locked");
            send_message(client_fd, succ_buf);
        }

        // --- WRITE_COMMIT (Enhanced with comprehensive validation and logging) ---
        else if (strcmp(op, "WRITE_COMMIT") == 0 || strcmp(op, "REPLICATE_WRITE") == 0) {
            int is_replica = (strcmp(op, "REPLICATE_WRITE") == 0);
            char fname[64] = {0}, user[64] = {0};
            int sentence_num = 0;
            
            // Heap allocation for large buffers to prevent stack overflow
            char (*sentences)[2048] = NULL;
            char (*final_sentences)[2048] = NULL;
            char (*words)[256] = NULL;
            char (*temp_words)[256] = NULL;
            
            typedef struct {
                int idx;
                char content[256];
            } WriteUpdate;
            WriteUpdate *update_list = NULL;
            
            // Allocate memory
            sentences = malloc(100 * 2048);
            final_sentences = malloc(100 * 2048);
            words = malloc(MAX_WORDS * 256);
            temp_words = malloc(50 * 256);
            update_list = malloc(MAX_WRITE_UPDATES * sizeof(WriteUpdate));
            
            if (!sentences || !final_sentences || !words || !temp_words || !update_list) {
                LOG_ERROR("WRITE_COMMIT: Memory allocation failed");
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Server memory error\n\n");
                close(client_fd);
                goto cleanup_write;
            }

            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);
            if (strstr(buf, "SENTENCE:"))
                sscanf(strstr(buf, "SENTENCE:"), "SENTENCE:%d", &sentence_num);

            LOG_INFO("%s request: file='%s', user='%s', sentence=%d", op, fname, user, sentence_num);

            if (!is_replica && !is_sentence_locked_by(fname, sentence_num, user)) {
                LOG_WARN("WRITE_COMMIT denied: %s sentence %d not locked by %s", fname, sentence_num, user);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_LOCK_FAILED,
                                     "Sentence not locked by current user");
                send_message(client_fd, err_buf);
                close(client_fd);
                goto cleanup_write;
            }

            // Extract updates
            char *updates_ptr = strstr(buf, "UPDATES:\n");
            if (!updates_ptr) {
                LOG_ERROR("WRITE_COMMIT: No updates provided");
                if (!is_replica) unlock_sentence(fname, sentence_num);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_INVALID_PARAMETERS, "No updates provided");
                send_message(client_fd, err_buf);
                close(client_fd);
                goto cleanup_write;
            }
            updates_ptr += 9; // Skip "UPDATES:\n"
            
            LOG_DEBUG("WRITE_COMMIT: Received updates for %s (sentence %d):\n%s", fname, sentence_num, updates_ptr);

            char data_path[128], backup_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
            snprintf(backup_path, sizeof(backup_path), "%s/%s.backup", FILES_DIR, fname);

            lock_file_write(fname);

            // Read current file content
            FILE *f = fopen(data_path, "r");
            if (!f) {
                unlock_file(fname);
                if (!is_replica) unlock_sentence(fname, sentence_num);
                LOG_ERROR("WRITE_COMMIT: Cannot read file '%s'", data_path);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_FILE_OPEN_FAILED, "Cannot read file");
                send_message(client_fd, err_buf);
                close(client_fd);
                goto cleanup_write;
            }

            char content[8192] = "";
            char line[512];
            size_t total_read = 0;
            while (fgets(line, sizeof(line), f)) {
                size_t line_len = strlen(line);
                if (total_read + line_len < sizeof(content) - 1) {
                    strncat(content, line, sizeof(content) - strlen(content) - 1);
                    total_read += line_len;
                } else {
                    LOG_WARN("WRITE_COMMIT: File content truncated during read");
                    break;
                }
            }
            fclose(f);
            LOG_INFO("WRITE_COMMIT: Read %zu bytes from '%s'", total_read, fname);

            // Backup original file
            f = fopen(backup_path, "w");
            if (f) {
                fprintf(f, "%s", content);
                fclose(f);
                LOG_INFO("WRITE_COMMIT: Created backup at '%s'", backup_path);
            } else {
                LOG_WARN("WRITE_COMMIT: Failed to create backup file");
            }

            // Parse into sentences
            int sent_count = parse_sentences(content, sentences, 100);
            LOG_INFO("WRITE_COMMIT: Parsed %d sentences", sent_count);

            // Check sentence index validity (should already be valid, but double-check)
            // Allow append when sentence_num == sent_count and last char is delimiter
            int allow_append = 0;
            int clen = strlen(content);
            int ii = clen - 1;
            while (ii >= 0 && isspace((unsigned char)content[ii])) ii--;
            if (ii < 0) allow_append = 1;
            else if (content[ii] == '.' || content[ii] == '!' || content[ii] == '?') allow_append = 1;

            if (sentence_num < 0 || sentence_num > sent_count ||
                (sentence_num == sent_count && !allow_append)) {
                unlock_file(fname);
                if (!is_replica) unlock_sentence(fname, sentence_num);
                LOG_ERROR("WRITE_COMMIT: Invalid sentence index %d (sent_count=%d, allow_append=%d)", 
                         sentence_num, sent_count, allow_append);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_SENTENCE_OUT_OF_RANGE, "Sentence index out of range");
                send_message(client_fd, err_buf);
                close(client_fd);
                goto cleanup_write;
            }

            // Parse target sentence into words. If appending a new sentence
            // (sentence_num == sent_count) initialize an empty sentence.
            int word_count = 0;
            if (sentence_num < sent_count) {
                word_count = parse_words(sentences[sentence_num], words, MAX_WORDS);
                LOG_INFO("WRITE_COMMIT: Sentence %d has %d words", sentence_num, word_count);
            } else {
                // Appending a new sentence: start with zero words
                words[0][0] = '\0';
                word_count = 0;
                sentences[sentence_num][0] = '\0';
                LOG_INFO("WRITE_COMMIT: Appending new sentence %d", sentence_num);
            }

            // If the last word ends with a sentence delimiter (.,!,?) separate it into its own token
            if (word_count > 0) {
                char *last = words[word_count-1];
                size_t llen = strlen(last);
                if (llen > 0) {
                    char lastc = last[llen-1];
                    if (lastc == '.' || lastc == '!' || lastc == '?') {
                        // remove delimiter from last word
                        last[llen-1] = '\0';
                        if (strlen(last) == 0) {
                            // last was only a delimiter: replace it with the delimiter token
                            last[0] = lastc;
                            last[1] = '\0';
                        } else {
                            // add delimiter as separate token if capacity allows
                            if (word_count + 1 <= MAX_WORDS) {
                                words[word_count][0] = lastc;
                                words[word_count][1] = '\0';
                                word_count++;
                                LOG_DEBUG("WRITE_COMMIT: Split delimiter '%c' as separate token", lastc);
                            }
                        }
                    }
                }
            }

            int update_total = 0;
            int parse_error = 0;
            char parse_error_msg[256] = "";
            char update_line[512];
            char *line_ptr = updates_ptr;

            while (*line_ptr) {
                if (*line_ptr == '\n') {
                    line_ptr++;
                    continue;
                }

                char *line_end = strchr(line_ptr, '\n');
                if (!line_end) {
                    if (strlen(line_ptr) > 0) {
                        line_end = line_ptr + strlen(line_ptr);
                    } else {
                        break;
                    }
                }

                int len = line_end - line_ptr;
                if (len <= 0 || len >= (int)sizeof(update_line)) {
                    snprintf(parse_error_msg, sizeof(parse_error_msg), "Invalid update length");
                    parse_error = 1;
                    break;
                }

                strncpy(update_line, line_ptr, len);
                update_line[len] = '\0';

                char *space_pos = strchr(update_line, ' ');
                if (!space_pos) {
                    strcpy(parse_error_msg, "Invalid update format - missing space");
                    parse_error = 1;
                    break;
                }

                int word_idx_user;
                if (sscanf(update_line, "%d", &word_idx_user) != 1) {
                    strcpy(parse_error_msg, "Invalid update format - bad index");
                    parse_error = 1;
                    break;
                }

                if (update_total >= MAX_WRITE_UPDATES) {
                    snprintf(parse_error_msg, sizeof(parse_error_msg), "Too many updates (max %d)", MAX_WRITE_UPDATES);
                    parse_error = 1;
                    break;
                }

                update_list[update_total].idx = word_idx_user;
                strncpy(update_list[update_total].content, space_pos + 1, sizeof(update_list[update_total].content) - 1);
                update_list[update_total].content[sizeof(update_list[update_total].content) - 1] = '\0';

                update_total++;
                line_ptr = line_end;
                if (*line_ptr == '\n') line_ptr++;
            }

            if (parse_error || update_total == 0) {
                unlock_file(fname);
                if (!is_replica) unlock_sentence(fname, sentence_num);
                LOG_ERROR("WRITE_COMMIT: Failed to parse updates - %s", parse_error_msg[0] ? parse_error_msg : "no updates provided");
                char err_resp[512];
                snprintf(err_resp, sizeof(err_resp),
                         "TYPE:RESP\nSTATUS:ERROR\nCODE:%d\nMSG:%s\n\n",
                         ERR_INVALID_UPDATE_FORMAT,
                         parse_error_msg[0] ? parse_error_msg : "No updates provided");
                send_message(client_fd, err_resp);
                close(client_fd);
                goto cleanup_write;
            }

            int sequential_rewrite = 1;
            for (int i = 0; i < update_total; i++) {
                if (update_list[i].idx != i + 1) {
                    sequential_rewrite = 0;
                    break;
                }
            }

            if (sequential_rewrite && word_count > 0) {
                LOG_INFO("WRITE_COMMIT: Sequential rewrite detected (%d updates) - clearing sentence %d", update_total, sentence_num);
                word_count = 0;
            }

            int error = 0;
            char error_msg[256] = "";
            int updates_applied = 0;

            for (int u = 0; u < update_total; u++) {
                int word_idx_user = sequential_rewrite ? (word_count + 1) : update_list[u].idx;

                if (word_idx_user < 1 || word_idx_user > word_count + 1) {
                    snprintf(error_msg, sizeof(error_msg),
                             "Word index %d out of range (valid: 1-%d)",
                             word_idx_user, word_count + 1);
                    LOG_ERROR("WRITE_COMMIT: %s", error_msg);
                    error = 1;
                    break;
                }

                int word_idx = word_idx_user - 1;
                const char *new_content_src = update_list[u].content;

                int temp_count = 0;
                char temp_word[256];
                int temp_idx = 0;

                for (const char *p = new_content_src; *p; p++) {
                    if (*p == ' ') {
                        if (temp_idx > 0) {
                            temp_word[temp_idx] = '\0';
                            if (temp_count < 50)
                                strcpy(temp_words[temp_count++], temp_word);
                            temp_idx = 0;
                        }
                    } else if (*p == '.' || *p == '!' || *p == '?') {
                        if (temp_idx > 0) {
                            temp_word[temp_idx] = '\0';
                            if (temp_count < 50)
                                strcpy(temp_words[temp_count++], temp_word);
                            temp_idx = 0;
                        }
                        temp_word[0] = *p;
                        temp_word[1] = '\0';
                        if (temp_count < 50)
                            strcpy(temp_words[temp_count++], temp_word);
                    } else {
                        if (temp_idx < (int)sizeof(temp_word) - 1)
                            temp_word[temp_idx++] = *p;
                    }
                }
                if (temp_idx > 0) {
                    temp_word[temp_idx] = '\0';
                    if (temp_count < 50)
                        strcpy(temp_words[temp_count++], temp_word);
                }

                int net_increase = (word_idx == word_count) ? temp_count : (temp_count - 1);
                if (word_count + net_increase > MAX_WORDS) {
                    snprintf(error_msg, sizeof(error_msg), "Not enough capacity to insert %d words (max %d)", temp_count, MAX_WORDS);
                    LOG_ERROR("WRITE_COMMIT: %s", error_msg);
                    error = 1;
                    break;
                }

                if (word_idx == word_count) {
                    // Append: just add the new words
                    for (int i = 0; i < temp_count; i++) {
                        strcpy(words[word_count++], temp_words[i]);
                    }
                    LOG_DEBUG("WRITE_COMMIT: Appended %d words at position %d", temp_count, word_idx_user);
                } else {
                    // Replace
                    int shift = temp_count - 1;
                    if (shift > 0) {
                        // Expanding: shift right
                        for (int i = word_count - 1; i > word_idx; i--) {
                            strcpy(words[i + shift], words[i]);
                        }
                    }
                    
                    // Copy new words
                    for (int i = 0; i < temp_count; i++) {
                        strcpy(words[word_idx + i], temp_words[i]);
                    }
                    
                    word_count += shift;
                    LOG_DEBUG("WRITE_COMMIT: Replaced word at %d with %d words", word_idx_user, temp_count);
                }
                updates_applied++;
            }

            if (error) {
                unlock_file(fname);
                if (!is_replica) unlock_sentence(fname, sentence_num);
                LOG_ERROR("WRITE_COMMIT: Failed after applying %d updates - %s", updates_applied, error_msg);
                char err_resp[512];
                snprintf(err_resp, sizeof(err_resp), "TYPE:RESP\nSTATUS:ERROR\nCODE:%d\nMSG:%s\n\n",
                         ERR_INVALID_UPDATE_FORMAT, error_msg);
                send_message(client_fd, err_resp);
                close(client_fd);
                goto cleanup_write;
            }

            LOG_INFO("WRITE_COMMIT: Applied %d updates successfully", updates_applied);

            // Reconstruct sentence
            reconstruct_sentence(words, word_count, sentences[sentence_num], 2048);
            LOG_DEBUG("WRITE_COMMIT: Reconstructed sentence %d", sentence_num);

            // Split sentences at delimiters
            int final_count = 0;
            
            // Copy sentences before modified
            for (int i = 0; i < sentence_num; i++) {
                strcpy(final_sentences[final_count++], sentences[i]);
            }
            
            // Split modified sentence
            char *modified = sentences[sentence_num];
            char temp_sent[2048] = "";
            int temp_len = 0;
            
            for (int i = 0; modified[i]; i++) {
                temp_sent[temp_len++] = modified[i];
                
                if (modified[i] == '.' || modified[i] == '!' || modified[i] == '?') {
                    temp_sent[temp_len] = '\0';
                    if (final_count < 100) {
                        strcpy(final_sentences[final_count++], temp_sent);
                    }
                    temp_len = 0;
                    
                    // Skip trailing spaces
                    while (modified[i+1] == ' ') i++;
                }
            }
            
            // Add remaining content
            if (temp_len > 0) {
                temp_sent[temp_len] = '\0';
                if (final_count < 100) {
                    strcpy(final_sentences[final_count++], temp_sent);
                }
            }
            
            // Copy sentences after modified
            for (int i = sentence_num + 1; i < sent_count; i++) {
                if (final_count < 100) {
                    strcpy(final_sentences[final_count++], sentences[i]);
                }
            }
            
            LOG_INFO("WRITE_COMMIT: Split into %d final sentences", final_count);

            // Reconstruct file
            char new_content[8192] = "";
            for (int i = 0; i < final_count; i++) {
                if (i > 0) strcat(new_content, " ");
                strncat(new_content, final_sentences[i], sizeof(new_content) - strlen(new_content) - 1);
            }
            
            size_t new_content_len = strlen(new_content);
            LOG_INFO("WRITE_COMMIT: Reconstructed file content (%zu bytes)", new_content_len);

            // Write file to temp first
            char temp_write_path[256];
            snprintf(temp_write_path, sizeof(temp_write_path), "%s.tmp", data_path);
            
            f = fopen(temp_write_path, "w");
            if (!f) {
                unlock_file(fname);
                if (!is_replica) unlock_sentence(fname, sentence_num);
                LOG_ERROR("WRITE_COMMIT: Cannot write temp file '%s'", temp_write_path);
                char err_buf[512];
                format_error_message(err_buf, sizeof(err_buf), ERR_FILE_WRITE_FAILED, "Cannot write temp file");
                send_message(client_fd, err_buf);
                close(client_fd);
                goto cleanup_write;
            }
            
            size_t written = fprintf(f, "%s", new_content);
            fclose(f);
            
            if (written != new_content_len) {
                LOG_WARN("WRITE_COMMIT: Partial write - expected %zu bytes, wrote %zu bytes", new_content_len, written);
                remove(temp_write_path); // Cleanup
                // Handle error...
            } else {
                // Atomic rename
                if (rename(temp_write_path, data_path) != 0) {
                    LOG_ERROR("WRITE_COMMIT: Failed to rename temp file to '%s'", data_path);
                    remove(temp_write_path);
                    // Handle error...
                } else {
                    LOG_INFO("WRITE_COMMIT: Successfully wrote %zu bytes to '%s'", written, data_path);
                }
            }

            // Update metadata
            update_metadata(fname);
            LOG_INFO("WRITE_COMMIT: Updated metadata for '%s'", fname);

            unlock_file(fname);
            if (!is_replica) unlock_sentence(fname, sentence_num);

            // Trigger replication if primary
            if (!is_replica) {
                // Read backups from .meta
                char meta_path[128];
                snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
                FILE *meta = fopen(meta_path, "r");
                if (meta) {
                    char line[256];
                    char backups[512] = "";
                    while (fgets(line, sizeof(line), meta)) {
                        if (strncmp(line, "BACKUPS:", 8) == 0) {
                            char *p = line + 8;
                            char *nl = strchr(p, '\n');
                            if (nl) *nl = '\0';
                            strcpy(backups, p);
                            break;
                        }
                    }
                    fclose(meta);
                    
                    if (strlen(backups) > 0) {
                        // Parse backups: ip:port,ip:port
                        char *token = strtok(backups, ",");
                        while (token) {
                            char ip[64];
                            int port;
                            if (sscanf(token, "%63[^:]:%d", ip, &port) == 2) {
                                // Send REPLICATE_WRITE
                                int sock = socket(AF_INET, SOCK_STREAM, 0);
                                struct sockaddr_in addr = {0};
                                addr.sin_family = AF_INET;
                                addr.sin_port = htons(port);
                                inet_pton(AF_INET, ip, &addr.sin_addr);
                                
                                if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                                    char msg[8192]; // Large buffer for updates
                                    snprintf(msg, sizeof(msg), 
                                             "TYPE:REQ\nOP:REPLICATE_WRITE\nFILENAME:%s\nUSER:%s\nSENTENCE:%d\nUPDATES:\n%s",
                                             fname, user, sentence_num, updates_ptr);
                                    send_message(sock, msg);
                                    // Don't wait for response (async)
                                    close(sock);
                                    printf("[SS] Replicated WRITE to %s:%d\n", ip, port);
                                } else {
                                    printf("[SS] Failed to replicate to %s:%d\n", ip, port);
                                }
                            }
                            token = strtok(NULL, ",");
                        }
                    }
                }
            }

            LOG_INFO("WRITE_COMMIT: Successfully committed changes to '%s' sentence %d by user '%s'", fname, sentence_num, user);
            
            // Notify NS to update cache with new word/char counts
            notify_ns_cache_update(fname);
            
            char succ_buf[512];
            format_success_message(succ_buf, sizeof(succ_buf), "Write successful");
            send_message(client_fd, succ_buf);

cleanup_write:
            if (sentences) free(sentences);
            if (final_sentences) free(final_sentences);
            if (words) free(words);
            if (temp_words) free(temp_words);
            if (update_list) free(update_list);
        }
        
        // CREATEFOLDER handler
        else if (strcmp(op, "CREATEFOLDER") == 0) {
            char foldername[256] = "";
            char owner[64] = "";
            
            if (strstr(buf, "FOLDERNAME:"))
                sscanf(strstr(buf, "FOLDERNAME:"), "FOLDERNAME:%255s", foldername);
            if (strstr(buf, "OWNER:"))
                sscanf(strstr(buf, "OWNER:"), "OWNER:%63s", owner);
            
            printf("[SS] CREATEFOLDER: %s (owner: %s)\n", foldername, owner);
            
            // Construct full path
            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s%s", FILES_DIR, foldername);
            
            // Create directory recursively
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s", full_path);
            size_t len = strlen(tmp);
            if (tmp[len - 1] == '/') tmp[len - 1] = 0;
            
            for (char *p = tmp + 1; *p; p++) {
                if (*p == '/') {
                    *p = 0;
                    mkdir(tmp, 0700);
                    *p = '/';
                }
            }
            
            if (mkdir(tmp, 0700) == 0 || errno == EEXIST) {
                 send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:Folder created\n\n");
            } else {
                 char err[256];
                 snprintf(err, sizeof(err), "TYPE:RESP\nSTATUS:ERROR\nMSG:Failed to create folder: %s\n\n", strerror(errno));
                 send_message(client_fd, err);
            }
        }
        
        // MOVE handler
        else if (strcmp(op, "MOVE") == 0) {
            char filename[256] = "";
            char dest[512] = "";
            
            if (strstr(buf, "FILENAME:"))
                sscanf(strstr(buf, "FILENAME:"), "FILENAME:%255s", filename);
            if (strstr(buf, "DEST:"))
                sscanf(strstr(buf, "DEST:"), "DEST:%511s", dest);
            
            printf("[SS] MOVE: %s -> %s\n", filename, dest);
            
            lock_file_write(filename);
            
            // Construct paths
            char old_data[512], new_data[512];
            char old_meta[512], new_meta[512];
            
            snprintf(old_data, sizeof(old_data), "%s/%s.data", FILES_DIR, filename);
            snprintf(new_data, sizeof(new_data), "%s%s.data", FILES_DIR, dest);
            
            snprintf(old_meta, sizeof(old_meta), "%s/%s.meta", FILES_DIR, filename);
            snprintf(new_meta, sizeof(new_meta), "%s%s.meta", FILES_DIR, dest);
            
            // Rename data file
            if (rename(old_data, new_data) != 0) {
                unlock_file(filename);
                char err[256];
                snprintf(err, sizeof(err), "TYPE:RESP\nSTATUS:ERROR\nMSG:Failed to move data file: %s\n\n", strerror(errno));
                send_message(client_fd, err);
                continue;
            }
            
            // Rename meta file
            if (rename(old_meta, new_meta) != 0) {
                // Rollback data file move
                rename(new_data, old_data);
                unlock_file(filename);
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Failed to move metadata file\n\n");
                close(client_fd);
                continue;
            }
            
            // Move backup if exists
            char old_backup[256], new_backup[512];
            snprintf(old_backup, sizeof(old_backup), "%s/%s.backup", FILES_DIR, filename);
            snprintf(new_backup, sizeof(new_backup), "%s%s.backup", FILES_DIR, dest);
            rename(old_backup, new_backup);  // Ignore error if no backup
            
            unlock_file(filename);
            
            send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:File moved\n\n");
            printf("[SS] Moved files: %s -> %s\n", filename, dest);
        }
        
        // --- SYNC_FILE ---
        else if (strcmp(op, "SYNC_FILE") == 0) {
            char fname[64] = {0};
            char src_ip[64] = {0};
            int src_port = 0;
            
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            sscanf(strstr(buf, "SRC_IP:"), "SRC_IP:%63s", src_ip);
            sscanf(strstr(buf, "SRC_PORT:"), "SRC_PORT:%d", &src_port);
            
            printf("[SS] Syncing file %s from %s:%d\n", fname, src_ip, src_port);
            
            // Connect to source SS
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(src_port);
            inet_pton(AF_INET, src_ip, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                printf("[SS] Failed to connect to source SS for sync\n");
                send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Connection failed\n\n");
                close(client_fd);
                continue;
            }
            
            // 1. Get Content
            char req[256];
            snprintf(req, sizeof(req), "TYPE:REQ\nOP:READ\nUSER:system\nFILENAME:%s\n\n", fname);
            send_message(sock, req);
            
            char resp[8192];
            if (recv_message(sock, resp, sizeof(resp)) == 0 && strstr(resp, "STATUS:OK")) {
                char *content = strstr(resp, "MSG:");
                if (content) {
                    content += 4;
                    while (*content == '\n') content++;
                    
                    lock_file_write(fname);
                    char data_path[128];
                    snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);
                    FILE *f = fopen(data_path, "w");
                    if (f) {
                        fprintf(f, "%s", content);
                        fclose(f);
                    }
                    unlock_file(fname);
                }
            }
            close(sock);
            
            // 2. Get Metadata (Reconnect for separate request)
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                snprintf(req, sizeof(req), "TYPE:REQ\nOP:GET_META\nFILENAME:%s\n\n", fname);
                send_message(sock, req);
                
                if (recv_message(sock, resp, sizeof(resp)) == 0 && strstr(resp, "STATUS:OK")) {
                    char *meta_content = strstr(resp, "MSG:");
                    if (meta_content) {
                        meta_content += 4;
                        while (*meta_content == '\n') meta_content++;
                        
                        lock_file_write(fname);
                        char meta_path[128];
                        snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
                        FILE *f = fopen(meta_path, "w");
                        if (f) {
                            fprintf(f, "%s", meta_content);
                            fclose(f);
                        }
                        unlock_file(fname);
                    }
                }
            }
            close(sock);
            
            printf("[SS] Sync complete for %s\n", fname);
            send_message(client_fd, "TYPE:RESP\nSTATUS:OK\nMSG:Sync complete\n\n");
        }
        
        else {
            send_message(client_fd, "TYPE:RESP\nSTATUS:ERROR\nMSG:Unsupported operation\n\n");
        }
        
        close(client_fd);
    }
    return NULL;
}

void *client_listener(void *arg) {
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0}, cli;
    socklen_t cli_len = sizeof(cli);

    int opt = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SS_CLIENT_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(client_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(client_fd, 5);
    printf("[SS] Client listener running on %d...\n", SS_CLIENT_PORT);

    while (1) {
        int conn = accept(client_fd, (struct sockaddr *)&cli, &cli_len);
        char buf[512];
        if (recv_message(conn, buf, sizeof(buf)) != 0) {
            close(conn);
            continue;
        }

        printf("[SS] Received STREAM request:\n%s\n", buf);

        char op[64] = {0};
        char *op_ptr = strstr(buf, "OP:");
        if (!op_ptr || sscanf(op_ptr, "OP:%63s", op) != 1) {
            send_message(conn, "TYPE:RESP\nSTATUS:ERROR\nMSG:Invalid operation\n\n");
            close(conn);
            continue;
        }

        if (strcmp(op, "STREAM") == 0) {
            char fname[64] = {0}, user[64] = {0};
            sscanf(strstr(buf, "FILENAME:"), "FILENAME:%63s", fname);
            if (strstr(buf, "USER:"))
                sscanf(strstr(buf, "USER:"), "USER:%63s", user);

            // Check access
            if (!check_access(fname, user, 'R')) {
                send_message(conn, "TYPE:RESP\nSTATUS:ERROR\nMSG:Access denied - no read permission\n\n");
                close(conn);
                continue;
            }

            char data_path[128];
            snprintf(data_path, sizeof(data_path), "%s/%s.data", FILES_DIR, fname);

            FILE *f = fopen(data_path, "r");
            if (!f) {
                send_message(conn, "TYPE:RESP\nSTATUS:ERROR\nMSG:Cannot open file for streaming\n\n");
                close(conn);
                continue;
            }

            char content[8192] = "";
            char line[512];
            while (fgets(line, sizeof(line), f))
                strncat(content, line, sizeof(content) - strlen(content) - 1);
            fclose(f);

            char resp[9000];
            snprintf(resp, sizeof(resp),
                     "TYPE:RESP\nSTATUS:OK\nMSG:\n%s\n", content);
            send_message(conn, resp);
            printf("[SS] Stream request handled for %s (user: %s)\n", fname, user);
        } else {
            send_message(conn, "TYPE:RESP\nSTATUS:ERROR\nMSG:Unsupported operation\n\n");
        }

        close(conn);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    // Parse command line arguments: ./storage_server <ss_name> <client_port> <ctrl_port> [ns_ip]
    if (argc < 4) {
        printf("Usage: %s <ss_name> <client_port> <ctrl_port> [ns_ip]\n", argv[0]);
        printf("  ss_name: Name/ID for this storage server (e.g., ss0, ss1)\n");
        printf("  client_port: Port for client connections\n");
        printf("  ctrl_port: Port for control/replication connections\n");
        printf("  ns_ip: (Optional) Name Server IP address (default: 127.0.0.1)\n");
        printf("\nEnvironment variables:\n");
        printf("  NS_IP: Name Server IP address (overrides default, overridden by command-line)\n");
        return 1;
    }
    
    strncpy(SS_NAME, argv[1], sizeof(SS_NAME) - 1);
    SS_NAME[sizeof(SS_NAME) - 1] = '\0';
    SS_CLIENT_PORT = atoi(argv[2]);
    SS_CTRL_PORT = atoi(argv[3]);
    
    // Check for NS IP from environment variable
    char *env_ns_ip = getenv("NS_IP");
    if (env_ns_ip != NULL) {
        strncpy(NS_IP, env_ns_ip, sizeof(NS_IP) - 1);
        NS_IP[sizeof(NS_IP) - 1] = '\0';
        printf("[SS] Using NS IP from environment: %s\n", NS_IP);
    }
    
    // Command-line argument overrides environment variable
    if (argc >= 5) {
        strncpy(NS_IP, argv[4], sizeof(NS_IP) - 1);
        NS_IP[sizeof(NS_IP) - 1] = '\0';
        printf("[SS] Using NS IP from command-line: %s\n", NS_IP);
    }
    
    printf("[SS] Starting Storage Server '%s' on CLIENT_PORT=%d, CTRL_PORT=%d\n",
           SS_NAME, SS_CLIENT_PORT, SS_CTRL_PORT);
    printf("[SS] Will connect to Name Server at %s:%d\n", NS_IP, NS_PORT);
    
    // Set up unique files directory for this storage server
    snprintf(FILES_DIR, sizeof(FILES_DIR), "ss/files_%s", SS_NAME);
    printf("[SS] Using files directory: %s\n", FILES_DIR);
    
    // Ignore SIGPIPE to prevent process termination on socket errors
    signal(SIGPIPE, SIG_IGN);

    // Initialize logging
    if (init_logging(COMP_SS, "logs") != 0) {
        printf("[SS] Warning: Failed to initialize logging\n");
    }
    LOG_INFO("Storage Server '%s' starting up...", SS_NAME);
    
    // Create SS-specific files directory
    mkdir("ss", 0755);  // Ensure ss/ directory exists
    mkdir(FILES_DIR, 0755);
    LOG_INFO("Created files directory: %s", FILES_DIR);
    
    // Initialize per-file locks (reader-writer locks)
    for (int i = 0; i < FILE_LOCK_BUCKETS; i++) {
        pthread_rwlock_init(&file_locks[i], NULL);
    }
    
    // Initialize sentence locks
    for (int i = 0; i < MAX_SENTENCE_LOCKS; i++) {
        sentence_locks[i].active = 0;
    }
    
    LOG_INFO("Initialized %d file lock buckets and %d sentence locks", 
             FILE_LOCK_BUCKETS, MAX_SENTENCE_LOCKS);

    // Scan for existing files and build file list with complete metadata
    DIR *d = opendir(FILES_DIR);
    char file_list[8192] = "";
    int file_count = 0;
    
    if (d) {
        struct dirent *entry;
        while ((entry = readdir(d))) {
            if (strstr(entry->d_name, ".data")) {
                char fname[64];
                strncpy(fname, entry->d_name, sizeof(fname));
                fname[strlen(fname) - 5] = '\0'; // Remove ".data"
                
                // Get complete metadata from .meta file
                char meta_path[256];
                snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", FILES_DIR, fname);
                FILE *meta = fopen(meta_path, "r");
                char owner[64] = "unknown";
                int words = 0, chars = 0;
                char modified[64] = "N/A";
                char access_list[512] = "";
                
                if (meta) {
                    char line[256];
                    while (fgets(line, sizeof(line), meta)) {
                        if (strncmp(line, "OWNER:", 6) == 0) {
                            sscanf(line, "OWNER:%63s", owner);
                        } else if (strncmp(line, "WORDS:", 6) == 0) {
                            sscanf(line, "WORDS:%d", &words);
                        } else if (strncmp(line, "CHARS:", 6) == 0) {
                            sscanf(line, "CHARS:%d", &chars);
                        } else if (strncmp(line, "MODIFIED:", 9) == 0) {
                            sscanf(line, "MODIFIED:%63s", modified);
                        } else if (strncmp(line, "ACCESS:", 7) == 0) {
                            // Parse access line: "ACCESS: user:R user:W"
                            char *access_start = line + 7;
                            while (*access_start == ' ') access_start++;
                            char *newline = strchr(access_start, '\n');
                            if (newline) *newline = '\0';
                            
                            // Convert "user:R user:W" to "user:R,user:W"
                            char *token = strtok(access_start, " ");
                            while (token) {
                                if (strlen(access_list) > 0) strcat(access_list, ",");
                                strncat(access_list, token, sizeof(access_list) - strlen(access_list) - 1);
                                token = strtok(NULL, " ");
                            }
                        }
                    }
                    fclose(meta);
                }
                
                // Format: filename:owner:words:chars:modified:access_list
                if (file_count > 0) strncat(file_list, "|", sizeof(file_list) - strlen(file_list) - 1);
                char file_entry[1024];
                snprintf(file_entry, sizeof(file_entry), "%s:%s:%d:%d:%s:%s",
                         fname, owner, words, chars, modified, access_list);
                strncat(file_list, file_entry, sizeof(file_list) - strlen(file_list) - 1);
                file_count++;
            }
        }
        closedir(d);
    }
    
    printf("[SS] Found %d existing files\n", file_count);

    // Start listeners BEFORE registering with NS to handle immediate sync requests
    pthread_t ctrl_thread, client_thread, heartbeat_thread;
    pthread_create(&ctrl_thread, NULL, control_listener, NULL);
    pthread_create(&client_thread, NULL, client_listener, NULL);
    
    // Give threads a moment to bind ports
    usleep(100000); // 100ms

    // Register with NS
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ns_addr = {0};
    ns_addr.sin_family = AF_INET;
    ns_addr.sin_port = htons(NS_PORT);
    inet_pton(AF_INET, NS_IP, &ns_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&ns_addr, sizeof(ns_addr)) == 0) {
        char msg[10240];
        snprintf(msg, sizeof(msg),
                 "TYPE:REQ\nOP:REGISTER_SS\nSS_NAME:%s\nSS_CLIENT_PORT:%d\nSS_CTRL_PORT:%d\nFILES:%s\nUSER:system\n\n",
                 SS_NAME, SS_CLIENT_PORT, SS_CTRL_PORT, file_list);

        printf("[SS %s] Registering with NS...\n", SS_NAME);
        send_message(sock, msg);
        char buf[512];
        recv_message(sock, buf, sizeof(buf));
        printf("[SS] NS replied:\n%s\n", buf);
        close(sock);
    } else {
        printf("[SS] Failed to connect to NS for registration\n");
    }
    
    // Start heartbeat thread
    pthread_create(&heartbeat_thread, NULL, heartbeat_sender, NULL);
    
    LOG_INFO("Storage Server fully initialized and running");
    pthread_join(ctrl_thread, NULL);
    
    // Cleanup
    LOG_INFO("Storage Server shutting down");
    for (int i = 0; i < FILE_LOCK_BUCKETS; i++) {
        pthread_rwlock_destroy(&file_locks[i]);
    }
    close_logging();
    
    return 0;
}