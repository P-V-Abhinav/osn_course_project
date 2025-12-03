#include "lru_cache.h"
#include "trie.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* Hash function for filename */
static unsigned int hash_filename(const char *s) {
    unsigned int h = 0;
    while (*s) h = (h * 31 + *s++) % TABLE_SIZE;
    return h;
}

/* Move node to front of LRU list (most recently used) */
static void move_to_front(LRUCache *cache, CacheNode *node) {
    if (cache->lru_head == node) return;  // Already at front
    
    // Remove from current position
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    if (cache->lru_tail == node) cache->lru_tail = node->prev;
    
    // Insert at front
    node->prev = NULL;
    node->next = cache->lru_head;
    if (cache->lru_head) cache->lru_head->prev = node;
    cache->lru_head = node;
    if (!cache->lru_tail) cache->lru_tail = node;
}

/* Remove node from LRU list */
static void remove_from_lru(LRUCache *cache, CacheNode *node) {
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    if (cache->lru_head == node) cache->lru_head = node->next;
    if (cache->lru_tail == node) cache->lru_tail = node->prev;
}

/* Evict least recently used entry */
static void evict_lru(LRUCache *cache) {
    if (!cache->lru_tail) return;
    
    CacheNode *victim = cache->lru_tail;
    int bucket = victim->bucket_idx;
    
    // Remove from LRU list
    pthread_mutex_lock(&cache->lru_lock);
    remove_from_lru(cache, victim);
    cache->current_size--;
    pthread_mutex_unlock(&cache->lru_lock);
    
    // Remove from hash bucket (need write lock)
    pthread_rwlock_wrlock(&cache->buckets[bucket].lock);
    CacheNode **pp = &cache->buckets[bucket].head;
    while (*pp && *pp != victim) pp = &(*pp)->bucket_next;
    if (*pp) *pp = victim->bucket_next;
    pthread_rwlock_unlock(&cache->buckets[bucket].lock);
    
    printf("[CACHE] Evicted: %s (LRU)\n", victim->filename);
    free(victim);
}

/* Initialize cache */
LRUCache* cache_init(size_t capacity) {
    LRUCache *cache = calloc(1, sizeof(LRUCache));
    cache->capacity = capacity;
    cache->current_size = 0;
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    pthread_mutex_init(&cache->lru_lock, NULL);
    
    // Initialize per-bucket locks
    for (int i = 0; i < TABLE_SIZE; i++) {
        cache->buckets[i].head = NULL;
        pthread_rwlock_init(&cache->buckets[i].lock, NULL);
    }
    
    return cache;
}

/* Destroy cache */
void cache_destroy(LRUCache *cache) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        pthread_rwlock_wrlock(&cache->buckets[i].lock);
        CacheNode *cur = cache->buckets[i].head;
        while (cur) {
            CacheNode *tmp = cur;
            cur = cur->next;
            free(tmp);
        }
        pthread_rwlock_unlock(&cache->buckets[i].lock);
        pthread_rwlock_destroy(&cache->buckets[i].lock);
    }
    pthread_mutex_destroy(&cache->lru_lock);
    free(cache);
}

/* Get file from cache (returns NULL if not found or expired) */
CacheNode* cache_get(LRUCache *cache, const char *filename) {
    unsigned int bucket = hash_filename(filename);
    time_t current_time = time(NULL);
    
    // Read lock on bucket (allows concurrent reads)
    pthread_rwlock_rdlock(&cache->buckets[bucket].lock);
    CacheNode *cur = cache->buckets[bucket].head;
    CacheNode *found = NULL;
    
    while (cur) {
        if (strcmp(cur->filename, filename) == 0) {
            // Check if entry is stale or expired
            // DISABLED TTL EXPIRATION: Since cache is the primary metadata store in this implementation,
            // we cannot expire entries based on time, otherwise we lose track of files.
            // Only explicit invalidation or LRU eviction (capacity) should remove entries.
            /*
            if (cur->is_stale || (current_time - cur->cached_time) > CACHE_TTL_SECONDS) {
                printf("[CACHE] Entry expired/stale for: %s (age: %ld seconds)\n", 
                       filename, (long)(current_time - cur->cached_time));
                // Don't return expired entries
                pthread_rwlock_unlock(&cache->buckets[bucket].lock);
                return NULL;
            }
            */
            found = cur;
            break;
        }
        cur = cur->bucket_next;
    }
    pthread_rwlock_unlock(&cache->buckets[bucket].lock);
    
    // Update LRU if found and valid
    if (found) {
        pthread_mutex_lock(&cache->lru_lock);
        move_to_front(cache, found);
        pthread_mutex_unlock(&cache->lru_lock);
    }
    
    return found;
}

/* Insert file into cache */
int cache_put(LRUCache *cache, const char *filename, const char *owner, int ss_id, int *replica_ids,
              int words, int chars, const char *last_modified, const char *access_list) {
    unsigned int bucket = hash_filename(filename);
    
    // Check if already exists
    CacheNode *existing = cache_get(cache, filename);
    if (existing) {
        // Update all fields and refresh timestamp
        strncpy(existing->owner, owner, sizeof(existing->owner) - 1);
        existing->ss_id = ss_id;
        if (replica_ids) {
            for(int i=0; i<MAX_REPLICAS; i++) existing->replica_ss_ids[i] = replica_ids[i];
        } else {
            for(int i=0; i<MAX_REPLICAS; i++) existing->replica_ss_ids[i] = -1;
        }
        existing->words = words;
        existing->chars = chars;
        strncpy(existing->last_modified, last_modified, sizeof(existing->last_modified) - 1);
        strncpy(existing->access_list, access_list, sizeof(existing->access_list) - 1);
        existing->cached_time = time(NULL);  // Refresh TTL
        existing->is_stale = 0;  // Mark as fresh
        printf("[CACHE] Updated: %s\n", filename);
        return 0;
    }
    
    // Evict if at capacity
    pthread_mutex_lock(&cache->lru_lock);
    if (cache->current_size >= cache->capacity) {
        pthread_mutex_unlock(&cache->lru_lock);
        evict_lru(cache);
        pthread_mutex_lock(&cache->lru_lock);
    }
    pthread_mutex_unlock(&cache->lru_lock);
    
    // Create new node
    CacheNode *node = malloc(sizeof(CacheNode));
    strncpy(node->filename, filename, sizeof(node->filename) - 1);
    strncpy(node->owner, owner, sizeof(node->owner) - 1);
    node->ss_id = ss_id;
    if (replica_ids) {
        for(int i=0; i<MAX_REPLICAS; i++) node->replica_ss_ids[i] = replica_ids[i];
    } else {
        for(int i=0; i<MAX_REPLICAS; i++) node->replica_ss_ids[i] = -1;
    }
    node->words = words;
    node->chars = chars;
    strncpy(node->last_modified, last_modified, sizeof(node->last_modified) - 1);
    strncpy(node->access_list, access_list, sizeof(node->access_list) - 1);
    node->bucket_idx = bucket;
    node->prev = NULL;
    node->next = NULL;
    node->bucket_next = NULL;
    node->cached_time = time(NULL);
    node->is_stale = 0;
    
    // Insert into hash bucket (write lock)
    pthread_rwlock_wrlock(&cache->buckets[bucket].lock);
    node->bucket_next = cache->buckets[bucket].head;
    cache->buckets[bucket].head = node;
    pthread_rwlock_unlock(&cache->buckets[bucket].lock);
    
    // Add to front of LRU list
    pthread_mutex_lock(&cache->lru_lock);
    node->prev = NULL;
    node->next = cache->lru_head;
    if (cache->lru_head) cache->lru_head->prev = node;
    cache->lru_head = node;
    if (!cache->lru_tail) cache->lru_tail = node;
    cache->current_size++;
    pthread_mutex_unlock(&cache->lru_lock);
    
    printf("[CACHE] Added: %s (%s) on SS#%d [%zu/%zu]\n", 
           filename, owner, ss_id, cache->current_size, cache->capacity);
    return 0;
}

/* Remove file from cache */
int cache_remove(LRUCache *cache, const char *filename) {
    unsigned int bucket = hash_filename(filename);
    
    pthread_rwlock_wrlock(&cache->buckets[bucket].lock);
    CacheNode **pp = &cache->buckets[bucket].head;
    CacheNode *found = NULL;
    
    while (*pp) {
        if (strcmp((*pp)->filename, filename) == 0) {
            found = *pp;
            *pp = found->bucket_next;
            break;
        }
        pp = &(*pp)->bucket_next;
    }
    pthread_rwlock_unlock(&cache->buckets[bucket].lock);
    
    if (found) {
        pthread_mutex_lock(&cache->lru_lock);
        remove_from_lru(cache, found);
        cache->current_size--;
        pthread_mutex_unlock(&cache->lru_lock);
        free(found);
        printf("[CACHE] Removed: %s\n", filename);
        return 0;
    }
    return -1;
}

/* Iterate over all cached entries */
void cache_foreach(LRUCache *cache,
                   void (*callback)(const char*, const char*, void*),
                   void *userdata) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        pthread_rwlock_rdlock(&cache->buckets[i].lock);
        CacheNode *cur = cache->buckets[i].head;
        while (cur) {
            callback(cur->filename, cur->owner, userdata);
            cur = cur->bucket_next;
        }
        pthread_rwlock_unlock(&cache->buckets[i].lock);
    }
}

/* Mark a cache entry as stale (to be refreshed on next access) */
void cache_invalidate(LRUCache *cache, const char *filename) {
    unsigned int bucket = hash_filename(filename);
    
    pthread_rwlock_wrlock(&cache->buckets[bucket].lock);
    CacheNode *cur = cache->buckets[bucket].head;
    
    while (cur) {
        if (strcmp(cur->filename, filename) == 0) {
            cur->is_stale = 1;
            printf("[CACHE] Invalidated: %s (marked stale)\n", filename);
            pthread_rwlock_unlock(&cache->buckets[bucket].lock);
            return;
        }
        cur = cur->bucket_next;
    }
    pthread_rwlock_unlock(&cache->buckets[bucket].lock);
}

/* Remove all stale/expired entries from cache */
void cache_cleanup_stale(LRUCache *cache) {
    time_t current_time = time(NULL);
    int cleaned = 0;
    
    for (int i = 0; i < TABLE_SIZE; i++) {
        pthread_rwlock_wrlock(&cache->buckets[i].lock);
        CacheNode **pp = &cache->buckets[i].head;
        
        while (*pp) {
            CacheNode *cur = *pp;
            int should_remove = 0;
            
            // Check if expired or marked stale
            if (cur->is_stale || (current_time - cur->cached_time) > CACHE_TTL_SECONDS) {
                should_remove = 1;
            }
            
            if (should_remove) {
                *pp = cur->bucket_next;  // Unlink from bucket
                
                // Remove from LRU list
                pthread_mutex_lock(&cache->lru_lock);
                remove_from_lru(cache, cur);
                cache->current_size--;
                pthread_mutex_unlock(&cache->lru_lock);
                
                free(cur);
                cleaned++;
            } else {
                pp = &(*pp)->bucket_next;
            }
        }
        pthread_rwlock_unlock(&cache->buckets[i].lock);
    }
    
    if (cleaned > 0) {
        printf("[CACHE] Cleanup: removed %d stale/expired entries\n", cleaned);
    }
}

/* Invalidate all cache entries from a specific storage server */
void cache_invalidate_by_ss(LRUCache *cache, int ss_id, void *trie_ptr) {
    int removed = 0;
    int promoted = 0;
    char removed_files[100][64];  // Track removed filenames for trie cleanup
    int file_count = 0;
    Trie *trie = (Trie*)trie_ptr;
    
    for (int i = 0; i < TABLE_SIZE; i++) {
        pthread_rwlock_wrlock(&cache->buckets[i].lock);
        CacheNode **pp = &cache->buckets[i].head;
        
        while (*pp) {
            CacheNode *cur = *pp;
            int should_remove = 0;
            
            if (cur->ss_id == ss_id) {
                // Primary SS failed. Check for backups.
                int new_primary = -1;
                
                // Find first valid replica
                if (cur->replica_ss_ids[0] != -1) {
                    new_primary = cur->replica_ss_ids[0];
                    
                    // Shift replicas left
                    for (int k = 0; k < MAX_REPLICAS - 1; k++) {
                        cur->replica_ss_ids[k] = cur->replica_ss_ids[k+1];
                    }
                    cur->replica_ss_ids[MAX_REPLICAS - 1] = -1;
                }
                
                if (new_primary != -1) {
                    printf("[CACHE] Failover: Promoted SS#%d as primary for '%s' (was SS#%d)\n", 
                           new_primary, cur->filename, ss_id);
                    cur->ss_id = new_primary;
                    promoted++;
                } else {
                    // No replicas available. Data lost.
                    should_remove = 1;
                }
            } else {
                // Primary is fine. Check if the failed SS was a replica.
                for (int k = 0; k < MAX_REPLICAS; k++) {
                    if (cur->replica_ss_ids[k] == ss_id) {
                        // Remove this replica and shift
                        for (int j = k; j < MAX_REPLICAS - 1; j++) {
                            cur->replica_ss_ids[j] = cur->replica_ss_ids[j+1];
                        }
                        cur->replica_ss_ids[MAX_REPLICAS - 1] = -1;
                        printf("[CACHE] Removed failed replica SS#%d from '%s'\n", ss_id, cur->filename);
                        break; 
                    }
                }
            }
            
            if (should_remove) {
                // Save filename for trie cleanup
                if (file_count < 100) {
                    strncpy(removed_files[file_count], cur->filename, 63);
                    removed_files[file_count][63] = '\0';
                    file_count++;
                }
                
                *pp = cur->bucket_next;  // Unlink from bucket
                
                // Remove from LRU list
                pthread_mutex_lock(&cache->lru_lock);
                remove_from_lru(cache, cur);
                cache->current_size--;
                pthread_mutex_unlock(&cache->lru_lock);
                
                printf("[CACHE] Removed '%s' (SS#%d inactive, no backups)\n", cur->filename, ss_id);
                free(cur);
                removed++;
            } else {
                pp = &(*pp)->bucket_next;
            }
        }
        pthread_rwlock_unlock(&cache->buckets[i].lock);
    }
    
    // Remove all collected filenames from trie
    if (trie) {
        for (int i = 0; i < file_count; i++) {
            if (trie_delete(trie, removed_files[i]) == 0) {
                printf("[TRIE] Removed '%s' from trie\n", removed_files[i]);
            }
        }
    }
    
    if (removed > 0 || promoted > 0) {
        printf("[CACHE] SS#%d failure handled: %d removed, %d promoted\n", ss_id, removed, promoted);
    }
}

/* Check if file exists on disk and get owner */
int file_exists_on_disk(const char *filename, char *owner_out, size_t owner_size) {
    char meta_path[256];
    snprintf(meta_path, sizeof(meta_path), "ss/files/%s.meta", filename);
    
    FILE *f = fopen(meta_path, "r");
    if (!f) return 0;
    
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "OWNER:", 6) == 0) {
            sscanf(line, "OWNER:%s", owner_out);
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}