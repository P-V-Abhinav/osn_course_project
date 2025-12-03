#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#define _XOPEN_SOURCE 700

#include <pthread.h>
#include <stddef.h>

#define CACHE_CAPACITY 100  // Max files in cache
#define TABLE_SIZE 211      // Hash table size (prime number)
#define CACHE_TTL_SECONDS 300  // 5 minutes TTL for cache entries
#define MAX_REPLICAS 2

/* Double-linked list node for LRU tracking */
typedef struct CacheNode {
    char filename[64];
    char owner[64];
    int ss_id;  // Which storage server has this file (0-based index)
    int replica_ss_ids[MAX_REPLICAS]; // Backup SSs
    
    // Metadata for INFO operations (served directly from NS)
    int words;
    int chars;
    char last_modified[64];
    char access_list[512];  // Comma-separated "user:R,user:W,..." format
    
    // TTL tracking
    time_t cached_time;  // When this entry was cached
    int is_stale;  // Flag for manual invalidation
    
    /* LRU list pointers */
    struct CacheNode *prev;
    struct CacheNode *next;
    /* Hash bucket singly-linked list pointer (separate from LRU list) */
    struct CacheNode *bucket_next;
    int bucket_idx;  // Which hash bucket this belongs to
} CacheNode;

/* Hash table bucket with fine-grained lock */
typedef struct HashBucket {
    CacheNode *head;
    pthread_rwlock_t lock;  // Reader-writer lock for this bucket
} HashBucket;

/* LRU Cache structure */
typedef struct LRUCache {
    HashBucket buckets[TABLE_SIZE];
    CacheNode *lru_head;  // Most recently used
    CacheNode *lru_tail;  // Least recently used
    pthread_mutex_t lru_lock;  // Protects LRU list manipulation
    size_t current_size;
    size_t capacity;
} LRUCache;

/* Cache operations */
LRUCache* cache_init(size_t capacity);
void cache_destroy(LRUCache *cache);

/* Thread-safe cache operations */
CacheNode* cache_get(LRUCache *cache, const char *filename);
int cache_put(LRUCache *cache, const char *filename, const char *owner, int ss_id, int *replica_ids,
              int words, int chars, const char *last_modified, const char *access_list);
int cache_remove(LRUCache *cache, const char *filename);

/* Cache invalidation */
void cache_invalidate(LRUCache *cache, const char *filename);  // Mark entry as stale
void cache_cleanup_stale(LRUCache *cache);  // Remove expired TTL entries
void cache_invalidate_by_ss(LRUCache *cache, int ss_id, void *trie);  // Invalidate all entries for a specific SS

/* Iterate over all cached files (for VIEW operations) */
void cache_foreach(LRUCache *cache, 
                   void (*callback)(const char *filename, const char *owner, void *userdata),
                   void *userdata);

/* Check if file exists on disk (used when cache miss occurs) */
int file_exists_on_disk(const char *filename, char *owner_out, size_t owner_size);

#endif