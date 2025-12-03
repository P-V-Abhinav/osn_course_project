#ifndef TRIE_H
#define TRIE_H

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 128  /* Support ASCII characters */

/* Trie Node Structure */
typedef struct TrieNode {
    struct TrieNode *children[ALPHABET_SIZE];
    int is_end_of_word;
    void *data;  /* Pointer to associated data (e.g., CacheNode) */
} TrieNode;

/* Trie Structure */
typedef struct Trie {
    TrieNode *root;
    int size;  /* Number of words in trie */
} Trie;

/* Search with prefix */
typedef struct {
    char **results;
    void **data_ptrs;
    int count;
    int capacity;
} PrefixSearchResult;

/* Function declarations */
TrieNode* create_trie_node(void);
Trie* trie_init(void);
int trie_insert(Trie *trie, const char *word, void *data);
void* trie_search(Trie *trie, const char *word);
void collect_words_with_prefix(TrieNode *node, char *prefix, int prefix_len,
                                PrefixSearchResult *result);
PrefixSearchResult* trie_search_prefix(Trie *trie, const char *prefix, 
                                       int max_results);
void free_prefix_result(PrefixSearchResult *result);
int trie_delete_helper(TrieNode *node, const char *word, int depth);
int trie_delete(Trie *trie, const char *word);
void destroy_trie_node(TrieNode *node);
void trie_destroy(Trie *trie);
int trie_size(Trie *trie);

#endif /* TRIE_H */
