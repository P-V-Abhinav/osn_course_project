#include "trie.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Create a new trie node */
TrieNode* create_trie_node() {
    TrieNode *node = (TrieNode*)calloc(1, sizeof(TrieNode));
    if (node) {
        node->is_end_of_word = 0;
        node->data = NULL;
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            node->children[i] = NULL;
        }
    }
    return node;
}

/* Initialize trie */
Trie* trie_init() {
    Trie *trie = (Trie*)malloc(sizeof(Trie));
    if (trie) {
        trie->root = create_trie_node();
        trie->size = 0;
    }
    return trie;
}

/* Insert a word into trie */
int trie_insert(Trie *trie, const char *word, void *data) {
    if (!trie || !trie->root || !word) return -1;
    
    TrieNode *current = trie->root;
    
    for (int i = 0; word[i] != '\0'; i++) {
        int index = (unsigned char)word[i];
        
        if (index < 0 || index >= ALPHABET_SIZE) {
            continue;  /* Skip invalid characters */
        }
        
        if (!current->children[index]) {
            current->children[index] = create_trie_node();
            if (!current->children[index]) {
                return -1;  /* Memory allocation failed */
            }
        }
        current = current->children[index];
    }
    
    /* Mark end of word and store data */
    if (!current->is_end_of_word) {
        trie->size++;
    }
    current->is_end_of_word = 1;
    current->data = data;
    
    return 0;
}

/* Search for exact word in trie */
void* trie_search(Trie *trie, const char *word) {
    if (!trie || !trie->root || !word) return NULL;
    
    TrieNode *current = trie->root;
    
    for (int i = 0; word[i] != '\0'; i++) {
        int index = (unsigned char)word[i];
        
        if (index < 0 || index >= ALPHABET_SIZE) {
            return NULL;
        }
        
        if (!current->children[index]) {
            return NULL;  /* Word not found */
        }
        current = current->children[index];
    }
    
    if (current && current->is_end_of_word) {
        return current->data;
    }
    
    return NULL;
}

/* Helper function for collecting all words with given prefix */
void collect_words_with_prefix(TrieNode *node, char *prefix, int prefix_len,
                                PrefixSearchResult *result) {
    if (!node) return;
    
    if (node->is_end_of_word && result->count < result->capacity) {
        result->results[result->count] = strdup(prefix);
        result->data_ptrs[result->count] = node->data;
        result->count++;
    }
    
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (node->children[i]) {
            prefix[prefix_len] = (char)i;
            prefix[prefix_len + 1] = '\0';
            collect_words_with_prefix(node->children[i], prefix, 
                                     prefix_len + 1, result);
        }
    }
    prefix[prefix_len] = '\0';
}

/* Search for all words with given prefix */
PrefixSearchResult* trie_search_prefix(Trie *trie, const char *prefix, 
                                       int max_results) {
    if (!trie || !trie->root || !prefix) return NULL;
    
    PrefixSearchResult *result = (PrefixSearchResult*)malloc(sizeof(PrefixSearchResult));
    if (!result) return NULL;
    
    result->capacity = max_results > 0 ? max_results : 100;
    result->results = (char**)calloc(result->capacity, sizeof(char*));
    result->data_ptrs = (void**)calloc(result->capacity, sizeof(void*));
    result->count = 0;
    
    if (!result->results || !result->data_ptrs) {
        free(result->results);
        free(result->data_ptrs);
        free(result);
        return NULL;
    }
    
    /* Navigate to end of prefix */
    TrieNode *current = trie->root;
    for (int i = 0; prefix[i] != '\0'; i++) {
        int index = (unsigned char)prefix[i];
        
        if (index < 0 || index >= ALPHABET_SIZE || !current->children[index]) {
            /* Prefix not found */
            return result;
        }
        current = current->children[index];
    }
    
    /* Collect all words from this point */
    char temp_prefix[256];
    strncpy(temp_prefix, prefix, sizeof(temp_prefix) - 1);
    temp_prefix[sizeof(temp_prefix) - 1] = '\0';
    int len = strlen(temp_prefix);
    
    collect_words_with_prefix(current, temp_prefix, len, result);
    
    return result;
}

/* Free prefix search result */
void free_prefix_result(PrefixSearchResult *result) {
    if (!result) return;
    
    for (int i = 0; i < result->count; i++) {
        free(result->results[i]);
    }
    free(result->results);
    free(result->data_ptrs);
    free(result);
}

/* Delete a word from trie */
int trie_delete_helper(TrieNode *node, const char *word, int depth) {
    if (!node) return 0;
    
    /* Base case: reached end of word */
    if (word[depth] == '\0') {
        if (node->is_end_of_word) {
            node->is_end_of_word = 0;
            node->data = NULL;
            
            /* Check if node has any children */
            for (int i = 0; i < ALPHABET_SIZE; i++) {
                if (node->children[i]) {
                    return 0;  /* Node has children, don't delete */
                }
            }
            return 1;  /* No children, can be deleted */
        }
        return 0;
    }
    
    int index = (unsigned char)word[depth];
    if (index < 0 || index >= ALPHABET_SIZE) return 0;
    
    if (trie_delete_helper(node->children[index], word, depth + 1)) {
        /* Child returned 1, delete it */
        free(node->children[index]);
        node->children[index] = NULL;
        
        /* Check if current node can also be deleted */
        if (!node->is_end_of_word) {
            for (int i = 0; i < ALPHABET_SIZE; i++) {
                if (node->children[i]) {
                    return 0;
                }
            }
            return 1;
        }
    }
    return 0;
}

int trie_delete(Trie *trie, const char *word) {
    if (!trie || !trie->root || !word) return -1;
    
    if (trie_search(trie, word)) {
        trie_delete_helper(trie->root, word, 0);
        trie->size--;
        return 0;
    }
    return -1;  /* Word not found */
}

/* Destroy trie node recursively */
void destroy_trie_node(TrieNode *node) {
    if (!node) return;
    
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (node->children[i]) {
            destroy_trie_node(node->children[i]);
        }
    }
    free(node);
}

/* Destroy trie */
void trie_destroy(Trie *trie) {
    if (!trie) return;
    
    destroy_trie_node(trie->root);
    free(trie);
}

/* Get trie size */
int trie_size(Trie *trie) {
    return trie ? trie->size : 0;
}
