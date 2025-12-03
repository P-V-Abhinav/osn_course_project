CC = gcc
CFLAGS = -Wall -pthread

# Directories
COMMON_DIR = common
NS_DIR = ns
SS_DIR = ss
CLIENT_DIR = client

# Object files
COMMON_OBJS = $(COMMON_DIR)/protocol.o

# LRU cache and trie now live inside the NS directory
LRU_OBJS = $(NS_DIR)/lru_cache.o
TRIE_OBJS = $(NS_DIR)/trie.o

# NS objects include trie
NS_OBJS = $(NS_DIR)/ns_main.o $(COMMON_OBJS) $(LRU_OBJS) $(TRIE_OBJS)

# SS and Client use the LRU cache too (for consistency) - they also need trie since lru_cache uses it
SS_OBJS = $(SS_DIR)/ss_main.o $(COMMON_OBJS) $(LRU_OBJS) $(TRIE_OBJS)
CLIENT_OBJS = $(CLIENT_DIR)/client_main.o $(COMMON_OBJS) $(LRU_OBJS) $(TRIE_OBJS)

# Targets
all: name_server storage_server client_app

name_server: $(NS_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

storage_server: $(SS_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

client_app: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f name_server storage_server client_app $(COMMON_DIR)/*.o $(NS_DIR)/*.o $(SS_DIR)/*.o $(CLIENT_DIR)/*.o
	rm -rf logs/
	rm -f ss/files/*.backup
	rm -f /tmp/exec_*