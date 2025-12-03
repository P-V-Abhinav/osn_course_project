#include "../common/protocol.h"
#include "../common/error_codes.h"
#include "../common/logging.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NS_PORT 8080

/* Global configuration - set at runtime */
char NS_IP[64] = "127.0.0.1";  // Can be overridden by environment variable or command-line

static int register_client_with_ns(const char *username) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("Failed to create socket for client registration");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NS_PORT);
    inet_pton(AF_INET, NS_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to connect to Name Server for registration");
        close(sock);
        return -1;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:REGISTER_CLIENT\nUSER:%s\n\n", username);
    if (send_message(sock, msg) != 0) {
        LOG_ERROR("Failed to send client registration message");
        close(sock);
        return -1;
    }

    char buf[512];
    if (recv_message(sock, buf, sizeof(buf)) == 0) {
        if (strstr(buf, "STATUS:OK")) {
            LOG_INFO("Client '%s' registered with NS", username);
            close(sock);
            return 0;
        } else if (strstr(buf, "STATUS:ERROR")) {
            // Extract error message
            char *msg_ptr = strstr(buf, "MSG:");
            if (msg_ptr) {
                msg_ptr += 4;
                char *end = strchr(msg_ptr, '\n');
                if (end) *end = '\0';
                printf("\nError: %s\n", msg_ptr);
                LOG_ERROR("Registration failed: %s", msg_ptr);
            } else {
                printf("\nError: User already logged in\n");
            }
            close(sock);
            return -1;
        }
    }

    LOG_WARN("Name Server did not acknowledge client registration");
    close(sock);
    return -1;
}

static void logout_client_from_ns(const char *username) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NS_PORT);
    inet_pton(AF_INET, NS_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:LOGOUT\nUSER:%s\n\n", username);
    send_message(sock, msg);
    
    char buf[256];
    recv_message(sock, buf, sizeof(buf));
    close(sock);
    
    LOG_INFO("Client '%s' logged out", username);
}

// Parse and display VIEW response
void display_view_response(const char *response, int show_long) {
    if (strstr(response, "STATUS:ERROR")) {
        char *msg = strstr(response, "MSG:");
        if (msg) {
            msg += 4;
            char *end = strchr(msg, '\n');
            if (end) *end = '\0';
            printf("Error: %s\n", msg);
        }
        return;
    }

    char *msg = strstr(response, "MSG:");
    if (!msg) return;
    msg += 4;
    while (*msg == '\n') msg++;
    
    if (show_long) {
        printf("---------------------------------------------------------\n");
        printf("|  Filename  | Words | Chars | Last Access Time | Owner |\n");
        printf("|------------|-------|-------|------------------|-------|\n");
        
        char line[512];
        char *ptr = msg;
        while (*ptr) {
            char *line_end = strchr(ptr, '\n');
            if (!line_end) break;
            
            int len = line_end - ptr;
            if (len > 0) {
                strncpy(line, ptr, len);
                line[len] = '\0';
                
                char fname[64], owner[64], lastaccess[64];
                int words = 0, chars = 0;
                
                if (sscanf(line, "%63[^|]|%d|%d|%63[^|]|%63s", 
                          fname, &words, &chars, lastaccess, owner) == 5) {
                    printf("| %-10s | %5d | %5d | %16s | %-5s |\n",
                           fname, words, chars, lastaccess, owner);
                }
            }
            ptr = line_end + 1;
        }
        printf("---------------------------------------------------------\n");
    } else {
        char line[128];
        char *ptr = msg;
        while (*ptr) {
            char *line_end = strchr(ptr, '\n');
            if (!line_end) break;
            
            int len = line_end - ptr;
            if (len > 0) {
                strncpy(line, ptr, len);
                line[len] = '\0';
                
                char *pipe = strchr(line, '|');
                if (pipe) *pipe = '\0';
                
                if (strlen(line) > 0) {
                    printf("--> %s\n", line);
                }
            }
            ptr = line_end + 1;
        }
    }
}

int main(int argc, char *argv[]) {
    // Parse command line arguments: ./client_app [ns_ip]
    if (argc >= 2) {
        strncpy(NS_IP, argv[1], sizeof(NS_IP) - 1);
        NS_IP[sizeof(NS_IP) - 1] = '\0';
        printf("[CLIENT] Using NS IP from command-line: %s\n", NS_IP);
    } else {
        // Check for NS IP from environment variable
        char *env_ns_ip = getenv("NS_IP");
        if (env_ns_ip != NULL) {
            strncpy(NS_IP, env_ns_ip, sizeof(NS_IP) - 1);
            NS_IP[sizeof(NS_IP) - 1] = '\0';
            printf("[CLIENT] Using NS IP from environment: %s\n", NS_IP);
        }
    }
    
    printf("[CLIENT] Will connect to Name Server at %s:%d\n", NS_IP, NS_PORT);
    
    // Initialize logging
    if (init_logging(COMP_CLIENT, "logs") != 0) {
        printf("Warning: Failed to initialize logging\n");
    }
    
    char username[64];
    printf("Enter username: ");
    if (!fgets(username, sizeof(username), stdin)) return 1;
    username[strcspn(username, "\n")] = 0;
    
    LOG_INFO("Client started for user %s", username);
    
    // Try to register - exit if already logged in
    if (register_client_with_ns(username) != 0) {
        printf("\nCannot start client. Exiting...\n");
        LOG_ERROR("Client registration failed for %s", username);
        close_logging();
        return 1;
    }
    
    printf("\nWelcome, %s! You are now logged in.\n", username);

    while (1) {
        printf("\nCommands: VIEW [-a|-l|-al] | CREATE <file> | READ <file> | WRITE <file> <sentence#> | DELETE <file> | LIST | INFO <file> | ADDACCESS -R/-W <file> <user> | REMACCESS <file> <user> | UNDO <file> | CHECKPOINT <file> <tag> | VIEWCHECKPOINT <file> <tag> | REVERT <file> <tag> | LISTCHECKPOINTS <file> | REQUESTACCESS -R/-W <file> | VIEWREQUESTS | APPROVEREQUEST <id> | DENYREQUEST <id> | CREATEFOLDER <folder> | VIEWFOLDER <folder> | MOVE <file> <folder> | EXEC <file> | STREAM <file> | EXIT\n> ");

        char line[256];
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = 0;

        char cmd[32], arg1[256], arg2[256], arg3[64];
        int parts = sscanf(line, "%31s %255s %255s %63s", cmd, arg1, arg2, arg3);

        if (parts <= 0) continue;

        if (strcasecmp(cmd, "EXIT") == 0) {
            logout_client_from_ns(username);
            break;
        }

        // For WRITE command, handle separately with dedicated socket
        else if (strcasecmp(cmd, "WRITE") == 0 && parts >= 3) {
            int sentence_num = atoi(arg2);
            
            // Step 1: Get SS info from NS
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            // Send WRITE_START request to NS to get SS info
            char msg[256];
            snprintf(msg, sizeof(msg),
                    "TYPE:REQ\nOP:WRITE_START\nUSER:%s\nFILENAME:%s\nSENTENCE:%d\n\n", 
                    username, arg1, sentence_num);
            
            if (send_message(sock, msg) != 0) {
                printf("Failed to send request to NS\n");
                close(sock);
                continue;
            }
            
            // Receive SS info from NS
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) != 0) {
                printf("Failed to receive SS info from NS\n");
                close(sock);
                continue;
            }
            
            if (strstr(buf, "STATUS:ERROR")) {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                }
                close(sock);
                continue;
            }
            
            // Step 2: Parse SS info
            char ss_ip[64];
            int ss_client_port = 0;
            int ss_ctrl_port = 0;
            char *msg_ptr = strstr(buf, "MSG:");
            int parsed = 0;
            if (msg_ptr) {
                parsed = sscanf(msg_ptr, "MSG:IP=%63[^,],CLIENT_PORT=%d,CTRL_PORT=%d",
                                ss_ip, &ss_client_port, &ss_ctrl_port);
                if (parsed < 3) {
                    parsed = sscanf(msg_ptr, "MSG:IP=%63[^,],CLIENT_PORT=%d",
                                    ss_ip, &ss_client_port);
                }
            }
            if (parsed < 2) {
                printf("Error parsing SS info\n");
                close(sock);
                continue;
            }

            int ss_port = ss_ctrl_port > 0 ? ss_ctrl_port : ss_client_port;
            
            close(sock);  // Close NS connection
            
            // Step 3: Connect directly to SS client port for file operations
            int ss_sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in ss_addr = {0};
            ss_addr.sin_family = AF_INET;
            ss_addr.sin_port = htons(ss_port);
            inet_pton(AF_INET, ss_ip, &ss_addr.sin_addr);
            
            if (connect(ss_sock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
                printf("Failed to connect to Storage Server\n");
                close(ss_sock);
                continue;
            }
            
            // Step 3: Send WRITE_START directly to SS
            snprintf(msg, sizeof(msg),
                    "TYPE:REQ\nOP:WRITE_START\nUSER:%s\nFILENAME:%s\nSENTENCE:%d\n\n", 
                    username, arg1, sentence_num);
            
            if (send_message(ss_sock, msg) != 0) {
                printf("Failed to send write request to SS\n");
                close(ss_sock);
                continue;
            }
            
            // Receive lock response from SS
            if (recv_message(ss_sock, buf, sizeof(buf)) != 0) {
                printf("Failed to receive lock response from SS\n");
                close(ss_sock);
                continue;
            }
            
            if (strstr(buf, "STATUS:ERROR")) {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                }
                close(ss_sock);
                continue;
            }
            
            // Sentence locked successfully
            printf("Sentence locked. Enter word updates (format: <word_index> <content>), type ETIRW to finish:\n");

            /* Close the WRITE_START socket */
            close(ss_sock);

            char updates[4096] = "";
            int update_count = 0;
            while (1) {
                char update_line[512];
                printf("> ");
                if (!fgets(update_line, sizeof(update_line), stdin)) {
                    /* Treat EOF (Ctrl-D) as end of write-mode, but clear EOF so shell keeps running */
                    clearerr(stdin);
                    break;
                }

                /* Remove newline */
                update_line[strcspn(update_line, "\n")] = 0;

                /* Check for end command */
                if (strcasecmp(update_line, "ETIRW") == 0) {
                    break;
                }

                /* Validate simple format: must start with a number (word index) */
                int tmp_idx = -1;
                if (sscanf(update_line, "%d", &tmp_idx) != 1) {
                    printf("Invalid format. Use: <word_index> <content>\n");
                    continue;
                }

                /* Append update safely */
                size_t cur_len = strlen(updates);
                size_t add_len = strlen(update_line) + 1; /* +1 for '\n' */
                if (cur_len + add_len >= sizeof(updates)) {
                    printf("Updates buffer full, cannot add more updates.\n");
                    break;
                }
                strncat(updates, update_line, sizeof(updates) - cur_len - 1);
                strncat(updates, "\n", sizeof(updates) - strlen(updates) - 1);
                update_count++;
            }
            
            /* Step 4: Connect to SS again for WRITE_COMMIT */
            int wsock = socket(AF_INET, SOCK_STREAM, 0);
            ss_addr.sin_port = htons(ss_port);
            inet_pton(AF_INET, ss_ip, &ss_addr.sin_addr);
            
            if (connect(wsock, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
                perror("connect (WRITE_COMMIT to SS) failed");
                close(wsock);
                continue;
            }

            /* Send all updates directly to SS */
            char write_msg[8192];
            snprintf(write_msg, sizeof(write_msg),
                    "TYPE:REQ\nOP:WRITE_COMMIT\nUSER:%s\nFILENAME:%s\nSENTENCE:%d\nUPDATES:\n%s\n\n",
                    username, arg1, sentence_num, updates);

            printf("Submitting %d updates...\n", update_count);
            printf("Sending write commit...\n");
            fflush(stdout);

            if (send_message(wsock, write_msg) != 0) {
                perror("send_message (WRITE_COMMIT) failed");
                close(wsock);
                continue;
            }

            /* Get final response from SS */
            if (recv_message(wsock, buf, sizeof(buf)) != 0) {
                fprintf(stderr, "recv_message failed after WRITE_COMMIT\n");
                close(wsock);
                continue;
            }
            if (strstr(buf, "STATUS:OK")) {
                printf("Write successful!\n");
            } else if (strstr(buf, "STATUS:ERROR")) {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                }
            }

            close(wsock);
            continue;
        }

        // All other commands use regular socket pattern
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(NS_PORT);
        inet_pton(AF_INET, NS_IP, &addr.sin_addr);
        
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("Failed to connect to server\n");
            close(sock);
            continue;
        }

        else if (strcasecmp(cmd, "VIEWREQUESTS") == 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:VIEWREQUESTS\nUSER:%s\n\n", username);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    char *content = strstr(buf, "MSG:");
                    if (content) {
                        content += 4;
                        while (*content == '\n') content++;
                        printf("%s", content);
                    }
                } else {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "VIEW") == 0) {
            char msg[256];
            char flags[16] = "none";
            int show_long = 0;
            
            if (parts >= 2) {
                strncpy(flags, arg1, sizeof(flags) - 1);
                if (strstr(flags, "l")) show_long = 1;
            }
            
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:VIEW\nUSER:%s\nFLAGS:%s\n\n", username, flags);
            send_message(sock, msg);
            
            char buf[8192];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                display_view_response(buf, show_long);
            }
        }

        else if (strcasecmp(cmd, "CREATE") == 0 && parts >= 2) {
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:CREATE\nUSER:%s\nFILENAME:%s\n\n", username, arg1);
            send_message(sock, msg);
            
            char buf[1024];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    printf("File created successfully\n");
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "DELETE") == 0 && parts >= 2) {
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:DELETE\nUSER:%s\nFILENAME:%s\n\n", username, arg1);
            send_message(sock, msg);
            
            char buf[1024];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    printf("File deleted successfully\n");
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "READ") == 0 && parts >= 2) {
            // Step 1: Ask NS for SS info
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:READ\nUSER:%s\nFILENAME:%s\n\n", username, arg1);
            send_message(sock, msg);
            
            char buf[8192];
            if (recv_message(sock, buf, sizeof(buf)) != 0) {
                printf("Failed to get SS info from Name Server\n");
                close(sock);
                continue;
            }
            
            if (strstr(buf, "STATUS:ERROR")) {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                }
                close(sock);
                continue;
            }
            
            // Step 2: Parse SS IP and port
            char ss_ip[64];
            int ss_client_port = 0;
            int ss_ctrl_port = 0;
            char *msg_ptr = strstr(buf, "MSG:");
            int parsed = 0;
            if (msg_ptr) {
                parsed = sscanf(msg_ptr, "MSG:IP=%63[^,],CLIENT_PORT=%d,CTRL_PORT=%d",
                                ss_ip, &ss_client_port, &ss_ctrl_port);
                if (parsed < 3) {
                    parsed = sscanf(msg_ptr, "MSG:IP=%63[^,],CLIENT_PORT=%d",
                                    ss_ip, &ss_client_port);
                }
            }
            if (parsed < 2) {
                printf("Error parsing SS info\n");
                close(sock);
                continue;
            }

            int ss_port = ss_ctrl_port > 0 ? ss_ctrl_port : ss_client_port;
            
            close(sock);  // Close NS connection
            
            // Step 3: Connect directly to SS client port for file operations
            int ssock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in saddr = {0};
            saddr.sin_family = AF_INET;
            saddr.sin_port = htons(ss_port);
            inet_pton(AF_INET, ss_ip, &saddr.sin_addr);

            if (connect(ssock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
                printf("Failed to connect to storage server\n");
                close(ssock);
                continue;
            }

            // Step 4: Send READ request directly to SS
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:READ\nUSER:%s\nFILENAME:%s\n\n", username, arg1);
            send_message(ssock, msg);
            
            if (recv_message(ssock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    char *content = strstr(buf, "MSG:");
                    if (content) {
                        content += 4;
                        while (*content == '\n') content++;
                        printf("%s", content);
                        if (strlen(content) > 0 && content[strlen(content)-1] != '\n') {
                            printf("\n");
                        }
                    }
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                    }
                }
            }
            close(ssock);
        }

        else if (strcasecmp(cmd, "LIST") == 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:LIST\nUSER:%s\n\n", username);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    char *users = strstr(buf, "MSG:");
                    if (users) {
                        users += 4;
                        while (*users == '\n') users++;
                        
                        char line[128];
                        char *ptr = users;
                        while (*ptr) {
                            char *line_end = strchr(ptr, '\n');
                            if (!line_end) break;
                            
                            int len = line_end - ptr;
                            if (len > 0) {
                                strncpy(line, ptr, len);
                                line[len] = '\0';
                                printf("--> %s\n", line);
                            }
                            ptr = line_end + 1;
                        }
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "INFO") == 0 && parts >= 2) {
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:INFO\nUSER:%s\nFILENAME:%s\n\n", username, arg1);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    char *info = strstr(buf, "MSG:");
                    if (info) {
                        info += 4;
                        while (*info == '\n') info++;
                        printf("%s", info);
                    }
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "ADDACCESS") == 0 && parts >= 4) {
            char flag = arg1[1];
            char msg[256];
            snprintf(msg, sizeof(msg),
                    "TYPE:REQ\nOP:ADDACCESS\nUSER:%s\nFILENAME:%s\nTARGET_USER:%s\nACCESS_TYPE:%c\n\n", 
                    username, arg2, arg3, flag);
            send_message(sock, msg);
            
            char buf[1024];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    printf("Access granted successfully\n");
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "REMACCESS") == 0 && parts >= 3) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                    "TYPE:REQ\nOP:REMACCESS\nUSER:%s\nFILENAME:%s\nTARGET_USER:%s\n\n", 
                    username, arg1, arg2);
            send_message(sock, msg);
            
            char buf[1024];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    printf("Access removed successfully\n");
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "UNDO") == 0 && parts >= 2) {
            LOG_INFO("Sending UNDO request for %s", arg1);
            log_request("NS", "UNDO", arg1, username);
            
            // Get SS info from NS
            char get_ss_msg[256];
            snprintf(get_ss_msg, sizeof(get_ss_msg), "TYPE:REQ\nOP:GET_SS_INFO\nFILENAME:%s\n\n", arg1);
            send_message(sock, get_ss_msg);
            
            char buf[512];
            if (recv_message(sock, buf, sizeof(buf)) != 0) {
                printf("Failed to get SS info from Name Server\n");
                LOG_ERROR("Failed to get SS info for UNDO");
                close(sock);
                continue;
            }
            
            if (strstr(buf, "STATUS:ERROR")) {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                    LOG_WARN("UNDO error: %s", msg_line);
                }
                close(sock);
                continue;
            }
            
            // Parse SS info
            char ss_ip[64];
            int ss_ctrl_port;
            if (sscanf(strstr(buf, "MSG:"), "MSG:IP=%63[^,],CLIENT_PORT=%*d,CTRL_PORT=%d",
                       ss_ip, &ss_ctrl_port) < 2) {
                printf("Error parsing SS info\n");
                close(sock);
                continue;
            }
            
            close(sock);  // Close NS connection
            
            // Connect to SS control port
            int ssock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in saddr = {0};
            saddr.sin_family = AF_INET;
            saddr.sin_port = htons(ss_ctrl_port);
            inet_pton(AF_INET, ss_ip, &saddr.sin_addr);
            
            if (connect(ssock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
                printf("Failed to connect to storage server\n");
                LOG_ERROR("Failed to connect to SS for UNDO");
                close(ssock);
                continue;
            }
            
            // Send UNDO request to SS
            char undo_msg[256];
            snprintf(undo_msg, sizeof(undo_msg), "TYPE:REQ\nOP:UNDO\nUSER:%s\nFILENAME:%s\n\n", username, arg1);
            send_message(ssock, undo_msg);
            
            if (recv_message(ssock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    printf("Undo successful!\n");
                    LOG_INFO("UNDO successful for %s", arg1);
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                        LOG_WARN("UNDO error: %s", msg_line);
                    }
                }
            }
            close(ssock);
        }

        // --- CHECKPOINT ---
        else if (strcasecmp(cmd, "CHECKPOINT") == 0 && parts >= 3) {
            // CHECKPOINT <filename> <tag>
            // Tag is already in arg2
            
            // Get SS info
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:GET_SS_INFO\nFILENAME:%s\n\n", arg1);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) != 0 || !strstr(buf, "STATUS:OK")) {
                printf("Error: File not found or unavailable\n");
                close(sock);
                continue;
            }
            close(sock);
            
            char ss_ip[64];
            int ss_ctrl_port;
            sscanf(strstr(buf, "IP="), "IP=%63[^,]", ss_ip);
            sscanf(strstr(buf, "CTRL_PORT="), "CTRL_PORT=%d", &ss_ctrl_port);
            
            // Connect to SS
            int ssock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in ss_addr;
            ss_addr.sin_family = AF_INET;
            ss_addr.sin_port = htons(ss_ctrl_port);
            inet_pton(AF_INET, ss_ip, &ss_addr.sin_addr);
            
            if (connect(ssock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
                printf("Error: Cannot connect to storage server\n");
                close(ssock);
                continue;
            }
            
            char checkpoint_msg[512];
            snprintf(checkpoint_msg, sizeof(checkpoint_msg), 
                    "TYPE:REQ\nOP:CHECKPOINT\nUSER:%s\nFILENAME:%s\nTAG:%s\n\n", 
                    username, arg1, arg2);
            send_message(ssock, checkpoint_msg);
            
            if (recv_message(ssock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                printf("Checkpoint '%s' created successfully!\n", arg2);
            } else {
                printf("Error: Failed to create checkpoint\n");
            }
            close(ssock);
        }

        // --- VIEWCHECKPOINT ---
        else if (strcasecmp(cmd, "VIEWCHECKPOINT") == 0 && parts >= 3) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:GET_SS_INFO\nFILENAME:%s\n\n", arg1);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) != 0 || !strstr(buf, "STATUS:OK")) {
                printf("Error: File not found\n");
                close(sock);
                continue;
            }
            close(sock);
            
            char ss_ip[64];
            int ss_ctrl_port;
            sscanf(strstr(buf, "IP="), "IP=%63[^,]", ss_ip);
            sscanf(strstr(buf, "CTRL_PORT="), "CTRL_PORT=%d", &ss_ctrl_port);
            
            int ssock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in ss_addr;
            ss_addr.sin_family = AF_INET;
            ss_addr.sin_port = htons(ss_ctrl_port);
            inet_pton(AF_INET, ss_ip, &ss_addr.sin_addr);
            
            if (connect(ssock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
                printf("Error: Cannot connect to storage server\n");
                close(ssock);
                continue;
            }
            
            char view_msg[512];
            snprintf(view_msg, sizeof(view_msg), 
                    "TYPE:REQ\nOP:VIEWCHECKPOINT\nFILENAME:%s\nTAG:%s\n\n", 
                    arg1, arg2);
            send_message(ssock, view_msg);
            
            if (recv_message(ssock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                char *content = strstr(buf, "MSG:\n");
                if (content) {
                    content += 5;
                    printf("%s", content);
                }
            } else {
                printf("Error: Checkpoint not found\n");
            }
            close(ssock);
        }

        // --- REVERT ---
        else if (strcasecmp(cmd, "REVERT") == 0 && parts >= 3) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:GET_SS_INFO\nFILENAME:%s\n\n", arg1);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) != 0 || !strstr(buf, "STATUS:OK")) {
                printf("Error: File not found\n");
                close(sock);
                continue;
            }
            close(sock);
            
            char ss_ip[64];
            int ss_ctrl_port;
            sscanf(strstr(buf, "IP="), "IP=%63[^,]", ss_ip);
            sscanf(strstr(buf, "CTRL_PORT="), "CTRL_PORT=%d", &ss_ctrl_port);
            
            int ssock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in ss_addr;
            ss_addr.sin_family = AF_INET;
            ss_addr.sin_port = htons(ss_ctrl_port);
            inet_pton(AF_INET, ss_ip, &ss_addr.sin_addr);
            
            if (connect(ssock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
                printf("Error: Cannot connect to storage server\n");
                close(ssock);
                continue;
            }
            
            char revert_msg[512];
            snprintf(revert_msg, sizeof(revert_msg), 
                    "TYPE:REQ\nOP:REVERT\nUSER:%s\nFILENAME:%s\nTAG:%s\n\n", 
                    username, arg1, arg2);
            send_message(ssock, revert_msg);
            
            if (recv_message(ssock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                printf("Reverted to checkpoint '%s' successfully!\n", arg2);
            } else {
                printf("Error: Failed to revert to checkpoint\n");
            }
            close(ssock);
        }

        // --- LISTCHECKPOINTS ---
        else if (strcasecmp(cmd, "LISTCHECKPOINTS") == 0 && parts >= 2) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:GET_SS_INFO\nFILENAME:%s\n\n", arg1);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) != 0 || !strstr(buf, "STATUS:OK")) {
                printf("Error: File not found\n");
                close(sock);
                continue;
            }
            close(sock);
            
            char ss_ip[64];
            int ss_ctrl_port;
            sscanf(strstr(buf, "IP="), "IP=%63[^,]", ss_ip);
            sscanf(strstr(buf, "CTRL_PORT="), "CTRL_PORT=%d", &ss_ctrl_port);
            
            int ssock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in ss_addr;
            ss_addr.sin_family = AF_INET;
            ss_addr.sin_port = htons(ss_ctrl_port);
            inet_pton(AF_INET, ss_ip, &ss_addr.sin_addr);
            
            if (connect(ssock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
                printf("Error: Cannot connect to storage server\n");
                close(ssock);
                continue;
            }
            
            char list_msg[256];
            snprintf(list_msg, sizeof(list_msg), 
                    "TYPE:REQ\nOP:LISTCHECKPOINTS\nFILENAME:%s\n\n", arg1);
            send_message(ssock, list_msg);
            
            if (recv_message(ssock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                char *content = strstr(buf, "MSG:\n");
                if (content) {
                    content += 5;
                    if (strlen(content) > 1) {
                        printf("Checkpoints for %s:\n%s", arg1, content);
                    } else {
                        printf("No checkpoints found for %s\n", arg1);
                    }
                }
            } else {
                printf("Error: Cannot list checkpoints\n");
            }
            close(ssock);
        }

        // --- REQUESTACCESS ---
        else if (strcasecmp(cmd, "REQUESTACCESS") == 0 && parts >= 3) {
            // REQUESTACCESS -R/-W <filename>
            char access_type = 'R';
            if (strcasecmp(arg1, "-W") == 0) {
                access_type = 'W';
            }
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), 
                    "TYPE:REQ\nOP:REQUESTACCESS\nUSER:%s\nFILENAME:%s\nACCESS_TYPE:%c\n\n",
                    username, arg2, access_type);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("%s\n", msg_line);
                }
            } else {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                }
            }
            close(sock);
        }

        // --- VIEWREQUESTS ---
        else if (strcasecmp(cmd, "VIEWREQUESTS") == 0) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:VIEWREQUESTS\nUSER:%s\n\n", username);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                char *content = strstr(buf, "MSG:\n");
                if (content) {
                    content += 5;
                    printf("Pending Access Requests:\n%s", content);
                }
            } else {
                printf("Error: Cannot view requests\n");
            }
            close(sock);
        }

        // --- APPROVEREQUEST ---
        else if (strcasecmp(cmd, "APPROVEREQUEST") == 0 && parts >= 2) {
            int request_id = atoi(arg1);
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), 
                    "TYPE:REQ\nOP:APPROVEREQUEST\nUSER:%s\nREQUEST_ID:%d\n\n",
                    username, request_id);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("%s\n", msg_line);
                }
            } else {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                }
            }
            close(sock);
        }

        // --- DENYREQUEST ---
        else if (strcasecmp(cmd, "DENYREQUEST") == 0 && parts >= 2) {
            int request_id = atoi(arg1);
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            char msg[256];
            snprintf(msg, sizeof(msg), 
                    "TYPE:REQ\nOP:DENYREQUEST\nUSER:%s\nREQUEST_ID:%d\n\n",
                    username, request_id);
            send_message(sock, msg);
            
            char buf[4096];
            if (recv_message(sock, buf, sizeof(buf)) == 0 && strstr(buf, "STATUS:OK")) {
                printf("Request denied successfully\n");
            } else {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                }
            }
            close(sock);
        }

        else if (strcasecmp(cmd, "EXEC") == 0 && parts >= 2) {
            char msg[256];
            snprintf(msg, sizeof(msg), "TYPE:REQ\nOP:EXEC\nUSER:%s\nFILENAME:%s\n\n", username, arg1);
            
            LOG_INFO("Sending EXEC request for %s", arg1);
            log_request("NS", "EXEC", arg1, username);
            
            send_message(sock, msg);
            
            char buf[8192];
            if (recv_message(sock, buf, sizeof(buf)) == 0) {
                if (strstr(buf, "STATUS:OK")) {
                    char *output = strstr(buf, "MSG:");
                    if (output) {
                        output += 4;
                        while (*output == '\n') output++;
                        printf("\n=== Execution Output ===\n");
                        printf("%s", output);
                        if (strlen(output) > 0 && output[strlen(output)-1] != '\n') {
                            printf("\n");
                        }
                        printf("========================\n");
                        LOG_INFO("EXEC successful for %s", arg1);
                    }
                } else if (strstr(buf, "STATUS:ERROR")) {
                    char *msg_line = strstr(buf, "MSG:");
                    if (msg_line) {
                        msg_line += 4;
                        char *end = strchr(msg_line, '\n');
                        if (end) *end = '\0';
                        printf("Error: %s\n", msg_line);
                        LOG_WARN("EXEC error: %s", msg_line);
                    }
                }
            }
        }

        else if (strcasecmp(cmd, "STREAM") == 0 && parts >= 2) {
            // --- Enhanced STREAM with retry logic and better error handling ---
            char ss_ip[64] = {0};
            int ss_client_port = 0;
            int retry_count = 0;
            int max_retries = 3;
            int ss_lookup_success = 0;

            // Retry loop for getting SS info
            while (retry_count < max_retries && !ss_lookup_success) {
                retry_count++;
                int nsock = socket(AF_INET, SOCK_STREAM, 0);
                if (nsock < 0) {
                    LOG_ERROR("Failed to create socket for NS");
                    if (retry_count < max_retries) {
                        printf("Retrying... (attempt %d/%d)\n", retry_count, max_retries);
                        usleep(500000); // 0.5s delay before retry
                    }
                    continue;
                }

                struct sockaddr_in nsaddr = {0};
                nsaddr.sin_family = AF_INET;
                nsaddr.sin_port = htons(NS_PORT);
                inet_pton(AF_INET, NS_IP, &nsaddr.sin_addr);

                if (connect(nsock, (struct sockaddr *)&nsaddr, sizeof(nsaddr)) < 0) {
                    LOG_ERROR("Failed to connect to Name Server");
                    close(nsock);
                    if (retry_count < max_retries) {
                        printf("Retrying... (attempt %d/%d)\n", retry_count, max_retries);
                        usleep(500000);
                    }
                    continue;
                }

                // Request SS info
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "TYPE:REQ\nOP:GET_SS_INFO\nUSER:%s\nFILENAME:%s\n\n",
                         username, arg1);
                if (send_message(nsock, msg) != 0) {
                    LOG_ERROR("Failed to send SS info request");
                    close(nsock);
                    if (retry_count < max_retries) {
                        printf("Retrying... (attempt %d/%d)\n", retry_count, max_retries);
                        usleep(500000);
                    }
                    continue;
                }

                char buf[512];
                if (recv_message(nsock, buf, sizeof(buf)) != 0) {
                    LOG_ERROR("Failed to receive SS info");
                    close(nsock);
                    if (retry_count < max_retries) {
                        printf("Retrying... (attempt %d/%d)\n", retry_count, max_retries);
                        usleep(500000);
                    }
                    continue;
                }
                close(nsock);

                if (strstr(buf, "STATUS:ERROR")) {
                    LOG_WARN("NS returned error for STREAM");
                    printf("Error: No storage server info available\n");
                    break; // Don't retry on NS error
                }

                // Parse IP and port from response
                char *msg_ptr = strstr(buf, "MSG:");
                int parsed = 0;
                if (msg_ptr) {
                    parsed = sscanf(msg_ptr, "MSG:IP=%63[^,],CLIENT_PORT=%d,CTRL_PORT=%*d",
                                    ss_ip, &ss_client_port);
                    if (parsed < 2) {
                        parsed = sscanf(msg_ptr, "MSG:IP=%63[^,],CLIENT_PORT=%d",
                                        ss_ip, &ss_client_port);
                    }
                }

                if (parsed < 2) {
                    LOG_ERROR("Failed to parse server info");
                    if (retry_count < max_retries) {
                        printf("Retrying... (attempt %d/%d)\n", retry_count, max_retries);
                        usleep(500000);
                    }
                    continue;
                }

                ss_lookup_success = 1;
            }

            if (!ss_lookup_success) {
                printf("Failed to retrieve storage server info after %d attempts\n", max_retries);
                LOG_ERROR("STREAM operation failed: Could not get SS info");
                continue;
            }

            printf("[Client] Connecting to SS at %s:%d for streaming...\n", ss_ip, ss_client_port);
            LOG_INFO("STREAM: Connecting to SS");

            // --- Connect to SS with retry logic ---
            int ssock = -1;
            retry_count = 0;
            int ss_connect_success = 0;

            while (retry_count < max_retries && !ss_connect_success) {
                retry_count++;
                ssock = socket(AF_INET, SOCK_STREAM, 0);
                if (ssock < 0) {
                    LOG_ERROR("Failed to create socket for SS");
                    if (retry_count < max_retries) {
                        printf("Retrying connection... (attempt %d/%d)\n", retry_count, max_retries);
                        usleep(500000);
                    }
                    continue;
                }

                struct sockaddr_in saddr = {0};
                saddr.sin_family = AF_INET;
                saddr.sin_port = htons(ss_client_port);
                inet_pton(AF_INET, ss_ip, &saddr.sin_addr);

                if (connect(ssock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
                    LOG_ERROR("Failed to connect to storage server");
                    close(ssock);
                    if (retry_count < max_retries) {
                        printf("Retrying connection... (attempt %d/%d)\n", retry_count, max_retries);
                        usleep(500000);
                    }
                    continue;
                }

                ss_connect_success = 1;
            }

            if (!ss_connect_success) {
                printf("Failed to connect to storage server after %d attempts\n", max_retries);
                LOG_ERROR("STREAM operation failed: Could not connect to SS");
                continue;
            }

            // Send STREAM request
            char stream_msg[256];
            snprintf(stream_msg, sizeof(stream_msg),
                     "TYPE:REQ\nOP:STREAM\nUSER:%s\nFILENAME:%s\n\n",
                     username, arg1);
            if (send_message(ssock, stream_msg) != 0) {
                printf("Failed to send STREAM request\n");
                LOG_ERROR("STREAM: Failed to send request to SS");
                close(ssock);
                continue;
            }

            // Receive stream data with timeout awareness
            char content_buf[9000];
            if (recv_message(ssock, content_buf, sizeof(content_buf)) != 0) {
                printf("Failed to receive stream data\n");
                LOG_ERROR("STREAM: Failed to receive data from SS");
                close(ssock);
                continue;
            }
            close(ssock);
            LOG_INFO("STREAM: Successfully received data from SS");

            if (strstr(content_buf, "STATUS:ERROR")) {
                char *msg_line = strstr(content_buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *end = strchr(msg_line, '\n');
                    if (end) *end = '\0';
                    printf("Error: %s\n", msg_line);
                    LOG_WARN("STREAM: SS returned error: %s", msg_line);
                }
                continue;
            }

            // Extract content and display it word-by-word with 0.1s delays
            char *content = strstr(content_buf, "MSG:");
            if (!content) {
                printf("Error: Invalid response format\n");
                LOG_ERROR("STREAM: Invalid response from SS");
                continue;
            }
            content += 4;
            while (*content == '\n') content++;

            // Make a copy of content for strtok (it modifies the string)
            char content_copy[8192];
            strncpy(content_copy, content, sizeof(content_copy) - 1);
            content_copy[sizeof(content_copy) - 1] = '\0';

            printf("\n=== Streaming content of '%s' (word-by-word, 0.1s delay) ===\n", arg1);
            fflush(stdout);
            LOG_INFO("STREAM: Starting word-by-word transmission");

            int word_count = 0;
            char *word = strtok(content_copy, " \n\t\r");
            while (word) {
                printf("%s ", word);
                fflush(stdout);
                word_count++;
                usleep(100000); // 0.1 seconds = 100ms delay between words
                word = strtok(NULL, " \n\t\r");
            }
            printf("\n=== End of stream (transmitted %d words) ===\n", word_count);
            fflush(stdout);
            LOG_INFO("STREAM: Completed - transmitted %d words", word_count);
        }

        // CREATEFOLDER - Create a new folder
        else if (strcasecmp(cmd, "CREATEFOLDER") == 0) {
            if (parts < 2) {
                printf("Usage: CREATEFOLDER <foldername>\n");
                continue;
            }
            
            char msg[512];
            snprintf(msg, sizeof(msg),
                    "TYPE:REQ\nOP:CREATEFOLDER\nFOLDERNAME:%s\nUSER:%s\n\n",
                    arg1, username);
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            send_message(sock, msg);
            
            char buf[1024];
            recv_message(sock, buf, sizeof(buf));
            
            if (strstr(buf, "STATUS:OK")) {
                printf("Folder '%s' created successfully!\n", arg1);
            } else {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *newline = strchr(msg_line, '\n');
                    if (newline) *newline = '\0';
                    printf("Error: %s\n", msg_line);
                }
            }
            
            close(sock);
        }

        // VIEWFOLDER - List contents of a folder
        else if (strcasecmp(cmd, "VIEWFOLDER") == 0) {
            if (parts < 2) {
                printf("Usage: VIEWFOLDER <foldername>\n");
                continue;
            }
            
            char msg[512];
            snprintf(msg, sizeof(msg),
                    "TYPE:REQ\nOP:VIEWFOLDER\nFOLDERNAME:%s\nUSER:%s\n\n",
                    arg1, username);
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            send_message(sock, msg);
            
            char buf[8192];
            recv_message(sock, buf, sizeof(buf));
            
            if (strstr(buf, "STATUS:OK")) {
                char *files = strstr(buf, "FILES:");
                if (files) {
                    files += 6;
                    printf("\n=== Contents of '%s' ===\n", arg1);
                    if (strlen(files) <= 2) {
                        printf("(empty)\n");
                    } else {
                        char *line = strtok(files, "\n");
                        while (line) {
                            char item[128], type[32];
                            if (sscanf(line, "%127[^|]|%31s", item, type) == 2) {
                                if (strcmp(type, "folder") == 0) {
                                    printf("  [DIR]  %s\n", item);
                                } else {
                                    printf("  [FILE] %s\n", item);
                                }
                            }
                            line = strtok(NULL, "\n");
                        }
                    }
                    printf("========================\n");
                }
            } else {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *newline = strchr(msg_line, '\n');
                    if (newline) *newline = '\0';
                    printf("Error: %s\n", msg_line);
                }
            }
            
            close(sock);
        }

        // MOVE - Move file to folder
        else if (strcasecmp(cmd, "MOVE") == 0) {
            if (parts < 3) {
                printf("Usage: MOVE <filename> <foldername>\n");
                continue;
            }
            
            char msg[512];
            snprintf(msg, sizeof(msg),
                    "TYPE:REQ\nOP:MOVE\nFILENAME:%s\nFOLDERNAME:%s\nUSER:%s\n\n",
                    arg1, arg2, username);
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(NS_PORT);
            inet_pton(AF_INET, NS_IP, &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("Failed to connect to Name Server\n");
                close(sock);
                continue;
            }
            
            send_message(sock, msg);
            
            char buf[1024];
            recv_message(sock, buf, sizeof(buf));
            
            if (strstr(buf, "STATUS:OK")) {
                printf("File '%s' moved to folder '%s' successfully!\n", arg1, arg2);
            } else {
                char *msg_line = strstr(buf, "MSG:");
                if (msg_line) {
                    msg_line += 4;
                    char *newline = strchr(msg_line, '\n');
                    if (newline) *newline = '\0';
                    printf("Error: %s\n", msg_line);
                }
            }
            
            close(sock);
        }


        else {
            printf("Unknown command: %s\n", cmd);
        }

        close(sock);
    }
    
    LOG_INFO("Client shutting down for user %s", username);
    close_logging();
    return 0;
}