# Distributed File Storage System with Replication and Failover

## Overview

This project implements a distributed file storage system with a Name Server (NS), multiple Storage Servers (SS), and a client application. The system provides file management, access control, versioning through checkpoints, and automatic replication with failover capabilities.

## System Architecture

### Components

1. **Name Server (NS)**
   - Central coordinator managing file metadata and storage server registry
   - Maintains an LRU cache with file information
   - Performs heartbeat monitoring and failover on server failures
   - Directs clients to appropriate storage servers using hash-based load balancing

2. **Storage Servers (SS)**
   - Multiple independent servers storing file data and metadata
   - Handle client read/write operations, access control, and versioning
   - Perform asynchronous replication to backup servers
   - Implement per-file reader-writer locks for concurrency control

3. **Client Application**
   - Interactive CLI for user operations
   - Direct communication with storage servers for file operations
   - Registration with name server for access control

### Networking Architecture

The system is designed to run across different computers with different IP addresses:

1. **Name Server (NS)**
   - Binds to all network interfaces (0.0.0.0) on port 8080
   - Accessible from any machine that can reach its IP address
   - Automatically detects Storage Server IPs from incoming connections

2. **Storage Servers (SS)**
   - Bind to all network interfaces for client and control ports
   - Connect to Name Server using configurable IP (command-line or environment variable)
   - Register with NS, which captures their IP automatically via socket connection
   - Support both local (127.0.0.1) and remote IP addresses

3. **Clients**
   - Connect to Name Server using configurable IP (command-line or environment variable)
   - Receive Storage Server IP addresses from Name Server
   - Establish direct connections to Storage Servers for file operations
   - Support connecting to NS and SS on different machines

**Communication Flow:**
- Client → NS: Get file location and SS information
- Client → SS: Direct file read/write operations
- SS → NS: Registration, heartbeats, and metadata updates
- SS → SS: Asynchronous replication between primary and backup servers

## Key Features Implemented

### File Management
- **Create**: Initialize new files with ownership and access control
- **Read**: Stream file content with access permission validation
- **Write**: Sentence-level modifications with atomic updates and word-level editing
- **Delete**: Remove files with owner verification
- **STREAM**: Send complete file content to clients
- **EXEC**: Execute shell commands from file content

### Access Control
- **Permission Model**: Read (R) and Write (W) permissions per user
- **ADDACCESS**: Grant access permissions to other users
- **REMACCESS**: Revoke access permissions
- **REQUEST/APPROVE/DENY**: Access request workflow for owner approval

### Versioning and Recovery
- **CHECKPOINT**: Create tagged snapshots of file state
- **REVERT**: Restore file to previous checkpoint
- **LISTCHECKPOINTS**: List all available checkpoints
- **UNDO**: Revert to backup created before last write operation
- **Backup Files**: Automatic pre-write backups for recovery

### Directory Operations
- **CREATEFOLDER**: Create logical folder hierarchies
- **VIEWFOLDER**: List folder contents (files and subdirectories)
- **MOVE**: Move files to folders

### Replication and Failover
- **Automatic Replication**: All write operations replicate to backup servers asynchronously
- **Heartbeat Monitoring**: NS periodically checks storage server health
- **Automatic Failover**: 
  - Backup servers promoted to primary when primary fails
  - Files without replicas are marked for data loss notification
  - Returning servers re-synchronize from active servers
- **Cache Invalidation**: Automatic cleanup when servers become unavailable

### Concurrency and Consistency
- **Per-File Locks**: Reader-writer locks prevent race conditions
- **Sentence-Level Locking**: Prevent concurrent modifications to same sentence
- **Lock Timeout**: Automatic stale lock cleanup after 5 minutes
- **Atomic Updates**: Temp-file-then-rename pattern for consistency

### Metadata Management
- **File Statistics**: Word count, character count, modification time
- **Owner Tracking**: File ownership and creation timestamps
- **Backup List**: Replication target servers stored in metadata
- **Access List**: Comma-separated user permission records

## Technical Implementation Details

### Data Structures
- **LRU Cache**: Bounded cache with per-bucket reader-writer locks for thread safety
- **Trie**: O(k) filename lookups for efficient file discovery
- **Hash-Based Storage**: Consistent hashing for load balancing

### Networking
- **Protocol**: Custom message-based protocol with length-prefixed framing
- **Async Replication**: Non-blocking write propagation to backup servers
- **Timeout Handling**: 10-second heartbeat timeout with cleanup

### Threading Model
- **Per-Connection Threads**: Concurrent client request handling
- **Background Monitoring**: Heartbeat thread for health checking
- **Thread-Safe Structures**: Mutex and reader-writer locks for shared state

### Memory Management
- **Heap Allocation**: Large buffers allocated on heap to prevent stack overflow
- **Resource Cleanup**: Proper deallocation in error paths using goto-based cleanup

## Building and Running

### Prerequisites
- GCC compiler
- POSIX-compliant system (Linux/Unix)
- GNU Make

### Compilation

```bash
cd course-project-deadlocked
make clean
make
```

This produces three executables:
- `./name_server`: Name server coordinator
- `./storage_server`: Storage server instance
- `./client_app`: Client application

### Configuration

The system supports running across different computers with different IP addresses. Network configuration can be set via command-line arguments or environment variables.

#### Name Server Configuration

**ns/ns_main.c:**
- `#define PORT 8080`: Name server port (default: 8080)
- The Name Server automatically binds to all network interfaces (0.0.0.0), making it accessible from other machines

#### Storage Server Configuration

**ss/ss_main.c:**
- `#define NS_PORT 8080`: Name server port (default: 8080)
- NS IP can be configured via:
  - Environment variable: `export NS_IP=<name_server_ip>`
  - Command-line argument: `./storage_server <ss_name> <client_port> <ctrl_port> [ns_ip]`
  - Default: `127.0.0.1` (localhost)

#### Client Configuration

**client/client_main.c:**
- NS IP can be configured via:
  - Command-line argument: `./client_app [ns_ip]`
  - Environment variable: `export NS_IP=<name_server_ip>`
  - Default: `127.0.0.1` (localhost)

**Priority Order:** Command-line argument > Environment variable > Default value

### Running the System

#### Single Machine Setup (All components on localhost)

**Terminal 1: Start Name Server**
```bash
./name_server
```

**Terminal 2: Start Storage Server 0**
```bash
./storage_server ss0 6000 6001
```

**Terminal 3: Start Storage Server 1**
```bash
./storage_server ss1 7000 7001
```

**Terminal 4: Start Storage Server 2**
```bash
./storage_server ss2 8000 8001
```

**Terminal 5: Start Client**
```bash
./client_app
```

#### Multi-Machine Setup (Components on different computers)

**Prerequisites:**
- Ensure all machines can communicate with each other over the network
- Configure firewall rules to allow traffic on the required ports
- Note the IP address of each machine

**Example Configuration:**
- Machine A (IP: 192.168.1.100): Name Server
- Machine B (IP: 192.168.1.101): Storage Server 0
- Machine C (IP: 192.168.1.102): Storage Server 1
- Machine D (IP: 192.168.1.103): Client

**Machine A - Start Name Server:**
```bash
./name_server
# Listens on all interfaces (0.0.0.0:8080)
```

**Machine B - Start Storage Server 0:**
```bash
# Using command-line argument:
./storage_server ss0 6000 6001 192.168.1.100

# OR using environment variable:
export NS_IP=192.168.1.100
./storage_server ss0 6000 6001
```

**Machine C - Start Storage Server 1:**
```bash
./storage_server ss1 7000 7001 192.168.1.100
```

**Machine D - Start Client:**
```bash
# Using command-line argument:
./client_app 192.168.1.100

# OR using environment variable:
export NS_IP=192.168.1.100
./client_app
```

#### Hybrid Setup (Some components remote, some local)

You can mix local and remote components. For example:
- Run Name Server and Storage Servers on one machine
- Connect clients from different machines

**Machine A - Start Name Server and Storage Servers:**
```bash
# Terminal 1:
./name_server

# Terminal 2:
./storage_server ss0 6000 6001

# Terminal 3:
./storage_server ss1 7000 7001
```

**Machine B - Start Remote Client:**
```bash
./client_app 192.168.1.100  # Replace with Machine A's IP
```

#### Important Notes

1. **Firewall Configuration**: Ensure the following ports are accessible:
   - Name Server: Port 8080 (TCP)
   - Storage Servers: Client ports (e.g., 6000, 7000, 8000) and Control ports (e.g., 6001, 7001, 8001)

2. **IP Address Discovery**: To find your machine's IP address:
   ```bash
   # On Linux:
   ip addr show
   # Or:
   hostname -I
   ```

3. **Storage Server IP Detection**: Storage Servers don't need to specify their own IP address. The Name Server automatically detects the Storage Server's IP from the incoming connection.

4. **Client Connections**: Clients connect to the Name Server for coordination, then establish direct connections to Storage Servers for file operations. Both the Name Server IP and Storage Server IPs must be reachable from the client machine.

The client will prompt for username and provide an interactive shell. Storage servers will automatically register with the name server and establish replication links.

### File Locations

- **Storage Data**: `ss/files_ss*/` directories contain file data and metadata
- **Logs**: `ss/logs/` and `ns/logs/` contain operation logs
- **Metadata**: `.meta` files store ownership, permissions, and replication targets

## Client Commands

```
VIEW [-a|-l|-al]
CREATE <file>
READ <file>
WRITE <file> <sentence_number>
DELETE <file>
LIST
INFO <file>
ADDACCESS -R|-W <file> <user>
REMACCESS <file> <user>
UNDO <file>
CHECKPOINT <file> <tag>
VIEWCHECKPOINT <file> <tag>
REVERT <file> <tag>
LISTCHECKPOINTS <file>
REQUESTACCESS -R|-W <file>
VIEWREQUESTS
APPROVEREQUEST <id>
DENYREQUEST <id>
CREATEFOLDER <folder>
VIEWFOLDER <folder>
MOVE <file> <folder>
EXEC <file>
STREAM <file>
EXIT
```

## Fault Tolerance

The system handles the following failure scenarios:

1. **Storage Server Failure**: Automatic failover to replica servers within 10 seconds
2. **Partial Replication Failure**: Failed replicas removed from active list; retry on recovery
3. **Replica Recovery**: Returning servers synchronize from primary and resume service
4. **Network Glitches**: SIGPIPE handling prevents process termination on socket errors

## Known Limitations

- Maximum 5 storage servers supported (configurable via `MAX_SS`)
- Maximum 2 replicas per file (configurable via `MAX_REPLICAS`)
- File content limited to 8KB per operation (configurable buffer sizes)
- Checkpoint count limited to 100 per file
- Word count per sentence limited to 500 words

## Performance Characteristics

- **File Lookup**: O(k) via trie, where k is filename length
- **Cache Lookup**: O(1) average via hash table with per-bucket locking
- **Replication**: Asynchronous, non-blocking
- **Failover Detection**: 5-10 seconds via heartbeat monitoring
