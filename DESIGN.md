# TaskCoward Design Document
## Goals
TaskCoward aims to be a TaskChampion sync server that use no resources on idle and that responds quickly and efficiently when called.
Implementation should be as simple as possible, understanding simplicity as a reduced number of operation and failure modes, coloquially referred to as "moving pieces". A small line count is a proxy measure for this, as is a small number of dependencies.
No protocol extensions are allowed: TaskChampion clients MUST work with TaskCoward without modification.

## Execution Model
In line with the goal of using no resources when idle, TaskCoward is implemented as a set of CGI programs, intentionally lacking a persistent server program. It plays particularly well with the `tipidee` HTTP server.
To keep resource usage and attack surface low, the endpoints are implemented as independent statically linked Zig programs, combined with short `execline` scripts to setup the environment.

## Code Organization
All logic is contained in `src/taskcoward.zig`.
Logic for CLI utilities is contained in functions named `cli_*` near the top of the file.
Logic for API endpoints is contained in functions named `api_*` near the top of the file.
Binaries are tiny files that just import `taskcoward.zig` and call their respective function.
Code should ideally not exceed 1kloc.

## Data Model

### User Directory
Each user has a directory named after its UUID. A user is enabled if and only if its folder exists and is accessible by the programs.
Inside this directory there are:
- A `metadata` file describing the current version of the version database.
- A set of at least one pair of `index-<metadata>` and `blobs-<metadata>` files, describing a given [#rotation] of the version database. There MUST be one pair where `<metadata>` equals the contents of the `metadata` file.
- A `snapshot` file containing the current snapshot for the user.
- A set of at least one `snapshot-<version>` files containing the snapshot for `<version>`. `snapshot` MUST be a hard link to the most recent of these files.
- A `write.lock` file used to serialize write operations.

### Version Database
The version database works as a log of blobs, with an index for validation and random access.
The index is made up of fixed size records, containing a given version's UUID, the start position of that version's data in the blobs file, the length of its data and a checksum used for database consistency purposes. The checksum enables single-phase commits.
New data is appended after the last valid entry for both the index and blob files.
A version's UUID must be a UUIDv8, where the 4 MSB are a Unix timestamp, the next 8 bytes MUST match the middle 8 bytes of the client id, and the last 4 bytes are a sequential number used for indexing.
The metadata file contains a single string matching `\d{8}-\d{16}`, representing start offsets for the index and blobs file respectively. These offsets need to be subtracted from the logical position before access.
The metadata file needs to be locked shared for opening the database. The lock may be released after opening.
When writing a new version, the blob is written and synchronized before modifying the index. All data that is not indexed is ignored. Incomplete records and records whose checksum doesn't match are ignored. This ensures atomic semantics.

### Rotation
Rotation of the version database might be needed from time to time to save space. The process takes the following steps:
1. Lock `write.lock` exclusive to avoid modifications during this process.
2. Open the database read only.
3. Create new files for new metadata, index and blobs.
4. Choose an approriate record to start the copy from, and copy from that record to the last one to the new index file, and copy from the appropriate blob offset to the new blob file.
5. Write metadata for the new files.
6. Once everything is persisted, lock `metadata` exclusive and rename the new metadata file atomically to `metadata`.
7. Delete the old index and blob files while holding the exclusive lock.
Performing the rotation this way ensures no lost changes and all readers that opened the database before we finished rotating can read their old version properly.

### Snapshots
Snapshots are stored as follows:
1. A 16 bytes prefix containing the binary serialization of its version UUID.
2. The CGI headers for a successful call to the `/v1/client/snapshot` endpoint.
3. The binary blob itself.

To ensure atomicity and consistency, new snapshots are always created in separate files named after the text representation of their version UUID `snapshot-<version>`, and only when ready get hard-linked to the `snapshot` file.
