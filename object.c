// object.c — Content-addressable object store

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(id_out->hash, &ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ───────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    // Step 1: Determine type string
    const char *type_str;
    if (type == OBJ_BLOB)        type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // Step 2: Build header e.g. "blob 13\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;
    // +1 to include the '\0' byte itself as part of the header

    // Step 3: Allocate buffer for full object = header + data
    size_t total = (size_t)header_len + len;
    uint8_t *full = malloc(total);
    if (!full) return -1;
    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    // Step 4: Compute SHA-256 of the full object
    compute_hash(full, total, id_out);

    // Step 5: Deduplication — if object already exists, skip writing
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Step 6: Get final storage path e.g. .pes/objects/ab/cdef1234...
    char path[512];
    object_path(id_out, path, sizeof(path));

    // Step 7: Build shard directory path e.g. .pes/objects/ab
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755); // OK if it already exists

    // Step 8: Write to a temporary file in the same shard directory
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/%.2s/tmp_XXXXXX", OBJECTS_DIR, hex);
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // Write full object to temp file
    ssize_t written = write(fd, full, total);
    free(full);
    if (written < 0 || (size_t)written != total) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    // Step 9: fsync to ensure data reaches disk
    if (fsync(fd) < 0) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    close(fd);

    // Step 10: Atomically rename temp file to final path
    if (rename(tmp_path, path) < 0) {
        unlink(tmp_path);
        return -1;
    }

    // Step 11: fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {

    // Step 1: Get file path from hash
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 2: Open and read the entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size_l = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size_l < 0) { fclose(f); return -1; }
    size_t file_size = (size_t)file_size_l;

    uint8_t *buf = malloc(file_size);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, file_size, f) != file_size) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    // Step 3: Verify integrity — recompute hash and compare to the expected hash
    ObjectID computed;
    compute_hash(buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1; // Data is corrupted
    }

    // Step 4: Find the '\0' that separates header from data
    uint8_t *null_ptr = memchr(buf, '\0', file_size);
    if (!null_ptr) {
        free(buf);
        return -1;
    }

    // Step 5: Parse the type from the header string e.g. "blob 13"
    if      (strncmp((char *)buf, "blob",   4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char *)buf, "tree",   4) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char *)buf, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else {
        free(buf);
        return -1;
    }

    // Step 6: Data starts right after the '\0'
    uint8_t *data_start = null_ptr + 1;
    *len_out = file_size - (size_t)(data_start - buf);

    // Step 7: Allocate and return a copy of just the data portion
    *data_out = malloc(*len_out);
    if (!*data_out) {
        free(buf);
        return -1;
    }
    memcpy(*data_out, data_start, *len_out);

    free(buf);
    return 0;
}
