#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <ctype.h>

void sha256_hex(const unsigned char *data, size_t len, char *out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + (i * 2), "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) != HASH_HEX_SIZE) return -1;

    for (int i = 0; i < HASH_SIZE; i++) {
        char byte_str[3];
        strncpy(byte_str, hex + (i * 2), 2);
        byte_str[2] = '\0';

        // Check if valid hex characters
        for (int j = 0; j < 2; j++) {
            if (!isxdigit(byte_str[j])) return -1;
        }

        unsigned int byte_val;
        if (sscanf(byte_str, "%02x", &byte_val) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte_val;
    }

    return 0;
}

static void ensure_dir(const char *path) {
    mkdir(path, 0755);
}

int object_write(const char *type, const void *data, size_t size, char *hash_out) {
    char header[64];
    int header_len = sprintf(header, "%s %zu", type, size) + 1;

    size_t total_size = header_len + size;
    unsigned char *buf = malloc(total_size);
    memcpy(buf, header, header_len);
    memcpy(buf + header_len, data, size);

    sha256_hex(buf, total_size, hash_out);

    char dir[64], path[128];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", hash_out);
    snprintf(path, sizeof(path), "%s/%s", dir, hash_out + 2);

    ensure_dir(".pes");
    ensure_dir(".pes/objects");
    ensure_dir(dir);

    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        free(buf);
        return 0;
    }

    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    f = fopen(tmp, "wb");
    fwrite(buf, 1, total_size, f);
    fclose(f);

    rename(tmp, path);
    free(buf);
    return 0;
}

int object_read(const char *hash, char **type_out, void **data_out, size_t *size_out) {
    char path[128];
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hash, hash + 2);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    char verify[65];
    sha256_hex(buf, len, verify);
    if (strcmp(verify, hash) != 0) {
        free(buf);
        return -1;
    }

    char *space = strchr((char *)buf, ' ');
    char *null = strchr((char *)buf, '\0');

    *space = '\0';
    *type_out = strdup((char *)buf);

    size_t size = atoi(space + 1);
    *size_out = size;

    *data_out = malloc(size);
    memcpy(*data_out, null + 1, size);

    free(buf);
    return 0;
}

// Helper function: get the path to an object file from its ObjectID
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, ".pes/objects/%.2s/%s", hex, hex + 2);
}

// Check if an object exists in the store
int object_exists(const ObjectID *id) {
    char path[256];
    object_path(id, path, sizeof(path));
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

// Type conversion helper
const char* object_type_to_string(ObjectType type) {
    switch (type) {
        case OBJ_BLOB:   return "blob";
        case OBJ_TREE:   return "tree";
        case OBJ_COMMIT: return "commit";
        default:         return NULL;
    }
}

// String to type conversion
ObjectType string_to_object_type(const char *type_str) {
    if (strcmp(type_str, "blob") == 0)   return OBJ_BLOB;
    if (strcmp(type_str, "tree") == 0)   return OBJ_TREE;
    if (strcmp(type_str, "commit") == 0) return OBJ_COMMIT;
    return -1;
}

// Wrapper: write object using ObjectType and ObjectID
int object_write_typed(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = object_type_to_string(type);
    if (!type_str) return -1;

    char hex_hash[HASH_HEX_SIZE + 1];
    if (object_write(type_str, data, len, hex_hash) != 0) return -1;

    return hex_to_hash(hex_hash, id_out);
}

// Wrapper: read object using ObjectType and ObjectID
int object_read_typed(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);

    char *type_str = NULL;
    if (object_read(hex, &type_str, data_out, len_out) != 0) return -1;

    ObjectType type = string_to_object_type(type_str);
    free(type_str);

    if (type == (ObjectType)-1) return -1;

    *type_out = type;
    return 0;
}
