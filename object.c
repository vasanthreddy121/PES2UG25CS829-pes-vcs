#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void sha256_hex(const unsigned char *data, size_t len, char *out);

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
