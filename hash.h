#include <stdint.h>
#include <sys/types.h>

#define DJB_HASH_MAGIC 5381

uint32_t djb_hash(const char *, size_t, uint32_t);
