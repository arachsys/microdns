#ifndef PACK_H
#define PACK_H

#include <stdint.h>

static inline void pack_uint16(char s[2], uint16_t u) {
  s[0] = u;
  s[1] = u >> 8;
}

static inline void pack_uint16_big(char s[2], uint16_t u) {
  s[1] = u;
  s[0] = u >> 8;
}

static inline void pack_uint32(char s[4], uint32_t u) {
  s[0] = u;
  s[1] = u >> 8;
  s[2] = u >> 16;
  s[3] = u >> 24;
}

static inline void pack_uint32_big(char s[4], uint32_t u) {
  s[3] = u;
  s[2] = u >> 8;
  s[1] = u >> 16;
  s[0] = u >> 24;
}

static inline void pack_uint64(char s[8], uint64_t u) {
  s[0] = u;
  s[1] = u >> 8;
  s[2] = u >> 16;
  s[3] = u >> 24;
  s[4] = u >> 32;
  s[5] = u >> 40;
  s[6] = u >> 48;
  s[7] = u >> 56;
}

static inline void pack_uint64_big(char s[8], uint64_t u) {
  s[7] = u;
  s[6] = u >> 8;
  s[5] = u >> 16;
  s[4] = u >> 24;
  s[3] = u >> 32;
  s[2] = u >> 40;
  s[1] = u >> 48;
  s[0] = u >> 56;
}

static inline uint16_t unpack_uint16(const char s[2]) {
  uint16_t result = 0;
  result += (uint16_t) (uint8_t) s[0];
  result += (uint16_t) (uint8_t) s[1] << 8;
  return result;
}

static inline uint16_t unpack_uint16_big(const char s[2]) {
  uint16_t result = 0;
  result += (uint16_t) (uint8_t) s[1];
  result += (uint16_t) (uint8_t) s[0] << 8;
  return result;
}

static inline uint32_t unpack_uint32(const char s[4]) {
  uint32_t result = 0;
  result += (uint32_t) (uint8_t) s[0];
  result += (uint32_t) (uint8_t) s[1] << 8;
  result += (uint32_t) (uint8_t) s[2] << 16;
  result += (uint32_t) (uint8_t) s[3] << 24;
  return result;
}

static inline uint32_t unpack_uint32_big(const char s[4]) {
  uint32_t result = 0;
  result += (uint32_t) (uint8_t) s[3];
  result += (uint32_t) (uint8_t) s[2] << 8;
  result += (uint32_t) (uint8_t) s[1] << 16;
  result += (uint32_t) (uint8_t) s[0] << 24;
  return result;
}

static inline uint64_t unpack_uint64(const char s[8]) {
  uint64_t result = 0;
  result += (uint64_t) (uint8_t) s[0];
  result += (uint64_t) (uint8_t) s[1] << 8;
  result += (uint64_t) (uint8_t) s[2] << 16;
  result += (uint64_t) (uint8_t) s[3] << 24;
  result += (uint64_t) (uint8_t) s[4] << 32;
  result += (uint64_t) (uint8_t) s[5] << 40;
  result += (uint64_t) (uint8_t) s[6] << 48;
  result += (uint64_t) (uint8_t) s[7] << 56;
  return result;
}

static inline uint64_t unpack_uint64_big(const char s[8]) {
  uint64_t result = 0;
  result += (uint64_t) (uint8_t) s[7];
  result += (uint64_t) (uint8_t) s[6] << 8;
  result += (uint64_t) (uint8_t) s[5] << 16;
  result += (uint64_t) (uint8_t) s[4] << 24;
  result += (uint64_t) (uint8_t) s[3] << 32;
  result += (uint64_t) (uint8_t) s[2] << 40;
  result += (uint64_t) (uint8_t) s[1] << 48;
  result += (uint64_t) (uint8_t) s[0] << 56;
  return result;
}

#endif
