#ifndef CRC_CHECK_H
#define CRC_CHECK_H

#include <stdint.h>
#include <stdio.h>

uint32_t compute_crc32(const uint8_t* data, size_t len);
int verify_so_crc(const char* so_path, uint64_t elf_size, uint32_t expected_crc);

#endif
