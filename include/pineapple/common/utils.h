#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef bool
#define bool uint8_t
#define TRUE 1
#define FALSE 0
#endif
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define LSH_FILL(m, s) ((m) << (s) | (uint64_t)(1 << (s)) - 1)
#define IS_NEGATIVE(n, b) (0x1 << ((b) * 8 - 1)) & (n)
#define HEX_NOTATION "0x"
#define DECIMAL_FORMAT "%d"
#define HEX_FORMAT "%x"

	typedef struct name_map {
		unsigned int id;
		char* name;
	} name_map;

	void concat_str(char** destination, char* source);

	void concat_decimal(char** destination, int64_t number, const char* format);

	char* decimal_to_str(int64_t number, const char* format);

	void read_decimal(uint8_t* byte_stream, uint8_t* number, size_t size);

#ifdef __cplusplus
}
#endif

#endif