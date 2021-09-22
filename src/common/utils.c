#include "pineapple/common/utils.h"

void concat_str(char** destination, const char* source) {
	size_t new_size = strlen(*destination) + strlen(source) + 1;
	char* new_buffer = malloc(sizeof(char) * new_size);
	strcpy(new_buffer, *destination);
	strcat(new_buffer, source);
	*destination = new_buffer;
}

void concat_decimal(char** destination, int64_t number, const char* format)
{
	char* buffer = decimal_to_str(number, format);
	concat_str(destination, buffer);
	free(buffer);
}

char* decimal_to_str(int64_t number, const char* format)
{
	char* buffer;
	buffer = malloc(16);
	snprintf(buffer, 16, format, number);
	return buffer;
}

void read_decimal(uint8_t* byte_stream, uint8_t* number, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++)
	{
		number[i] = byte_stream[i];
	}
}
