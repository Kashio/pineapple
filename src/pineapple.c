#include "pineapple/pineapple.h"
#include "pineapple/arch/x86/decoder.h"

size_t disassemble(pa_handle* handle, char* instruction_stream, size_t size, size_t start_address, pa_instruction** instruction)
{
	size_t instruction_count = 0;
	size_t total_bytes_read = 0;
	*instruction = calloc(size, sizeof(pa_instruction));
	do {
		pa_instruction* current_instruction = (*instruction + instruction_count);
		current_instruction->operand_str = "";
		size_t bytes_read = decode(handle, instruction_stream, size, current_instruction);
		if (total_bytes_read + bytes_read > size)
		{
			current_instruction->mnemonic = ".byte";
			current_instruction->operand_str = HEX_NOTATION;
			concat_decimal(&current_instruction->operand_str, (uint8_t)(*instruction_stream), HEX_FORMAT);
			bytes_read = 1;
		}
		current_instruction->size = bytes_read;
		current_instruction->address = start_address;
		size_t i;
		for (i = 0; i < current_instruction->size; i++)
		{
			current_instruction->bytes[i] = instruction_stream[i];
		}
		start_address += bytes_read;
		instruction_stream += bytes_read;
		total_bytes_read += bytes_read;
		++instruction_count;
		printf("%d - %s %s\n", instruction_count, current_instruction->mnemonic, current_instruction->operand_str);
	} while (total_bytes_read < size);
	*instruction = realloc(*instruction, instruction_count * sizeof(pa_instruction));
	return instruction_count;
}

void pa_print_instruction(pa_instruction* instruction, size_t longest_instruction)
{
	size_t i;
	printf("%08x:  ", instruction->address);
	for (i = 0; i < instruction->size; i++) {
		printf("%02X ", instruction->bytes[i]);
	}
	printf("%*s", (longest_instruction - instruction->size) * 3 + 1, "");
	printf("%s  %s", instruction->mnemonic, instruction->operand_str);
	printf("\n");
}