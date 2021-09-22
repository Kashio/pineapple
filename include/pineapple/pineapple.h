#ifndef CORE_H
#define CORE_H

#include "arch/x86/x86.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef enum pa_arch {
		VD_ARCH_X86
	} pa_arch;

	typedef enum pa_mode {
		VD_MODE_16,
		VD_MODE_32,
		VD_MODE_64
	} pa_mode;

	typedef struct pa_handle {
		pa_arch arch;
		pa_mode mode;
	} pa_handle;

	typedef struct pa_instruction {
		uint64_t address;
		uint8_t size;
		uint8_t bytes[16];
		char* mnemonic;
		char* operand_str;
		union {
			pa_x86_instruction_details x86;
		} details;
	} pa_instruction;

	size_t disassemble(pa_handle* handle, char* stream, size_t size, size_t start_address, pa_instruction** instruction);

	void pa_print_instruction(pa_instruction* instruction, size_t longest_instruction);

#ifdef __cplusplus
}
#endif

#endif
