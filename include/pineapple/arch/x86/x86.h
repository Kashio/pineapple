#ifndef X86_H_
#define X86_H_

#include "mnemonic.h"
#include "register.h"
#include "prefix.h"
#include "pineapple/common/utils.h"
#include <stdint.h>

typedef enum pa_x86_operand_type {
	VD_X86_OP_REGISTER,
	VD_X86_OP_IMMEDIATE,
	VD_X86_OP_MEMORY,
	VD_X86_OP_OFFSET,
	VD_X86_OP_RELATIVE,
	VD_X86_OP_ADDRESS,
	VD_X86_OP_FLOATING_POINT
} pa_x86_operand_type;

typedef struct pa_x86_operand_memory_sib {
	pa_x86_register base;
	pa_x86_register index;
	uint8_t scale;
} pa_x86_operand_memory_sib;

typedef struct pa_x86_operand_memory {
	uint16_t segment;
	union {
		pa_x86_register reg;
		pa_x86_operand_memory_sib sib;
	};
	int64_t displacement;
	uint8_t displacement_size;
} pa_x86_operand_memory;

typedef struct pa_x86_operand {
	uint8_t attributes;
	pa_x86_operand_type operand_type;
	union {
		pa_x86_register reg;
		int64_t immediate;
		double fp;
		pa_x86_operand_memory memory;
	};
	uint8_t size;
} pa_x86_operand;

typedef struct pa_x86_instruction_details {
	pa_x86_prefix prefixes[4];
	pa_x86_operand operands[8];
} pa_x86_instruction_details;

typedef struct pa_x86_instruction_rex {
	uint8_t rex;
	uint8_t w;
	uint8_t r;
	uint8_t x;
	uint8_t b;
} pa_x86_instruction_rex;

typedef enum pa_x86_data_size {
	DATA_8 = 1,
	DATA_16 = 2,
	DATA_32 = 4,
	DATA_40 = 5,
	DATA_48 = 6,
	DATA_64 = 8,
	DATA_80 = 10,
	DATA_112 = 14,
	DATA_128 = 16,
	DATA_224 = 28,
	DATA_752 = 94,
	DATA_864 = 108,
	DATA_2048 = 256,
	DATA_4096 = 512
} pa_x86_data_size;

typedef enum {
	MEMORY_ADDRESSING,
	MEMORY_DISPLACEMENT_8_ADDRESSING,
	MEMORY_DISPLACEMENT_16_32_ADDRESSING,
	REGISTER_ADDRESSING
} pa_x86_modrm_mod;

typedef struct pa_x86_instruction_internals {
	bool is_not_valid;
	uint8_t bytes_read;
	pa_x86_prefix prefixes[4];
	pa_x86_instruction_rex rex;
	uint8_t operands_count;
	pa_x86_operand operands[8];
	pa_x86_modrm_mod mod;
	uint8_t reg;
	uint8_t rm;
	bool is_read_sib;
	uint8_t scale;
	uint8_t index;
	uint8_t base;
	int64_t displacement;
	uint8_t displacement_size;
	uint8_t last_operand_size;
} pa_x86_instruction_internals;

#endif
