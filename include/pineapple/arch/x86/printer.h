#ifndef PRINTER_H
#define PRINTER_H

#include "../../pineapple.h"
#include "decoder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MODRM_TABLE_SCALE 3
#define SIB_INDEX_TABLE_OFFSET 2
#define SEGMENT_TABLE_OFFSET 38
#define SEGMENT_TABLE_DIVIDER 8
#define DEFAULT_SEGMENT_OFFSET 3

	void print_instruction(pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

	void print_register(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

		void print_immediate(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

		void print_memory(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

		void print_offset(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

		void print_relative(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

		void print_address(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

		void print_floating_point(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

		typedef void(*print_fn)(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

	static print_fn operand_type_print_fn_table[7] = {
		print_register,
		print_immediate,
		print_memory,
		print_offset,
		print_relative,
		print_address,
		print_floating_point
	};

#ifdef __cplusplus
}
#endif

#endif