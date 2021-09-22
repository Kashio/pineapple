#include "pineapple/arch/x86/printer.h"

#include <math.h>

#define X86_INTEL_SYNTAX_SEPARATOR " "
#define X86_INTEL_SYNTAX_OPERAND_SEPARATOR ", "
#define X86_INTEL_SYNTAX_OFFSET_SEPARATOR ":"
#define X86_INTEL_SYNTAX_MEMORY_OPEN "["
#define X86_INTEL_SYNTAX_MEMORY_CLOSE "]"
#define X86_INTEL_SYNTAX_PLUS " + "
#define X86_INTEL_SYNTAX_MINUS " - "
#define X86_INTEL_SYNTAX_SCALE " * "

static const char* memory_addressing_directives_table[4] = {
	"byte ptr",
	"word ptr",
	"dword ptr",
	"qword ptr"
};

void print_instruction(pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	pa_x86_operand operand = x86_instruction_internals->operands[0];
	if (!(IS_OPERAND_IMPLICIT(operand.attributes)))
	{
		operand_type_print_fn_table[operand.operand_type](instruction, &operand, x86_instruction_internals, x86_instruction_context);
	}
	size_t i;
	for (i = 1; i < x86_instruction_internals->operands_count; i++)
	{
		operand = x86_instruction_internals->operands[i];
		if (!(IS_OPERAND_IMPLICIT(operand.attributes)))
		{
			concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_OPERAND_SEPARATOR);
			operand_type_print_fn_table[operand.operand_type](instruction, &operand, x86_instruction_internals, x86_instruction_context);
		}
	}
}

void print_register(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	concat_str(&instruction->operand_str, reg_name_maps[operand->reg].name);
}

void print_immediate(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	concat_str(&instruction->operand_str, HEX_NOTATION);
	if (IS_NEGATIVE(operand->immediate, operand->size))
	{
		int64_t mask = LSH_FILL(0xFF, (operand->size - 1) * 8);
		concat_decimal(&instruction->operand_str, operand->immediate & mask, HEX_FORMAT);
	}
	else
	{
		concat_decimal(&instruction->operand_str, operand->immediate, HEX_FORMAT);
	}
}

void print_memory(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	const float memory_addressing_directives_table_offset = log2(operand->size);
	if (memory_addressing_directives_table_offset != -INFINITY)
	{
		concat_str(&instruction->operand_str, memory_addressing_directives_table[(size_t)memory_addressing_directives_table_offset]);
		concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_SEPARATOR);
	}
	if (operand->memory.segment)
	{
		uint8_t segment_offset = operand->memory.segment - SEGMENT_TABLE_OFFSET;
		concat_str(&instruction->operand_str, segment_name_map[segment_offset / SEGMENT_TABLE_DIVIDER + segment_offset % SEGMENT_TABLE_DIVIDER].name); // TODO ; wont work for fs gs
		concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_OFFSET_SEPARATOR);
	}
	if (IS_DISPLACEMENT_ONLY((*x86_instruction_internals)))
	{
		if (!operand->memory.segment)
		{
			concat_str(&instruction->operand_str, segment_name_map[DEFAULT_SEGMENT_OFFSET].name);
			concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_OFFSET_SEPARATOR);
		}
		concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_MEMORY_OPEN);
		concat_str(&instruction->operand_str, HEX_NOTATION);
		concat_decimal(&instruction->operand_str, operand->memory.displacement, HEX_FORMAT);
	}
	else
	{
		concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_MEMORY_OPEN);
		if (x86_instruction_internals->is_read_sib) {
			if (!IS_SIB_DISPLACEMENT_ONLY_NO_BASE((*x86_instruction_internals)))
			{
				concat_str(&instruction->operand_str, reg_name_maps[operand->memory.sib.base].name);
				concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_PLUS);
			}
			concat_str(&instruction->operand_str, reg_name_maps[operand->memory.sib.index].name);
			concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_SCALE);
			concat_decimal(&instruction->operand_str, pow(2, operand->memory.sib.scale), DECIMAL_FORMAT);
		}
		else {
			concat_str(&instruction->operand_str, reg_name_maps[operand->memory.reg].name);
		}
		if (operand->memory.displacement_size)
		{
			if (IS_NEGATIVE(operand->memory.displacement, operand->memory.displacement_size))
			{
				concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_MINUS);
				concat_str(&instruction->operand_str, HEX_NOTATION);
				int64_t mask = LSH_FILL(0xFF, (operand->memory.displacement_size - 1) * 8);
				concat_decimal(&instruction->operand_str, (~operand->memory.displacement + 1) & mask, HEX_FORMAT);
			}
			else
			{
				concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_PLUS);
				concat_str(&instruction->operand_str, HEX_NOTATION);
				concat_decimal(&instruction->operand_str, operand->memory.displacement, HEX_FORMAT);
			}
		}
	}
	concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_MEMORY_CLOSE);
}

void print_offset(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	concat_str(&instruction->operand_str, memory_addressing_directives_table[(size_t)log2(operand->size)]);
	concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_SEPARATOR);
	if (operand->memory.segment)
	{
		uint8_t segment_offset = operand->memory.segment - SEGMENT_TABLE_OFFSET;
		concat_str(&instruction->operand_str, segment_name_map[segment_offset / SEGMENT_TABLE_DIVIDER + segment_offset % SEGMENT_TABLE_DIVIDER].name);
	}
	else
	{
		concat_str(&instruction->operand_str, segment_name_map[DEFAULT_SEGMENT_OFFSET].name);
	}
	concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_OFFSET_SEPARATOR);
	concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_MEMORY_OPEN);
	concat_str(&instruction->operand_str, HEX_NOTATION);
	concat_decimal(&instruction->operand_str, operand->memory.displacement, HEX_FORMAT);
	concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_MEMORY_CLOSE);
}

void print_relative(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	concat_str(&instruction->operand_str, HEX_NOTATION);
	concat_decimal(&instruction->operand_str, (operand->immediate + x86_instruction_internals->bytes_read) & LSH_FILL(0xFF, (operand->size - 1) * 8), HEX_FORMAT);
}

void print_address(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	concat_str(&instruction->operand_str, HEX_NOTATION);
	concat_decimal(&instruction->operand_str, operand->memory.segment, HEX_FORMAT);
	concat_str(&instruction->operand_str, X86_INTEL_SYNTAX_OFFSET_SEPARATOR);
	concat_str(&instruction->operand_str, HEX_NOTATION);
	concat_decimal(&instruction->operand_str, operand->memory.displacement, HEX_FORMAT);
}

void print_floating_point(pa_instruction* instruction, pa_x86_operand* operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{

}
























































//void append_modrm_operands(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	char** operand_memory_addressing_table = x86_instruction_internals->prefixes[1] ?
//		modrm_memory_16_addressing_table : modrm_memory_32_addressing_table;
//	if (x86_instruction_internals->operands_direction)
//	{
//		concat_str(&instruction->operand_str, modrm_register_addressing_table[x86_instruction_internals->reg][x86_instruction_internals->operands_size]);
//		append_comma(&instruction->operand_str);
//		append_modrm_operand(&instruction->operand_str, operand_memory_addressing_table, x86_instruction_internals->rm, x86_instruction_internals, x86_instruction_context);
//	}
//	else
//	{
//		append_modrm_operand(&instruction->operand_str, operand_memory_addressing_table, x86_instruction_internals->rm, x86_instruction_internals, x86_instruction_context);
//		append_comma(&instruction->operand_str);
//		concat_str(&instruction->operand_str, modrm_register_addressing_table[x86_instruction_internals->reg][x86_instruction_internals->operands_size]);
//	}
//}
//
//void append_modrm_single_operand(uint8_t * instruction_stream, pa_instruction * instruction, pa_x86_instruction_internals * x86_instruction_internals, pa_x86_instruction_context * x86_instruction_context)
//{
//	if (x86_instruction_internals->operands_direction)
//	{
//		concat_str(&instruction->operand_str, modrm_register_addressing_table[x86_instruction_internals->rm][x86_instruction_internals->operands_size]);
//	}
//	else
//	{
//		char** operand_memory_addressing_table = x86_instruction_internals->prefixes[1] ?
//			modrm_memory_16_addressing_table : modrm_memory_32_addressing_table;
//		append_modrm_operand(&instruction->operand_str, operand_memory_addressing_table, x86_instruction_internals->rm, x86_instruction_internals, x86_instruction_context);
//	}
//}
//
//void append_modrm_operand_and_segment_register(uint8_t * instruction_stream, pa_instruction * instruction, pa_x86_instruction_internals * x86_instruction_internals, pa_x86_instruction_context * x86_instruction_context)
//{
//	char** operand_memory_addressing_table = x86_instruction_internals->prefixes[1] ?
//		modrm_memory_16_addressing_table : modrm_memory_32_addressing_table;
//	if (x86_instruction_internals->operands_direction)
//	{
//		concat_str(&instruction->operand_str, segment_name_map_modrm_reg[x86_instruction_internals->reg].name);
//		append_comma(&instruction->operand_str);
//		append_modrm_operand(&instruction->operand_str, operand_memory_addressing_table, x86_instruction_internals->rm, x86_instruction_internals, x86_instruction_context);
//	}
//	else
//	{
//		append_modrm_operand(&instruction->operand_str, operand_memory_addressing_table, x86_instruction_internals->rm, x86_instruction_internals, x86_instruction_context);
//		append_comma(&instruction->operand_str);
//		concat_str(&instruction->operand_str, segment_name_map_modrm_reg[x86_instruction_internals->reg].name);
//	}
//}
//
//void append_modrm_operand(char** operand, char** operand_memory_addressing_table, uint8_t operand_register_table_offset, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	if (IS_MEMORY_ADDRESSING((*x86_instruction_internals)))
//	{
//		append_memory_addressing_operand_directive(operand, x86_instruction_internals, x86_instruction_context);
//		concat_str(operand, " ");
//		append_memory_addressing_operand_segment(operand, x86_instruction_internals);
//		concat_str(operand, "[");
//		append_memory_addressing_operand(operand, operand_memory_addressing_table, operand_register_table_offset, x86_instruction_internals);
//		append_displacement(operand, x86_instruction_internals);
//		concat_str(operand, "]");
//	}
//	else
//	{
//		concat_str(operand, modrm_register_addressing_table[operand_register_table_offset][x86_instruction_internals->operands_size]);
//	}
//}
//
//void append_memory_addressing_operand_directive(char** operand, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	concat_str(operand, memory_addressing_directives_table[x86_instruction_context->read_memory_addressing_directive_offset_fn(x86_instruction_internals, x86_instruction_context)]);
//}
//
//void append_memory_addressing_operand_segment(char** operand, pa_x86_instruction_internals* x86_instruction_internals)
//{
//	uint8_t segment = x86_instruction_internals->prefixes[3];
//	if (IS_DISPLACEMENT_ONLY((*x86_instruction_internals)))
//	{
//		if (segment)
//		{
//			uint8_t offseted_segment = x86_instruction_internals->prefixes[3] - SEGMENT_TABLE_OFFSET;
//			concat_str(operand, segment_name_map[offseted_segment / SEGMENT_TABLE_DIVIDER + offseted_segment % SEGMENT_TABLE_DIVIDER].name);
//		}
//		else
//		{
//			concat_str(operand, segment_name_map[DEFAULT_SEGMENT_OFFSET].name);
//		}
//		concat_str(operand, ":");
//	}
//	else if (IS_MEMORY_ADDRESSING((*x86_instruction_internals)))
//	{
//		if (segment)
//		{
//			uint8_t offseted_segment = x86_instruction_internals->prefixes[3] - SEGMENT_TABLE_OFFSET;
//			concat_str(operand, segment_name_map[offseted_segment / SEGMENT_TABLE_DIVIDER + offseted_segment % SEGMENT_TABLE_DIVIDER].name);
//			concat_str(operand, ":");
//		}
//	}
//}
//
//void append_memory_addressing_operand(char** operand, char** operand_memory_addressing_table, uint8_t operand_register_table_offset, pa_x86_instruction_internals* x86_instruction_internals)
//{
//	if (!IS_DISPLACEMENT_ONLY((*x86_instruction_internals)))
//	{
//		if (x86_instruction_internals->is_read_sib)
//		{
//			if (!IS_SIB_DISPLACEMENT_ONLY_NO_BASE((*x86_instruction_internals)))
//			{
//				concat_str(operand, operand_memory_addressing_table[x86_instruction_internals->base * MODRM_TABLE_SCALE + SIB_INDEX_TABLE_OFFSET]);
//				concat_str(operand, " + ");
//			}
//			concat_str(operand, operand_memory_addressing_table[x86_instruction_internals->index * MODRM_TABLE_SCALE + SIB_INDEX_TABLE_OFFSET]);
//			concat_str(operand, " * ");
//			concat_decimal(operand, pow(2, x86_instruction_internals->scale), DECIMAL_FORMAT);
//		}
//		else
//		{
//			concat_str(operand, operand_memory_addressing_table[operand_register_table_offset * MODRM_TABLE_SCALE + x86_instruction_internals->operands_size]);
//		}
//		if (x86_instruction_internals->displacement_size)
//		{
//			if (IS_NEGATIVE(x86_instruction_internals->displacement, x86_instruction_internals->displacement_size))
//			{
//				concat_str(operand, " - ");
//			}
//			else
//			{
//				concat_str(operand, " + ");
//			}
//		}
//	}
//}
//
//void append_displacement(char** operand, pa_x86_instruction_internals* x86_instruction_internals)
//{
//	if (x86_instruction_internals->displacement_size)
//	{
//		concat_str(operand, HEX_NOTATION);
//		if (IS_NEGATIVE(x86_instruction_internals->displacement, x86_instruction_internals->displacement_size))
//		{
//			int64_t mask = LSH_FILL(0xFF, (x86_instruction_internals->displacement_size - 1) * 8);
//			concat_decimal(operand, (~x86_instruction_internals->displacement + 1) & mask, HEX_FORMAT);
//		}
//		else
//		{
//			concat_decimal(operand, x86_instruction_internals->displacement, HEX_FORMAT);
//		}
//	}
//}
//
//void append_explicit_operand(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	append_comma(&instruction->operand_str);
//	pa_x86_operand* explicit_operand = x86_instruction_context->explicit_operands[x86_instruction_internals->operands_size];
//	concat_str(&instruction->operand_str, reg_name_maps[explicit_operand->reg].name);
//}
//
//void append_implicit_operand(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	pa_x86_operand* implicitly_used_register;
//	size_t i = 0;
//	while ((implicitly_used_register = *(x86_instruction_context->implicit_operands + i)) != NULL)
//	{
//		append_comma(&instruction->operand_str);
//		switch (implicitly_used_register->operand_type)
//		{
//		case VD_X86_OP_REG:
//			concat_str(&instruction->operand_str, reg_name_maps[implicitly_used_register->reg].name);
//			break;
//		case VD_X86_OP_MEM:
//			append_memory_addressing_operand_directive(&instruction->operand_str, x86_instruction_internals, x86_instruction_context);
//			concat_str(&instruction->operand_str, " ");
//			if (implicitly_used_register->memory.segment)
//			{
//				uint8_t offseted_segment = implicitly_used_register->memory.segment - SEGMENT_TABLE_OFFSET;
//				concat_str(&instruction->operand_str, segment_name_map[offseted_segment / SEGMENT_TABLE_DIVIDER + offseted_segment % SEGMENT_TABLE_DIVIDER].name);
//				concat_str(&instruction->operand_str, ":");
//			}
//			concat_str(&instruction->operand_str, "[");
//			if (implicitly_used_register->memory.reg)
//			{
//				concat_str(&instruction->operand_str, reg_name_maps[implicitly_used_register->memory.reg].name);
//			}
//			/*else
//			{
//			concat_str(&instruction->operand_str, modrm_memory_32_addressing_table[implicitly_used_registers->memory.sib.base * MODRM_TABLE_SCALE + SIB_INDEX_TABLE_OFFSET]);
//			concat_str(&instruction->operand_str, " + ");
//			concat_str(&instruction->operand_str, modrm_memory_32_addressing_table[implicitly_used_registers->memory.sib.index * MODRM_TABLE_SCALE + SIB_INDEX_TABLE_OFFSET]);
//			concat_str(&instruction->operand_str, " * ");
//			concat_decimal(&instruction->operand_str, pow(2, implicitly_used_registers->memory.sib.scale), DECIMAL_FORMAT);
//			}*/
//			concat_str(&instruction->operand_str, "]");
//			break;
//		}
//		++i;
//	}
//}
//
//void append_immediate(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	if (x86_instruction_internals->immediate_size)
//	{
//		append_comma(&instruction->operand_str);
//		concat_str(&instruction->operand_str, HEX_NOTATION);
//		if (IS_NEGATIVE(x86_instruction_internals->immediate, x86_instruction_internals->immediate_size))
//		{
//			int64_t mask = LSH_FILL(0xFF, (x86_instruction_internals->immediate_size - 1) * 8);
//			concat_decimal(&instruction->operand_str, x86_instruction_internals->immediate, HEX_FORMAT);
//		}
//		else
//		{
//			concat_decimal(&instruction->operand_str, x86_instruction_internals->immediate, HEX_FORMAT);
//		}
//	}
//}
//
//void append_relative(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	if (x86_instruction_internals->immediate_size)
//	{
//		append_comma(&instruction->operand_str);
//		concat_str(&instruction->operand_str, HEX_NOTATION);
//		concat_decimal(&instruction->operand_str, (x86_instruction_internals->immediate + x86_instruction_internals->bytes_read) & LSH_FILL(0xFF, (x86_instruction_internals->immediate_size - 1) * 8), HEX_FORMAT);
//	}
//}
//
//void append_direct_address(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	concat_str(&instruction->operand_str, HEX_NOTATION);
//	concat_decimal(&instruction->operand_str, x86_instruction_internals->direct_address_base, DIRECT_ADDRESS_BASE_SIZE);
//	concat_str(&instruction->operand_str, ":");
//	concat_str(&instruction->operand_str, HEX_NOTATION);
//	uint8_t direct_address_offset_size = x86_instruction_internals->prefixes[2] == VD_X86_PREFIX_OPERAND_SIZE ? 2 : 4;
//	concat_decimal(&instruction->operand_str, x86_instruction_internals->direct_address_offset & LSH_FILL(0xFF, (direct_address_offset_size - 1) * 8), HEX_FORMAT);
//}
//
//void append_moffset(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	append_comma(&instruction->operand_str);
//	append_memory_addressing_operand_segment(&instruction->operand_str, x86_instruction_internals);
//	concat_str(&instruction->operand_str, "[");
//	concat_str(&instruction->operand_str, HEX_NOTATION);
//	uint8_t moffset_size = x86_instruction_internals->prefixes[1] == VD_X86_PREFIX_ADDRESS_SIZE ? 2 : 4;
//	concat_decimal(&instruction->operand_str, x86_instruction_internals->direct_address_offset & LSH_FILL(0xFF, (moffset_size - 1) * 8), HEX_FORMAT);
//	concat_str(&instruction->operand_str, "]");
//}
//
//void append_opcode_register(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	concat_str(&instruction->operand_str, modrm_register_addressing_table[x86_instruction_internals->reg][x86_instruction_context->read_operand_size_fn(instruction_stream, x86_instruction_internals)]);
//}
//
//void append_prefix(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
//{
//	size_t i;
//	for (i = 0; i < 3; i++)
//	{
//		if (x86_instruction_internals->prefixes[i])
//		{
//			concat_str(&instruction->operand_str, prefix_name_map[i].name);
//		}
//	}
//}
//
//void append_comma(char** operand)
//{
//	if (*operand[0] != '\0')
//	{
//		concat_str(operand, ", ");
//	}
//}