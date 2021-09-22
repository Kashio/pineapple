#include "pineapple/arch/x86/decoder.h"

#include <stdlib.h>
#include <math.h>

size_t decode(pa_handle* handle, uint8_t* instruction_stream, size_t size, pa_instruction* instruction)
{
	pa_x86_instruction_internals x86_instruction_internals = empty_x86_instruction_internals;
	read_prefix(handle, instruction_stream, instruction, &x86_instruction_internals);
	while (x86_instruction_internals.bytes_read >= size)
	{
		--x86_instruction_internals.bytes_read;
	}
	instruction_stream += x86_instruction_internals.bytes_read;
	const uint8_t prefix_bytes_read = x86_instruction_internals.bytes_read;
	const pa_x86_instruction_context* context;
	read_opcode(instruction_stream, instruction, &x86_instruction_internals, &context);
	instruction_stream += x86_instruction_internals.bytes_read - prefix_bytes_read;
	if (HAS_MODRM(context))
	{
		const uint8_t modrm_bytes_read = x86_instruction_internals.bytes_read;
		read_modrm(handle, instruction_stream, instruction, &x86_instruction_internals, context);
		instruction_stream += x86_instruction_internals.bytes_read - modrm_bytes_read;
	}
	decision_loop(handle, instruction_stream, instruction, &x86_instruction_internals, context);
	if (x86_instruction_internals.is_not_valid)
	{
		return size + 1;
	}
	print_instruction(instruction, &x86_instruction_internals, context);
	return x86_instruction_internals.bytes_read;
}

void read_prefix(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals)
{
	uint8_t last_prefix = 0;
	do {
		switch (*instruction_stream)
		{
		case VD_X86_PREFIX_LOCK:
		case VD_X86_PREFIX_REP:
		case VD_X86_PREFIX_REPNE:
			last_prefix = x86_instruction_internals->prefixes[0] = instruction->details.x86.prefixes[0] = *instruction_stream;
			break;
		case VD_X86_PREFIX_ADDRESS_SIZE:
			last_prefix = x86_instruction_internals->prefixes[1] = instruction->details.x86.prefixes[1] = *instruction_stream;
			break;
		case VD_X86_PREFIX_OPERAND_SIZE:
			last_prefix = x86_instruction_internals->prefixes[2] = instruction->details.x86.prefixes[2] = *instruction_stream;
			break;
		case VD_X86_PREFIX_CS:
		case VD_X86_PREFIX_SS:
		case VD_X86_PREFIX_DS:
		case VD_X86_PREFIX_ES:
		case VD_X86_PREFIX_FS:
		case VD_X86_PREFIX_GS:
			last_prefix = x86_instruction_internals->prefixes[3] = instruction->details.x86.prefixes[3] = *instruction_stream;
			break;
		default:
			if (IS_REX_PREFIX(*instruction_stream) && handle->mode == VD_MODE_64)
			{
				last_prefix = *instruction_stream;
				break;
			}
			return;
		}
		++x86_instruction_internals->bytes_read;
		++instruction_stream;
	} while (x86_instruction_internals->bytes_read < MAX_INSTRUCTION_SIZE && !IS_REX_PREFIX(last_prefix));
	if (IS_REX_PREFIX(last_prefix))
	{
		x86_instruction_internals->rex.rex = 1;
		if (IS_REX_W(last_prefix))
		{
			x86_instruction_internals->rex.w = 1;
		}
		/*else
		{
			x86_instruction_internals->prefixes[2] = instruction->details.x86.prefixes[2] = 0;
		}*/
		x86_instruction_internals->rex.r = IS_REX_R(last_prefix);
		x86_instruction_internals->rex.x = IS_REX_X(last_prefix);
		x86_instruction_internals->rex.b = IS_REX_B(last_prefix);
	}
}

void read_opcode(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context** x86_instruction_context)
{
	++x86_instruction_internals->bytes_read;
	const pa_x86_instruction_context_table* table = &primary[*instruction_stream];
	while (table->table)
	{
		size_t table_bytes_read = table->read_table_offset_fn(instruction_stream + 1, x86_instruction_internals, &table);
		x86_instruction_internals->bytes_read += table_bytes_read;
		instruction_stream += table_bytes_read;
	}
	*x86_instruction_context = table->context;
	x86_instruction_internals->reg = READ_RM(*instruction_stream); // Only for opcodes with register values - modrm decisions will overwrite otherwise
	instruction->mnemonic = insn_name_maps[(*x86_instruction_context)->mnemonic].name;
}

void decision_loop(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	decision_node* current_decision_node = x86_instruction_context->decision_node;
	while (current_decision_node && !x86_instruction_internals->is_not_valid)
	{
		size_t decision_bytes_read = x86_instruction_internals->bytes_read;
		current_decision_node->addressing(handle, instruction_stream, instruction, x86_instruction_internals, x86_instruction_context, current_decision_node);
		decision_bytes_read = x86_instruction_internals->bytes_read - decision_bytes_read;
		instruction_stream += decision_bytes_read;
		current_decision_node = current_decision_node->next;
	}
}

void read_modrm(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context)
{
	++x86_instruction_internals->bytes_read;
	x86_instruction_internals->mod = READ_MOD(*instruction_stream);
	x86_instruction_internals->reg = READ_REG(*instruction_stream);
	x86_instruction_internals->rm = READ_RM(*instruction_stream);
	if (handle->mode != VD_MODE_16 && SHOULD_READ_SIB((*x86_instruction_internals)))
	{
		read_sib(++instruction_stream, instruction, x86_instruction_internals);
	}
	x86_instruction_internals->displacement_size = DISPLACEMENT_SIZE((*x86_instruction_internals));
	if (x86_instruction_internals->displacement_size)
	{
		read_displacement(++instruction_stream, instruction, x86_instruction_internals);
	}
}

void read_sib(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals)
{
	++x86_instruction_internals->bytes_read;
	x86_instruction_internals->is_read_sib = TRUE;
	x86_instruction_internals->scale = READ_SCALE(*instruction_stream);
	x86_instruction_internals->index = READ_INDEX(*instruction_stream);
	x86_instruction_internals->base = READ_BASE(*instruction_stream);
}

void read_displacement(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals)
{
	x86_instruction_internals->bytes_read += x86_instruction_internals->displacement_size;
	read_decimal(instruction_stream, &x86_instruction_internals->displacement, x86_instruction_internals->displacement_size);
}

void readm_rm_memory(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision, pa_x86_operand* operand)
{
	operand->operand_type = VD_X86_OP_MEMORY;
	operand->memory.displacement_size = x86_instruction_internals->displacement_size;
	operand->memory.displacement = x86_instruction_internals->displacement;
	operand->memory.segment = x86_instruction_internals->prefixes[3];
	if (x86_instruction_internals->is_read_sib)
	{
		if (IS_SIB_DISPLACEMENT_ONLY_NO_BASE((*x86_instruction_internals)))
		{
			operand->memory.sib.base = VD_X86_REG_UNDEFINED;
		}
		else
		{
			/*size_t operand_size_table_offset = log2(operand->size);
			if ((operand_size_table_offset == 0 && x86_instruction_internals->rex.b) || operand_size_table_offset != 0)
			{
				++operand_size_table_offset;
			}*/
			size_t operand_size_table_offset = handle->mode + 2;
			operand->memory.sib.base = general_register_table[x86_instruction_internals->rex.b][x86_instruction_internals->base][operand_size_table_offset];
		}
		if (IS_SIB_NO_INDEX(operand->memory.sib))
		{
			operand->memory.sib.index = VD_X86_REG_UNDEFINED; // TODO: maybe use VD_X86_REG_EIZ (gdb standart for missing index ESP register as index)
		}
		else
		{
			/*size_t operand_size_table_offset = log2(operand->size);
			if ((operand_size_table_offset == 0 && x86_instruction_internals->rex.x) || operand_size_table_offset != 0)
			{
				++operand_size_table_offset;
			}*/
			size_t operand_size_table_offset = handle->mode + 2;
			operand->memory.sib.index = general_register_table[x86_instruction_internals->rex.x][x86_instruction_internals->index][operand_size_table_offset];
		}
		operand->memory.sib.scale = x86_instruction_internals->scale;
	}
	else
	{
		uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
		uint8_t memory_addressing_table_index;
		if (handle->mode != VD_MODE_64)
		{
			if (!IS_DISPLACEMENT_ONLY((*x86_instruction_internals)))
			{
				memory_addressing_table_index = abs(handle->mode - hasAddressSizePrefix);
				operand->memory.reg = general_register_16_32_memory_table[memory_addressing_table_index][x86_instruction_internals->rm][x86_instruction_internals->mod];
			}
		}
		else
		{
			memory_addressing_table_index = !hasAddressSizePrefix;
			operand->memory.reg = general_register_32_64_memory_table[x86_instruction_internals->rex.b][memory_addressing_table_index][x86_instruction_internals->rm][x86_instruction_internals->mod];
		}
	}
}

void A(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_ADDRESS;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.memory.displacement_size = operand.size - DATA_16;
	read_decimal(instruction_stream, &operand.memory.displacement, operand.memory.displacement_size);
	read_decimal(instruction_stream + operand.memory.displacement_size, &operand.memory.segment, DATA_16);
	x86_instruction_internals->bytes_read += operand.size;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void BA(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_MEMORY;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.memory.segment = x86_instruction_internals->prefixes[3] ? x86_instruction_internals->prefixes[3] : VD_X86_PREFIX_DS;
	uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
	uint8_t memory_addressing_table_index = abs(handle->mode - hasAddressSizePrefix);
	operand.memory.reg = ax_eax_rax_memory_addressing_table[memory_addressing_table_index];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void BB(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_MEMORY;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.memory.segment = x86_instruction_internals->prefixes[3] ? x86_instruction_internals->prefixes[3] : VD_X86_PREFIX_DS;
	uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
	uint8_t memory_addressing_table_index = abs(handle->mode - hasAddressSizePrefix);
	operand.memory.reg = bx_ebx_rbx_memory_addressing_table[memory_addressing_table_index];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void BD(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_MEMORY;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.memory.segment = x86_instruction_internals->prefixes[3] ? x86_instruction_internals->prefixes[3] : VD_X86_PREFIX_DS;
	uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
	uint8_t memory_addressing_table_index = abs(handle->mode - hasAddressSizePrefix);
	operand.memory.reg = di_edi_rdi_memory_addressing_table[memory_addressing_table_index];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void C(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = control_register_table[x86_instruction_internals->reg][x86_instruction_internals->rex.r];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void D(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = debug_register_table[x86_instruction_internals->reg][x86_instruction_internals->rex.r];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void E(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	if (IS_MEMORY_ADDRESSING((*x86_instruction_internals)))
	{
		readm_rm_memory(handle, instruction_stream, instruction, x86_instruction_internals, x86_instruction_context, decision, &operand);
	}
	else
	{
		operand.operand_type = VD_X86_OP_REGISTER;
		size_t operand_size_table_offset = log2(operand.size);
		if ((operand_size_table_offset == 0 && x86_instruction_internals->rex.b) || operand_size_table_offset != 0)
		{
			++operand_size_table_offset;
		}
		operand.reg = general_register_table[x86_instruction_internals->rex.b][x86_instruction_internals->rm][operand_size_table_offset];
	}
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ES(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	if (IS_MEMORY_ADDRESSING((*x86_instruction_internals)))
	{
		readm_rm_memory(handle, instruction_stream, instruction, x86_instruction_internals, x86_instruction_context, decision, &operand);
	}
	else
	{
		operand.operand_type = VD_X86_OP_REGISTER;
		operand.reg = fpu_register_table[x86_instruction_internals->rm];
	}
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void EST(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = fpu_register_table[x86_instruction_internals->rm];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void F(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = flags_table[(size_t)log2(operand.size) - 1];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void G(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	size_t operand_size_table_offset = log2(operand.size);
	if ((operand_size_table_offset == 0 && x86_instruction_internals->rex.rex) || operand_size_table_offset != 0)
	{
		++operand_size_table_offset;
	}
	operand.reg = general_register_table[x86_instruction_internals->rex.r][x86_instruction_internals->reg][operand_size_table_offset];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void H(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	size_t operand_size_table_offset = log2(operand.size);
	if ((operand_size_table_offset == 0 && x86_instruction_internals->rex.b) || operand_size_table_offset != 0)
	{
		++operand_size_table_offset;
	}
	operand.reg = general_register_table[x86_instruction_internals->rex.b][x86_instruction_internals->rm][operand_size_table_offset];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void I(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_IMMEDIATE;
	operand.size = decision->type(handle, x86_instruction_internals);
	x86_instruction_internals->bytes_read += operand.size;
	read_decimal(instruction_stream, &operand.immediate, operand.size);
	if (IS_OPERAND_SIGN_EXTENDED(operand.attributes) && IS_NEGATIVE(operand.immediate, operand.size))
	{
		uint8_t new_operand_size;
		if (x86_instruction_internals->last_operand_size)
		{
			// TODO: sign extend to last operand size
			new_operand_size = x86_instruction_internals->last_operand_size;
		}
		else
		{
			// TODO: sign extend to stack pointer size (by mode sp/esp/rsp)
			new_operand_size = pow(2, handle->mode + 1);
		}
		uint64_t mask = LSH_FILL(1, new_operand_size * 8 - 1) - LSH_FILL(1, operand.size * 8 - 1);
		operand.immediate |= mask;
		operand.size = x86_instruction_internals->last_operand_size = new_operand_size;
	}
	else
	{
		x86_instruction_internals->last_operand_size = operand.size;
	}
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void I1(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_IMMEDIATE;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.immediate = 1;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void I3(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_IMMEDIATE;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.immediate = 3;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void J(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_RELATIVE;
	operand.size = decision->type(handle, x86_instruction_internals);
	x86_instruction_internals->bytes_read += operand.size;
	read_decimal(instruction_stream, &operand.immediate, operand.size);
	// TODO: pas is only sign extended when 4 bytes size operand
	if (IS_OPERAND_SIGN_EXTENDED(operand.attributes) && IS_NEGATIVE(operand.immediate, operand.size))
	{
		uint8_t new_operand_size;
		if (x86_instruction_internals->last_operand_size)
		{
			// TODO: sign extend to last operand size
			new_operand_size = x86_instruction_internals->last_operand_size;
		}
		else
		{
			// TODO: sign extend to stack pointer size (by mode sp/esp/rsp)
			new_operand_size = pow(2, handle->mode + 1);
		}
		uint64_t mask = LSH_FILL(1, new_operand_size * 8 - 1) - LSH_FILL(1, operand.size * 8 - 1);
		operand.immediate |= mask;
		operand.size = x86_instruction_internals->last_operand_size = new_operand_size;
	}
	else
	{
		x86_instruction_internals->last_operand_size = operand.size;
	}
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void M(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	if (decision->type)
	{
		operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	}
	else
	{
		operand.size = x86_instruction_internals->last_operand_size = 0;
	}
	readm_rm_memory(handle, instruction_stream, instruction, x86_instruction_internals, x86_instruction_context, decision, &operand);
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void N(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = mmx_register_table[x86_instruction_internals->rm];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void O(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_OFFSET;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.memory.segment = x86_instruction_internals->prefixes[3];
	uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
	operand.memory.displacement = abs(handle->mode - hasAddressSizePrefix) * 4;
	read_decimal(instruction_stream, &operand.memory.displacement, operand.memory.displacement);
	x86_instruction_internals->bytes_read += operand.memory.displacement;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void P(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = mmx_register_table[x86_instruction_internals->reg];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void Q(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	if (IS_MEMORY_ADDRESSING((*x86_instruction_internals)))
	{
		readm_rm_memory(handle, instruction_stream, instruction, x86_instruction_internals, x86_instruction_context, decision, &operand);
	}
	else
	{
		operand.operand_type = VD_X86_OP_REGISTER;
		operand.reg = mmx_register_table[x86_instruction_internals->rm];
	}
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void R(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	size_t operand_size_table_offset = log2(operand.size);
	if ((operand_size_table_offset == 0 && x86_instruction_internals->rex.b) || operand_size_table_offset != 0)
	{
		++operand_size_table_offset;
	}
	operand.reg = general_register_table[x86_instruction_internals->rex.b][x86_instruction_internals->rm][operand_size_table_offset];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void S(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = segment_register_table[x86_instruction_internals->reg][x86_instruction_internals->rex.r];
	if (operand.reg == VD_X86_REG_UNDEFINED)
	{
		x86_instruction_internals->is_not_valid = 1;
	}
	else
	{
		instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
		++x86_instruction_internals->operands_count;
	}
}

void SC(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	//pa_x86_operand operand = empty_x86_operand;
	//operand.attributes = decision->attributes;
	//operand.operand_type = VD_X86_OP_MEMORY;
	//operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	//operand.memory.segment = VD_X86_PREFIX_SS;
	//uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
	//uint8_t memory_addressing_table_index = handle->mode;
	//operand.memory.reg = sp_esp_rsp_memory_addressing_table[memory_addressing_table_index];
	//instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	//++x86_instruction_internals->operands_count;
}

void T(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = test_register_table[x86_instruction_internals->reg];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void U(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = xmm_register_table[x86_instruction_internals->rm][x86_instruction_internals->rex.b];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void V(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = xmm_register_table[x86_instruction_internals->reg][x86_instruction_internals->rex.r];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void W(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	if (IS_MEMORY_ADDRESSING((*x86_instruction_internals)))
	{
		readm_rm_memory(handle, instruction_stream, instruction, x86_instruction_internals, x86_instruction_context, decision, &operand);
	}
	else
	{
		operand.operand_type = VD_X86_OP_REGISTER;
		operand.reg = xmm_register_table[x86_instruction_internals->rm][x86_instruction_internals->rex.b];
	}
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void X(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_MEMORY;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.memory.segment = x86_instruction_internals->prefixes[3] ? x86_instruction_internals->prefixes[3] : VD_X86_PREFIX_DS;
	uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
	uint8_t memory_addressing_table_index = abs(handle->mode - hasAddressSizePrefix);
	operand.memory.reg = si_esi_rsi_memory_addressing_table[memory_addressing_table_index];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void Y(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_MEMORY;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.memory.segment = VD_X86_PREFIX_ES;
	uint8_t hasAddressSizePrefix = x86_instruction_internals->prefixes[1] != 0;
	uint8_t memory_addressing_table_index = abs(handle->mode - hasAddressSizePrefix);
	operand.memory.reg = di_edi_rdi_memory_addressing_table[memory_addressing_table_index];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void Z(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	size_t operand_size_table_offset = log2(operand.size);
	if ((operand_size_table_offset == 0 && x86_instruction_internals->rex.rex) || operand_size_table_offset != 0)
	{
		++operand_size_table_offset;
	}
	operand.reg = general_register_table[x86_instruction_internals->rex.r][x86_instruction_internals->reg][operand_size_table_offset];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void S2(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = segment_register_table[READ_SEGMENT_REG_FROM_OPCODE_S2(*(instruction_stream - 1))][0];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void S30(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = segment_register_table[READ_SEGMENT_REG_FROM_OPCODE_S30(*(instruction_stream - 1))][0];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void S33(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = segment_register_table[READ_SEGMENT_REG_FROM_OPCODE_S33(*(instruction_stream - 1))][0];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void Gen(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	size_t operand_size_table_offset = log2(operand.size);
	if (operand_size_table_offset != 0)
	{
		++operand_size_table_offset;
	}
	operand.reg = general_register_table[0][NR(operand.attributes)][operand_size_table_offset];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void Seg(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals);
	operand.reg = segment_register_table[NR(operand.attributes)][0];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void Mmx(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = mmx_register_table[NR(operand.attributes)];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void Xmm(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_128;
	operand.reg = xmm_register_table[NR(operand.attributes) - MAX_NR][NR(operand.attributes) / MAX_NR];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void X87fpu(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_80;
	operand.reg = fpu_register_table[NR(operand.attributes)];
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ldtr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_48;
	operand.reg = VD_X86_REG_LDTR;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void tr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_16;
	operand.reg = VD_X86_REG_TR;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void gdtr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = handle->mode == VD_MODE_64 ? DATA_80 : DATA_48;
	operand.reg = VD_X86_REG_GDTR;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void idtr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_2048;
	operand.reg = VD_X86_REG_IDTR;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void xcr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = VD_X86_REG_XCR0;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void msr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = VD_X86_REG_MSR;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void msw(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = decision->type(handle, x86_instruction_internals); // https://web.itu.edu.tr/kesgin/mul06/intel/intel_msw.html says it 4 bytes ?
	operand.reg = VD_X86_REG_MSW;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void pmc(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_40;
	operand.reg = VD_X86_REG_PMC;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ia32_bios_sign_id(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = VD_X86_REG_IA32_BIOS_SIGN_ID;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ia32_tsc_aux(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_32;
	operand.reg = VD_X86_REG_IA32_TSC_AUX;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ia32_time_stamp_counter(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = VD_X86_REG_IA32_TSC;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void cr0(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = handle->mode == VD_MODE_64 ? DATA_64 : DATA_32;
	operand.reg = VD_X86_REG_CR0;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ia32_sysenter_cs(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = VD_X86_REG_IA32_SYSENTER_CS;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ia32_sysenter_eip(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = VD_X86_REG_IA32_SYSENTER_EIP;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

void ia32_sysenter_esp(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision)
{
	pa_x86_operand operand = empty_x86_operand;
	operand.attributes = decision->attributes;
	operand.operand_type = VD_X86_OP_REGISTER;
	operand.size = x86_instruction_internals->last_operand_size = DATA_64;
	operand.reg = VD_X86_REG_IA32_SYSENTER_ESP;
	instruction->details.x86.operands[x86_instruction_internals->operands_count] = x86_instruction_internals->operands[x86_instruction_internals->operands_count] = operand;
	++x86_instruction_internals->operands_count;
}

















uint8_t a(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[2])
		{
			return DATA_64;
		}
		return DATA_32;
	}
	if (x86_instruction_internals->prefixes[2])
	{
		return DATA_32;
	}
	return DATA_64;
}

uint8_t b(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_8;
}

uint8_t bcd(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_80;
}

uint8_t bs(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_8;
}

uint8_t bss(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_8;
}

uint8_t d(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_32;
}

uint8_t da(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_32;
}

uint8_t di(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_32;
}

uint8_t doo(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_32;
}

uint8_t dq(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_128;
}

uint8_t dqa(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (x86_instruction_internals->prefixes[1])
	{
		return DATA_32;
	}
	return DATA_64;
}

uint8_t dqp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (x86_instruction_internals->rex.w)
	{
		return DATA_64;
	}
	return DATA_32;
}

uint8_t dr(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t e(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		return DATA_112;
	}
	return DATA_224;
}

uint8_t er(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_80;
}

uint8_t m(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return pow(2, handle->mode + 1);
}

uint8_t p(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[2])
		{
			return DATA_48;
		}
		return DATA_32;
	}
	if (x86_instruction_internals->prefixes[2])
	{
		return DATA_32;
	}
	return DATA_48;
}

uint8_t pi(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t pd(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_128;
}

uint8_t ps(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_128;
}

uint8_t psq(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t ptp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (x86_instruction_internals->rex.w)
	{
		return DATA_80;
	}
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[2])
		{
			return DATA_48;
		}
		return DATA_32;
	}
	if (x86_instruction_internals->prefixes[2])
	{
		return DATA_32;
	}
	return DATA_48;
}

uint8_t q(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t qa(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t qi(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t qp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t qs(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_64;
}

uint8_t s(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_64)
	{
		return DATA_80;
	}
	return DATA_48;
}

uint8_t sd(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_128;
}

uint8_t sr(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_32;
}

uint8_t ss(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_128;
}

uint8_t st(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		return DATA_752;
	}
	return DATA_864;
}

uint8_t stx(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_4096;
}

uint8_t v(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[2])
		{
			return DATA_32;
		}
		return DATA_16;
	}
	if (x86_instruction_internals->prefixes[2])
	{
		return DATA_16;
	}
	return DATA_32;
}

uint8_t va(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[1])
		{
			return DATA_32;
		}
		return DATA_16;
	}
	if (x86_instruction_internals->prefixes[1])
	{
		return DATA_16;
	}
	return DATA_32;
}

uint8_t pas(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[2])
		{
			return DATA_32;
		}
		return DATA_16;
	}
	if (x86_instruction_internals->prefixes[2])
	{
		return DATA_16;
	}
	return DATA_32;
}

uint8_t vq(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return x86_instruction_internals->prefixes[2] ? DATA_16 : DATA_64;
}

uint8_t vqp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (x86_instruction_internals->rex.w)
	{
		return DATA_64;
	}
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[2])
		{
			return DATA_32;
		}
		return DATA_16;
	}
	if (x86_instruction_internals->prefixes[2])
	{
		return DATA_16;
	}
	return DATA_32;
}

uint8_t vs(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	if (handle->mode == VD_MODE_16)
	{
		if (x86_instruction_internals->prefixes[2])
		{
			return DATA_32;
		}
		return DATA_16;
	}
	if (x86_instruction_internals->prefixes[2])
	{
		return DATA_16;
	}
	return DATA_32;
}

uint8_t w(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_16;
}

uint8_t wa(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_16;
}

uint8_t wi(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_16;
}

uint8_t wo(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_16;
}

uint8_t ws(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals)
{
	return DATA_16;
}

size_t read_table_offset_by_mod(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table)
{
	*x86_instruction_context_table = &(*x86_instruction_context_table)->table[READ_MOD((*instruction_stream)) == REGISTER_ADDRESSING];
	return 0;
}

size_t read_table_offset_by_prefix(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table)
{
	if (x86_instruction_internals->prefixes[0])
	{
		*x86_instruction_context_table = &(*x86_instruction_context_table)->table[(x86_instruction_internals->prefixes[0] == VD_X86_PREFIX_REP) + 2];
	}
	else
	{
		*x86_instruction_context_table = &(*x86_instruction_context_table)->table[x86_instruction_internals->prefixes[2] == VD_X86_PREFIX_OPERAND_SIZE];
	}
	return 0;
}

size_t read_table_offset_by_second_opcode(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table)
{
	*x86_instruction_context_table = &(*x86_instruction_context_table)->table[READ_RM((*instruction_stream))];
	return 0;
}

size_t read_table_offset_by_opcode_extension(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table)
{
	*x86_instruction_context_table = &(*x86_instruction_context_table)->table[READ_REG((*instruction_stream))];
	return 0;
}

size_t read_table_offset_by_opcode(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table)
{
	*x86_instruction_context_table = &(*x86_instruction_context_table)->table[*instruction_stream];
	return 1;
}