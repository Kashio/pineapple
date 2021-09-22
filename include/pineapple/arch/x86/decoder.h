#ifndef DECODER_H
#define DECODER_H

#include "pineapple/pineapple.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_INSTRUCTION_SIZE 16

	static const pa_x86_instruction_internals empty_x86_instruction_internals;

	static const pa_x86_operand empty_x86_operand;

	typedef struct pa_x86_instruction_context pa_x86_instruction_context;

	typedef struct decision_node decision_node;

	typedef void(*addressing_fn)(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

	typedef uint8_t(*type_fn)(pa_handle* handle, uint8_t* instruction_stream);

	struct decision_node {
		addressing_fn addressing;
		type_fn type;
		uint8_t attributes;
		decision_node* next;
	};

	struct pa_x86_instruction_context {
		const pa_x86_mnemonic mnemonic;
		const uint8_t attributes;
		const decision_node* decision_node;
	};

	typedef struct pa_x86_instruction_context_table pa_x86_instruction_context_table;

	typedef size_t(*read_table_offset_fn)(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table);

	struct pa_x86_instruction_context_table {
		const pa_x86_instruction_context* context;
		const pa_x86_instruction_context_table* table;
		const read_table_offset_fn read_table_offset_fn;
	};

	size_t decode(pa_handle* handle, uint8_t* instruction_stream, size_t size, pa_instruction* instruction);

#define IS_REX_PREFIX(INSTRUCTION_STREAM) ((0xF0 & INSTRUCTION_STREAM) == 0x40)
#define IS_REX_W(INSTRUCTION_STREAM) ((0x08 & INSTRUCTION_STREAM) == 0x08)
#define IS_REX_R(INSTRUCTION_STREAM) ((0x04 & INSTRUCTION_STREAM) == 0x04)
#define IS_REX_X(INSTRUCTION_STREAM) ((0x02 & INSTRUCTION_STREAM) == 0x02)
#define IS_REX_B(INSTRUCTION_STREAM) ((0x01 & INSTRUCTION_STREAM) == 0x01)

	void read_prefix(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals);

	void read_opcode(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context** x86_instruction_context);

	void decision_loop(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

#define HAS_MODRM(CTX) CTX->attributes & 0x1

#define READ_MOD(INSTRUCTION_STREAM)         INSTRUCTION_STREAM >> 0x6
#define READ_REG(INSTRUCTION_STREAM) (INSTRUCTION_STREAM >> 0x3) & 0x7
#define READ_RM(INSTRUCTION_STREAM)           INSTRUCTION_STREAM & 0x7

	void read_modrm(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context);

#define SHOULD_READ_SIB(X86_INSTRUCTION_INTERNALS) \
	                         !X86_INSTRUCTION_INTERNALS.prefixes[1] && \
	            X86_INSTRUCTION_INTERNALS.mod != REGISTER_ADDRESSING && \
	                                 X86_INSTRUCTION_INTERNALS.rm == 0x4
#define READ_SCALE(INSTRUCTION_STREAM)         INSTRUCTION_STREAM >> 0x6
#define READ_INDEX(INSTRUCTION_STREAM) (INSTRUCTION_STREAM >> 0x3) & 0x7
#define READ_BASE(INSTRUCTION_STREAM)           INSTRUCTION_STREAM & 0x7

	void read_sib(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals);

#define DISPLACEMENT_SIZE(X86_INSTRUCTION_INTERNALS) \
	(X86_INSTRUCTION_INTERNALS.mod == MEMORY_DISPLACEMENT_8_ADDRESSING ? \
		1 : \
		(X86_INSTRUCTION_INTERNALS.mod == MEMORY_DISPLACEMENT_16_32_ADDRESSING ? \
			(X86_INSTRUCTION_INTERNALS.prefixes[1] ? 2 : 4) : \
			(X86_INSTRUCTION_INTERNALS.mod == MEMORY_ADDRESSING ? \
				(X86_INSTRUCTION_INTERNALS.prefixes[1] ? \
					(X86_INSTRUCTION_INTERNALS.rm == 0x6 ? 2 : 0) : \
					(X86_INSTRUCTION_INTERNALS.base == 0x5 || X86_INSTRUCTION_INTERNALS.rm == 0x5 ? 4 : 0) \
				) : 0 \
			) \
		) \
	)

	void read_displacement(uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals);

#define IS_MEMORY_ADDRESSING(X86_INSTRUCTION_INTERNALS) \
	(X86_INSTRUCTION_INTERNALS.mod != REGISTER_ADDRESSING)
#define IS_DISPLACEMENT_ONLY(X86_INSTRUCTION_INTERNALS) \
	(X86_INSTRUCTION_INTERNALS.mod == MEMORY_ADDRESSING ? \
		(X86_INSTRUCTION_INTERNALS.prefixes[1] ? \
			(X86_INSTRUCTION_INTERNALS.rm == 0x6 ? TRUE : FALSE) : \
			(X86_INSTRUCTION_INTERNALS.rm == 0x5 ? TRUE : FALSE) \
		) : 0 \
	)
#define IS_SIB_DISPLACEMENT_ONLY_NO_BASE(X86_INSTRUCTION_INTERNALS) \
	(X86_INSTRUCTION_INTERNALS.mod == MEMORY_ADDRESSING && X86_INSTRUCTION_INTERNALS.base == 0x5)

#define IS_SIB_NO_INDEX(sib) sib.index == 0x4

#define READ_SEGMENT_REG_FROM_OPCODE_S2(INSTRUCTION_STREAM) (INSTRUCTION_STREAM >> 0x3) & 0x3

#define READ_SEGMENT_REG_FROM_OPCODE_S30(INSTRUCTION_STREAM) INSTRUCTION_STREAM & 0x7

#define READ_SEGMENT_REG_FROM_OPCODE_S33(INSTRUCTION_STREAM) (INSTRUCTION_STREAM >> 0x3) & 0x7

#define IS_OPERAND_IMPLICIT(attributes) attributes & 0x2

#define IS_OPERAND_SIGN_EXTENDED(attributes) attributes & 0x4

#define NR(attributes) attributes >> 0x5

#define MAX_NR 8

	static const pa_x86_register ax_eax_rax_memory_addressing_table[3] =
	{
		VD_X86_REG_AX,
		VD_X86_REG_EAX,
		VD_X86_REG_RAX
	};

	static const pa_x86_register bx_ebx_rbx_memory_addressing_table[3] =
	{
		VD_X86_REG_BX,
		VD_X86_REG_EBX,
		VD_X86_REG_RBX
	};

	static const pa_x86_register cx_ecx_rcx_memory_addressing_table[3] =
	{
		VD_X86_REG_CX,
		VD_X86_REG_ECX,
		VD_X86_REG_RCX
	};

	static const pa_x86_register di_edi_rdi_memory_addressing_table[3] =
	{
		VD_X86_REG_DI,
		VD_X86_REG_EDI,
		VD_X86_REG_RDI
	};

	static const pa_x86_register si_esi_rsi_memory_addressing_table[3] =
	{
		VD_X86_REG_SI,
		VD_X86_REG_ESI,
		VD_X86_REG_RSI
	};

	static const pa_x86_register sp_esp_rsp_memory_addressing_table[3] =
	{
		VD_X86_REG_SP,
		VD_X86_REG_ESP,
		VD_X86_REG_RSP
	};

	static const pa_x86_register control_register_table[8][2] =
	{
		{ VD_X86_REG_CR0, VD_X86_REG_CR8 },
		{ VD_X86_REG_CR1, VD_X86_REG_CR9 },
		{ VD_X86_REG_CR2, VD_X86_REG_CR10 },
		{ VD_X86_REG_CR3, VD_X86_REG_CR11 },
		{ VD_X86_REG_CR4, VD_X86_REG_CR12 },
		{ VD_X86_REG_CR5, VD_X86_REG_CR13 },
		{ VD_X86_REG_CR6, VD_X86_REG_CR14 },
		{ VD_X86_REG_CR7, VD_X86_REG_CR15 }
	};

	static const pa_x86_register debug_register_table[8][2] =
	{
		{ VD_X86_REG_DR0, VD_X86_REG_DR8 },
		{ VD_X86_REG_DR1, VD_X86_REG_DR9 },
		{ VD_X86_REG_DR2, VD_X86_REG_DR10 },
		{ VD_X86_REG_DR3, VD_X86_REG_DR11 },
		{ VD_X86_REG_DR4, VD_X86_REG_DR12 },
		{ VD_X86_REG_DR5, VD_X86_REG_DR13 },
		{ VD_X86_REG_DR6, VD_X86_REG_DR14 },
		{ VD_X86_REG_DR7, VD_X86_REG_DR15 }
	};

	static const pa_x86_register general_register_16_memory_table[8][3] =
	{
		{ VD_X86_REG_BX_SI, VD_X86_REG_BX_SI, VD_X86_REG_BX_SI },
		{ VD_X86_REG_BX_DI, VD_X86_REG_BX_DI, VD_X86_REG_BX_DI },
		{ VD_X86_REG_BP_SI, VD_X86_REG_BP_SI, VD_X86_REG_BP_SI },
		{ VD_X86_REG_BP_DI, VD_X86_REG_BP_DI, VD_X86_REG_BP_DI },
		{ VD_X86_REG_SI, VD_X86_REG_SI, VD_X86_REG_SI },
		{ VD_X86_REG_DI, VD_X86_REG_DI, VD_X86_REG_DI },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_BP, VD_X86_REG_BP },
		{ VD_X86_REG_BX, VD_X86_REG_BX, VD_X86_REG_BX }
	};

	static const pa_x86_register general_register_32_memory_table[8][3] =
	{
		{ VD_X86_REG_EAX, VD_X86_REG_EAX, VD_X86_REG_EAX },
		{ VD_X86_REG_ECX, VD_X86_REG_ECX, VD_X86_REG_ECX },
		{ VD_X86_REG_EDX, VD_X86_REG_EDX, VD_X86_REG_EDX },
		{ VD_X86_REG_EBX, VD_X86_REG_EBX, VD_X86_REG_EBX },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_EBP, VD_X86_REG_EBP },
		{ VD_X86_REG_ESI, VD_X86_REG_ESI, VD_X86_REG_ESI },
		{ VD_X86_REG_EDI, VD_X86_REG_EDI, VD_X86_REG_EDI }
	};

	static const pa_x86_register general_register_32_mode64_memory_table[8][3] =
	{
		{ VD_X86_REG_EAX, VD_X86_REG_EAX, VD_X86_REG_EAX },
		{ VD_X86_REG_ECX, VD_X86_REG_ECX, VD_X86_REG_ECX },
		{ VD_X86_REG_EDX, VD_X86_REG_EDX, VD_X86_REG_EDX },
		{ VD_X86_REG_EBX, VD_X86_REG_EBX, VD_X86_REG_EBX },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED },
		{ VD_X86_REG_EIP, VD_X86_REG_EBP, VD_X86_REG_EBP },
		{ VD_X86_REG_ESI, VD_X86_REG_ESI, VD_X86_REG_ESI },
		{ VD_X86_REG_EDI, VD_X86_REG_EDI, VD_X86_REG_EDI }
	};

	static const pa_x86_register general_register_64_memory_table[8][3] =
	{
		{ VD_X86_REG_RAX, VD_X86_REG_RAX, VD_X86_REG_RAX },
		{ VD_X86_REG_RCX, VD_X86_REG_RCX, VD_X86_REG_RCX },
		{ VD_X86_REG_RDX, VD_X86_REG_RDX, VD_X86_REG_RDX },
		{ VD_X86_REG_RBX, VD_X86_REG_RBX, VD_X86_REG_RBX },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED },
		{ VD_X86_REG_RIP, VD_X86_REG_RBP, VD_X86_REG_RBP },
		{ VD_X86_REG_RSI, VD_X86_REG_RSI, VD_X86_REG_RSI },
		{ VD_X86_REG_RDI, VD_X86_REG_RDI, VD_X86_REG_RDI }
	};

	static const pa_x86_register general_register_RxD_32_memory_table[8][3] =
	{
		{ VD_X86_REG_R8D, VD_X86_REG_R8D, VD_X86_REG_R8D },
		{ VD_X86_REG_R9D, VD_X86_REG_R9D, VD_X86_REG_R9D },
		{ VD_X86_REG_R10D, VD_X86_REG_R10D, VD_X86_REG_R10D },
		{ VD_X86_REG_R11D, VD_X86_REG_R11D, VD_X86_REG_R11D },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED },
		{ VD_X86_REG_EIP, VD_X86_REG_R13D, VD_X86_REG_R13D },
		{ VD_X86_REG_R14D, VD_X86_REG_R14D, VD_X86_REG_R14D },
		{ VD_X86_REG_R15D, VD_X86_REG_R15D, VD_X86_REG_R15D }
	};

	static const pa_x86_register general_register_Rx_64_memory_table[8][3] =
	{
		{ VD_X86_REG_R8, VD_X86_REG_R8, VD_X86_REG_R8 },
		{ VD_X86_REG_R9, VD_X86_REG_R9, VD_X86_REG_R9 },
		{ VD_X86_REG_R10, VD_X86_REG_R10, VD_X86_REG_R10 },
		{ VD_X86_REG_R11, VD_X86_REG_R11, VD_X86_REG_R11 },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED },
		{ VD_X86_REG_RIP, VD_X86_REG_R13, VD_X86_REG_R13 },
		{ VD_X86_REG_R14, VD_X86_REG_R14, VD_X86_REG_R14 },
		{ VD_X86_REG_R15, VD_X86_REG_R15, VD_X86_REG_R15 }
	};

	static const pa_x86_register(*general_register_16_32_memory_table[2])[3] =
	{
		general_register_16_memory_table,
		general_register_32_memory_table
	};

	static const pa_x86_register** general_register_32_64_memory_table[2][2] =
	{
		{ general_register_32_mode64_memory_table, general_register_64_memory_table },
		{ general_register_RxD_32_memory_table, general_register_Rx_64_memory_table }
	};

	static const pa_x86_register general_register_table[2][8][5] =
	{
		{
			{ VD_X86_REG_AL, VD_X86_REG_AL, VD_X86_REG_AX, VD_X86_REG_EAX, VD_X86_REG_RAX },
			{ VD_X86_REG_CL, VD_X86_REG_CL, VD_X86_REG_CX, VD_X86_REG_ECX, VD_X86_REG_RCX },
			{ VD_X86_REG_DL, VD_X86_REG_DL, VD_X86_REG_DX, VD_X86_REG_EDX, VD_X86_REG_RDX },
			{ VD_X86_REG_BL, VD_X86_REG_BL, VD_X86_REG_BX, VD_X86_REG_EBX, VD_X86_REG_RBX },
			{ VD_X86_REG_AH, VD_X86_REG_SPL, VD_X86_REG_SP, VD_X86_REG_ESP, VD_X86_REG_RSP },
			{ VD_X86_REG_CH, VD_X86_REG_BPL, VD_X86_REG_BP, VD_X86_REG_EBP, VD_X86_REG_RBP },
			{ VD_X86_REG_DH, VD_X86_REG_SIL, VD_X86_REG_SI, VD_X86_REG_ESI, VD_X86_REG_RSI },
			{ VD_X86_REG_BH, VD_X86_REG_DIL, VD_X86_REG_DI, VD_X86_REG_EDI, VD_X86_REG_RDI }
		},
		{
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R8B, VD_X86_REG_R8W, VD_X86_REG_R8D, VD_X86_REG_R8 },
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R9B, VD_X86_REG_R9W, VD_X86_REG_R9D, VD_X86_REG_R9 },
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R10B, VD_X86_REG_R10W, VD_X86_REG_R10D, VD_X86_REG_R10 },
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R11B, VD_X86_REG_R11W, VD_X86_REG_R11D, VD_X86_REG_R11 },
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R12B, VD_X86_REG_R12W, VD_X86_REG_R12D, VD_X86_REG_R12 },
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R13B, VD_X86_REG_R13W, VD_X86_REG_R13D, VD_X86_REG_R13 },
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R14B, VD_X86_REG_R14W, VD_X86_REG_R14D, VD_X86_REG_R14 },
			{ VD_X86_REG_UNDEFINED, VD_X86_REG_R15B, VD_X86_REG_R15W, VD_X86_REG_R15D, VD_X86_REG_R15 }
		}
	};

	static const pa_x86_register fpu_register_table[8] =
	{
		VD_X86_REG_ST0,
		VD_X86_REG_ST1,
		VD_X86_REG_ST2,
		VD_X86_REG_ST3,
		VD_X86_REG_ST4,
		VD_X86_REG_ST5,
		VD_X86_REG_ST6,
		VD_X86_REG_ST7
	};

	static const pa_x86_register flags_table[3] =
	{
		VD_X86_REG_FLAGS,
		VD_X86_REG_EFLAGS,
		VD_X86_REG_RFLAGS
	};

	static const pa_x86_register mmx_register_table[8] =
	{
		VD_X86_REG_MM0,
		VD_X86_REG_MM1,
		VD_X86_REG_MM2,
		VD_X86_REG_MM3,
		VD_X86_REG_MM4,
		VD_X86_REG_MM5,
		VD_X86_REG_MM6,
		VD_X86_REG_MM7
	};

	static const pa_x86_register segment_register_table[8][2] =
	{
		{ VD_X86_REG_ES, VD_X86_REG_ES },
		{ VD_X86_REG_CS, VD_X86_REG_CS },
		{ VD_X86_REG_SS, VD_X86_REG_SS },
		{ VD_X86_REG_DS, VD_X86_REG_DS },
		{ VD_X86_REG_FS, VD_X86_REG_FS },
		{ VD_X86_REG_GS, VD_X86_REG_GS },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED },
		{ VD_X86_REG_UNDEFINED, VD_X86_REG_UNDEFINED }
	};

	static const pa_x86_register test_register_table[8] =
	{
		VD_X86_REG_TR0,
		VD_X86_REG_TR1,
		VD_X86_REG_TR2,
		VD_X86_REG_TR3,
		VD_X86_REG_TR4,
		VD_X86_REG_TR5,
		VD_X86_REG_TR6,
		VD_X86_REG_TR7
	};

	static const pa_x86_register xmm_register_table[8][2] =
	{
		{ VD_X86_REG_XMM0, VD_X86_REG_XMM8 },
		{ VD_X86_REG_XMM1, VD_X86_REG_XMM9 },
		{ VD_X86_REG_XMM2, VD_X86_REG_XMM10 },
		{ VD_X86_REG_XMM3, VD_X86_REG_XMM11 },
		{ VD_X86_REG_XMM4, VD_X86_REG_XMM12 },
		{ VD_X86_REG_XMM5, VD_X86_REG_XMM13 },
		{ VD_X86_REG_XMM6, VD_X86_REG_XMM14 },
		{ VD_X86_REG_XMM7, VD_X86_REG_XMM15 }
	};

	/*********************/
	/*Adressing Functions*/
	/*********************/

	void readm_rm_memory(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision, pa_x86_operand* operand);

	void A(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void BA(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void BB(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void BD(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void C(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void D(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void E(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ES(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void EST(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void F(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void G(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void H(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void I(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void I1(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void I3(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void J(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void M(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void N(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void O(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void P(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void Q(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void R(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void S(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void SC(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void T(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void U(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void V(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void W(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void X(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void Y(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void Z(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void S2(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void S30(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void S33(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void Gen(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void Seg(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void Mmx(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void Xmm(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void X87fpu(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ldtr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void tr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void gdtr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void idtr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void xcr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void msr(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void msw(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void pmc(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ia32_bios_sign_id(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ia32_tsc_aux(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ia32_time_stamp_counter(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void cr0(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ia32_sysenter_cs(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ia32_sysenter_eip(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	void ia32_sysenter_esp(pa_handle* handle, uint8_t* instruction_stream, pa_instruction* instruction, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context* x86_instruction_context, decision_node* decision);

	uint8_t a(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t b(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t bcd(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t bs(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t bss(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t d(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t da(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t di(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t doo(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t dq(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t dqa(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t dqp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t dr(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t e(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t er(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t m(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t p(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t pi(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t pd(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t ps(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t psq(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t ptp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t q(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t qa(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t qi(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t qp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t qs(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t s(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t sd(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t sr(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t ss(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t st(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t stx(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t v(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t va(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t pas(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t vq(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t vqp(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t vs(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t w(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t wa(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t wi(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t wo(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	uint8_t ws(pa_handle* handle, pa_x86_instruction_internals* x86_instruction_internals);

	size_t read_table_offset_by_mod(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table);

	size_t read_table_offset_by_prefix(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table);

	size_t read_table_offset_by_second_opcode(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table);

	size_t read_table_offset_by_opcode_extension(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table);

	size_t read_table_offset_by_opcode(uint8_t* instruction_stream, pa_x86_instruction_internals* x86_instruction_internals, pa_x86_instruction_context_table** x86_instruction_context_table);

	static const decision_node Gb0 = {
		&G,
		&b,
		0,
		NULL
	};

	static const decision_node Eb1_Gb0 = {
		&E,
		&b,
		1,
		&Gb0
	};

	static const decision_node Gvqp0 = {
		&G,
		&vqp,
		0,
		NULL
	};

	static const decision_node Evqp1_Gvqp0 = {
		&E,
		&vqp,
		1,
		&Gvqp0
	};

	static const decision_node Eb0 = {
		&E,
		&b,
		0,
		NULL
	};

	static const decision_node Gb1_Eb0 = {
		&G,
		&b,
		1,
		&Eb0
	};

	static const decision_node Evqp0 = {
		&E,
		&vqp,
		0,
		NULL
	};

	static const decision_node Gvqp1_Evqp0 = {
		&G,
		&vqp,
		1,
		&Evqp0
	};

	static const decision_node Ib0 = {
		&I,
		&b,
		0,
		NULL
	};

	static const decision_node Genb1_Ib0 = {
		&Gen,
		&b,
		1,
		&Ib0
	};

	static const decision_node Ipas4 = {
		&I,
		&pas,
		4,
		NULL
	};

	static const decision_node Genvqp1_Ipas4 = {
		&Gen,
		&vqp,
		1,
		&Ipas4
	};

	static const decision_node S2w0 = {
		&S2,
		&w,
		0,
		NULL
	};

	static const decision_node SCw3_S2w0 = {
		&SC,
		&w,
		3,
		&S2w0
	};

	static const decision_node SCw2 = {
		&SC,
		&w,
		2,
		NULL
	};

	static const decision_node S2w1_SCw2 = {
		&S2,
		&w,
		1,
		&SCw2
	};

	static const decision_node ldtr2 = {
		&ldtr,
		NULL,
		2,
		NULL
	};

	static const decision_node Mw1_ldtr2 = {
		&M,
		&w,
		1,
		&ldtr2
	};

	static const decision_node Rvqp1_ldtr2 = {
		&R,
		&vqp,
		1,
		&ldtr2
	};

	static const decision_node tr2 = {
		&tr,
		NULL,
		2,
		NULL
	};

	static const decision_node Mw1_tr2 = {
		&M,
		&w,
		1,
		&tr2
	};

	static const decision_node Rvqp1_tr2 = {
		&R,
		&vqp,
		1,
		&tr2
	};

	static const decision_node Ew0 = {
		&E,
		&w,
		0,
		NULL
	};

	static const decision_node ldtr3_Ew0 = {
		&ldtr,
		NULL,
		3,
		&Ew0
	};

	static const decision_node tr3_Ew0 = {
		&tr,
		NULL,
		3,
		&Ew0
	};

	static const decision_node gdtr2 = {
		&gdtr,
		NULL,
		2,
		NULL
	};

	static const decision_node Ms1_gdtr2 = {
		&M,
		&s,
		1,
		&gdtr2
	};

	static const decision_node idtr2 = {
		&idtr,
		NULL,
		2,
		NULL
	};

	static const decision_node Ms1_idtr2 = {
		&M,
		&s,
		1,
		&idtr2
	};

	static const decision_node Gend66 = {
		&Gen,
		&d,
		66,
		NULL
	};

	static const decision_node Gend34_Gend66 = {
		&Gen,
		&d,
		34,
		&Gend66
	};

	static const decision_node BAb2_Gend34_Gend66 = {
		&BA,
		&b,
		2,
		&Gend34_Gend66
	};

	static const decision_node Gend34 = {
		&Gen,
		&d,
		34,
		NULL
	};

	static const decision_node Gend2_Gend34 = {
		&Gen,
		&d,
		2,
		&Gend34
	};

	static const decision_node Ms0 = {
		&M,
		&s,
		0,
		NULL
	};

	static const decision_node gdtr3_Ms0 = {
		&gdtr,
		NULL,
		3,
		&Ms0
	};

	static const decision_node xcr2 = {
		&xcr,
		NULL,
		2,
		NULL
	};

	static const decision_node Gend34_xcr2 = {
		&Gen,
		&d,
		34,
		&xcr2
	};

	static const decision_node Gend3_Gend34_xcr2 = {
		&Gen,
		&d,
		3,
		&Gend34_xcr2
	};

	static const decision_node Gend67_Gend3_Gend34_xcr2 = {
		&Gen,
		&d,
		67,
		&Gend3_Gend34_xcr2
	};

	static const decision_node Gend2 = {
		&Gen,
		&d,
		2,
		NULL
	};

	static const decision_node Gend66_Gend2 = {
		&Gen,
		&d,
		66,
		&Gend2
	};

	static const decision_node Gend34_Gend66_Gend2 = {
		&Gen,
		&d,
		34,
		&Gend66_Gend2
	};

	static const decision_node xcr3_Gend34_Gend66_Gend2 = {
		&xcr,
		NULL,
		3,
		&Gend34_Gend66_Gend2
	};

	static const decision_node idtr3_Ms0 = {
		&idtr,
		NULL,
		3,
		&Ms0
	};

	static const decision_node msww2 = {
		&msw,
		&w,
		2,
		NULL
	};

	static const decision_node Mw1_msww2 = {
		&M,
		&w,
		1,
		&msww2
	};

	static const decision_node Rvqp1_msww2 = {
		&R,
		&vqp,
		1,
		&msww2
	};

	static const decision_node msww3_Ew0 = {
		&msw,
		&w,
		3,
		&Ew0
	};

	static const decision_node M0 = {
		&M,
		NULL,
		0,
		NULL
	};

	static const decision_node ia32_tsc_aux2 = {
		&ia32_tsc_aux,
		NULL,
		2,
		NULL
	};

	static const decision_node ia32_time_stamp_counter2_ia32_tsc_aux2 = {
		&ia32_time_stamp_counter,
		NULL,
		2,
		&ia32_tsc_aux2
	};

	static const decision_node Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2 = {
		&Gen,
		&d,
		35,
		&ia32_time_stamp_counter2_ia32_tsc_aux2
	};

	static const decision_node Gend67_Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2 = {
		&Gen,
		&d,
		67,
		&Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2
	};

	static const decision_node Gend3_Gend67_Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2 = {
		&Gen,
		&d,
		3,
		&Gend67_Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2
	};

	static const decision_node Mw0 = {
		&M,
		&w,
		0,
		NULL
	};

	static const decision_node Gvqp1_Mw0 = {
		&G,
		&vqp,
		1,
		&Mw0
	};

	static const decision_node Rv0 = {
		&R,
		&v,
		0,
		NULL
	};

	static const decision_node Gvqp1_Rv0 = {
		&G,
		&vqp,
		1,
		&Rv0
	};

	static const decision_node cr03 = {
		&cr0,
		NULL,
		3,
		NULL
	};

	static const decision_node Ev0 = {
		&E,
		&v,
		0,
		NULL
	};

	static const decision_node Wps0 = {
		&W,
		&ps,
		0,
		NULL
	};

	static const decision_node Vps1_Wps0 = {
		&V,
		&ps,
		1,
		&Wps0
	};

	static const decision_node Wpd0 = {
		&W,
		&pd,
		0,
		NULL
	};

	static const decision_node Vpd1_Wpd0 = {
		&V,
		&pd,
		1,
		&Wpd0
	};

	static const decision_node Wsd0 = {
		&W,
		&sd,
		0,
		NULL
	};

	static const decision_node Vsd1_Wsd0 = {
		&V,
		&sd,
		1,
		&Wsd0
	};

	static const decision_node Wss0 = {
		&W,
		&ss,
		0,
		NULL
	};

	static const decision_node Vss1_Wss0 = {
		&V,
		&ss,
		1,
		&Wss0
	};

	static const decision_node Vps0 = {
		&V,
		&ps,
		0,
		NULL
	};

	static const decision_node Wps1_Vps0 = {
		&W,
		&ps,
		1,
		&Vps0
	};

	static const decision_node Vpd0 = {
		&V,
		&pd,
		0,
		NULL
	};

	static const decision_node Wpd1_Vpd0 = {
		&W,
		&pd,
		1,
		&Vpd0
	};

	static const decision_node Vsd0 = {
		&V,
		&sd,
		0,
		NULL
	};

	static const decision_node Wsd1_Vsd0 = {
		&W,
		&sd,
		1,
		&Vsd0
	};

	static const decision_node Vss0 = {
		&V,
		&ss,
		0,
		NULL
	};

	static const decision_node Wss1_Vss0 = {
		&W,
		&ss,
		1,
		&Vss0
	};

	static const decision_node Mq0 = {
		&M,
		&q,
		0,
		NULL
	};

	static const decision_node Vq1_Mq0 = {
		&V,
		&q,
		1,
		&Mq0
	};

	static const decision_node Uq0 = {
		&U,
		&q,
		0,
		NULL
	};

	static const decision_node Vq1_Uq0 = {
		&V,
		&q,
		1,
		&Uq0
	};

	static const decision_node Wq0 = {
		&W,
		&q,
		0,
		NULL
	};

	static const decision_node Vq1_Wq0 = {
		&V,
		&q,
		1,
		&Wq0
	};

	static const decision_node Vq0 = {
		&V,
		&q,
		0,
		NULL
	};

	static const decision_node Mq1_Vq0 = {
		&M,
		&q,
		1,
		&Vq0
	};

	static const decision_node Vps1_Wq0 = {
		&V,
		&ps,
		1,
		&Wq0
	};

	static const decision_node Mb0 = {
		&M,
		&b,
		0,
		NULL
	};

	static const decision_node Cd0 = {
		&C,
		&d,
		0,
		NULL
	};

	static const decision_node Hd1_Cd0 = {
		&H,
		&d,
		1,
		&Cd0
	};

	static const decision_node Dd0 = {
		&D,
		&d,
		0,
		NULL
	};

	static const decision_node Hd1_Dd0 = {
		&H,
		&d,
		1,
		&Dd0
	};

	static const decision_node Hd0 = {
		&H,
		&d,
		0,
		NULL
	};

	static const decision_node Cd1_Hd0 = {
		&C,
		&d,
		1,
		&Hd0
	};

	static const decision_node Hq0 = {
		&H,
		&q,
		0,
		NULL
	};

	static const decision_node Dq1_Hq0 = {
		&D,
		&q,
		1,
		&Hq0
	};

	static const decision_node Td0 = {
		&T,
		&d,
		0,
		NULL
	};

	static const decision_node Hd1_Td0 = {
		&H,
		&d,
		1,
		&Td0
	};

	static const decision_node Td1_Hd0 = {
		&T,
		&d,
		1,
		&Hd0
	};

	static const decision_node Qpi0 = {
		&Q,
		&pi,
		0,
		NULL
	};

	static const decision_node Vps1_Qpi0 = {
		&V,
		&ps,
		1,
		&Qpi0
	};

	static const decision_node Vpd1_Qpi0 = {
		&V,
		&pd,
		1,
		&Qpi0
	};

	static const decision_node Edqp0 = {
		&E,
		&dqp,
		0,
		NULL
	};

	static const decision_node Vsd1_Edqp0 = {
		&V,
		&sd,
		1,
		&Edqp0
	};

	static const decision_node Vss1_Edqp0 = {
		&V,
		&ss,
		1,
		&Edqp0
	};

	static const decision_node Mps1_Vps0 = {
		&M,
		&ps,
		1,
		&Vps0
	};

	static const decision_node Mpd1_Vpd0 = {
		&M,
		&pd,
		1,
		&Vpd0
	};

	static const decision_node Wpsq0 = {
		&W,
		&psq,
		0,
		NULL
	};

	static const decision_node Ppi1_Wpsq0 = {
		&P,
		&pi,
		1,
		&Wpsq0
	};

	static const decision_node Ppi1_Wpd0 = {
		&P,
		&pi,
		1,
		&Wpd0
	};

	static const decision_node Gdqp1_Wsd0 = {
		&G,
		&dqp,
		1,
		&Wsd0
	};

	static const decision_node Gdqp1_Wss0 = {
		&G,
		&dqp,
		1,
		&Wss0
	};

	static const decision_node Vss0_Wss0 = {
		&V,
		&ss,
		0,
		&Wss0
	};

	static const decision_node Vsd0_Wsd0 = {
		&V,
		&sd,
		0,
		&Wsd0
	};

	static const decision_node Gendqp66 = {
		&Gen,
		&dqp,
		66,
		NULL
	};

	static const decision_node Gendqp2_Gendqp66 = {
		&Gen,
		&dqp,
		2,
		&Gendqp66
	};

	static const decision_node Gendqp34_Gendqp2_Gendqp66 = {
		&Gen,
		&dqp,
		34,
		&Gendqp2_Gendqp66
	};

	static const decision_node msr3_Gendqp34_Gendqp2_Gendqp66 = {
		&msr,
		NULL,
		3,
		&Gendqp34_Gendqp2_Gendqp66
	};

	static const decision_node ia32_time_stamp_counter2 = {
		&ia32_time_stamp_counter,
		NULL,
		2,
		NULL
	};

	static const decision_node Gend67_ia32_time_stamp_counter2 = {
		&Gen,
		&d,
		67,
		&ia32_time_stamp_counter2
	};

	static const decision_node Gend3_Gend67_ia32_time_stamp_counter2 = {
		&Gen,
		&d,
		3,
		&Gend67_ia32_time_stamp_counter2
	};

	static const decision_node msr2 = {
		&msr,
		NULL,
		2,
		NULL
	};

	static const decision_node Gendqp34_msr2 = {
		&Gen,
		&dqp,
		34,
		&msr2
	};

	static const decision_node Gendqp67_Gendqp34_msr2 = {
		&Gen,
		&dqp,
		67,
		&Gendqp34_msr2
	};

	static const decision_node Gendqp3_Gendqp67_Gendqp34_msr2 = {
		&Gen,
		&dqp,
		3,
		&Gendqp67_Gendqp34_msr2
	};

	static const decision_node pmc2 = {
		&pmc,
		NULL,
		2,
		NULL
	};

	static const decision_node Gend67_pmc2 = {
		&Gen,
		&d,
		67,
		&pmc2
	};

	static const decision_node Gend3_Gend67_pmc2 = {
		&Gen,
		&d,
		3,
		&Gend67_pmc2
	};

	static const decision_node ia32_sysenter_eip2 = {
		&ia32_sysenter_eip,
		NULL,
		2,
		NULL
	};

	static const decision_node ia32_sysenter_esp2_ia32_sysenter_eip2 = {
		&ia32_sysenter_esp,
		NULL,
		2,
		&ia32_sysenter_eip2
	};

	static const decision_node ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2 = {
		&ia32_sysenter_cs,
		NULL,
		2,
		&ia32_sysenter_esp2_ia32_sysenter_eip2
	};

	static const decision_node Gend131_ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2 = {
		&Gen,
		&d,
		131,
		&ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2
	};

	static const decision_node S2w3_Gend131_ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2 = {
		&S2,
		&w,
		3,
		&Gend131_ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2
	};

	static const decision_node Gendqp34_Gendqp66 = {
		&Gen,
		&dqp,
		34,
		&Gendqp66
	};

	static const decision_node ia32_sysenter_cs2_Gendqp34_Gendqp66 = {
		&ia32_sysenter_cs,
		NULL,
		2,
		&Gendqp34_Gendqp66
	};

	static const decision_node Gendqp131_ia32_sysenter_cs2_Gendqp34_Gendqp66 = {
		&Gen,
		&dqp,
		131,
		&ia32_sysenter_cs2_Gendqp34_Gendqp66
	};

	static const decision_node S2w3_Gendqp131_ia32_sysenter_cs2_Gendqp34_Gendqp66 = {
		&S2,
		&w,
		3,
		&Gendqp131_ia32_sysenter_cs2_Gendqp34_Gendqp66
	};

	static const decision_node Qq0 = {
		&Q,
		&q,
		0,
		NULL
	};

	static const decision_node Pq1_Qq0 = {
		&P,
		&q,
		1,
		&Qq0
	};

	static const decision_node Wdq0 = {
		&W,
		&dq,
		0,
		NULL
	};

	static const decision_node Vdq1_Wdq0 = {
		&V,
		&dq,
		1,
		&Wdq0
	};

	static const decision_node Xmm2 = {
		&Xmm,
		NULL,
		2,
		NULL
	};

	static const decision_node Wdq0_Xmm2 = {
		&W,
		&dq,
		0,
		&Xmm2
	};

	static const decision_node Vdq1_Wdq0_Xmm2 = {
		&V,
		&dq,
		1,
		&Wdq0_Xmm2
	};

	static const decision_node Wps0_Xmm2 = {
		&W,
		&ps,
		0,
		&Xmm2
	};

	static const decision_node Vps1_Wps0_Xmm2 = {
		&V,
		&ps,
		1,
		&Wps0_Xmm2
	};

	static const decision_node Wpd0_Xmm2 = {
		&W,
		&pd,
		0,
		&Xmm2
	};

	static const decision_node Vpd1_Wpd0_Xmm2 = {
		&V,
		&pd,
		1,
		&Wpd0_Xmm2
	};

	static const decision_node Vdq0_Wdq0 = {
		&V,
		&dq,
		0,
		&Wdq0
	};

	static const decision_node Vdq1_Mq0 = {
		&V,
		&dq,
		1,
		&Mq0
	};

	static const decision_node Udq0 = {
		&U,
		&dq,
		0,
		NULL
	};

	static const decision_node Vdq1_Udq0 = {
		&V,
		&dq,
		1,
		&Udq0
	};

	static const decision_node Md0 = {
		&M,
		&d,
		0,
		NULL
	};

	static const decision_node Vdq1_Md0 = {
		&V,
		&dq,
		1,
		&Md0
	};

	static const decision_node Vdq1_Mw0 = {
		&V,
		&dq,
		1,
		&Mw0
	};

	static const decision_node Mdq0 = {
		&M,
		&dq,
		0,
		NULL
	};

	static const decision_node Vdq1_Mdq0 = {
		&V,
		&dq,
		1,
		&Mdq0
	};

	static const decision_node Gd0_Mdq0 = {
		&G,
		&d,
		0,
		&Mdq0
	};

	static const decision_node Mvqp0 = {
		&M,
		&vqp,
		0,
		NULL
	};

	static const decision_node Gvqp1_Mvqp0 = {
		&G,
		&vqp,
		1,
		&Mvqp0
	};

	static const decision_node Gdqp1_Eb0 = {
		&G,
		&dqp,
		1,
		&Eb0
	};

	static const decision_node Mvqp1_Gvqp0 = {
		&M,
		&vqp,
		1,
		&Gvqp0
	};

	static const decision_node Gdqp1_Evqp0 = {
		&G,
		&dqp,
		1,
		&Evqp0
	};

	static const decision_node Wps0_Ib0 = {
		&W,
		&ps,
		0,
		&Ib0
	};

	static const decision_node Vps1_Wps0_Ib0 = {
		&V,
		&ps,
		1,
		&Wps0_Ib0
	};

	static const decision_node Wpd0_Ib0 = {
		&W,
		&pd,
		0,
		&Ib0
	};

	static const decision_node Vps1_Wpd0_Ib0 = {
		&V,
		&ps,
		1,
		&Wpd0_Ib0
	};

	static const decision_node Wss0_Ib0 = {
		&W,
		&ss,
		0,
		&Ib0
	};

	static const decision_node Vss1_Wss0_Ib0 = {
		&V,
		&ss,
		1,
		&Wss0_Ib0
	};

	static const decision_node Wsd0_Ib0 = {
		&W,
		&sd,
		0,
		&Ib0
	};

	static const decision_node Vsd1_Wsd0_Ib0 = {
		&V,
		&sd,
		1,
		&Wsd0_Ib0
	};

	static const decision_node Vpd1_Wpd0_Ib0 = {
		&V,
		&pd,
		1,
		&Wpd0_Ib0
	};

	static const decision_node Wdq0_Ib0 = {
		&W,
		&dq,
		0,
		&Ib0
	};

	static const decision_node Vdq1_Wdq0_Ib0 = {
		&V,
		&dq,
		1,
		&Wdq0_Ib0
	};

	static const decision_node Vdq0_Ib0 = {
		&V,
		&dq,
		0,
		&Ib0
	};

	static const decision_node Mb1_Vdq0_Ib0 = {
		&M,
		&b,
		1,
		&Vdq0_Ib0
	};

	static const decision_node Rdqp1_Vdq0_Ib0 = {
		&R,
		&dqp,
		1,
		&Vdq0_Ib0
	};

	static const decision_node Mw1_Vdq0_Ib0 = {
		&M,
		&w,
		1,
		&Vdq0_Ib0
	};

	static const decision_node Eqp1_Vdq0_Ib0 = {
		&E,
		&qp,
		1,
		&Vdq0_Ib0
	};

	static const decision_node Ed1_Vdq0_Ib0 = {
		&E,
		&d,
		1,
		&Vdq0_Ib0
	};

	static const decision_node Mb0_Ib0 = {
		&M,
		&b,
		0,
		&Ib0
	};

	static const decision_node Vdq1_Mb0_Ib0 = {
		&V,
		&dq,
		1,
		&Mb0_Ib0
	};

	static const decision_node Rdqp0_Ib0 = {
		&R,
		&dqp,
		0,
		&Ib0
	};

	static const decision_node Vdq1_Rdqp0_Ib0 = {
		&V,
		&dq,
		1,
		&Rdqp0_Ib0
	};

	static const decision_node Md0_Ib0 = {
		&M,
		&d,
		0,
		&Ib0
	};

	static const decision_node Vps1_Md0_Ib0 = {
		&V,
		&ps,
		1,
		&Md0_Ib0
	};

	static const decision_node Ups0_Ib0 = {
		&U,
		&ps,
		0,
		&Ib0
	};

	static const decision_node Vps1_Ups0_Ib0 = {
		&V,
		&ps,
		1,
		&Ups0_Ib0
	};

	static const decision_node Eqp0_Ib0 = {
		&E,
		&qp,
		0,
		&Ib0
	};

	static const decision_node Vdq1_Eqp0_Ib0 = {
		&V,
		&dq,
		1,
		&Eqp0_Ib0
	};

	static const decision_node Ib0_Gendqp2_Gendqp66 = {
		&I,
		&b,
		0,
		&Gendqp2_Gendqp66
	};

	static const decision_node Wdq0_Ib0_Gendqp2_Gendqp66 = {
		&W,
		&dq,
		0,
		&Ib0_Gendqp2_Gendqp66
	};

	static const decision_node Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66 = {
		&V,
		&dq,
		0,
		&Wdq0_Ib0_Gendqp2_Gendqp66
	};

	static const decision_node Xmm3_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66 = {
		&Xmm,
		NULL,
		3,
		&Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66
	};

	static const decision_node Gendqp35_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66 = {
		&Gen,
		&dqp,
		35,
		&Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66
	};

	static const decision_node Vdq0_Wdq0_Ib0 = {
		&V,
		&dq,
		0,
		&Wdq0_Ib0
	};

	static const decision_node Xmm3_Vdq0_Wdq0_Ib0 = {
		&Xmm,
		NULL,
		3,
		&Vdq0_Wdq0_Ib0
	};

	static const decision_node Gendqp35_Vdq0_Wdq0_Ib0 = {
		&Gen,
		&dqp,
		35,
		&Vdq0_Wdq0_Ib0
	};

	static const decision_node Ups0 = {
		&U,
		&ps,
		0,
		NULL
	};

	static const decision_node Gdqp1_Ups0 = {
		&G,
		&dqp,
		1,
		&Ups0
	};

	static const decision_node Upd0 = {
		&U,
		&pd,
		0,
		NULL
	};

	static const decision_node Gdqp1_Upd0 = {
		&G,
		&dqp,
		1,
		&Upd0
	};

	static const decision_node Vpd1_Wps0 = {
		&V,
		&pd,
		1,
		&Wps0
	};

	static const decision_node Vps1_Wpd0 = {
		&V,
		&ps,
		1,
		&Wpd0
	};

	static const decision_node Vss1_Wsd0 = {
		&V,
		&ss,
		1,
		&Wsd0
	};

	static const decision_node Vsd1_Wss0 = {
		&V,
		&sd,
		1,
		&Wss0
	};

	static const decision_node Vps1_Wdq0 = {
		&V,
		&ps,
		1,
		&Wdq0
	};

	static const decision_node Vdq1_Wps0 = {
		&V,
		&dq,
		1,
		&Wps0
	};

	static const decision_node Qd0 = {
		&Q,
		&d,
		0,
		NULL
	};

	static const decision_node Pq1_Qd0 = {
		&P,
		&q,
		1,
		&Qd0
	};

	static const decision_node Ed0 = {
		&E,
		&d,
		0,
		NULL
	};

	static const decision_node Pq1_Ed0 = {
		&P,
		&q,
		1,
		&Ed0
	};

	static const decision_node Vdq1_Ed0 = {
		&V,
		&dq,
		1,
		&Ed0
	};

	static const decision_node Qq0_Ib0 = {
		&Q,
		&q,
		0,
		&Ib0
	};

	static const decision_node Pq1_Qq0_Ib0 = {
		&P,
		&q,
		1,
		&Qq0_Ib0
	};

	static const decision_node Nq1_Ib0 = {
		&N,
		&q,
		1,
		&Ib0
	};

	static const decision_node Udq1_Ib0 = {
		&U,
		&dq,
		1,
		&Ib0
	};

	static const decision_node Gd0 = {
		&G,
		&d,
		0,
		NULL
	};

	static const decision_node Ed1_Gd0 = {
		&E,
		&d,
		1,
		&Gd0
	};

	static const decision_node Gd0_Ed0 = {
		&G,
		&d,
		0,
		&Ed0
	};

	static const decision_node Pq0 = {
		&P,
		&q,
		0,
		NULL
	};

	static const decision_node Ed1_Pq0 = {
		&E,
		&d,
		1,
		&Pq0
	};

	static const decision_node Vdq0 = {
		&V,
		&dq,
		0,
		NULL
	};

	static const decision_node Ed1_Vdq0 = {
		&E,
		&d,
		1,
		&Vdq0
	};

	static const decision_node Qq1_Pq0 = {
		&Q,
		&q,
		1,
		&Pq0
	};

	static const decision_node Wdq1_Vdq0 = {
		&W,
		&dq,
		1,
		&Vdq0
	};

	static const decision_node Jpas4 = {
		&J,
		&pas,
		4,
		NULL
	};

	static const decision_node Eb1 = {
		&E,
		&b,
		1,
		NULL
	};

	static const decision_node S33w0 = {
		&S33,
		&w,
		0,
		NULL
	};

	static const decision_node SCw3_S33w0 = {
		&SC,
		&w,
		3,
		&S33w0
	};

	static const decision_node S33w1_SCw2 = {
		&S33,
		&w,
		1,
		&SCw2
	};

	static const decision_node Gend99 = {
		&Gen,
		&d,
		99,
		NULL
	};

	static const decision_node Gend67_Gend99 = {
		&Gen,
		&d,
		67,
		&Gend99
	};

	static const decision_node Gend35_Gend67_Gend99 = {
		&Gen,
		&d,
		35,
		&Gend67_Gend99
	};

	static const decision_node Gend3_Gend35_Gend67_Gend99 = {
		&Gen,
		&d,
		3,
		&Gend35_Gend67_Gend99
	};

	static const decision_node ia32_bios_sign_id3_Gend3_Gend35_Gend67_Gend99 = {
		&ia32_bios_sign_id,
		NULL,
		3,
		&Gend3_Gend35_Gend67_Gend99
	};

	static const decision_node Evqp0_Gvqp0 = {
		&E,
		&vqp,
		0,
		&Gvqp0
	};

	static const decision_node Gvqp0_Ib0 = {
		&G,
		&vqp,
		0,
		&Ib0
	};

	static const decision_node Evqp1_Gvqp0_Ib0 = {
		&E,
		&vqp,
		1,
		&Gvqp0_Ib0
	};

	static const decision_node Genb32 = {
		&Gen,
		&b,
		32,
		NULL
	};

	static const decision_node Gvqp0_Genb32 = {
		&G,
		&vqp,
		0,
		&Genb32
	};

	static const decision_node Evqp1_Gvqp0_Genb32 = {
		&E,
		&vqp,
		1,
		&Gvqp0_Genb32
	};

	static const decision_node Fw3 = {
		&F,
		&w,
		3,
		NULL
	};

	static const decision_node Xmm226 = {
		&Xmm,
		NULL,
		226,
		NULL
	};

	static const decision_node Xmm194_Xmm226 = {
		&Xmm,
		NULL,
		194,
		&Xmm226
	};

	static const decision_node Xmm162_Xmm194_Xmm226 = {
		&Xmm,
		NULL,
		162,
		&Xmm194_Xmm226
	};

	static const decision_node Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Xmm,
		NULL,
		130,
		&Xmm162_Xmm194_Xmm226
	};

	static const decision_node Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Xmm,
		NULL,
		98,
		&Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Xmm,
		NULL,
		66,
		&Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Xmm,
		NULL,
		34,
		&Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Xmm,
		NULL,
		2,
		&Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		226,
		&Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		194,
		&Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		162,
		&Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		130,
		&Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		98,
		&Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		66,
		&Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		34,
		&Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Mmx,
		NULL,
		2,
		&Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		226,
		&Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		194,
		&X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		162,
		&X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		130,
		&X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		98,
		&X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		66,
		&X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		34,
		&X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&X87fpu,
		NULL,
		2,
		&X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mstx1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&M,
		&stx,
		1,
		&X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Mstx0 = {
		&M,
		&stx,
		0,
		NULL
	};

	static const decision_node Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		227,
		&Mstx0
	};

	static const decision_node Xmm195_Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		195,
		&Xmm227_Mstx0
	};

	static const decision_node Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		163,
		&Xmm195_Xmm227_Mstx0
	};

	static const decision_node Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		131,
		&Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		99,
		&Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		67,
		&Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		35,
		&Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Xmm,
		NULL,
		3,
		&Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		227,
		&Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		195,
		&Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		163,
		&Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		131,
		&Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		99,
		&Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		67,
		&Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		35,
		&Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&Mmx,
		NULL,
		3,
		&Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		227,
		&Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		195,
		&X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		163,
		&X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		131,
		&X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		99,
		&X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		67,
		&X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		35,
		&X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		&X87fpu,
		NULL,
		3,
		&X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const decision_node Md1 = {
		&M,
		&d,
		1,
		NULL
	};

	static const decision_node Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Gen,
		&d,
		2,
		&X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node Gend66_Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&Gen,
		&d,
		66,
		&Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node M1_Gend66_Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		&M,
		NULL,
		1,
		&Gend66_Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const decision_node M0_Gend66_Gend2 = {
		&M,
		NULL,
		0,
		&Gend66_Gend2
	};

	static const decision_node Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		227,
		&M0_Gend66_Gend2
	};

	static const decision_node Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		195,
		&Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		163,
		&Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		131,
		&Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		99,
		&Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		67,
		&Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		35,
		&Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Xmm,
		NULL,
		3,
		&Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		227,
		&Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		195,
		&Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		163,
		&Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		131,
		&Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		99,
		&Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		67,
		&Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		35,
		&Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&Mmx,
		NULL,
		3,
		&Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		227,
		&Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		195,
		&X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		163,
		&X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		131,
		&X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		99,
		&X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		67,
		&X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		35,
		&X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		&X87fpu,
		NULL,
		3,
		&X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const decision_node Genb3_Gb0 = {
		&Gen,
		&b,
		3,
		&Gb0
	};

	static const decision_node Eb1_Genb3_Gb0 = {
		&E,
		&b,
		1,
		&Genb3_Gb0
	};

	static const decision_node Genvqp3_Gvqp0 = {
		&Gen,
		&vqp,
		3,
		&Gvqp0
	};

	static const decision_node Evqp1_Genvqp3_Gvqp0 = {
		&E,
		&vqp,
		1,
		&Genvqp3_Gvqp0
	};

	static const decision_node Mptp0 = {
		&M,
		&ptp,
		0,
		NULL
	};

	static const decision_node Gvqp1_Mptp0 = {
		&G,
		&vqp,
		1,
		&Mptp0
	};

	static const decision_node S30w3_Gvqp1_Mptp0 = {
		&S30,
		&w,
		3,
		&Gvqp1_Mptp0
	};

	static const decision_node Gvqp1_Eb0 = {
		&G,
		&vqp,
		1,
		&Eb0
	};

	static const decision_node Gvqp1_Ew0 = {
		&G,
		&vqp,
		1,
		&Ew0
	};

	static const decision_node Evqp0_Ib0 = {
		&E,
		&vqp,
		0,
		&Ib0
	};

	static const decision_node Evqp1_Ib0 = {
		&E,
		&vqp,
		1,
		&Ib0
	};

	static const decision_node Gb1 = {
		&G,
		&b,
		1,
		NULL
	};

	static const decision_node Eb1_Gb1 = {
		&E,
		&b,
		1,
		&Gb1
	};

	static const decision_node Gvqp1 = {
		&G,
		&vqp,
		1,
		NULL
	};

	static const decision_node Evqp1_Gvqp1 = {
		&E,
		&vqp,
		1,
		&Gvqp1
	};

	static const decision_node Gdqp0 = {
		&G,
		&dqp,
		0,
		NULL
	};

	static const decision_node Mdqp1_Gdqp0 = {
		&M,
		&dqp,
		1,
		&Gdqp0
	};

	static const decision_node Mw0_Ib0 = {
		&M,
		&w,
		0,
		&Ib0
	};

	static const decision_node Pq1_Mw0_Ib0 = {
		&P,
		&q,
		1,
		&Mw0_Ib0
	};

	static const decision_node Pq1_Rdqp0_Ib0 = {
		&P,
		&q,
		1,
		&Rdqp0_Ib0
	};

	static const decision_node Vdq1_Mw0_Ib0 = {
		&V,
		&dq,
		1,
		&Mw0_Ib0
	};

	static const decision_node Nq0_Ib0 = {
		&N,
		&q,
		0,
		&Ib0
	};

	static const decision_node Gdqp1_Nq0_Ib0 = {
		&G,
		&dqp,
		1,
		&Nq0_Ib0
	};

	static const decision_node Udq0_Ib0 = {
		&U,
		&dq,
		0,
		&Ib0
	};

	static const decision_node Gdqp1_Udq0_Ib0 = {
		&G,
		&dqp,
		1,
		&Udq0_Ib0
	};

	static const decision_node Gend98_Gend34 = {
		&Gen,
		&d,
		98,
		&Gend34
	};

	static const decision_node Gend67_Gend98_Gend34 = {
		&Gen,
		&d,
		67,
		&Gend98_Gend34
	};

	static const decision_node Gend3_Gend67_Gend98_Gend34 = {
		&Gen,
		&d,
		3,
		&Gend67_Gend98_Gend34
	};

	static const decision_node Mq1_Gend3_Gend67_Gend98_Gend34 = {
		&M,
		&q,
		1,
		&Gend3_Gend67_Gend98_Gend34
	};

	static const decision_node Mq1 = {
		&M,
		&q,
		1,
		NULL
	};

	static const decision_node Zvqp1 = {
		&Z,
		&vqp,
		1,
		NULL
	};

	static const decision_node Wq1_Vq0 = {
		&W,
		&q,
		1,
		&Vq0
	};

	static const decision_node Pq1_Uq0 = {
		&P,
		&q,
		1,
		&Uq0
	};

	static const decision_node Nq0 = {
		&N,
		&q,
		0,
		NULL
	};

	static const decision_node Vdq1_Nq0 = {
		&V,
		&dq,
		1,
		&Nq0
	};

	static const decision_node Gdqp1_Nq0 = {
		&G,
		&dqp,
		1,
		&Nq0
	};

	static const decision_node Gdqp1_Udq0 = {
		&G,
		&dqp,
		1,
		&Udq0
	};

	static const decision_node Vdq1_Wpd0 = {
		&V,
		&dq,
		1,
		&Wpd0
	};

	static const decision_node Vpd1_Wdq0 = {
		&V,
		&pd,
		1,
		&Wdq0
	};

	static const decision_node Mq1_Pq0 = {
		&M,
		&q,
		1,
		&Pq0
	};

	static const decision_node Mdq1_Vdq0 = {
		&M,
		&dq,
		1,
		&Vdq0
	};

	static const decision_node Pq1_Nq0 = {
		&P,
		&q,
		1,
		&Nq0
	};

	static const decision_node BDq3_Pq1_Nq0 = {
		&BD,
		&q,
		3,
		&Pq1_Nq0
	};

	static const decision_node Vdq0_Udq0 = {
		&V,
		&dq,
		0,
		&Udq0
	};

	static const decision_node BDdq3_Vdq0_Udq0 = {
		&BD,
		&dq,
		3,
		&Vdq0_Udq0
	};

	static const decision_node Genb3 = {
		&Gen,
		&b,
		3,
		NULL
	};

	static const decision_node Genb131 = {
		&Gen,
		&b,
		131,
		NULL
	};

	static const decision_node Genb3_Genb131 = {
		&Gen,
		&b,
		3,
		&Genb131
	};

	static const decision_node Eb0_Gb0 = {
		&E,
		&b,
		0,
		&Gb0
	};

	static const decision_node Gb0_Eb0 = {
		&G,
		&b,
		0,
		&Eb0
	};

	static const decision_node Gvqp0_Evqp0 = {
		&G,
		&vqp,
		0,
		&Evqp0
	};

	static const decision_node Genb0_Ib0 = {
		&Gen,
		&b,
		0,
		&Ib0
	};

	static const decision_node Genvqp0_Ipas4 = {
		&Gen,
		&vqp,
		0,
		&Ipas4
	};

	static const decision_node Zv1 = {
		&Z,
		&v,
		1,
		NULL
	};

	static const decision_node Zv0 = {
		&Z,
		&v,
		0,
		NULL
	};

	static const decision_node SCv3_Zv0 = {
		&SC,
		&v,
		3,
		&Zv0
	};

	static const decision_node SCv2 = {
		&SC,
		&v,
		2,
		NULL
	};

	static const decision_node Zv1_SCv2 = {
		&Z,
		&v,
		1,
		&SCv2
	};

	static const decision_node Genwo226 = {
		&Gen,
		&wo,
		226,
		NULL
	};

	static const decision_node Genwo194_Genwo226 = {
		&Gen,
		&wo,
		194,
		&Genwo226
	};

	static const decision_node Genwo162_Genwo194_Genwo226 = {
		&Gen,
		&wo,
		162,
		&Genwo194_Genwo226
	};

	static const decision_node Genwo130_Genwo162_Genwo194_Genwo226 = {
		&Gen,
		&wo,
		130,
		&Genwo162_Genwo194_Genwo226
	};

	static const decision_node Genwo98_Genwo130_Genwo162_Genwo194_Genwo226 = {
		&Gen,
		&wo,
		98,
		&Genwo130_Genwo162_Genwo194_Genwo226
	};

	static const decision_node Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226 = {
		&Gen,
		&wo,
		66,
		&Genwo98_Genwo130_Genwo162_Genwo194_Genwo226
	};

	static const decision_node Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226 = {
		&Gen,
		&wo,
		34,
		&Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226
	};

	static const decision_node Genwo2_Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226 = {
		&Gen,
		&wo,
		2,
		&Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226
	};

	static const decision_node SCwo3_Genwo2_Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226 = {
		&SC,
		&wo,
		3,
		&Genwo2_Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226
	};

	static const decision_node Gendoo226 = {
		&Gen,
		&doo,
		226,
		NULL
	};

	static const decision_node Gendoo194_Gendoo226 = {
		&Gen,
		&doo,
		194,
		&Gendoo226
	};

	static const decision_node Gendoo162_Gendoo194_Gendoo226 = {
		&Gen,
		&doo,
		162,
		&Gendoo194_Gendoo226
	};

	static const decision_node Gendoo130_Gendoo162_Gendoo194_Gendoo226 = {
		&Gen,
		&doo,
		130,
		&Gendoo162_Gendoo194_Gendoo226
	};

	static const decision_node Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226 = {
		&Gen,
		&doo,
		98,
		&Gendoo130_Gendoo162_Gendoo194_Gendoo226
	};

	static const decision_node Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226 = {
		&Gen,
		&doo,
		66,
		&Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226
	};

	static const decision_node Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226 = {
		&Gen,
		&doo,
		34,
		&Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226
	};

	static const decision_node Gendoo2_Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226 = {
		&Gen,
		&doo,
		2,
		&Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226
	};

	static const decision_node SCdoo3_Gendoo2_Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226 = {
		&SC,
		&doo,
		3,
		&Gendoo2_Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226
	};

	static const decision_node SCwo2 = {
		&SC,
		&wo,
		2,
		NULL
	};

	static const decision_node Genwo3_SCwo2 = {
		&Gen,
		&wo,
		3,
		&SCwo2
	};

	static const decision_node Genwo35_Genwo3_SCwo2 = {
		&Gen,
		&wo,
		35,
		&Genwo3_SCwo2
	};

	static const decision_node Genwo67_Genwo35_Genwo3_SCwo2 = {
		&Gen,
		&wo,
		67,
		&Genwo35_Genwo3_SCwo2
	};

	static const decision_node Genwo99_Genwo67_Genwo35_Genwo3_SCwo2 = {
		&Gen,
		&wo,
		99,
		&Genwo67_Genwo35_Genwo3_SCwo2
	};

	static const decision_node Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2 = {
		&Gen,
		&wo,
		163,
		&Genwo99_Genwo67_Genwo35_Genwo3_SCwo2
	};

	static const decision_node Genwo195_Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2 = {
		&Gen,
		&wo,
		195,
		&Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2
	};

	static const decision_node Genwo227_Genwo195_Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2 = {
		&Gen,
		&wo,
		227,
		&Genwo195_Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2
	};

	static const decision_node SCdoo2 = {
		&SC,
		&doo,
		2,
		NULL
	};

	static const decision_node Gendoo3_SCdoo2 = {
		&Gen,
		&doo,
		3,
		&SCdoo2
	};

	static const decision_node Gendoo35_Gendoo3_SCdoo2 = {
		&Gen,
		&doo,
		35,
		&Gendoo3_SCdoo2
	};

	static const decision_node Gendoo67_Gendoo35_Gendoo3_SCdoo2 = {
		&Gen,
		&doo,
		67,
		&Gendoo35_Gendoo3_SCdoo2
	};

	static const decision_node Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2 = {
		&Gen,
		&doo,
		99,
		&Gendoo67_Gendoo35_Gendoo3_SCdoo2
	};

	static const decision_node Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2 = {
		&Gen,
		&doo,
		163,
		&Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2
	};

	static const decision_node Gendoo195_Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2 = {
		&Gen,
		&doo,
		195,
		&Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2
	};

	static const decision_node Gendoo227_Gendoo195_Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2 = {
		&Gen,
		&doo,
		227,
		&Gendoo195_Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2
	};

	static const decision_node Fv2 = {
		&F,
		&v,
		2,
		NULL
	};

	static const decision_node Ma0_Fv2 = {
		&M,
		&a,
		0,
		&Fv2
	};

	static const decision_node Gv0_Ma0_Fv2 = {
		&G,
		&v,
		0,
		&Ma0_Fv2
	};

	static const decision_node SCv3_Gv0_Ma0_Fv2 = {
		&SC,
		&v,
		3,
		&Gv0_Ma0_Fv2
	};

	static const decision_node Gw0 = {
		&G,
		&w,
		0,
		NULL
	};

	static const decision_node Ew0_Gw0 = {
		&E,
		&w,
		0,
		&Gw0
	};

	static const decision_node Ivs4 = {
		&I,
		&vs,
		4,
		NULL
	};

	static const decision_node SCm3_Ivs4 = {
		&SC,
		&m,
		3,
		&Ivs4
	};

	static const decision_node Evqp0_Ipas4 = {
		&E,
		&vqp,
		0,
		&Ipas4
	};

	static const decision_node Gvqp1_Evqp0_Ipas4 = {
		&G,
		&vqp,
		1,
		&Evqp0_Ipas4
	};

	static const decision_node Ibss4 = {
		&I,
		&bss,
		4,
		NULL
	};

	static const decision_node SCm3_Ibss4 = {
		&SC,
		&m,
		3,
		&Ibss4
	};

	static const decision_node Ibs4 = {
		&I,
		&bs,
		4,
		NULL
	};

	static const decision_node Evqp0_Ibs4 = {
		&E,
		&vqp,
		0,
		&Ibs4
	};

	static const decision_node Gvqp1_Evqp0_Ibs4 = {
		&G,
		&vqp,
		1,
		&Evqp0_Ibs4
	};

	static const decision_node Genw66 = {
		&Gen,
		&w,
		66,
		NULL
	};

	static const decision_node Yb3_Genw66 = {
		&Y,
		&b,
		3,
		&Genw66
	};

	static const decision_node Ywo3_Genw66 = {
		&Y,
		&wo,
		3,
		&Genw66
	};

	static const decision_node Ydoo3_Genw66 = {
		&Y,
		&doo,
		3,
		&Genw66
	};

	static const decision_node Xb2 = {
		&X,
		&b,
		2,
		NULL
	};

	static const decision_node Genw67_Xb2 = {
		&Gen,
		&w,
		67,
		&Xb2
	};

	static const decision_node Xwo2 = {
		&X,
		&wo,
		2,
		NULL
	};

	static const decision_node Genw67_Xwo2 = {
		&Gen,
		&w,
		67,
		&Xwo2
	};

	static const decision_node Xdoo2 = {
		&X,
		&doo,
		2,
		NULL
	};

	static const decision_node Genw67_Xdoo2 = {
		&Gen,
		&w,
		67,
		&Xdoo2
	};

	static const decision_node Jbs4 = {
		&J,
		&bs,
		4,
		NULL
	};

	static const decision_node Eb1_Ib0 = {
		&E,
		&b,
		1,
		&Ib0
	};

	static const decision_node Eb0_Ib0 = {
		&E,
		&b,
		0,
		&Ib0
	};

	static const decision_node Evqp1_Ipas4 = {
		&E,
		&vqp,
		1,
		&Ipas4
	};

	static const decision_node Evqp1_Ibs4 = {
		&E,
		&vqp,
		1,
		&Ibs4
	};

	static const decision_node Gb1_Eb1 = {
		&G,
		&b,
		1,
		&Eb1
	};

	static const decision_node Evqp1 = {
		&E,
		&vqp,
		1,
		NULL
	};

	static const decision_node Gvqp1_Evqp1 = {
		&G,
		&vqp,
		1,
		&Evqp1
	};

	static const decision_node Sw0 = {
		&S,
		&w,
		0,
		NULL
	};

	static const decision_node Mw1_Sw0 = {
		&M,
		&w,
		1,
		&Sw0
	};

	static const decision_node Rvqp1_Sw0 = {
		&R,
		&vqp,
		1,
		&Sw0
	};

	static const decision_node Gvqp1_M0 = {
		&G,
		&vqp,
		1,
		&M0
	};

	static const decision_node Sw1_Ew0 = {
		&S,
		&w,
		1,
		&Ew0
	};

	static const decision_node Ev1_SCv2 = {
		&E,
		&v,
		1,
		&SCv2
	};

	static const decision_node Genvqp1 = {
		&Gen,
		&vqp,
		1,
		NULL
	};

	static const decision_node Zvqp1_Genvqp1 = {
		&Z,
		&vqp,
		1,
		&Genvqp1
	};

	static const decision_node Genb2 = {
		&Gen,
		&b,
		2,
		NULL
	};

	static const decision_node Genwo3_Genb2 = {
		&Gen,
		&wo,
		3,
		&Genb2
	};

	static const decision_node Genw2 = {
		&Gen,
		&w,
		2,
		NULL
	};

	static const decision_node Gendoo3_Genw2 = {
		&Gen,
		&doo,
		3,
		&Genw2
	};

	static const decision_node Genwo2 = {
		&Gen,
		&wo,
		2,
		NULL
	};

	static const decision_node Genwo67_Genwo2 = {
		&Gen,
		&wo,
		67,
		&Genwo2
	};

	static const decision_node Gendoo2 = {
		&Gen,
		&doo,
		2,
		NULL
	};

	static const decision_node Gendoo67_Gendoo2 = {
		&Gen,
		&doo,
		67,
		&Gendoo2
	};

	static const decision_node Ap0 = {
		&A,
		&p,
		0,
		NULL
	};

	static const decision_node SCp3_Ap0 = {
		&SC,
		&p,
		3,
		&Ap0
	};

	static const decision_node Fwo2 = {
		&F,
		&wo,
		2,
		NULL
	};

	static const decision_node SCwo3_Fwo2 = {
		&SC,
		&wo,
		3,
		&Fwo2
	};

	static const decision_node Fdoo2 = {
		&F,
		&doo,
		2,
		NULL
	};

	static const decision_node SCdoo3_Fdoo2 = {
		&SC,
		&doo,
		3,
		&Fdoo2
	};

	static const decision_node Fwo3_SCwo2 = {
		&F,
		&wo,
		3,
		&SCwo2
	};

	static const decision_node Fdoo3_SCdoo2 = {
		&F,
		&doo,
		3,
		&SCdoo2
	};

	static const decision_node Genb130 = {
		&Gen,
		&b,
		130,
		NULL
	};

	static const decision_node Ob0 = {
		&O,
		&b,
		0,
		NULL
	};

	static const decision_node Genb1_Ob0 = {
		&Gen,
		&b,
		1,
		&Ob0
	};

	static const decision_node Ovqp0 = {
		&O,
		&vqp,
		0,
		NULL
	};

	static const decision_node Genvqp1_Ovqp0 = {
		&Gen,
		&vqp,
		1,
		&Ovqp0
	};

	static const decision_node Genb0 = {
		&Gen,
		&b,
		0,
		NULL
	};

	static const decision_node Ob1_Genb0 = {
		&O,
		&b,
		1,
		&Genb0
	};

	static const decision_node Genvqp0 = {
		&Gen,
		&vqp,
		0,
		NULL
	};

	static const decision_node Ovqp1_Genvqp0 = {
		&O,
		&vqp,
		1,
		&Genvqp0
	};

	static const decision_node Yb3_Xb2 = {
		&Y,
		&b,
		3,
		&Xb2
	};

	static const decision_node Ywo3_Xwo2 = {
		&Y,
		&wo,
		3,
		&Xwo2
	};

	static const decision_node Ydoo3_Xdoo2 = {
		&Y,
		&doo,
		3,
		&Xdoo2
	};

	static const decision_node Yb2_Xb2 = {
		&Y,
		&b,
		2,
		&Xb2
	};

	static const decision_node Ywo2_Xwo2 = {
		&Y,
		&wo,
		2,
		&Xwo2
	};

	static const decision_node Ydoo2_Xdoo2 = {
		&Y,
		&doo,
		2,
		&Xdoo2
	};

	static const decision_node Yb3_Genb2 = {
		&Y,
		&b,
		3,
		&Genb2
	};

	static const decision_node Ywo3_Genwo2 = {
		&Y,
		&wo,
		3,
		&Genwo2
	};

	static const decision_node Ydoo3_Gendoo2 = {
		&Y,
		&doo,
		3,
		&Gendoo2
	};

	static const decision_node Genb3_Xb2 = {
		&Gen,
		&b,
		3,
		&Xb2
	};

	static const decision_node Genwo3_Xwo2 = {
		&Gen,
		&wo,
		3,
		&Xwo2
	};

	static const decision_node Gendoo3_Xdoo2 = {
		&Gen,
		&doo,
		3,
		&Xdoo2
	};

	static const decision_node Yb2_Genb2 = {
		&Y,
		&b,
		2,
		&Genb2
	};

	static const decision_node Ywo2_Genwo2 = {
		&Y,
		&wo,
		2,
		&Genwo2
	};

	static const decision_node Ydoo2_Gendoo2 = {
		&Y,
		&doo,
		2,
		&Gendoo2
	};

	static const decision_node Zb1_Ib0 = {
		&Z,
		&b,
		1,
		&Ib0
	};

	static const decision_node Ivqp0 = {
		&I,
		&vqp,
		0,
		NULL
	};

	static const decision_node Zvqp1_Ivqp0 = {
		&Z,
		&vqp,
		1,
		&Ivqp0
	};

	static const decision_node Iw0 = {
		&I,
		&w,
		0,
		NULL
	};

	static const decision_node SCw2_Iw0 = {
		&SC,
		&w,
		2,
		&Iw0
	};

	static const decision_node SCm2 = {
		&SC,
		&m,
		2,
		NULL
	};

	static const decision_node Mp0 = {
		&M,
		&p,
		0,
		NULL
	};

	static const decision_node Gv1_Mp0 = {
		&G,
		&v,
		1,
		&Mp0
	};

	static const decision_node Segw3_Gv1_Mp0 = {
		&Seg,
		&w,
		3,
		&Gv1_Mp0
	};

	static const decision_node Segw99_Gv1_Mp0 = {
		&Seg,
		&w,
		99,
		&Gv1_Mp0
	};

	static const decision_node Iw0_Ib0 = {
		&I,
		&w,
		0,
		&Ib0
	};

	static const decision_node Genv163_Iw0_Ib0 = {
		&Gen,
		&v,
		163,
		&Iw0_Ib0
	};

	static const decision_node SCw3_Genv163_Iw0_Ib0 = {
		&SC,
		&w,
		3,
		&Genv163_Iw0_Ib0
	};

	static const decision_node Genv163_SCv2 = {
		&Gen,
		&v,
		163,
		&SCv2
	};

	static const decision_node Iw0_SCw2 = {
		&I,
		&w,
		0,
		&SCw2
	};

	static const decision_node I3b0_Fv2 = {
		&I3,
		&b,
		0,
		&Fv2
	};

	static const decision_node SCv3_I3b0_Fv2 = {
		&SC,
		&v,
		3,
		&I3b0_Fv2
	};

	static const decision_node Ib0_Fv2 = {
		&I,
		&b,
		0,
		&Fv2
	};

	static const decision_node SCb3_Ib0_Fv2 = {
		&SC,
		&b,
		3,
		&Ib0_Fv2
	};

	static const decision_node SCv3_Fv2 = {
		&SC,
		&v,
		3,
		&Fv2
	};

	static const decision_node I1b0 = {
		&I1,
		&b,
		0,
		NULL
	};

	static const decision_node Eb1_I1b0 = {
		&E,
		&b,
		1,
		&I1b0
	};

	static const decision_node Evqp1_I1b0 = {
		&E,
		&vqp,
		1,
		&I1b0
	};

	static const decision_node Eb1_Genb32 = {
		&E,
		&b,
		1,
		&Genb32
	};

	static const decision_node Evqp1_Genb32 = {
		&E,
		&vqp,
		1,
		&Genb32
	};

	static const decision_node BBb2 = {
		&BB,
		&b,
		2,
		NULL
	};

	static const decision_node Genb3_BBb2 = {
		&Gen,
		&b,
		3,
		&BBb2
	};

	static const decision_node Msr0 = {
		&M,
		&sr,
		0,
		NULL
	};

	static const decision_node X87fpu3_Msr0 = {
		&X87fpu,
		NULL,
		3,
		&Msr0
	};

	static const decision_node EST0 = {
		&EST,
		NULL,
		0,
		NULL
	};

	static const decision_node X87fpu1_EST0 = {
		&X87fpu,
		NULL,
		1,
		&EST0
	};

	static const decision_node ESsr0 = {
		&ES,
		&sr,
		0,
		NULL
	};

	static const decision_node X87fpu2_ESsr0 = {
		&X87fpu,
		NULL,
		2,
		&ESsr0
	};

	static const decision_node X87fpu3_ESsr0 = {
		&X87fpu,
		NULL,
		3,
		&ESsr0
	};

	static const decision_node EST1 = {
		&EST,
		NULL,
		1,
		NULL
	};

	static const decision_node X87fpu3_EST1 = {
		&X87fpu,
		NULL,
		3,
		&EST1
	};

	static const decision_node X87fpu2 = {
		&X87fpu,
		NULL,
		2,
		NULL
	};

	static const decision_node Msr1_X87fpu2 = {
		&M,
		&sr,
		1,
		&X87fpu2
	};

	static const decision_node EST1_X87fpu2 = {
		&EST,
		NULL,
		1,
		&X87fpu2
	};

	static const decision_node Me0 = {
		&M,
		&e,
		0,
		NULL
	};

	static const decision_node X87fpu3 = {
		&X87fpu,
		NULL,
		3,
		NULL
	};

	static const decision_node Me1 = {
		&M,
		&e,
		1,
		NULL
	};

	static const decision_node X87fpu35_X87fpu2 = {
		&X87fpu,
		NULL,
		35,
		&X87fpu2
	};

	static const decision_node X87fpu34 = {
		&X87fpu,
		NULL,
		34,
		NULL
	};

	static const decision_node X87fpu3_X87fpu34 = {
		&X87fpu,
		NULL,
		3,
		&X87fpu34
	};

	static const decision_node Mw1 = {
		&M,
		&w,
		1,
		NULL
	};

	static const decision_node Mdi0 = {
		&M,
		&di,
		0,
		NULL
	};

	static const decision_node X87fpu3_Mdi0 = {
		&X87fpu,
		NULL,
		3,
		&Mdi0
	};

	static const decision_node X87fpu2_Mdi0 = {
		&X87fpu,
		NULL,
		2,
		&Mdi0
	};

	static const decision_node X87fpu2_X87fpu34 = {
		&X87fpu,
		NULL,
		2,
		&X87fpu34
	};

	static const decision_node Mdi1_X87fpu2 = {
		&M,
		&di,
		1,
		&X87fpu2
	};

	static const decision_node Mer0 = {
		&M,
		&er,
		0,
		NULL
	};

	static const decision_node X87fpu3_Mer0 = {
		&X87fpu,
		NULL,
		3,
		&Mer0
	};

	static const decision_node X87fpu0_EST0 = {
		&X87fpu,
		NULL,
		0,
		&EST0
	};

	static const decision_node Mer1_X87fpu2 = {
		&M,
		&er,
		1,
		&X87fpu2
	};

	static const decision_node Mdr0 = {
		&M,
		&dr,
		0,
		NULL
	};

	static const decision_node X87fpu3_Mdr0 = {
		&X87fpu,
		NULL,
		3,
		&Mdr0
	};

	static const decision_node X87fpu0 = {
		&X87fpu,
		NULL,
		0,
		NULL
	};

	static const decision_node EST1_X87fpu0 = {
		&EST,
		NULL,
		1,
		&X87fpu0
	};

	static const decision_node X87fpu2_Mdr0 = {
		&X87fpu,
		NULL,
		2,
		&Mdr0
	};

	static const decision_node X87fpu2_EST0 = {
		&X87fpu,
		NULL,
		2,
		&EST0
	};

	static const decision_node Mqi1_X87fpu2 = {
		&M,
		&qi,
		1,
		&X87fpu2
	};

	static const decision_node Mdr1_X87fpu2 = {
		&M,
		&dr,
		1,
		&X87fpu2
	};

	static const decision_node X87fpu3_EST0 = {
		&X87fpu,
		NULL,
		3,
		&EST0
	};

	static const decision_node Mst0 = {
		&M,
		&st,
		0,
		NULL
	};

	static const decision_node X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		227,
		&Mst0
	};

	static const decision_node X87fpu195_X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		195,
		&X87fpu227_Mst0
	};

	static const decision_node X87fpu163_X87fpu195_X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		163,
		&X87fpu195_X87fpu227_Mst0
	};

	static const decision_node X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		131,
		&X87fpu163_X87fpu195_X87fpu227_Mst0
	};

	static const decision_node X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		99,
		&X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0
	};

	static const decision_node X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		67,
		&X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0
	};

	static const decision_node X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		35,
		&X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0
	};

	static const decision_node X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0 = {
		&X87fpu,
		NULL,
		3,
		&X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0
	};

	static const decision_node X87fpu226 = {
		&X87fpu,
		NULL,
		226,
		NULL
	};

	static const decision_node X87fpu194_X87fpu226 = {
		&X87fpu,
		NULL,
		194,
		&X87fpu226
	};

	static const decision_node X87fpu162_X87fpu194_X87fpu226 = {
		&X87fpu,
		NULL,
		162,
		&X87fpu194_X87fpu226
	};

	static const decision_node X87fpu130_X87fpu162_X87fpu194_X87fpu226 = {
		&X87fpu,
		NULL,
		130,
		&X87fpu162_X87fpu194_X87fpu226
	};

	static const decision_node X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226 = {
		&X87fpu,
		NULL,
		98,
		&X87fpu130_X87fpu162_X87fpu194_X87fpu226
	};

	static const decision_node X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226 = {
		&X87fpu,
		NULL,
		66,
		&X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226
	};

	static const decision_node X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226 = {
		&X87fpu,
		NULL,
		34,
		&X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226
	};

	static const decision_node X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226 = {
		&X87fpu,
		NULL,
		2,
		&X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226
	};

	static const decision_node Mst1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226 = {
		&M,
		&st,
		1,
		&X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226
	};

	static const decision_node Mwi0 = {
		&M,
		&wi,
		0,
		NULL
	};

	static const decision_node X87fpu3_Mwi0 = {
		&X87fpu,
		NULL,
		3,
		&Mwi0
	};

	static const decision_node X87fpu2_Mwi0 = {
		&X87fpu,
		NULL,
		2,
		&Mwi0
	};

	static const decision_node Mwi1_X87fpu2 = {
		&M,
		&wi,
		1,
		&X87fpu2
	};

	static const decision_node Mbcd0 = {
		&M,
		&bcd,
		0,
		NULL
	};

	static const decision_node X87fpu3_Mbcd0 = {
		&X87fpu,
		NULL,
		3,
		&Mbcd0
	};

	static const decision_node Genw1 = {
		&Gen,
		&w,
		1,
		NULL
	};

	static const decision_node Mqi0 = {
		&M,
		&qi,
		0,
		NULL
	};

	static const decision_node X87fpu3_Mqi0 = {
		&X87fpu,
		NULL,
		3,
		&Mqi0
	};

	static const decision_node Mbcd1_X87fpu2 = {
		&M,
		&bcd,
		1,
		&X87fpu2
	};

	static const decision_node Genva35_Jbs4 = {
		&Gen,
		&va,
		35,
		&Jbs4
	};

	static const decision_node Genda34 = {
		&Gen,
		&da,
		34,
		NULL
	};

	static const decision_node Jbs4_Genda34 = {
		&J,
		&bs,
		4,
		&Genda34
	};

	static const decision_node Genv1_Ib0 = {
		&Gen,
		&v,
		1,
		&Ib0
	};

	static const decision_node Ib1_Genb0 = {
		&I,
		&b,
		1,
		&Genb0
	};

	static const decision_node Genv0 = {
		&Gen,
		&v,
		0,
		NULL
	};

	static const decision_node Ib1_Genv0 = {
		&I,
		&b,
		1,
		&Genv0
	};

	static const decision_node SCpas7_Jpas4 = {
		&SC,
		&pas,
		7,
		&Jpas4
	};

	static const decision_node Genw64 = {
		&Gen,
		&w,
		64,
		NULL
	};

	static const decision_node Genb1_Genw64 = {
		&Gen,
		&b,
		1,
		&Genw64
	};

	static const decision_node Genv1_Genw64 = {
		&Gen,
		&v,
		1,
		&Genw64
	};

	static const decision_node Genw65_Genb0 = {
		&Gen,
		&w,
		65,
		&Genb0
	};

	static const decision_node Genw65_Genv0 = {
		&Gen,
		&w,
		65,
		&Genv0
	};

	static const decision_node Genb2_Eb0 = {
		&Gen,
		&b,
		2,
		&Eb0
	};

	static const decision_node Genw3_Genb2_Eb0 = {
		&Gen,
		&w,
		3,
		&Genb2_Eb0
	};

	static const decision_node Genw2_Eb0 = {
		&Gen,
		&w,
		2,
		&Eb0
	};

	static const decision_node Genb131_Genw2_Eb0 = {
		&Gen,
		&b,
		131,
		&Genw2_Eb0
	};

	static const decision_node Genb3_Genb131_Genw2_Eb0 = {
		&Gen,
		&b,
		3,
		&Genb131_Genw2_Eb0
	};

	static const decision_node Evqp0_Ivqp0 = {
		&E,
		&vqp,
		0,
		&Ivqp0
	};

	static const decision_node Genvqp3_Evqp0 = {
		&Gen,
		&vqp,
		3,
		&Evqp0
	};

	static const decision_node Genvqp67_Genvqp3_Evqp0 = {
		&Gen,
		&vqp,
		67,
		&Genvqp3_Evqp0
	};

	static const decision_node SCv3_Ev0 = {
		&SC,
		&v,
		3,
		&Ev0
	};

	static const decision_node SCptp3_Mptp0 = {
		&SC,
		&ptp,
		3,
		&Mptp0
	};

	static const pa_x86_instruction_context add_context_Eb1_Gb0 = {
		VD_X86_INS_ADD,
		3,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context add_context_Evqp1_Gvqp0 = {
		VD_X86_INS_ADD,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context add_context_Gb1_Eb0 = {
		VD_X86_INS_ADD,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context add_context_Gvqp1_Evqp0 = {
		VD_X86_INS_ADD,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context add_context_Genb1_Ib0 = {
		VD_X86_INS_ADD,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context add_context_Genvqp1_Ipas4 = {
		VD_X86_INS_ADD,
		0,
		&Genvqp1_Ipas4
	};

	static const pa_x86_instruction_context push_context_SCw3_S2w0 = {
		VD_X86_INS_PUSH,
		0,
		&SCw3_S2w0
	};

	static const pa_x86_instruction_context pop_context_S2w1_SCw2 = {
		VD_X86_INS_POP,
		0,
		&S2w1_SCw2
	};

	static const pa_x86_instruction_context or_context_Eb1_Gb0 = {
		VD_X86_INS_OR,
		3,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context or_context_Evqp1_Gvqp0 = {
		VD_X86_INS_OR,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context or_context_Gb1_Eb0 = {
		VD_X86_INS_OR,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context or_context_Gvqp1_Evqp0 = {
		VD_X86_INS_OR,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context or_context_Genb1_Ib0 = {
		VD_X86_INS_OR,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context or_context_Genvqp1_Ipas4 = {
		VD_X86_INS_OR,
		0,
		&Genvqp1_Ipas4
	};

	static const pa_x86_instruction_context sldt_context_Mw1_ldtr2 = {
		VD_X86_INS_SLDT,
		1,
		&Mw1_ldtr2
	};

	static const pa_x86_instruction_context sldt_context_Rvqp1_ldtr2 = {
		VD_X86_INS_SLDT,
		1,
		&Rvqp1_ldtr2
	};

	static const pa_x86_instruction_context str_context_Mw1_tr2 = {
		VD_X86_INS_STR,
		1,
		&Mw1_tr2
	};

	static const pa_x86_instruction_context str_context_Rvqp1_tr2 = {
		VD_X86_INS_STR,
		1,
		&Rvqp1_tr2
	};

	static const pa_x86_instruction_context lldt_context_ldtr3_Ew0 = {
		VD_X86_INS_LLDT,
		1,
		&ldtr3_Ew0
	};

	static const pa_x86_instruction_context ltr_context_tr3_Ew0 = {
		VD_X86_INS_LTR,
		1,
		&tr3_Ew0
	};

	static const pa_x86_instruction_context verr_context_Ew0 = {
		VD_X86_INS_VERR,
		1,
		&Ew0
	};

	static const pa_x86_instruction_context verw_context_Ew0 = {
		VD_X86_INS_VERW,
		1,
		&Ew0
	};

	static const pa_x86_instruction_context jmpe_context = {
		VD_X86_INS_JMPE,
		1,
		NULL
	};

	static const pa_x86_instruction_context sgdt_context_Ms1_gdtr2 = {
		VD_X86_INS_SGDT,
		1,
		&Ms1_gdtr2
	};

	static const pa_x86_instruction_context vmcall_context = {
		VD_X86_INS_VMCALL,
		1,
		NULL
	};

	static const pa_x86_instruction_context vmlaunch_context = {
		VD_X86_INS_VMLAUNCH,
		1,
		NULL
	};

	static const pa_x86_instruction_context vmresume_context = {
		VD_X86_INS_VMRESUME,
		1,
		NULL
	};

	static const pa_x86_instruction_context vmxoff_context = {
		VD_X86_INS_VMXOFF,
		1,
		NULL
	};

	static const pa_x86_instruction_context sidt_context_Ms1_idtr2 = {
		VD_X86_INS_SIDT,
		1,
		&Ms1_idtr2
	};

	static const pa_x86_instruction_context monitor_context_BAb2_Gend34_Gend66 = {
		VD_X86_INS_MONITOR,
		1,
		&BAb2_Gend34_Gend66
	};

	static const pa_x86_instruction_context mwait_context_Gend2_Gend34 = {
		VD_X86_INS_MWAIT,
		1,
		&Gend2_Gend34
	};

	static const pa_x86_instruction_context lgdt_context_gdtr3_Ms0 = {
		VD_X86_INS_LGDT,
		1,
		&gdtr3_Ms0
	};

	static const pa_x86_instruction_context xgetbv_context_Gend67_Gend3_Gend34_xcr2 = {
		VD_X86_INS_XGETBV,
		1,
		&Gend67_Gend3_Gend34_xcr2
	};

	static const pa_x86_instruction_context xsetbv_context_xcr3_Gend34_Gend66_Gend2 = {
		VD_X86_INS_XSETBV,
		1,
		&xcr3_Gend34_Gend66_Gend2
	};

	static const pa_x86_instruction_context lidt_context_idtr3_Ms0 = {
		VD_X86_INS_LIDT,
		1,
		&idtr3_Ms0
	};

	static const pa_x86_instruction_context smsw_context_Mw1_msww2 = {
		VD_X86_INS_SMSW,
		1,
		&Mw1_msww2
	};

	static const pa_x86_instruction_context smsw_context_Rvqp1_msww2 = {
		VD_X86_INS_SMSW,
		1,
		&Rvqp1_msww2
	};

	static const pa_x86_instruction_context lmsw_context_msww3_Ew0 = {
		VD_X86_INS_LMSW,
		1,
		&msww3_Ew0
	};

	static const pa_x86_instruction_context invlpg_context_M0 = {
		VD_X86_INS_INVLPG,
		1,
		&M0
	};

	static const pa_x86_instruction_context rdtscp_context_Gend3_Gend67_Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2 = {
		VD_X86_INS_RDTSCP,
		1,
		&Gend3_Gend67_Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2
	};

	static const pa_x86_instruction_context lar_context_Gvqp1_Mw0 = {
		VD_X86_INS_LAR,
		1,
		&Gvqp1_Mw0
	};

	static const pa_x86_instruction_context lar_context_Gvqp1_Rv0 = {
		VD_X86_INS_LAR,
		1,
		&Gvqp1_Rv0
	};

	static const pa_x86_instruction_context lsl_context_Gvqp1_Mw0 = {
		VD_X86_INS_LSL,
		1,
		&Gvqp1_Mw0
	};

	static const pa_x86_instruction_context lsl_context_Gvqp1_Rv0 = {
		VD_X86_INS_LSL,
		1,
		&Gvqp1_Rv0
	};

	static const pa_x86_instruction_context clts_context_cr03 = {
		VD_X86_INS_CLTS,
		0,
		&cr03
	};

	static const pa_x86_instruction_context inpa_context = {
		VD_X86_INS_INVD,
		0,
		NULL
	};

	static const pa_x86_instruction_context wbinpa_context = {
		VD_X86_INS_WBINVD,
		0,
		NULL
	};

	static const pa_x86_instruction_context nop_context_Ev0 = {
		VD_X86_INS_NOP,
		0,
		&Ev0
	};

	static const pa_x86_instruction_context movups_context_Vps1_Wps0 = {
		VD_X86_INS_MOVUPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context movupd_context_Vpd1_Wpd0 = {
		VD_X86_INS_MOVUPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context movsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_MOVSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context movss_context_Vss1_Wss0 = {
		VD_X86_INS_MOVSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context movups_context_Wps1_Vps0 = {
		VD_X86_INS_MOVUPS,
		1,
		&Wps1_Vps0
	};

	static const pa_x86_instruction_context movupd_context_Wpd1_Vpd0 = {
		VD_X86_INS_MOVUPD,
		1,
		&Wpd1_Vpd0
	};

	static const pa_x86_instruction_context movsd_context_Wsd1_Vsd0 = {
		VD_X86_INS_MOVSD,
		1,
		&Wsd1_Vsd0
	};

	static const pa_x86_instruction_context movss_context_Wss1_Vss0 = {
		VD_X86_INS_MOVSS,
		1,
		&Wss1_Vss0
	};

	static const pa_x86_instruction_context movlps_context_Vq1_Mq0 = {
		VD_X86_INS_MOVLPS,
		1,
		&Vq1_Mq0
	};

	static const pa_x86_instruction_context movhlps_context_Vq1_Uq0 = {
		VD_X86_INS_MOVHLPS,
		1,
		&Vq1_Uq0
	};

	static const pa_x86_instruction_context movlpd_context_Vq1_Mq0 = {
		VD_X86_INS_MOVLPD,
		1,
		&Vq1_Mq0
	};

	static const pa_x86_instruction_context mopadup_context_Vq1_Wq0 = {
		VD_X86_INS_MOVDDUP,
		1,
		&Vq1_Wq0
	};

	static const pa_x86_instruction_context movsldup_context_Vq1_Wq0 = {
		VD_X86_INS_MOVSLDUP,
		1,
		&Vq1_Wq0
	};

	static const pa_x86_instruction_context movlps_context_Mq1_Vq0 = {
		VD_X86_INS_MOVLPS,
		1,
		&Mq1_Vq0
	};

	static const pa_x86_instruction_context movlpd_context_Mq1_Vq0 = {
		VD_X86_INS_MOVLPD,
		1,
		&Mq1_Vq0
	};

	static const pa_x86_instruction_context unpcklps_context_Vps1_Wq0 = {
		VD_X86_INS_UNPCKLPS,
		1,
		&Vps1_Wq0
	};

	static const pa_x86_instruction_context unpcklpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_UNPCKLPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context unpckhps_context_Vps1_Wq0 = {
		VD_X86_INS_UNPCKHPS,
		1,
		&Vps1_Wq0
	};

	static const pa_x86_instruction_context unpckhpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_UNPCKHPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context movhps_context_Vq1_Mq0 = {
		VD_X86_INS_MOVHPS,
		1,
		&Vq1_Mq0
	};

	static const pa_x86_instruction_context movlhps_context_Vq1_Uq0 = {
		VD_X86_INS_MOVLHPS,
		1,
		&Vq1_Uq0
	};

	static const pa_x86_instruction_context movhpd_context_Vq1_Mq0 = {
		VD_X86_INS_MOVHPD,
		1,
		&Vq1_Mq0
	};

	static const pa_x86_instruction_context movshdup_context_Vq1_Wq0 = {
		VD_X86_INS_MOVSHDUP,
		1,
		&Vq1_Wq0
	};

	static const pa_x86_instruction_context movhps_context_Mq1_Vq0 = {
		VD_X86_INS_MOVHPS,
		1,
		&Mq1_Vq0
	};

	static const pa_x86_instruction_context movhpd_context_Mq1_Vq0 = {
		VD_X86_INS_MOVHPD,
		1,
		&Mq1_Vq0
	};

	static const pa_x86_instruction_context prefetchnta_context_Mb0 = {
		VD_X86_INS_PREFETCHNTA,
		1,
		&Mb0
	};

	static const pa_x86_instruction_context prefetcht0_context_Mb0 = {
		VD_X86_INS_PREFETCHT0,
		1,
		&Mb0
	};

	static const pa_x86_instruction_context prefetcht1_context_Mb0 = {
		VD_X86_INS_PREFETCHT1,
		1,
		&Mb0
	};

	static const pa_x86_instruction_context prefetcht2_context_Mb0 = {
		VD_X86_INS_PREFETCHT2,
		1,
		&Mb0
	};

	static const pa_x86_instruction_context hint_nop_context_Ev0 = {
		VD_X86_INS_HINT_NOP,
		1,
		&Ev0
	};

	static const pa_x86_instruction_context mov_context_Hd1_Cd0 = {
		VD_X86_INS_MOV,
		1,
		&Hd1_Cd0
	};

	static const pa_x86_instruction_context mov_context_Hd1_Dd0 = {
		VD_X86_INS_MOV,
		1,
		&Hd1_Dd0
	};

	static const pa_x86_instruction_context mov_context_Cd1_Hd0 = {
		VD_X86_INS_MOV,
		1,
		&Cd1_Hd0
	};

	static const pa_x86_instruction_context mov_context_Dq1_Hq0 = {
		VD_X86_INS_MOV,
		1,
		&Dq1_Hq0
	};

	static const pa_x86_instruction_context mov_context_Hd1_Td0 = {
		VD_X86_INS_MOV,
		1,
		&Hd1_Td0
	};

	static const pa_x86_instruction_context mov_context_Td1_Hd0 = {
		VD_X86_INS_MOV,
		1,
		&Td1_Hd0
	};

	static const pa_x86_instruction_context movaps_context_Vps1_Wps0 = {
		VD_X86_INS_MOVAPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context movapd_context_Vpd1_Wpd0 = {
		VD_X86_INS_MOVAPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context movaps_context_Wps1_Vps0 = {
		VD_X86_INS_MOVAPS,
		1,
		&Wps1_Vps0
	};

	static const pa_x86_instruction_context movapd_context_Wpd1_Vpd0 = {
		VD_X86_INS_MOVAPD,
		1,
		&Wpd1_Vpd0
	};

	static const pa_x86_instruction_context cvtpi2ps_context_Vps1_Qpi0 = {
		VD_X86_INS_CVTPI2PS,
		1,
		&Vps1_Qpi0
	};

	static const pa_x86_instruction_context cvtpi2pd_context_Vpd1_Qpi0 = {
		VD_X86_INS_CVTPI2PD,
		1,
		&Vpd1_Qpi0
	};

	static const pa_x86_instruction_context cvtsi2sd_context_Vsd1_Edqp0 = {
		VD_X86_INS_CVTSI2SD,
		1,
		&Vsd1_Edqp0
	};

	static const pa_x86_instruction_context cvtsi2ss_context_Vss1_Edqp0 = {
		VD_X86_INS_CVTSI2SS,
		1,
		&Vss1_Edqp0
	};

	static const pa_x86_instruction_context movntps_context_Mps1_Vps0 = {
		VD_X86_INS_MOVNTPS,
		1,
		&Mps1_Vps0
	};

	static const pa_x86_instruction_context movntpd_context_Mpd1_Vpd0 = {
		VD_X86_INS_MOVNTPD,
		1,
		&Mpd1_Vpd0
	};

	static const pa_x86_instruction_context cvttps2pi_context_Ppi1_Wpsq0 = {
		VD_X86_INS_CVTTPS2PI,
		1,
		&Ppi1_Wpsq0
	};

	static const pa_x86_instruction_context cvttpd2pi_context_Ppi1_Wpd0 = {
		VD_X86_INS_CVTTPD2PI,
		1,
		&Ppi1_Wpd0
	};

	static const pa_x86_instruction_context cvttsd2si_context_Gdqp1_Wsd0 = {
		VD_X86_INS_CVTTSD2SI,
		1,
		&Gdqp1_Wsd0
	};

	static const pa_x86_instruction_context cvttss2si_context_Gdqp1_Wss0 = {
		VD_X86_INS_CVTTSS2SI,
		1,
		&Gdqp1_Wss0
	};

	static const pa_x86_instruction_context cvtps2pi_context_Ppi1_Wpsq0 = {
		VD_X86_INS_CVTPS2PI,
		1,
		&Ppi1_Wpsq0
	};

	static const pa_x86_instruction_context cvtpd2pi_context_Ppi1_Wpd0 = {
		VD_X86_INS_CVTPD2PI,
		1,
		&Ppi1_Wpd0
	};

	static const pa_x86_instruction_context cvtsd2si_context_Gdqp1_Wsd0 = {
		VD_X86_INS_CVTSD2SI,
		1,
		&Gdqp1_Wsd0
	};

	static const pa_x86_instruction_context cvtss2si_context_Gdqp1_Wss0 = {
		VD_X86_INS_CVTSS2SI,
		1,
		&Gdqp1_Wss0
	};

	static const pa_x86_instruction_context ucomiss_context_Vss0_Wss0 = {
		VD_X86_INS_UCOMISS,
		1,
		&Vss0_Wss0
	};

	static const pa_x86_instruction_context ucomisd_context_Vsd0_Wsd0 = {
		VD_X86_INS_UCOMISD,
		1,
		&Vsd0_Wsd0
	};

	static const pa_x86_instruction_context comiss_context_Vss0_Wss0 = {
		VD_X86_INS_COMISS,
		1,
		&Vss0_Wss0
	};

	static const pa_x86_instruction_context comisd_context_Vsd0_Wsd0 = {
		VD_X86_INS_COMISD,
		1,
		&Vsd0_Wsd0
	};

	static const pa_x86_instruction_context wrmsr_context_msr3_Gendqp34_Gendqp2_Gendqp66 = {
		VD_X86_INS_WRMSR,
		0,
		&msr3_Gendqp34_Gendqp2_Gendqp66
	};

	static const pa_x86_instruction_context rdtsc_context_Gend3_Gend67_ia32_time_stamp_counter2 = {
		VD_X86_INS_RDTSC,
		0,
		&Gend3_Gend67_ia32_time_stamp_counter2
	};

	static const pa_x86_instruction_context rdmsr_context_Gendqp3_Gendqp67_Gendqp34_msr2 = {
		VD_X86_INS_RDMSR,
		0,
		&Gendqp3_Gendqp67_Gendqp34_msr2
	};

	static const pa_x86_instruction_context rdpmc_context_Gend3_Gend67_pmc2 = {
		VD_X86_INS_RDPMC,
		0,
		&Gend3_Gend67_pmc2
	};

	static const pa_x86_instruction_context sysenter_context_S2w3_Gend131_ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2 = {
		VD_X86_INS_SYSENTER,
		0,
		&S2w3_Gend131_ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2
	};

	static const pa_x86_instruction_context sysexit_context_S2w3_Gendqp131_ia32_sysenter_cs2_Gendqp34_Gendqp66 = {
		VD_X86_INS_SYSEXIT,
		0,
		&S2w3_Gendqp131_ia32_sysenter_cs2_Gendqp34_Gendqp66
	};

	static const pa_x86_instruction_context getsec_context_Gend2 = {
		VD_X86_INS_GETSEC,
		0,
		&Gend2
	};

	static const pa_x86_instruction_context pshufb_context_Pq1_Qq0 = {
		VD_X86_INS_PSHUFB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pshufb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSHUFB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context phaddw_context_Pq1_Qq0 = {
		VD_X86_INS_PHADDW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context phaddw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PHADDW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context phaddd_context_Pq1_Qq0 = {
		VD_X86_INS_PHADDD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context phaddd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PHADDD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context phaddsw_context_Pq1_Qq0 = {
		VD_X86_INS_PHADDSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context phaddsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PHADDSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaddubsw_context_Pq1_Qq0 = {
		VD_X86_INS_PMADDUBSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmaddubsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMADDUBSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context phsubw_context_Pq1_Qq0 = {
		VD_X86_INS_PHSUBW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context phsubw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PHSUBW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context phsubd_context_Pq1_Qq0 = {
		VD_X86_INS_PHSUBD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context phsubd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PHSUBD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context phsubsw_context_Pq1_Qq0 = {
		VD_X86_INS_PHSUBSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context phsubsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PHSUBSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psignb_context_Pq1_Qq0 = {
		VD_X86_INS_PSIGNB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psignb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSIGNB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psignw_context_Pq1_Qq0 = {
		VD_X86_INS_PSIGNW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psignw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSIGNW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psignd_context_Pq1_Qq0 = {
		VD_X86_INS_PSIGND,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psignd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSIGND,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmulhrsw_context_Pq1_Qq0 = {
		VD_X86_INS_PMULHRSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmulhrsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMULHRSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pblendvb_context_Vdq1_Wdq0_Xmm2 = {
		VD_X86_INS_PBLENDVB,
		1,
		&Vdq1_Wdq0_Xmm2
	};

	static const pa_x86_instruction_context blendvps_context_Vps1_Wps0_Xmm2 = {
		VD_X86_INS_BLENDVPS,
		1,
		&Vps1_Wps0_Xmm2
	};

	static const pa_x86_instruction_context blendvpd_context_Vpd1_Wpd0_Xmm2 = {
		VD_X86_INS_BLENDVPD,
		1,
		&Vpd1_Wpd0_Xmm2
	};

	static const pa_x86_instruction_context ptest_context_Vdq0_Wdq0 = {
		VD_X86_INS_PTEST,
		1,
		&Vdq0_Wdq0
	};

	static const pa_x86_instruction_context pabsb_context_Pq1_Qq0 = {
		VD_X86_INS_PABSB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pabsb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PABSB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pabsw_context_Pq1_Qq0 = {
		VD_X86_INS_PABSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pabsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PABSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pabsd_context_Pq1_Qq0 = {
		VD_X86_INS_PABSD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pabsd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PABSD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmovsxbw_context_Vdq1_Mq0 = {
		VD_X86_INS_PMOVSXBW,
		1,
		&Vdq1_Mq0
	};

	static const pa_x86_instruction_context pmovsxbw_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVSXBW,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovsxbd_context_Vdq1_Md0 = {
		VD_X86_INS_PMOVSXBD,
		1,
		&Vdq1_Md0
	};

	static const pa_x86_instruction_context pmovsxbd_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVSXBD,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovsxbq_context_Vdq1_Mw0 = {
		VD_X86_INS_PMOVSXBQ,
		1,
		&Vdq1_Mw0
	};

	static const pa_x86_instruction_context pmovsxbq_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVSXBQ,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovsxwd_context_Vdq1_Mq0 = {
		VD_X86_INS_PMOVSXWD,
		1,
		&Vdq1_Mq0
	};

	static const pa_x86_instruction_context pmovsxwd_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVSXWD,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovsxwq_context_Vdq1_Md0 = {
		VD_X86_INS_PMOVSXWQ,
		1,
		&Vdq1_Md0
	};

	static const pa_x86_instruction_context pmovsxwq_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVSXWQ,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovsxdq_context_Vdq1_Mq0 = {
		VD_X86_INS_PMOVSXDQ,
		1,
		&Vdq1_Mq0
	};

	static const pa_x86_instruction_context pmovsxdq_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVSXDQ,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmuldq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMULDQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pcmpeqq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPEQQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context movntdqa_context_Vdq1_Mdq0 = {
		VD_X86_INS_MOVNTDQA,
		1,
		&Vdq1_Mdq0
	};

	static const pa_x86_instruction_context packusdw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PACKUSDW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmovzxbw_context_Vdq1_Mq0 = {
		VD_X86_INS_PMOVZXBW,
		1,
		&Vdq1_Mq0
	};

	static const pa_x86_instruction_context pmovzxbw_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVZXBW,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovzxbd_context_Vdq1_Md0 = {
		VD_X86_INS_PMOVZXBD,
		1,
		&Vdq1_Md0
	};

	static const pa_x86_instruction_context pmovzxbd_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVZXBD,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovzxbq_context_Vdq1_Mw0 = {
		VD_X86_INS_PMOVZXBQ,
		1,
		&Vdq1_Mw0
	};

	static const pa_x86_instruction_context pmovzxbq_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVZXBQ,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovzxwd_context_Vdq1_Mq0 = {
		VD_X86_INS_PMOVZXWD,
		1,
		&Vdq1_Mq0
	};

	static const pa_x86_instruction_context pmovzxwd_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVZXWD,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovzxwq_context_Vdq1_Md0 = {
		VD_X86_INS_PMOVZXWQ,
		1,
		&Vdq1_Md0
	};

	static const pa_x86_instruction_context pmovzxwq_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVZXWQ,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pmovzxdq_context_Vdq1_Mq0 = {
		VD_X86_INS_PMOVZXDQ,
		1,
		&Vdq1_Mq0
	};

	static const pa_x86_instruction_context pmovzxdq_context_Vdq1_Udq0 = {
		VD_X86_INS_PMOVZXDQ,
		1,
		&Vdq1_Udq0
	};

	static const pa_x86_instruction_context pcmpgtq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPGTQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pminsb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMINSB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pminsd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMINSD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pminuw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMINUW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pminud_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMINUD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaxsb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMAXSB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaxsd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMAXSD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaxuw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMAXUW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaxud_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMAXUD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmulld_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMULLD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context phminposuw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PHMINPOSUW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context invept_context_Gd0_Mdq0 = {
		VD_X86_INS_INVEPT,
		1,
		&Gd0_Mdq0
	};

	static const pa_x86_instruction_context invvpid_context_Gd0_Mdq0 = {
		VD_X86_INS_INVVPID,
		1,
		&Gd0_Mdq0
	};

	static const pa_x86_instruction_context movbe_context_Gvqp1_Mvqp0 = {
		VD_X86_INS_MOVBE,
		1,
		&Gvqp1_Mvqp0
	};

	static const pa_x86_instruction_context crc32_context_Gdqp1_Eb0 = {
		VD_X86_INS_CRC32,
		1,
		&Gdqp1_Eb0
	};

	static const pa_x86_instruction_context movbe_context_Mvqp1_Gvqp0 = {
		VD_X86_INS_MOVBE,
		1,
		&Mvqp1_Gvqp0
	};

	static const pa_x86_instruction_context crc32_context_Gdqp1_Evqp0 = {
		VD_X86_INS_CRC32,
		1,
		&Gdqp1_Evqp0
	};

	static const pa_x86_instruction_context roundps_context_Vps1_Wps0_Ib0 = {
		VD_X86_INS_ROUNDPS,
		1,
		&Vps1_Wps0_Ib0
	};

	static const pa_x86_instruction_context roundpd_context_Vps1_Wpd0_Ib0 = {
		VD_X86_INS_ROUNDPD,
		1,
		&Vps1_Wpd0_Ib0
	};

	static const pa_x86_instruction_context roundss_context_Vss1_Wss0_Ib0 = {
		VD_X86_INS_ROUNDSS,
		1,
		&Vss1_Wss0_Ib0
	};

	static const pa_x86_instruction_context roundsd_context_Vsd1_Wsd0_Ib0 = {
		VD_X86_INS_ROUNDSD,
		1,
		&Vsd1_Wsd0_Ib0
	};

	static const pa_x86_instruction_context blendps_context_Vps1_Wps0_Ib0 = {
		VD_X86_INS_BLENDPS,
		1,
		&Vps1_Wps0_Ib0
	};

	static const pa_x86_instruction_context blendpd_context_Vpd1_Wpd0_Ib0 = {
		VD_X86_INS_BLENDPD,
		1,
		&Vpd1_Wpd0_Ib0
	};

	static const pa_x86_instruction_context pblendw_context_Vdq1_Wdq0_Ib0 = {
		VD_X86_INS_PBLENDW,
		1,
		&Vdq1_Wdq0_Ib0
	};

	static const pa_x86_instruction_context palignr_context_Pq1_Qq0 = {
		VD_X86_INS_PALIGNR,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context palignr_context_Vdq1_Wdq0 = {
		VD_X86_INS_PALIGNR,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pextrb_context_Mb1_Vdq0_Ib0 = {
		VD_X86_INS_PEXTRB,
		1,
		&Mb1_Vdq0_Ib0
	};

	static const pa_x86_instruction_context pextrb_context_Rdqp1_Vdq0_Ib0 = {
		VD_X86_INS_PEXTRB,
		1,
		&Rdqp1_Vdq0_Ib0
	};

	static const pa_x86_instruction_context pextrw_context_Mw1_Vdq0_Ib0 = {
		VD_X86_INS_PEXTRW,
		1,
		&Mw1_Vdq0_Ib0
	};

	static const pa_x86_instruction_context pextrw_context_Rdqp1_Vdq0_Ib0 = {
		VD_X86_INS_PEXTRW,
		1,
		&Rdqp1_Vdq0_Ib0
	};

	static const pa_x86_instruction_context pextrq_context_Eqp1_Vdq0_Ib0 = {
		VD_X86_INS_PEXTRQ,
		1,
		&Eqp1_Vdq0_Ib0
	};

	static const pa_x86_instruction_context extractps_context_Ed1_Vdq0_Ib0 = {
		VD_X86_INS_EXTRACTPS,
		1,
		&Ed1_Vdq0_Ib0
	};

	static const pa_x86_instruction_context pinsrb_context_Vdq1_Mb0_Ib0 = {
		VD_X86_INS_PINSRB,
		1,
		&Vdq1_Mb0_Ib0
	};

	static const pa_x86_instruction_context pinsrb_context_Vdq1_Rdqp0_Ib0 = {
		VD_X86_INS_PINSRB,
		1,
		&Vdq1_Rdqp0_Ib0
	};

	static const pa_x86_instruction_context insertps_context_Vps1_Md0_Ib0 = {
		VD_X86_INS_INSERTPS,
		1,
		&Vps1_Md0_Ib0
	};

	static const pa_x86_instruction_context insertps_context_Vps1_Ups0_Ib0 = {
		VD_X86_INS_INSERTPS,
		1,
		&Vps1_Ups0_Ib0
	};

	static const pa_x86_instruction_context pinsrq_context_Vdq1_Eqp0_Ib0 = {
		VD_X86_INS_PINSRQ,
		1,
		&Vdq1_Eqp0_Ib0
	};

	static const pa_x86_instruction_context dpps_context_Vps1_Wps0 = {
		VD_X86_INS_DPPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context dppd_context_Vpd1_Wpd0 = {
		VD_X86_INS_DPPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context mpsadbw_context_Vdq1_Wdq0_Ib0 = {
		VD_X86_INS_MPSADBW,
		1,
		&Vdq1_Wdq0_Ib0
	};

	static const pa_x86_instruction_context pcmpestrm_context_Xmm3_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66 = {
		VD_X86_INS_PCMPESTRM,
		1,
		&Xmm3_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66
	};

	static const pa_x86_instruction_context pcmpestri_context_Gendqp35_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66 = {
		VD_X86_INS_PCMPESTRI,
		1,
		&Gendqp35_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66
	};

	static const pa_x86_instruction_context pcmpistrm_context_Xmm3_Vdq0_Wdq0_Ib0 = {
		VD_X86_INS_PCMPISTRM,
		1,
		&Xmm3_Vdq0_Wdq0_Ib0
	};

	static const pa_x86_instruction_context pcmpistri_context_Gendqp35_Vdq0_Wdq0_Ib0 = {
		VD_X86_INS_PCMPISTRI,
		1,
		&Gendqp35_Vdq0_Wdq0_Ib0
	};

	static const pa_x86_instruction_context cmovo_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVO,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovno_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVNO,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovc_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVC,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovnc_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVNC,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmove_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVE,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovne_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVNE,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovna_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVNA,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmova_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVA,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovs_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVS,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovns_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVNS,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovpe_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVPE,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovpo_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVPO,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovnge_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVNGE,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovge_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVGE,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovng_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVNG,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmovg_context_Gvqp1_Evqp0 = {
		VD_X86_INS_CMOVG,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context movmskps_context_Gdqp1_Ups0 = {
		VD_X86_INS_MOVMSKPS,
		1,
		&Gdqp1_Ups0
	};

	static const pa_x86_instruction_context movmskpd_context_Gdqp1_Upd0 = {
		VD_X86_INS_MOVMSKPD,
		1,
		&Gdqp1_Upd0
	};

	static const pa_x86_instruction_context sqrtps_context_Vps1_Wps0 = {
		VD_X86_INS_SQRTPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context sqrtpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_SQRTPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context sqrtsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_SQRTSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context sqrtss_context_Vss1_Wss0 = {
		VD_X86_INS_SQRTSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context rsqrtps_context_Vps1_Wps0 = {
		VD_X86_INS_RSQRTPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context rsqrtss_context_Vss1_Wss0 = {
		VD_X86_INS_RSQRTSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context rcpps_context_Vps1_Wps0 = {
		VD_X86_INS_RCPPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context rcpss_context_Vss1_Wss0 = {
		VD_X86_INS_RCPSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context andps_context_Vps1_Wps0 = {
		VD_X86_INS_ANDPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context andpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_ANDPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context andnps_context_Vps1_Wps0 = {
		VD_X86_INS_ANDNPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context andnpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_ANDNPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context orps_context_Vps1_Wps0 = {
		VD_X86_INS_ORPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context orpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_ORPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context xorps_context_Vps1_Wps0 = {
		VD_X86_INS_XORPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context xorpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_XORPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context addps_context_Vps1_Wps0 = {
		VD_X86_INS_ADDPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context addpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_ADDPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context addsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_ADDSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context addss_context_Vss1_Wss0 = {
		VD_X86_INS_ADDSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context mulps_context_Vps1_Wps0 = {
		VD_X86_INS_MULPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context mulpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_MULPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context mulsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_MULSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context mulss_context_Vss1_Wss0 = {
		VD_X86_INS_MULSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context cvtps2pd_context_Vpd1_Wps0 = {
		VD_X86_INS_CVTPS2PD,
		1,
		&Vpd1_Wps0
	};

	static const pa_x86_instruction_context cvtpd2ps_context_Vps1_Wpd0 = {
		VD_X86_INS_CVTPD2PS,
		1,
		&Vps1_Wpd0
	};

	static const pa_x86_instruction_context cvtsd2ss_context_Vss1_Wsd0 = {
		VD_X86_INS_CVTSD2SS,
		1,
		&Vss1_Wsd0
	};

	static const pa_x86_instruction_context cvtss2sd_context_Vsd1_Wss0 = {
		VD_X86_INS_CVTSS2SD,
		1,
		&Vsd1_Wss0
	};

	static const pa_x86_instruction_context cvtdq2ps_context_Vps1_Wdq0 = {
		VD_X86_INS_CVTDQ2PS,
		1,
		&Vps1_Wdq0
	};

	static const pa_x86_instruction_context cvtps2dq_context_Vdq1_Wps0 = {
		VD_X86_INS_CVTPS2DQ,
		1,
		&Vdq1_Wps0
	};

	static const pa_x86_instruction_context cvttps2dq_context_Vdq1_Wps0 = {
		VD_X86_INS_CVTTPS2DQ,
		1,
		&Vdq1_Wps0
	};

	static const pa_x86_instruction_context subps_context_Vps1_Wps0 = {
		VD_X86_INS_SUBPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context subpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_SUBPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context subsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_SUBSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context subss_context_Vss1_Wss0 = {
		VD_X86_INS_SUBSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context minps_context_Vps1_Wps0 = {
		VD_X86_INS_MINPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context minpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_MINPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context minsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_MINSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context minss_context_Vss1_Wss0 = {
		VD_X86_INS_MINSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context divps_context_Vps1_Wps0 = {
		VD_X86_INS_DIVPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context divpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_DIVPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context divsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_DIVSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context divss_context_Vss1_Wss0 = {
		VD_X86_INS_DIVSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context maxps_context_Vps1_Wps0 = {
		VD_X86_INS_MAXPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context maxpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_MAXPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context maxsd_context_Vsd1_Wsd0 = {
		VD_X86_INS_MAXSD,
		1,
		&Vsd1_Wsd0
	};

	static const pa_x86_instruction_context maxss_context_Vss1_Wss0 = {
		VD_X86_INS_MAXSS,
		1,
		&Vss1_Wss0
	};

	static const pa_x86_instruction_context punpcklbw_context_Pq1_Qd0 = {
		VD_X86_INS_PUNPCKLBW,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context punpcklbw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKLBW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context punpcklwd_context_Pq1_Qd0 = {
		VD_X86_INS_PUNPCKLWD,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context punpcklwd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKLWD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context punpckldq_context_Pq1_Qd0 = {
		VD_X86_INS_PUNPCKLDQ,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context punpckldq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKLDQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context packsswb_context_Pq1_Qd0 = {
		VD_X86_INS_PACKSSWB,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context packsswb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PACKSSWB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pcmpgtb_context_Pq1_Qd0 = {
		VD_X86_INS_PCMPGTB,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context pcmpgtb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPGTB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pcmpgtw_context_Pq1_Qd0 = {
		VD_X86_INS_PCMPGTW,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context pcmpgtw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPGTW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pcmpgtd_context_Pq1_Qd0 = {
		VD_X86_INS_PCMPGTD,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context pcmpgtd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPGTD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context packuswb_context_Pq1_Qq0 = {
		VD_X86_INS_PACKUSWB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context packuswb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PACKUSWB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context punpckhbw_context_Pq1_Qq0 = {
		VD_X86_INS_PUNPCKHBW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context punpckhbw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKHBW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context punpckhwd_context_Pq1_Qq0 = {
		VD_X86_INS_PUNPCKHWD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context punpckhwd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKHWD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context punpckhdq_context_Pq1_Qq0 = {
		VD_X86_INS_PUNPCKHDQ,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context punpckhdq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKHDQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context packssdw_context_Pq1_Qq0 = {
		VD_X86_INS_PACKSSDW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context packssdw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PACKSSDW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context punpcklqdq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKLQDQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context punpckhqdq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PUNPCKHQDQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context mopa_context_Pq1_Ed0 = {
		VD_X86_INS_MOVD,
		1,
		&Pq1_Ed0
	};

	static const pa_x86_instruction_context mopa_context_Vdq1_Ed0 = {
		VD_X86_INS_MOVD,
		1,
		&Vdq1_Ed0
	};

	static const pa_x86_instruction_context movq_context_Pq1_Qq0 = {
		VD_X86_INS_MOVQ,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context mopaqa_context_Vdq1_Wdq0 = {
		VD_X86_INS_MOVDQA,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context mopaqu_context_Vdq1_Wdq0 = {
		VD_X86_INS_MOVDQU,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pshufw_context_Pq1_Qq0_Ib0 = {
		VD_X86_INS_PSHUFW,
		1,
		&Pq1_Qq0_Ib0
	};

	static const pa_x86_instruction_context pshufd_context_Vdq1_Wdq0_Ib0 = {
		VD_X86_INS_PSHUFD,
		1,
		&Vdq1_Wdq0_Ib0
	};

	static const pa_x86_instruction_context pshuflw_context_Vdq1_Wdq0_Ib0 = {
		VD_X86_INS_PSHUFLW,
		1,
		&Vdq1_Wdq0_Ib0
	};

	static const pa_x86_instruction_context pshufhw_context_Vdq1_Wdq0_Ib0 = {
		VD_X86_INS_PSHUFHW,
		1,
		&Vdq1_Wdq0_Ib0
	};

	static const pa_x86_instruction_context psrlw_context_Nq1_Ib0 = {
		VD_X86_INS_PSRLW,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context psrlw_context_Udq1_Ib0 = {
		VD_X86_INS_PSRLW,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context psraw_context_Nq1_Ib0 = {
		VD_X86_INS_PSRAW,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context psraw_context_Udq1_Ib0 = {
		VD_X86_INS_PSRAW,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context psllw_context_Nq1_Ib0 = {
		VD_X86_INS_PSLLW,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context psllw_context_Udq1_Ib0 = {
		VD_X86_INS_PSLLW,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context psrld_context_Nq1_Ib0 = {
		VD_X86_INS_PSRLD,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context psrld_context_Udq1_Ib0 = {
		VD_X86_INS_PSRLD,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context psrad_context_Nq1_Ib0 = {
		VD_X86_INS_PSRAD,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context psrad_context_Udq1_Ib0 = {
		VD_X86_INS_PSRAD,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context pslld_context_Nq1_Ib0 = {
		VD_X86_INS_PSLLD,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context pslld_context_Udq1_Ib0 = {
		VD_X86_INS_PSLLD,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context psrlq_context_Nq1_Ib0 = {
		VD_X86_INS_PSRLQ,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context psrlq_context_Udq1_Ib0 = {
		VD_X86_INS_PSRLQ,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context psrldq_context_Udq1_Ib0 = {
		VD_X86_INS_PSRLDQ,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context psllq_context_Nq1_Ib0 = {
		VD_X86_INS_PSLLQ,
		1,
		&Nq1_Ib0
	};

	static const pa_x86_instruction_context psllq_context_Udq1_Ib0 = {
		VD_X86_INS_PSLLQ,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context pslldq_context_Udq1_Ib0 = {
		VD_X86_INS_PSLLDQ,
		1,
		&Udq1_Ib0
	};

	static const pa_x86_instruction_context pcmpeqb_context_Pq1_Qq0 = {
		VD_X86_INS_PCMPEQB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pcmpeqb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPEQB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pcmpeqw_context_Pq1_Qq0 = {
		VD_X86_INS_PCMPEQW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pcmpeqw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPEQW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pcmpeqd_context_Pq1_Qq0 = {
		VD_X86_INS_PCMPEQD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pcmpeqd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PCMPEQD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context emms_context = {
		VD_X86_INS_EMMS,
		0,
		NULL
	};

	static const pa_x86_instruction_context vmread_context_Ed1_Gd0 = {
		VD_X86_INS_VMREAD,
		1,
		&Ed1_Gd0
	};

	static const pa_x86_instruction_context vmwrite_context_Gd0_Ed0 = {
		VD_X86_INS_VMWRITE,
		1,
		&Gd0_Ed0
	};

	static const pa_x86_instruction_context haddpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_HADDPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context haddps_context_Vps1_Wps0 = {
		VD_X86_INS_HADDPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context hsubpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_HSUBPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context hsubps_context_Vps1_Wps0 = {
		VD_X86_INS_HSUBPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context mopa_context_Ed1_Pq0 = {
		VD_X86_INS_MOVD,
		1,
		&Ed1_Pq0
	};

	static const pa_x86_instruction_context mopa_context_Ed1_Vdq0 = {
		VD_X86_INS_MOVD,
		1,
		&Ed1_Vdq0
	};

	static const pa_x86_instruction_context movq_context_Vq1_Wq0 = {
		VD_X86_INS_MOVQ,
		1,
		&Vq1_Wq0
	};

	static const pa_x86_instruction_context movq_context_Qq1_Pq0 = {
		VD_X86_INS_MOVQ,
		1,
		&Qq1_Pq0
	};

	static const pa_x86_instruction_context mopaqa_context_Wdq1_Vdq0 = {
		VD_X86_INS_MOVDQA,
		1,
		&Wdq1_Vdq0
	};

	static const pa_x86_instruction_context mopaqu_context_Wdq1_Vdq0 = {
		VD_X86_INS_MOVDQU,
		1,
		&Wdq1_Vdq0
	};

	static const pa_x86_instruction_context jo_context_Jpas4 = {
		VD_X86_INS_JO,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jno_context_Jpas4 = {
		VD_X86_INS_JNO,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jc_context_Jpas4 = {
		VD_X86_INS_JC,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jnc_context_Jpas4 = {
		VD_X86_INS_JNC,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context je_context_Jpas4 = {
		VD_X86_INS_JE,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jne_context_Jpas4 = {
		VD_X86_INS_JNE,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jna_context_Jpas4 = {
		VD_X86_INS_JNA,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context ja_context_Jpas4 = {
		VD_X86_INS_JA,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context js_context_Jpas4 = {
		VD_X86_INS_JS,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jns_context_Jpas4 = {
		VD_X86_INS_JNS,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jpe_context_Jpas4 = {
		VD_X86_INS_JPE,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jpo_context_Jpas4 = {
		VD_X86_INS_JPO,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jnge_context_Jpas4 = {
		VD_X86_INS_JNGE,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jge_context_Jpas4 = {
		VD_X86_INS_JGE,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jng_context_Jpas4 = {
		VD_X86_INS_JNG,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jg_context_Jpas4 = {
		VD_X86_INS_JG,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context seto_context_Eb1 = {
		VD_X86_INS_SETO,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setno_context_Eb1 = {
		VD_X86_INS_SETNO,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setc_context_Eb1 = {
		VD_X86_INS_SETC,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setnc_context_Eb1 = {
		VD_X86_INS_SETNC,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context sete_context_Eb1 = {
		VD_X86_INS_SETE,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setne_context_Eb1 = {
		VD_X86_INS_SETNE,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setna_context_Eb1 = {
		VD_X86_INS_SETNA,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context seta_context_Eb1 = {
		VD_X86_INS_SETA,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context sets_context_Eb1 = {
		VD_X86_INS_SETS,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setns_context_Eb1 = {
		VD_X86_INS_SETNS,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setpe_context_Eb1 = {
		VD_X86_INS_SETPE,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setpo_context_Eb1 = {
		VD_X86_INS_SETPO,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setnge_context_Eb1 = {
		VD_X86_INS_SETNGE,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setge_context_Eb1 = {
		VD_X86_INS_SETGE,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setng_context_Eb1 = {
		VD_X86_INS_SETNG,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context setg_context_Eb1 = {
		VD_X86_INS_SETG,
		0,
		&Eb1
	};

	static const pa_x86_instruction_context push_context_SCw3_S33w0 = {
		VD_X86_INS_PUSH,
		0,
		&SCw3_S33w0
	};

	static const pa_x86_instruction_context pop_context_S33w1_SCw2 = {
		VD_X86_INS_POP,
		0,
		&S33w1_SCw2
	};

	static const pa_x86_instruction_context cpuid_context_ia32_bios_sign_id3_Gend3_Gend35_Gend67_Gend99 = {
		VD_X86_INS_CPUID,
		0,
		&ia32_bios_sign_id3_Gend3_Gend35_Gend67_Gend99
	};

	static const pa_x86_instruction_context bt_context_Evqp0_Gvqp0 = {
		VD_X86_INS_BT,
		1,
		&Evqp0_Gvqp0
	};

	static const pa_x86_instruction_context shld_context_Evqp1_Gvqp0_Ib0 = {
		VD_X86_INS_SHLD,
		1,
		&Evqp1_Gvqp0_Ib0
	};

	static const pa_x86_instruction_context shld_context_Evqp1_Gvqp0_Genb32 = {
		VD_X86_INS_SHLD,
		1,
		&Evqp1_Gvqp0_Genb32
	};

	static const pa_x86_instruction_context rsm_context_Fw3 = {
		VD_X86_INS_RSM,
		0,
		&Fw3
	};

	static const pa_x86_instruction_context bts_context_Evqp1_Gvqp0 = {
		VD_X86_INS_BTS,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context shrd_context_Evqp1_Gvqp0_Ib0 = {
		VD_X86_INS_SHRD,
		1,
		&Evqp1_Gvqp0_Ib0
	};

	static const pa_x86_instruction_context shrd_context_Evqp1_Gvqp0_Genb32 = {
		VD_X86_INS_SHRD,
		1,
		&Evqp1_Gvqp0_Genb32
	};

	static const pa_x86_instruction_context fxsave_context_Mstx1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		VD_X86_INS_FXSAVE,
		1,
		&Mstx1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const pa_x86_instruction_context fxrstor_context_X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0 = {
		VD_X86_INS_FXRSTOR,
		1,
		&X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0
	};

	static const pa_x86_instruction_context ldmxcsr_context_Md0 = {
		VD_X86_INS_LDMXCSR,
		1,
		&Md0
	};

	static const pa_x86_instruction_context stmxcsr_context_Md1 = {
		VD_X86_INS_STMXCSR,
		1,
		&Md1
	};

	static const pa_x86_instruction_context xsave_context_M1_Gend66_Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226 = {
		VD_X86_INS_XSAVE,
		1,
		&M1_Gend66_Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226
	};

	static const pa_x86_instruction_context xrstor_context_X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2 = {
		VD_X86_INS_XRSTOR,
		1,
		&X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2
	};

	static const pa_x86_instruction_context lfence_context = {
		VD_X86_INS_LFENCE,
		1,
		NULL
	};

	static const pa_x86_instruction_context mfence_context = {
		VD_X86_INS_MFENCE,
		1,
		NULL
	};

	static const pa_x86_instruction_context clflush_context_Mb0 = {
		VD_X86_INS_CLFLUSH,
		1,
		&Mb0
	};

	static const pa_x86_instruction_context sfence_context = {
		VD_X86_INS_SFENCE,
		1,
		NULL
	};

	static const pa_x86_instruction_context imul_context_Gvqp1_Evqp0 = {
		VD_X86_INS_IMUL,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context cmpxchg_context_Eb1_Genb3_Gb0 = {
		VD_X86_INS_CMPXCHG,
		3,
		&Eb1_Genb3_Gb0
	};

	static const pa_x86_instruction_context cmpxchg_context_Evqp1_Genvqp3_Gvqp0 = {
		VD_X86_INS_CMPXCHG,
		3,
		&Evqp1_Genvqp3_Gvqp0
	};

	static const pa_x86_instruction_context lss_context_S30w3_Gvqp1_Mptp0 = {
		VD_X86_INS_LSS,
		1,
		&S30w3_Gvqp1_Mptp0
	};

	static const pa_x86_instruction_context btr_context_Evqp1_Gvqp0 = {
		VD_X86_INS_BTR,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context lfs_context_S30w3_Gvqp1_Mptp0 = {
		VD_X86_INS_LFS,
		1,
		&S30w3_Gvqp1_Mptp0
	};

	static const pa_x86_instruction_context lgs_context_S30w3_Gvqp1_Mptp0 = {
		VD_X86_INS_LGS,
		1,
		&S30w3_Gvqp1_Mptp0
	};

	static const pa_x86_instruction_context movzx_context_Gvqp1_Eb0 = {
		VD_X86_INS_MOVZX,
		1,
		&Gvqp1_Eb0
	};

	static const pa_x86_instruction_context movzx_context_Gvqp1_Ew0 = {
		VD_X86_INS_MOVZX,
		1,
		&Gvqp1_Ew0
	};

	static const pa_x86_instruction_context popcnt_context_Gvqp1_Evqp0 = {
		VD_X86_INS_POPCNT,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context bt_context_Evqp0_Ib0 = {
		VD_X86_INS_BT,
		1,
		&Evqp0_Ib0
	};

	static const pa_x86_instruction_context bts_context_Evqp1_Ib0 = {
		VD_X86_INS_BTS,
		3,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context btr_context_Evqp1_Ib0 = {
		VD_X86_INS_BTR,
		3,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context btc_context_Evqp1_Ib0 = {
		VD_X86_INS_BTC,
		3,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context btc_context_Evqp1_Gvqp0 = {
		VD_X86_INS_BTC,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context bsf_context_Gvqp1_Evqp0 = {
		VD_X86_INS_BSF,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context bsr_context_Gvqp1_Evqp0 = {
		VD_X86_INS_BSR,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context movsx_context_Gvqp1_Eb0 = {
		VD_X86_INS_MOVSX,
		1,
		&Gvqp1_Eb0
	};

	static const pa_x86_instruction_context movsx_context_Gvqp1_Ew0 = {
		VD_X86_INS_MOVSX,
		1,
		&Gvqp1_Ew0
	};

	static const pa_x86_instruction_context xadd_context_Eb1_Gb1 = {
		VD_X86_INS_XADD,
		3,
		&Eb1_Gb1
	};

	static const pa_x86_instruction_context xadd_context_Evqp1_Gvqp1 = {
		VD_X86_INS_XADD,
		3,
		&Evqp1_Gvqp1
	};

	static const pa_x86_instruction_context cmpps_context_Vps1_Wps0_Ib0 = {
		VD_X86_INS_CMPPS,
		1,
		&Vps1_Wps0_Ib0
	};

	static const pa_x86_instruction_context cmppd_context_Vpd1_Wpd0_Ib0 = {
		VD_X86_INS_CMPPD,
		1,
		&Vpd1_Wpd0_Ib0
	};

	static const pa_x86_instruction_context cmpsd_context_Vsd1_Wsd0_Ib0 = {
		VD_X86_INS_CMPSD,
		1,
		&Vsd1_Wsd0_Ib0
	};

	static const pa_x86_instruction_context cmpss_context_Vss1_Wss0_Ib0 = {
		VD_X86_INS_CMPSS,
		1,
		&Vss1_Wss0_Ib0
	};

	static const pa_x86_instruction_context movnti_context_Mdqp1_Gdqp0 = {
		VD_X86_INS_MOVNTI,
		1,
		&Mdqp1_Gdqp0
	};

	static const pa_x86_instruction_context pinsrw_context_Pq1_Mw0_Ib0 = {
		VD_X86_INS_PINSRW,
		1,
		&Pq1_Mw0_Ib0
	};

	static const pa_x86_instruction_context pinsrw_context_Pq1_Rdqp0_Ib0 = {
		VD_X86_INS_PINSRW,
		1,
		&Pq1_Rdqp0_Ib0
	};

	static const pa_x86_instruction_context pinsrw_context_Vdq1_Mw0_Ib0 = {
		VD_X86_INS_PINSRW,
		1,
		&Vdq1_Mw0_Ib0
	};

	static const pa_x86_instruction_context pinsrw_context_Vdq1_Rdqp0_Ib0 = {
		VD_X86_INS_PINSRW,
		1,
		&Vdq1_Rdqp0_Ib0
	};

	static const pa_x86_instruction_context pextrw_context_Gdqp1_Nq0_Ib0 = {
		VD_X86_INS_PEXTRW,
		1,
		&Gdqp1_Nq0_Ib0
	};

	static const pa_x86_instruction_context pextrw_context_Gdqp1_Udq0_Ib0 = {
		VD_X86_INS_PEXTRW,
		1,
		&Gdqp1_Udq0_Ib0
	};

	static const pa_x86_instruction_context shufps_context_Vps1_Wps0_Ib0 = {
		VD_X86_INS_SHUFPS,
		1,
		&Vps1_Wps0_Ib0
	};

	static const pa_x86_instruction_context shufpd_context_Vpd1_Wpd0_Ib0 = {
		VD_X86_INS_SHUFPD,
		1,
		&Vpd1_Wpd0_Ib0
	};

	static const pa_x86_instruction_context cmpxchg8b_context_Mq1_Gend3_Gend67_Gend98_Gend34 = {
		VD_X86_INS_CMPXCHG8B,
		3,
		&Mq1_Gend3_Gend67_Gend98_Gend34
	};

	static const pa_x86_instruction_context vmptrld_context_Mq0 = {
		VD_X86_INS_VMPTRLD,
		1,
		&Mq0
	};

	static const pa_x86_instruction_context vmclear_context_Mq1 = {
		VD_X86_INS_VMCLEAR,
		1,
		&Mq1
	};

	static const pa_x86_instruction_context vmxon_context_Mq0 = {
		VD_X86_INS_VMXON,
		1,
		&Mq0
	};

	static const pa_x86_instruction_context vmptrst_context_Mq1 = {
		VD_X86_INS_VMPTRST,
		1,
		&Mq1
	};

	static const pa_x86_instruction_context bswap_context_Zvqp1 = {
		VD_X86_INS_BSWAP,
		0,
		&Zvqp1
	};

	static const pa_x86_instruction_context addsubpd_context_Vpd1_Wpd0 = {
		VD_X86_INS_ADDSUBPD,
		1,
		&Vpd1_Wpd0
	};

	static const pa_x86_instruction_context addsubps_context_Vps1_Wps0 = {
		VD_X86_INS_ADDSUBPS,
		1,
		&Vps1_Wps0
	};

	static const pa_x86_instruction_context psrlw_context_Pq1_Qq0 = {
		VD_X86_INS_PSRLW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psrlw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSRLW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psrld_context_Pq1_Qq0 = {
		VD_X86_INS_PSRLD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psrld_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSRLD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psrlq_context_Pq1_Qq0 = {
		VD_X86_INS_PSRLQ,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psrlq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSRLQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddq_context_Pq1_Qq0 = {
		VD_X86_INS_PADDQ,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmullw_context_Pq1_Qq0 = {
		VD_X86_INS_PMULLW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmullw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMULLW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context movq_context_Wq1_Vq0 = {
		VD_X86_INS_MOVQ,
		1,
		&Wq1_Vq0
	};

	static const pa_x86_instruction_context mopaq2q_context_Pq1_Uq0 = {
		VD_X86_INS_MOVDQ2Q,
		1,
		&Pq1_Uq0
	};

	static const pa_x86_instruction_context movq2dq_context_Vdq1_Nq0 = {
		VD_X86_INS_MOVQ2DQ,
		1,
		&Vdq1_Nq0
	};

	static const pa_x86_instruction_context pmovmskb_context_Gdqp1_Nq0 = {
		VD_X86_INS_PMOVMSKB,
		1,
		&Gdqp1_Nq0
	};

	static const pa_x86_instruction_context pmovmskb_context_Gdqp1_Udq0 = {
		VD_X86_INS_PMOVMSKB,
		1,
		&Gdqp1_Udq0
	};

	static const pa_x86_instruction_context psubusb_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBUSB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubusb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBUSB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psubusw_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBUSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubusw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBUSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pminub_context_Pq1_Qq0 = {
		VD_X86_INS_PMINUB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pminub_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMINUB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pand_context_Pq1_Qd0 = {
		VD_X86_INS_PAND,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context pand_context_Vdq1_Wdq0 = {
		VD_X86_INS_PAND,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddusb_context_Pq1_Qq0 = {
		VD_X86_INS_PADDUSB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddusb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDUSB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddusw_context_Pq1_Qq0 = {
		VD_X86_INS_PADDUSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddusw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDUSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaxub_context_Pq1_Qq0 = {
		VD_X86_INS_PMAXUB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmaxub_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMAXUB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pandn_context_Pq1_Qq0 = {
		VD_X86_INS_PANDN,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pandn_context_Vdq1_Wdq0 = {
		VD_X86_INS_PANDN,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pavgb_context_Pq1_Qq0 = {
		VD_X86_INS_PAVGB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pavgb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PAVGB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psraw_context_Pq1_Qq0 = {
		VD_X86_INS_PSRAW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psraw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSRAW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psrad_context_Pq1_Qq0 = {
		VD_X86_INS_PSRAD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psrad_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSRAD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pavgw_context_Pq1_Qq0 = {
		VD_X86_INS_PAVGW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pavgw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PAVGW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmulhuw_context_Pq1_Qq0 = {
		VD_X86_INS_PMULHUW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmulhuw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMULHUW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmulhw_context_Pq1_Qq0 = {
		VD_X86_INS_PMULHW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmulhw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMULHW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context cvttpd2dq_context_Vdq1_Wpd0 = {
		VD_X86_INS_CVTTPD2DQ,
		1,
		&Vdq1_Wpd0
	};

	static const pa_x86_instruction_context cvtpd2dq_context_Vdq1_Wpd0 = {
		VD_X86_INS_CVTPD2DQ,
		1,
		&Vdq1_Wpd0
	};

	static const pa_x86_instruction_context cvtdq2pd_context_Vpd1_Wdq0 = {
		VD_X86_INS_CVTDQ2PD,
		1,
		&Vpd1_Wdq0
	};

	static const pa_x86_instruction_context movntq_context_Mq1_Pq0 = {
		VD_X86_INS_MOVNTQ,
		1,
		&Mq1_Pq0
	};

	static const pa_x86_instruction_context movntdq_context_Mdq1_Vdq0 = {
		VD_X86_INS_MOVNTDQ,
		1,
		&Mdq1_Vdq0
	};

	static const pa_x86_instruction_context psubsb_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBSB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubsb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBSB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psubsw_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pminsw_context_Pq1_Qq0 = {
		VD_X86_INS_PMINSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pminsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMINSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context por_context_Pq1_Qq0 = {
		VD_X86_INS_POR,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context por_context_Vdq1_Wdq0 = {
		VD_X86_INS_POR,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddsb_context_Pq1_Qq0 = {
		VD_X86_INS_PADDSB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddsb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDSB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddsw_context_Pq1_Qq0 = {
		VD_X86_INS_PADDSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaxsw_context_Pq1_Qq0 = {
		VD_X86_INS_PMAXSW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmaxsw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMAXSW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pxor_context_Pq1_Qq0 = {
		VD_X86_INS_PXOR,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pxor_context_Vdq1_Wdq0 = {
		VD_X86_INS_PXOR,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context lddqu_context_Vdq1_Mdq0 = {
		VD_X86_INS_LDDQU,
		1,
		&Vdq1_Mdq0
	};

	static const pa_x86_instruction_context psllw_context_Pq1_Qq0 = {
		VD_X86_INS_PSLLW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psllw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSLLW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pslld_context_Pq1_Qq0 = {
		VD_X86_INS_PSLLD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pslld_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSLLD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psllq_context_Pq1_Qq0 = {
		VD_X86_INS_PSLLQ,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psllq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSLLQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmuludq_context_Pq1_Qq0 = {
		VD_X86_INS_PMULUDQ,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context pmuludq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMULUDQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context pmaddwd_context_Pq1_Qd0 = {
		VD_X86_INS_PMADDWD,
		1,
		&Pq1_Qd0
	};

	static const pa_x86_instruction_context pmaddwd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PMADDWD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psadbw_context_Pq1_Qq0 = {
		VD_X86_INS_PSADBW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psadbw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSADBW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context maskmovq_context_BDq3_Pq1_Nq0 = {
		VD_X86_INS_MASKMOVQ,
		1,
		&BDq3_Pq1_Nq0
	};

	static const pa_x86_instruction_context maskmopaqu_context_BDdq3_Vdq0_Udq0 = {
		VD_X86_INS_MASKMOVDQU,
		1,
		&BDdq3_Vdq0_Udq0
	};

	static const pa_x86_instruction_context psubb_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psubw_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psubd_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context psubq_context_Pq1_Qq0 = {
		VD_X86_INS_PSUBQ,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context psubq_context_Vdq1_Wdq0 = {
		VD_X86_INS_PSUBQ,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddb_context_Pq1_Qq0 = {
		VD_X86_INS_PADDB,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddb_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDB,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddw_context_Pq1_Qq0 = {
		VD_X86_INS_PADDW,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddw_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDW,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context paddd_context_Pq1_Qq0 = {
		VD_X86_INS_PADDD,
		1,
		&Pq1_Qq0
	};

	static const pa_x86_instruction_context paddd_context_Vdq1_Wdq0 = {
		VD_X86_INS_PADDD,
		1,
		&Vdq1_Wdq0
	};

	static const pa_x86_instruction_context adc_context_Eb1_Gb0 = {
		VD_X86_INS_ADC,
		3,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context adc_context_Evqp1_Gvqp0 = {
		VD_X86_INS_ADC,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context adc_context_Gb1_Eb0 = {
		VD_X86_INS_ADC,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context adc_context_Gvqp1_Evqp0 = {
		VD_X86_INS_ADC,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context adc_context_Genb1_Ib0 = {
		VD_X86_INS_ADC,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context adc_context_Genvqp1_Ipas4 = {
		VD_X86_INS_ADC,
		0,
		&Genvqp1_Ipas4
	};

	static const pa_x86_instruction_context sbb_context_Eb1_Gb0 = {
		VD_X86_INS_SBB,
		3,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context sbb_context_Evqp1_Gvqp0 = {
		VD_X86_INS_SBB,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context sbb_context_Gb1_Eb0 = {
		VD_X86_INS_SBB,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context sbb_context_Gvqp1_Evqp0 = {
		VD_X86_INS_SBB,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context sbb_context_Genb1_Ib0 = {
		VD_X86_INS_SBB,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context sbb_context_Genvqp1_Ipas4 = {
		VD_X86_INS_SBB,
		0,
		&Genvqp1_Ipas4
	};

	static const pa_x86_instruction_context and_context_Eb1_Gb0 = {
		VD_X86_INS_AND,
		3,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context and_context_Evqp1_Gvqp0 = {
		VD_X86_INS_AND,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context and_context_Gb1_Eb0 = {
		VD_X86_INS_AND,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context and_context_Gvqp1_Evqp0 = {
		VD_X86_INS_AND,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context and_context_Genb1_Ib0 = {
		VD_X86_INS_AND,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context and_context_Genvqp1_Ipas4 = {
		VD_X86_INS_AND,
		0,
		&Genvqp1_Ipas4
	};

	static const pa_x86_instruction_context daa_context_Genb3 = {
		VD_X86_INS_DAA,
		0,
		&Genb3
	};

	static const pa_x86_instruction_context sub_context_Eb1_Gb0 = {
		VD_X86_INS_SUB,
		3,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context sub_context_Evqp1_Gvqp0 = {
		VD_X86_INS_SUB,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context sub_context_Gb1_Eb0 = {
		VD_X86_INS_SUB,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context sub_context_Gvqp1_Evqp0 = {
		VD_X86_INS_SUB,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context sub_context_Genb1_Ib0 = {
		VD_X86_INS_SUB,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context sub_context_Genvqp1_Ipas4 = {
		VD_X86_INS_SUB,
		0,
		&Genvqp1_Ipas4
	};

	static const pa_x86_instruction_context das_context_Genb3 = {
		VD_X86_INS_DAS,
		0,
		&Genb3
	};

	static const pa_x86_instruction_context xor_context_Eb1_Gb0 = {
		VD_X86_INS_XOR,
		3,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context xor_context_Evqp1_Gvqp0 = {
		VD_X86_INS_XOR,
		3,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context xor_context_Gb1_Eb0 = {
		VD_X86_INS_XOR,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context xor_context_Gvqp1_Evqp0 = {
		VD_X86_INS_XOR,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context xor_context_Genb1_Ib0 = {
		VD_X86_INS_XOR,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context xor_context_Genvqp1_Ipas4 = {
		VD_X86_INS_XOR,
		0,
		&Genvqp1_Ipas4
	};

	static const pa_x86_instruction_context aaa_context_Genb3_Genb131 = {
		VD_X86_INS_AAA,
		0,
		&Genb3_Genb131
	};

	static const pa_x86_instruction_context cmp_context_Eb0_Gb0 = {
		VD_X86_INS_CMP,
		1,
		&Eb0_Gb0
	};

	static const pa_x86_instruction_context cmp_context_Evqp0_Gvqp0 = {
		VD_X86_INS_CMP,
		1,
		&Evqp0_Gvqp0
	};

	static const pa_x86_instruction_context cmp_context_Gb0_Eb0 = {
		VD_X86_INS_CMP,
		1,
		&Gb0_Eb0
	};

	static const pa_x86_instruction_context cmp_context_Gvqp0_Evqp0 = {
		VD_X86_INS_CMP,
		1,
		&Gvqp0_Evqp0
	};

	static const pa_x86_instruction_context cmp_context_Genb0_Ib0 = {
		VD_X86_INS_CMP,
		0,
		&Genb0_Ib0
	};

	static const pa_x86_instruction_context cmp_context_Genvqp0_Ipas4 = {
		VD_X86_INS_CMP,
		0,
		&Genvqp0_Ipas4
	};

	static const pa_x86_instruction_context aas_context_Genb3_Genb131 = {
		VD_X86_INS_AAS,
		0,
		&Genb3_Genb131
	};

	static const pa_x86_instruction_context inc_context_Zv1 = {
		VD_X86_INS_INC,
		0,
		&Zv1
	};

	static const pa_x86_instruction_context dec_context_Zv1 = {
		VD_X86_INS_DEC,
		0,
		&Zv1
	};

	static const pa_x86_instruction_context push_context_SCv3_Zv0 = {
		VD_X86_INS_PUSH,
		0,
		&SCv3_Zv0
	};

	static const pa_x86_instruction_context pop_context_Zv1_SCv2 = {
		VD_X86_INS_POP,
		0,
		&Zv1_SCv2
	};

	static const pa_x86_instruction_context pusha_context_SCwo3_Genwo2_Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226 = {
		VD_X86_INS_PUSHA,
		0,
		&SCwo3_Genwo2_Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226
	};

	static const pa_x86_instruction_context pushad_context_SCdoo3_Gendoo2_Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226 = {
		VD_X86_INS_PUSHAD,
		0,
		&SCdoo3_Gendoo2_Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226
	};

	static const pa_x86_instruction_context popa_context_Genwo227_Genwo195_Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2 = {
		VD_X86_INS_POPA,
		0,
		&Genwo227_Genwo195_Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2
	};

	static const pa_x86_instruction_context popad_context_Gendoo227_Gendoo195_Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2 = {
		VD_X86_INS_POPAD,
		0,
		&Gendoo227_Gendoo195_Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2
	};

	static const pa_x86_instruction_context bound_context_SCv3_Gv0_Ma0_Fv2 = {
		VD_X86_INS_BOUND,
		1,
		&SCv3_Gv0_Ma0_Fv2
	};

	static const pa_x86_instruction_context arpl_context_Ew0_Gw0 = {
		VD_X86_INS_ARPL,
		1,
		&Ew0_Gw0
	};

	static const pa_x86_instruction_context push_context_SCm3_Ivs4 = {
		VD_X86_INS_PUSH,
		0,
		&SCm3_Ivs4
	};

	static const pa_x86_instruction_context imul_context_Gvqp1_Evqp0_Ipas4 = {
		VD_X86_INS_IMUL,
		1,
		&Gvqp1_Evqp0_Ipas4
	};

	static const pa_x86_instruction_context push_context_SCm3_Ibss4 = {
		VD_X86_INS_PUSH,
		0,
		&SCm3_Ibss4
	};

	static const pa_x86_instruction_context imul_context_Gvqp1_Evqp0_Ibs4 = {
		VD_X86_INS_IMUL,
		1,
		&Gvqp1_Evqp0_Ibs4
	};

	static const pa_x86_instruction_context insb_context_Yb3_Genw66 = {
		VD_X86_INS_INSB,
		0,
		&Yb3_Genw66
	};

	static const pa_x86_instruction_context insw_context_Ywo3_Genw66 = {
		VD_X86_INS_INSW,
		0,
		&Ywo3_Genw66
	};

	static const pa_x86_instruction_context insd_context_Ydoo3_Genw66 = {
		VD_X86_INS_INSD,
		0,
		&Ydoo3_Genw66
	};

	static const pa_x86_instruction_context outsb_context_Genw67_Xb2 = {
		VD_X86_INS_OUTSB,
		0,
		&Genw67_Xb2
	};

	static const pa_x86_instruction_context outsw_context_Genw67_Xwo2 = {
		VD_X86_INS_OUTSW,
		0,
		&Genw67_Xwo2
	};

	static const pa_x86_instruction_context outsd_context_Genw67_Xdoo2 = {
		VD_X86_INS_OUTSD,
		0,
		&Genw67_Xdoo2
	};

	static const pa_x86_instruction_context jo_context_Jbs4 = {
		VD_X86_INS_JO,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jno_context_Jbs4 = {
		VD_X86_INS_JNO,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jc_context_Jbs4 = {
		VD_X86_INS_JC,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jnc_context_Jbs4 = {
		VD_X86_INS_JNC,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context je_context_Jbs4 = {
		VD_X86_INS_JE,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jne_context_Jbs4 = {
		VD_X86_INS_JNE,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jna_context_Jbs4 = {
		VD_X86_INS_JNA,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context ja_context_Jbs4 = {
		VD_X86_INS_JA,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context js_context_Jbs4 = {
		VD_X86_INS_JS,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jns_context_Jbs4 = {
		VD_X86_INS_JNS,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jpe_context_Jbs4 = {
		VD_X86_INS_JPE,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jpo_context_Jbs4 = {
		VD_X86_INS_JPO,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jnge_context_Jbs4 = {
		VD_X86_INS_JNGE,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jge_context_Jbs4 = {
		VD_X86_INS_JGE,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jng_context_Jbs4 = {
		VD_X86_INS_JNG,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context jg_context_Jbs4 = {
		VD_X86_INS_JG,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context add_context_Eb1_Ib0 = {
		VD_X86_INS_ADD,
		3,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context or_context_Eb1_Ib0 = {
		VD_X86_INS_OR,
		3,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context adc_context_Eb1_Ib0 = {
		VD_X86_INS_ADC,
		3,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context sbb_context_Eb1_Ib0 = {
		VD_X86_INS_SBB,
		3,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context and_context_Eb1_Ib0 = {
		VD_X86_INS_AND,
		3,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context sub_context_Eb1_Ib0 = {
		VD_X86_INS_SUB,
		3,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context xor_context_Eb1_Ib0 = {
		VD_X86_INS_XOR,
		3,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context cmp_context_Eb0_Ib0 = {
		VD_X86_INS_CMP,
		1,
		&Eb0_Ib0
	};

	static const pa_x86_instruction_context add_context_Evqp1_Ipas4 = {
		VD_X86_INS_ADD,
		3,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context or_context_Evqp1_Ipas4 = {
		VD_X86_INS_OR,
		3,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context adc_context_Evqp1_Ipas4 = {
		VD_X86_INS_ADC,
		3,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context sbb_context_Evqp1_Ipas4 = {
		VD_X86_INS_SBB,
		3,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context and_context_Evqp1_Ipas4 = {
		VD_X86_INS_AND,
		3,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context sub_context_Evqp1_Ipas4 = {
		VD_X86_INS_SUB,
		3,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context xor_context_Evqp1_Ipas4 = {
		VD_X86_INS_XOR,
		3,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context cmp_context_Evqp0_Ipas4 = {
		VD_X86_INS_CMP,
		1,
		&Evqp0_Ipas4
	};

	static const pa_x86_instruction_context add_context_Evqp1_Ibs4 = {
		VD_X86_INS_ADD,
		3,
		&Evqp1_Ibs4
	};

	static const pa_x86_instruction_context or_context_Evqp1_Ibs4 = {
		VD_X86_INS_OR,
		3,
		&Evqp1_Ibs4
	};

	static const pa_x86_instruction_context adc_context_Evqp1_Ibs4 = {
		VD_X86_INS_ADC,
		3,
		&Evqp1_Ibs4
	};

	static const pa_x86_instruction_context sbb_context_Evqp1_Ibs4 = {
		VD_X86_INS_SBB,
		3,
		&Evqp1_Ibs4
	};

	static const pa_x86_instruction_context and_context_Evqp1_Ibs4 = {
		VD_X86_INS_AND,
		3,
		&Evqp1_Ibs4
	};

	static const pa_x86_instruction_context sub_context_Evqp1_Ibs4 = {
		VD_X86_INS_SUB,
		3,
		&Evqp1_Ibs4
	};

	static const pa_x86_instruction_context xor_context_Evqp1_Ibs4 = {
		VD_X86_INS_XOR,
		3,
		&Evqp1_Ibs4
	};

	static const pa_x86_instruction_context cmp_context_Evqp0_Ibs4 = {
		VD_X86_INS_CMP,
		1,
		&Evqp0_Ibs4
	};

	static const pa_x86_instruction_context test_context_Eb0_Gb0 = {
		VD_X86_INS_TEST,
		1,
		&Eb0_Gb0
	};

	static const pa_x86_instruction_context test_context_Evqp0_Gvqp0 = {
		VD_X86_INS_TEST,
		1,
		&Evqp0_Gvqp0
	};

	static const pa_x86_instruction_context xchg_context_Gb1_Eb1 = {
		VD_X86_INS_XCHG,
		3,
		&Gb1_Eb1
	};

	static const pa_x86_instruction_context xchg_context_Gvqp1_Evqp1 = {
		VD_X86_INS_XCHG,
		3,
		&Gvqp1_Evqp1
	};

	static const pa_x86_instruction_context mov_context_Eb1_Gb0 = {
		VD_X86_INS_MOV,
		1,
		&Eb1_Gb0
	};

	static const pa_x86_instruction_context mov_context_Evqp1_Gvqp0 = {
		VD_X86_INS_MOV,
		1,
		&Evqp1_Gvqp0
	};

	static const pa_x86_instruction_context mov_context_Gb1_Eb0 = {
		VD_X86_INS_MOV,
		1,
		&Gb1_Eb0
	};

	static const pa_x86_instruction_context mov_context_Gvqp1_Evqp0 = {
		VD_X86_INS_MOV,
		1,
		&Gvqp1_Evqp0
	};

	static const pa_x86_instruction_context mov_context_Mw1_Sw0 = {
		VD_X86_INS_MOV,
		1,
		&Mw1_Sw0
	};

	static const pa_x86_instruction_context mov_context_Rvqp1_Sw0 = {
		VD_X86_INS_MOV,
		1,
		&Rvqp1_Sw0
	};

	static const pa_x86_instruction_context lea_context_Gvqp1_M0 = {
		VD_X86_INS_LEA,
		1,
		&Gvqp1_M0
	};

	static const pa_x86_instruction_context mov_context_Sw1_Ew0 = {
		VD_X86_INS_MOV,
		1,
		&Sw1_Ew0
	};

	static const pa_x86_instruction_context pop_context_Ev1_SCv2 = {
		VD_X86_INS_POP,
		1,
		&Ev1_SCv2
	};

	static const pa_x86_instruction_context nop_context = {
		VD_X86_INS_NOP,
		0,
		NULL
	};

	static const pa_x86_instruction_context pause_context = {
		VD_X86_INS_PAUSE,
		0,
		NULL
	};

	static const pa_x86_instruction_context xchg_context_Zvqp1_Genvqp1 = {
		VD_X86_INS_XCHG,
		0,
		&Zvqp1_Genvqp1
	};

	static const pa_x86_instruction_context cbw_context_Genwo3_Genb2 = {
		VD_X86_INS_CBW,
		0,
		&Genwo3_Genb2
	};

	static const pa_x86_instruction_context cwde_context_Gendoo3_Genw2 = {
		VD_X86_INS_CWDE,
		0,
		&Gendoo3_Genw2
	};

	static const pa_x86_instruction_context cwd_context_Genwo67_Genwo2 = {
		VD_X86_INS_CWD,
		0,
		&Genwo67_Genwo2
	};

	static const pa_x86_instruction_context cdq_context_Gendoo67_Gendoo2 = {
		VD_X86_INS_CDQ,
		0,
		&Gendoo67_Gendoo2
	};

	static const pa_x86_instruction_context callf_context_SCp3_Ap0 = {
		VD_X86_INS_CALLF,
		0,
		&SCp3_Ap0
	};

	static const pa_x86_instruction_context wait_context = {
		VD_X86_INS_WAIT,
		0,
		NULL
	};

	static const pa_x86_instruction_context pushf_context_SCwo3_Fwo2 = {
		VD_X86_INS_PUSHF,
		0,
		&SCwo3_Fwo2
	};

	static const pa_x86_instruction_context pushfd_context_SCdoo3_Fdoo2 = {
		VD_X86_INS_PUSHFD,
		0,
		&SCdoo3_Fdoo2
	};

	static const pa_x86_instruction_context popf_context_Fwo3_SCwo2 = {
		VD_X86_INS_POPF,
		0,
		&Fwo3_SCwo2
	};

	static const pa_x86_instruction_context popfd_context_Fdoo3_SCdoo2 = {
		VD_X86_INS_POPFD,
		0,
		&Fdoo3_SCdoo2
	};

	static const pa_x86_instruction_context sahf_context_Genb130 = {
		VD_X86_INS_SAHF,
		0,
		&Genb130
	};

	static const pa_x86_instruction_context lahf_context_Genb131 = {
		VD_X86_INS_LAHF,
		0,
		&Genb131
	};

	static const pa_x86_instruction_context mov_context_Genb1_Ob0 = {
		VD_X86_INS_MOV,
		0,
		&Genb1_Ob0
	};

	static const pa_x86_instruction_context mov_context_Genvqp1_Ovqp0 = {
		VD_X86_INS_MOV,
		0,
		&Genvqp1_Ovqp0
	};

	static const pa_x86_instruction_context mov_context_Ob1_Genb0 = {
		VD_X86_INS_MOV,
		0,
		&Ob1_Genb0
	};

	static const pa_x86_instruction_context mov_context_Ovqp1_Genvqp0 = {
		VD_X86_INS_MOV,
		0,
		&Ovqp1_Genvqp0
	};

	static const pa_x86_instruction_context movsb_context_Yb3_Xb2 = {
		VD_X86_INS_MOVSB,
		0,
		&Yb3_Xb2
	};

	static const pa_x86_instruction_context movsw_context_Ywo3_Xwo2 = {
		VD_X86_INS_MOVSW,
		0,
		&Ywo3_Xwo2
	};

	static const pa_x86_instruction_context movsd_context_Ydoo3_Xdoo2 = {
		VD_X86_INS_MOVSD,
		0,
		&Ydoo3_Xdoo2
	};

	static const pa_x86_instruction_context cmpsb_context_Yb2_Xb2 = {
		VD_X86_INS_CMPSB,
		0,
		&Yb2_Xb2
	};

	static const pa_x86_instruction_context cmpsw_context_Ywo2_Xwo2 = {
		VD_X86_INS_CMPSW,
		0,
		&Ywo2_Xwo2
	};

	static const pa_x86_instruction_context cmpsd_context_Ydoo2_Xdoo2 = {
		VD_X86_INS_CMPSD,
		0,
		&Ydoo2_Xdoo2
	};

	static const pa_x86_instruction_context test_context_Genb0_Ib0 = {
		VD_X86_INS_TEST,
		0,
		&Genb0_Ib0
	};

	static const pa_x86_instruction_context test_context_Genvqp0_Ipas4 = {
		VD_X86_INS_TEST,
		0,
		&Genvqp0_Ipas4
	};

	static const pa_x86_instruction_context stosb_context_Yb3_Genb2 = {
		VD_X86_INS_STOSB,
		0,
		&Yb3_Genb2
	};

	static const pa_x86_instruction_context stosw_context_Ywo3_Genwo2 = {
		VD_X86_INS_STOSW,
		0,
		&Ywo3_Genwo2
	};

	static const pa_x86_instruction_context stosd_context_Ydoo3_Gendoo2 = {
		VD_X86_INS_STOSD,
		0,
		&Ydoo3_Gendoo2
	};

	static const pa_x86_instruction_context lodsb_context_Genb3_Xb2 = {
		VD_X86_INS_LODSB,
		0,
		&Genb3_Xb2
	};

	static const pa_x86_instruction_context lodsw_context_Genwo3_Xwo2 = {
		VD_X86_INS_LODSW,
		0,
		&Genwo3_Xwo2
	};

	static const pa_x86_instruction_context lodsd_context_Gendoo3_Xdoo2 = {
		VD_X86_INS_LODSD,
		0,
		&Gendoo3_Xdoo2
	};

	static const pa_x86_instruction_context scasb_context_Yb2_Genb2 = {
		VD_X86_INS_SCASB,
		0,
		&Yb2_Genb2
	};

	static const pa_x86_instruction_context scasw_context_Ywo2_Genwo2 = {
		VD_X86_INS_SCASW,
		0,
		&Ywo2_Genwo2
	};

	static const pa_x86_instruction_context scasd_context_Ydoo2_Gendoo2 = {
		VD_X86_INS_SCASD,
		0,
		&Ydoo2_Gendoo2
	};

	static const pa_x86_instruction_context mov_context_Zb1_Ib0 = {
		VD_X86_INS_MOV,
		0,
		&Zb1_Ib0
	};

	static const pa_x86_instruction_context mov_context_Zvqp1_Ivqp0 = {
		VD_X86_INS_MOV,
		0,
		&Zvqp1_Ivqp0
	};

	static const pa_x86_instruction_context rol_context_Eb1_Ib0 = {
		VD_X86_INS_ROL,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context ror_context_Eb1_Ib0 = {
		VD_X86_INS_ROR,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context rcl_context_Eb1_Ib0 = {
		VD_X86_INS_RCL,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context rcr_context_Eb1_Ib0 = {
		VD_X86_INS_RCR,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context sal_context_Eb1_Ib0 = {
		VD_X86_INS_SAL,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context shr_context_Eb1_Ib0 = {
		VD_X86_INS_SHR,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context shl_context_Eb1_Ib0 = {
		VD_X86_INS_SHL,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context sar_context_Eb1_Ib0 = {
		VD_X86_INS_SAR,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context rol_context_Evqp1_Ib0 = {
		VD_X86_INS_ROL,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context ror_context_Evqp1_Ib0 = {
		VD_X86_INS_ROR,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context rcl_context_Evqp1_Ib0 = {
		VD_X86_INS_RCL,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context rcr_context_Evqp1_Ib0 = {
		VD_X86_INS_RCR,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context sal_context_Evqp1_Ib0 = {
		VD_X86_INS_SAL,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context shr_context_Evqp1_Ib0 = {
		VD_X86_INS_SHR,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context shl_context_Evqp1_Ib0 = {
		VD_X86_INS_SHL,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context sar_context_Evqp1_Ib0 = {
		VD_X86_INS_SAR,
		1,
		&Evqp1_Ib0
	};

	static const pa_x86_instruction_context retn_context_SCw2_Iw0 = {
		VD_X86_INS_RETN,
		0,
		&SCw2_Iw0
	};

	static const pa_x86_instruction_context retn_context_SCm2 = {
		VD_X86_INS_RETN,
		0,
		&SCm2
	};

	static const pa_x86_instruction_context les_context_Segw3_Gv1_Mp0 = {
		VD_X86_INS_LES,
		1,
		&Segw3_Gv1_Mp0
	};

	static const pa_x86_instruction_context lds_context_Segw99_Gv1_Mp0 = {
		VD_X86_INS_LDS,
		1,
		&Segw99_Gv1_Mp0
	};

	static const pa_x86_instruction_context mov_context_Eb1_Ib0 = {
		VD_X86_INS_MOV,
		1,
		&Eb1_Ib0
	};

	static const pa_x86_instruction_context mov_context_Evqp1_Ipas4 = {
		VD_X86_INS_MOV,
		1,
		&Evqp1_Ipas4
	};

	static const pa_x86_instruction_context enter_context_SCw3_Genv163_Iw0_Ib0 = {
		VD_X86_INS_ENTER,
		0,
		&SCw3_Genv163_Iw0_Ib0
	};

	static const pa_x86_instruction_context leave_context_Genv163_SCv2 = {
		VD_X86_INS_LEAVE,
		0,
		&Genv163_SCv2
	};

	static const pa_x86_instruction_context retf_context_Iw0_SCw2 = {
		VD_X86_INS_RETF,
		0,
		&Iw0_SCw2
	};

	static const pa_x86_instruction_context retf_context_SCm2 = {
		VD_X86_INS_RETF,
		0,
		&SCm2
	};

	static const pa_x86_instruction_context int_context_SCv3_I3b0_Fv2 = {
		VD_X86_INS_INT,
		0,
		&SCv3_I3b0_Fv2
	};

	static const pa_x86_instruction_context int_context_SCb3_Ib0_Fv2 = {
		VD_X86_INS_INT,
		0,
		&SCb3_Ib0_Fv2
	};

	static const pa_x86_instruction_context into_context_SCv3_Fv2 = {
		VD_X86_INS_INTO,
		0,
		&SCv3_Fv2
	};

	static const pa_x86_instruction_context iret_context_Fwo3_SCwo2 = {
		VD_X86_INS_IRET,
		0,
		&Fwo3_SCwo2
	};

	static const pa_x86_instruction_context iretd_context_Fdoo3_SCdoo2 = {
		VD_X86_INS_IRETD,
		0,
		&Fdoo3_SCdoo2
	};

	static const pa_x86_instruction_context rol_context_Eb1_I1b0 = {
		VD_X86_INS_ROL,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context ror_context_Eb1_I1b0 = {
		VD_X86_INS_ROR,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context rcl_context_Eb1_I1b0 = {
		VD_X86_INS_RCL,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context rcr_context_Eb1_I1b0 = {
		VD_X86_INS_RCR,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context sal_context_Eb1_I1b0 = {
		VD_X86_INS_SAL,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context shr_context_Eb1_I1b0 = {
		VD_X86_INS_SHR,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context shl_context_Eb1_I1b0 = {
		VD_X86_INS_SHL,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context sar_context_Eb1_I1b0 = {
		VD_X86_INS_SAR,
		1,
		&Eb1_I1b0
	};

	static const pa_x86_instruction_context rol_context_Evqp1_I1b0 = {
		VD_X86_INS_ROL,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context ror_context_Evqp1_I1b0 = {
		VD_X86_INS_ROR,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context rcl_context_Evqp1_I1b0 = {
		VD_X86_INS_RCL,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context rcr_context_Evqp1_I1b0 = {
		VD_X86_INS_RCR,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context sal_context_Evqp1_I1b0 = {
		VD_X86_INS_SAL,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context shr_context_Evqp1_I1b0 = {
		VD_X86_INS_SHR,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context shl_context_Evqp1_I1b0 = {
		VD_X86_INS_SHL,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context sar_context_Evqp1_I1b0 = {
		VD_X86_INS_SAR,
		1,
		&Evqp1_I1b0
	};

	static const pa_x86_instruction_context rol_context_Eb1_Genb32 = {
		VD_X86_INS_ROL,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context ror_context_Eb1_Genb32 = {
		VD_X86_INS_ROR,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context rcl_context_Eb1_Genb32 = {
		VD_X86_INS_RCL,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context rcr_context_Eb1_Genb32 = {
		VD_X86_INS_RCR,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context sal_context_Eb1_Genb32 = {
		VD_X86_INS_SAL,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context shr_context_Eb1_Genb32 = {
		VD_X86_INS_SHR,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context shl_context_Eb1_Genb32 = {
		VD_X86_INS_SHL,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context sar_context_Eb1_Genb32 = {
		VD_X86_INS_SAR,
		1,
		&Eb1_Genb32
	};

	static const pa_x86_instruction_context rol_context_Evqp1_Genb32 = {
		VD_X86_INS_ROL,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context ror_context_Evqp1_Genb32 = {
		VD_X86_INS_ROR,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context rcl_context_Evqp1_Genb32 = {
		VD_X86_INS_RCL,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context rcr_context_Evqp1_Genb32 = {
		VD_X86_INS_RCR,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context sal_context_Evqp1_Genb32 = {
		VD_X86_INS_SAL,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context shr_context_Evqp1_Genb32 = {
		VD_X86_INS_SHR,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context shl_context_Evqp1_Genb32 = {
		VD_X86_INS_SHL,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context sar_context_Evqp1_Genb32 = {
		VD_X86_INS_SAR,
		1,
		&Evqp1_Genb32
	};

	static const pa_x86_instruction_context aam_context_Genb3_Genb131 = {
		VD_X86_INS_AAM,
		0,
		&Genb3_Genb131
	};

	static const pa_x86_instruction_context aad_context_Genb3_Genb131 = {
		VD_X86_INS_AAD,
		0,
		&Genb3_Genb131
	};

	static const pa_x86_instruction_context setalc_context_Genb3 = {
		VD_X86_INS_SETALC,
		0,
		&Genb3
	};

	static const pa_x86_instruction_context xlatb_context_Genb3_BBb2 = {
		VD_X86_INS_XLATB,
		0,
		&Genb3_BBb2
	};

	static const pa_x86_instruction_context fadd_context_X87fpu3_Msr0 = {
		VD_X86_INS_FADD,
		1,
		&X87fpu3_Msr0
	};

	static const pa_x86_instruction_context fadd_context_X87fpu1_EST0 = {
		VD_X86_INS_FADD,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fmul_context_X87fpu3_Msr0 = {
		VD_X86_INS_FMUL,
		1,
		&X87fpu3_Msr0
	};

	static const pa_x86_instruction_context fmul_context_X87fpu1_EST0 = {
		VD_X86_INS_FMUL,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fcom_context_X87fpu2_ESsr0 = {
		VD_X86_INS_FCOM,
		1,
		&X87fpu2_ESsr0
	};

	static const pa_x86_instruction_context fcomp_context_X87fpu2_ESsr0 = {
		VD_X86_INS_FCOMP,
		1,
		&X87fpu2_ESsr0
	};

	static const pa_x86_instruction_context fsub_context_X87fpu3_Msr0 = {
		VD_X86_INS_FSUB,
		1,
		&X87fpu3_Msr0
	};

	static const pa_x86_instruction_context fsub_context_X87fpu1_EST0 = {
		VD_X86_INS_FSUB,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fsubr_context_X87fpu3_Msr0 = {
		VD_X86_INS_FSUBR,
		1,
		&X87fpu3_Msr0
	};

	static const pa_x86_instruction_context fsubr_context_X87fpu1_EST0 = {
		VD_X86_INS_FSUBR,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fdiv_context_X87fpu3_Msr0 = {
		VD_X86_INS_FDIV,
		1,
		&X87fpu3_Msr0
	};

	static const pa_x86_instruction_context fdiv_context_X87fpu1_EST0 = {
		VD_X86_INS_FDIV,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fdivr_context_X87fpu3_Msr0 = {
		VD_X86_INS_FDIVR,
		1,
		&X87fpu3_Msr0
	};

	static const pa_x86_instruction_context fdivr_context_X87fpu1_EST0 = {
		VD_X86_INS_FDIVR,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fld_context_X87fpu3_ESsr0 = {
		VD_X86_INS_FLD,
		1,
		&X87fpu3_ESsr0
	};

	static const pa_x86_instruction_context fxch_context_X87fpu3_EST1 = {
		VD_X86_INS_FXCH,
		1,
		&X87fpu3_EST1
	};

	static const pa_x86_instruction_context fst_context_Msr1_X87fpu2 = {
		VD_X86_INS_FST,
		1,
		&Msr1_X87fpu2
	};

	static const pa_x86_instruction_context fnop_context = {
		VD_X86_INS_FNOP,
		1,
		NULL
	};

	static const pa_x86_instruction_context fstp_context_Msr1_X87fpu2 = {
		VD_X86_INS_FSTP,
		1,
		&Msr1_X87fpu2
	};

	static const pa_x86_instruction_context fstp1_context_EST1_X87fpu2 = {
		VD_X86_INS_FSTP1,
		1,
		&EST1_X87fpu2
	};

	static const pa_x86_instruction_context fldenv_context_Me0 = {
		VD_X86_INS_FLDENV,
		1,
		&Me0
	};

	static const pa_x86_instruction_context fchs_context_X87fpu3 = {
		VD_X86_INS_FCHS,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fabs_context_X87fpu3 = {
		VD_X86_INS_FABS,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context ftst_context_X87fpu2 = {
		VD_X86_INS_FTST,
		1,
		&X87fpu2
	};

	static const pa_x86_instruction_context fxam_context_X87fpu2 = {
		VD_X86_INS_FXAM,
		1,
		&X87fpu2
	};

	static const pa_x86_instruction_context fldcw_context_Mw0 = {
		VD_X86_INS_FLDCW,
		1,
		&Mw0
	};

	static const pa_x86_instruction_context fld1_context_X87fpu3 = {
		VD_X86_INS_FLD1,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fldl2t_context_X87fpu3 = {
		VD_X86_INS_FLDL2T,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fldl2e_context_X87fpu3 = {
		VD_X86_INS_FLDL2E,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fldpi_context_X87fpu3 = {
		VD_X86_INS_FLDPI,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fldlg2_context_X87fpu3 = {
		VD_X86_INS_FLDLG2,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fldln2_context_X87fpu3 = {
		VD_X86_INS_FLDLN2,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fldz_context_X87fpu3 = {
		VD_X86_INS_FLDZ,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fnstenv_context_Me1 = {
		VD_X86_INS_FNSTENV,
		1,
		&Me1
	};

	static const pa_x86_instruction_context f2xm1_context_X87fpu3 = {
		VD_X86_INS_F2XM1,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fyl2x_context_X87fpu35_X87fpu2 = {
		VD_X86_INS_FYL2X,
		1,
		&X87fpu35_X87fpu2
	};

	static const pa_x86_instruction_context fptan_context_X87fpu3 = {
		VD_X86_INS_FPTAN,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fpatan_context_X87fpu35_X87fpu2 = {
		VD_X86_INS_FPATAN,
		1,
		&X87fpu35_X87fpu2
	};

	static const pa_x86_instruction_context fxtract_context_X87fpu3 = {
		VD_X86_INS_FXTRACT,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fprem1_context_X87fpu3_X87fpu34 = {
		VD_X86_INS_FPREM1,
		1,
		&X87fpu3_X87fpu34
	};

	static const pa_x86_instruction_context fdecstp_context = {
		VD_X86_INS_FDECSTP,
		1,
		NULL
	};

	static const pa_x86_instruction_context fincstp_context = {
		VD_X86_INS_FINCSTP,
		1,
		NULL
	};

	static const pa_x86_instruction_context fnstcw_context_Mw1 = {
		VD_X86_INS_FNSTCW,
		1,
		&Mw1
	};

	static const pa_x86_instruction_context fprem_context_X87fpu3_X87fpu34 = {
		VD_X86_INS_FPREM,
		1,
		&X87fpu3_X87fpu34
	};

	static const pa_x86_instruction_context fyl2xp1_context_X87fpu35_X87fpu2 = {
		VD_X86_INS_FYL2XP1,
		1,
		&X87fpu35_X87fpu2
	};

	static const pa_x86_instruction_context fsqrt_context_X87fpu3 = {
		VD_X86_INS_FSQRT,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fsincos_context_X87fpu3 = {
		VD_X86_INS_FSINCOS,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context frndint_context_X87fpu3 = {
		VD_X86_INS_FRNDINT,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fscale_context_X87fpu3_X87fpu34 = {
		VD_X86_INS_FSCALE,
		1,
		&X87fpu3_X87fpu34
	};

	static const pa_x86_instruction_context fsin_context_X87fpu3 = {
		VD_X86_INS_FSIN,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fcos_context_X87fpu3 = {
		VD_X86_INS_FCOS,
		1,
		&X87fpu3
	};

	static const pa_x86_instruction_context fiadd_context_X87fpu3_Mdi0 = {
		VD_X86_INS_FIADD,
		1,
		&X87fpu3_Mdi0
	};

	static const pa_x86_instruction_context fcmovb_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVB,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fimul_context_X87fpu3_Mdi0 = {
		VD_X86_INS_FIMUL,
		1,
		&X87fpu3_Mdi0
	};

	static const pa_x86_instruction_context fcmove_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVE,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context ficom_context_X87fpu2_Mdi0 = {
		VD_X86_INS_FICOM,
		1,
		&X87fpu2_Mdi0
	};

	static const pa_x86_instruction_context fcmovbe_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVBE,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context ficomp_context_X87fpu2_Mdi0 = {
		VD_X86_INS_FICOMP,
		1,
		&X87fpu2_Mdi0
	};

	static const pa_x86_instruction_context fcmovu_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVU,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fisub_context_X87fpu3_Mdi0 = {
		VD_X86_INS_FISUB,
		1,
		&X87fpu3_Mdi0
	};

	static const pa_x86_instruction_context fisubr_context_X87fpu3_Mdi0 = {
		VD_X86_INS_FISUBR,
		1,
		&X87fpu3_Mdi0
	};

	static const pa_x86_instruction_context fucompp_context_X87fpu2_X87fpu34 = {
		VD_X86_INS_FUCOMPP,
		1,
		&X87fpu2_X87fpu34
	};

	static const pa_x86_instruction_context fidiv_context_X87fpu3_Mdi0 = {
		VD_X86_INS_FIDIV,
		1,
		&X87fpu3_Mdi0
	};

	static const pa_x86_instruction_context fidivr_context_X87fpu3_Mdi0 = {
		VD_X86_INS_FIDIVR,
		1,
		&X87fpu3_Mdi0
	};

	static const pa_x86_instruction_context fild_context_X87fpu3_Mdi0 = {
		VD_X86_INS_FILD,
		1,
		&X87fpu3_Mdi0
	};

	static const pa_x86_instruction_context fcmovnb_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVNB,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fisttp_context_Mdi1_X87fpu2 = {
		VD_X86_INS_FISTTP,
		1,
		&Mdi1_X87fpu2
	};

	static const pa_x86_instruction_context fcmovne_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVNE,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fist_context_Mdi1_X87fpu2 = {
		VD_X86_INS_FIST,
		1,
		&Mdi1_X87fpu2
	};

	static const pa_x86_instruction_context fcmovnbe_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVNBE,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fistp_context_Mdi1_X87fpu2 = {
		VD_X86_INS_FISTP,
		1,
		&Mdi1_X87fpu2
	};

	static const pa_x86_instruction_context fcmovnu_context_X87fpu1_EST0 = {
		VD_X86_INS_FCMOVNU,
		1,
		&X87fpu1_EST0
	};

	static const pa_x86_instruction_context fneni_context = {
		VD_X86_INS_FNENI,
		1,
		NULL
	};

	static const pa_x86_instruction_context fndisi_context = {
		VD_X86_INS_FNDISI,
		1,
		NULL
	};

	static const pa_x86_instruction_context fnclex_context = {
		VD_X86_INS_FNCLEX,
		1,
		NULL
	};

	static const pa_x86_instruction_context fninit_context = {
		VD_X86_INS_FNINIT,
		1,
		NULL
	};

	static const pa_x86_instruction_context fnsetpm_context = {
		VD_X86_INS_FNSETPM,
		1,
		NULL
	};

	static const pa_x86_instruction_context fld_context_X87fpu3_Mer0 = {
		VD_X86_INS_FLD,
		1,
		&X87fpu3_Mer0
	};

	static const pa_x86_instruction_context fucomi_context_X87fpu0_EST0 = {
		VD_X86_INS_FUCOMI,
		1,
		&X87fpu0_EST0
	};

	static const pa_x86_instruction_context fcomi_context_X87fpu0_EST0 = {
		VD_X86_INS_FCOMI,
		1,
		&X87fpu0_EST0
	};

	static const pa_x86_instruction_context fstp_context_Mer1_X87fpu2 = {
		VD_X86_INS_FSTP,
		1,
		&Mer1_X87fpu2
	};

	static const pa_x86_instruction_context fadd_context_X87fpu3_Mdr0 = {
		VD_X86_INS_FADD,
		1,
		&X87fpu3_Mdr0
	};

	static const pa_x86_instruction_context fadd_context_EST1_X87fpu0 = {
		VD_X86_INS_FADD,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fmul_context_X87fpu3_Mdr0 = {
		VD_X86_INS_FMUL,
		1,
		&X87fpu3_Mdr0
	};

	static const pa_x86_instruction_context fmul_context_EST1_X87fpu0 = {
		VD_X86_INS_FMUL,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fcom_context_X87fpu2_Mdr0 = {
		VD_X86_INS_FCOM,
		1,
		&X87fpu2_Mdr0
	};

	static const pa_x86_instruction_context fcom2_context_X87fpu2_EST0 = {
		VD_X86_INS_FCOM2,
		1,
		&X87fpu2_EST0
	};

	static const pa_x86_instruction_context fcomp_context_X87fpu2_Mdr0 = {
		VD_X86_INS_FCOMP,
		1,
		&X87fpu2_Mdr0
	};

	static const pa_x86_instruction_context fcomp3_context_X87fpu2_EST0 = {
		VD_X86_INS_FCOMP3,
		1,
		&X87fpu2_EST0
	};

	static const pa_x86_instruction_context fsub_context_X87fpu3_Mdr0 = {
		VD_X86_INS_FSUB,
		1,
		&X87fpu3_Mdr0
	};

	static const pa_x86_instruction_context fsubr_context_EST1_X87fpu0 = {
		VD_X86_INS_FSUBR,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fsubr_context_X87fpu3_Mdr0 = {
		VD_X86_INS_FSUBR,
		1,
		&X87fpu3_Mdr0
	};

	static const pa_x86_instruction_context fsub_context_EST1_X87fpu0 = {
		VD_X86_INS_FSUB,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fdiv_context_X87fpu3_Mdr0 = {
		VD_X86_INS_FDIV,
		1,
		&X87fpu3_Mdr0
	};

	static const pa_x86_instruction_context fdivr_context_EST1_X87fpu0 = {
		VD_X86_INS_FDIVR,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fdivr_context_X87fpu3_Mdr0 = {
		VD_X86_INS_FDIVR,
		1,
		&X87fpu3_Mdr0
	};

	static const pa_x86_instruction_context fdiv_context_EST1_X87fpu0 = {
		VD_X86_INS_FDIV,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fld_context_X87fpu3_Mdr0 = {
		VD_X86_INS_FLD,
		1,
		&X87fpu3_Mdr0
	};

	static const pa_x86_instruction_context ffree_context_EST0 = {
		VD_X86_INS_FFREE,
		1,
		&EST0
	};

	static const pa_x86_instruction_context fisttp_context_Mqi1_X87fpu2 = {
		VD_X86_INS_FISTTP,
		1,
		&Mqi1_X87fpu2
	};

	static const pa_x86_instruction_context fxch4_context_X87fpu3_EST1 = {
		VD_X86_INS_FXCH4,
		1,
		&X87fpu3_EST1
	};

	static const pa_x86_instruction_context fst_context_Mdr1_X87fpu2 = {
		VD_X86_INS_FST,
		1,
		&Mdr1_X87fpu2
	};

	static const pa_x86_instruction_context fst_context_X87fpu3_EST0 = {
		VD_X86_INS_FST,
		1,
		&X87fpu3_EST0
	};

	static const pa_x86_instruction_context fstp_context_Mdr1_X87fpu2 = {
		VD_X86_INS_FSTP,
		1,
		&Mdr1_X87fpu2
	};

	static const pa_x86_instruction_context fstp_context_X87fpu3_EST0 = {
		VD_X86_INS_FSTP,
		1,
		&X87fpu3_EST0
	};

	static const pa_x86_instruction_context frstor_context_X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0 = {
		VD_X86_INS_FRSTOR,
		1,
		&X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0
	};

	static const pa_x86_instruction_context fucom_context_X87fpu2_EST0 = {
		VD_X86_INS_FUCOM,
		1,
		&X87fpu2_EST0
	};

	static const pa_x86_instruction_context fucomp_context_X87fpu2_EST0 = {
		VD_X86_INS_FUCOMP,
		1,
		&X87fpu2_EST0
	};

	static const pa_x86_instruction_context fnsave_context_Mst1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226 = {
		VD_X86_INS_FNSAVE,
		1,
		&Mst1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226
	};

	static const pa_x86_instruction_context fnstsw_context_Mw1 = {
		VD_X86_INS_FNSTSW,
		1,
		&Mw1
	};

	static const pa_x86_instruction_context fiadd_context_X87fpu3_Mwi0 = {
		VD_X86_INS_FIADD,
		1,
		&X87fpu3_Mwi0
	};

	static const pa_x86_instruction_context faddp_context_EST1_X87fpu0 = {
		VD_X86_INS_FADDP,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fimul_context_X87fpu3_Mwi0 = {
		VD_X86_INS_FIMUL,
		1,
		&X87fpu3_Mwi0
	};

	static const pa_x86_instruction_context fmulp_context_EST1_X87fpu0 = {
		VD_X86_INS_FMULP,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context ficom_context_X87fpu2_Mwi0 = {
		VD_X86_INS_FICOM,
		1,
		&X87fpu2_Mwi0
	};

	static const pa_x86_instruction_context fcomp5_context_X87fpu2_EST0 = {
		VD_X86_INS_FCOMP5,
		1,
		&X87fpu2_EST0
	};

	static const pa_x86_instruction_context ficomp_context_X87fpu2_Mwi0 = {
		VD_X86_INS_FICOMP,
		1,
		&X87fpu2_Mwi0
	};

	static const pa_x86_instruction_context fcompp_context_X87fpu2_X87fpu34 = {
		VD_X86_INS_FCOMPP,
		1,
		&X87fpu2_X87fpu34
	};

	static const pa_x86_instruction_context fisub_context_X87fpu3_Mwi0 = {
		VD_X86_INS_FISUB,
		1,
		&X87fpu3_Mwi0
	};

	static const pa_x86_instruction_context fsubrp_context_EST1_X87fpu0 = {
		VD_X86_INS_FSUBRP,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fisubr_context_X87fpu3_Mwi0 = {
		VD_X86_INS_FISUBR,
		1,
		&X87fpu3_Mwi0
	};

	static const pa_x86_instruction_context fsubp_context_EST1_X87fpu0 = {
		VD_X86_INS_FSUBP,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fidiv_context_X87fpu3_Mwi0 = {
		VD_X86_INS_FIDIV,
		1,
		&X87fpu3_Mwi0
	};

	static const pa_x86_instruction_context fdivrp_context_EST1_X87fpu0 = {
		VD_X86_INS_FDIVRP,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fidivr_context_X87fpu3_Mwi0 = {
		VD_X86_INS_FIDIVR,
		1,
		&X87fpu3_Mwi0
	};

	static const pa_x86_instruction_context fdivp_context_EST1_X87fpu0 = {
		VD_X86_INS_FDIVP,
		1,
		&EST1_X87fpu0
	};

	static const pa_x86_instruction_context fild_context_X87fpu3_Mwi0 = {
		VD_X86_INS_FILD,
		1,
		&X87fpu3_Mwi0
	};

	static const pa_x86_instruction_context ffreep_context_EST0 = {
		VD_X86_INS_FFREEP,
		1,
		&EST0
	};

	static const pa_x86_instruction_context fisttp_context_Mwi1_X87fpu2 = {
		VD_X86_INS_FISTTP,
		1,
		&Mwi1_X87fpu2
	};

	static const pa_x86_instruction_context fxch7_context_X87fpu3_EST1 = {
		VD_X86_INS_FXCH7,
		1,
		&X87fpu3_EST1
	};

	static const pa_x86_instruction_context fist_context_Mwi1_X87fpu2 = {
		VD_X86_INS_FIST,
		1,
		&Mwi1_X87fpu2
	};

	static const pa_x86_instruction_context fstp8_context_EST1_X87fpu2 = {
		VD_X86_INS_FSTP8,
		1,
		&EST1_X87fpu2
	};

	static const pa_x86_instruction_context fistp_context_Mwi1_X87fpu2 = {
		VD_X86_INS_FISTP,
		1,
		&Mwi1_X87fpu2
	};

	static const pa_x86_instruction_context fstp9_context_EST1_X87fpu2 = {
		VD_X86_INS_FSTP9,
		1,
		&EST1_X87fpu2
	};

	static const pa_x86_instruction_context fbld_context_X87fpu3_Mbcd0 = {
		VD_X86_INS_FBLD,
		1,
		&X87fpu3_Mbcd0
	};

	static const pa_x86_instruction_context fnstsw_context_Genw1 = {
		VD_X86_INS_FNSTSW,
		1,
		&Genw1
	};

	static const pa_x86_instruction_context fild_context_X87fpu3_Mqi0 = {
		VD_X86_INS_FILD,
		1,
		&X87fpu3_Mqi0
	};

	static const pa_x86_instruction_context fucomip_context_X87fpu0_EST0 = {
		VD_X86_INS_FUCOMIP,
		1,
		&X87fpu0_EST0
	};

	static const pa_x86_instruction_context fbstp_context_Mbcd1_X87fpu2 = {
		VD_X86_INS_FBSTP,
		1,
		&Mbcd1_X87fpu2
	};

	static const pa_x86_instruction_context fcomip_context_X87fpu0_EST0 = {
		VD_X86_INS_FCOMIP,
		1,
		&X87fpu0_EST0
	};

	static const pa_x86_instruction_context fistp_context_Mqi1_X87fpu2 = {
		VD_X86_INS_FISTP,
		1,
		&Mqi1_X87fpu2
	};

	static const pa_x86_instruction_context loopne_context_Genva35_Jbs4 = {
		VD_X86_INS_LOOPNE,
		0,
		&Genva35_Jbs4
	};

	static const pa_x86_instruction_context loope_context_Genva35_Jbs4 = {
		VD_X86_INS_LOOPE,
		0,
		&Genva35_Jbs4
	};

	static const pa_x86_instruction_context loop_context_Genva35_Jbs4 = {
		VD_X86_INS_LOOP,
		0,
		&Genva35_Jbs4
	};

	static const pa_x86_instruction_context jecxz_context_Jbs4_Genda34 = {
		VD_X86_INS_JECXZ,
		0,
		&Jbs4_Genda34
	};

	static const pa_x86_instruction_context in_context_Genb1_Ib0 = {
		VD_X86_INS_IN,
		0,
		&Genb1_Ib0
	};

	static const pa_x86_instruction_context in_context_Genv1_Ib0 = {
		VD_X86_INS_IN,
		0,
		&Genv1_Ib0
	};

	static const pa_x86_instruction_context out_context_Ib1_Genb0 = {
		VD_X86_INS_OUT,
		0,
		&Ib1_Genb0
	};

	static const pa_x86_instruction_context out_context_Ib1_Genv0 = {
		VD_X86_INS_OUT,
		0,
		&Ib1_Genv0
	};

	static const pa_x86_instruction_context call_context_SCpas7_Jpas4 = {
		VD_X86_INS_CALL,
		0,
		&SCpas7_Jpas4
	};

	static const pa_x86_instruction_context jmp_context_Jpas4 = {
		VD_X86_INS_JMP,
		0,
		&Jpas4
	};

	static const pa_x86_instruction_context jmpf_context_Ap0 = {
		VD_X86_INS_JMPF,
		0,
		&Ap0
	};

	static const pa_x86_instruction_context jmp_context_Jbs4 = {
		VD_X86_INS_JMP,
		0,
		&Jbs4
	};

	static const pa_x86_instruction_context in_context_Genb1_Genw64 = {
		VD_X86_INS_IN,
		0,
		&Genb1_Genw64
	};

	static const pa_x86_instruction_context in_context_Genv1_Genw64 = {
		VD_X86_INS_IN,
		0,
		&Genv1_Genw64
	};

	static const pa_x86_instruction_context out_context_Genw65_Genb0 = {
		VD_X86_INS_OUT,
		0,
		&Genw65_Genb0
	};

	static const pa_x86_instruction_context out_context_Genw65_Genv0 = {
		VD_X86_INS_OUT,
		0,
		&Genw65_Genv0
	};

	static const pa_x86_instruction_context icebp_context_SCv3_Fv2 = {
		VD_X86_INS_ICEBP,
		0,
		&SCv3_Fv2
	};

	static const pa_x86_instruction_context hlt_context = {
		VD_X86_INS_HLT,
		0,
		NULL
	};

	static const pa_x86_instruction_context cmc_context = {
		VD_X86_INS_CMC,
		0,
		NULL
	};

	static const pa_x86_instruction_context test_context_Eb0_Ib0 = {
		VD_X86_INS_TEST,
		1,
		&Eb0_Ib0
	};

	static const pa_x86_instruction_context not_context_Eb1 = {
		VD_X86_INS_NOT,
		1,
		&Eb1
	};

	static const pa_x86_instruction_context neg_context_Eb1 = {
		VD_X86_INS_NEG,
		1,
		&Eb1
	};

	static const pa_x86_instruction_context mul_context_Genw3_Genb2_Eb0 = {
		VD_X86_INS_MUL,
		1,
		&Genw3_Genb2_Eb0
	};

	static const pa_x86_instruction_context imul_context_Genw3_Genb2_Eb0 = {
		VD_X86_INS_IMUL,
		1,
		&Genw3_Genb2_Eb0
	};

	static const pa_x86_instruction_context div_context_Genb3_Genb131_Genw2_Eb0 = {
		VD_X86_INS_DIV,
		1,
		&Genb3_Genb131_Genw2_Eb0
	};

	static const pa_x86_instruction_context idiv_context_Genb3_Genb131_Genw2_Eb0 = {
		VD_X86_INS_IDIV,
		1,
		&Genb3_Genb131_Genw2_Eb0
	};

	static const pa_x86_instruction_context test_context_Evqp0_Ivqp0 = {
		VD_X86_INS_TEST,
		1,
		&Evqp0_Ivqp0
	};

	static const pa_x86_instruction_context not_context_Evqp1 = {
		VD_X86_INS_NOT,
		1,
		&Evqp1
	};

	static const pa_x86_instruction_context neg_context_Evqp1 = {
		VD_X86_INS_NEG,
		1,
		&Evqp1
	};

	static const pa_x86_instruction_context mul_context_Genvqp67_Genvqp3_Evqp0 = {
		VD_X86_INS_MUL,
		1,
		&Genvqp67_Genvqp3_Evqp0
	};

	static const pa_x86_instruction_context imul_context_Genvqp67_Genvqp3_Evqp0 = {
		VD_X86_INS_IMUL,
		1,
		&Genvqp67_Genvqp3_Evqp0
	};

	static const pa_x86_instruction_context div_context_Genvqp67_Genvqp3_Evqp0 = {
		VD_X86_INS_DIV,
		1,
		&Genvqp67_Genvqp3_Evqp0
	};

	static const pa_x86_instruction_context idiv_context_Genvqp67_Genvqp3_Evqp0 = {
		VD_X86_INS_IDIV,
		1,
		&Genvqp67_Genvqp3_Evqp0
	};

	static const pa_x86_instruction_context clc_context = {
		VD_X86_INS_CLC,
		0,
		NULL
	};

	static const pa_x86_instruction_context stc_context = {
		VD_X86_INS_STC,
		0,
		NULL
	};

	static const pa_x86_instruction_context cli_context = {
		VD_X86_INS_CLI,
		0,
		NULL
	};

	static const pa_x86_instruction_context sti_context = {
		VD_X86_INS_STI,
		0,
		NULL
	};

	static const pa_x86_instruction_context cld_context = {
		VD_X86_INS_CLD,
		0,
		NULL
	};

	static const pa_x86_instruction_context std_context = {
		VD_X86_INS_STD,
		0,
		NULL
	};

	static const pa_x86_instruction_context inc_context_Eb1 = {
		VD_X86_INS_INC,
		1,
		&Eb1
	};

	static const pa_x86_instruction_context dec_context_Eb1 = {
		VD_X86_INS_DEC,
		1,
		&Eb1
	};

	static const pa_x86_instruction_context inc_context_Evqp1 = {
		VD_X86_INS_INC,
		1,
		&Evqp1
	};

	static const pa_x86_instruction_context dec_context_Evqp1 = {
		VD_X86_INS_DEC,
		1,
		&Evqp1
	};

	static const pa_x86_instruction_context call_context_SCv3_Ev0 = {
		VD_X86_INS_CALL,
		1,
		&SCv3_Ev0
	};

	static const pa_x86_instruction_context callf_context_SCptp3_Mptp0 = {
		VD_X86_INS_CALLF,
		1,
		&SCptp3_Mptp0
	};

	static const pa_x86_instruction_context jmp_context_Ev0 = {
		VD_X86_INS_JMP,
		1,
		&Ev0
	};

	static const pa_x86_instruction_context jmpf_context_Mptp0 = {
		VD_X86_INS_JMPF,
		1,
		&Mptp0
	};

	static const pa_x86_instruction_context push_context_SCv3_Ev0 = {
		VD_X86_INS_PUSH,
		1,
		&SCv3_Ev0
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_00[2] = {
		/*0F_38_00*/{ &pshufb_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_00*/{ &pshufb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_01[2] = {
		/*0F_38_01*/{ &phaddw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_01*/{ &phaddw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_02[2] = {
		/*0F_38_02*/{ &phaddd_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_02*/{ &phaddd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_03[2] = {
		/*0F_38_03*/{ &phaddsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_03*/{ &phaddsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_04[2] = {
		/*0F_38_04*/{ &pmaddubsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_04*/{ &pmaddubsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_05[2] = {
		/*0F_38_05*/{ &phsubw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_05*/{ &phsubw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_06[2] = {
		/*0F_38_06*/{ &phsubd_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_06*/{ &phsubd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_07[2] = {
		/*0F_38_07*/{ &phsubsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_07*/{ &phsubsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_08[2] = {
		/*0F_38_08*/{ &psignb_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_08*/{ &psignb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_09[2] = {
		/*0F_38_09*/{ &psignw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_09*/{ &psignw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_0A[2] = {
		/*0F_38_0A*/{ &psignd_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_0A*/{ &psignd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_0B[2] = {
		/*0F_38_0B*/{ &pmulhrsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_0B*/{ &pmulhrsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_10[2] = {
		/*0F_38_10*/{ NULL, NULL, NULL },
		/*0F_38_10*/{ &pblendvb_context_Vdq1_Wdq0_Xmm2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_14[2] = {
		/*0F_38_14*/{ NULL, NULL, NULL },
		/*0F_38_14*/{ &blendvps_context_Vps1_Wps0_Xmm2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_15[2] = {
		/*0F_38_15*/{ NULL, NULL, NULL },
		/*0F_38_15*/{ &blendvpd_context_Vpd1_Wpd0_Xmm2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_17[2] = {
		/*0F_38_17*/{ NULL, NULL, NULL },
		/*0F_38_17*/{ &ptest_context_Vdq0_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_1C[2] = {
		/*0F_38_1C*/{ &pabsb_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_1C*/{ &pabsb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_1D[2] = {
		/*0F_38_1D*/{ &pabsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_1D*/{ &pabsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_1E[2] = {
		/*0F_38_1E*/{ &pabsd_context_Pq1_Qq0, NULL, NULL },
		/*0F_38_1E*/{ &pabsd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_38_20_mod_perfix_66[2] = {
		/*0F_38_20*/{ &pmovsxbw_context_Vdq1_Mq0, NULL, NULL },
		/*0F_38_20*/{ &pmovsxbw_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_20[2] = {
		/*0F_38_20*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_20_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_21_mod_perfix_66[2] = {
		/*0F_38_21*/{ &pmovsxbd_context_Vdq1_Md0, NULL, NULL },
		/*0F_38_21*/{ &pmovsxbd_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_21[2] = {
		/*0F_38_21*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_21_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_22_mod_perfix_66[2] = {
		/*0F_38_22*/{ &pmovsxbq_context_Vdq1_Mw0, NULL, NULL },
		/*0F_38_22*/{ &pmovsxbq_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_22[2] = {
		/*0F_38_22*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_22_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_23_mod_perfix_66[2] = {
		/*0F_38_23*/{ &pmovsxwd_context_Vdq1_Mq0, NULL, NULL },
		/*0F_38_23*/{ &pmovsxwd_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_23[2] = {
		/*0F_38_23*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_23_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_24_mod_perfix_66[2] = {
		/*0F_38_24*/{ &pmovsxwq_context_Vdq1_Md0, NULL, NULL },
		/*0F_38_24*/{ &pmovsxwq_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_24[2] = {
		/*0F_38_24*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_24_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_25_mod_perfix_66[2] = {
		/*0F_38_25*/{ &pmovsxdq_context_Vdq1_Mq0, NULL, NULL },
		/*0F_38_25*/{ &pmovsxdq_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_25[2] = {
		/*0F_38_25*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_25_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_28[2] = {
		/*0F_38_28*/{ NULL, NULL, NULL },
		/*0F_38_28*/{ &pmuldq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_29[2] = {
		/*0F_38_29*/{ NULL, NULL, NULL },
		/*0F_38_29*/{ &pcmpeqq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_38_2A_mod_perfix_66[1] = {
		/*0F_38_2A*/{ &movntdqa_context_Vdq1_Mdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_2A[2] = {
		/*0F_38_2A*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_2A_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_2B[2] = {
		/*0F_38_2B*/{ NULL, NULL, NULL },
		/*0F_38_2B*/{ &packusdw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_38_30_mod_perfix_66[2] = {
		/*0F_38_30*/{ &pmovzxbw_context_Vdq1_Mq0, NULL, NULL },
		/*0F_38_30*/{ &pmovzxbw_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_30[2] = {
		/*0F_38_30*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_30_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_31_mod_perfix_66[2] = {
		/*0F_38_31*/{ &pmovzxbd_context_Vdq1_Md0, NULL, NULL },
		/*0F_38_31*/{ &pmovzxbd_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_31[2] = {
		/*0F_38_31*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_31_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_32_mod_perfix_66[2] = {
		/*0F_38_32*/{ &pmovzxbq_context_Vdq1_Mw0, NULL, NULL },
		/*0F_38_32*/{ &pmovzxbq_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_32[2] = {
		/*0F_38_32*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_32_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_33_mod_perfix_66[2] = {
		/*0F_38_33*/{ &pmovzxwd_context_Vdq1_Mq0, NULL, NULL },
		/*0F_38_33*/{ &pmovzxwd_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_33[2] = {
		/*0F_38_33*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_33_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_34_mod_perfix_66[2] = {
		/*0F_38_34*/{ &pmovzxwq_context_Vdq1_Md0, NULL, NULL },
		/*0F_38_34*/{ &pmovzxwq_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_34[2] = {
		/*0F_38_34*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_34_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_35_mod_perfix_66[2] = {
		/*0F_38_35*/{ &pmovzxdq_context_Vdq1_Mq0, NULL, NULL },
		/*0F_38_35*/{ &pmovzxdq_context_Vdq1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_35[2] = {
		/*0F_38_35*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_35_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_37[2] = {
		/*0F_38_37*/{ NULL, NULL, NULL },
		/*0F_38_37*/{ &pcmpgtq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_38[2] = {
		/*0F_38_38*/{ NULL, NULL, NULL },
		/*0F_38_38*/{ &pminsb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_39[2] = {
		/*0F_38_39*/{ NULL, NULL, NULL },
		/*0F_38_39*/{ &pminsd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_3A[2] = {
		/*0F_38_3A*/{ NULL, NULL, NULL },
		/*0F_38_3A*/{ &pminuw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_3B[2] = {
		/*0F_38_3B*/{ NULL, NULL, NULL },
		/*0F_38_3B*/{ &pminud_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_3C[2] = {
		/*0F_38_3C*/{ NULL, NULL, NULL },
		/*0F_38_3C*/{ &pmaxsb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_3D[2] = {
		/*0F_38_3D*/{ NULL, NULL, NULL },
		/*0F_38_3D*/{ &pmaxsd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_3E[2] = {
		/*0F_38_3E*/{ NULL, NULL, NULL },
		/*0F_38_3E*/{ &pmaxuw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_3F[2] = {
		/*0F_38_3F*/{ NULL, NULL, NULL },
		/*0F_38_3F*/{ &pmaxud_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_40[2] = {
		/*0F_38_40*/{ NULL, NULL, NULL },
		/*0F_38_40*/{ &pmulld_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_41[2] = {
		/*0F_38_41*/{ NULL, NULL, NULL },
		/*0F_38_41*/{ &phminposuw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_38_80_mod_perfix_66[1] = {
		/*0F_38_80*/{ &invept_context_Gd0_Mdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_80[2] = {
		/*0F_38_80*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_80_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_81_mod_perfix_66[1] = {
		/*0F_38_81*/{ &invvpid_context_Gd0_Mdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_81[2] = {
		/*0F_38_81*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_38_81_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_38_F0_mod[1] = {
		/*0F_38_F0*/{ &movbe_context_Gvqp1_Mvqp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_F0[3] = {
		{ NULL, &table_0F_38_F0_mod, read_table_offset_by_mod },
		/*0F_38_F0*/{ NULL, NULL, NULL },
		/*0F_38_F0*/{ &crc32_context_Gdqp1_Eb0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_38_F1_mod[1] = {
		/*0F_38_F1*/{ &movbe_context_Mvqp1_Gvqp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_38_F1[3] = {
		{ NULL, &table_0F_38_F1_mod, read_table_offset_by_mod },
		/*0F_38_F1*/{ NULL, NULL, NULL },
		/*0F_38_F1*/{ &crc32_context_Gdqp1_Evqp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_extended_0F_38[242] = {
		{ NULL, &table_prefix_0F_38_00, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_01, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_02, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_03, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_04, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_05, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_06, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_07, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_08, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_09, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_0A, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_0B, read_table_offset_by_prefix },
		/*0F_38_0C*/{ NULL, NULL, NULL },
		/*0F_38_0D*/{ NULL, NULL, NULL },
		/*0F_38_0E*/{ NULL, NULL, NULL },
		/*0F_38_0F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_10, read_table_offset_by_prefix },
		/*0F_38_11*/{ NULL, NULL, NULL },
		/*0F_38_12*/{ NULL, NULL, NULL },
		/*0F_38_13*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_14, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_15, read_table_offset_by_prefix },
		/*0F_38_16*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_17, read_table_offset_by_prefix },
		/*0F_38_18*/{ NULL, NULL, NULL },
		/*0F_38_19*/{ NULL, NULL, NULL },
		/*0F_38_1A*/{ NULL, NULL, NULL },
		/*0F_38_1B*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_1C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_1D, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_1E, read_table_offset_by_prefix },
		/*0F_38_1F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_20, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_21, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_22, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_23, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_24, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_25, read_table_offset_by_prefix },
		/*0F_38_26*/{ NULL, NULL, NULL },
		/*0F_38_27*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_28, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_29, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_2A, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_2B, read_table_offset_by_prefix },
		/*0F_38_2C*/{ NULL, NULL, NULL },
		/*0F_38_2D*/{ NULL, NULL, NULL },
		/*0F_38_2E*/{ NULL, NULL, NULL },
		/*0F_38_2F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_30, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_31, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_32, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_33, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_34, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_35, read_table_offset_by_prefix },
		/*0F_38_36*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_37, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_38, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_39, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_3A, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_3B, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_3C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_3D, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_3E, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_3F, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_40, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_41, read_table_offset_by_prefix },
		/*0F_38_42*/{ NULL, NULL, NULL },
		/*0F_38_43*/{ NULL, NULL, NULL },
		/*0F_38_44*/{ NULL, NULL, NULL },
		/*0F_38_45*/{ NULL, NULL, NULL },
		/*0F_38_46*/{ NULL, NULL, NULL },
		/*0F_38_47*/{ NULL, NULL, NULL },
		/*0F_38_48*/{ NULL, NULL, NULL },
		/*0F_38_49*/{ NULL, NULL, NULL },
		/*0F_38_4A*/{ NULL, NULL, NULL },
		/*0F_38_4B*/{ NULL, NULL, NULL },
		/*0F_38_4C*/{ NULL, NULL, NULL },
		/*0F_38_4D*/{ NULL, NULL, NULL },
		/*0F_38_4E*/{ NULL, NULL, NULL },
		/*0F_38_4F*/{ NULL, NULL, NULL },
		/*0F_38_50*/{ NULL, NULL, NULL },
		/*0F_38_51*/{ NULL, NULL, NULL },
		/*0F_38_52*/{ NULL, NULL, NULL },
		/*0F_38_53*/{ NULL, NULL, NULL },
		/*0F_38_54*/{ NULL, NULL, NULL },
		/*0F_38_55*/{ NULL, NULL, NULL },
		/*0F_38_56*/{ NULL, NULL, NULL },
		/*0F_38_57*/{ NULL, NULL, NULL },
		/*0F_38_58*/{ NULL, NULL, NULL },
		/*0F_38_59*/{ NULL, NULL, NULL },
		/*0F_38_5A*/{ NULL, NULL, NULL },
		/*0F_38_5B*/{ NULL, NULL, NULL },
		/*0F_38_5C*/{ NULL, NULL, NULL },
		/*0F_38_5D*/{ NULL, NULL, NULL },
		/*0F_38_5E*/{ NULL, NULL, NULL },
		/*0F_38_5F*/{ NULL, NULL, NULL },
		/*0F_38_60*/{ NULL, NULL, NULL },
		/*0F_38_61*/{ NULL, NULL, NULL },
		/*0F_38_62*/{ NULL, NULL, NULL },
		/*0F_38_63*/{ NULL, NULL, NULL },
		/*0F_38_64*/{ NULL, NULL, NULL },
		/*0F_38_65*/{ NULL, NULL, NULL },
		/*0F_38_66*/{ NULL, NULL, NULL },
		/*0F_38_67*/{ NULL, NULL, NULL },
		/*0F_38_68*/{ NULL, NULL, NULL },
		/*0F_38_69*/{ NULL, NULL, NULL },
		/*0F_38_6A*/{ NULL, NULL, NULL },
		/*0F_38_6B*/{ NULL, NULL, NULL },
		/*0F_38_6C*/{ NULL, NULL, NULL },
		/*0F_38_6D*/{ NULL, NULL, NULL },
		/*0F_38_6E*/{ NULL, NULL, NULL },
		/*0F_38_6F*/{ NULL, NULL, NULL },
		/*0F_38_70*/{ NULL, NULL, NULL },
		/*0F_38_71*/{ NULL, NULL, NULL },
		/*0F_38_72*/{ NULL, NULL, NULL },
		/*0F_38_73*/{ NULL, NULL, NULL },
		/*0F_38_74*/{ NULL, NULL, NULL },
		/*0F_38_75*/{ NULL, NULL, NULL },
		/*0F_38_76*/{ NULL, NULL, NULL },
		/*0F_38_77*/{ NULL, NULL, NULL },
		/*0F_38_78*/{ NULL, NULL, NULL },
		/*0F_38_79*/{ NULL, NULL, NULL },
		/*0F_38_7A*/{ NULL, NULL, NULL },
		/*0F_38_7B*/{ NULL, NULL, NULL },
		/*0F_38_7C*/{ NULL, NULL, NULL },
		/*0F_38_7D*/{ NULL, NULL, NULL },
		/*0F_38_7E*/{ NULL, NULL, NULL },
		/*0F_38_7F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_80, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_81, read_table_offset_by_prefix },
		/*0F_38_82*/{ NULL, NULL, NULL },
		/*0F_38_83*/{ NULL, NULL, NULL },
		/*0F_38_84*/{ NULL, NULL, NULL },
		/*0F_38_85*/{ NULL, NULL, NULL },
		/*0F_38_86*/{ NULL, NULL, NULL },
		/*0F_38_87*/{ NULL, NULL, NULL },
		/*0F_38_88*/{ NULL, NULL, NULL },
		/*0F_38_89*/{ NULL, NULL, NULL },
		/*0F_38_8A*/{ NULL, NULL, NULL },
		/*0F_38_8B*/{ NULL, NULL, NULL },
		/*0F_38_8C*/{ NULL, NULL, NULL },
		/*0F_38_8D*/{ NULL, NULL, NULL },
		/*0F_38_8E*/{ NULL, NULL, NULL },
		/*0F_38_8F*/{ NULL, NULL, NULL },
		/*0F_38_90*/{ NULL, NULL, NULL },
		/*0F_38_91*/{ NULL, NULL, NULL },
		/*0F_38_92*/{ NULL, NULL, NULL },
		/*0F_38_93*/{ NULL, NULL, NULL },
		/*0F_38_94*/{ NULL, NULL, NULL },
		/*0F_38_95*/{ NULL, NULL, NULL },
		/*0F_38_96*/{ NULL, NULL, NULL },
		/*0F_38_97*/{ NULL, NULL, NULL },
		/*0F_38_98*/{ NULL, NULL, NULL },
		/*0F_38_99*/{ NULL, NULL, NULL },
		/*0F_38_9A*/{ NULL, NULL, NULL },
		/*0F_38_9B*/{ NULL, NULL, NULL },
		/*0F_38_9C*/{ NULL, NULL, NULL },
		/*0F_38_9D*/{ NULL, NULL, NULL },
		/*0F_38_9E*/{ NULL, NULL, NULL },
		/*0F_38_9F*/{ NULL, NULL, NULL },
		/*0F_38_A0*/{ NULL, NULL, NULL },
		/*0F_38_A1*/{ NULL, NULL, NULL },
		/*0F_38_A2*/{ NULL, NULL, NULL },
		/*0F_38_A3*/{ NULL, NULL, NULL },
		/*0F_38_A4*/{ NULL, NULL, NULL },
		/*0F_38_A5*/{ NULL, NULL, NULL },
		/*0F_38_A6*/{ NULL, NULL, NULL },
		/*0F_38_A7*/{ NULL, NULL, NULL },
		/*0F_38_A8*/{ NULL, NULL, NULL },
		/*0F_38_A9*/{ NULL, NULL, NULL },
		/*0F_38_AA*/{ NULL, NULL, NULL },
		/*0F_38_AB*/{ NULL, NULL, NULL },
		/*0F_38_AC*/{ NULL, NULL, NULL },
		/*0F_38_AD*/{ NULL, NULL, NULL },
		/*0F_38_AE*/{ NULL, NULL, NULL },
		/*0F_38_AF*/{ NULL, NULL, NULL },
		/*0F_38_B0*/{ NULL, NULL, NULL },
		/*0F_38_B1*/{ NULL, NULL, NULL },
		/*0F_38_B2*/{ NULL, NULL, NULL },
		/*0F_38_B3*/{ NULL, NULL, NULL },
		/*0F_38_B4*/{ NULL, NULL, NULL },
		/*0F_38_B5*/{ NULL, NULL, NULL },
		/*0F_38_B6*/{ NULL, NULL, NULL },
		/*0F_38_B7*/{ NULL, NULL, NULL },
		/*0F_38_B8*/{ NULL, NULL, NULL },
		/*0F_38_B9*/{ NULL, NULL, NULL },
		/*0F_38_BA*/{ NULL, NULL, NULL },
		/*0F_38_BB*/{ NULL, NULL, NULL },
		/*0F_38_BC*/{ NULL, NULL, NULL },
		/*0F_38_BD*/{ NULL, NULL, NULL },
		/*0F_38_BE*/{ NULL, NULL, NULL },
		/*0F_38_BF*/{ NULL, NULL, NULL },
		/*0F_38_C0*/{ NULL, NULL, NULL },
		/*0F_38_C1*/{ NULL, NULL, NULL },
		/*0F_38_C2*/{ NULL, NULL, NULL },
		/*0F_38_C3*/{ NULL, NULL, NULL },
		/*0F_38_C4*/{ NULL, NULL, NULL },
		/*0F_38_C5*/{ NULL, NULL, NULL },
		/*0F_38_C6*/{ NULL, NULL, NULL },
		/*0F_38_C7*/{ NULL, NULL, NULL },
		/*0F_38_C8*/{ NULL, NULL, NULL },
		/*0F_38_C9*/{ NULL, NULL, NULL },
		/*0F_38_CA*/{ NULL, NULL, NULL },
		/*0F_38_CB*/{ NULL, NULL, NULL },
		/*0F_38_CC*/{ NULL, NULL, NULL },
		/*0F_38_CD*/{ NULL, NULL, NULL },
		/*0F_38_CE*/{ NULL, NULL, NULL },
		/*0F_38_CF*/{ NULL, NULL, NULL },
		/*0F_38_D0*/{ NULL, NULL, NULL },
		/*0F_38_D1*/{ NULL, NULL, NULL },
		/*0F_38_D2*/{ NULL, NULL, NULL },
		/*0F_38_D3*/{ NULL, NULL, NULL },
		/*0F_38_D4*/{ NULL, NULL, NULL },
		/*0F_38_D5*/{ NULL, NULL, NULL },
		/*0F_38_D6*/{ NULL, NULL, NULL },
		/*0F_38_D7*/{ NULL, NULL, NULL },
		/*0F_38_D8*/{ NULL, NULL, NULL },
		/*0F_38_D9*/{ NULL, NULL, NULL },
		/*0F_38_DA*/{ NULL, NULL, NULL },
		/*0F_38_DB*/{ NULL, NULL, NULL },
		/*0F_38_DC*/{ NULL, NULL, NULL },
		/*0F_38_DD*/{ NULL, NULL, NULL },
		/*0F_38_DE*/{ NULL, NULL, NULL },
		/*0F_38_DF*/{ NULL, NULL, NULL },
		/*0F_38_E0*/{ NULL, NULL, NULL },
		/*0F_38_E1*/{ NULL, NULL, NULL },
		/*0F_38_E2*/{ NULL, NULL, NULL },
		/*0F_38_E3*/{ NULL, NULL, NULL },
		/*0F_38_E4*/{ NULL, NULL, NULL },
		/*0F_38_E5*/{ NULL, NULL, NULL },
		/*0F_38_E6*/{ NULL, NULL, NULL },
		/*0F_38_E7*/{ NULL, NULL, NULL },
		/*0F_38_E8*/{ NULL, NULL, NULL },
		/*0F_38_E9*/{ NULL, NULL, NULL },
		/*0F_38_EA*/{ NULL, NULL, NULL },
		/*0F_38_EB*/{ NULL, NULL, NULL },
		/*0F_38_EC*/{ NULL, NULL, NULL },
		/*0F_38_ED*/{ NULL, NULL, NULL },
		/*0F_38_EE*/{ NULL, NULL, NULL },
		/*0F_38_EF*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_38_F0, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_38_F1, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_08[2] = {
		/*0F_3A_08*/{ NULL, NULL, NULL },
		/*0F_3A_08*/{ &roundps_context_Vps1_Wps0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_09[2] = {
		/*0F_3A_09*/{ NULL, NULL, NULL },
		/*0F_3A_09*/{ &roundpd_context_Vps1_Wpd0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_0A[2] = {
		/*0F_3A_0A*/{ NULL, NULL, NULL },
		/*0F_3A_0A*/{ &roundss_context_Vss1_Wss0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_0B[2] = {
		/*0F_3A_0B*/{ NULL, NULL, NULL },
		/*0F_3A_0B*/{ &roundsd_context_Vsd1_Wsd0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_0C[2] = {
		/*0F_3A_0C*/{ NULL, NULL, NULL },
		/*0F_3A_0C*/{ &blendps_context_Vps1_Wps0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_0D[2] = {
		/*0F_3A_0D*/{ NULL, NULL, NULL },
		/*0F_3A_0D*/{ &blendpd_context_Vpd1_Wpd0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_0E[2] = {
		/*0F_3A_0E*/{ NULL, NULL, NULL },
		/*0F_3A_0E*/{ &pblendw_context_Vdq1_Wdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_0F[2] = {
		/*0F_3A_0F*/{ &palignr_context_Pq1_Qq0, NULL, NULL },
		/*0F_3A_0F*/{ &palignr_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_3A_14_mod_perfix_66[2] = {
		/*0F_3A_14*/{ &pextrb_context_Mb1_Vdq0_Ib0, NULL, NULL },
		/*0F_3A_14*/{ &pextrb_context_Rdqp1_Vdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_14[2] = {
		/*0F_3A_14*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_3A_14_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_3A_15_mod_perfix_66[2] = {
		/*0F_3A_15*/{ &pextrw_context_Mw1_Vdq0_Ib0, NULL, NULL },
		/*0F_3A_15*/{ &pextrw_context_Rdqp1_Vdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_15[2] = {
		/*0F_3A_15*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_3A_15_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_16[2] = {
		/*0F_3A_16*/{ NULL, NULL, NULL },
		/*0F_3A_16*/{ &pextrq_context_Eqp1_Vdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_17[2] = {
		/*0F_3A_17*/{ NULL, NULL, NULL },
		/*0F_3A_17*/{ &extractps_context_Ed1_Vdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_3A_20_mod_perfix_66[2] = {
		/*0F_3A_20*/{ &pinsrb_context_Vdq1_Mb0_Ib0, NULL, NULL },
		/*0F_3A_20*/{ &pinsrb_context_Vdq1_Rdqp0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_20[2] = {
		/*0F_3A_20*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_3A_20_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_3A_21_mod_perfix_66[2] = {
		/*0F_3A_21*/{ &insertps_context_Vps1_Md0_Ib0, NULL, NULL },
		/*0F_3A_21*/{ &insertps_context_Vps1_Ups0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_21[2] = {
		/*0F_3A_21*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_3A_21_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_22[2] = {
		/*0F_3A_22*/{ NULL, NULL, NULL },
		/*0F_3A_22*/{ &pinsrq_context_Vdq1_Eqp0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_40[2] = {
		/*0F_3A_40*/{ NULL, NULL, NULL },
		/*0F_3A_40*/{ &dpps_context_Vps1_Wps0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_41[2] = {
		/*0F_3A_41*/{ NULL, NULL, NULL },
		/*0F_3A_41*/{ &dppd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_42[2] = {
		/*0F_3A_42*/{ NULL, NULL, NULL },
		/*0F_3A_42*/{ &mpsadbw_context_Vdq1_Wdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_60[2] = {
		/*0F_3A_60*/{ NULL, NULL, NULL },
		/*0F_3A_60*/{ &pcmpestrm_context_Xmm3_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_61[2] = {
		/*0F_3A_61*/{ NULL, NULL, NULL },
		/*0F_3A_61*/{ &pcmpestri_context_Gendqp35_Vdq0_Wdq0_Ib0_Gendqp2_Gendqp66, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_62[2] = {
		/*0F_3A_62*/{ NULL, NULL, NULL },
		/*0F_3A_62*/{ &pcmpistrm_context_Xmm3_Vdq0_Wdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_3A_63[2] = {
		/*0F_3A_63*/{ NULL, NULL, NULL },
		/*0F_3A_63*/{ &pcmpistri_context_Gendqp35_Vdq0_Wdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_extended_0F_3A[100] = {
		/*0F_3A_00*/{ NULL, NULL, NULL },
		/*0F_3A_01*/{ NULL, NULL, NULL },
		/*0F_3A_02*/{ NULL, NULL, NULL },
		/*0F_3A_03*/{ NULL, NULL, NULL },
		/*0F_3A_04*/{ NULL, NULL, NULL },
		/*0F_3A_05*/{ NULL, NULL, NULL },
		/*0F_3A_06*/{ NULL, NULL, NULL },
		/*0F_3A_07*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_3A_08, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_09, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_0A, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_0B, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_0C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_0D, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_0E, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_0F, read_table_offset_by_prefix },
		/*0F_3A_10*/{ NULL, NULL, NULL },
		/*0F_3A_11*/{ NULL, NULL, NULL },
		/*0F_3A_12*/{ NULL, NULL, NULL },
		/*0F_3A_13*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_3A_14, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_15, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_16, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_17, read_table_offset_by_prefix },
		/*0F_3A_18*/{ NULL, NULL, NULL },
		/*0F_3A_19*/{ NULL, NULL, NULL },
		/*0F_3A_1A*/{ NULL, NULL, NULL },
		/*0F_3A_1B*/{ NULL, NULL, NULL },
		/*0F_3A_1C*/{ NULL, NULL, NULL },
		/*0F_3A_1D*/{ NULL, NULL, NULL },
		/*0F_3A_1E*/{ NULL, NULL, NULL },
		/*0F_3A_1F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_3A_20, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_21, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_22, read_table_offset_by_prefix },
		/*0F_3A_23*/{ NULL, NULL, NULL },
		/*0F_3A_24*/{ NULL, NULL, NULL },
		/*0F_3A_25*/{ NULL, NULL, NULL },
		/*0F_3A_26*/{ NULL, NULL, NULL },
		/*0F_3A_27*/{ NULL, NULL, NULL },
		/*0F_3A_28*/{ NULL, NULL, NULL },
		/*0F_3A_29*/{ NULL, NULL, NULL },
		/*0F_3A_2A*/{ NULL, NULL, NULL },
		/*0F_3A_2B*/{ NULL, NULL, NULL },
		/*0F_3A_2C*/{ NULL, NULL, NULL },
		/*0F_3A_2D*/{ NULL, NULL, NULL },
		/*0F_3A_2E*/{ NULL, NULL, NULL },
		/*0F_3A_2F*/{ NULL, NULL, NULL },
		/*0F_3A_30*/{ NULL, NULL, NULL },
		/*0F_3A_31*/{ NULL, NULL, NULL },
		/*0F_3A_32*/{ NULL, NULL, NULL },
		/*0F_3A_33*/{ NULL, NULL, NULL },
		/*0F_3A_34*/{ NULL, NULL, NULL },
		/*0F_3A_35*/{ NULL, NULL, NULL },
		/*0F_3A_36*/{ NULL, NULL, NULL },
		/*0F_3A_37*/{ NULL, NULL, NULL },
		/*0F_3A_38*/{ NULL, NULL, NULL },
		/*0F_3A_39*/{ NULL, NULL, NULL },
		/*0F_3A_3A*/{ NULL, NULL, NULL },
		/*0F_3A_3B*/{ NULL, NULL, NULL },
		/*0F_3A_3C*/{ NULL, NULL, NULL },
		/*0F_3A_3D*/{ NULL, NULL, NULL },
		/*0F_3A_3E*/{ NULL, NULL, NULL },
		/*0F_3A_3F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_3A_40, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_41, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_42, read_table_offset_by_prefix },
		/*0F_3A_43*/{ NULL, NULL, NULL },
		/*0F_3A_44*/{ NULL, NULL, NULL },
		/*0F_3A_45*/{ NULL, NULL, NULL },
		/*0F_3A_46*/{ NULL, NULL, NULL },
		/*0F_3A_47*/{ NULL, NULL, NULL },
		/*0F_3A_48*/{ NULL, NULL, NULL },
		/*0F_3A_49*/{ NULL, NULL, NULL },
		/*0F_3A_4A*/{ NULL, NULL, NULL },
		/*0F_3A_4B*/{ NULL, NULL, NULL },
		/*0F_3A_4C*/{ NULL, NULL, NULL },
		/*0F_3A_4D*/{ NULL, NULL, NULL },
		/*0F_3A_4E*/{ NULL, NULL, NULL },
		/*0F_3A_4F*/{ NULL, NULL, NULL },
		/*0F_3A_50*/{ NULL, NULL, NULL },
		/*0F_3A_51*/{ NULL, NULL, NULL },
		/*0F_3A_52*/{ NULL, NULL, NULL },
		/*0F_3A_53*/{ NULL, NULL, NULL },
		/*0F_3A_54*/{ NULL, NULL, NULL },
		/*0F_3A_55*/{ NULL, NULL, NULL },
		/*0F_3A_56*/{ NULL, NULL, NULL },
		/*0F_3A_57*/{ NULL, NULL, NULL },
		/*0F_3A_58*/{ NULL, NULL, NULL },
		/*0F_3A_59*/{ NULL, NULL, NULL },
		/*0F_3A_5A*/{ NULL, NULL, NULL },
		/*0F_3A_5B*/{ NULL, NULL, NULL },
		/*0F_3A_5C*/{ NULL, NULL, NULL },
		/*0F_3A_5D*/{ NULL, NULL, NULL },
		/*0F_3A_5E*/{ NULL, NULL, NULL },
		/*0F_3A_5F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_3A_60, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_61, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_62, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_3A_63, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_0F_00_mod_opcode_extension_0[2] = {
		/*0F_00*/{ &sldt_context_Mw1_ldtr2, NULL, NULL },
		/*0F_00*/{ &sldt_context_Rvqp1_ldtr2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_00_mod_opcode_extension_1[2] = {
		/*0F_00*/{ &str_context_Mw1_tr2, NULL, NULL },
		/*0F_00*/{ &str_context_Rvqp1_tr2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_00[7] = {
		{ NULL, &table_0F_00_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_0F_00_mod_opcode_extension_1, read_table_offset_by_mod },
		/*0F_00*/{ &lldt_context_ldtr3_Ew0, NULL, NULL },
		/*0F_00*/{ &ltr_context_tr3_Ew0, NULL, NULL },
		/*0F_00*/{ &verr_context_Ew0, NULL, NULL },
		/*0F_00*/{ &verw_context_Ew0, NULL, NULL },
		/*0F_00*/{ &jmpe_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_01_opcode_extension_0_second_opcode[5] = {
		/*0F_01*/{ NULL, NULL, NULL },
		/*0F_01*/{ &vmcall_context, NULL, NULL },
		/*0F_01*/{ &vmlaunch_context, NULL, NULL },
		/*0F_01*/{ &vmresume_context, NULL, NULL },
		/*0F_01*/{ &vmxoff_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_01_mod_opcode_extension_0[2] = {
		/*0F_01*/{ &sgdt_context_Ms1_gdtr2, NULL, NULL },
		{ NULL, &table_0F_01_opcode_extension_0_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_0F_01_opcode_extension_1_second_opcode[2] = {
		/*0F_01*/{ &monitor_context_BAb2_Gend34_Gend66, NULL, NULL },
		/*0F_01*/{ &mwait_context_Gend2_Gend34, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_01_mod_opcode_extension_1[2] = {
		/*0F_01*/{ &sidt_context_Ms1_idtr2, NULL, NULL },
		{ NULL, &table_0F_01_opcode_extension_1_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_0F_01_opcode_extension_2_second_opcode[2] = {
		/*0F_01*/{ &xgetbv_context_Gend67_Gend3_Gend34_xcr2, NULL, NULL },
		/*0F_01*/{ &xsetbv_context_xcr3_Gend34_Gend66_Gend2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_01_mod_opcode_extension_2[2] = {
		/*0F_01*/{ &lgdt_context_gdtr3_Ms0, NULL, NULL },
		{ NULL, &table_0F_01_opcode_extension_2_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_0F_01_mod_opcode_extension_3[1] = {
		/*0F_01*/{ &lidt_context_idtr3_Ms0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_01_mod_opcode_extension_4[2] = {
		/*0F_01*/{ &smsw_context_Mw1_msww2, NULL, NULL },
		/*0F_01*/{ &smsw_context_Rvqp1_msww2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_01_opcode_extension_7_second_opcode[2] = {
		/*0F_01*/{ NULL, NULL, NULL },
		/*0F_01*/{ &rdtscp_context_Gend3_Gend67_Gend35_ia32_time_stamp_counter2_ia32_tsc_aux2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_01_mod_opcode_extension_7[2] = {
		/*0F_01*/{ &invlpg_context_M0, NULL, NULL },
		{ NULL, &table_0F_01_opcode_extension_7_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_01[8] = {
		{ NULL, &table_0F_01_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_0F_01_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_0F_01_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_0F_01_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_0F_01_mod_opcode_extension_4, read_table_offset_by_mod },
		/*0F_01*/{ NULL, NULL, NULL },
		/*0F_01*/{ &lmsw_context_msww3_Ew0, NULL, NULL },
		{ NULL, &table_0F_01_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_02_mod[2] = {
		/*0F_02*/{ &lar_context_Gvqp1_Mw0, NULL, NULL },
		/*0F_02*/{ &lar_context_Gvqp1_Rv0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_03_mod[2] = {
		/*0F_03*/{ &lsl_context_Gvqp1_Mw0, NULL, NULL },
		/*0F_03*/{ &lsl_context_Gvqp1_Rv0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_10[4] = {
		/*0F_10*/{ &movups_context_Vps1_Wps0, NULL, NULL },
		/*0F_10*/{ &movupd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_10*/{ &movsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_10*/{ &movss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_11[4] = {
		/*0F_11*/{ &movups_context_Wps1_Vps0, NULL, NULL },
		/*0F_11*/{ &movupd_context_Wpd1_Vpd0, NULL, NULL },
		/*0F_11*/{ &movsd_context_Wsd1_Vsd0, NULL, NULL },
		/*0F_11*/{ &movss_context_Wss1_Vss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_12_mod[2] = {
		/*0F_12*/{ &movlps_context_Vq1_Mq0, NULL, NULL },
		/*0F_12*/{ &movhlps_context_Vq1_Uq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_12_mod_perfix_66[1] = {
		/*0F_12*/{ &movlpd_context_Vq1_Mq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_12[4] = {
		{ NULL, &table_0F_12_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_12_mod_perfix_66, read_table_offset_by_mod },
		/*0F_12*/{ &mopadup_context_Vq1_Wq0, NULL, NULL },
		/*0F_12*/{ &movsldup_context_Vq1_Wq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_13_mod[1] = {
		/*0F_13*/{ &movlps_context_Mq1_Vq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_13_mod_perfix_66[1] = {
		/*0F_13*/{ &movlpd_context_Mq1_Vq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_13[2] = {
		{ NULL, &table_0F_13_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_13_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_14[2] = {
		/*0F_14*/{ &unpcklps_context_Vps1_Wq0, NULL, NULL },
		/*0F_14*/{ &unpcklpd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_15[2] = {
		/*0F_15*/{ &unpckhps_context_Vps1_Wq0, NULL, NULL },
		/*0F_15*/{ &unpckhpd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_16_mod[2] = {
		/*0F_16*/{ &movhps_context_Vq1_Mq0, NULL, NULL },
		/*0F_16*/{ &movlhps_context_Vq1_Uq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_16_mod_perfix_66[1] = {
		/*0F_16*/{ &movhpd_context_Vq1_Mq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_16[4] = {
		{ NULL, &table_0F_16_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_16_mod_perfix_66, read_table_offset_by_mod },
		/*0F_16*/{ NULL, NULL, NULL },
		/*0F_16*/{ &movshdup_context_Vq1_Wq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_17_mod[1] = {
		/*0F_17*/{ &movhps_context_Mq1_Vq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_17_mod_perfix_66[1] = {
		/*0F_17*/{ &movhpd_context_Mq1_Vq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_17[2] = {
		{ NULL, &table_0F_17_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_17_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_18_mod_opcode_extension_0[1] = {
		/*0F_18*/{ &prefetchnta_context_Mb0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_18_mod_opcode_extension_1[1] = {
		/*0F_18*/{ &prefetcht0_context_Mb0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_18_mod_opcode_extension_2[1] = {
		/*0F_18*/{ &prefetcht1_context_Mb0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_18_mod_opcode_extension_3[1] = {
		/*0F_18*/{ &prefetcht2_context_Mb0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_18[8] = {
		{ NULL, &table_0F_18_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_0F_18_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_0F_18_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_0F_18_mod_opcode_extension_3, read_table_offset_by_mod },
		/*0F_18*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_18*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_18*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_18*/{ &hint_nop_context_Ev0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_1F[8] = {
		/*0F_1F*/{ &nop_context_Ev0, NULL, NULL },
		/*0F_1F*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1F*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1F*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1F*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1F*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1F*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1F*/{ &hint_nop_context_Ev0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_28[2] = {
		/*0F_28*/{ &movaps_context_Vps1_Wps0, NULL, NULL },
		/*0F_28*/{ &movapd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_29[2] = {
		/*0F_29*/{ &movaps_context_Wps1_Vps0, NULL, NULL },
		/*0F_29*/{ &movapd_context_Wpd1_Vpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_2A[4] = {
		/*0F_2A*/{ &cvtpi2ps_context_Vps1_Qpi0, NULL, NULL },
		/*0F_2A*/{ &cvtpi2pd_context_Vpd1_Qpi0, NULL, NULL },
		/*0F_2A*/{ &cvtsi2sd_context_Vsd1_Edqp0, NULL, NULL },
		/*0F_2A*/{ &cvtsi2ss_context_Vss1_Edqp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_2B_mod[1] = {
		/*0F_2B*/{ &movntps_context_Mps1_Vps0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_2B_mod_perfix_66[1] = {
		/*0F_2B*/{ &movntpd_context_Mpd1_Vpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_2B[2] = {
		{ NULL, &table_0F_2B_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_2B_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_2C[4] = {
		/*0F_2C*/{ &cvttps2pi_context_Ppi1_Wpsq0, NULL, NULL },
		/*0F_2C*/{ &cvttpd2pi_context_Ppi1_Wpd0, NULL, NULL },
		/*0F_2C*/{ &cvttsd2si_context_Gdqp1_Wsd0, NULL, NULL },
		/*0F_2C*/{ &cvttss2si_context_Gdqp1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_2D[4] = {
		/*0F_2D*/{ &cvtps2pi_context_Ppi1_Wpsq0, NULL, NULL },
		/*0F_2D*/{ &cvtpd2pi_context_Ppi1_Wpd0, NULL, NULL },
		/*0F_2D*/{ &cvtsd2si_context_Gdqp1_Wsd0, NULL, NULL },
		/*0F_2D*/{ &cvtss2si_context_Gdqp1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_2E[2] = {
		/*0F_2E*/{ &ucomiss_context_Vss0_Wss0, NULL, NULL },
		/*0F_2E*/{ &ucomisd_context_Vsd0_Wsd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_2F[2] = {
		/*0F_2F*/{ &comiss_context_Vss0_Wss0, NULL, NULL },
		/*0F_2F*/{ &comisd_context_Vsd0_Wsd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_50_mod[2] = {
		/*0F_50*/{ NULL, NULL, NULL },
		/*0F_50*/{ &movmskps_context_Gdqp1_Ups0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_50_mod_perfix_66[2] = {
		/*0F_50*/{ NULL, NULL, NULL },
		/*0F_50*/{ &movmskpd_context_Gdqp1_Upd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_50[2] = {
		{ NULL, &table_0F_50_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_50_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_51[4] = {
		/*0F_51*/{ &sqrtps_context_Vps1_Wps0, NULL, NULL },
		/*0F_51*/{ &sqrtpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_51*/{ &sqrtsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_51*/{ &sqrtss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_52[4] = {
		/*0F_52*/{ &rsqrtps_context_Vps1_Wps0, NULL, NULL },
		/*0F_52*/{ NULL, NULL, NULL },
		/*0F_52*/{ NULL, NULL, NULL },
		/*0F_52*/{ &rsqrtss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_53[4] = {
		/*0F_53*/{ &rcpps_context_Vps1_Wps0, NULL, NULL },
		/*0F_53*/{ NULL, NULL, NULL },
		/*0F_53*/{ NULL, NULL, NULL },
		/*0F_53*/{ &rcpss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_54[2] = {
		/*0F_54*/{ &andps_context_Vps1_Wps0, NULL, NULL },
		/*0F_54*/{ &andpd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_55[2] = {
		/*0F_55*/{ &andnps_context_Vps1_Wps0, NULL, NULL },
		/*0F_55*/{ &andnpd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_56[2] = {
		/*0F_56*/{ &orps_context_Vps1_Wps0, NULL, NULL },
		/*0F_56*/{ &orpd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_57[2] = {
		/*0F_57*/{ &xorps_context_Vps1_Wps0, NULL, NULL },
		/*0F_57*/{ &xorpd_context_Vpd1_Wpd0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_58[4] = {
		/*0F_58*/{ &addps_context_Vps1_Wps0, NULL, NULL },
		/*0F_58*/{ &addpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_58*/{ &addsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_58*/{ &addss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_59[4] = {
		/*0F_59*/{ &mulps_context_Vps1_Wps0, NULL, NULL },
		/*0F_59*/{ &mulpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_59*/{ &mulsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_59*/{ &mulss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_5A[4] = {
		/*0F_5A*/{ &cvtps2pd_context_Vpd1_Wps0, NULL, NULL },
		/*0F_5A*/{ &cvtpd2ps_context_Vps1_Wpd0, NULL, NULL },
		/*0F_5A*/{ &cvtsd2ss_context_Vss1_Wsd0, NULL, NULL },
		/*0F_5A*/{ &cvtss2sd_context_Vsd1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_5B[4] = {
		/*0F_5B*/{ &cvtdq2ps_context_Vps1_Wdq0, NULL, NULL },
		/*0F_5B*/{ &cvtps2dq_context_Vdq1_Wps0, NULL, NULL },
		/*0F_5B*/{ NULL, NULL, NULL },
		/*0F_5B*/{ &cvttps2dq_context_Vdq1_Wps0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_5C[4] = {
		/*0F_5C*/{ &subps_context_Vps1_Wps0, NULL, NULL },
		/*0F_5C*/{ &subpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_5C*/{ &subsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_5C*/{ &subss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_5D[4] = {
		/*0F_5D*/{ &minps_context_Vps1_Wps0, NULL, NULL },
		/*0F_5D*/{ &minpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_5D*/{ &minsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_5D*/{ &minss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_5E[4] = {
		/*0F_5E*/{ &divps_context_Vps1_Wps0, NULL, NULL },
		/*0F_5E*/{ &divpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_5E*/{ &divsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_5E*/{ &divss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_5F[4] = {
		/*0F_5F*/{ &maxps_context_Vps1_Wps0, NULL, NULL },
		/*0F_5F*/{ &maxpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_5F*/{ &maxsd_context_Vsd1_Wsd0, NULL, NULL },
		/*0F_5F*/{ &maxss_context_Vss1_Wss0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_60[2] = {
		/*0F_60*/{ &punpcklbw_context_Pq1_Qd0, NULL, NULL },
		/*0F_60*/{ &punpcklbw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_61[2] = {
		/*0F_61*/{ &punpcklwd_context_Pq1_Qd0, NULL, NULL },
		/*0F_61*/{ &punpcklwd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_62[2] = {
		/*0F_62*/{ &punpckldq_context_Pq1_Qd0, NULL, NULL },
		/*0F_62*/{ &punpckldq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_63[2] = {
		/*0F_63*/{ &packsswb_context_Pq1_Qd0, NULL, NULL },
		/*0F_63*/{ &packsswb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_64[2] = {
		/*0F_64*/{ &pcmpgtb_context_Pq1_Qd0, NULL, NULL },
		/*0F_64*/{ &pcmpgtb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_65[2] = {
		/*0F_65*/{ &pcmpgtw_context_Pq1_Qd0, NULL, NULL },
		/*0F_65*/{ &pcmpgtw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_66[2] = {
		/*0F_66*/{ &pcmpgtd_context_Pq1_Qd0, NULL, NULL },
		/*0F_66*/{ &pcmpgtd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_67[2] = {
		/*0F_67*/{ &packuswb_context_Pq1_Qq0, NULL, NULL },
		/*0F_67*/{ &packuswb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_68[2] = {
		/*0F_68*/{ &punpckhbw_context_Pq1_Qq0, NULL, NULL },
		/*0F_68*/{ &punpckhbw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_69[2] = {
		/*0F_69*/{ &punpckhwd_context_Pq1_Qq0, NULL, NULL },
		/*0F_69*/{ &punpckhwd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_6A[2] = {
		/*0F_6A*/{ &punpckhdq_context_Pq1_Qq0, NULL, NULL },
		/*0F_6A*/{ &punpckhdq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_6B[2] = {
		/*0F_6B*/{ &packssdw_context_Pq1_Qq0, NULL, NULL },
		/*0F_6B*/{ &packssdw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_6C[2] = {
		/*0F_6C*/{ NULL, NULL, NULL },
		/*0F_6C*/{ &punpcklqdq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_6D[2] = {
		/*0F_6D*/{ NULL, NULL, NULL },
		/*0F_6D*/{ &punpckhqdq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_6E[2] = {
		/*0F_6E*/{ &mopa_context_Pq1_Ed0, NULL, NULL },
		/*0F_6E*/{ &mopa_context_Vdq1_Ed0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_6F[4] = {
		/*0F_6F*/{ &movq_context_Pq1_Qq0, NULL, NULL },
		/*0F_6F*/{ &mopaqa_context_Vdq1_Wdq0, NULL, NULL },
		/*0F_6F*/{ NULL, NULL, NULL },
		/*0F_6F*/{ &mopaqu_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_70[4] = {
		/*0F_70*/{ &pshufw_context_Pq1_Qq0_Ib0, NULL, NULL },
		/*0F_70*/{ &pshufd_context_Vdq1_Wdq0_Ib0, NULL, NULL },
		/*0F_70*/{ &pshuflw_context_Vdq1_Wdq0_Ib0, NULL, NULL },
		/*0F_70*/{ &pshufhw_context_Vdq1_Wdq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_71_opcode_extension_2[2] = {
		/*0F_71*/{ &psrlw_context_Nq1_Ib0, NULL, NULL },
		/*0F_71*/{ &psrlw_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_71_mod_opcode_extension_2[2] = {
		/*0F_71*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_71_opcode_extension_2, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_71_opcode_extension_4[2] = {
		/*0F_71*/{ &psraw_context_Nq1_Ib0, NULL, NULL },
		/*0F_71*/{ &psraw_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_71_mod_opcode_extension_4[2] = {
		/*0F_71*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_71_opcode_extension_4, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_71_opcode_extension_6[2] = {
		/*0F_71*/{ &psllw_context_Nq1_Ib0, NULL, NULL },
		/*0F_71*/{ &psllw_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_71_mod_opcode_extension_6[2] = {
		/*0F_71*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_71_opcode_extension_6, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_71[7] = {
		/*0F_71*/{ NULL, NULL, NULL },
		/*0F_71*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_71_mod_opcode_extension_2, read_table_offset_by_mod },
		/*0F_71*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_71_mod_opcode_extension_4, read_table_offset_by_mod },
		/*0F_71*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_71_mod_opcode_extension_6, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_72_opcode_extension_2[2] = {
		/*0F_72*/{ &psrld_context_Nq1_Ib0, NULL, NULL },
		/*0F_72*/{ &psrld_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_72_mod_opcode_extension_2[2] = {
		/*0F_72*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_72_opcode_extension_2, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_72_opcode_extension_4[2] = {
		/*0F_72*/{ &psrad_context_Nq1_Ib0, NULL, NULL },
		/*0F_72*/{ &psrad_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_72_mod_opcode_extension_4[2] = {
		/*0F_72*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_72_opcode_extension_4, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_72_opcode_extension_6[2] = {
		/*0F_72*/{ &pslld_context_Nq1_Ib0, NULL, NULL },
		/*0F_72*/{ &pslld_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_72_mod_opcode_extension_6[2] = {
		/*0F_72*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_72_opcode_extension_6, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_72[7] = {
		/*0F_72*/{ NULL, NULL, NULL },
		/*0F_72*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_72_mod_opcode_extension_2, read_table_offset_by_mod },
		/*0F_72*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_72_mod_opcode_extension_4, read_table_offset_by_mod },
		/*0F_72*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_72_mod_opcode_extension_6, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_73_opcode_extension_2[2] = {
		/*0F_73*/{ &psrlq_context_Nq1_Ib0, NULL, NULL },
		/*0F_73*/{ &psrlq_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_73_mod_opcode_extension_2[2] = {
		/*0F_73*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_73_opcode_extension_2, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_73_opcode_extension_3[2] = {
		/*0F_73*/{ NULL, NULL, NULL },
		/*0F_73*/{ &psrldq_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_73_mod_opcode_extension_3_perfix_66[2] = {
		/*0F_73*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_73_opcode_extension_3, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_73_opcode_extension_6[2] = {
		/*0F_73*/{ &psllq_context_Nq1_Ib0, NULL, NULL },
		/*0F_73*/{ &psllq_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_73_mod_opcode_extension_6[2] = {
		/*0F_73*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_73_opcode_extension_6, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_73_opcode_extension_7[2] = {
		/*0F_73*/{ NULL, NULL, NULL },
		/*0F_73*/{ &pslldq_context_Udq1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_73_mod_opcode_extension_7_perfix_66[2] = {
		/*0F_73*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_73_opcode_extension_7, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_73[8] = {
		/*0F_73*/{ NULL, NULL, NULL },
		/*0F_73*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_73_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_0F_73_mod_opcode_extension_3_perfix_66, read_table_offset_by_mod },
		/*0F_73*/{ NULL, NULL, NULL },
		/*0F_73*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_73_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_0F_73_mod_opcode_extension_7_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_74[2] = {
		/*0F_74*/{ &pcmpeqb_context_Pq1_Qq0, NULL, NULL },
		/*0F_74*/{ &pcmpeqb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_75[2] = {
		/*0F_75*/{ &pcmpeqw_context_Pq1_Qq0, NULL, NULL },
		/*0F_75*/{ &pcmpeqw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_76[2] = {
		/*0F_76*/{ &pcmpeqd_context_Pq1_Qq0, NULL, NULL },
		/*0F_76*/{ &pcmpeqd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_7C[3] = {
		/*0F_7C*/{ NULL, NULL, NULL },
		/*0F_7C*/{ &haddpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_7C*/{ &haddps_context_Vps1_Wps0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_7D[3] = {
		/*0F_7D*/{ NULL, NULL, NULL },
		/*0F_7D*/{ &hsubpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_7D*/{ &hsubps_context_Vps1_Wps0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_7E[4] = {
		/*0F_7E*/{ &mopa_context_Ed1_Pq0, NULL, NULL },
		/*0F_7E*/{ &mopa_context_Ed1_Vdq0, NULL, NULL },
		/*0F_7E*/{ NULL, NULL, NULL },
		/*0F_7E*/{ &movq_context_Vq1_Wq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_7F[4] = {
		/*0F_7F*/{ &movq_context_Qq1_Pq0, NULL, NULL },
		/*0F_7F*/{ &mopaqa_context_Wdq1_Vdq0, NULL, NULL },
		/*0F_7F*/{ NULL, NULL, NULL },
		/*0F_7F*/{ &mopaqu_context_Wdq1_Vdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_AE_mod_opcode_extension_0[1] = {
		/*0F_AE*/{ &fxsave_context_Mstx1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_AE_mod_opcode_extension_1[1] = {
		/*0F_AE*/{ &fxrstor_context_X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_Mstx0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_AE_mod_opcode_extension_2[1] = {
		/*0F_AE*/{ &ldmxcsr_context_Md0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_AE_mod_opcode_extension_3[1] = {
		/*0F_AE*/{ &stmxcsr_context_Md1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_AE_mod_opcode_extension_4[1] = {
		/*0F_AE*/{ &xsave_context_M1_Gend66_Gend2_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226_Mmx2_Mmx34_Mmx66_Mmx98_Mmx130_Mmx162_Mmx194_Mmx226_Xmm2_Xmm34_Xmm66_Xmm98_Xmm130_Xmm162_Xmm194_Xmm226, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_AE_mod_opcode_extension_5[2] = {
		/*0F_AE*/{ &xrstor_context_X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mmx3_Mmx35_Mmx67_Mmx99_Mmx131_Mmx163_Mmx195_Mmx227_Xmm3_Xmm35_Xmm67_Xmm99_Xmm131_Xmm163_Xmm195_Xmm227_M0_Gend66_Gend2, NULL, NULL },
		/*0F_AE*/{ &lfence_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_AE_mod_opcode_extension_7[2] = {
		/*0F_AE*/{ &clflush_context_Mb0, NULL, NULL },
		/*0F_AE*/{ &sfence_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_AE[8] = {
		{ NULL, &table_0F_AE_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_0F_AE_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_0F_AE_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_0F_AE_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_0F_AE_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_0F_AE_mod_opcode_extension_5, read_table_offset_by_mod },
		/*0F_AE*/{ &mfence_context, NULL, NULL },
		{ NULL, &table_0F_AE_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_B2_mod[1] = {
		/*0F_B2*/{ &lss_context_S30w3_Gvqp1_Mptp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_B4_mod[1] = {
		/*0F_B4*/{ &lfs_context_S30w3_Gvqp1_Mptp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_B5_mod[1] = {
		/*0F_B5*/{ &lgs_context_S30w3_Gvqp1_Mptp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_B8[4] = {
		/*0F_B8*/{ &jmpe_context, NULL, NULL },
		/*0F_B8*/{ NULL, NULL, NULL },
		/*0F_B8*/{ NULL, NULL, NULL },
		/*0F_B8*/{ &popcnt_context_Gvqp1_Evqp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_BA[8] = {
		/*0F_BA*/{ NULL, NULL, NULL },
		/*0F_BA*/{ NULL, NULL, NULL },
		/*0F_BA*/{ NULL, NULL, NULL },
		/*0F_BA*/{ NULL, NULL, NULL },
		/*0F_BA*/{ &bt_context_Evqp0_Ib0, NULL, NULL },
		/*0F_BA*/{ &bts_context_Evqp1_Ib0, NULL, NULL },
		/*0F_BA*/{ &btr_context_Evqp1_Ib0, NULL, NULL },
		/*0F_BA*/{ &btc_context_Evqp1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_C2[4] = {
		/*0F_C2*/{ &cmpps_context_Vps1_Wps0_Ib0, NULL, NULL },
		/*0F_C2*/{ &cmppd_context_Vpd1_Wpd0_Ib0, NULL, NULL },
		/*0F_C2*/{ &cmpsd_context_Vsd1_Wsd0_Ib0, NULL, NULL },
		/*0F_C2*/{ &cmpss_context_Vss1_Wss0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_C3_mod[1] = {
		/*0F_C3*/{ &movnti_context_Mdqp1_Gdqp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_C4_mod[2] = {
		/*0F_C4*/{ &pinsrw_context_Pq1_Mw0_Ib0, NULL, NULL },
		/*0F_C4*/{ &pinsrw_context_Pq1_Rdqp0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_C4_mod_perfix_66[2] = {
		/*0F_C4*/{ &pinsrw_context_Vdq1_Mw0_Ib0, NULL, NULL },
		/*0F_C4*/{ &pinsrw_context_Vdq1_Rdqp0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_C4[2] = {
		{ NULL, &table_0F_C4_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_C4_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_C5_mod[2] = {
		/*0F_C5*/{ NULL, NULL, NULL },
		/*0F_C5*/{ &pextrw_context_Gdqp1_Nq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_C5_mod_perfix_66[2] = {
		/*0F_C5*/{ NULL, NULL, NULL },
		/*0F_C5*/{ &pextrw_context_Gdqp1_Udq0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_C5[2] = {
		{ NULL, &table_0F_C5_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_C5_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_C6[2] = {
		/*0F_C6*/{ &shufps_context_Vps1_Wps0_Ib0, NULL, NULL },
		/*0F_C6*/{ &shufpd_context_Vpd1_Wpd0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_C7_mod_opcode_extension_1[1] = {
		/*0F_C7*/{ &cmpxchg8b_context_Mq1_Gend3_Gend67_Gend98_Gend34, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_C7_opcode_extension_6[4] = {
		/*0F_C7*/{ &vmptrld_context_Mq0, NULL, NULL },
		/*0F_C7*/{ &vmclear_context_Mq1, NULL, NULL },
		/*0F_C7*/{ NULL, NULL, NULL },
		/*0F_C7*/{ &vmxon_context_Mq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_C7_mod_opcode_extension_6[1] = {
		{ NULL, &table_prefix_0F_C7_opcode_extension_6, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_0F_C7_mod_opcode_extension_7[1] = {
		/*0F_C7*/{ &vmptrst_context_Mq1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_0F_C7[8] = {
		/*0F_C7*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_C7_mod_opcode_extension_1, read_table_offset_by_mod },
		/*0F_C7*/{ NULL, NULL, NULL },
		/*0F_C7*/{ NULL, NULL, NULL },
		/*0F_C7*/{ NULL, NULL, NULL },
		/*0F_C7*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_C7_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_0F_C7_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D0[3] = {
		/*0F_D0*/{ NULL, NULL, NULL },
		/*0F_D0*/{ &addsubpd_context_Vpd1_Wpd0, NULL, NULL },
		/*0F_D0*/{ &addsubps_context_Vps1_Wps0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D1[2] = {
		/*0F_D1*/{ &psrlw_context_Pq1_Qq0, NULL, NULL },
		/*0F_D1*/{ &psrlw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D2[2] = {
		/*0F_D2*/{ &psrld_context_Pq1_Qq0, NULL, NULL },
		/*0F_D2*/{ &psrld_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D3[2] = {
		/*0F_D3*/{ &psrlq_context_Pq1_Qq0, NULL, NULL },
		/*0F_D3*/{ &psrlq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D4[2] = {
		/*0F_D4*/{ &paddq_context_Pq1_Qq0, NULL, NULL },
		/*0F_D4*/{ &paddq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D5[2] = {
		/*0F_D5*/{ &pmullw_context_Pq1_Qq0, NULL, NULL },
		/*0F_D5*/{ &pmullw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_D6_mod_perfix_F2[2] = {
		/*0F_D6*/{ NULL, NULL, NULL },
		/*0F_D6*/{ &mopaq2q_context_Pq1_Uq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_D6_mod_perfix_F3[2] = {
		/*0F_D6*/{ NULL, NULL, NULL },
		/*0F_D6*/{ &movq2dq_context_Vdq1_Nq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D6[4] = {
		/*0F_D6*/{ NULL, NULL, NULL },
		/*0F_D6*/{ &movq_context_Wq1_Vq0, NULL, NULL },
		{ NULL, &table_0F_D6_mod_perfix_F2, read_table_offset_by_mod },
		{ NULL, &table_0F_D6_mod_perfix_F3, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_0F_D7_mod[2] = {
		/*0F_D7*/{ NULL, NULL, NULL },
		/*0F_D7*/{ &pmovmskb_context_Gdqp1_Nq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_D7_mod_perfix_66[2] = {
		/*0F_D7*/{ NULL, NULL, NULL },
		/*0F_D7*/{ &pmovmskb_context_Gdqp1_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D7[2] = {
		{ NULL, &table_0F_D7_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_D7_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D8[2] = {
		/*0F_D8*/{ &psubusb_context_Pq1_Qq0, NULL, NULL },
		/*0F_D8*/{ &psubusb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_D9[2] = {
		/*0F_D9*/{ &psubusw_context_Pq1_Qq0, NULL, NULL },
		/*0F_D9*/{ &psubusw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_DA[2] = {
		/*0F_DA*/{ &pminub_context_Pq1_Qq0, NULL, NULL },
		/*0F_DA*/{ &pminub_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_DB[2] = {
		/*0F_DB*/{ &pand_context_Pq1_Qd0, NULL, NULL },
		/*0F_DB*/{ &pand_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_DC[2] = {
		/*0F_DC*/{ &paddusb_context_Pq1_Qq0, NULL, NULL },
		/*0F_DC*/{ &paddusb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_DD[2] = {
		/*0F_DD*/{ &paddusw_context_Pq1_Qq0, NULL, NULL },
		/*0F_DD*/{ &paddusw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_DE[2] = {
		/*0F_DE*/{ &pmaxub_context_Pq1_Qq0, NULL, NULL },
		/*0F_DE*/{ &pmaxub_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_DF[2] = {
		/*0F_DF*/{ &pandn_context_Pq1_Qq0, NULL, NULL },
		/*0F_DF*/{ &pandn_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E0[2] = {
		/*0F_E0*/{ &pavgb_context_Pq1_Qq0, NULL, NULL },
		/*0F_E0*/{ &pavgb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E1[2] = {
		/*0F_E1*/{ &psraw_context_Pq1_Qq0, NULL, NULL },
		/*0F_E1*/{ &psraw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E2[2] = {
		/*0F_E2*/{ &psrad_context_Pq1_Qq0, NULL, NULL },
		/*0F_E2*/{ &psrad_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E3[2] = {
		/*0F_E3*/{ &pavgw_context_Pq1_Qq0, NULL, NULL },
		/*0F_E3*/{ &pavgw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E4[2] = {
		/*0F_E4*/{ &pmulhuw_context_Pq1_Qq0, NULL, NULL },
		/*0F_E4*/{ &pmulhuw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E5[2] = {
		/*0F_E5*/{ &pmulhw_context_Pq1_Qq0, NULL, NULL },
		/*0F_E5*/{ &pmulhw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E6[4] = {
		/*0F_E6*/{ NULL, NULL, NULL },
		/*0F_E6*/{ &cvttpd2dq_context_Vdq1_Wpd0, NULL, NULL },
		/*0F_E6*/{ &cvtpd2dq_context_Vdq1_Wpd0, NULL, NULL },
		/*0F_E6*/{ &cvtdq2pd_context_Vpd1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_E7_mod[1] = {
		/*0F_E7*/{ &movntq_context_Mq1_Pq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_E7_mod_perfix_66[1] = {
		/*0F_E7*/{ &movntdq_context_Mdq1_Vdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E7[2] = {
		{ NULL, &table_0F_E7_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_E7_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E8[2] = {
		/*0F_E8*/{ &psubsb_context_Pq1_Qq0, NULL, NULL },
		/*0F_E8*/{ &psubsb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_E9[2] = {
		/*0F_E9*/{ &psubsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_E9*/{ &psubsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_EA[2] = {
		/*0F_EA*/{ &pminsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_EA*/{ &pminsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_EB[2] = {
		/*0F_EB*/{ &por_context_Pq1_Qq0, NULL, NULL },
		/*0F_EB*/{ &por_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_EC[2] = {
		/*0F_EC*/{ &paddsb_context_Pq1_Qq0, NULL, NULL },
		/*0F_EC*/{ &paddsb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_ED[2] = {
		/*0F_ED*/{ &paddsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_ED*/{ &paddsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_EE[2] = {
		/*0F_EE*/{ &pmaxsw_context_Pq1_Qq0, NULL, NULL },
		/*0F_EE*/{ &pmaxsw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_EF[2] = {
		/*0F_EF*/{ &pxor_context_Pq1_Qq0, NULL, NULL },
		/*0F_EF*/{ &pxor_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_F0_mod_perfix_F2[1] = {
		/*0F_F0*/{ &lddqu_context_Vdq1_Mdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F0[3] = {
		/*0F_F0*/{ NULL, NULL, NULL },
		/*0F_F0*/{ NULL, NULL, NULL },
		{ NULL, &table_0F_F0_mod_perfix_F2, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F1[2] = {
		/*0F_F1*/{ &psllw_context_Pq1_Qq0, NULL, NULL },
		/*0F_F1*/{ &psllw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F2[2] = {
		/*0F_F2*/{ &pslld_context_Pq1_Qq0, NULL, NULL },
		/*0F_F2*/{ &pslld_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F3[2] = {
		/*0F_F3*/{ &psllq_context_Pq1_Qq0, NULL, NULL },
		/*0F_F3*/{ &psllq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F4[2] = {
		/*0F_F4*/{ &pmuludq_context_Pq1_Qq0, NULL, NULL },
		/*0F_F4*/{ &pmuludq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F5[2] = {
		/*0F_F5*/{ &pmaddwd_context_Pq1_Qd0, NULL, NULL },
		/*0F_F5*/{ &pmaddwd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F6[2] = {
		/*0F_F6*/{ &psadbw_context_Pq1_Qq0, NULL, NULL },
		/*0F_F6*/{ &psadbw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_F7_mod[2] = {
		/*0F_F7*/{ NULL, NULL, NULL },
		/*0F_F7*/{ &maskmovq_context_BDq3_Pq1_Nq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_0F_F7_mod_perfix_66[2] = {
		/*0F_F7*/{ NULL, NULL, NULL },
		/*0F_F7*/{ &maskmopaqu_context_BDdq3_Vdq0_Udq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F7[2] = {
		{ NULL, &table_0F_F7_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_F7_mod_perfix_66, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F8[2] = {
		/*0F_F8*/{ &psubb_context_Pq1_Qq0, NULL, NULL },
		/*0F_F8*/{ &psubb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_F9[2] = {
		/*0F_F9*/{ &psubw_context_Pq1_Qq0, NULL, NULL },
		/*0F_F9*/{ &psubw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_FA[2] = {
		/*0F_FA*/{ &psubd_context_Pq1_Qq0, NULL, NULL },
		/*0F_FA*/{ &psubd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_FB[2] = {
		/*0F_FB*/{ &psubq_context_Pq1_Qq0, NULL, NULL },
		/*0F_FB*/{ &psubq_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_FC[2] = {
		/*0F_FC*/{ &paddb_context_Pq1_Qq0, NULL, NULL },
		/*0F_FC*/{ &paddb_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_FD[2] = {
		/*0F_FD*/{ &paddw_context_Pq1_Qq0, NULL, NULL },
		/*0F_FD*/{ &paddw_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_0F_FE[2] = {
		/*0F_FE*/{ &paddd_context_Pq1_Qq0, NULL, NULL },
		/*0F_FE*/{ &paddd_context_Vdq1_Wdq0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_extended_0F[255] = {
		{ NULL, &opcode_extension_0F_00, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_0F_01, read_table_offset_by_opcode_extension },
		{ NULL, &table_0F_02_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_03_mod, read_table_offset_by_mod },
		/*0F_04*/{ NULL, NULL, NULL },
		/*0F_05*/{ NULL, NULL, NULL },
		/*0F_06*/{ &clts_context_cr03, NULL, NULL },
		/*0F_07*/{ NULL, NULL, NULL },
		/*0F_08*/{ &inpa_context, NULL, NULL },
		/*0F_09*/{ &wbinpa_context, NULL, NULL },
		/*0F_0A*/{ NULL, NULL, NULL },
		/*0F_0B*/{ NULL, NULL, NULL },
		/*0F_0C*/{ NULL, NULL, NULL },
		/*0F_0D*/{ &nop_context_Ev0, NULL, NULL },
		/*0F_0E*/{ NULL, NULL, NULL },
		/*0F_0F*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_10, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_11, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_12, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_13, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_14, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_15, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_16, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_17, read_table_offset_by_prefix },
		{ NULL, &opcode_extension_0F_18, read_table_offset_by_opcode_extension },
		/*0F_19*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1A*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1B*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1C*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1D*/{ &hint_nop_context_Ev0, NULL, NULL },
		/*0F_1E*/{ &hint_nop_context_Ev0, NULL, NULL },
		{ NULL, &opcode_extension_0F_1F, read_table_offset_by_opcode_extension },
		/*0F_20*/{ &mov_context_Hd1_Cd0, NULL, NULL },
		/*0F_21*/{ &mov_context_Hd1_Dd0, NULL, NULL },
		/*0F_22*/{ &mov_context_Cd1_Hd0, NULL, NULL },
		/*0F_23*/{ &mov_context_Dq1_Hq0, NULL, NULL },
		/*0F_24*/{ &mov_context_Hd1_Td0, NULL, NULL },
		/*0F_25*/{ NULL, NULL, NULL },
		/*0F_26*/{ &mov_context_Td1_Hd0, NULL, NULL },
		/*0F_27*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_28, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_29, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_2A, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_2B, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_2C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_2D, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_2E, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_2F, read_table_offset_by_prefix },
		/*0F_30*/{ &wrmsr_context_msr3_Gendqp34_Gendqp2_Gendqp66, NULL, NULL },
		/*0F_31*/{ &rdtsc_context_Gend3_Gend67_ia32_time_stamp_counter2, NULL, NULL },
		/*0F_32*/{ &rdmsr_context_Gendqp3_Gendqp67_Gendqp34_msr2, NULL, NULL },
		/*0F_33*/{ &rdpmc_context_Gend3_Gend67_pmc2, NULL, NULL },
		/*0F_34*/{ &sysenter_context_S2w3_Gend131_ia32_sysenter_cs2_ia32_sysenter_esp2_ia32_sysenter_eip2, NULL, NULL },
		/*0F_35*/{ &sysexit_context_S2w3_Gendqp131_ia32_sysenter_cs2_Gendqp34_Gendqp66, NULL, NULL },
		/*0F_36*/{ NULL, NULL, NULL },
		/*0F_37*/{ &getsec_context_Gend2, NULL, NULL },
		{ NULL, &table_extended_0F_38, read_table_offset_by_opcode },
		/*0F_39*/{ NULL, NULL, NULL },
		{ NULL, &table_extended_0F_3A, read_table_offset_by_opcode },
		/*0F_3B*/{ NULL, NULL, NULL },
		/*0F_3C*/{ NULL, NULL, NULL },
		/*0F_3D*/{ NULL, NULL, NULL },
		/*0F_3E*/{ NULL, NULL, NULL },
		/*0F_3F*/{ NULL, NULL, NULL },
		/*0F_40*/{ &cmovo_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_41*/{ &cmovno_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_42*/{ &cmovc_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_43*/{ &cmovnc_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_44*/{ &cmove_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_45*/{ &cmovne_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_46*/{ &cmovna_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_47*/{ &cmova_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_48*/{ &cmovs_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_49*/{ &cmovns_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_4A*/{ &cmovpe_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_4B*/{ &cmovpo_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_4C*/{ &cmovnge_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_4D*/{ &cmovge_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_4E*/{ &cmovng_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_4F*/{ &cmovg_context_Gvqp1_Evqp0, NULL, NULL },
		{ NULL, &table_prefix_0F_50, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_51, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_52, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_53, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_54, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_55, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_56, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_57, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_58, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_59, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_5A, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_5B, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_5C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_5D, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_5E, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_5F, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_60, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_61, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_62, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_63, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_64, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_65, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_66, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_67, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_68, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_69, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_6A, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_6B, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_6C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_6D, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_6E, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_6F, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_70, read_table_offset_by_prefix },
		{ NULL, &opcode_extension_0F_71, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_0F_72, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_0F_73, read_table_offset_by_opcode_extension },
		{ NULL, &table_prefix_0F_74, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_75, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_76, read_table_offset_by_prefix },
		/*0F_77*/{ &emms_context, NULL, NULL },
		/*0F_78*/{ &vmread_context_Ed1_Gd0, NULL, NULL },
		/*0F_79*/{ &vmwrite_context_Gd0_Ed0, NULL, NULL },
		/*0F_7A*/{ NULL, NULL, NULL },
		/*0F_7B*/{ NULL, NULL, NULL },
		{ NULL, &table_prefix_0F_7C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_7D, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_7E, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_7F, read_table_offset_by_prefix },
		/*0F_80*/{ &jo_context_Jpas4, NULL, NULL },
		/*0F_81*/{ &jno_context_Jpas4, NULL, NULL },
		/*0F_82*/{ &jc_context_Jpas4, NULL, NULL },
		/*0F_83*/{ &jnc_context_Jpas4, NULL, NULL },
		/*0F_84*/{ &je_context_Jpas4, NULL, NULL },
		/*0F_85*/{ &jne_context_Jpas4, NULL, NULL },
		/*0F_86*/{ &jna_context_Jpas4, NULL, NULL },
		/*0F_87*/{ &ja_context_Jpas4, NULL, NULL },
		/*0F_88*/{ &js_context_Jpas4, NULL, NULL },
		/*0F_89*/{ &jns_context_Jpas4, NULL, NULL },
		/*0F_8A*/{ &jpe_context_Jpas4, NULL, NULL },
		/*0F_8B*/{ &jpo_context_Jpas4, NULL, NULL },
		/*0F_8C*/{ &jnge_context_Jpas4, NULL, NULL },
		/*0F_8D*/{ &jge_context_Jpas4, NULL, NULL },
		/*0F_8E*/{ &jng_context_Jpas4, NULL, NULL },
		/*0F_8F*/{ &jg_context_Jpas4, NULL, NULL },
		/*0F_90*/{ &seto_context_Eb1, NULL, NULL },
		/*0F_91*/{ &setno_context_Eb1, NULL, NULL },
		/*0F_92*/{ &setc_context_Eb1, NULL, NULL },
		/*0F_93*/{ &setnc_context_Eb1, NULL, NULL },
		/*0F_94*/{ &sete_context_Eb1, NULL, NULL },
		/*0F_95*/{ &setne_context_Eb1, NULL, NULL },
		/*0F_96*/{ &setna_context_Eb1, NULL, NULL },
		/*0F_97*/{ &seta_context_Eb1, NULL, NULL },
		/*0F_98*/{ &sets_context_Eb1, NULL, NULL },
		/*0F_99*/{ &setns_context_Eb1, NULL, NULL },
		/*0F_9A*/{ &setpe_context_Eb1, NULL, NULL },
		/*0F_9B*/{ &setpo_context_Eb1, NULL, NULL },
		/*0F_9C*/{ &setnge_context_Eb1, NULL, NULL },
		/*0F_9D*/{ &setge_context_Eb1, NULL, NULL },
		/*0F_9E*/{ &setng_context_Eb1, NULL, NULL },
		/*0F_9F*/{ &setg_context_Eb1, NULL, NULL },
		/*0F_A0*/{ &push_context_SCw3_S33w0, NULL, NULL },
		/*0F_A1*/{ &pop_context_S33w1_SCw2, NULL, NULL },
		/*0F_A2*/{ &cpuid_context_ia32_bios_sign_id3_Gend3_Gend35_Gend67_Gend99, NULL, NULL },
		/*0F_A3*/{ &bt_context_Evqp0_Gvqp0, NULL, NULL },
		/*0F_A4*/{ &shld_context_Evqp1_Gvqp0_Ib0, NULL, NULL },
		/*0F_A5*/{ &shld_context_Evqp1_Gvqp0_Genb32, NULL, NULL },
		/*0F_A6*/{ NULL, NULL, NULL },
		/*0F_A7*/{ NULL, NULL, NULL },
		/*0F_A8*/{ &push_context_SCw3_S33w0, NULL, NULL },
		/*0F_A9*/{ &pop_context_S33w1_SCw2, NULL, NULL },
		/*0F_AA*/{ &rsm_context_Fw3, NULL, NULL },
		/*0F_AB*/{ &bts_context_Evqp1_Gvqp0, NULL, NULL },
		/*0F_AC*/{ &shrd_context_Evqp1_Gvqp0_Ib0, NULL, NULL },
		/*0F_AD*/{ &shrd_context_Evqp1_Gvqp0_Genb32, NULL, NULL },
		{ NULL, &opcode_extension_0F_AE, read_table_offset_by_opcode_extension },
		/*0F_AF*/{ &imul_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_B0*/{ &cmpxchg_context_Eb1_Genb3_Gb0, NULL, NULL },
		/*0F_B1*/{ &cmpxchg_context_Evqp1_Genvqp3_Gvqp0, NULL, NULL },
		{ NULL, &table_0F_B2_mod, read_table_offset_by_mod },
		/*0F_B3*/{ &btr_context_Evqp1_Gvqp0, NULL, NULL },
		{ NULL, &table_0F_B4_mod, read_table_offset_by_mod },
		{ NULL, &table_0F_B5_mod, read_table_offset_by_mod },
		/*0F_B6*/{ &movzx_context_Gvqp1_Eb0, NULL, NULL },
		/*0F_B7*/{ &movzx_context_Gvqp1_Ew0, NULL, NULL },
		{ NULL, &table_prefix_0F_B8, read_table_offset_by_prefix },
		/*0F_B9*/{ NULL, NULL, NULL },
		{ NULL, &opcode_extension_0F_BA, read_table_offset_by_opcode_extension },
		/*0F_BB*/{ &btc_context_Evqp1_Gvqp0, NULL, NULL },
		/*0F_BC*/{ &bsf_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_BD*/{ &bsr_context_Gvqp1_Evqp0, NULL, NULL },
		/*0F_BE*/{ &movsx_context_Gvqp1_Eb0, NULL, NULL },
		/*0F_BF*/{ &movsx_context_Gvqp1_Ew0, NULL, NULL },
		/*0F_C0*/{ &xadd_context_Eb1_Gb1, NULL, NULL },
		/*0F_C1*/{ &xadd_context_Evqp1_Gvqp1, NULL, NULL },
		{ NULL, &table_prefix_0F_C2, read_table_offset_by_prefix },
		{ NULL, &table_0F_C3_mod, read_table_offset_by_mod },
		{ NULL, &table_prefix_0F_C4, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_C5, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_C6, read_table_offset_by_prefix },
		{ NULL, &opcode_extension_0F_C7, read_table_offset_by_opcode_extension },
		/*0F_C8*/{ &bswap_context_Zvqp1, NULL, NULL },
		/*0F_C9*/{ &bswap_context_Zvqp1, NULL, NULL },
		/*0F_CA*/{ &bswap_context_Zvqp1, NULL, NULL },
		/*0F_CB*/{ &bswap_context_Zvqp1, NULL, NULL },
		/*0F_CC*/{ &bswap_context_Zvqp1, NULL, NULL },
		/*0F_CD*/{ &bswap_context_Zvqp1, NULL, NULL },
		/*0F_CE*/{ &bswap_context_Zvqp1, NULL, NULL },
		/*0F_CF*/{ &bswap_context_Zvqp1, NULL, NULL },
		{ NULL, &table_prefix_0F_D0, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D1, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D2, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D3, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D4, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D5, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D6, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D7, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D8, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_D9, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_DA, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_DB, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_DC, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_DD, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_DE, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_DF, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E0, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E1, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E2, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E3, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E4, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E5, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E6, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E7, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E8, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_E9, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_EA, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_EB, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_EC, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_ED, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_EE, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_EF, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F0, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F1, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F2, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F3, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F4, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F5, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F6, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F7, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F8, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_F9, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_FA, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_FB, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_FC, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_FD, read_table_offset_by_prefix },
		{ NULL, &table_prefix_0F_FE, read_table_offset_by_prefix }
	};

	static const pa_x86_instruction_context_table table_prefix_60[2] = {
		/*60*/{ &pushad_context_SCdoo3_Gendoo2_Gendoo34_Gendoo66_Gendoo98_Gendoo130_Gendoo162_Gendoo194_Gendoo226, NULL, NULL },
		/*60*/{ &pusha_context_SCwo3_Genwo2_Genwo34_Genwo66_Genwo98_Genwo130_Genwo162_Genwo194_Genwo226, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_61[2] = {
		/*61*/{ &popad_context_Gendoo227_Gendoo195_Gendoo163_Gendoo99_Gendoo67_Gendoo35_Gendoo3_SCdoo2, NULL, NULL },
		/*61*/{ &popa_context_Genwo227_Genwo195_Genwo163_Genwo99_Genwo67_Genwo35_Genwo3_SCwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_62_mod[1] = {
		/*62*/{ &bound_context_SCv3_Gv0_Ma0_Fv2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_6D[2] = {
		/*6D*/{ &insd_context_Ydoo3_Genw66, NULL, NULL },
		/*6D*/{ &insw_context_Ywo3_Genw66, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_6F[2] = {
		/*6F*/{ &outsd_context_Genw67_Xdoo2, NULL, NULL },
		/*6F*/{ &outsw_context_Genw67_Xwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_80[8] = {
		/*80*/{ &add_context_Eb1_Ib0, NULL, NULL },
		/*80*/{ &or_context_Eb1_Ib0, NULL, NULL },
		/*80*/{ &adc_context_Eb1_Ib0, NULL, NULL },
		/*80*/{ &sbb_context_Eb1_Ib0, NULL, NULL },
		/*80*/{ &and_context_Eb1_Ib0, NULL, NULL },
		/*80*/{ &sub_context_Eb1_Ib0, NULL, NULL },
		/*80*/{ &xor_context_Eb1_Ib0, NULL, NULL },
		/*80*/{ &cmp_context_Eb0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_81[8] = {
		/*81*/{ &add_context_Evqp1_Ipas4, NULL, NULL },
		/*81*/{ &or_context_Evqp1_Ipas4, NULL, NULL },
		/*81*/{ &adc_context_Evqp1_Ipas4, NULL, NULL },
		/*81*/{ &sbb_context_Evqp1_Ipas4, NULL, NULL },
		/*81*/{ &and_context_Evqp1_Ipas4, NULL, NULL },
		/*81*/{ &sub_context_Evqp1_Ipas4, NULL, NULL },
		/*81*/{ &xor_context_Evqp1_Ipas4, NULL, NULL },
		/*81*/{ &cmp_context_Evqp0_Ipas4, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_82[8] = {
		/*82*/{ &add_context_Eb1_Ib0, NULL, NULL },
		/*82*/{ &or_context_Eb1_Ib0, NULL, NULL },
		/*82*/{ &adc_context_Eb1_Ib0, NULL, NULL },
		/*82*/{ &sbb_context_Eb1_Ib0, NULL, NULL },
		/*82*/{ &and_context_Eb1_Ib0, NULL, NULL },
		/*82*/{ &sub_context_Eb1_Ib0, NULL, NULL },
		/*82*/{ &xor_context_Eb1_Ib0, NULL, NULL },
		/*82*/{ &cmp_context_Eb0_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_83[8] = {
		/*83*/{ &add_context_Evqp1_Ibs4, NULL, NULL },
		/*83*/{ &or_context_Evqp1_Ibs4, NULL, NULL },
		/*83*/{ &adc_context_Evqp1_Ibs4, NULL, NULL },
		/*83*/{ &sbb_context_Evqp1_Ibs4, NULL, NULL },
		/*83*/{ &and_context_Evqp1_Ibs4, NULL, NULL },
		/*83*/{ &sub_context_Evqp1_Ibs4, NULL, NULL },
		/*83*/{ &xor_context_Evqp1_Ibs4, NULL, NULL },
		/*83*/{ &cmp_context_Evqp0_Ibs4, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_8C_mod[2] = {
		/*8C*/{ &mov_context_Mw1_Sw0, NULL, NULL },
		/*8C*/{ &mov_context_Rvqp1_Sw0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_8D_mod[1] = {
		/*8D*/{ &lea_context_Gvqp1_M0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_8F[1] = {
		/*8F*/{ &pop_context_Ev1_SCv2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_90[4] = {
		/*90*/{ &nop_context, NULL, NULL },
		/*90*/{ NULL, NULL, NULL },
		/*90*/{ NULL, NULL, NULL },
		/*90*/{ &pause_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_98[2] = {
		/*98*/{ &cwde_context_Gendoo3_Genw2, NULL, NULL },
		/*98*/{ &cbw_context_Genwo3_Genb2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_99[2] = {
		/*99*/{ &cdq_context_Gendoo67_Gendoo2, NULL, NULL },
		/*99*/{ &cwd_context_Genwo67_Genwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_9C[2] = {
		/*9C*/{ &pushfd_context_SCdoo3_Fdoo2, NULL, NULL },
		/*9C*/{ &pushf_context_SCwo3_Fwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_9D[2] = {
		/*9D*/{ &popfd_context_Fdoo3_SCdoo2, NULL, NULL },
		/*9D*/{ &popf_context_Fwo3_SCwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_A5[2] = {
		/*A5*/{ &movsd_context_Ydoo3_Xdoo2, NULL, NULL },
		/*A5*/{ &movsw_context_Ywo3_Xwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_A7[2] = {
		/*A7*/{ &cmpsd_context_Ydoo2_Xdoo2, NULL, NULL },
		/*A7*/{ &cmpsw_context_Ywo2_Xwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_AB[2] = {
		/*AB*/{ &stosd_context_Ydoo3_Gendoo2, NULL, NULL },
		/*AB*/{ &stosw_context_Ywo3_Genwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_AD[2] = {
		/*AD*/{ &lodsd_context_Gendoo3_Xdoo2, NULL, NULL },
		/*AD*/{ &lodsw_context_Genwo3_Xwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_AF[2] = {
		/*AF*/{ &scasd_context_Ydoo2_Gendoo2, NULL, NULL },
		/*AF*/{ &scasw_context_Ywo2_Genwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_C0[8] = {
		/*C0*/{ &rol_context_Eb1_Ib0, NULL, NULL },
		/*C0*/{ &ror_context_Eb1_Ib0, NULL, NULL },
		/*C0*/{ &rcl_context_Eb1_Ib0, NULL, NULL },
		/*C0*/{ &rcr_context_Eb1_Ib0, NULL, NULL },
		/*C0*/{ &sal_context_Eb1_Ib0, NULL, NULL },
		/*C0*/{ &shr_context_Eb1_Ib0, NULL, NULL },
		/*C0*/{ &shl_context_Eb1_Ib0, NULL, NULL },
		/*C0*/{ &sar_context_Eb1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_C1[8] = {
		/*C1*/{ &rol_context_Evqp1_Ib0, NULL, NULL },
		/*C1*/{ &ror_context_Evqp1_Ib0, NULL, NULL },
		/*C1*/{ &rcl_context_Evqp1_Ib0, NULL, NULL },
		/*C1*/{ &rcr_context_Evqp1_Ib0, NULL, NULL },
		/*C1*/{ &sal_context_Evqp1_Ib0, NULL, NULL },
		/*C1*/{ &shr_context_Evqp1_Ib0, NULL, NULL },
		/*C1*/{ &shl_context_Evqp1_Ib0, NULL, NULL },
		/*C1*/{ &sar_context_Evqp1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_C4_mod[1] = {
		/*C4*/{ &les_context_Segw3_Gv1_Mp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_C5_mod[1] = {
		/*C5*/{ &lds_context_Segw99_Gv1_Mp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_C6[1] = {
		/*C6*/{ &mov_context_Eb1_Ib0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_C7[1] = {
		/*C7*/{ &mov_context_Evqp1_Ipas4, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_prefix_CF[2] = {
		/*CF*/{ &iretd_context_Fdoo3_SCdoo2, NULL, NULL },
		/*CF*/{ &iret_context_Fwo3_SCwo2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_D0[8] = {
		/*D0*/{ &rol_context_Eb1_I1b0, NULL, NULL },
		/*D0*/{ &ror_context_Eb1_I1b0, NULL, NULL },
		/*D0*/{ &rcl_context_Eb1_I1b0, NULL, NULL },
		/*D0*/{ &rcr_context_Eb1_I1b0, NULL, NULL },
		/*D0*/{ &sal_context_Eb1_I1b0, NULL, NULL },
		/*D0*/{ &shr_context_Eb1_I1b0, NULL, NULL },
		/*D0*/{ &shl_context_Eb1_I1b0, NULL, NULL },
		/*D0*/{ &sar_context_Eb1_I1b0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_D1[8] = {
		/*D1*/{ &rol_context_Evqp1_I1b0, NULL, NULL },
		/*D1*/{ &ror_context_Evqp1_I1b0, NULL, NULL },
		/*D1*/{ &rcl_context_Evqp1_I1b0, NULL, NULL },
		/*D1*/{ &rcr_context_Evqp1_I1b0, NULL, NULL },
		/*D1*/{ &sal_context_Evqp1_I1b0, NULL, NULL },
		/*D1*/{ &shr_context_Evqp1_I1b0, NULL, NULL },
		/*D1*/{ &shl_context_Evqp1_I1b0, NULL, NULL },
		/*D1*/{ &sar_context_Evqp1_I1b0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_D2[8] = {
		/*D2*/{ &rol_context_Eb1_Genb32, NULL, NULL },
		/*D2*/{ &ror_context_Eb1_Genb32, NULL, NULL },
		/*D2*/{ &rcl_context_Eb1_Genb32, NULL, NULL },
		/*D2*/{ &rcr_context_Eb1_Genb32, NULL, NULL },
		/*D2*/{ &sal_context_Eb1_Genb32, NULL, NULL },
		/*D2*/{ &shr_context_Eb1_Genb32, NULL, NULL },
		/*D2*/{ &shl_context_Eb1_Genb32, NULL, NULL },
		/*D2*/{ &sar_context_Eb1_Genb32, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_D3[8] = {
		/*D3*/{ &rol_context_Evqp1_Genb32, NULL, NULL },
		/*D3*/{ &ror_context_Evqp1_Genb32, NULL, NULL },
		/*D3*/{ &rcl_context_Evqp1_Genb32, NULL, NULL },
		/*D3*/{ &rcr_context_Evqp1_Genb32, NULL, NULL },
		/*D3*/{ &sal_context_Evqp1_Genb32, NULL, NULL },
		/*D3*/{ &shr_context_Evqp1_Genb32, NULL, NULL },
		/*D3*/{ &shl_context_Evqp1_Genb32, NULL, NULL },
		/*D3*/{ &sar_context_Evqp1_Genb32, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D8_mod_opcode_extension_0[2] = {
		/*D8*/{ &fadd_context_X87fpu3_Msr0, NULL, NULL },
		/*D8*/{ &fadd_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D8_mod_opcode_extension_1[2] = {
		/*D8*/{ &fmul_context_X87fpu3_Msr0, NULL, NULL },
		/*D8*/{ &fmul_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D8_mod_opcode_extension_4[2] = {
		/*D8*/{ &fsub_context_X87fpu3_Msr0, NULL, NULL },
		/*D8*/{ &fsub_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D8_mod_opcode_extension_5[2] = {
		/*D8*/{ &fsubr_context_X87fpu3_Msr0, NULL, NULL },
		/*D8*/{ &fsubr_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D8_mod_opcode_extension_6[2] = {
		/*D8*/{ &fdiv_context_X87fpu3_Msr0, NULL, NULL },
		/*D8*/{ &fdiv_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D8_mod_opcode_extension_7[2] = {
		/*D8*/{ &fdivr_context_X87fpu3_Msr0, NULL, NULL },
		/*D8*/{ &fdivr_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_D8[8] = {
		{ NULL, &table_D8_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_D8_mod_opcode_extension_1, read_table_offset_by_mod },
		/*D8*/{ &fcom_context_X87fpu2_ESsr0, NULL, NULL },
		/*D8*/{ &fcomp_context_X87fpu2_ESsr0, NULL, NULL },
		{ NULL, &table_D8_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_D8_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_D8_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_D8_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_D9_mod_opcode_extension_1[2] = {
		/*D9*/{ NULL, NULL, NULL },
		/*D9*/{ &fxch_context_X87fpu3_EST1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D9_opcode_extension_2_second_opcode[1] = {
		/*D9*/{ &fnop_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D9_mod_opcode_extension_2[2] = {
		/*D9*/{ &fst_context_Msr1_X87fpu2, NULL, NULL },
		{ NULL, &table_D9_opcode_extension_2_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_D9_mod_opcode_extension_3[2] = {
		/*D9*/{ &fstp_context_Msr1_X87fpu2, NULL, NULL },
		/*D9*/{ &fstp1_context_EST1_X87fpu2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D9_opcode_extension_4_second_opcode[6] = {
		/*D9*/{ &fchs_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fabs_context_X87fpu3, NULL, NULL },
		/*D9*/{ NULL, NULL, NULL },
		/*D9*/{ NULL, NULL, NULL },
		/*D9*/{ &ftst_context_X87fpu2, NULL, NULL },
		/*D9*/{ &fxam_context_X87fpu2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D9_mod_opcode_extension_4[2] = {
		/*D9*/{ &fldenv_context_Me0, NULL, NULL },
		{ NULL, &table_D9_opcode_extension_4_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_D9_opcode_extension_5_second_opcode[7] = {
		/*D9*/{ &fld1_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fldl2t_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fldl2e_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fldpi_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fldlg2_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fldln2_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fldz_context_X87fpu3, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D9_mod_opcode_extension_5[2] = {
		/*D9*/{ &fldcw_context_Mw0, NULL, NULL },
		{ NULL, &table_D9_opcode_extension_5_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_D9_opcode_extension_6_second_opcode[8] = {
		/*D9*/{ &f2xm1_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fyl2x_context_X87fpu35_X87fpu2, NULL, NULL },
		/*D9*/{ &fptan_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fpatan_context_X87fpu35_X87fpu2, NULL, NULL },
		/*D9*/{ &fxtract_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fprem1_context_X87fpu3_X87fpu34, NULL, NULL },
		/*D9*/{ &fdecstp_context, NULL, NULL },
		/*D9*/{ &fincstp_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D9_mod_opcode_extension_6[2] = {
		/*D9*/{ &fnstenv_context_Me1, NULL, NULL },
		{ NULL, &table_D9_opcode_extension_6_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_D9_opcode_extension_7_second_opcode[8] = {
		/*D9*/{ &fprem_context_X87fpu3_X87fpu34, NULL, NULL },
		/*D9*/{ &fyl2xp1_context_X87fpu35_X87fpu2, NULL, NULL },
		/*D9*/{ &fsqrt_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fsincos_context_X87fpu3, NULL, NULL },
		/*D9*/{ &frndint_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fscale_context_X87fpu3_X87fpu34, NULL, NULL },
		/*D9*/{ &fsin_context_X87fpu3, NULL, NULL },
		/*D9*/{ &fcos_context_X87fpu3, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_D9_mod_opcode_extension_7[2] = {
		/*D9*/{ &fnstcw_context_Mw1, NULL, NULL },
	{ NULL, &table_D9_opcode_extension_7_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table opcode_extension_D9[8] = {
		/*D9*/{ &fld_context_X87fpu3_ESsr0, NULL, NULL },
		{ NULL, &table_D9_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_D9_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_D9_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_D9_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_D9_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_D9_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_D9_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_0[2] = {
		/*DA*/{ &fiadd_context_X87fpu3_Mdi0, NULL, NULL },
		/*DA*/{ &fcmovb_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_1[2] = {
		/*DA*/{ &fimul_context_X87fpu3_Mdi0, NULL, NULL },
		/*DA*/{ &fcmove_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_2[2] = {
		/*DA*/{ &ficom_context_X87fpu2_Mdi0, NULL, NULL },
		/*DA*/{ &fcmovbe_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_3[2] = {
		/*DA*/{ &ficomp_context_X87fpu2_Mdi0, NULL, NULL },
		/*DA*/{ &fcmovu_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_4[1] = {
		/*DA*/{ &fisub_context_X87fpu3_Mdi0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DA_opcode_extension_5_second_opcode[2] = {
		/*DA*/{ NULL, NULL, NULL },
		/*DA*/{ &fucompp_context_X87fpu2_X87fpu34, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_5[2] = {
		/*DA*/{ &fisubr_context_X87fpu3_Mdi0, NULL, NULL },
		{ NULL, &table_DA_opcode_extension_5_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_6[1] = {
		/*DA*/{ &fidiv_context_X87fpu3_Mdi0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DA_mod_opcode_extension_7[1] = {
		/*DA*/{ &fidivr_context_X87fpu3_Mdi0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_DA[8] = {
		{ NULL, &table_DA_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_DA_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_DA_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_DA_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_DA_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_DA_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_DA_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_DA_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_DB_mod_opcode_extension_0[2] = {
		/*DB*/{ &fild_context_X87fpu3_Mdi0, NULL, NULL },
		/*DB*/{ &fcmovnb_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DB_mod_opcode_extension_1[2] = {
		/*DB*/{ &fisttp_context_Mdi1_X87fpu2, NULL, NULL },
		/*DB*/{ &fcmovne_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DB_mod_opcode_extension_2[2] = {
		/*DB*/{ &fist_context_Mdi1_X87fpu2, NULL, NULL },
		/*DB*/{ &fcmovnbe_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DB_mod_opcode_extension_3[2] = {
		/*DB*/{ &fistp_context_Mdi1_X87fpu2, NULL, NULL },
		/*DB*/{ &fcmovnu_context_X87fpu1_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DB_opcode_extension_4_second_opcode[5] = {
		/*DB*/{ &fneni_context, NULL, NULL },
		/*DB*/{ &fndisi_context, NULL, NULL },
		/*DB*/{ &fnclex_context, NULL, NULL },
		/*DB*/{ &fninit_context, NULL, NULL },
		/*DB*/{ &fnsetpm_context, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DB_mod_opcode_extension_5[2] = {
		/*DB*/{ &fld_context_X87fpu3_Mer0, NULL, NULL },
		/*DB*/{ &fucomi_context_X87fpu0_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DB_mod_opcode_extension_6[2] = {
		/*DB*/{ NULL, NULL, NULL },
		/*DB*/{ &fcomi_context_X87fpu0_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DB_mod_opcode_extension_7[1] = {
		/*DB*/{ &fstp_context_Mer1_X87fpu2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_DB[8] = {
		{ NULL, &table_DB_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_DB_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_DB_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_DB_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_DB_opcode_extension_4_second_opcode, read_table_offset_by_second_opcode },
		{ NULL, &table_DB_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_DB_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_DB_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_0[2] = {
		/*DC*/{ &fadd_context_X87fpu3_Mdr0, NULL, NULL },
		/*DC*/{ &fadd_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_1[2] = {
		/*DC*/{ &fmul_context_X87fpu3_Mdr0, NULL, NULL },
		/*DC*/{ &fmul_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_2[2] = {
		/*DC*/{ &fcom_context_X87fpu2_Mdr0, NULL, NULL },
		/*DC*/{ &fcom2_context_X87fpu2_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_3[2] = {
		/*DC*/{ &fcomp_context_X87fpu2_Mdr0, NULL, NULL },
		/*DC*/{ &fcomp3_context_X87fpu2_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_4[2] = {
		/*DC*/{ &fsub_context_X87fpu3_Mdr0, NULL, NULL },
		/*DC*/{ &fsubr_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_5[2] = {
		/*DC*/{ &fsubr_context_X87fpu3_Mdr0, NULL, NULL },
		/*DC*/{ &fsub_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_6[2] = {
		/*DC*/{ &fdiv_context_X87fpu3_Mdr0, NULL, NULL },
		/*DC*/{ &fdivr_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DC_mod_opcode_extension_7[2] = {
		/*DC*/{ &fdivr_context_X87fpu3_Mdr0, NULL, NULL },
		/*DC*/{ &fdiv_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_DC[8] = {
		{ NULL, &table_DC_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_DC_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_DC_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_DC_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_DC_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_DC_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_DC_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_DC_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_0[2] = {
		/*DD*/{ &fld_context_X87fpu3_Mdr0, NULL, NULL },
		/*DD*/{ &ffree_context_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_1[2] = {
		/*DD*/{ &fisttp_context_Mqi1_X87fpu2, NULL, NULL },
		/*DD*/{ &fxch4_context_X87fpu3_EST1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_2[2] = {
		/*DD*/{ &fst_context_Mdr1_X87fpu2, NULL, NULL },
		/*DD*/{ &fst_context_X87fpu3_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_3[2] = {
		/*DD*/{ &fstp_context_Mdr1_X87fpu2, NULL, NULL },
		/*DD*/{ &fstp_context_X87fpu3_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_4[2] = {
		/*DD*/{ &frstor_context_X87fpu3_X87fpu35_X87fpu67_X87fpu99_X87fpu131_X87fpu163_X87fpu195_X87fpu227_Mst0, NULL, NULL },
		/*DD*/{ &fucom_context_X87fpu2_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_5[2] = {
		/*DD*/{ NULL, NULL, NULL },
		/*DD*/{ &fucomp_context_X87fpu2_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_6[1] = {
		/*DD*/{ &fnsave_context_Mst1_X87fpu2_X87fpu34_X87fpu66_X87fpu98_X87fpu130_X87fpu162_X87fpu194_X87fpu226, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DD_mod_opcode_extension_7[1] = {
		/*DD*/{ &fnstsw_context_Mw1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_DD[8] = {
		{ NULL, &table_DD_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_DD_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_DD_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_DD_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_DD_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_DD_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_DD_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_DD_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_0[2] = {
		/*DE*/{ &fiadd_context_X87fpu3_Mwi0, NULL, NULL },
		/*DE*/{ &faddp_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_1[2] = {
		/*DE*/{ &fimul_context_X87fpu3_Mwi0, NULL, NULL },
		/*DE*/{ &fmulp_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_2[2] = {
		/*DE*/{ &ficom_context_X87fpu2_Mwi0, NULL, NULL },
		/*DE*/{ &fcomp5_context_X87fpu2_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DE_opcode_extension_3_second_opcode[2] = {
		/*DE*/{ NULL, NULL, NULL },
		/*DE*/{ &fcompp_context_X87fpu2_X87fpu34, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_3[2] = {
		/*DE*/{ &ficomp_context_X87fpu2_Mwi0, NULL, NULL },
		{ NULL, &table_DE_opcode_extension_3_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_4[2] = {
		/*DE*/{ &fisub_context_X87fpu3_Mwi0, NULL, NULL },
		/*DE*/{ &fsubrp_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_5[2] = {
		/*DE*/{ &fisubr_context_X87fpu3_Mwi0, NULL, NULL },
		/*DE*/{ &fsubp_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_6[2] = {
		/*DE*/{ &fidiv_context_X87fpu3_Mwi0, NULL, NULL },
		/*DE*/{ &fdivrp_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DE_mod_opcode_extension_7[2] = {
		/*DE*/{ &fidivr_context_X87fpu3_Mwi0, NULL, NULL },
		/*DE*/{ &fdivp_context_EST1_X87fpu0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_DE[8] = {
		{ NULL, &table_DE_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_DE_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_DE_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_DE_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_DE_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_DE_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_DE_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_DE_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_0[2] = {
		/*DF*/{ &fild_context_X87fpu3_Mwi0, NULL, NULL },
		/*DF*/{ &ffreep_context_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_1[2] = {
		/*DF*/{ &fisttp_context_Mwi1_X87fpu2, NULL, NULL },
		/*DF*/{ &fxch7_context_X87fpu3_EST1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_2[2] = {
		/*DF*/{ &fist_context_Mwi1_X87fpu2, NULL, NULL },
		/*DF*/{ &fstp8_context_EST1_X87fpu2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_3[2] = {
		/*DF*/{ &fistp_context_Mwi1_X87fpu2, NULL, NULL },
		/*DF*/{ &fstp9_context_EST1_X87fpu2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DF_opcode_extension_4_second_opcode[1] = {
		/*DF*/{ &fnstsw_context_Genw1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_4[2] = {
		/*DF*/{ &fbld_context_X87fpu3_Mbcd0, NULL, NULL },
		{ NULL, &table_DF_opcode_extension_4_second_opcode, read_table_offset_by_second_opcode }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_5[2] = {
		/*DF*/{ &fild_context_X87fpu3_Mqi0, NULL, NULL },
		/*DF*/{ &fucomip_context_X87fpu0_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_6[2] = {
		/*DF*/{ &fbstp_context_Mbcd1_X87fpu2, NULL, NULL },
		/*DF*/{ &fcomip_context_X87fpu0_EST0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_DF_mod_opcode_extension_7[1] = {
		/*DF*/{ &fistp_context_Mqi1_X87fpu2, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_DF[8] = {
		{ NULL, &table_DF_mod_opcode_extension_0, read_table_offset_by_mod },
		{ NULL, &table_DF_mod_opcode_extension_1, read_table_offset_by_mod },
		{ NULL, &table_DF_mod_opcode_extension_2, read_table_offset_by_mod },
		{ NULL, &table_DF_mod_opcode_extension_3, read_table_offset_by_mod },
		{ NULL, &table_DF_mod_opcode_extension_4, read_table_offset_by_mod },
		{ NULL, &table_DF_mod_opcode_extension_5, read_table_offset_by_mod },
		{ NULL, &table_DF_mod_opcode_extension_6, read_table_offset_by_mod },
		{ NULL, &table_DF_mod_opcode_extension_7, read_table_offset_by_mod }
	};

	static const pa_x86_instruction_context_table opcode_extension_F6[8] = {
		/*F6*/{ &test_context_Eb0_Ib0, NULL, NULL },
		/*F6*/{ &test_context_Eb0_Ib0, NULL, NULL },
		/*F6*/{ &not_context_Eb1, NULL, NULL },
		/*F6*/{ &neg_context_Eb1, NULL, NULL },
		/*F6*/{ &mul_context_Genw3_Genb2_Eb0, NULL, NULL },
		/*F6*/{ &imul_context_Genw3_Genb2_Eb0, NULL, NULL },
		/*F6*/{ &div_context_Genb3_Genb131_Genw2_Eb0, NULL, NULL },
		/*F6*/{ &idiv_context_Genb3_Genb131_Genw2_Eb0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_F7[8] = {
		/*F7*/{ &test_context_Evqp0_Ivqp0, NULL, NULL },
		/*F7*/{ &test_context_Evqp0_Ivqp0, NULL, NULL },
		/*F7*/{ &not_context_Evqp1, NULL, NULL },
		/*F7*/{ &neg_context_Evqp1, NULL, NULL },
		/*F7*/{ &mul_context_Genvqp67_Genvqp3_Evqp0, NULL, NULL },
		/*F7*/{ &imul_context_Genvqp67_Genvqp3_Evqp0, NULL, NULL },
		/*F7*/{ &div_context_Genvqp67_Genvqp3_Evqp0, NULL, NULL },
		/*F7*/{ &idiv_context_Genvqp67_Genvqp3_Evqp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_FE[2] = {
		/*FE*/{ &inc_context_Eb1, NULL, NULL },
		/*FE*/{ &dec_context_Eb1, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_FF_mod_opcode_extension_3[1] = {
		/*FF*/{ &callf_context_SCptp3_Mptp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table table_FF_mod_opcode_extension_5[1] = {
		/*FF*/{ &jmpf_context_Mptp0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table opcode_extension_FF[7] = {
		/*FF*/{ &inc_context_Evqp1, NULL, NULL },
		/*FF*/{ &dec_context_Evqp1, NULL, NULL },
		/*FF*/{ &call_context_SCv3_Ev0, NULL, NULL },
		{ NULL, &table_FF_mod_opcode_extension_3, read_table_offset_by_mod },
		/*FF*/{ &jmp_context_Ev0, NULL, NULL },
		{ NULL, &table_FF_mod_opcode_extension_5, read_table_offset_by_mod },
		/*FF*/{ &push_context_SCv3_Ev0, NULL, NULL }
	};

	static const pa_x86_instruction_context_table primary[256] = {
		/*00*/{ &add_context_Eb1_Gb0, NULL, NULL },
		/*01*/{ &add_context_Evqp1_Gvqp0, NULL, NULL },
		/*02*/{ &add_context_Gb1_Eb0, NULL, NULL },
		/*03*/{ &add_context_Gvqp1_Evqp0, NULL, NULL },
		/*04*/{ &add_context_Genb1_Ib0, NULL, NULL },
		/*05*/{ &add_context_Genvqp1_Ipas4, NULL, NULL },
		/*06*/{ &push_context_SCw3_S2w0, NULL, NULL },
		/*07*/{ &pop_context_S2w1_SCw2, NULL, NULL },
		/*08*/{ &or_context_Eb1_Gb0, NULL, NULL },
		/*09*/{ &or_context_Evqp1_Gvqp0, NULL, NULL },
		/*0A*/{ &or_context_Gb1_Eb0, NULL, NULL },
		/*0B*/{ &or_context_Gvqp1_Evqp0, NULL, NULL },
		/*0C*/{ &or_context_Genb1_Ib0, NULL, NULL },
		/*0D*/{ &or_context_Genvqp1_Ipas4, NULL, NULL },
		/*0E*/{ &push_context_SCw3_S2w0, NULL, NULL },
		{ NULL, &table_extended_0F, read_table_offset_by_opcode },
		/*10*/{ &adc_context_Eb1_Gb0, NULL, NULL },
		/*11*/{ &adc_context_Evqp1_Gvqp0, NULL, NULL },
		/*12*/{ &adc_context_Gb1_Eb0, NULL, NULL },
		/*13*/{ &adc_context_Gvqp1_Evqp0, NULL, NULL },
		/*14*/{ &adc_context_Genb1_Ib0, NULL, NULL },
		/*15*/{ &adc_context_Genvqp1_Ipas4, NULL, NULL },
		/*16*/{ &push_context_SCw3_S2w0, NULL, NULL },
		/*17*/{ &pop_context_S2w1_SCw2, NULL, NULL },
		/*18*/{ &sbb_context_Eb1_Gb0, NULL, NULL },
		/*19*/{ &sbb_context_Evqp1_Gvqp0, NULL, NULL },
		/*1A*/{ &sbb_context_Gb1_Eb0, NULL, NULL },
		/*1B*/{ &sbb_context_Gvqp1_Evqp0, NULL, NULL },
		/*1C*/{ &sbb_context_Genb1_Ib0, NULL, NULL },
		/*1D*/{ &sbb_context_Genvqp1_Ipas4, NULL, NULL },
		/*1E*/{ &push_context_SCw3_S2w0, NULL, NULL },
		/*1F*/{ &pop_context_S2w1_SCw2, NULL, NULL },
		/*20*/{ &and_context_Eb1_Gb0, NULL, NULL },
		/*21*/{ &and_context_Evqp1_Gvqp0, NULL, NULL },
		/*22*/{ &and_context_Gb1_Eb0, NULL, NULL },
		/*23*/{ &and_context_Gvqp1_Evqp0, NULL, NULL },
		/*24*/{ &and_context_Genb1_Ib0, NULL, NULL },
		/*25*/{ &and_context_Genvqp1_Ipas4, NULL, NULL },
		/*26*/{ NULL, NULL, NULL },
		/*27*/{ &daa_context_Genb3, NULL, NULL },
		/*28*/{ &sub_context_Eb1_Gb0, NULL, NULL },
		/*29*/{ &sub_context_Evqp1_Gvqp0, NULL, NULL },
		/*2A*/{ &sub_context_Gb1_Eb0, NULL, NULL },
		/*2B*/{ &sub_context_Gvqp1_Evqp0, NULL, NULL },
		/*2C*/{ &sub_context_Genb1_Ib0, NULL, NULL },
		/*2D*/{ &sub_context_Genvqp1_Ipas4, NULL, NULL },
		/*2E*/{ NULL, NULL, NULL },
		/*2F*/{ &das_context_Genb3, NULL, NULL },
		/*30*/{ &xor_context_Eb1_Gb0, NULL, NULL },
		/*31*/{ &xor_context_Evqp1_Gvqp0, NULL, NULL },
		/*32*/{ &xor_context_Gb1_Eb0, NULL, NULL },
		/*33*/{ &xor_context_Gvqp1_Evqp0, NULL, NULL },
		/*34*/{ &xor_context_Genb1_Ib0, NULL, NULL },
		/*35*/{ &xor_context_Genvqp1_Ipas4, NULL, NULL },
		/*36*/{ NULL, NULL, NULL },
		/*37*/{ &aaa_context_Genb3_Genb131, NULL, NULL },
		/*38*/{ &cmp_context_Eb0_Gb0, NULL, NULL },
		/*39*/{ &cmp_context_Evqp0_Gvqp0, NULL, NULL },
		/*3A*/{ &cmp_context_Gb0_Eb0, NULL, NULL },
		/*3B*/{ &cmp_context_Gvqp0_Evqp0, NULL, NULL },
		/*3C*/{ &cmp_context_Genb0_Ib0, NULL, NULL },
		/*3D*/{ &cmp_context_Genvqp0_Ipas4, NULL, NULL },
		/*3E*/{ NULL, NULL, NULL },
		/*3F*/{ &aas_context_Genb3_Genb131, NULL, NULL },
		/*40*/{ &inc_context_Zv1, NULL, NULL },
		/*41*/{ &inc_context_Zv1, NULL, NULL },
		/*42*/{ &inc_context_Zv1, NULL, NULL },
		/*43*/{ &inc_context_Zv1, NULL, NULL },
		/*44*/{ &inc_context_Zv1, NULL, NULL },
		/*45*/{ &inc_context_Zv1, NULL, NULL },
		/*46*/{ &inc_context_Zv1, NULL, NULL },
		/*47*/{ &inc_context_Zv1, NULL, NULL },
		/*48*/{ &dec_context_Zv1, NULL, NULL },
		/*49*/{ &dec_context_Zv1, NULL, NULL },
		/*4A*/{ &dec_context_Zv1, NULL, NULL },
		/*4B*/{ &dec_context_Zv1, NULL, NULL },
		/*4C*/{ &dec_context_Zv1, NULL, NULL },
		/*4D*/{ &dec_context_Zv1, NULL, NULL },
		/*4E*/{ &dec_context_Zv1, NULL, NULL },
		/*4F*/{ &dec_context_Zv1, NULL, NULL },
		/*50*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*51*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*52*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*53*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*54*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*55*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*56*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*57*/{ &push_context_SCv3_Zv0, NULL, NULL },
		/*58*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		/*59*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		/*5A*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		/*5B*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		/*5C*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		/*5D*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		/*5E*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		/*5F*/{ &pop_context_Zv1_SCv2, NULL, NULL },
		{ NULL, &table_prefix_60, read_table_offset_by_prefix },
		{ NULL, &table_prefix_61, read_table_offset_by_prefix },
		{ NULL, &table_62_mod, read_table_offset_by_mod },
		/*63*/{ &arpl_context_Ew0_Gw0, NULL, NULL },
		/*64*/{ NULL, NULL, NULL },
		/*65*/{ NULL, NULL, NULL },
		/*66*/{ NULL, NULL, NULL },
		/*67*/{ NULL, NULL, NULL },
		/*68*/{ &push_context_SCm3_Ivs4, NULL, NULL },
		/*69*/{ &imul_context_Gvqp1_Evqp0_Ipas4, NULL, NULL },
		/*6A*/{ &push_context_SCm3_Ibss4, NULL, NULL },
		/*6B*/{ &imul_context_Gvqp1_Evqp0_Ibs4, NULL, NULL },
		/*6C*/{ &insb_context_Yb3_Genw66, NULL, NULL },
		{ NULL, &table_prefix_6D, read_table_offset_by_prefix },
		/*6E*/{ &outsb_context_Genw67_Xb2, NULL, NULL },
		{ NULL, &table_prefix_6F, read_table_offset_by_prefix },
		/*70*/{ &jo_context_Jbs4, NULL, NULL },
		/*71*/{ &jno_context_Jbs4, NULL, NULL },
		/*72*/{ &jc_context_Jbs4, NULL, NULL },
		/*73*/{ &jnc_context_Jbs4, NULL, NULL },
		/*74*/{ &je_context_Jbs4, NULL, NULL },
		/*75*/{ &jne_context_Jbs4, NULL, NULL },
		/*76*/{ &jna_context_Jbs4, NULL, NULL },
		/*77*/{ &ja_context_Jbs4, NULL, NULL },
		/*78*/{ &js_context_Jbs4, NULL, NULL },
		/*79*/{ &jns_context_Jbs4, NULL, NULL },
		/*7A*/{ &jpe_context_Jbs4, NULL, NULL },
		/*7B*/{ &jpo_context_Jbs4, NULL, NULL },
		/*7C*/{ &jnge_context_Jbs4, NULL, NULL },
		/*7D*/{ &jge_context_Jbs4, NULL, NULL },
		/*7E*/{ &jng_context_Jbs4, NULL, NULL },
		/*7F*/{ &jg_context_Jbs4, NULL, NULL },
		{ NULL, &opcode_extension_80, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_81, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_82, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_83, read_table_offset_by_opcode_extension },
		/*84*/{ &test_context_Eb0_Gb0, NULL, NULL },
		/*85*/{ &test_context_Evqp0_Gvqp0, NULL, NULL },
		/*86*/{ &xchg_context_Gb1_Eb1, NULL, NULL },
		/*87*/{ &xchg_context_Gvqp1_Evqp1, NULL, NULL },
		/*88*/{ &mov_context_Eb1_Gb0, NULL, NULL },
		/*89*/{ &mov_context_Evqp1_Gvqp0, NULL, NULL },
		/*8A*/{ &mov_context_Gb1_Eb0, NULL, NULL },
		/*8B*/{ &mov_context_Gvqp1_Evqp0, NULL, NULL },
		{ NULL, &table_8C_mod, read_table_offset_by_mod },
		{ NULL, &table_8D_mod, read_table_offset_by_mod },
		/*8E*/{ &mov_context_Sw1_Ew0, NULL, NULL },
		{ NULL, &opcode_extension_8F, read_table_offset_by_opcode_extension },
		{ NULL, &table_prefix_90, read_table_offset_by_prefix },
		/*91*/{ &xchg_context_Zvqp1_Genvqp1, NULL, NULL },
		/*92*/{ &xchg_context_Zvqp1_Genvqp1, NULL, NULL },
		/*93*/{ &xchg_context_Zvqp1_Genvqp1, NULL, NULL },
		/*94*/{ &xchg_context_Zvqp1_Genvqp1, NULL, NULL },
		/*95*/{ &xchg_context_Zvqp1_Genvqp1, NULL, NULL },
		/*96*/{ &xchg_context_Zvqp1_Genvqp1, NULL, NULL },
		/*97*/{ &xchg_context_Zvqp1_Genvqp1, NULL, NULL },
		{ NULL, &table_prefix_98, read_table_offset_by_prefix },
		{ NULL, &table_prefix_99, read_table_offset_by_prefix },
		/*9A*/{ &callf_context_SCp3_Ap0, NULL, NULL },
		/*9B*/{ &wait_context, NULL, NULL },
		{ NULL, &table_prefix_9C, read_table_offset_by_prefix },
		{ NULL, &table_prefix_9D, read_table_offset_by_prefix },
		/*9E*/{ &sahf_context_Genb130, NULL, NULL },
		/*9F*/{ &lahf_context_Genb131, NULL, NULL },
		/*A0*/{ &mov_context_Genb1_Ob0, NULL, NULL },
		/*A1*/{ &mov_context_Genvqp1_Ovqp0, NULL, NULL },
		/*A2*/{ &mov_context_Ob1_Genb0, NULL, NULL },
		/*A3*/{ &mov_context_Ovqp1_Genvqp0, NULL, NULL },
		/*A4*/{ &movsb_context_Yb3_Xb2, NULL, NULL },
		{ NULL, &table_prefix_A5, read_table_offset_by_prefix },
		/*A6*/{ &cmpsb_context_Yb2_Xb2, NULL, NULL },
		{ NULL, &table_prefix_A7, read_table_offset_by_prefix },
		/*A8*/{ &test_context_Genb0_Ib0, NULL, NULL },
		/*A9*/{ &test_context_Genvqp0_Ipas4, NULL, NULL },
		/*AA*/{ &stosb_context_Yb3_Genb2, NULL, NULL },
		{ NULL, &table_prefix_AB, read_table_offset_by_prefix },
		/*AC*/{ &lodsb_context_Genb3_Xb2, NULL, NULL },
		{ NULL, &table_prefix_AD, read_table_offset_by_prefix },
		/*AE*/{ &scasb_context_Yb2_Genb2, NULL, NULL },
		{ NULL, &table_prefix_AF, read_table_offset_by_prefix },
		/*B0*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B1*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B2*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B3*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B4*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B5*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B6*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B7*/{ &mov_context_Zb1_Ib0, NULL, NULL },
		/*B8*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		/*B9*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		/*BA*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		/*BB*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		/*BC*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		/*BD*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		/*BE*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		/*BF*/{ &mov_context_Zvqp1_Ivqp0, NULL, NULL },
		{ NULL, &opcode_extension_C0, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_C1, read_table_offset_by_opcode_extension },
		/*C2*/{ &retn_context_SCw2_Iw0, NULL, NULL },
		/*C3*/{ &retn_context_SCm2, NULL, NULL },
		{ NULL, &table_C4_mod, read_table_offset_by_mod },
		{ NULL, &table_C5_mod, read_table_offset_by_mod },
		{ NULL, &opcode_extension_C6, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_C7, read_table_offset_by_opcode_extension },
		/*C8*/{ &enter_context_SCw3_Genv163_Iw0_Ib0, NULL, NULL },
		/*C9*/{ &leave_context_Genv163_SCv2, NULL, NULL },
		/*CA*/{ &retf_context_Iw0_SCw2, NULL, NULL },
		/*CB*/{ &retf_context_SCm2, NULL, NULL },
		/*CC*/{ &int_context_SCv3_I3b0_Fv2, NULL, NULL },
		/*CD*/{ &int_context_SCb3_Ib0_Fv2, NULL, NULL },
		/*CE*/{ &into_context_SCv3_Fv2, NULL, NULL },
		{ NULL, &table_prefix_CF, read_table_offset_by_prefix },
		{ NULL, &opcode_extension_D0, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_D1, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_D2, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_D3, read_table_offset_by_opcode_extension },
		/*D4*/{ &aam_context_Genb3_Genb131, NULL, NULL },
		/*D5*/{ &aad_context_Genb3_Genb131, NULL, NULL },
		/*D6*/{ &setalc_context_Genb3, NULL, NULL },
		/*D7*/{ &xlatb_context_Genb3_BBb2, NULL, NULL },
		{ NULL, &opcode_extension_D8, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_D9, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_DA, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_DB, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_DC, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_DD, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_DE, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_DF, read_table_offset_by_opcode_extension },
		/*E0*/{ &loopne_context_Genva35_Jbs4, NULL, NULL },
		/*E1*/{ &loope_context_Genva35_Jbs4, NULL, NULL },
		/*E2*/{ &loop_context_Genva35_Jbs4, NULL, NULL },
		/*E3*/{ &jecxz_context_Jbs4_Genda34, NULL, NULL },
		/*E4*/{ &in_context_Genb1_Ib0, NULL, NULL },
		/*E5*/{ &in_context_Genv1_Ib0, NULL, NULL },
		/*E6*/{ &out_context_Ib1_Genb0, NULL, NULL },
		/*E7*/{ &out_context_Ib1_Genv0, NULL, NULL },
		/*E8*/{ &call_context_SCpas7_Jpas4, NULL, NULL },
		/*E9*/{ &jmp_context_Jpas4, NULL, NULL },
		/*EA*/{ &jmpf_context_Ap0, NULL, NULL },
		/*EB*/{ &jmp_context_Jbs4, NULL, NULL },
		/*EC*/{ &in_context_Genb1_Genw64, NULL, NULL },
		/*ED*/{ &in_context_Genv1_Genw64, NULL, NULL },
		/*EE*/{ &out_context_Genw65_Genb0, NULL, NULL },
		/*EF*/{ &out_context_Genw65_Genv0, NULL, NULL },
		/*F0*/{ NULL, NULL, NULL },
		/*F1*/{ &icebp_context_SCv3_Fv2, NULL, NULL },
		/*F2*/{ NULL, NULL, NULL },
		/*F3*/{ NULL, NULL, NULL },
		/*F4*/{ &hlt_context, NULL, NULL },
		/*F5*/{ &cmc_context, NULL, NULL },
		{ NULL, &opcode_extension_F6, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_F7, read_table_offset_by_opcode_extension },
		/*F8*/{ &clc_context, NULL, NULL },
		/*F9*/{ &stc_context, NULL, NULL },
		/*FA*/{ &cli_context, NULL, NULL },
		/*FB*/{ &sti_context, NULL, NULL },
		/*FC*/{ &cld_context, NULL, NULL },
		/*FD*/{ &std_context, NULL, NULL },
		{ NULL, &opcode_extension_FE, read_table_offset_by_opcode_extension },
		{ NULL, &opcode_extension_FF, read_table_offset_by_opcode_extension }
	};


#ifdef __cplusplus
}
#endif

#endif