#ifndef PREFIX_H
#define PREFIX_H

#include "pineapple/common/utils.h"

typedef enum pa_x86_prefix {
	VD_x86_PREFIX_NONE = 0x0,
	VD_X86_PREFIX_LOCK = 0xf0,
	VD_X86_PREFIX_REP = 0xf3,
	VD_X86_PREFIX_REPNE = 0xf2,
	VD_X86_PREFIX_ADDRESS_SIZE = 0x67,
	VD_X86_PREFIX_OPERAND_SIZE = 0x66,
	VD_X86_PREFIX_CS = 0x2e,
	VD_X86_PREFIX_SS = 0x36,
	VD_X86_PREFIX_DS = 0x3e,
	VD_X86_PREFIX_ES = 0x26,
	VD_X86_PREFIX_FS = 0x64,
	VD_X86_PREFIX_GS = 0x65
} pa_x86_prefix;

static const name_map prefix_name_map[] = {
	{ 0, "lock/rep/repne" },
	{ 1, "addr16" },
	{ 2, "data16" },
};

static const name_map segment_name_map[] = {
	{ 0, "es" },
	{ 1, "cs" },
	{ 2, "ss" },
	{ 3, "ds" },
	{ 4, "" },
	{ 5, "" },
	{ 6, "" },
	{ 7, "" },
	{ 8, "gs" },
	{ 7, "fs" }
};

static const pa_x86_register segment_name_map_modrm_reg[] = {
	VD_X86_REG_ES,
	VD_X86_REG_CS,
	VD_X86_REG_SS,
	VD_X86_REG_DS,
	VD_X86_REG_FS,
	VD_X86_REG_GS,
	VD_X86_REG_UNDEFINED,
	VD_X86_REG_UNDEFINED
};

#endif