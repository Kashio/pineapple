#include <gtest/gtest.h>
#include <pineapple/pineapple.h>

#define STREAMS_NUMBER 256

typedef struct instruction {
	uint8_t number_of_bytes;
	char* bytes;
	char* instruction;
	uint8_t ignore;
} instruction;

void concat_str_n(char** destination, const char* source, size_t size) {
	size_t new_size = strlen(*destination) + size + 1;
	char* new_buffer = (char*)malloc(sizeof(char) * new_size);
	strcpy(new_buffer, *destination);
	strncat(new_buffer, source, size);
	*destination = new_buffer;
}

TEST(X86_64_ARCH, Instructions_Sanity)
{
	instruction instructions[STREAMS_NUMBER] = {
		{ 3, "\x00\xc1", "add cl, al", 0 },
		{ 2, "\x02\xc8", "add cl, al", 0 },
		{ 2, "\x01\xc1", "add ecx, eax", 0 },
		{ 2, "\x03\xc8", "add ecx, eax", 0 },
		{ 6, "\x03\x1d\xc8\x01\x00\x00", "add ebx, dword ptr ds:[0x1c8]", 0 },
		{ 2, "\x03\x3b", "add edi, dword ptr [ebx]", 0 },
		{ 3, "\x03\x46\x3a", "add eax, dword ptr [esi + 0x3a]", 0 },
		{ 6, "\x03\x9d\xa9\x8f\x16\x00", "add ebx, dword ptr [ebp + 0x168fa9]", 0 },
		{ 3, "\x03\x0c\xbb", "add ecx, dword ptr [ebx + edi * 4]", 0 },
		{ 4, "\x67\x03\x40\x58", "add eax, dword ptr [bx + si + 0x58]", 0 },
		{ 5, "\x67\x03\xAF\x9D\x00", "add ebp, dword ptr [bx + 0x9d]", 0 },
		{ 3, "\x67\x01\xD8", "add eax, ebx", 0 },
		{ 2, "\x04\x03", "add al, 0x3", 0 },
		{ 5, "\x05\xCC\x0D\x00\x00", "add eax, 0xdcc", 0 },
		{ 1, "\x06", "push es", 0 },
		{ 1, "\x07", "pop es", 0 },
		{ 2, "\x08\x03", "or byte ptr [ebx], al", 0 },
		{ 2, "\x09\x03", "or dword ptr [ebx], eax", 0 },
		{ 3, "\x67\x0A\x07", "or al, byte ptr [bx]", 0 },
		{ 4, "\x67\x66\x0B\x07", "or ax, word ptr [bx]", 0 },
		{ 3, "\x67\x0B\x07", "or eax, dword ptr [bx]", 0 },
		{ 2, "\x0C\x05", "or al, 0x5", 0 },
		{ 5, "\x0D\x1C\x09\x00\x00", "or eax, 0x91c", 0 },
		{ 1, "\x0E", "push cs", 0 },
		{ 3, "\x11\x58\x03", "adc dword ptr [eax + 0x3], ebx", 0 },
		{ 2, "\x14\x63", "adc al, 0x63", 0 },
		{ 1, "\x16", "push ss", 0 },
		{ 1, "\x17", "pop ss", 0 },
		{ 7, "\x1B\x04\x9D\x00\x00\x00\x00", "sbb eax, dword ptr [ebx * 4 + 0x0]", 0 },
		{ 2, "\x1C\x03", "sbb al, 0x3", 0 },
		{ 1, "\x1E", "push ds", 0 },
		{ 1, "\x1F", "pop ds", 0 },
		{ 2, "\x20\xD8", "and al, bl", 0 },
		{ 5, "\x25\x58\x6E\x01\x00", "and eax, 0x16e58", 0 },
		//{ 1, "\x26", "es", 1 },
		{ 7, "\x0F\x00\x81\x05\x00\x00\x00", "sldt word ptr es:[ecx + 0x5]", 0 },
		{ 1, "\x27", "daa", 0 },
		{ 3, "\x2B\x04\x9A", "sub eax, dword ptr [edx + ebx * 4]", 0 },
		{ 3, "\x67\x28\x07", "sub byte ptr [bx], al", 0 },
		{ 5, "\x2D\xCF\xC4\x2A\x03", "sub eax, 0x32ac4cf", 0 },
		//{ 1, "\2E", "cs", 1 },
		{ 1, "\2F", "das", 0 },
		{ 4, "\x67\x31\x77\x20", "xor dword ptr [bx + 0x20], esi", 0 },
		{ 7, "\x66\x33\x93\x9C\x00\x00\x00", "xor dx, word ptr [ebx + 0x9c]", 0 },
		{ 2, "\x30\xC0", "xor al, al", 0 },
		//{ 1, "\x36", "ss", 1 },
		{ 1, "\x37", "aaa", 0 },
		{ 7, "\x3B\x84\x93\x7A\x11\x00\x00", "cmp eax, dword ptr [ebx + edx * 4 + 0x117a]", 0 },
		{ 2, "\x3C\x07", "cmp al, 0x7", 0 },
		//{ 1, "\x3E", "ds", 1 },
		{ 1, "\x3F", "aas", 0 },
		{ 1, "\x41", "inc ecx", 0 },
		{ 2, "\x66\x47", "inc di", 0 },
		{ 1, "\x48", "dec eax", 0 },
		{ 2, "\x66\x4C", "dec sp", 0 },
		{ 1, "\x54", "push esp", 0 },
		{ 2, "\x66\x51", "push cx", 0 },
		{ 1, "\x5D", "pop ebp", 0 },
		{ 2, "\x66\x5A", "pop dx", 0 }, // 55 is here
		{ 2, "\x66\x60", "pusha", 0 },
		{ 1, "\x60", "pushad", 0 },
		{ 2, "\x66\x61", "popa", 0 },
		{ 1, "\x61", "popad", 0 },
		{ 3, "\x66\x62\x39", "bound di, dword ptr [ecx]", 0 },
		{ 4, "\x67\x66\x62\x39", "bound di, dword ptr [bx + di]", 0 },
		{ 2, "\x62\x39", "bound edi, qword ptr [ecx]", 0 },
		{ 2, "\x63\x39", "arpl word ptr [ecx], di", 0 },
		//{ 1, "\x64", "fs", 1 },
		//{ 1, "\x65", "gs", 1 },
		//{ 1, "\x66", "data16", 1 },
		//{ 1, "\x67", "addr16", 1 },
		{ 5, "\x68\x21\x02\x00\x00", "push 0x221", 0 },
		{ 4, "\x66\x68\x21\x32", "push 0x3221", 0 },
		{ 6, "\x69\xCA\x29\x16\x00\x00", "imul ecx, edx, 0x1629", 0 },
		{ 2, "\x6A\x77", "push 0x77", 0 },
		{ 3, "\x6B\xFE\x05", "imul edi, esi, 0x5", 0 },
		{ 1, "\x6C", "insb", 0 },
		{ 1, "\x6D", "insd", 0 },
		{ 2, "\x66\x6D", "insw", 0 },
		{ 1, "\x6E", "outsb", 0 },
		{ 1, "\x6F", "outsd", 0 },
		{ 2, "\x66\x6F", "outsw", 0 },
		{ 2, "\x70\x54", "jo 0x56", 0 },
		{ 2, "\x71\x59", "jno 0x5b", 0 },
		{ 2, "\x72\x0A", "jc 0xc", 0 },
		{ 2, "\x73\x11", "jnc 0x13", 0 },
		{ 2, "\x74\x15", "je 0x17", 0 },
		{ 2, "\x75\x19", "jne 0x1b", 0 },
		{ 2, "\x76\x38", "jna 0x3a", 0 },
		{ 2, "\x77\x99", "ja 0xffffff9b", 0 },
		{ 2, "\x78\x00", "js 0x2", 0 },
		{ 2, "\x79\x01", "jns 0x3", 0 },
		{ 2, "\x7A\x8F", "jpe 0xffffff91", 0 },
		{ 2, "\x7B\x88", "jpo 0xffffff8a", 0 },
		{ 2, "\x7C\x10", "jnge 0x12", 0 },
		{ 2, "\x7D\xD0", "jge 0xffffffd2", 0 },
		{ 2, "\x7E\xD8", "jng 0xffffffda", 0 },
		{ 2, "\x7F\xFF", "jg 0x1", 0 },
		{ 3, "\x80\xC3\x05", "add bl, 0x5", 0 },
		{ 3, "\x80\xFA\x33", "cmp dl, 0x33", 0 },
		{ 3, "\x80\xED\xFF", "sub ch, 0xff", 0 },
		{ 5, "\x66\x81\xE9\x00\x01", "sub cx, 0x100", 0 },
		{ 6, "\x81\xD6\x02\x0F\x00\x00", "adc esi, 0xf02", 0 },
		{ 5, "\x66\x81\xF6\x05\x00", "xor si, 0x5", 0 },
		{ 3, "\x82\xC3\x01", "add bl, 0x1", 0 },
		{ 4, "\x66\x83\xC2\x05", "add dx, 0x5", 0 },
		{ 3, "\x83\xDD\x26", "sbb ebp, 0x26", 0 },
		{ 2, "\x84\x32", "test byte ptr [edx], dh", 0 },
		{ 3, "\x66\x85\x13", "test word ptr [ebx], dx", 0 },
		{ 2, "\x86\x03", "xchg al, byte ptr [ebx]", 0 },
		{ 3, "\x66\x87\xFE", "xchg di, si", 0 },
		{ 2, "\x88\x1F", "mov byte ptr [edi], bl", 0 },
		{ 2, "\x89\xE7", "mov edi, esp", 0 },
		{ 2, "\x8A\x0B", "mov cl, byte ptr [ebx]", 0 },
		{ 4, "\x67\x66\x8B\x0B", "mov cx, word ptr [bp + di]", 0 },
		{ 2, "\x8C\x28", "mov word ptr [eax], gs", 0 },
		{ 2, "\x8D\x11", "lea edx, [ecx]", 0 }, // 109 is here
		{ 7, "\x8E\x94\xB9\x81\x01\x00\x00", "mov ss, word ptr [ecx + edi * 4 + 0x181]", 0 },
		//{ 4, "\x8E\x94\xB9\x81", "mov ss, word ptr [si - 0x7e47]", 0}, // TODO: check only in 16bit mode - not yet added to stream
		{ 2, "\x8F\x03", "pop dword ptr [ebx]", 0 },
		{ 4, "\x66\x8F\x43\x93", "pop word ptr [ebx - 0x6d]", 0 },
		//{ 2, "\x8F\x43", ".byte 0x8f inc ebx - (only if last on stream because missing displacement byte)", 1 },
		{ 1, "\x90", "nop", 0 },
		{ 2, "\xF3\x90", "pause", 0 },
		{ 1, "\x92", "xchg edx, eax", 0 },
		{ 2, "\x66\x98", "cbw", 0 },
		{ 1, "\x98", "cwde", 0 },
		{ 2, "\x66\x99", "cwd", 0 },
		{ 1, "\x99", "cdq", 0 },
		{ 7, "\x9A\x00\x50\x30\x84\x38\x22", "callf 0x2238:0x84305000", 0 },
		{ 6, "\x66\x9A\x31\x74\x00\x99", "callf 0x9900:0x7431", 0 },
		{ 1, "\x9B", "wait", 0 },
		{ 2, "\x66\x9C", "pushf", 0 },
		{ 1, "\x9C", "pushfd", 0 },
		{ 2, "\x66\x9D", "popf", 0 },
		{ 1, "\x9D", "popfd", 0 },
		{ 1, "\x9E", "sahf", 0 },
		{ 1, "\x9F", "lahf", 0 },
		{ 5, "\xA0\x04\x03\x02\x01", "mov al, byte ptr ds:[0x1020304]", 0 },
		{ 5, "\xA1\x04\x03\x02\x01", "mov eax, dword ptr ds:[0x1020304]", 0 },
		{ 6, "\x66\xA1\x04\x03\x02\x01", "mov ax, word ptr ds:[0x1020304]", 0 },
		{ 5, "\xA2\x04\x03\x02\x01", "mov byte ptr ds:[0x1020304], al", 0 },
		{ 5, "\xA3\x04\x03\x02\x01", "mov dword ptr ds:[0x1020304], eax", 0 },
		{ 6, "\x66\xA3\x04\x03\x02\x01", "mov word ptr ds:[0x1020304], ax", 0 },
		{ 1, "\xA4", /*"movsb byte ptr es:[edi], byte ptr ds:[esi]"*/ "movsb", 0 },
		{ 2, "\x67\xA4", /*"movsb byte ptr es:[di], byte ptr ds:[si]"*/ "movsb", 0 },
		{ 1, "\xA5", /*"movsd dword ptr es:[edi], dword ptr ds:[esi]"*/ "movsd", 0 },
		{ 3, "\x67\x66\xA5", /*"movsw word ptr es:[di], word ptr ds:[si]"*/ "movsw", 0 },
		{ 1, "\xA6", /*"cmpsb byte ptr es:[edi], byte ptr ds:[esi]"*/ "cmpsb", 0 },
		{ 2, "\x67\xA6", /*"cmpsb byte ptr es:[di], byte ptr ds:[si]"*/ "cmpsb", 0 },
		{ 1, "\xA7", /*"cmpsd dword ptr es:[edi], dword ptr ds:[esi]"*/ "cmpsd", 0 },
		{ 3, "\x67\x66\xA7", /*"cmpsw word ptr es:[di], word ptr ds:[si]"*/ "cmpsw", 0 },
		{ 2, "\xA8\x33", "test al, 0x33", 0 },
		{ 5, "\xA9\x4A\x11\x23\x15", "test eax, 0x1523114a", 0 },
		{ 4, "\x66\xA9\x4A\x11", "test ax, 0x114a", 0 },
		{ 1, "\xAA", /*"stosb byte ptr es:[edi], al"*/ "stosb", 0 },
		{ 2, "\x67\xAA", /*"stosb byte ptr es:[di], al"*/ "stosb", 0 },
		{ 1, "\xAB", /*"stosd dword ptr es:[edi], eax"*/ "stosd", 0 },
		{ 3, "\x67\x66\xAB", /*"stosw word ptr es:[di], ax"*/ "stosw", 0 },
		{ 1, "\xAC", /*"lodsb al, byte ptr ds:[esi]"*/ "lodsb", 0 },
		{ 2, "\x67\xAC", /*"lodsb al, byte ptr ds:[si]"*/ "lodsb", 0 },
		{ 1, "\xAD", /*"lodsd eax, dword ptr ds:[esi]"*/ "lodsd", 0 },
		{ 3, "\x67\x66\xAD", /*"lodsw ax, word ptr ds:[si]"*/ "lodsw", 0 },
		{ 1, "\xAE", /*"scasb byte ptr es:[edi], al"*/ "scasb", 0 },
		{ 2, "\x67\xAE", /*"scasb byte ptr es:[di], al"*/ "scasb", 0 },
		{ 1, "\xAF", /*"scasd dword ptr es:[edi], eax"*/ "scasd", 0 },
		{ 3, "\x67\x66\xAF", /*"scasw word ptr es:[di], ax"*/ "scasw", 0 },
		{ 2, "\xB0\x01", "mov al, 0x1", 0 },
		{ 2, "\xB1\x01", "mov cl, 0x1", 0 },
		{ 2, "\xB2\x01", "mov dl, 0x1", 0 },
		{ 2, "\xB3\x01", "mov bl, 0x1", 0 },
		{ 2, "\xB4\x01", "mov ah, 0x1", 0 },
		{ 2, "\xB5\x01", "mov ch, 0x1", 0 },
		{ 2, "\xB6\x01", "mov dh, 0x1", 0 },
		{ 2, "\xB7\x01", "mov bh, 0x1", 0 },
		{ 5, "\xB8\x01\x02\x03\x04", "mov eax, 0x4030201", 0 },
		{ 4, "\x66\xB8\x01\x02", "mov ax, 0x201", 0 },
		{ 5, "\xB9\x01\x02\x03\x04", "mov ecx, 0x4030201", 0 },
		{ 4, "\x66\xB9\x01\x02", "mov cx, 0x201", 0 },
		{ 5, "\xBA\x01\x02\x03\x04", "mov edx, 0x4030201", 0 },
		{ 4, "\x66\xBA\x01\x02", "mov dx, 0x201", 0 },
		{ 5, "\xBB\x01\x02\x03\x04", "mov ebx, 0x4030201", 0 },
		{ 4, "\x66\xBB\x01\x02", "mov bx, 0x201", 0 },
		{ 5, "\xBC\x01\x02\x03\x04", "mov esp, 0x4030201", 0 },
		{ 4, "\x66\xBC\x01\x02", "mov sp, 0x201", 0 },
		{ 5, "\xBD\x01\x02\x03\x04", "mov ebp, 0x4030201", 0 },
		{ 4, "\x66\xBD\x01\x02", "mov bp, 0x201", 0 },
		{ 5, "\xBE\x01\x02\x03\x04", "mov esi, 0x4030201", 0 },
		{ 4, "\x66\xBE\x01\x02", "mov si, 0x201", 0 },
		{ 5, "\xBF\x01\x02\x03\x04", "mov edi, 0x4030201", 0 },
		{ 4, "\x66\xBF\x01\x02", "mov di, 0x201", 0 },
		{ 3, "\xC0\xC2\x05", "rol dl, 0x5", 0 },
		{ 4, "\xC0\x42\x11\x53", "rol byte ptr [edx + 0x11], 0x53", 0 },
		{ 4, "\xC0\x4F\x12\x23", "ror byte ptr [edi + 0x12], 0x23", 0 },
		{ 7, "\xC0\x97\x35\xE8\x00\x00\x23", "rcl byte ptr [edi + 0xe835], 0x23", 0 },
		{ 3, "\xC0\xDB\x23", "rcr bl, 0x23", 0 }
	};
	char* inst_stream = "";
	size_t inst_stream_size = 0;
	size_t i;
	size_t number_of_streams = sizeof(instructions) / sizeof(instructions[0]);
	for (i = 0; i < number_of_streams; i++) {
		if (instructions[i].ignore) {
			continue;
		}
		concat_str_n(&inst_stream, instructions[i].bytes, instructions[i].number_of_bytes);
		inst_stream_size += instructions[i].number_of_bytes;
	}
	pa_instruction* inst;
	pa_handle h;
	h.mode = VD_MODE_32;
	size_t count = disassemble(&h, "\x00\xc1\x02\xc8\x01\xc1\x03\xc8\x03\x1d\xc8\x01\x00\x00\x03\x3b\x03\x46\x3a\x03\x9d\xa9\x8f\x16\x00\x03\x0c\xbb\x67\x03\x40\x58\x67\x03\xAF\x9D\x00\x67\x01\xD8\x04\x03\x05\xCC\x0D\x00\x00\x06\x07\x08\x03\x09\x03\x67\x0A\x07\x67\x66\x0B\x07\x67\x0B\x07\x0C\x05\x0D\x1C\x09\x00\x00\x0E\x11\x58\x03\x14\x63\x16\x17\x1B\x04\x9D\x00\x00\x00\x00\x1C\x03\x1E\x1F\x20\xD8\x25\x58\x6E\x01\x00\x26\x0F\x00\x81\x05\x00\x00\x00\x27\x2B\x04\x9A\x67\x28\x07\x2D\xCF\xC4\x2A\x03\x2F\x67\x31\x77\x20\x66\x33\x93\x9C\x00\x00\x00\x30\xC0\x37\x3B\x84\x93\x7A\x11\x00\x00\x3C\x07\x3F\x41\x66\x47\x48\x66\x4C\x54\x66\x51\x5D\x66\x5A\x66\x60\x60\x66\x61\x61\x66\x62\x39\x67\x66\x62\x39\x62\x39\x63\x39\x68\x21\x02\x00\x00\x66\x68\x21\x32\x69\xCA\x29\x16\x00\x00\x6A\x77\x6B\xFE\x05\x6C\x6D\x66\x6D\x6E\x6F\x66\x6F\x70\x54\x71\x59\x72\x0A\x73\x11\x74\x15\x75\x19\x76\x38\x77\x99\x78\x00\x79\x01\x7A\x8F\x7B\x88\x7C\x10\x7D\xD0\x7E\xD8\x7F\xFF\x80\xC3\x05\x80\xFA\x33\x80\xED\xFF\x66\x81\xE9\x00\x01\x81\xD6\x02\x0F\x00\x00\x66\x81\xF6\x05\x00\x82\xC3\x01\x66\x83\xC2\x05\x83\xDD\x26\x84\x32\x66\x85\x13\x86\x03\x66\x87\xFE\x88\x1F\x89\xE7\x8A\x0B\x67\x66\x8B\x0B\x8C\x28\x8D\x11\x8E\x94\xB9\x81\x01\x00\x00\x8F\x03\x66\x8F\x43\x93\x90\xF3\x90\x92\x66\x98\x98\x66\x99\x99\x9A\x00\x50\x30\x84\x38\x22\x66\x9A\x31\x74\x00\x99\x9B\x66\x9C\x9C\x66\x9D\x9D\x9E\x9F\xA0\x04\x03\x02\x01\xA1\x04\x03\x02\x01\x66\xA1\x04\x03\x02\x01\xA2\x04\x03\x02\x01\xA3\x04\x03\x02\x01\x66\xA3\x04\x03\x02\x01\xA4\x67\xA4\xA5\x67\x66\xA5\xA6\x67\xA6\xA7\x67\x66\xA7\xA8\x33\xA9\x4A\x11\x23\x15\x66\xA9\x4A\x11\xAA\x67\xAA\xAB\x67\x66\xAB\xAC\x67\xAC\xAD\x67\x66\xAD\xAE\x67\xAE\xAF\x67\x66\xAF\xB0\x01\xB1\x01\xB2\x01\xB3\x01\xB4\x01\xB5\x01\xB6\x01\xB7\x01\xB8\x01\x02\x03\x04\x66\xB8\x01\x02\xB9\x01\x02\x03\x04\x66\xB9\x01\x02\xBA\x01\x02\x03\x04\x66\xBA\x01\x02\xBB\x01\x02\x03\x04\x66\xBB\x01\x02\xBC\x01\x02\x03\x04\x66\xBC\x01\x02\xBD\x01\x02\x03\x04\x66\xBD\x01\x02\xBE\x01\x02\x03\x04\x66\xBE\x01\x02\xBF\x01\x02\x03\x04\x66\xBF\x01\x02\xC0\xC2\x05\xC0\x42\x11\x53\xC0\x4F\x12\x23\xC0\x97\x35\xE8\x00\x00\x23\xC0\xDB\x23", 521, 0, &inst);
	size_t longest_instruction = 1;
	for (i = 0; i < count; i++)
	{
		longest_instruction = MAX(longest_instruction, inst[i].size);
	}
	for (i = 0; i < count; i++)
	{
		pa_print_instruction(&inst[i], longest_instruction);
	}
	for (i = 0; i < count; i++)
	{
		char* inst_str = "";
		concat_str(&inst_str, inst[i].mnemonic);
		if (strcmp(inst[i].operand_str, "") != 0) {
			concat_str(&inst_str, " ");
			concat_str(&inst_str, inst[i].operand_str);
		}
		if (strcmp(inst_str, instructions[i].instruction) != 0) {
			printf("INSTRUCTION:\n\t");
			for (size_t j = 0; j < inst[i].size; j++) {
				printf("\\x%02X", inst[i].bytes[j]);
			}
			printf(" %s  %s\n\t", inst[i].mnemonic, inst[i].operand_str);
			printf("SHOULD BE:\n\t");
			for (size_t j = 0; j < instructions[i].number_of_bytes; j++) {
				printf("\\x%02X", instructions[i].bytes[j]);
			}
			printf(" %s\n", instructions[i].instruction);
		}
	}
	// \x62\xF9 - should not be bound
}
