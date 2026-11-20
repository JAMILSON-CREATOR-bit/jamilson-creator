#include <stdint.h>

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

static inline int64_t syscall6(int64_t num, int64_t a0, int64_t a1, int64_t a2,
                               int64_t a3, int64_t a4, int64_t a5) {
    register int64_t x0 asm("x0") = a0;
    register int64_t x1 asm("x1") = a1;
    register int64_t x2 asm("x2") = a2;
    register int64_t x3 asm("x3") = a3;
    register int64_t x4 asm("x4") = a4;
    register int64_t x5 asm("x5") = a5;
    register int64_t x8 asm("x8") = num;

    asm volatile (
        "svc #0\n\t"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5), "r" (x8)
        : "memory"
    );
    return x0;
}

uint64_t str_len(const char *s) {
    uint64_t n = 0;
    while (s[n]) n++;
    return n;
}

int str_eq(const char *a, const char *b) {
    while (*a && (*a == *b)) { a++; b++; }
    return *(const uint8_t *)a - *(const uint8_t *)b;
}

void print_str(const char *s) {
    syscall6(64, 1, (int64_t)s, str_len(s), 0, 0, 0);
}

void print_hex32(uint32_t val) {
    char hex[11];
    const char digitos[] = "0123456789abcdef";
    hex[0] = '0'; hex[1] = 'x';
    for (int i = 7; i >= 0; i--) {
        hex[2 + (7 - i)] = digitos[(val >> (i * 4)) & 0xF];
    }
    hex[10] = '\0';
    print_str(hex);
}

void print_hex64(uint64_t val) {
    char hex[19];
    const char digitos[] = "0123456789abcdef";
    hex[0] = '0'; hex[1] = 'x';
    for (int i = 15; i >= 0; i--) {
        hex[2 + (15 - i)] = digitos[(val >> (i * 4)) & 0xF];
    }
    hex[18] = '\0';
    print_str(hex);
}

void print_dec(uint32_t val) {
    char buf[12];
    int i = 10;
    buf[11] = '\0';
    if (val == 0) {
        print_str("0");
        return;
    }
    while (val > 0 && i >= 0) {
        buf[i--] = '0' + (val % 10);
        val /= 10;
    }
    print_str(&buf[i + 1]);
}

// Decodificador ARM64 expandido (bit a bit)
void desmontar_funcao(const char *nome, const uint32_t *instrucoes, uint64_t offset_elf, uint64_t bytes) {
    print_str("=== Disassembly Puro: ");
    print_str(nome);
    print_str(" (Offset: ");
    print_hex64(offset_elf);
    print_str(") ===\n");

    uint64_t total_inst = bytes / 4;
    if (total_inst > 24) total_inst = 24;

    for (uint64_t i = 0; i < total_inst; i++) {
        uint32_t inst = instrucoes[i];
        uint64_t pc_atual = offset_elf + (i * 4);

        print_str("  ");
        print_hex32(inst);
        print_str("  ->  ");

        // 1. MOVZ (mov xN, #imm16)
        if ((inst & 0xFFE00000) == 0xD2800000) {
            uint32_t reg = inst & 0x1F;
            uint32_t imm = (inst >> 5) & 0xFFFF;
            print_str("mov x"); print_dec(reg); print_str(", #"); print_dec(imm);
            if (reg == 8) print_str("  [Syscall ID em x8!]");
        }
        // 2. SVC #imm
        else if ((inst & 0xFFE0001F) == 0xD4000001) {
            uint32_t imm = (inst >> 5) & 0xFFFF;
            print_str("svc #"); print_dec(imm);
            print_str("       [Salto EL0 -> EL1]");
        }
        // 3. ADRP xD, #page_offset (Calcula pagina de 4KB relativa ao PC)
        else if ((inst & 0x9F000000) == 0x90000000) {
            uint32_t rd = inst & 0x1F;
            // Reconstroi o imediato de 21 bits com sinal (immhi:immlo) << 12
            int64_t immlo = (inst >> 29) & 0x3;
            int64_t immhi = (inst >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & 0x100000) imm |= ~0x1FFFFFULL; // Extensao de sinal 21 bits
            uint64_t pagina_alvo = (pc_atual & ~0xFFFULL) + (imm << 12);

            print_str("adrp x"); print_dec(rd); print_str(", "); print_hex64(pagina_alvo);
            print_str(" [Base Pagina PC]");
        }
        // 4. ADD imediato 64 bits (add xD, xN, #imm12)
        else if ((inst & 0xFF800000) == 0x91000000) {
            uint32_t rd = inst & 0x1F;
            uint32_t rn = (inst >> 5) & 0x1F;
            uint32_t imm12 = (inst >> 10) & 0xFFF;
            if ((inst >> 22) & 1) imm12 <<= 12; // Shift opcional LSL #12
            print_str("add x"); print_dec(rd); print_str(", x"); print_dec(rn);
            print_str(", #"); print_dec(imm12);
        }
        // 5. LDR 64 bits (ldr xT, [xN, #offset])
        else if ((inst & 0xFFC00000) == 0xF9400000) {
            uint32_t rt = inst & 0x1F;
            uint32_t rn = (inst >> 5) & 0x1F;
            uint32_t offset = ((inst >> 10) & 0xFFF) * 8;
            print_str("ldr x"); print_dec(rt); print_str(", [x"); print_dec(rn);
            print_str(", #"); print_dec(offset); print_str("]");
        }
        // 6. STR 64 bits (str xT, [xN, #offset])
        else if ((inst & 0xFFC00000) == 0xF9000000) {
            uint32_t rt = inst & 0x1F;
            uint32_t rn = (inst >> 5) & 0x1F;
            uint32_t offset = ((inst >> 10) & 0xFFF) * 8;
            print_str("str x"); print_dec(rt); print_str(", [x"); print_dec(rn);
            print_str(", #"); print_dec(offset); print_str("]");
        }
        // 7. RET (x30)
        else if (inst == 0xD65F03C0) {
            print_str("ret          [Fim da funcao]\n");
            break;
        }
        // 8. B.cond
        else if ((inst & 0xFF000010) == 0x54000000) {
            print_str("b.cond       [Desvio condicional]");
        }
        // 9. B / BL
        else if ((inst & 0x7C000000) == 0x14000000) {
            if (inst & 0x80000000) print_str("bl           [Chamada sub-rotina]");
            else print_str("b            [Salto direto]");
        }
        else {
            print_str("inst_arm64   [Outra operacao]");
        }

        print_str("\n");
    }
    print_str("\n");
}

void _start(void) {
    const char alvo[] = "/apex/com.android.runtime/lib64/bionic/libc.so";

    int64_t fd = syscall6(56, -100, (int64_t)alvo, 0, 0, 0, 0);
    if (fd < 0) syscall6(93, 1, 0, 0, 0, 0, 0);

    int64_t tam = syscall6(62, fd, 0, 2, 0, 0, 0);
    int64_t base = syscall6(222, 0, tam, 1, 2, fd, 0);
    if ((uint64_t)base >= (uint64_t)-4095) syscall6(93, 1, 0, 0, 0, 0, 0);

    uint8_t *mem = (uint8_t *)base;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;

    if (ehdr->e_ident[0] == 0x7F && ehdr->e_ident[1] == 'E' &&
        ehdr->e_ident[2] == 'L'  && ehdr->e_ident[3] == 'F' &&
        ehdr->e_machine == 0xB7) {

        Elf64_Shdr *secoes = (Elf64_Shdr *)(mem + ehdr->e_shoff);

        for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
            if (secoes[i].sh_type == 11) { // SHT_DYNSYM
                Elf64_Sym *simbolos = (Elf64_Sym *)(mem + secoes[i].sh_offset);
                uint64_t total = secoes[i].sh_size / secoes[i].sh_entsize;
                const char *nomes = (const char *)(mem + secoes[secoes[i].sh_link].sh_offset);

                for (uint64_t s = 0; s < total; s++) {
                    const char *nome = nomes + simbolos[s].st_name;

                    if (str_eq(nome, "openat") == 0 ||
                        str_eq(nome, "read") == 0   ||
                        str_eq(nome, "write") == 0  ||
                        str_eq(nome, "mmap") == 0   ||
                        str_eq(nome, "socket") == 0) {

                        const uint32_t *codigo = (const uint32_t *)(mem + simbolos[s].st_value);
                        desmontar_funcao(nome, codigo, simbolos[s].st_value, simbolos[s].st_size);
                    }
                }
            }
        }
    }

    syscall6(215, base, tam, 0, 0, 0, 0);
    syscall6(57, fd, 0, 0, 0, 0, 0);
    syscall6(93, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
