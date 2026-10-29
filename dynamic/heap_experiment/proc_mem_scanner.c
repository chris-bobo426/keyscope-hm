/**
 * dynamic/heap_experiment/proc_mem_scanner.c
 * 鸿钥卫士 KeyScope-HM v3.0 —— 基于 Win32 VirtualQueryEx + ReadProcessMemory 的进程虚拟内存物理扫描器
 *
 * 作用：
 * 作为独立外部进程挂载目标 Node.js/V8 进程 (PID)，直接读取其所有可读写的私有虚拟内存页 (MEM_PRIVATE / PAGE_READWRITE)，
 * 同时支持检索：
 *   1. 原始 16 字节二进制密钥序列 (Raw 16-byte binary key in ArrayBuffer/Uint8Array backing store)
 *   2. 托管字符串字节序列 (ASCII/UTF-8 String in V8 Heap)
 * 从而以完全对称的物理观测原语同时验证：
 *   - 阴性基线 (Baseline): 0/10
 *   - 阳性正控 (Positive Control — 未调用 fill(0) 的 Uint8Array 原始字节): 10/10
 *   - 风险组 (Risky String — 转为 String 后置 null，不使用 Symbol.for): 10/10
 *   - 安全组 (Safe Buffer — Uint8Array 使用后立即调用 .fill(0)): 0/10
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATTERNS 64
#define MAX_PAT_LEN  64

typedef struct {
    char id[32];
    uint8_t bytes[MAX_PAT_LEN];
    size_t len;
    int hit_count;
} PatternItem;

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t slen = strlen(hex);
    if (slen % 2 != 0 || slen / 2 > max_len) return -1;
    size_t blen = slen / 2;
    for (size_t i = 0; i < blen; i++) {
        unsigned int val = 0;
        if (sscanf(hex + 2 * i, "%02x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    return (int)blen;
}

static void scan_buffer(const uint8_t *buf, size_t buf_len, PatternItem *items, int num_items) {
    for (int p = 0; p < num_items; p++) {
        size_t plen = items[p].len;
        if (plen == 0 || buf_len < plen) continue;
        const uint8_t first = items[p].bytes[0];
        const uint8_t * pat = items[p].bytes;
        size_t limit = buf_len - plen;
        for (size_t i = 0; i <= limit; i++) {
            if (buf[i] == first && memcmp(buf + i, pat, plen) == 0) {
                items[p].hit_count++;
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <patterns_file>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    const char *pat_file = argv[2];

    FILE *fp = fopen(pat_file, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open pattern file: %s\n", pat_file);
        return 1;
    }

    PatternItem items[MAX_PATTERNS];
    int num_items = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp) && num_items < MAX_PATTERNS) {
        char id[32] = {0};
        char hex[140] = {0};
        if (sscanf(line, "%31s %139s", id, hex) == 2) {
            strncpy(items[num_items].id, id, sizeof(items[num_items].id) - 1);
            int blen = hex_to_bytes(hex, items[num_items].bytes, MAX_PAT_LEN);
            if (blen > 0) {
                items[num_items].len = (size_t)blen;
                items[num_items].hit_count = 0;
                num_items++;
            }
        }
    }
    fclose(fp);

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "OpenProcess failed for PID %lu (err=%lu)\n", (unsigned long)pid, (unsigned long)GetLastError());
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = 0;
    size_t total_scanned_bytes = 0;
    size_t regions_scanned = 0;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        int is_rw = (mbi.State == MEM_COMMIT) &&
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                    ((mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) || (mbi.Protect & PAGE_EXECUTE_READWRITE)) &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    !(mbi.Protect & PAGE_NOACCESS);

        if (is_rw && mbi.RegionSize > 0 && mbi.RegionSize <= (128ULL * 1024 * 1024)) {
            uint8_t *chunk = (uint8_t *)malloc(mbi.RegionSize);
            if (chunk) {
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProc, mbi.BaseAddress, chunk, mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                    scan_buffer(chunk, bytesRead, items, num_items);
                    total_scanned_bytes += bytesRead;
                    regions_scanned++;
                }
                free(chunk);
            }
        }
        uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    CloseHandle(hProc);

    printf("{\"pid\":%lu,\"regionsScanned\":%llu,\"bytesScanned\":%llu,\"hits\":{",
           (unsigned long)pid,
           (unsigned long long)regions_scanned,
           (unsigned long long)total_scanned_bytes);
    for (int i = 0; i < num_items; i++) {
        printf("\"%s\":%d%s", items[i].id, items[i].hit_count, (i + 1 < num_items) ? "," : "");
    }
    printf("}}\n");
    return 0;
}
