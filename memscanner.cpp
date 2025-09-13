// memory_scanner.cpp
// Versione aggiornata: ricerca per pattern e ricerca per protezione memoria
// Compila con Visual Studio (cl) o MinGW (g++) su Windows

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include "Include\cxxopts.hpp"

typedef unsigned char BYTE;

typedef struct {
    BYTE* bytes;
    size_t size;
} Pattern;

Pattern parsePattern(const std::string& input);
HANDLE openProcess(int pid);
void scanMemory(HANDLE hProcess, const Pattern& pattern);
DWORD parseProtectionString(const std::string& s);
void scanProtection(HANDLE hProcess, DWORD protection, bool exactMatch = false);

int main(int argc, char **argv){
    printf("\nWelcome to my basic memory scanner\n");

    cxxopts::Options options("Memory Scanner", "Basic Memory Scanner for fun");
    options.add_options()
        ("p,pid", "Target Process ID", cxxopts::value<int>())
        ("s,string", "Search for ASCII String Pattern (case sensitive)", cxxopts::value<std::vector<std::string>>())
        ("b,bytes",  "Search for HEX Pattern (e.g.: \"90 90 CC\")", cxxopts::value<std::vector<std::string>>())
        ("q,query", "Search for memory areas with a specific memory protection value (e.g.: r, rw, rwx, 0x04, ecc...)", cxxopts::value<std::string>())
        ("exact", "Require exact protection match (default: contains)", cxxopts::value<bool>()->default_value("false"))
        ("h,help", "Print help");

    auto result = options.parse(argc, argv);

    if (result.count("help") || !result.count("pid")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    if ((result.count("string") + result.count("bytes") + result.count("query")) > 1) {
        std::cout << "Use only one of -s, -b or -q at a time" << std::endl;
        std::cout << options.help() << std::endl;
        return 1;
    }

    if (!result.count("string") && !result.count("bytes") && !result.count("query")) {
        std::cout << options.help() << std::endl;
        return 1;
    }

    int pid = result["pid"].as<int>();
    HANDLE hProcess = openProcess(pid);
    if(hProcess == NULL){
        return EXIT_FAILURE;
    }

    // ASCII Patterns
    if (result.count("string")) {
        auto inputs = result["string"].as<std::vector<std::string>>();
        for (auto& s : inputs) {
            Pattern p;
            p.size = s.size();
            p.bytes = (BYTE*)malloc(p.size);
            memcpy(p.bytes, s.c_str(), p.size);

            scanMemory(hProcess, p);
            free(p.bytes);
        }
    }

    // HEX Patterns
    if (result.count("bytes")) {
        auto inputs = result["bytes"].as<std::vector<std::string>>();
        for (auto& s : inputs) {
            Pattern p = parsePattern(s);
            scanMemory(hProcess, p);
            free(p.bytes);
        }
    }

    if (result.count("query")) {
        std::string q = result["query"].as<std::string>();
        DWORD protection = parseProtectionString(q);
        if (protection == 0) {
            std::cerr << "Unable to parse protection '" << q << "'. Try r, rw, rwx, noaccess or 0x04\n";
        } else {
            bool exact = false;
            if (result.count("exact")) exact = result["exact"].as<bool>();
            scanProtection(hProcess, protection, exact);
        }
    }

    CloseHandle(hProcess);
    return 0;
}

Pattern parsePattern(const std::string& input){
    Pattern p;
    p.bytes = nullptr;
    p.size = 0;

    std::vector<std::string> tokens;
    char* tmp = _strdup(input.c_str());
    char* token = strtok(tmp, " ");
    while (token) {
        tokens.push_back(token);
        token = strtok(nullptr, " ");
    }

    p.size = tokens.size();
    p.bytes = (BYTE*)malloc(p.size);
    if (!p.bytes) {
        std::cerr << "Malloc error\n";
        free(tmp);
        exit(1);
    }

    for (size_t i = 0; i < tokens.size(); i++) {
        char* end;
        unsigned long val = strtoul(tokens[i].c_str(), &end, 16);
        if (*end != '\0') {
            std::cerr << "Error: please provide a valid token '" << tokens[i] << "'\n";
            free(tmp);
            free(p.bytes);
            exit(1);
        }
        p.bytes[i] = (BYTE)val;
    }

    free(tmp);
    return p;
}

HANDLE openProcess(int pid){
    // Open with the minimum required rights for reading memory and querying info
    DWORD desired = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    HANDLE hProcess = OpenProcess(desired, FALSE, pid);
    if (hProcess == NULL) { // Failed to get a handle
        printf("\nOpenProcess failed. GetLastError = %d\n", GetLastError());
        return NULL;
    } else {
        printf("\nOpenProcess succeeded (pid=%d)\n", pid);
    }
    return hProcess;
}

void scanMemory(HANDLE hProcess, const Pattern& pattern){
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = 0;
    int found = 0;
    while (addr < (unsigned char*)sysInfo.lpMaximumApplicationAddress) {
        SIZE_T vq = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));
        if (vq == 0) {
            addr += sysInfo.dwPageSize;
            continue;
        }

        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_EXECUTE))) {
            // read in chunks to avoid huge allocations for very large regions
            SIZE_T regionSize = mbi.RegionSize;
            unsigned char* baseAddr = (unsigned char*)mbi.BaseAddress;
            const SIZE_T CHUNK = 0x1000 * 64; // 256 KB chunks
            SIZE_T offset = 0;
            while (offset < regionSize) {
                SIZE_T toRead = (regionSize - offset > CHUNK) ? CHUNK : regionSize - offset;
                std::vector<BYTE> buffer(toRead);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, baseAddr + offset, buffer.data(), toRead, &bytesRead) && bytesRead > 0) {
                    for (size_t i = 0; i + pattern.size <= bytesRead; i++) {
                        if (memcmp(buffer.data() + i, pattern.bytes, pattern.size) == 0) {
                            printf("\nPattern found at address 0x%p with protection 0x%x\n", static_cast<void*>(baseAddr + offset + i), mbi.Protect);
                            found = 1;
                        }
                    }
                }
                offset += toRead;
            }
        }

        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
    if(!found){
        printf("\nPattern not found\n");
    }
    system("pause");
}

DWORD parseProtectionString(const std::string& s) {
    std::string str = s;
    // trim
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char ch){ return !std::isspace(ch); }));
    str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch){ return !std::isspace(ch); }).base(), str.end());
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c){ return std::tolower(c); });

    // Hex like 0x04
    if (str.size() > 2 && str.rfind("0x", 0) == 0) {
        try {
            return static_cast<DWORD>(std::stoul(str, nullptr, 16));
        } catch (...) { return 0; }
    }

    // Decimal number
    if (!str.empty() && std::all_of(str.begin(), str.end(), [](char c){ return std::isdigit((unsigned char)c); })) {
        try {
            return static_cast<DWORD>(std::stoul(str, nullptr, 10));
        } catch (...) { return 0; }
    }

    // mnemonics
    if (str == "noaccess" || str == "na" || str == "n") return PAGE_NOACCESS;           // 0x01
    if (str == "r" || str == "read" || str == "readonly") return PAGE_READONLY;        // 0x02
    if (str == "rw" || str == "readwrite") return PAGE_READWRITE;                     // 0x04
    if (str == "w" || str == "writecopy") return PAGE_WRITECOPY;                      // 0x08
    if (str == "x" || str == "exec") return PAGE_EXECUTE;                             // 0x10
    if (str == "rx" || str == "readexec" || str == "rexec") return PAGE_EXECUTE_READ; // 0x20
    if (str == "rwx" || str == "rw+x" || str == "rexecreadwrite") return PAGE_EXECUTE_READWRITE; // 0x40
    if (str == "xw" || str == "wx" || str == "exewritecopy") return PAGE_EXECUTE_WRITECOPY; // 0x80

    // fallback: interpret "rwx" as EXECUTE_READWRITE
    if (str == "rwx") return PAGE_EXECUTE_READWRITE;

    return 0;
}

void scanProtection(HANDLE hProcess, DWORD protection, bool exactMatch){
    if (protection == 0) {
        printf("Protection value 0 (invalid) passed to scanProtection\n");
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = 0;
    bool foundAny = false;

    const DWORD PROTECTION_BASE_MASK = 0xFF; // low byte holds base protection flags

    while (addr < (unsigned char*)sysInfo.lpMaximumApplicationAddress) {
        SIZE_T result = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));
        if (result == 0) {
            addr += sysInfo.dwPageSize;
            continue;
        }

        if (mbi.State == MEM_COMMIT) {
            DWORD baseProtect = mbi.Protect & PROTECTION_BASE_MASK;

            bool match = false;
            if (exactMatch) {
                match = (baseProtect == protection);
            } else {
                match = ((baseProtect & protection) == protection);
            }

            if (match) {
                printf("Region: base=0x%p size=0x%llx protect=0x%x (base=0x%x) state=0x%x\n",
                       mbi.BaseAddress,
                       (unsigned long long)mbi.RegionSize,
                       mbi.Protect,
                       baseProtect,
                       mbi.State);
                foundAny = true;
            }
        }

        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!foundAny) {
        printf("No regions matched the requested protection.\n");
    }

    system("pause");
}
