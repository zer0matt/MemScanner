// Memory Scanner

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Include\cxxopts.hpp"


typedef unsigned char BYTE;

typedef struct {
    BYTE* bytes;
    size_t size;
} Pattern;

Pattern parsePattern(const std::string& input);
HANDLE openProcess(int pid);
void scanMemory(HANDLE hProcess, const Pattern& pattern);

int main(int argc, char **argv){
	printf("\nWelcome to my basic memory scanner\n");
	
	cxxopts::Options options("Memory Scanner", "Basic Memory Scanner for fun");
	options.add_options()
		("p,pid", "Target Process ID", cxxopts::value<int>())
    	("s,string", "Search for ASCII String Pattern (case sensitive)", cxxopts::value<std::vector<std::string>>())
    	("b,bytes",  "Search for HEX Pattern (e.g.: \"90 90 CC\")", cxxopts::value<std::vector<std::string>>())
    	("h,help", "Print help");
		
				
	auto result = options.parse(argc, argv);
	
	if (result.count("help") || !result.count("pid")) {
        std::cout << options.help() << std::endl;
        return 0;
    }
	
	if (result.count("string") && result.count("bytes")) {
	    std::cout << options.help() << std::endl;
	    return 1;
	}

	if (!result.count("string") && !result.count("bytes")) {
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

    CloseHandle(hProcess);
	return 0;
}

Pattern parsePattern(const std::string& input){
    Pattern p;
    p.bytes = nullptr;
    p.size = 0;

    
    std::vector<std::string> tokens;
    char* tmp = strdup(input.c_str());
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
            std::cerr << "Error: please provide a valid token'" << tokens[i] << "'\n";
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
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) { // Failed to get a handle
		printf("\nOpenProcess failed. GetLastError = %d\n", GetLastError());
		//system("pause");
		return NULL;
	}
	else {
		printf("\nOpenProcess succedeed with code: %d\n", GetLastError());
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
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if ((mbi.State == MEM_COMMIT) && 
                (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    // search for pattern
                    for (size_t i = 0; i + pattern.size <= bytesRead; i++) {
                        if (memcmp(buffer.data() + i, pattern.bytes, pattern.size) == 0) {
                        	printf("\nPattern found at address 0x%p with protection 0x%x\n", static_cast<void*>(addr + i), mbi.Protect);
                        	found = 1;
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        } else {
            addr += 0x1000; // fallback if VirtualQueryEx fails
        }
    }
    if(!found){
        printf("\nPattern not found\n");
	}
    system("pause");
}























































