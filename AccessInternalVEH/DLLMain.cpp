#include <windows.h>
#include <d3d9.h>
#include <Psapi.h>
#include <stdio.h>
#include <string>
#include <ctime>
#include <intrin.h>

#include "detours.h"
#pragma comment (lib, "detours.lib")

#include "xorstr.hpp"

#pragma intrinsic(_ReturnAddress)

typedef HRESULT(APIENTRY* EndScene_t)(IDirect3DDevice9*);
EndScene_t oEndScene = NULL;

typedef struct _CLIENT_ID {
	DWORD_PTR UniqueProcess;
	DWORD_PTR UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

CONST WCHAR* NewMutant = NULL;

DWORD myBase = NULL;
DWORD mySize = NULL;


void MakeJMP(BYTE* pAddress, DWORD dwJumpTo, DWORD dwLen)
{
	DWORD dwOldProtect, dwBkup, dwRelAddr;

	// give the paged memory read/write permissions

	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// calculate the distance between our address and our target location
	// and subtract the 5bytes, which is the size of the jmp
	// (0xE9 0xAA 0xBB 0xCC 0xDD) = 5 bytes

	dwRelAddr = (DWORD)(dwJumpTo - (DWORD)pAddress) - 5;

	// overwrite the byte at pAddress with the jmp opcode (0xE9)

	*pAddress = 0xE9;

	// overwrite the next 4 bytes (which is the size of a DWORD)
	// with the dwRelAddr

	*((DWORD*)(pAddress + 0x1)) = dwRelAddr;

	// overwrite the remaining bytes with the NOP opcode (0x90)
	// NOP opcode = No OPeration

	for (DWORD x = 0x5; x < dwLen; x++) *(pAddress + x) = 0x90;

	// restore the paged memory permissions saved in dwOldProtect

	VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);

	return;

}



DWORD GetSizeofImage(HMODULE hModule)
{
	if (!hModule) return NULL;
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(hModule);
	if (!pDosHeader) return NULL;
	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS((LONG)hModule + pDosHeader->e_lfanew);
	if (!pNTHeader) return NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;
	if (!pOptionalHeader) return NULL;
	return pOptionalHeader->SizeOfImage;
}

DWORD GetSizeofCode(HMODULE hModule)
{
	if (!hModule) return NULL;
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(hModule);
	if (!pDosHeader) return NULL;
	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS((LONG)hModule + pDosHeader->e_lfanew);
	if (!pNTHeader) return NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;
	if (!pOptionalHeader) return NULL;
	return pOptionalHeader->SizeOfCode;
}

BOOL DataCompare(BYTE* pData, BYTE* bMask, char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return FALSE;

	return (*szMask == NULL);
}



DWORD FindPattern(HMODULE hModule, DWORD dwLen, BYTE* bMask, char* szMask, DWORD offset = 0)
{
	DWORD dwAddress = (DWORD)hModule + 0x1000;

	if (dwLen == 0)
	{
		//MODULEINFO mi = { 0 };
		//GetModuleInformation(GetCurrentProcess(), (hModule ? hModule : GetModuleHandle(NULL)), &mi, sizeof(mi));

		dwLen = GetSizeofImage(hModule) - 0x1000;
	}

	for (DWORD i = 0; i < dwLen; i++)
	{
		if (IsBadReadPtr((void*)(dwAddress + i), 4) == 0 && DataCompare((BYTE*)(dwAddress + i), bMask, szMask))
		{
			return (DWORD)(dwAddress + i + offset);
		}
	}

	return 0;
}

extern "C"
__declspec(dllexport) int darkraycity() {

	//AddVectoredExceptionHandler(1ul, VectoredExceptionHandler);
	//initializeBreakpoint((PBYTE)0x00D0A4ED);
	return 0;
}




typedef HWND(WINAPI* GetFocus_t)(VOID);
GetFocus_t oGetFocus = NULL;




HWND GetFocus_Detour() {


	return (HWND)1234;
}




std::string GetRandomString(int n)
{
	char letters[26] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q',
	'r','s','t','u','v','w','x',
	'y','z' };
	std::string ran = "";
	for (int i = 0; i < n; i++)
		ran = ran + letters[rand() % 26];
	return ran;
}

const wchar_t* GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}



BOOL WINAPI DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hinstDLL);
		if (GetModuleHandle("d3d9.dll") && GetModuleHandle("bcrypt.dll")) {
			return FALSE;
		}
			
		while (!GetModuleHandle("user32.dll")) Sleep(100);

		srand(time(NULL));
		NewMutant = GetWC(GetRandomString(10).c_str());

		DWORD oldProtect = 0;

		VirtualProtect((PBYTE)&TerminateProcess, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy((PBYTE)&TerminateProcess, (PBYTE)"\xC3\x90", 2);
		VirtualProtect((PBYTE)&TerminateProcess, 2, oldProtect, &oldProtect);

		VirtualProtect((PBYTE)0x004C9499, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy((PBYTE)0x004C9499, (PBYTE)&NewMutant, 4);
		VirtualProtect((PBYTE)0x004C9499, 4, oldProtect, &oldProtect);

		myBase = (DWORD)GetModuleHandle(NULL);
		mySize = GetSizeofCode(NULL);

		oGetFocus = (GetFocus_t)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("user32.dll"), _xor_("GetFocus").c_str()), (PBYTE)GetFocus_Detour);

		MessageBox(NULL, _xor_("Cr.Leeza007 #MegaBangna#8654").c_str(), "OK", MB_OK);



	}
		break;

	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}