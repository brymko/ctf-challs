#include "pvDebugger.h"
#include "pvValidation.h"
#include <Psapi.h>

#include "../DebuggerCtlCodes.h"

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

void PVDebugger::init(HANDLE hProc, DWORD procid)
{
	this->pctl = std::make_unique<ProcessControl>(procid);
	DebugActiveProcess(procid);
	this->isrunning = CreateEvent(NULL, TRUE, FALSE, NULL);
}

void PVDebugger::setTerminated()
{
	SetEvent(this->isrunning);
	this->pctl->terminate();
}

void PVDebugger::waitTermination()
{
	WaitForSingleObject(this->isrunning, INFINITE);
}

void PVDebugger::handleInitPhase()
{
	while (this->waitForEvent(1000));
}

bool PVDebugger::injectDllFromMemory(const char* filename, byte* buf, size_t size) const
{
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)	
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

	NTSTATUS (NTAPI* NtCreateTransaction)(
		_Out_ PHANDLE TransactionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ LPGUID Uow,
		_In_opt_ HANDLE TmHandle,
		_In_opt_ ULONG CreateOptions,
		_In_opt_ ULONG IsolationLevel,
		_In_opt_ ULONG IsolationFlags,
		_In_opt_ PLARGE_INTEGER Timeout,
		_In_opt_ PUNICODE_STRING Description) = (decltype(NtCreateTransaction))GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtCreateTransaction");

	NTSTATUS (NTAPI* NtCreateSection)(
		_Out_ PHANDLE SectionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG SectionPageProtection,
		_In_ ULONG AllocationAttributes,
		_In_opt_ HANDLE FileHandle) = (decltype(NtCreateSection))GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtCreateSection");

	NTSTATUS(NTAPI* NtMapViewOfSection)(
		_In_ HANDLE SectionHandle,
		_In_ HANDLE ProcessHandle,
		_Inout_	PVOID *BaseAddress,
		_In_ ULONG_PTR ZeroBits,
		_In_ SIZE_T CommitSize,
		_Inout_opt_ PLARGE_INTEGER SectionOffset,
		_Inout_ PSIZE_T ViewSize,
		_In_ SECTION_INHERIT InheritDisposition,
		_In_ ULONG AllocationType,
		_In_ ULONG Win32Protec) = (decltype(NtMapViewOfSection))GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtMapViewOfSection");

	NTSTATUS(NTAPI* NtRollbackTransaction)(
		_In_ HANDLE TransactionHandle,
		_In_ BOOLEAN Wait) = (decltype(NtRollbackTransaction))GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtRollbackTransaction");

	NTSTATUS(NTAPI* NtClose)(
		_In_ HANDLE Handle) = (decltype(NtClose))GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtClose");
	
	const unsigned char key[] = { 0x13, 0x37, 0xC0, 0xDE, 0xBA, 0xBE, 0x04, 0x20, 0xFE, 0xED, 0xB0, 0x0B, 0xCA, 0xFE };
	NTSTATUS status;
	HANDLE hTransaction = NULL, hTransactedFile = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
	OBJECT_ATTRIBUTES obja;
	ULONG ReturnLength = 0;
	DWORD oldp;
	HANDLE hSection = NULL;
	const char* usedfile = "seed";

	do {
		if (!CopyFile(filename, usedfile, FALSE))
		{
			return false;
		}

		InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
		status = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &obja, NULL, NULL, 0, 0, 0, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			return false;
		}

		hTransactedFile = CreateFileTransactedA(usedfile, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
		if (hTransactedFile == INVALID_HANDLE_VALUE) {
			return false;
		}

		VirtualProtect(buf, size, PAGE_READWRITE, &oldp);

		for (size_t i = 0; i < size; ++i)
		{
			buf[i] ^= key[i % sizeof(key)];
		}

		VirtualProtect(buf, size, oldp, &oldp);

		if (!WriteFile(hTransactedFile, buf, size, &ReturnLength, NULL) || ReturnLength != size) {
			return false;
		}
		if(!FlushFileBuffers(hTransactedFile)) return false;

		status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTransactedFile);
		if (!NT_SUCCESS(status)) {
			return false;
		}

		PVOID map = 0;
		SIZE_T vsize = size;
		status = NtMapViewOfSection(hSection, this->pctl->getHandle(), &map, 0, 0, 0, &vsize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			return false;
		}

		//status = NtRollbackTransaction(hTransaction, TRUE);
		//if (!NT_SUCCESS(status)) {
		//	return false;
		//}

		NtClose(hTransaction);
		CloseHandle(hTransactedFile);
		NtClose(hSection);
		DeleteFile(usedfile);

		//auto nt = (IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)buf)->e_lfanew + (size_t)buf);
#error update this offset
		size_t entry = size_t(map) + 0x150C;
		HANDLE hTh = CreateRemoteThread(this->pctl->getHandle(), NULL, 0, (LPTHREAD_START_ROUTINE)entry, map, 0, NULL);
		WaitForSingleObject(hTh, INFINITE);
		//entry = (size_t)map;
	} while (false);
	return true;
}

ProcessControl * PVDebugger::getPctl()
{
	return this->pctl.get();
}

DWORD PVDebugger::OnDllLoad() 
{
	auto db = this->getDebugEvent();
	auto& dll = db.u.LoadDll;
	//size_t ptr = 0;
	//char str[0x50] = { 0 };
	//wchar_t wstr[0x50] = { 0 };


	//do {
	//	if (dll.lpImageName == NULL) break;
	//	if (!this->pctl->rpm((size_t)dll.lpImageName, ptr)) break;
	//	
	//	if (ptr == 0) break;

	//	if (dll.fUnicode) 
	//	{
	//		if (!this->pctl->rpm(ptr, wstr)) break;
	//	}
	//	else 
	//	{
	//		if (!this->pctl->rpm(ptr, str)) break;
	//	}

	//
	//	// choose to do what ever
	//	// APC injection with tid?
	//} while (false);

	CloseHandle(dll.hFile);
	return DBG_CONTINUE;
}

DWORD PVDebugger::OnExceptionEvent() 
{
	DWORD ret = DBG_CONTINUE;
	auto db = this->getDebugEvent();
	auto& exp = db.u.Exception;
	CONTEXT ctx = { 0 };
	std::string input;

	do
	{
		if (!exp.dwFirstChance || exp.ExceptionRecord.ExceptionFlags)
		{
			ret = DBG_TERMINATE_PROCESS;
			break; // well fuck
		}

		if (exp.ExceptionRecord.ExceptionCode != EXCEPTION_ACCESS_VIOLATION) break;

		auto elem = this->threadList.find(db.dwThreadId);
		if (elem == this->threadList.end()) break;
		auto th = elem->second;
		ctx.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(th, &ctx)) break;

		switch (ctx.Rcx)
		{ 
		case DBGCTL_WRITE: {
			auto addr = ctx.R8;
			char chr = 0;
			for (size_t i = 0; i < ctx.Rdx; ++i)
			{
				if (!this->pctl->rpm(addr + i, chr)) break;
				input += chr;
				chr = 0;
			}
				
			PVValidator::getInstance()->VerfiyProductKey(input);
			
			ret = DBG_EXCEPTION_HANDLED;
			break;
			}
		case DBGCTL_GETCM: {
			ctx.Rax = PVValidator::getInstance()->getCM();
			ret = DBG_EXCEPTION_HANDLED;
			break;
			}
		case DBGCTL_ISVALID: {
			ctx.Rax = PVValidator::getInstance()->isValid();
			ret = DBG_EXCEPTION_HANDLED;
			break;
			}
		}

		if(ret != DBG_EXCEPTION_HANDLED) break;
		
		ctx.Rbx = ctx.Rip;
		//if(!FlushInstructionCache(this->pctl->getHandle(), exp.ExceptionRecord.ExceptionAddress, 0x5)) break;
		if(!SetThreadContext(th, &ctx)) break;

		ret = DBG_EXCEPTION_HANDLED;
	} while (false);

	return ret;
}

DWORD PVDebugger::OnThreadCreation() 
{
	DWORD ret = DBG_CONTINUE;
	auto db = this->getDebugEvent();
	auto& tc = db.u.CreateThread;

	this->threadList.insert({ db.dwThreadId, tc.hThread });

	return ret;
}

DWORD PVDebugger::OnThreadExit() 
{
	DWORD ret = DBG_CONTINUE;
	auto db = this->getDebugEvent();

	this->threadList.erase(db.dwThreadId);
	return ret;
}

