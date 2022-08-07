#pragma once

#include <Windows.h>

class ProcessControl 
{
public:
	ProcessControl(HANDLE hProc) 
		: ProcessControl(hProc, 0)
	{}

	ProcessControl(DWORD pid)
		: ProcessControl(INVALID_HANDLE_VALUE, pid)
	{}

	ProcessControl(HANDLE hProc, DWORD pid)
		: hProc(hProc), pid(pid)
	{
		this->hProc = getHandle();
		if (this->isWoW64())
		{
			MessageBoxW(0, L"Unable to perfom validation... Please use on a 64 bit system!", L"Error", 0);
			ExitProcess(1);
		}
	}

	~ProcessControl() { CloseHandle(this->hProc); }
	
	template <typename T> BOOL rpm(size_t ptr, T& data) const;
	template <typename T> BOOL wpm(size_t ptr, T&& data) const;
	
	template <typename T> BOOL vpwpm(size_t ptr, T&& data) const;

	//bool triggerHooked__fnCOPYDATA(HWND hwnd, PVOID addr) const;
	HANDLE getHandle();
	DWORD getPid();
	BOOL isWoW64() const;
	void terminate() const;
	
private:
	constexpr static DWORD procAccess = PROCESS_ALL_ACCESS;//PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION;
	DWORD pid = 0;
	HANDLE hProc = INVALID_HANDLE_VALUE;
};

//
// Inlined Funcs
//

template<typename T>
inline BOOL ProcessControl::rpm(size_t ptr, T & data) const
{
	SIZE_T numread = 0;

	if (this->hProc == INVALID_HANDLE_VALUE) return false;
	BOOL ret = ReadProcessMemory(this->hProc, (LPCVOID)ptr, &data, sizeof(T), &numread);
	return ret && numread == sizeof(T);
}

template<typename T>
inline BOOL ProcessControl::wpm(size_t ptr, T && data) const
{
	SIZE_T numwrote = 0;
	if (this->hProc == INVALID_HANDLE_VALUE) return false;
	BOOL ret = WriteProcessMemory(this->hProc, (LPVOID)ptr, &data, sizeof(T), &numwrote);
 	return ret && numwrote == sizeof(T);
}

template<typename T>
inline BOOL ProcessControl::vpwpm(size_t ptr, T && data) const
{
	SIZE_T numwrote = 0;
	DWORD oldp = 0;
	if (this->hProc == INVALID_HANDLE_VALUE) return false;
	if (!VirtualProtectEx(this->hProc, (LPVOID)ptr, sizeof(T), PAGE_EXECUTE_READWRITE, &oldp)) return false;
	BOOL ret = WriteProcessMemory(this->hProc, (LPVOID)ptr, &data, sizeof(T), &numwrote);
	if (!VirtualProtectEx(this->hProc, (LPVOID)ptr, sizeof(T), oldp, &oldp)) return false;
	return ret && numwrote == sizeof(T);
}
