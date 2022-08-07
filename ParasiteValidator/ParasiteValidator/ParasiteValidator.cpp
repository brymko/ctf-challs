#include <Windows.h>
#include "resource.h"
#include "pvDebugger.h"
#include "pvValidation.h"
#include "pvAntiDebug.h"
#include "WindowCtl.h"
#include <thread>


byte* GetInjDll(size_t& size)
{
	HRSRC hRse = FindResource(GetModuleHandle(0), MAKEINTRESOURCE(IDR_BINARY1), "D");
	HGLOBAL hFres = LoadResource(GetModuleHandle(0), hRse);
	size = SizeofResource(GetModuleHandle(0), hRse);
	return (byte*)hFres;
}

int main(int argc, char* argv[]);
int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	char filename[0x400] = { 0 };
	char* pseudoargv[] = { filename };
	GetModuleFileName(NULL, filename, 0x400);
	main(1, pseudoargv);
}

int main(int argc, char* argv[])
{
	FreeConsole();
	auto ad = PVAntiDebug::getInstance();
	auto dbg = PVDebugger::getInstance();
	auto val = PVValidator::getInstance();
	PROCESS_INFORMATION procinf = { 0 };
	STARTUPINFOW suinf = { 0 };
	WCHAR cmdline[1] = { 0 };
	HANDLE hToken = NULL;
	LUID luid = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			{
				ExitProcess(1);
			}
		}
	}

	if (!CreateProcessW(L"C:\\Windows\\system32\\notepad.exe", cmdline, NULL, NULL, FALSE, 0,  NULL, NULL, &suinf, &procinf))
	{
		return 1;
	}

	auto tDbg = std::thread([&]() -> void {
		size_t size = 0;
		ad->suppressDebugMessages();
		ad->hideFromDebugger();
		dbg->init(procinf.hProcess, procinf.dwProcessId);
		dbg->handleInitPhase();
		while (dbg->waitForEvent(INFINITE));
		dbg->setTerminated();
	});
	
	auto tVal = std::thread([&]() -> void {
		size_t size = 0;
		ad->hideFromDebugger();
		ad->suppressDebugMessages();
		auto wnd = WindowCtl(procinf.dwProcessId);
		if (!dbg->injectDllFromMemory(argv[0], GetInjDll(size), size))
		{
			ExitProcess(1);
		}
		wnd.sendText("Enter Key: ");
		wnd.sendEnableCapture();
		val->init();
		while(val->waitForValidationRequest()) {
			static int i = 0;
			if(i++ < 3)
			{
				if (val->isValid())
				{
					wnd.sendText("\nValid key, have fun with our awesome software\nLoading...");
					MessageBoxW(0, L"Success", L"", 0);
					dbg->setTerminated();
					ExitProcess(0);
					break;
				}
				else if (i != 3)
				{
					std::string msg = "\nInvalid key, ";
					msg += '0' + (3 - i);
					msg += " tries left\nEnter Key: ";
					wnd.sendText(msg);
					wnd.sendEnableCapture();
					continue;
				}
				else
					ExitProcess(1);
			}
			ExitProcess(1);
		}
			
		dbg->waitTermination();
	});

	tDbg.join();
	tVal.join();
	ExitProcess(0);
}