#include "Debugger.h"

bool DebuggerEventPipe::waitForEvent(DWORD timeout)
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	BOOL ret = WaitForDebugEvent(&this->dbgevent, timeout);

	if (!ret)
	{
		return false;
	}

	switch (this->dbgevent.dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
		dwContinueStatus = this->OnExceptionEvent();
		break;

	case CREATE_THREAD_DEBUG_EVENT:
		dwContinueStatus = this->OnThreadCreation();
		break;

	case CREATE_PROCESS_DEBUG_EVENT:
		dwContinueStatus = this->OnProcessCreation();
		break;

	case EXIT_THREAD_DEBUG_EVENT:
		dwContinueStatus = this->OnThreadExit();
		break;

	case EXIT_PROCESS_DEBUG_EVENT:
		dwContinueStatus = this->OnProcessExit();
		break;

	case LOAD_DLL_DEBUG_EVENT:
		dwContinueStatus = this->OnDllLoad();
		break;

	case UNLOAD_DLL_DEBUG_EVENT:
		dwContinueStatus = this->OnDllUnload();
		break;

	case OUTPUT_DEBUG_STRING_EVENT:
		dwContinueStatus = this->OnDebugStringInformation();
		break;

	case RIP_EVENT:
		dwContinueStatus = this->OnRipEvent();
		break;
	}

	return ContinueDebugEvent(this->dbgevent.dwProcessId, this->dbgevent.dwThreadId, dwContinueStatus);
}

DWORD DebuggerEventPipe::OnExceptionEvent()
{
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnThreadCreation()
{
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnProcessCreation()
{
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnThreadExit()
{
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnProcessExit()
{
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnDllLoad()
{
	CloseHandle(this->dbgevent.u.LoadDll.hFile);
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnDllUnload()
{
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnDebugStringInformation()
{
	return DBG_CONTINUE;
}

DWORD DebuggerEventPipe::OnRipEvent()
{
	return DBG_CONTINUE;
}

const DEBUG_EVENT & DebuggerEventPipe::getDebugEvent() const
{
	return this->dbgevent;
}


