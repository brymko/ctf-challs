#include <Windows.h>
#include <functional>
#include <vector>
#include "ThreadSingleton.h"


class DebuggerEventPipe : public ThreadSingleton<DebuggerEventPipe>
{
public:
	bool waitForEvent(DWORD timeout);
	
protected:
	virtual DWORD OnExceptionEvent();
	virtual DWORD OnThreadCreation();
	virtual DWORD OnProcessCreation();
	virtual DWORD OnThreadExit();
	virtual DWORD OnProcessExit();
	virtual DWORD OnDllLoad();
	virtual DWORD OnDllUnload();
	virtual DWORD OnDebugStringInformation();
	virtual DWORD OnRipEvent();

	const DEBUG_EVENT& getDebugEvent() const;
private:
	DEBUG_EVENT dbgevent;
};