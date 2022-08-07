#include "Debugger.h"
#include "Process.h"
#include <map>
#include <memory>

class PVDebugger : public DebuggerEventPipe
{
public:

	void init(HANDLE hProc, DWORD procid);

	inline static PVDebugger* getInstance()
	{
		thread_local static PVDebugger instance;
		return &instance;
	}

	void setTerminated();
	void waitTermination();
	void handleInitPhase();
	bool injectDllFromMemory(const char* filename, byte* buf, size_t size) const;
	ProcessControl* getPctl();

private:
	HANDLE isrunning = INVALID_HANDLE_VALUE;
	std::unique_ptr<ProcessControl> pctl{};
	std::map<DWORD, HANDLE> threadList{};

	virtual DWORD OnDllLoad();
	virtual DWORD OnExceptionEvent();
	virtual DWORD OnThreadCreation();
	virtual DWORD OnThreadExit();
};
