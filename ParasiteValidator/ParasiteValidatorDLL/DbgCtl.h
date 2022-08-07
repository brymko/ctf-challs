#pragma once

#include <Windows.h>

#include "../DebuggerCtlCodes.h"

extern "C" size_t __DebuggerCtl(const size_t ctl, ...);

class DbgCtl {
public:
	DbgCtl() {}
	
	size_t sendGeneric(const size_t len, const char* data) const
	{
		return __DebuggerCtl(DBGCTL_WRITE, len, data);
	}

	virtual size_t awaitCmd() const
	{
		return __DebuggerCtl(DBGCTL_AWAITCMD);
	}

	virtual size_t getCryptoMethod() const 
	{
		return __DebuggerCtl(DBGCTL_GETCM);
	}

	virtual size_t setValidState(size_t state) const
	{
		return __DebuggerCtl(DBGCTL_ISVALID, state);
	}
};
