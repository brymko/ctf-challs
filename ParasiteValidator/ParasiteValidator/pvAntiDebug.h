#pragma once


#include "ThreadSingleton.h"

class PVAntiDebug : public ThreadSingleton<PVAntiDebug> {
public:
	void suppressDebugMessages() const;
	void hideFromDebugger() const;
};
