#pragma once

#include "singleton.h"
#include <string>
#include <vector>
#include <Windows.h>
#include <functional>

class PVValidator : public Singleton<PVValidator>
{
public:
	bool isValid();
	void VerfiyProductKey(const std::string& content);
	size_t getCM();
	bool waitForValidationRequest();
	void init();
private:
	bool valid = false;
	HANDLE waiter = INVALID_HANDLE_VALUE;
};
