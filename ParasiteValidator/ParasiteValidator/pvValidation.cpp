#include "pvValidation.h"
#include <Windows.h>



bool PVValidator::isValid()
{
	return this->valid;
}

void PVValidator::VerfiyProductKey(const std::string & key)
{
	// flag{4_tr33_a_d4y_k33ps_th3_cO2_4w4y}
	this->valid = key == "C81477CEFC17B7241647696EDD01341E156B6C3073ACF9BD4413168AE5F04A062D7F75C508"; // key == "283BD153";
	SetEvent(this->waiter);
}

size_t PVValidator::getCM()
{
	return 0xe466334e;
}

bool PVValidator::waitForValidationRequest()
{
	WaitForSingleObject(this->waiter, INFINITE);
	ResetEvent(this->waiter);
	return true;
}

void PVValidator::init()
{
	this->waiter = CreateEvent(NULL, TRUE, FALSE, NULL);
}
