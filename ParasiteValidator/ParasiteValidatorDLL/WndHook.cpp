#include "WndHook.h"

LRESULT WndHook::HookWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	auto ins = WndHook::getInstance();

	do
	{
		if (uMsg == WM_CHAR)
		{

			if (wParam == '\b')
			{
				ins->text.erase(ins->text.length() - 1);
				break;
			}
			else if (wParam == '\r')
			{
				SetEvent(ins->e);
				break;
			}
			else
			{
				ins->text += (char)wParam;
			}
		}
	} while (false);

	//return ins->oldWndProc(hWnd, uMsg, wParam, lParam);
	return CallWindowProcA(ins->oldWndProc, hWnd, uMsg, wParam, lParam);
}

void WndHook::init(HWND hWnd)
{
	if (this->isinit) return;
	this->e = CreateEvent(NULL, TRUE, FALSE, NULL);
	this->oldWndProc = (WNDPROC)SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)HookWndProc);
	this->isinit = true;
}

void WndHook::awaitKey(std::string & key)
{
	WaitForSingleObject(this->e, INFINITE);
	ResetEvent(this->e);
	if(this->text.find("Key: ") != -1)
		key = this->text.substr(this->text.find("Key: ") + 5);
	else
		key = this->text;
	this->text.clear();
}
