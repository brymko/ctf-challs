#pragma once

#include <Windows.h>
#include <string>

class WindowCtl
{
public:
	WindowCtl(HWND hwnd) : window(hwnd) {};
	WindowCtl(DWORD pid) : window(getHwndFromPid(pid)) {};
	virtual ~WindowCtl() {}
	
	void getEditWindow();

	HWND getHwnd() const { return window; }

private:
	HWND getHwndFromPid(DWORD pid);
	HWND window;
};
