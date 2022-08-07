#pragma once

#include <Windows.h>
#include <string>


class WindowCtl
{
public:
	WindowCtl(HWND hwnd) : window(hwnd) {};
	WindowCtl(DWORD pid) : window(getHwndFromPid(pid)) {};
	virtual ~WindowCtl() {}

	void sendText(const std::string& str);
	void sendChar(char chr);
	void sendEnableCapture();
	HWND getHWND();
private:
	HWND getHwndFromPid(DWORD pid);

	HWND window;
};
