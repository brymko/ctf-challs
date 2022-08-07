#include "WindowCtl.h"

void WindowCtl::getEditWindow()
{
	HWND hWnd = { 0 };


	EnumChildWindows(this->window, [](HWND hWnd, LPARAM lParam) -> BOOL {
		CHAR wndclass[0x100];
		HWND* phWnd = (HWND*)lParam;
		RealGetWindowClassA(hWnd, wndclass, 0x100);
		if (strcmp(wndclass, "Edit") == 0)
		{
			*phWnd = hWnd;
			return FALSE;
		}
		return TRUE;
	}, (LPARAM)&hWnd);

	this->window = hWnd;
}

HWND WindowCtl::getHwndFromPid(DWORD pid)
{
	struct ProcIdHWndPair {
		DWORD pid = { 0 };
		HWND hWnd = { 0 };
	} pair;

	pair.pid = pid;

	while (pair.hWnd == NULL)
	{
		EnumWindows([](HWND hWnd, LPARAM lparam)->BOOL {
			ProcIdHWndPair* pair = reinterpret_cast<ProcIdHWndPair*>(lparam);
			DWORD wpid = { 0 };

			GetWindowThreadProcessId(hWnd, &wpid);

			if (wpid == pair->pid)
			{
				pair->hWnd = hWnd;
			}

			return wpid != pair->pid;
		}, (LPARAM)&pair);

		Sleep(50);
	}
	return pair.hWnd;
}
