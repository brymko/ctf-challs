#include "WindowCtl.h"

void WindowCtl::sendText(const std::string & str)
{
	for (auto& c : str)
	{
		this->sendChar(c);
	}
}

void WindowCtl::sendChar(char chr)
{
	constexpr LPARAM downf = 1;
	constexpr LPARAM charf = 1;
	constexpr LPARAM upf = 0xC0000000 | 1;
	struct KeyCodePair
	{
		char realchr;
		WPARAM keycode;
	} inpair;

	inpair.keycode = inpair.realchr = chr;

	if (this->window == NULL) return;

	if (chr >= 'a' && chr <= 'z')
	{
		inpair.keycode -= 0x20;
	}

	SendMessageA(this->window, WM_KEYDOWN, inpair.keycode, downf);
	SendMessageA(this->window, WM_CHAR, inpair.realchr, charf);
	SendMessageA(this->window, WM_KEYUP, inpair.keycode, upf);

	EnumChildWindows(this->window, [](HWND hWnd, LPARAM vKey) -> BOOL {
		constexpr LPARAM downf = 1;
		constexpr LPARAM charf = 1;
		constexpr LPARAM upf = 0xC0000000 | 1;

		auto inpair = (KeyCodePair*)vKey;

		SendMessageA(hWnd, WM_KEYDOWN, inpair->keycode, downf);
		SendMessageA(hWnd, WM_CHAR, inpair->realchr, charf);
		SendMessageA(hWnd, WM_KEYUP, inpair->keycode, upf);
		return TRUE;
	}, (LPARAM)&inpair);
}

void WindowCtl::sendEnableCapture()
{
	SendMessageA(this->window, WM_USER, 0, 0);
	EnumChildWindows(this->window, [](HWND hWnd, LPARAM unused) -> BOOL {
		SendMessageA(hWnd, WM_USER, 0, 0);
		return TRUE;
	}, (LPARAM)&SendMessageA);
}

HWND WindowCtl::getHWND()
{
	return this->window;
}

HWND WindowCtl::getHwndFromPid(DWORD pid)
{
	struct ProcIdHWndPair {
		DWORD pid = { 0 };
		HWND hWnd = { 0 };
	} pair;

	pair.pid = pid;


	while (pair.hWnd == NULL) {
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
