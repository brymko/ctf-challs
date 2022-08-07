#pragma once

#include <Windows.h>
#include <string>


class WndHook
{
private:
	WndHook() {}

	static LRESULT CALLBACK HookWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

public:
	WndHook(const WndHook&) = delete;
	WndHook operator=(const WndHook&) = delete;

	static WndHook* getInstance()
	{
		static WndHook ins;
		return &ins;
	}

	void init(HWND hWnd);
	void awaitKey(std::string& key);

private:
	bool isinit = false;
	WNDPROC oldWndProc;
	std::string text;
	HANDLE e{};
}; 
