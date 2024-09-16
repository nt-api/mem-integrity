#include "win32api.h"
#include <windows.h>

int APIENTRY wWinMain(HINSTANCE hInstance,
                      HINSTANCE hPrevInstance,
                      LPTSTR lpCmdLine,
                      int nCmdShow)
{
	const std::wstring processName = L"lsass.exe";
	if (!set_debug_privilege())
	{
		MessageBoxA(nullptr, "Failed to enable debug privilege.", "Error", MB_OK | MB_ICONERROR);
		return 1;
	}

	const DWORD processId = get_process_id_by_name(processName);
	if (processId == 0)
	{
		MessageBoxA(nullptr, "Failed to find process.", "Error", MB_OK | MB_ICONERROR);
		return 1;
	}

	const HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess == nullptr)
	{
		MessageBoxA(nullptr, "Failed to open process for reading.", "Error", MB_OK | MB_ICONERROR);
		return 1;
	}

	const std::map<std::string, int> searchStrings = {
		{"skript.gg", 100},
		{".gg", 80},
		{"tzproject.com", 100},
		{"tzproject", 100},
		{"keyauth", 80}
	};

	if (!search_strings_in_memory(hProcess, searchStrings))
	{
		MessageBoxA(nullptr, "No suspicious strings found!", "Info", MB_OK | MB_ICONINFORMATION);
	}

	CloseHandle(hProcess);
	return 0;
}
