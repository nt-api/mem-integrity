#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <map>

static bool set_debug_privilege()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp{};

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		MessageBoxA(nullptr, "Failed to open process token.", "Error", MB_OK | MB_ICONERROR);
		return false;
	}

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
	{
		MessageBoxA(nullptr, "Failed to lookup privilege value.", "Error", MB_OK | MB_ICONERROR);
		CloseHandle(hToken);
		return false;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr))
	{
		MessageBoxA(nullptr, "Failed to adjust token privileges.", "Error", MB_OK | MB_ICONERROR);
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		MessageBoxA(nullptr, "The token does not have the specified privilege.", "Error", MB_OK | MB_ICONERROR);
		return false;
	}

	return true;
}

static DWORD get_process_id_by_name(const std::wstring& processName)
{
	const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(nullptr, "Failed to create snapshot of processes.", "Error", MB_OK | MB_ICONERROR);
		return 0;
	}

	PROCESSENTRY32W processEntry{};
	processEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &processEntry))
	{
		MessageBoxA(nullptr, "Failed to retrieve first process.", "Error", MB_OK | MB_ICONERROR);
		CloseHandle(hSnapshot);
		return 0;
	}

	do
	{
		if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0)
		{
			CloseHandle(hSnapshot);
			return processEntry.th32ProcessID;
		}
	}
	while (Process32NextW(hSnapshot, &processEntry));

	CloseHandle(hSnapshot);
	MessageBoxA(nullptr, "Process not found.", "Error", MB_OK | MB_ICONERROR);
	return 0;
}

static bool search_strings_in_memory(const HANDLE hProcess, const std::map<std::string, int>& searchStrings)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	MEMORY_BASIC_INFORMATION memInfo;
	const char* addr = nullptr;

	while (addr < sysInfo.lpMaximumApplicationAddress)
	{
		if (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
		{
			if (memInfo.State == MEM_COMMIT && (memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_READONLY))
			{
				std::vector<char> buffer(memInfo.RegionSize);
				SIZE_T bytesRead;

				if (addr != nullptr && ReadProcessMemory(hProcess, addr, buffer.data(), buffer.size(), &bytesRead))
				{
					for (const auto& searchPair : searchStrings)
					{
						const std::string& searchString = searchPair.first;
						const int percentage = searchPair.second;
						for (size_t i = 0; i < bytesRead - searchString.size(); ++i)
						{
							if (memcmp(buffer.data() + i, searchString.c_str(), searchString.size()) == 0)
							{
								const std::string message = "Found " + searchString + "! Indicator: " + std::to_string(
									percentage) + "%";
								MessageBoxA(nullptr, message.c_str(), "Result", MB_OK | MB_ICONINFORMATION);
								return true;
							}
						}
					}
				}
			}
		}
		addr += memInfo.RegionSize;
	}
	return false;
}

int main()
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
