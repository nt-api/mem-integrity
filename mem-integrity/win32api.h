#ifndef WIN32_API_H
#define WIN32_API_H
#include <map>
#include <string>
#include <windows.h>

bool set_debug_privilege();
DWORD get_process_id_by_name(const std::wstring& processName);
bool search_strings_in_memory(const HANDLE hProcess, const std::map<std::string, int>& searchStrings);

#endif // WIN32_API_H
