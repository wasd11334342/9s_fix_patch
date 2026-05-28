#include <windows.h>
#include <iostream>

int main()
{
    const char* mapleDir = "C:\\Program Files\\gamania Games\\MapleStory";

    SetDllDirectoryA(mapleDir);
    HMODULE h = LoadLibraryA("C:\\Program Files\\gamania Games\\MapleStory\\dinput8.dll");

    if (!h)
    {
        DWORD err = GetLastError();
        std::cout << "Load failed, error = " << err << "\n";
        return 0;
    }

    std::cout << "DLL loaded\n";

    getchar();
}