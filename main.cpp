#include <windows.h>
#include <psapi.h>
#include <set>
#include <fstream>
#pragma comment( lib, "psapi.lib" )
#pragma comment( lib, "advapi32.lib" )


#define CRASH(var) { std::ofstream outFile("log.txt", std::ios_base::out|std::ios_base::trunc); outFile<<"\nCrashed "<<"var"; outFile.close(); return 13; }

int main()
{
  //debug privelege
  {
    HANDLE hToken;
    if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, FALSE, &hToken))
      {
        if(GetLastError() == ERROR_NO_TOKEN)
          {
            if(!ImpersonateSelf(SecurityImpersonation)) CRASH(1);
            if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) CRASH(2);
          }
      }
    else CRASH(4);
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;
    DWORD cb=sizeof(TOKEN_PRIVILEGES);
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) CRASH(4);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, cb, NULL, NULL);
    if (GetLastError() != ERROR_SUCCESS) CRASH(5);
    CloseHandle(hToken);
  }

  DWORD processes[1024];
  std::set<DWORD> set_processes, set_processes_next;
  for(;;)
    {
      DWORD proc_n;
      if(!EnumProcesses(processes, sizeof(processes), &proc_n)) CRASH(6);

      for(unsigned int i=0; i<proc_n/sizeof(DWORD); ++i)
        {
          set_processes_next.insert(processes[i]);
          if(processes[i] && set_processes.find(processes[i])!=set_processes.end())
            {
              const HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_SET_INFORMATION, FALSE, processes[i]);
              DWORD mask1, mask2;
              if(GetProcessAffinityMask(processHandle, &mask1, &mask2) && mask1 != 13) SetProcessAffinityMask(processHandle, 13);
              CloseHandle(processHandle);
            }
        }

      set_processes.clear();
      set_processes.swap(set_processes_next);
      Sleep(500);
    }
  return 0;
}
