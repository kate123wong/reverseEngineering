#include <Windows.h>
#include <stdio.h>
#include <versionhelpers.h>
#include "fheaders.h"
#include "auxiliary.h"


DWORD wmain(int argc, wchar_t* argv[])
{
	// argv ： argument value的缩写
	// 入口函数，wmain想比与main，支持unicode的参数
	PCWSTR pszLibFile = NULL;
	wchar_t *strProcName;
	DWORD dwProcessId = 0;
	DWORD dwTechnique = 0;

	if (argc != 5) // 应该有5个参数
	{
		displayHelp();
		return(0);
	}

	if (_wcsicmp(argv[1], TEXT("-t")) == 0)
	{
		strProcName = (wchar_t *)malloc((wcslen(argv[3]) + 1) * sizeof(wchar_t));
		strProcName = argv[3];

		pszLibFile = (wchar_t *)malloc((wcslen(argv[4]) + 1) * sizeof(wchar_t));
		pszLibFile = argv[4];

		dwProcessId = findPidByName(strProcName);//找到strProcName进程的IPD
		if (dwProcessId == 0)
		{
			// 没有找到相应的IPD，则报错
			wprintf(TEXT("[-] Error: Could not find PID (%d).\n"), dwProcessId);
			return(1);
		}

		SetSePrivilege(); // 提权，具有调试器的权限。
		
		switch (_wtoi(argv[2]))
		{
			// _wtoi : string 转换成int数据
		case 1:
			demoCreateRemoteThreadW(pszLibFile, dwProcessId);  // pszLibFile 和 目标进程id
			break;
		case 2:
			demoNtCreateThreadEx(pszLibFile, dwProcessId);
			break;
		case 3:
			demoQueueUserAPC(pszLibFile, dwProcessId);
			break;
		case 4:
			demoSetWindowsHookEx(pszLibFile, dwProcessId, strProcName);
			break;
		case 5:
			demoRtlCreateUserThread(pszLibFile, dwProcessId);
			break;
		case 6:
#ifdef _WIN64
			demoSuspendInjectResume64(pszLibFile, dwProcessId);
#else
			demoSuspendInjectResume(pszLibFile, dwProcessId);
#endif
			break;
		case 7:
			demoReflectiveDllInjection(pszLibFile, dwProcessId);
			break;
		default:
			displayHelp();
		}
	}
	else
		displayHelp();

	return(0);
}