// ProcessEvent.cpp: implementation of the CProcessEvent class.
//
//////////////////////////////////////////////////////////////////////

#include "ProcessEvent.h"
#include "Debugger.h"
#include "PE.H"
#include <winternl.h>

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CProcessEvent::CProcessEvent()
{

}

CProcessEvent::~CProcessEvent()
{

}


/*
typedef struct _CREATE_PROCESS_DEBUG_INFO {
HANDLE hFile;
HANDLE hProcess;
HANDLE hThread;
LPVOID lpBaseOfImage;
DWORD dwDebugInfoFileOffset;
DWORD nDebugInfoSize;
LPVOID lpThreadLocalBase;
LPTHREAD_START_ROUTINE lpStartAddress;
LPVOID lpImageName;
WORD fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;
*/
DWORD CProcessEvent::OnCreateProcess(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

	CREATE_PROCESS_DEBUG_INFO processInfo = (CREATE_PROCESS_DEBUG_INFO)pEvent->m_debugEvent.u.CreateProcessInfo;

	//被调试进程信息
	tagModule module = { 0 };
	module.modBaseAddr = (DWORD)processInfo.lpBaseOfImage;
	::SetImageBuf(processInfo.hFile);
	::GetModuleInfo(&module);
	pEvent->m_dwBaseOfImage = (DWORD)processInfo.lpBaseOfImage;
	pEvent->m_dwSizeOfImage = module.modBaseSize;
	pEvent->m_dwBaseOfCode = module.dwBaseOfCode;
	pEvent->m_dwSizeOfCode = module.dwSizeOfCode;
	pEvent->m_hFileProcess = processInfo.hFile;
	pEvent->m_dwOEP = (DWORD)processInfo.lpStartAddress;
	


	_snprintf(g_szBuf, MAXBUF, "----------------Process Created-------\r\n"
		"OEP: %p ImageBase: %p  CodeRange: %p-%p\r\n\r\n",
		processInfo.lpStartAddress,
		processInfo.lpBaseOfImage,
		pEvent->m_dwBaseOfCode,
		pEvent->m_dwBaseOfCode + pEvent->m_dwSizeOfCode);
	pEvent->m_pMenu->ShowInfo(g_szBuf);

	//设置BP在OEP
	if (pEvent->m_dwOEP)
	{
		strcpy(g_szBuf, "bp");
		sprintf(&g_szBuf[3], "%p", processInfo.lpStartAddress);
		int argv[] = { 0, 3 };

		((CDebugger *)pEvent)->m_bTmpBP = TRUE;	//在OEP设置一个临时断点
		((CDebugger *)pEvent)->DoBP(2, argv, g_szBuf);
		pEvent->m_bTalk = FALSE;
	}

	//监视主线程 SEH
	//((CDebugger *)pEvent)->MonitorSEH(NULL, NULL, NULL);

	

	return dwContinueStatus;
}

/*
typedef struct _CREATE_THREAD_DEBUG_INFO {
HANDLE hThread;
LPVOID lpThreadLocalBase;
LPTHREAD_START_ROUTINE lpStartAddress;
} CREATE_THREAD_DEBUG_INFO, *LPCREATE_THREAD_DEBUG_INFO;
*/
DWORD CProcessEvent::OnCreateThread(const CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

	CREATE_THREAD_DEBUG_INFO threadInfo = (CREATE_THREAD_DEBUG_INFO)pEvent->m_debugEvent.u.CreateThread;

	_snprintf(g_szBuf, MAXBUF, "Thread Created-------\r\n"
		"ThreadProc: %p TLS: %p Handle: %p\r\n\r\n",
		threadInfo.lpStartAddress,
		threadInfo.lpThreadLocalBase,
		threadInfo.hThread);
	pEvent->m_pMenu->ShowInfo(g_szBuf);

/*
	//监控seh连锁
	((CDebugger *)pEvent)->MonitorSEH(NULL, NULL, NULL);*/

	return dwContinueStatus;
}

DWORD CProcessEvent::OnExitThread(const CBaseEvent *pEvent)
{
	assert(pEvent != NULL);
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
	sprintf(g_szBuf, "\r\nExitThread: ExitCode %p\r\n",
		pEvent->m_debugEvent.u.ExitThread.dwExitCode);
	m_pMenu->ShowInfo(g_szBuf);

	return dwContinueStatus;
}

DWORD CProcessEvent::OnExitProcess(const CBaseEvent *pEvent)
{
	assert(pEvent != NULL);
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
	sprintf(g_szBuf, "\r\nExitProcess: ExitCode %p\r\n",
		pEvent->m_debugEvent.u.ExitProcess.dwExitCode);
	m_pMenu->ShowInfo(g_szBuf);
	return dwContinueStatus;
}

