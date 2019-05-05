// Debugger.cpp: implementation of the CDebugger class.
//
//////////////////////////////////////////////////////////////////////
#include "Debugger.h"
#include <concrt.h>
#include <winternl.h>

BOOL gs_bContinue = TRUE;

//////////////////////////////////////////////////////////////////////////

//声明函数指针，用于调试事件分发
typedef DWORD(CDebugger::*PFNDispatchEvent)(void);
//调试事件map容器
static map<DWORD, PFNDispatchEvent> gs_mapEventID_PFN;

//用于输入命令的分发
typedef BOOL(CDebugger::*PFNDispatchInput)(int argc, int pargv[], const char *pszBuf);
static map<const char *, PFNDispatchInput, Compare> gs_mapInput_PFN;


//制定规则：哪个命令应该由哪个func处理
void CDebugger::DispatchCommand()
{
	//存储事件ID以及对应的处理函数
#define DISPATCHEVENT(ID, pfn)  gs_mapEventID_PFN[ID] = pfn;	
		DISPATCHEVENT(EXCEPTION_DEBUG_EVENT, &CDebugger::OnExceptDispatch)				//异常事件分发
		DISPATCHEVENT(CREATE_THREAD_DEBUG_EVENT, &CDebugger::OnCreateThread)			//创建线程
		DISPATCHEVENT(CREATE_PROCESS_DEBUG_EVENT, &CDebugger::OnCreateProcess)			//创建进程
		DISPATCHEVENT(EXIT_THREAD_DEBUG_EVENT, &CDebugger::OnExitThread)				//退出线程
		DISPATCHEVENT(EXIT_PROCESS_DEBUG_EVENT, &CDebugger::OnExitProcess)				//退出进程
		DISPATCHEVENT(LOAD_DLL_DEBUG_EVENT, &CDebugger::OnLoadDLL)						//加载Dll
		DISPATCHEVENT(UNLOAD_DLL_DEBUG_EVENT, &CDebugger::OnUnLoadDLL)					//卸载Dll
		DISPATCHEVENT(OUTPUT_DEBUG_STRING_EVENT, &CDebugger::OnOutputDebugString)		//输出调试信息
		DISPATCHEVENT(EXCEPTION_ACCESS_VIOLATION, &CDebugger::OnAccessViolation)		//访问冲突
		DISPATCHEVENT(EXCEPTION_BREAKPOINT, &CDebugger::OnBreakPoint)					//断点
		DISPATCHEVENT(EXCEPTION_SINGLE_STEP, &CDebugger::OnSingleStep)					//单步

		//存储用户输入字符串以及对应的处理函数
#define DISPATCHINPUT(str, pfn)  gs_mapInput_PFN[str] = pfn;
		DISPATCHINPUT("bm", &CDebugger::DoBM)
		DISPATCHINPUT("bml", &CDebugger::DoBML)
		DISPATCHINPUT("bmpl", &CDebugger::DoBMPL)
		DISPATCHINPUT("bmc", &CDebugger::DoBMC)
		DISPATCHINPUT("bp", &CDebugger::DoBP);
		DISPATCHINPUT("bpl", &CDebugger::DoBPL);
		DISPATCHINPUT("bpc", &CDebugger::DoBPC);
		DISPATCHINPUT("t", &CDebugger::DoStepInto);
		DISPATCHINPUT("g", &CDebugger::DoGo);
		DISPATCHINPUT("r", &CDebugger::DoShowRegs);
		DISPATCHINPUT("bh", &CDebugger::DoBH);
		DISPATCHINPUT("bhl", &CDebugger::DoBHL);
		DISPATCHINPUT("bhc", &CDebugger::DoBHC);
		DISPATCHINPUT("p", &CDebugger::DoStepOver);
		DISPATCHINPUT("u", &CDebugger::DoShowASM);			//查看汇编代码
		DISPATCHINPUT("e", &CDebugger::DoModifyOpCode);			//修改op
		DISPATCHINPUT("d", &CDebugger::DoShowData);
		DISPATCHINPUT("?", &CDebugger::DoShowHelp);
		DISPATCHINPUT("help", &CDebugger::DoShowHelp);
		//DISPATCHINPUT("q",   &  CDebugger::Quit);
		DISPATCHINPUT("es", &CDebugger::DoExport);
		DISPATCHINPUT("ls", &CDebugger::DoImport);
		DISPATCHINPUT("log", &CDebugger::DoLog);
		DISPATCHINPUT("trace", &CDebugger::DoTrace);
		DISPATCHINPUT("vseh", &CDebugger::DoShowSEH);
		DISPATCHINPUT("mseh", &CDebugger::MonitorSEH);
		DISPATCHINPUT("modl", &CDebugger::DoListModule);
		DISPATCHINPUT("modi", &CDebugger::DoListModuleImport);
		DISPATCHINPUT("mode", &CDebugger::DoListModuleExport);
		DISPATCHINPUT("bptj", &CDebugger::DoBPtj);

		DISPATCHINPUT("dump", &CDebugger::DoDump);





}

bool CDebugger::injectDll(DWORD dwPid, HANDLE hProcess)
{

	char pszDllPath[MAX_PATH] = { "反PEB反调试Dll.dll" };

	bool	bRet = false;
	HANDLE	hRemoteThread = 0;
	LPVOID	pRemoteBuff = NULL;
	SIZE_T 	dwWrite = 0;
	DWORD	dwSize = 0;


	//1. 在远程进程上开辟内存空间
	pRemoteBuff = VirtualAllocEx(
		hProcess,
		NULL,
		64 * 1024,/*大小：64Kb*/
		MEM_COMMIT,/*预定并提交*/
		PAGE_EXECUTE_READWRITE/*可读可写可执行的属性*/
	);
	if (pRemoteBuff == NULL)
	{
		printf("在远程进程上开辟空降失败\n");
		goto _EXIT;
	}


	//2. 将DLL路径写入到新开的内存空间中
	dwSize = strlen(pszDllPath) + 1;
	WriteProcessMemory(
		hProcess,
		pRemoteBuff,/* 要写入的地址 */
		pszDllPath,	/* 要写入的内容的地址*/
		dwSize,		/* 写入的字节数 */
		&dwWrite	/* 输入：函数实际写入的字节数*/
	);

	if (dwWrite != dwSize)
	{
		printf("写入Dll路径失败\n");
		goto _EXIT;
	}


	//3. 创建远程线程
	//   远程线程创建成功后,DLL就会被加载,DLL被加载后DllMain函数
	//	 就会被执行,如果想要执行什么代码,就在DllMain中调用即可.

	hRemoteThread = CreateRemoteThread(
		hProcess,
		0, 0,
		(LPTHREAD_START_ROUTINE)LoadLibraryA,  /* 线程回调函数 */
		pRemoteBuff,							/* 回调函数参数 */
		0, 0);

	// 等待远程线程退出.
	// 退出了才释放远程进程的内存空间.
	WaitForSingleObject(hRemoteThread, -1);


	bRet = true;


_EXIT:
	// 释放远程进程的内存
	VirtualFreeEx(hProcess, pRemoteBuff, 0, MEM_RELEASE);
	// 关闭进程句柄
	CloseHandle(hProcess);

	return bRet;

}

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CDebugger::CDebugger()
{
	m_pDllEvent = NULL;
	m_pDllEvent = new CDllEvent;
	assert(m_pDllEvent != NULL);

	m_pProcessEvent = NULL;
	m_pProcessEvent = new CProcessEvent;
	assert(m_pProcessEvent != NULL);

	m_pExceptEvent = NULL;
	m_pExceptEvent = new CExceptEvent;
	assert(m_pExceptEvent != NULL);

	
	
	
	this->DispatchCommand();


}

CDebugger::~CDebugger()
{

}

//确保只有一个实例
CDebugger * CDebugger::CreateSystem(void)
{
	static CDebugger *pobj = new CDebugger;
	return pobj;
}

//删除对象
void CDebugger::DestorySystem(void)
{
	delete this;
}


/*调试主循环1) 打印选项2) 分发异常事件3) 用户操作4) 分发用户指令 */      
void CDebugger::Run(void)
{
	BOOL bRet = TRUE;
	char ch;
	while (true)
	{
		//显示主菜单
		m_pMenu->ShowMainMenu();
		//获取用户主菜单选择
		m_pMenu->GetCH(&ch);

		if (ch == '1')//调试进程
		{
			bRet = this->DebugNewProcess();
		}
		else if (ch == '2')//附加进程
		{
			bRet = this->DebugAttachedProcess();
		}
		else if (ch == '3')//显示帮助
		{
			bRet = this->DoShowHelp();
		}
		else if (ch == '0')	//退出
		{
			break;
		}
	}
}
HANDLE temp;
//调试进程
BOOL CDebugger::DebugNewProcess()
{
	BOOL bRet = TRUE;
	char szFilePath[MAX_PATH];

	//选择要调试的文件
	bRet = m_pMenu->SelectFile(szFilePath);
	if (!bRet)
	{
		return bRet;
	}


	//进程信息结构体对象
	PROCESS_INFORMATION pi = { 0 };
	//启动信息
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);

	//打开进程
	bRet = ::CreateProcess(NULL,
		szFilePath,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS| CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi);
	if (!bRet)//打开进程失败
	{
		CMENU::ShowErrorMessage();	//显示错误信息
		return FALSE;
	}


	strcpy_s(m_path, szFilePath);

	//反反调试
	//AntiPEBDebug( pi.hProcess);

	
	temp = pi.hProcess;

	//调试进程
	this->DebugProcess();

	return TRUE;
}

BOOL getSeDebugPrivilge()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	//获取SEDEBUG特权的LUID
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//获取这个进程的关机特权
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
		return false;

	return true;
}


//调试已经运行的进程(附加进程）                                                        
BOOL CDebugger::DebugAttachedProcess()
{
	m_pMenu->ShowInfo("Please Enter the PID:\r\n");
	//system("taskmgr");

	//获取pid
	int argc;
	int pargv[MAXBYTE];
	m_pMenu->GetInput(&argc, pargv, g_szBuf, MAXBUF);

// 	DWORD dwPID;
// 	scanf_s("%X", &dwPID);
	
 	DWORD dwPID = strtoul(g_szBuf, NULL, 10);
 	assert(dwPID != 0 && dwPID != ULONG_MAX);


	getSeDebugPrivilge();

	
	//DWORD dwPID = GetAttachPID();

	if (DebugActiveProcess(dwPID))//使调试器附加到一个活动进程并且调试它,成功返回值为非零值。
	{
		this->DebugProcess();
		return TRUE;
	}
	else {
		CMENU::ShowErrorMessage();	//显示错误信息
	}

	return FALSE;
}





//调试主循环 1) 显示主菜单 2）调试事件调度 3）与用户交互 4）用户输入调度                                                 
BOOL CDebugger::DebugProcess()
{
	//声明一个函数指针，返回类型：HANDLE，参数类型：DWORD, BOOL, DWORD
	typedef HANDLE(WINAPI *OPENTHREAD)(DWORD, BOOL, DWORD);

	//获取Kernel32,dll 中OpenThread地址，并将函数指针指向它
	OPENTHREAD pfnOpenThread = (OPENTHREAD)GetProcAddress(GetModuleHandle("Kernel32"), "OpenThread");
	assert(pfnOpenThread != NULL);	//失败则退出

									//用于接收用户输入
	int argc;			//接收的个数
	int pargv[MAXBYTE];	//接收的字符串数组指针

						//用于处理事件的分发
	map<DWORD, PFNDispatchEvent>::iterator itevt;//迭代器
	map<DWORD, PFNDispatchEvent>::iterator itevtend = gs_mapEventID_PFN.end();//指向末尾的迭代器
	PFNDispatchEvent pfnEvent = NULL;	//定义一个PFNDispatchEvent指针

										//用于处理输入指令的分发
	map<const char *, PFNDispatchInput, Compare>::iterator itinput;
	map<const char *, PFNDispatchInput, Compare>::iterator itinputend = gs_mapInput_PFN.end();
	PFNDispatchInput pfnInput = NULL;

	BOOL bRet = TRUE;
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;//默认设置为调试事件没有被处理




	while (gs_bContinue)
	{
		//等待调试事件
		bRet = ::WaitForDebugEvent(&m_debugEvent, INFINITE);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return FALSE;
		}

		dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;//默认设置为调试事件没有被处理
		m_bTalk = FALSE;//不允许用户输入

						//保存进程句柄
		m_hProcess = ::OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			m_debugEvent.dwProcessId
		);
		if (NULL == m_hProcess)
		{
			CMENU::ShowErrorMessage();
			return FALSE;
		}

		//AntiPEBDebug(m_hProcess);

		//保存线程句柄，函数指针指向OpenThread
		m_hThread = pfnOpenThread(
			THREAD_ALL_ACCESS,	//安全描述符
			FALSE,																//是否继承
			m_debugEvent.dwThreadId
		);
		if (NULL == m_hThread)
		{
			CMENU::ShowErrorMessage();
			return FALSE;
		}

		//保存进程上下文
		m_Context.ContextFlags = { CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS };
		bRet = ::GetThreadContext(m_hThread, &m_Context);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return FALSE;
		}


		//调试事件分发
		itevt = gs_mapEventID_PFN.find(m_debugEvent.dwDebugEventCode);
		if (itevt != itevtend)
		{
			pfnEvent = (*itevt).second;//函数指针为map中的第二个参数（value）
			dwContinueStatus = (this->*pfnEvent)();	//分发事件处理函数
		}

		//与用户进行交互
		while (m_bTalk)
		{
			m_pMenu->GetInput(&argc, pargv, g_szBuf, MAXBUF);

			//用户输入调度
			itinput = gs_mapInput_PFN.find(g_szBuf);//查找对应的命令
			if (itinput != itinputend)
			{
				pfnInput = (*itinput).second;
				(this->*pfnInput)(argc, pargv, g_szBuf);
			}
			else
			{
				m_pMenu->ShowInfo("Invalid Input\r\n");
			}
		}

		//恢复上下文，并关闭句柄     
		bRet = ::SetThreadContext(m_hThread, &m_Context);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return FALSE;
		}

		::SafeClose(m_hThread);
		::SafeClose(m_hProcess);

		::ContinueDebugEvent(
			m_debugEvent.dwProcessId,
			m_debugEvent.dwThreadId,
			dwContinueStatus);

	}

	return TRUE;
}

//分发异常事件                                                                   
DWORD CDebugger::OnExceptDispatch()
{
	map<DWORD, PFNDispatchEvent>::iterator it;
	map<DWORD, PFNDispatchEvent>::iterator itend = gs_mapEventID_PFN.end();
	PFNDispatchEvent pfnEvent = NULL;
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

	//分发
	it = gs_mapEventID_PFN.find(m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
	if (it != itend)
	{
		pfnEvent = (*it).second;
		dwContinueStatus = (this->*pfnEvent)();
	}

	return dwContinueStatus;
}

/************************************************************************
功能：所有这些用于事件分发，调度到不同的事件处理功能
1) Create(/Exit)Process(/Thread) --->CProcessEvent
2) Load(/Unload)Dll --> CDllEvent
3) DebugString --> CDllEvent
4) Exception (BreakPoint, AccessViolation, SingleStep) --> CExceptEvent*/
/************************************************************************/
DWORD CDebugger::OnCreateThread()
{
	return m_pProcessEvent->OnCreateThread(this);
}

DWORD CDebugger::OnCreateProcess()
{
	//AntiPEBDebug(temp);

	return m_pProcessEvent->OnCreateProcess(this);
}

DWORD CDebugger::OnExitThread()
{
	return m_pProcessEvent->OnExitThread(this);
}

DWORD CDebugger::OnExitProcess()
{
	return m_pProcessEvent->OnExitProcess(this);
}

DWORD CDebugger::OnLoadDLL()
{
	return m_pDllEvent->OnLoad(this);
}
DWORD CDebugger::OnUnLoadDLL()
{
	return m_pDllEvent->OnUnload(this);
}

DWORD CDebugger::OnOutputDebugString()
{
	return m_pDllEvent->OnOutputString(this);
}

//访问异常事件处理
DWORD CDebugger::OnAccessViolation()
{
	return m_pExceptEvent->OnAccessViolation(this);
}

DWORD CDebugger::OnBreakPoint()
{
	return m_pExceptEvent->OnBreakPoint(this);
}

DWORD CDebugger::OnSingleStep()
{
	return m_pExceptEvent->OnSingleStep(this);
}

/************************************************************************
功能：用户输入命令的分发
1) ShowASM, ShowData, ShowRegs --> CBaseEvent
2) others (BP, BPL, BPC, BM, BH .etc) ---> CExceptEvent
/************************************************************************/
BOOL CDebugger::DoShowASM(int argc, int pargv[], const char *pszBuf)
{
	//u [addr]
	m_bTalk = TRUE;
	return m_pExceptEvent->DoShowASM(this, argc, pargv, pszBuf);
}

BOOL CDebugger::DoModifyOpCode(int argc, int pargv[], const char * pszBuf)
{

	//e [addr]
	m_bTalk = TRUE;
	return m_pExceptEvent->DoModifyOpCode(this, argc, pargv, pszBuf);
}



BOOL CDebugger::DoShowData(int argc, int pargv[], const char *pszBuf)
{
	//d [addr]
	m_bTalk = TRUE;

	m_pExceptEvent->DoShowData(this, argc, pargv, pszBuf);
	return TRUE;
}

//显示调试信息
BOOL CDebugger::DoShowRegs(int argc, int pargv[], const char *pszBuf)
{
	//r
	m_bTalk = TRUE;
	m_pExceptEvent->DoShowRegs(this);
	return TRUE;
}

BOOL CDebugger::DoShowHelp(int argc/*=NULL*/, int pargv[]/*=NULL*/, const char *pszBuf/*=NULL*/)
{
	static char szBuf[1024];
	_snprintf_s(szBuf, 1024, 
		"-------------------帮助--------------------\r\n"
		"命令	 格式                  作用\r\n"
		"t       t                     步入\r\n"
		"p       p                     步过\r\n"
		"g       g [addr]              运行\r\n"
		"r       r                     查看寄存器\r\n"
		"u       u [addr]              查看汇编代码\r\n"
		"d       d [addr]              内存数据查看\r\n"
		"modl    modl                  查看模块信息\r\n"
		"modi    modi                  查看模块导入表\r\n"
		"mode    mode                  查看模块导出表\r\n"
		"bm      bm addr a|w|e len     内存断点设置\r\n"
		"bml     bml                   内存断点查看\r\n"
		"bmpl    bmpl                  分页内内存断点查看\r\n"
		"bmc     bmc id (from bml)     硬件断点删除\r\n"
		"bp      bp addr               一般断点设置\r\n"
		"bpl     bpl                   一般断点查看\r\n"
		"bpc     bpc id (from bpl)     一般断点删除\r\n"
		"bh      bh addr e|w|a 1|2|4   硬件断点设置\r\n"
		"bhl     bhl                   硬件断点查看\r\n"
		"bhc     bhc id (from bhl)     硬件断点删除\r\n"
		"help/?  help/?	               帮助\r\n"
	);

	/*_snprintf_s(szBuf, 1024,
		"----------------帮助-----------------\r\n"
		"命令	 格式                作用\r\n"
		"t		 t                   步入\r\n"
		"p		 p                   步过\r\n"
		"g		 g [addr]            运行\r\n"
		"r		 r                   寄存器查看\r\n"
		"u		 u [addr]            汇编查看\r\n"
		"d		 d [addr]            内存数据查看\r\n"
		"modl	 modl				 查看模块信息\r\n"
		"modi    modi				 查看模块导入表\r\n"
		"mode    mode				 查看模块导出表\r\n"
		"bm		 bm addr a|w len     内存断点设置\r\n"
		"bml	 bml                 内存断点查看\r\n"
		"bmpl	 bmpl                分页内内存断点查看\r\n"
		"bmc	 bmc id (from bml)   硬件断点删除\r\n"
		"bp		 bp addr             一般断点设置\r\n"
		"bpl	 bpl                 一般断点查看\r\n"
		"bpc	 bpc id (from bpl)   一般断点删除\r\n"
		"bh		 bh addr e|w|a 1|2|4 硬件断点设置\r\n"
		"bhl	 bhl                 硬件断点查看\r\n"
		"bhc	 bhc id (from bhl)   硬件断点删除\r\n"
		"log	 log                 记录所有\r\n"
		"vseh	 vseh                查看seh 链\r\n"
		"mseh	 mseh                对seh链的变化进行监控\r\n"
		"trace	 trace addrbegin addrend [dll1] [dll2]  对指定区间的代码进行trace\r\n"
		"help/?	 help/?                帮助\r\n"
	);*/

	m_pMenu->ShowInfo(szBuf);

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////

//单步步过
BOOL CDebugger::DoStepOver(int argc, int pargv[], const char *pszBuf)
{
	//p
	m_bTalk = FALSE;
	return m_pExceptEvent->DoStepOver(this/*, argc, pargv, pszBuf*/);
}

//单步步入
BOOL CDebugger::DoStepInto(int argc, int pargv[], const char *pszBuf)
{
	//t
	m_bUserTF = TRUE;
	m_bTalk = FALSE;
	return m_pExceptEvent->DoStepInto(this/*, argc, pargv, pszBuf*/);
}

BOOL CDebugger::DoGo(int argc, int pargv[], const char *pszBuf)
{
	//g [addr]
	m_bTalk = FALSE;
	//g_GoFlag = TRUE;
	return m_pExceptEvent->DoGo(this, argc, pargv, pszBuf);
}

BOOL CDebugger::DoBP(int argc, int pargv[], const char *pszBuf)
{
	//bp addr
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBP(this, argc, pargv, pszBuf);
}

BOOL CDebugger::DoBPL(int argc, int pargv[], const char *pszBuf)
{
	//bpl 
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBPL(this/*, argc, pargv, pszBuf*/);
}

BOOL CDebugger::DoBPC(int argc, int pargv[], const char *pszBuf)
{
	//bpc id
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBPC(this, argc, pargv, pszBuf);
}

//条件断点
BOOL CDebugger::DoBPtj(int argc, int pargv[], const char *pszBuf)
{
	//bptj exx >|=|< value
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBPtj(this, argc, pargv, pszBuf);
}

BOOL CDebugger::DoBM(int argc, int pargv[], const char *pszBuf)
{
	//bm addr a|w len
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBM(this, argc, pargv, pszBuf, FALSE);
}

BOOL CDebugger::DoBM(int argc, int pargv[], const char *pszBuf, BOOL bTrace)
{
	//this is used for debugger
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBM(this, argc, pargv, pszBuf, bTrace);
}

BOOL
CDebugger::DoBML(int argc, int pargv[], const char *pszBuf)
{
	//bml
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBML(this, argc, pargv, pszBuf);
}

BOOL
CDebugger::DoBMPL(int argc, int pargv[], const char *pszBuf)
{
	//bmpl
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBMPL(this, argc, pargv, pszBuf);
}

BOOL
CDebugger::DoBMC(int argc, int pargv[], const char *pszBuf)
{
	//bmc id
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBMC(this, argc, pargv, pszBuf);
}

BOOL
CDebugger::DoBH(int argc, int pargv[], const char *pszBuf)
{
	//bh addr a|w|e 1|2|4
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBH(this, argc, pargv, pszBuf);
}

BOOL
CDebugger::DoBHL(int argc, int pargv[], const char *pszBuf)
{
	//bhl
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBHL(this/*,argc, pargv, pszBuf*/);
}

BOOL
CDebugger::DoBHC(int argc, int pargv[], const char *pszBuf)
{
	//bhc id
	m_bTalk = TRUE;
	return m_pExceptEvent->DoBHC(this, argc, pargv, pszBuf);
}

BOOL CDebugger::Quit(int argc, int pargv[], const char *pszBuf)
{
	//尚未完成
	m_bTalk = FALSE;
	gs_bContinue = FALSE;
	return TRUE;
}

/************************************************************************/
/*
Function :将所有用户输入（在调试过程中）保存到文件中                                                                */
/************************************************************************/
BOOL
CDebugger::DoExport(int argc, int pargv[], const char *pszBuf)
{
	//export
	m_pMenu->ExportScript();
	return TRUE;
}

/************************************************************************/
/*
Function :加载保存的脚本（命令历史记录）并执行    */
/************************************************************************/
BOOL
CDebugger::DoImport(int argc, int pargv[], const char *pszBuf)
{
	//import
	m_pMenu->ImportScript();
	return TRUE;
}

/************************************************************************/
/*
Function :保存所有的操作，输出，无论你在屏幕上看到什么
及时归档                                       */
/************************************************************************/
BOOL CDebugger::DoLog(int argc, int pargv[], const char *pszBuf)
{
	//log
	m_bTalk = TRUE;
	m_pMenu->Log();
	return TRUE;
}

BOOL CDebugger::DoTrace(int argc, int pargv[], const char *pszBuf)
{
	//trace addrstart addrend [dll1] [dll2]
	m_bTalk = TRUE;
	m_bTrace = TRUE;
	m_pMenu->PreTrace();

	//针对指定区间的trace
	m_pExceptEvent->DoTrace(this, argc, pargv, pszBuf);

	//针对其他模块的trace
	if (3 == argc)
	{
		//不对其他模块进行trace
		this->m_bTraceAll = FALSE;
	}
	else
	{
		//排除掉这些模块进行trace
		this->m_bTraceAll = TRUE;
		m_pDllEvent->DoTrace(this, argc, pargv, pszBuf);
	}

	return TRUE;
}

BOOL
CDebugger::DoShowSEH(int argc, int pargv[], const char *pszBuf)
{
	//vseh
	m_bTalk = TRUE;
	return m_pExceptEvent->DoShowSEH(this, argc, pargv, pszBuf);
}

BOOL
CDebugger::MonitorSEH(int argc, int pargv[], const char *pszBuf)
{
	//调试器使用
	return m_pExceptEvent->MonitorSEH(this);
}

BOOL
CDebugger::ReadBuf(CBaseEvent *pEvent,
	HANDLE hProcess,
	LPVOID lpAddr,
	LPVOID lpBuf,
	SIZE_T nSize)
{
	return m_pExceptEvent->ReadBuf(pEvent, hProcess, lpAddr, lpBuf, nSize);
}

//查看模块
BOOL CDebugger::DoListModule(int argc, int pargv[], const char *pszBuf)
{
	return m_pDllEvent->DoListModule(this/*, argc, pargv, pszBuf*/);
}

//模块导入表
BOOL CDebugger::DoListModuleImport(int argc, int pargb[], const char * pszBuf)
{

	return m_pDllEvent->DoListModuleImport(this/*, argc, pargv, pszBuf*/);
}

//模块导出表
BOOL CDebugger::DoListModuleExport(int argc, int pargb[], const char * pszBuf)
{

	return m_pDllEvent->DoListModuleExport(this/*, argc, pargv, pszBuf*/);
}

BOOL CDebugger::RemoveTrace(tagModule *pModule)
{
	return m_pExceptEvent->RemoveTrace(this, pModule);
}

BOOL CDebugger::GetModule(CBaseEvent *pEvent, DWORD dwAddr, tagModule *pModule)
{
	return m_pDllEvent->GetModule(pEvent, dwAddr, pModule);
}



//#include <Winternl.h>
//传入被调试进程的句柄，内部修改PEB的值
void CDebugger::AntiPEBDebug(HANDLE hDebugProcess)
{

	typedef NTSTATUS(WINAPI*pfnNtQueryInformationProcess)
		(HANDLE ProcessHandle, ULONG ProcessInformationClass,
			PVOID ProcessInformation, UINT32 ProcessInformationLength,
			UINT32* ReturnLength);

	typedef struct _MY_PEB {               // Size: 0x1D8
		UCHAR           InheritedAddressSpace;
		UCHAR           ReadImageFileExecOptions;
		UCHAR           BeingDebugged;              //Debug运行标志
		UCHAR           SpareBool;
		HANDLE          Mutant;
		HINSTANCE       ImageBaseAddress;           //程序加载的基地址
		struct _PEB_LDR_DATA    *Ldr;                //Ptr32 _PEB_LDR_DATA
		struct _RTL_USER_PROCESS_PARAMETERS  *ProcessParameters;
		ULONG           SubSystemData;
		HANDLE         ProcessHeap;
		KSPIN_LOCK      FastPebLock;
		ULONG           FastPebLockRoutine;
		ULONG           FastPebUnlockRoutine;
		ULONG           EnvironmentUpdateCount;
		ULONG           KernelCallbackTable;
		LARGE_INTEGER   SystemReserved;
		struct _PEB_FREE_BLOCK  *FreeList;
		ULONG           TlsExpansionCounter;
		ULONG           TlsBitmap;
		LARGE_INTEGER   TlsBitmapBits;
		ULONG           ReadOnlySharedMemoryBase;
		ULONG           ReadOnlySharedMemoryHeap;
		ULONG           ReadOnlyStaticServerData;
		ULONG           AnsiCodePageData;
		ULONG           OemCodePageData;
		ULONG           UnicodeCaseTableData;
		ULONG           NumberOfProcessors;
		LARGE_INTEGER   NtGlobalFlag;               // Address of a local copy
		LARGE_INTEGER   CriticalSectionTimeout;
		ULONG           HeapSegmentReserve;
		ULONG           HeapSegmentCommit;
		ULONG           HeapDeCommitTotalFreeThreshold;
		ULONG           HeapDeCommitFreeBlockThreshold;
		ULONG           NumberOfHeaps;
		ULONG           MaximumNumberOfHeaps;
		ULONG           ProcessHeaps;
		ULONG           GdiSharedHandleTable;
		ULONG           ProcessStarterHelper;
		ULONG           GdiDCAttributeList;
		KSPIN_LOCK      LoaderLock;
		ULONG           OSMajorVersion;
		ULONG           OSMinorVersion;
		USHORT          OSBuildNumber;
		USHORT          OSCSDVersion;
		ULONG           OSPlatformId;
		ULONG           ImageSubsystem;
		ULONG           ImageSubsystemMajorVersion;
		ULONG           ImageSubsystemMinorVersion;
		ULONG           ImageProcessAffinityMask;
		ULONG           GdiHandleBuffer[0x22];
		ULONG           PostProcessInitRoutine;
		ULONG           TlsExpansionBitmap;
		UCHAR           TlsExpansionBitmapBits[0x80];
		ULONG           SessionId;
	} MY_PEB, *PMY_PEB;


	HMODULE NtdllModule = GetModuleHandle("ntdll.dll");
	pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION  pbi = { 0 };	//进程信息
	UINT32  ReturnLength = 0;
	DWORD	dwOldProtect;	//原内存页属性
	MY_PEB* Peb = (MY_PEB*)malloc(sizeof(MY_PEB));


	//检查状态 NTSTATUS>=0为成功，NTSTATUS<0为错误
	NTSTATUS Status = NtQueryInformationProcess(hDebugProcess, ProcessBasicInformation, &pbi, (UINT32)sizeof(pbi), (UINT32*)&ReturnLength);

	if (NT_SUCCESS(Status))
	{
		if (!ReadProcessMemory(hDebugProcess, (LPVOID)pbi.PebBaseAddress, Peb, sizeof(MY_PEB), NULL))
		{
			printf("要修改的内存地址无效\r\n");
			
			return;
		}

		Peb->BeingDebugged = 0;
		Peb->NtGlobalFlag.u.HighPart = 0;

		WriteProcessMemory(hDebugProcess, (LPVOID)pbi.PebBaseAddress, Peb, sizeof(MY_PEB), NULL);
		
	}
}





BOOL CDebugger::DoDump(int argc, int pargv[], const char *pszBuf)
{
	//dump [addr]
	m_bTalk = TRUE;

	//return m_pExceptEvent->dump(this, argc, pargv, pszBuf);


	
	//dump前不能有断点

	char* strPath = m_path;

	HANDLE hFile = this->m_hFileProcess;
	//CloseHandle(hFile);
	//HANDLE hFile = CreateFile(strPath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);




	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("创建文件失败,\n");
		printf("%s\n", GetLastError());
		return FALSE;
	}
	IMAGE_DOS_HEADER dos;//dos头

	IMAGE_NT_HEADERS nt;
	//读dos头
	if (ReadProcessMemory(this->m_hProcess, (LPVOID)this->m_dwBaseOfImage, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
	{
		return FALSE;
	}


	//读nt头
	if (ReadProcessMemory(this->m_hProcess, (BYTE *)this->m_dwBaseOfImage + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE)
	{
		return FALSE;
	}


	//读取节区并计算节区大小
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//读取节区
	if (ReadProcessMemory(this->m_hProcess,
		(BYTE *)this->m_dwBaseOfImage + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		Sections,
		secNum * sizeof(IMAGE_SECTION_HEADER),
		NULL) == FALSE)
	{
		return FALSE;
	}

	//计算所有节区的大小
	DWORD allsecSize = 0;
	DWORD maxSec;//最大的节区

	maxSec = 0;

	for (int i = 0; i < secNum; ++i)
	{
		allsecSize += Sections[i].SizeOfRawData;

	}

	//dos
	//nt
	//节区总大小
	DWORD topsize = secNum * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_NT_HEADERS) + dos.e_lfanew;

	//使头大小按照文件对齐
	if ((topsize&nt.OptionalHeader.FileAlignment) != topsize)
	{
		topsize &= nt.OptionalHeader.FileAlignment;
		topsize += nt.OptionalHeader.FileAlignment;
	}
	DWORD ftsize = topsize + allsecSize;
	//创建文件映射
	HANDLE hMap = CreateFileMapping(hFile,
		NULL, PAGE_READWRITE,
		0,
		ftsize,
		0);

	if (hMap == NULL)
	{
		DWORD er = GetLastError();
		printf("创建文件映射失败\n");
		return FALSE;
	}

	//创建视图
	LPVOID lpmem = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	if (lpmem == NULL)
	{
		delete[] Sections;
		CloseHandle(hMap);
		printf("创建视图失败\n");
		return FALSE;
	}
	PBYTE bpMem = (PBYTE)lpmem;
	memcpy(lpmem, &dos, sizeof(IMAGE_DOS_HEADER));
	//计算dossub 大小

	DWORD subSize = dos.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (ReadProcessMemory(this->m_hProcess, (BYTE *)this->m_dwBaseOfImage + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return FALSE;
	}

	nt.OptionalHeader.ImageBase = (DWORD)this->m_dwBaseOfImage;
	//保存NT头
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//保存节区
	memcpy(bpMem + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS), Sections, secNum * sizeof(IMAGE_SECTION_HEADER));

	for (int i = 0; i < secNum; ++i)
	{
		if (ReadProcessMemory(
			this->m_hProcess, (BYTE *)this->m_dwBaseOfImage + Sections[i].VirtualAddress,
			bpMem + Sections[i].PointerToRawData,
			Sections[i].SizeOfRawData,
			NULL) == FALSE)
		{
			delete[] Sections;
			CloseHandle(hMap);
			UnmapViewOfFile(lpmem);
			return FALSE;
		}
	}
	if (FlushViewOfFile(lpmem, 0) == false)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		printf("保存到文件失败\n");
		return FALSE;
	}
	delete[] Sections;
	CloseHandle(hMap);
	UnmapViewOfFile(lpmem);
	MessageBox(0, "ok", 0, 0);
	return TRUE;

}