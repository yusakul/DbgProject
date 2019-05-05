// DllEvent.cpp: implementation of the CDllEvent class.
//
//////////////////////////////////////////////////////////////////////

#include "DllEvent.h"
#include "Debugger.h"
#include "PE.H"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CDllEvent::CDllEvent()
{
	m_pLordPe = new CLordPe;
}

CDllEvent::~CDllEvent()
{

	delete m_pLordPe;
	m_pLordPe = NULL;
}

/*
typedef struct _LOAD_DLL_DEBUG_INFO {
HANDLE hFile;
LPVOID lpBaseOfDll;
DWORD  dwDebugInfoFileOffset;
DWORD  nDebugInfoSize;
LPVOID lpImageName;
WORD fUnicode;
} LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;
*/
DWORD CDllEvent::OnLoad(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
	tagModule module = { 0 };

	//检索模块名称和路径
	m_pMenu->ShowInfo("Dll Loaded: ");
	this->GetModuleInfo(pEvent, &module);

	if (module.hFile != NULL)
	{
		::SetImageBuf(module.hFile);
	}
	else
	{
		::LoadFile(module.szPath);
	}
	/*PE*/::GetModuleInfo(&module);

	//update loaded modules
	m_mapBase_Module[module.modBaseAddr] = module;

	//for every loaded dll, consider whether necessary to trace the instruction
	map<const char *, const char *, Compare>::iterator itName;
	if (pEvent->m_bTrace
		&& pEvent->m_bTraceAll)
	{
		//this module excluded from tracing
		itName = m_mapName_Module.find(module.szName);
		if (itName != m_mapName_Module.end())
		{
			return dwContinueStatus;
		}

		//set MemBP for this module's code range, for tracing
		int argv[] = { 0, 3, 0x0C, 0x0E };
		sprintf(g_szBuf, "bm %p a %d",
			module.dwBaseOfCode,
			module.dwSizeOfCode
		);
		((CDebugger *)pEvent)->DoBM(4, argv, g_szBuf, TRUE);
		((CDebugger *)pEvent)->m_bTalk = FALSE;       //no need to interact with the user
	}

	return dwContinueStatus;
}

DWORD CDllEvent::OnUnload(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

	UNLOAD_DLL_DEBUG_INFO unloadInfo = (UNLOAD_DLL_DEBUG_INFO)pEvent->m_debugEvent.u.UnloadDll;
	sprintf(g_szBuf, "Dll Unloaded: %p\r\n", unloadInfo.lpBaseOfDll);
	m_pMenu->ShowInfo(g_szBuf);

	//remove MemBP used for trace
	tagModule *pModule = &m_mapBase_Module[(DWORD)unloadInfo.lpBaseOfDll];
	if (pEvent->m_bTrace)
	{
		((CDebugger *)pEvent)->RemoveTrace(pModule);
		((CDebugger *)pEvent)->m_bTalk = FALSE;
	}

	//update modules
	m_mapBase_Module.erase((DWORD)unloadInfo.lpBaseOfDll);

	return dwContinueStatus;
}

DWORD CDllEvent::OnOutputString(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;


	OUTPUT_DEBUG_STRING_INFO outputInfo = (OUTPUT_DEBUG_STRING_INFO)pEvent->m_debugEvent.u.DebugString;
	DWORD nLen = outputInfo.nDebugStringLength;
	char *pstrBuf = NULL;
	char *pstrBufA = NULL;
	BOOL bRet;

	pstrBuf = new char[nLen];
	pstrBufA = new char[nLen + 32];
	if (NULL == pstrBuf
		|| NULL == pstrBufA)
	{
		CMENU::ShowErrorMessage();
		return dwContinueStatus;
	}

	bRet = ((CDebugger *)pEvent)->ReadBuf(pEvent,
		pEvent->m_hProcess,
		outputInfo.lpDebugStringData,
		pstrBuf,
		nLen);
	if (!bRet)
	{
		CMENU::ShowErrorMessage();
		return dwContinueStatus;
	}

	if (outputInfo.fUnicode)
	{
		sprintf(pstrBufA, "DebugString: %S\r\n", pstrBuf);
		m_pMenu->ShowInfo(pstrBufA);
	}
	else
	{
		m_pMenu->ShowInfo("DebugString: ");
		m_pMenu->ShowInfo(pstrBuf);
		m_pMenu->ShowInfo("\r\n");
	}

	if (pstrBuf != NULL)
	{
		delete[] pstrBuf;
		pstrBuf = NULL;
	}

	if (pstrBufA != NULL)
	{
		delete[] pstrBufA;
		pstrBufA = NULL;
	}

	return dwContinueStatus;
}

/************************************************************************/
/*
Function : try to get dll info (loaded base, module name, path etc)
Params   : pModule used to receive module info
Return   : TRUE if success, FALSE otherwise                                                             */
/************************************************************************/
BOOL CDllEvent::GetModuleInfo(CBaseEvent *pEvent, tagModule *pModule)
{
	assert(pEvent != NULL);
	assert(pModule != NULL);

	BOOL bRet;
	char szBuf[MAX_PATH * 2];
	char szBufA[MAX_PATH];      //for Unicode Convert
	DWORD ptrImageName;
	HANDLE hProcess = pEvent->m_hProcess;
	LOAD_DLL_DEBUG_INFO loadDllInfo = (LOAD_DLL_DEBUG_INFO)pEvent->m_debugEvent.u.LoadDll;
	if (NULL == hProcess
		|| NULL == loadDllInfo.lpImageName)
	{
		return FALSE;
	}

	//Debuggers must be prepared to handle the case where lpImageName is NULL
	//or *lpImageName (in the address space of the process being debugged) is NULL.
	bRet = ((CDebugger *)pEvent)->ReadBuf(pEvent,
		hProcess,
		loadDllInfo.lpImageName,
		&ptrImageName,
		sizeof(DWORD)
	);

	if (!bRet)
	{
		return FALSE;
	}

	bRet = ((CDebugger *)pEvent)->ReadBuf(pEvent,
		hProcess,
		(LPVOID)ptrImageName,
		szBuf,
		MAX_PATH * 2
	);

	if (!bRet)
	{
		sprintf(szBufA, "%p ", loadDllInfo.lpBaseOfDll);
		m_pMenu->ShowInfo(szBufA);
		CMENU::ShowErrorMessage();
		return FALSE;
	}

	if (loadDllInfo.fUnicode)
	{
		//module info set
		_snprintf(pModule->szPath, MAX_PATH, "%S", szBuf);

		_snprintf(szBufA, MAX_PATH, "%p %S\r\n", loadDllInfo.lpBaseOfDll, szBuf);
		m_pMenu->ShowInfo(szBufA);
	}
	else
	{
		//module info set
		_snprintf(pModule->szPath, MAX_PATH, "%s", szBuf);

		sprintf(szBufA, "%p ", loadDllInfo.lpBaseOfDll);
		m_pMenu->ShowInfo(szBufA);
		m_pMenu->ShowInfo(szBuf);
		m_pMenu->ShowInfo("\r\n");
	}

	//module info set
	pModule->modBaseAddr = (DWORD)loadDllInfo.lpBaseOfDll;
	pModule->hFile = loadDllInfo.hFile;

	//get module name
	char *pName = strrchr(pModule->szPath, '\\');
	if (NULL == pName)
	{
		strcpy(pModule->szName, pModule->szPath);
	}
	else
	{
		strcpy(pModule->szName, pName + 1);
	}

	return TRUE;
}

//列出模块的导入表
BOOL CDllEvent::DoListModuleImport(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/)
{
	//将文件读取进本程序内存，以便解析PE
	if (!m_pLordPe->GetDosHead(pEvent->m_path))
	{
		printf("%s\n", "将文件读取进内存失败！");
	}

	m_pLordPe->ImportTable();//解析导入表
	
	//输出导入表基本信息
	printf("----------------模块列表-----------------\n");
		printf("%-25s%-10s\t%-10s\t%-10s\t%-10s\n", "DLL名称", "INT RVA", "INT偏移", "IAT RVA", "IAT偏移");
	for (MY_IMPORT_DESCRIPTOR &importDescriptor : m_pLordPe->m_vecImportDescriptor)
	{
		printf("%-25s%08X\t%08X\t%08X\t%08X\n", importDescriptor.Name, importDescriptor.OriginalFirstThunk,
			importDescriptor.OffsetOriginalFirstThunk, importDescriptor.FirstThunk, importDescriptor.OffsetFirstThunk);
	}
	printf("请输入dll名查看详细信息：");
	WCHAR temp[MAX_PATH] = { 0 };
	wscanf_s(L"%s", temp, MAX_PATH);
	CString dllName = temp;
	int i = 0;//计数
	for (auto each : m_pLordPe->m_vecImportDescriptor)
	{
		if (each.Name == dllName)
		{
			break;
		}
		++i;
	}
	printf("-------------导入表-------------\n");
	printf("%-10s\t%-10s\n", "序号", "名称");
	for (auto& each : m_pLordPe->m_vvImportFunInfo[--i])
	{
		printf("%08X\t%s\n", each.Ordinal, each.Name);
	}
	return TRUE;
}

//列出模块导出表
BOOL CDllEvent::DoListModuleExport(CBaseEvent * pEvent)
{
	
	DoListModule(pEvent);
	printf("请输入dll名查看其导出表：");
	WCHAR temp[MAX_PATH] = { 0 };
	wscanf_s(L"%s", temp, MAX_PATH);
	CString dllName = temp;
	CString strModuleName;

	tagModule *pModule;
	map<DWORD, tagModule>::iterator it;
	for (it = m_mapBase_Module.begin();
		it != m_mapBase_Module.end();
		it++)
	{
		pModule = &it->second;
		if (pModule->szName == dllName)
		{
			strModuleName = pModule->szPath;
			break;
		}
	}

	m_pLordPe->GetDosHead(strModuleName);
	m_pLordPe->ExportTable();

	printf("名称：%s\n", m_pLordPe->m_my_im_ex_di.name);
	printf("序号基数：%08X\n", m_pLordPe->m_my_im_ex_di.Base);
	printf("函数数量：%08X\n", m_pLordPe->m_my_im_ex_di.NumberOfFunctions);
	printf("函数名数量%08X\n", m_pLordPe->m_my_im_ex_di.NumberOfNames);
	printf("地址表RVA%08X\n", m_pLordPe->m_my_im_ex_di.AddressOfFunctions);
	printf("名称表RVA%08X\n", m_pLordPe->m_my_im_ex_di.AddressOfNames);
	printf("序号表RVA%08X\n", m_pLordPe->m_my_im_ex_di.AddressOfNameOrdinals);

	printf("%-10s\t%-10s\t%-10s\t%-10s\n", "导出序号", "RVA", "偏移", "函数名");
	for (EXPORTFUNINFO &each : m_pLordPe->m_vecExportFunInfo)
	{
		printf("%08X\t%08X\t%08X\t%s\n", each.ExportOrdinals, each.FunctionRVA, each.FunctionOffset, each.FunctionName);
	}
	return 0;
}

/************************************************************************
列出调试对象中的所有加载模块                                                                 
/************************************************************************/
BOOL CDllEvent::DoListModule(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/)
{
	sprintf(g_szBuf, "-------------Module List-------------\r\n"
		"Range\t\t\tOEP\t\tPath\r\n");

	tagModule *pModule;
	map<DWORD, tagModule>::iterator it;
	for (it = m_mapBase_Module.begin();
		it != m_mapBase_Module.end();
		it++)
	{
		pModule = &it->second;
		_snprintf(g_szBuf, MAXBUF, "%s%p-%p\t%p\t%s\r\n"
			"%p-%p\r\n", //code range
			g_szBuf,
			pModule->modBaseAddr,
			pModule->modBaseAddr + pModule->modBaseSize,
			pModule->dwOEP,
			pModule->szPath,
			pModule->dwBaseOfCode,
			pModule->dwBaseOfCode + pModule->dwSizeOfCode);
	}

	//also include main app
	_snprintf(g_szBuf, MAXBUF, "%s%p-%p\t%p\t%s\r\n"
		"%p-%p\r\n",
		g_szBuf,
		pEvent->m_dwBaseOfImage,
		pEvent->m_dwBaseOfImage + pEvent->m_dwSizeOfImage,
		pEvent->m_dwOEP,
		"exe",
		pEvent->m_dwBaseOfCode,
		pEvent->m_dwBaseOfCode + pEvent->m_dwSizeOfCode);

	CMENU::ShowInfo(g_szBuf);
	return TRUE;
}

/************************************************************************/
/*
Function : set MemBP for the loaded module, used for tracing instruction

Params   : trace addrstart addrend  dll1 dll2 ...
argc     indicate the number of arguments
pargv[]  store the index for every arguments within pszBuf
dll1, dll2 are the modules to be exclude from tracing */
/************************************************************************/
BOOL
CDllEvent::DoTrace(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	//if just trace specified range
	if (!pEvent->m_bTraceAll)
	{
		return TRUE;
	}

	//those to be excluded
	//trace addrstart addrend dll1 dll2
	for (int i = 3; i < argc; i++)
	{
		m_mapName_Module[&pszBuf[pargv[i]]] = &pszBuf[pargv[i]];
	}

	int argv[] = { 0, 3, 0x0C, 0x0E };
	tagModule *pModule;

	map<const char *, const char *, Compare>::iterator itName;
	map<DWORD, tagModule>::iterator it;
	for (it = m_mapBase_Module.begin();
		it != m_mapBase_Module.end();
		it++)
	{
		pModule = &it->second;
		itName = m_mapName_Module.find(pModule->szName);
		if (itName != m_mapName_Module.end())
		{
			//this module is excluded from tracing
			continue;
		}

		sprintf(g_szBuf, "bm %p a %d",
			pModule->dwBaseOfCode,
			pModule->dwSizeOfCode);
		((CDebugger *)pEvent)->DoBM(4, argv, g_szBuf, TRUE);
	}
	return TRUE;
}

/************************************************************************/
/*
Function :模块地址
/************************************************************************/
BOOL
CDllEvent::GetModule(CBaseEvent *pEvent, DWORD dwAddr, tagModule *pModule)
{
	assert(pEvent != NULL);
	assert(pModule != NULL);

	map<DWORD, tagModule>::iterator it;
	for (it = m_mapBase_Module.begin();
		it != m_mapBase_Module.end();
		it++)
	{
		if (dwAddr >= it->second.modBaseAddr
			&& dwAddr < it->second.modBaseAddr + it->second.modBaseSize)
		{
			memcpy(pModule, &it->second, sizeof(tagModule));
			return TRUE;
		}
	}

	//now consider whether in the main app
	if (dwAddr >= pEvent->m_dwBaseOfImage
		&& dwAddr < pEvent->m_dwBaseOfImage + pEvent->m_dwSizeOfImage
		)
	{
		pModule->dwBaseOfCode = pEvent->m_dwBaseOfCode;
		pModule->dwSizeOfCode = pEvent->m_dwSizeOfCode;
		pModule->modBaseAddr = pEvent->m_dwBaseOfImage;
		pModule->modBaseSize = pEvent->m_dwSizeOfImage;
		pModule->hFile = pEvent->m_hFileProcess;
		strcpy(pModule->szName, "main.exe");    //we just didn't retrieve the debugee's name and path
		strcpy(pModule->szPath, "main.exe");
		return TRUE;
	}

	return FALSE;
}
