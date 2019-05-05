

#include "ExceptEvent.h"
#include "Debugger.h"
#include "PE.H"
#include <winternl.h>

#define  MAX_INSTRUCTION    1    //只是用来设置保护 //15
#define  SYSSPACE           0x70000000  //系统空间


static const unsigned char gs_BP = 0xCC;
static char gs_szCodeBuf[64];	
static char gs_szOpcode[64];		//存储机器码
static char gs_szASM[128];			//存储汇编代码
static char gs_szBuf[128];			//用于各种临时缓存

CExceptEvent::CExceptEvent()
{
	//获取页面大小
	SYSTEM_INFO  sysInfo;
	GetSystemInfo(&sysInfo);
	m_dwPageSize = sysInfo.dwPageSize;

	m_szLastASM[0] = '\0';
}

CExceptEvent::~CExceptEvent()
{
	map<char *, char *, Compare>::iterator it;
	for (it = m_mapModule_Export.begin();
		it != m_mapModule_Export.end();
		it++)
	{
		if (it->second != NULL)
		{
			free(it->second);
			it->second = NULL;
		}
	}
}

/************************************************************************/
/*
功能：检查dw地址是否命中内存断点
Params：dwAddr：要检查的地址
ppageBP包含dwAddr所在的PageBP信息
返回：如果命中，则为TRUE
否则，返回FALSE
* /
/************************************************************************/
BOOL
CExceptEvent::CheckHitMemBP(CBaseEvent *pEvent, DWORD dwAddr, tagPageBP *ppageBP)
{
	assert(ppageBP != NULL);
	assert(pEvent != NULL);
	DWORD dwOffset = dwAddr - ppageBP->dwPageAddr;	//相对地址页起始地址偏移
	BOOL bRet = FALSE;
	BOOL bTraced = FALSE;  //只追踪一次

	g_szBuf[0] = '\0';

	const char *pszASM;
	tagMemBPInPage *pmemBPInPage = NULL;
	list<tagMemBPInPage>::iterator it;
	for (it = ppageBP->lstMemBP.begin();
		it != ppageBP->lstMemBP.end();
		it++)
	{
		
		pmemBPInPage = &(*it);
		if (dwOffset >= pmemBPInPage->wOffset			//当前地址偏移大于等于断点的偏移
			&& dwOffset < pmemBPInPage->wOffset			//当前地址偏移小于（断点的偏移+断点长度）
			+ pmemBPInPage->wSize						//满足以上才命中内存断点
			)
		{
			//如果用于追踪，并且尚未追踪
			if (pmemBPInPage->bTrace
				&& !bTraced)
			{
				//需要记录该指令，只能追踪
				bTraced = TRUE;

				pszASM = this->GetOneASM(pEvent/*,dwAddr*/);
				if (0 == strcmp(pszASM, m_szLastASM))
				{
					//避免重复，如repxxx
					continue;
				}

				//prefetch until call, jxx or ret (For System Code)            
				if (pEvent->m_bTrace
					&& dwAddr > SYSSPACE)
				{
					PrefetchCode(pEvent);
				}
				else
				{
					//对于用户代码，我们只需逐一进行追踪
					strcpy_s(m_szLastASM, pszASM);
					pEvent->m_pMenu->TraceLog(pszASM);
				}

				continue;
			}

			bRet = TRUE;
			_snprintf_s(g_szBuf, MAXBUF, "%sPage: %p Offset: %04X Size: %04X\r\n",
				g_szBuf,
				ppageBP->dwPageAddr,
				pmemBPInPage->wOffset,
				pmemBPInPage->wSize
			);
		}
	}

	if (bRet)
	{
		pEvent->m_pMenu->ShowInfo(g_szBuf);
	}

	return bRet;
}

/************************************************************************/
/*
Function : 处理访问冲突事件
1）页面中是否存在内存断点
2）如果是，则恢复保护
设置单步改回                                                               */
/************************************************************************/
DWORD
CExceptEvent::OnAccessViolation(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

	//获取当前异常地址
	EXCEPTION_DEBUG_INFO exceptInfo = pEvent->m_debugEvent.u.Exception;
	EXCEPTION_RECORD exceptRecord = exceptInfo.ExceptionRecord;
	DWORD dwAddr = exceptRecord.ExceptionInformation[1];

	//是否存在内存断点
	tagPageBP *ppageBP = NULL;		//断点内存结构
	DWORD dwOldProtect;				//原内存页属性
	BOOL bRet = HasMemBP(pEvent, dwAddr, &ppageBP);
	if (bRet)
	{
		//需要恢复保护，（并添加PAGE READWRITE属性）
		//恢复预读取
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwAddr,
			MAX_INSTRUCTION,
			ppageBP->dwOldProtect,
			&dwOldProtect
		);

		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return DBG_CONTINUE;    
		}

		//判断是否命中内存断点
		bRet = CheckHitMemBP(pEvent, dwAddr, ppageBP);
		if (bRet)
		{
			_snprintf(g_szBuf, MAXBUF, "Hit MemBP %p %s***********\r\n\r\n",
				dwAddr,
				0 == exceptRecord.ExceptionInformation[0] ? "read" : "write"
			);

			pEvent->m_pMenu->ShowInfo(g_szBuf);
			DoShowRegs(pEvent);
			pEvent->m_bTalk = TRUE;
		}

		//如果追踪，则不需要恢复保护
		if (pEvent->m_bTrace
			&& dwAddr > SYSSPACE)
		{
			return DBG_CONTINUE;
		}

		//用户代码的恢复
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwAddr,
			MAX_INSTRUCTION,
			ppageBP->dwOldProtect,
			&dwOldProtect
		);

		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return DBG_CONTINUE;    //really?
		}

		//需要设置单步恢复保护
		m_bAccessVioTF = TRUE;
		m_dwAddr = dwAddr;
		DoStepInto(pEvent/*, 1, argv, g_szBuf*/);
		return DBG_CONTINUE;
	}


	return dwContinueStatus;
}


void AntiPEBDebug(HANDLE hDebugProcess)
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



/************************************************************************/
/*
Function :处理断点事件
Process  : 1) 是否系统BP
2) 是否由普通断点（永久或临时）引起，
3）int 3上的普通断点
4）用于跟踪+预读取                                                      */
/************************************************************************/
DWORD CExceptEvent::OnBreakPoint(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

	//系统断点
	static BOOL bSysPoint = TRUE;
	if (bSysPoint)
	{
		bSysPoint = FALSE;
		pEvent->m_bTalk = TRUE;
		DoShowRegs(pEvent);

		AntiPEBDebug(pEvent->m_hProcess);

		return DBG_CONTINUE;
	}



	EXCEPTION_DEBUG_INFO exceptInfo = pEvent->m_debugEvent.u.Exception;
	EXCEPTION_RECORD exceptRecord = exceptInfo.ExceptionRecord;
	DWORD dwFirstChance = pEvent->m_debugEvent.u.Exception.dwFirstChance;
	DWORD dwAddr = (DWORD)exceptRecord.ExceptionAddress;

	BOOL flag = FALSE;
	if (pEvent->m_bTJBPTF)	//判断是否有条件
	{
		for (auto&index : m_vecTJBP)
		{
			if (index.dwAddr == dwAddr)
			{
				if (CheckHitTJBP(pEvent, dwAddr) == TRUE)//满足条件
				{
					pEvent->m_bTJBPTF = FALSE;
					flag = TRUE;
					goto NORMAL;
				}
				else
				{
					tagNormalBP *pNormalBP = NULL;
					BOOL bRet = HasNormalBP(pEvent, dwAddr, &pNormalBP);
					bRet = WriteProcessMemory(pEvent->m_hProcess,
						(LPVOID)dwAddr,
						(LPVOID)&pNormalBP->oldvalue,
						sizeof(gs_BP),
						NULL);
					if (!bRet)
					{
						CMENU::ShowErrorMessage();
					}

					//设置单步重新设置普通BP  bptj 4117d0 eax = 2
					m_bNormalBPTF = TRUE;
					m_dwAddr = dwAddr;
					DoStepInto(pEvent);	//回复数据	
					m_mapAddr_NormBP.erase(dwAddr);
					pEvent->m_Context.Eip--;

					return DBG_CONTINUE;
				}
			}

		}

	}


NORMAL:
	tagNormalBP *pNormalBP = NULL;
	//是否是普通断点
	BOOL bRet = HasNormalBP(pEvent, dwAddr, &pNormalBP);
	if (bRet)
	{
		//是普通断点
		assert(pNormalBP != NULL);

		//在int 3上设置的普通断点
		if (pNormalBP->bDisabled)
		{
			goto NORMALBP_ON_INT3;
		}

		//是否在int 3上设置普通断点
		if (gs_BP == pNormalBP->oldvalue)	//原数据是否等于CC
		{
			if (dwAddr == pEvent->m_Context.Eip)
			{
				goto NORMALBP_ON_INT3;
			}

			//禁用普通断点
			pNormalBP->bDisabled = TRUE;

			//不需要恢复字节，直接返回
			pEvent->m_Context.Eip--;
			pEvent->m_bTalk = TRUE;
			DoShowRegs(pEvent);
			return DBG_CONTINUE;
		}

		//恢复代码
		bRet = WriteProcessMemory(pEvent->m_hProcess,
			(LPVOID)dwAddr,
			(LPVOID)&pNormalBP->oldvalue,
			sizeof(gs_BP),
			NULL);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
		}

		if (pNormalBP->bPerment)
		{
			//设置单步重新设置普通BP
			if(1)
			{
				m_bNormalBPTF = FALSE;
				m_dwAddr = dwAddr;
				DoStepInto(pEvent);
			}
// 			else
// 			{
// 				m_bNormalBPTF = TRUE;
// 				m_dwAddr = dwAddr;
// 				DoStepInto(pEvent);
// 			}
		}
		else
		{
			m_mapAddr_NormBP.erase(dwAddr);

			//用于追踪
			if (pEvent->m_bTrace)
			{
				//设置PAGE NOACCESS
				m_bTraceTF = TRUE;
				m_dwAddr = dwAddr;
				DoStepInto(pEvent);
				pEvent->m_Context.Eip--;
				return DBG_CONTINUE;
			}
		}

		pEvent->m_Context.Eip--;
		pEvent->m_bTalk = TRUE;
		DoShowRegs(pEvent);

		return DBG_CONTINUE;
	}

NORMALBP_ON_INT3:
	//普通BP设置在int 3上
	if (dwFirstChance)
	{
		pEvent->m_pMenu->ShowInfo("\r\nBreakPoint First Chance*********\r\n");

		if (pNormalBP != NULL
			&& pNormalBP->bDisabled)
		{
			//re-enable
			pNormalBP->bDisabled = FALSE;
		}
	}
	else
	{
		pEvent->m_pMenu->ShowInfo("\r\nBreakPoint Second Chance*********\r\n");
		//dwContinueStatus = DBG_CONTINUE;  //can we ?
	}
	DoShowRegs(pEvent);

	return dwContinueStatus;
}

//检查是否命中硬件断点
//硬件执行断点被断下后，此时需要暂时取消掉该硬件执行断点（否则程序一直被断在这里，跑不下去）。并设置单步，在下一次单步中重设该硬件执行断点。
BOOL CExceptEvent::HasHitHWBP(CBaseEvent *pEvent)
{


	//是否设置DR6 B0〜B3
	DWORD dwIndex = 0;
	//B0-B3全部为0，则没有硬件断点
	dwIndex = (pEvent->m_Context.Dr6 & 0x0F);


	if (0 == dwIndex)
	{
		return FALSE;
	}



	//是否单步产生的命中断点
	tagDR6 *pDR6 = (tagDR6 *)(&pEvent->m_Context.Dr6);
	if (pDR6->BS)
	{
		return FALSE;
	}

	//是否需要与用户交互
	pEvent->m_bTalk = TRUE;

	//BO~B3 可能会设置多个
	tagHWBP hwBP;
	hwBP.pDRAddr[0] = &pEvent->m_Context.Dr0;
	hwBP.pDRAddr[1] = &pEvent->m_Context.Dr1;
	hwBP.pDRAddr[2] = &pEvent->m_Context.Dr2;
	hwBP.pDRAddr[3] = &pEvent->m_Context.Dr3;

	
	DWORD dwDR7;
	DWORD dwLENRW;
	DWORD i;
	DWORD dwB03 = 0;        //B0~B3
	DWORD dwCheck = 1;      //检查BX已设置
	while (dwCheck != 16)   //1,2,4,8
	{
		if (0 == (dwIndex & dwCheck))
		{
			dwB03++;
			dwCheck <<= 1;
			continue;
		}

		dwDR7 = pEvent->m_Context.Dr7;
		dwLENRW = dwDR7 >> 16;
		for (i = 0; i < dwB03; i++)
		{
			dwLENRW >>= 4;
		}

		hwBP.dwAddr = *(hwBP.pDRAddr[dwB03]);
		hwBP.dwType = dwLENRW & 0x3;
		dwLENRW >>= 2;
		hwBP.dwLen = (dwLENRW & 0x03) + 1;
		dwLENRW >>= 2;

		
		if (HWBP_EXECUTE == hwBP.dwType)
		{
			//执行断点
			hwBP.dwLen = 0;
		}

		sprintf_s(g_szBuf, MAXBUF, "\rHit HardBP: %p\t%d\t%s *****************\r\n",
			hwBP.dwAddr,
			hwBP.dwLen,
			(HWBP_EXECUTE == hwBP.dwType) ? STREXECUTE :
			((HWBP_WRITE == hwBP.dwType) ? STRWRITE : STRACCESS)
		);
		pEvent->m_pMenu->ShowInfo(g_szBuf);

		//禁用HWBP，并在单步内重新启用
		if (HWBP_EXECUTE == hwBP.dwType)
		{
			int argv[] = { 0, 4 };
			sprintf_s(g_szBuf, MAXBUF, "bhc %d", dwB03);
			DoBHC(pEvent, 2, argv, g_szBuf);

			m_bHWBPTF = TRUE;
			m_dwAddr = hwBP.dwAddr;
			DoStepInto(pEvent);
		}

		//清除DR6
		pEvent->m_Context.Dr6 = 0;

// 		//如果改变FS：[0]，SEH Chain，则不需要与用户交互
// 		if (hwBP.dwAddr > 0x7F000000)
// 		{
// 			((CDebugger *)pEvent)->DoShowSEH(NULL, NULL, NULL);
// 			pEvent->m_bTalk = TRUE;
// 		}

		dwCheck <<= 1;
	}

	DoShowRegs(pEvent);
	return TRUE;

#if 0
	//here we only take care of one, not a good idea
	for (int i = 0; dwIndex != 1; i++)
	{
		dwIndex >>= 1;
	}

	dwIndex = i;

	tagHWBP hwBP;
	hwBP.pDRAddr[0] = &pEvent->m_Context.Dr0;
	hwBP.pDRAddr[1] = &pEvent->m_Context.Dr1;
	hwBP.pDRAddr[2] = &pEvent->m_Context.Dr2;
	hwBP.pDRAddr[3] = &pEvent->m_Context.Dr3;

	DWORD dwDR7 = pEvent->m_Context.Dr7;
	DWORD dwLENRW = dwDR7 >> 16;
	for (i = 0; i < dwIndex; i++)
	{
		dwLENRW >>= 4;
	}

	hwBP.dwAddr = *(hwBP.pDRAddr[dwIndex]);
	hwBP.dwType = dwLENRW & 0x3;
	dwLENRW >>= 2;
	hwBP.dwLen = (dwLENRW & 0x03) + 1;
	dwLENRW >>= 2;

	//take care of execute
	if (HWBP_EXECUTE == hwBP.dwType)
	{
		hwBP.dwLen = 0;
	}

	DoShowRegs(pEvent);
	sprintf(g_szBuf, "\r\nHWBP Hit: %p\t%d\t%s *****************\r\n",
		hwBP.dwAddr,
		hwBP.dwLen,
		(HWBP_EXECUTE == hwBP.dwType) ? STREXECUTE :
		((HWBP_WRITE == hwBP.dwType) ? STRWRITE : STRACCESS)
	);
	pEvent->m_pMenu->ShowInfo(g_szBuf);

	//用HWBP，并在单步内重新启用
	if (HWBP_EXECUTE == hwBP.dwType)
	{
		int argv[] = { 0, 4 };
		sprintf(g_szBuf, "bhc %d", dwIndex);
		DoBHC(pEvent, 2, argv, g_szBuf);

		m_bHWBPTF = TRUE;
		m_dwAddr = hwBP.dwAddr;
		DoStepInto(pEvent);
	}
#endif
}

//是否符合条件断点
BOOL CExceptEvent::CheckHitTJBP(CBaseEvent * pEvent,DWORD dwAddr)
{
	//当前地址寄存器
	char EXXarry[4][4] = { "eax", "ebx", "ecx", "edx" };

	for (auto&index : m_vecTJBP)
	{
		for (int i = 0; i < 4; i++)
		{
			if (strcmp(index.strExx, EXXarry[i]) == 0)
			{
				if (strcmp(index.strSymbol, ">") == 0)
				{
					if (pEvent->m_Context.Eax - index.dwValue)
					{
						pEvent->m_bTmpBP = TRUE;	//临时断点开关开启
				/*		DoBPtemp(pEvent, dwAddr);*/
						return TRUE;
					}
				}
				else if (strcmp(index.strSymbol, "=") == 0)
				{
					if ((pEvent->m_Context.Eax - index.dwValue) == 0)
					{
						pEvent->m_bTmpBP = TRUE;	//临时断点开关开启
				/*		DoBPtemp(pEvent, dwAddr);*/
						return TRUE;
					}
				}
				else if (strcmp(index.strSymbol, "<") == 0)
				{
					if ((pEvent->m_Context.Eax - index.dwValue) < 0)
					{
						pEvent->m_bTmpBP = TRUE;	//临时断点开关开启
				/*		DoBPtemp(pEvent, dwAddr);*/
						return TRUE;
					}
				}

			}
		}
	}

	return FALSE;
}

/************************************************************************/
/*
功能：处理由不同原因造成的单步事件
过程：1）是否由单步跟踪调试引起
2）是否用于重新启用硬件执行断点
3）是否由Hard Ware Breapoint击中造成的
4）是否用于重新启用Mem BP（访问冲突）
5）是否用于重新启用普通BP
6）是否由用户单步步入导致
7）是否由用户单步步过结束
8）是否由调试器造成* /

/************************************************************************/
DWORD
CExceptEvent::OnSingleStep(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
	DWORD dwFirstChance = pEvent->m_debugEvent.u.Exception.dwFirstChance;
	tagPageBP *ppageBP = NULL;
	tagModule module = { 0 };
	DWORD dwOldProtect;
	BOOL bRet;


	//完成跟踪+预取，重新启用Page NOACCESS
	if (m_bTraceTF)
	{
		m_bTraceTF = FALSE;

		//某些调试异常可能会清除0-3位。
		// DR6寄存器的其余内容永远不会被处理器清除。
		//为了避免混淆识别调试异常，调试处理程序应该在返回被中断的任务之前清除寄存器。
		pEvent->m_Context.Dr6 = 0;

		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)m_dwAddr,
			MAX_INSTRUCTION,
			PAGE_NOACCESS, //ppageBP->dwNewProtect,
			&dwOldProtect
		);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return DBG_CONTINUE;    //really?
		}
		return DBG_CONTINUE;
	}


	//重新启用HEBP硬件断点，但不保证相同的索引
	if (m_bHWBPTF)
	{
		//在异常代码上修复t，p
		if (!IsSameModule(pEvent,
			pEvent->m_Context.Eip,
			pEvent->m_dwLastAddr,
			&module)
			)
		{
			sprintf_s(g_szBuf, MAXBUF, "\r\nHit/Exit Exception Dispatch: %p********\r\n\r\n", pEvent->m_Context.Eip);
			CMENU::ShowInfo(g_szBuf);

			//禁用用户输入
			pEvent->m_dwLastAddr = pEvent->m_Context.Eip;
			pEvent->m_bTalk = TRUE;

			//不能重置tf标志
		}
		else
		{
			m_bHWBPTF = FALSE;
		}

// 		_snprintf(g_szBuf, MAXBUF, "重启硬件断点 at eip: %p\r\n",
// 			pEvent->m_Context.Eip);
// 		pEvent->m_pMenu->ShowInfo(g_szBuf);

		//清零 DR6
		pEvent->m_Context.Dr6 = 0;

		//bh 00400000 e 0
		int argv[] = { 0, 3, 0x0C, 0x0e };
		sprintf_s(g_szBuf, MAXBUF, "bh %p e 0", m_dwAddr);
		DoBH(pEvent, 4, argv, g_szBuf);
		return DBG_CONTINUE;
	}


	//检查硬件bp是否命中
	if (HasHitHWBP(pEvent))
	{
		pEvent->m_Context.Dr6 = 0;

		return DBG_CONTINUE;
	}


	//是否访问异常
	if (m_bAccessVioTF)
	{
		m_bAccessVioTF = FALSE;

		pEvent->m_Context.Dr6 = 0;

		bRet = HasMemBP(pEvent, m_dwAddr, &ppageBP);	//是否内存断点
		if (bRet)
		{
			//需要恢复保护（PAGE NOACCESS）
			bRet = VirtualProtectEx(pEvent->m_hProcess,
				(LPVOID)m_dwAddr,
				MAX_INSTRUCTION,
				ppageBP->dwNewProtect,
				&dwOldProtect
			);
			if (!bRet)
			{
				CMENU::ShowErrorMessage();
				return DBG_CONTINUE;    //really?
			}
		}
		return DBG_CONTINUE;
	}


	//是否存在条件断点
	if (pEvent->m_bTJBPTF)
	{

		DoBPtemp(pEvent, m_vecTJBP[0].dwAddr);
		return DBG_CONTINUE;

	}
	//重新设置普通断点
	tagNormalBP *pNomalBP = NULL;
	if (m_bNormalBPTF)
	{
		m_bNormalBPTF = FALSE;

		pEvent->m_Context.Dr6 = 0;

		bRet = HasNormalBP(pEvent, m_dwAddr, &pNomalBP);
		if (!bRet)
		{
			return DBG_CONTINUE;
		}


		//恢复代码
		assert(pNomalBP->bPerment);
		bRet = WriteProcessMemory(pEvent->m_hProcess,
			(LPVOID)m_dwAddr,
			(LPVOID)&gs_BP,
			sizeof(gs_BP),
			NULL);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
		}

		//普通断点是否设置在int3上
		if (pNomalBP->bPerment && pNomalBP->oldvalue != gs_BP )
		{
			//没有设置在int3上
			pEvent->m_bTalk = TRUE;
			DoShowRegs(pEvent);
 		}
		return DBG_CONTINUE;
	}

	//////////////////////////////////////////////////////////////////////////
	//用于用户输入't'
	if (pEvent->m_bUserTF)
	{
		pEvent->m_Context.Dr6 = 0;

		if (!IsSameModule(pEvent,
			pEvent->m_Context.Eip,
			pEvent->m_dwLastAddr,
			&module)
			)
		{
			sprintf_s(g_szBuf, MAXBUF, "\r\nHit/Exit Exception Dispatch: %p********\r\n\r\n", pEvent->m_Context.Eip);
			CMENU::ShowInfo(g_szBuf);

			pEvent->m_dwLastAddr = pEvent->m_Context.Eip;

		}
		else
		{
			pEvent->m_bUserTF = FALSE;
		}

		pEvent->m_bTalk = TRUE;
		DoShowRegs(pEvent);
		return DBG_CONTINUE;
	}


	//单步步过
	if (pEvent->m_bStepOverTF)
	{
		pEvent->m_Context.Dr6 = 0;

		if (!IsSameModule(pEvent,
			pEvent->m_Context.Eip,
			pEvent->m_dwLastAddr,
			&module)
			)
		{
			sprintf_s(g_szBuf, MAXBUF, "\r\nHit/Exit Exception Dispatch: %p*****\r\n\r\n", pEvent->m_Context.Eip);
			CMENU::ShowInfo(g_szBuf);

			pEvent->m_dwLastAddr = pEvent->m_Context.Eip;

		}
		else
		{
			pEvent->m_bStepOverTF = FALSE;
		}

		pEvent->m_bTalk = TRUE;
		DoShowRegs(pEvent);
		return DBG_CONTINUE;
	}


// 	//是否由调试对象引起
// 	if (dwFirstChance)
// 	{
// 		pEvent->m_pMenu->ShowInfo("\r\nSingleStep First Chance*********\r\n");
// 	}
// 	else
// 	{
// 		pEvent->m_pMenu->ShowInfo("\r\nSingleStep Second Chance*********\r\n");
// 		//dwContinueStatus = DBG_CONTINUE;  //can we ?
// 	}





	//DoShowRegs(pEvent);

	//是g 或者无操作
	return DBG_CONTINUE;

}



//用户步过操作                 
BOOL CExceptEvent::DoStepOver(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/)
{
	assert(pEvent != NULL);

	//修复异常代码
	m_dwLastAddr = m_Context.Eip;

	pEvent->m_bStepOverTF = TRUE;
	UINT nCodeLen = 0;

	//如果不是调用，按一般步骤进行处理
	if (!IsCall(pEvent, pEvent->m_Context.Eip, &nCodeLen))
	{
		m_dwAddr = pEvent->m_Context.Eip;
		DoStepInto(pEvent);
	}
	else
	{
		//如果是调用函数，在其上设置临时普通断点
		int argv[] = { 0, 3 };
		sprintf_s(g_szBuf, MAXBUF, "bp %p", pEvent->m_Context.Eip + nCodeLen);

		pEvent->m_bTmpBP = TRUE;	//临时断点开关开启
		DoBP(pEvent, 2, argv, g_szBuf);
	}

	return TRUE;
}

BOOL CExceptEvent::DoStepInto(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/)
{
	assert(pEvent != NULL);

	//修复异常代码
	pEvent->m_dwLastAddr = pEvent->m_Context.Eip;

	pEvent->m_Context.EFlags |= 0x100;
	return TRUE;
}

/************************************************************************/
/*
Function : 处理用户go命令
Params   : g [addr]
argc    命令长度
pargv[] pszBuf中每个参数的索引
pszBuf  用户命令字符串                                                               
/************************************************************************/
BOOL CExceptEvent::DoGo(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//g  or g addr
	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	CONTEXT ct1 = { CONTEXT_FULL |CONTEXT_DEBUG_REGISTERS };
	::GetThreadContext(pEvent->m_hThread, &ct1);
	
	//g
	if (1 == argc)
	{
		return TRUE;
	}

	//g addr   在该地址设置一个临时断点
	pEvent->m_bTmpBP = TRUE;
	return DoBP(pEvent, argc, pargv, pszBuf);
}

/************************************************************************/
/*
功能：判断addrin的页面是否有效
Params：dwAddr是指定的地址
返回：TRUE有效，否则返回FALSE
处理：通过MEM COMMIT定义                           */
/************************************************************************/
BOOL
CExceptEvent::IsPageValid(CBaseEvent *pEvent, DWORD dwAddr)
{
	assert(pEvent != NULL);

	MEMORY_BASIC_INFORMATION memInfo;
	VirtualQueryEx(pEvent->m_hProcess,
		(LPVOID)dwAddr,
		&memInfo,
		sizeof(MEMORY_BASIC_INFORMATION)
	);

	if (memInfo.State != MEM_COMMIT)
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*
功能：判断地址是否可读
用于Get One ASM
Params：dw Addr是指定的地址
返回：如果有效，则为TRUE，
否则，返回FALSE                                                                  */
/************************************************************************/
BOOL
CExceptEvent::IsPageReadable(CBaseEvent *pEvent, DWORD dwAddr)
{
	assert(pEvent != NULL);

	//如果在用户代码中 并且 正在追踪则不可读的

	if (pEvent->m_bTrace
		&& dwAddr < SYSSPACE)
	{
		return FALSE;
	}

	MEMORY_BASIC_INFORMATION memInfo;
	VirtualQueryEx(pEvent->m_hProcess,
		(LPVOID)dwAddr,
		&memInfo,
		sizeof(MEMORY_BASIC_INFORMATION)
	);

	//perhaps need more detail
	if (PAGE_NOACCESS == memInfo.Protect)
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*
Function : 判断addr中是否存在内存断点的页面
Params：dw Addr是指定的地址
[OUT]页面BP用于接收页面BP信息（如果存在）
返回：如果存在则为TRUE，否则为FALSE                                                             */
/************************************************************************/
BOOL CExceptEvent::HasMemBP(CBaseEvent *pEvent, DWORD dwAddr, tagPageBP **ppPageBP)
{
	assert(pEvent != NULL);
	assert(ppPageBP != NULL);
	*ppPageBP = NULL;

	//是否在系统地址空间内
	if (dwAddr > SYSSPACE)
	{
		if (IsPageReadable(pEvent, dwAddr))
		{
			return FALSE;
		}
	}

	//断点所在的地址页的页起始地址
	DWORD dwPageAddr = (dwAddr / m_dwPageSize) * m_dwPageSize;	
	map<DWORD, tagPageBP>::iterator it;
	it = m_mapPage_PageBP.find(dwPageAddr);
	if (it != m_mapPage_PageBP.end())
	{
		*ppPageBP = &it->second;
		return TRUE;
	}

	return FALSE;
}

/************************************************************************/
/*
Function : 判断addr是否设置了普通断点
/************************************************************************/
BOOL
CExceptEvent::HasNormalBP(CBaseEvent *pEvent, DWORD dwAddr, tagNormalBP **ppNormalBP)
{
	assert(pEvent != NULL);
	assert(ppNormalBP != NULL);
	*ppNormalBP = NULL;

	map<DWORD, tagNormalBP>::iterator it;
	it = m_mapAddr_NormBP.find(dwAddr);
	if (it != m_mapAddr_NormBP.end())
	{
		*ppNormalBP = &it->second;
		return TRUE;
	}
	return FALSE;
}

/************************************************************************/
/*
功能：在指定的地址设置断点
过程：
1）是否已经设置
2）页面是否有效
3）考虑内存断点可能会改变页面
*/
/************************************************************************/
BOOL CExceptEvent::DoBP(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//bp addr
	assert(2 == argc);
	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	BOOL bRet;
	DWORD dwAddr = strtoul(&pszBuf[pargv[1]], NULL, 16);
	assert((dwAddr != 0) && (dwAddr != ULONG_MAX));

	//是否已设置临时或永久断点
	tagNormalBP *pNormalBP = NULL;
	bRet = HasNormalBP(pEvent, dwAddr, &pNormalBP);
	if (bRet)
	{
		assert(pNormalBP != NULL);

		//如果要设置临时断点
		if (pEvent->m_bTmpBP)
		{
			if (pNormalBP->bTmp)
			{
				//
			}
			else if (pNormalBP->bPerment)
			{
				pNormalBP->bTmp = TRUE;
			}
			else
			{
			//既不是临时也不是永久断点，不可能
				assert(FALSE);
			}
			pEvent->m_bTmpBP = FALSE;
		}
		else
		{
			if (pNormalBP->bTmp)
			{
				pNormalBP->bPerment = TRUE;
			}
			else if (pNormalBP->bPerment)
			{
			}
			else
			{
				assert(FALSE);
			}
		}

		pNormalBP->bDisabled = FALSE;
		return TRUE;
	}



	//页面是否有效
	bRet = IsPageValid(pEvent, dwAddr);
	if (!bRet)
	{
		return FALSE;
	}

	//判断内存断点是否存在于页面中
	tagPageBP *ppageBP = NULL;
	DWORD dwOldProtect;
	bRet = HasMemBP(pEvent, dwAddr, &ppageBP);

	//现在保存普通断点
	tagNormalBP normalBP = { 0 };
	bRet = ReadBuf(pEvent,
		pEvent->m_hProcess,
		(LPVOID)dwAddr,
		(LPVOID)&normalBP.oldvalue,
		sizeof(normalBP.oldvalue)
	);
	if (!bRet)
	{
		return FALSE;
	}

	//存在内存断点
	if (ppageBP != NULL)
	{
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwAddr,
			MAX_INSTRUCTION,
			ppageBP->dwOldProtect,
			&dwOldProtect
		);
	}

	//写入CC——gs_BP
	bRet = WriteProcessMemory(pEvent->m_hProcess,
		(LPVOID)dwAddr,
		(LPVOID)&gs_BP,
		sizeof(gs_BP),
		NULL
	);
	if (!bRet)
	{
		CMENU::ShowErrorMessage();
		return FALSE;
	}

	//保存普通断点
	if (pEvent->m_bTmpBP)//如果是调试器自己设置的临时普通断点
	{
		normalBP.bTmp = TRUE;	//断点是临时的
		pEvent->m_bTmpBP = FALSE;	
	}
	else
	{
		normalBP.bPerment = TRUE;	//那么就是用户设置的普通断点
	}
	normalBP.bDisabled = FALSE;   //在int3 上设置普通断点
	m_mapAddr_NormBP[dwAddr] = normalBP;

	//恢复保护
	if (ppageBP != NULL)
	{
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwAddr,
			MAX_INSTRUCTION,
			ppageBP->dwNewProtect,
			&dwOldProtect
		);
	}

	return TRUE;
}


BOOL CExceptEvent::DoBPtemp(CBaseEvent *pEvent, DWORD dwAddr)
{

	//是否已设置临时或永久断点
	tagNormalBP *pNormalBP = NULL;
	DWORD bRet = HasNormalBP(pEvent, dwAddr, &pNormalBP);
	if (bRet)
	{
		assert(pNormalBP != NULL);

		//如果要设置临时断点
		if (pEvent->m_bTmpBP)
		{
			if (pNormalBP->bTmp)
			{
				//
			}
			else if (pNormalBP->bPerment)
			{
				pNormalBP->bTmp = TRUE;
			}
			else
			{
				//既不是临时也不是永久断点，不可能
				assert(FALSE);
			}
			pEvent->m_bTmpBP = FALSE;
		}
		else
		{
			if (pNormalBP->bTmp)
			{
				pNormalBP->bPerment = TRUE;
			}
			else if (pNormalBP->bPerment)
			{
			}
			else
			{
				assert(FALSE);
			}
		}

		pNormalBP->bDisabled = FALSE;
		return TRUE;
	}



	//页面是否有效
	bRet = IsPageValid(pEvent, dwAddr);
	if (!bRet)
	{
		return FALSE;
	}

	//判断内存断点是否存在于页面中
	tagPageBP *ppageBP = NULL;
	DWORD dwOldProtect;
	bRet = HasMemBP(pEvent, dwAddr, &ppageBP);

	//现在保存普通断点
	tagNormalBP normalBP = { 0 };
	bRet = ReadBuf(pEvent,
		pEvent->m_hProcess,
		(LPVOID)dwAddr,
		(LPVOID)&normalBP.oldvalue,
		sizeof(normalBP.oldvalue)
	);
	if (!bRet)
	{
		return FALSE;
	}

	//存在内存断点
	if (ppageBP != NULL)
	{
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwAddr,
			MAX_INSTRUCTION,
			ppageBP->dwOldProtect,
			&dwOldProtect
		);
	}

	bRet = WriteProcessMemory(pEvent->m_hProcess,
		(LPVOID)dwAddr,
		(LPVOID)&gs_BP,
		sizeof(gs_BP),
		NULL
	);
	if (!bRet)
	{
		CMENU::ShowErrorMessage();
		return FALSE;
	}

	//保存普通断点
	if (pEvent->m_bTmpBP)//如果是调试器自己设置的临时普通断点
	{
		normalBP.bTmp = TRUE;	//断点是临时的
		pEvent->m_bTmpBP = FALSE;
	}
	else
	{
		normalBP.bPerment = TRUE;	//那么就是用户设置的普通断点
	}
	normalBP.bDisabled = FALSE;   //在int3 上设置普通断点
	m_mapAddr_NormBP[dwAddr] = normalBP;

	//恢复保护
	if (ppageBP != NULL)
	{
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwAddr,
			MAX_INSTRUCTION,
			ppageBP->dwNewProtect,
			&dwOldProtect
		);
	}

	return TRUE;
}

//条件断点
BOOL CExceptEvent::DoBPtj(CBaseEvent * pEvent, int argc, int pargv[], const char * pszBuf)
{
	//bptj addr Exx >|=|< value
	assert(pEvent != NULL);
	assert(pszBuf != NULL);
	assert(5 == argc);		//指令有四段

	DWORD dwAddr = strtoul(&pszBuf[pargv[1]], NULL, 16);
	assert((dwAddr != 0) && (dwAddr != ULONG_MAX));
	const char* strExx = &pszBuf[pargv[2]];	//寄存器
	const char* strSymbol = &pszBuf[pargv[3]];	//符号
	DWORD dwValue = strtoul(&pszBuf[pargv[4]], NULL, 16);	//值

	

	tagTJBP tjBP;
	tjBP.dwAddr = dwAddr;
	strcpy_s(tjBP.strExx ,strExx);
	strcpy_s(tjBP.strSymbol, strSymbol);
	tjBP.dwValue = dwValue;
	m_vecTJBP.push_back(tjBP);
	pEvent->m_bTJBPTF = TRUE;

	DoBP(pEvent, 2, pargv, pszBuf);

	return TRUE;
}



//显示普通断点列表
BOOL CExceptEvent::DoBPL(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/)
{
	assert(pEvent != NULL);

	sprintf_s(g_szBuf, MAXBUF, "----------------普通断点列表----------------\r\n"
		"序号\t地址\r\n");

	tagNormalBP *pNormalBP = NULL;
	int i = 0;
	map<DWORD, tagNormalBP>::iterator it;
	for (it = m_mapAddr_NormBP.begin();
		it != m_mapAddr_NormBP.end();
		it++, i++)
	{
		pNormalBP = &it->second;
		if (pNormalBP->bPerment)
		{
			_snprintf(g_szBuf, MAXBUF, "%s%d\t%p\r\n",
				g_szBuf,
				i,
				it->first
			);
		}
	}

	pEvent->m_pMenu->ShowInfo(g_szBuf);
	return TRUE;
}

/************************************************************************/
/*
Function :删除指定的普通断点
Params   : bpc id
id is the index shown by bpl
pszBuf[pargv[0]] = "bpc"
pszBuf[pargv[1]] = id
/************************************************************************/
BOOL CExceptEvent::DoBPC(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//bpc id
	assert(pEvent != NULL);
	assert(pszBuf != NULL);
	assert(2 == argc);
	assert(isdigit(pszBuf[pargv[1]]));

	
	DWORD dwIndex = strtoul(&pszBuf[pargv[1]], NULL, 10);
	assert(dwIndex != ULONG_MAX);

	tagNormalBP *pNormalBP = NULL;
	DWORD i = 0;
	map<DWORD, tagNormalBP>::iterator it;
	for (it = m_mapAddr_NormBP.begin();
		it != m_mapAddr_NormBP.end();
		it++, i++)
	{
		if (i == dwIndex)
		{
			m_mapAddr_NormBP.erase(it);
			return TRUE;
		}
	}

	return FALSE;
}

/************************************************************************
Function :检查内存断点的有效性
/************************************************************************/
BOOL CExceptEvent::CheckBMValidity(CBaseEvent *pEvent,
	tagMemBP *pMemBP)
{
	assert(pEvent != NULL);

	//可以调用多少页面
	DWORD nPages = (pMemBP->dwAddr + pMemBP->dwSize) / m_dwPageSize - pMemBP->dwAddr / m_dwPageSize;
	if (0 == nPages)
	{
		nPages = 1;
	}

	DWORD nTmp = pMemBP->dwSize / m_dwPageSize + 1;
	if (nTmp > nPages)
	{
		nPages = nTmp;
	}

	//检查这些内存状态
	MEMORY_BASIC_INFORMATION memInfo;
	tagMemBPInPage memBPInPage;         //断点在分页内信息
	map<DWORD, tagPageBP>::iterator it;
	map<DWORD, tagPageBP>::iterator itend = m_mapPage_PageBP.end();
	list<tagMemBP>::iterator itMemBP;

	DWORD dwPageAddr = (pMemBP->dwAddr / m_dwPageSize) * m_dwPageSize;
	DWORD dwRealSize = 0;
	DWORD dwOldProtect;
	BOOL  bRet;

	//如果已经存在
	itMemBP = find(m_lstMemBP.begin(), m_lstMemBP.end(), *pMemBP);
	if (itMemBP != m_lstMemBP.end())
	{
		return FALSE;
	}
	DWORD i = 0;
	for (; i < nPages; i++)
	{
		//检索虚拟地址空间内的页面信息
		VirtualQueryEx(pEvent->m_hProcess,
			(LPVOID)dwPageAddr,
			&memInfo,
			sizeof(MEMORY_BASIC_INFORMATION)
		);

		//不处理MEM_FREE(空闲状态)，MEM_RESERVE(页面被保留)
		if (memInfo.State != MEM_COMMIT)//MEM_COMMIT:已分配物理内存或者系统页文件
		{
			pEvent->m_pMenu->ShowInfo("not MEM_COMMIT\r\n");//没有提交
			break;
		}

		//如果已经设置页面属性
		if (PAGE_NOACCESS == memInfo.Protect)
		{
			it = m_mapPage_PageBP.find(dwPageAddr);
			if (it == itend)
			{
				dwPageAddr += m_dwPageSize;
				continue;
			}
			memInfo.Protect = (*it).second.dwOldProtect;
		}

		//如果要设置写入断点，但页属性不可写，则不需要设置
		if ((MEMBP_WRITE == pMemBP->dwType)			//写入断点
			&& (PAGE_READONLY == pMemBP->dwType || PAGE_EXECUTE == pMemBP->dwType || PAGE_EXECUTE_READ == pMemBP->dwType))
		{
			dwPageAddr += m_dwPageSize;
			continue;
		}

		
		if (i > 0 && i < nPages - 1)
		{
			memBPInPage.wOffset = 0;			//在页内的偏移
			memBPInPage.wSize = m_dwPageSize;	//在页内的大小
		}
		else if (0 == i)
		{
			memBPInPage.wOffset = pMemBP->dwAddr - dwPageAddr;
			memBPInPage.wSize = min(pMemBP->dwSize, m_dwPageSize - memBPInPage.wOffset);
		}
		else    //i = nPages - 1
		{
			memBPInPage.wOffset = 0;
			memBPInPage.wSize = pMemBP->dwAddr + pMemBP->dwSize - dwPageAddr;
		}
		memBPInPage.bTrace = pMemBP->bTrace;

		//如果大小为零，全部完成
		if (0 == memBPInPage.wSize)
		{
			break;
		}

		m_mapPage_PageBP[dwPageAddr].dwPageAddr = dwPageAddr;
		m_mapPage_PageBP[dwPageAddr].dwOldProtect = memInfo.Protect;
		m_mapPage_PageBP[dwPageAddr].dwNewProtect = PAGE_NOACCESS;
		m_mapPage_PageBP[dwPageAddr].lstMemBP.remove(memBPInPage);    //以避免已经存在
		m_mapPage_PageBP[dwPageAddr].lstMemBP.push_back(memBPInPage);

	//回复属性
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwPageAddr,
			MAX_INSTRUCTION,
			PAGE_NOACCESS,
			&dwOldProtect);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
		}

		dwPageAddr += m_dwPageSize;
	}


	if (i != 0)
	{
		m_lstMemBP.push_back(*pMemBP);
	}

	return TRUE;
}

/************************************************************************/
/*
Function : 设置内存断点
Params   :  bm addr a|w len
addr为断点起始值，a|w分别表示访问类型和写入类型，len表示断点的长度

处理：
1)断点合法性检查（分页是否有效，断点属性与分页属性，重复性设置），
2)新属性的设置，
3)分页断点的信息更新
/************************************************************************/
BOOL CExceptEvent::DoBM(CBaseEvent *pEvent,
	int argc,
	int pargv[],
	const char *pszBuf,
	BOOL bTrace
)
{
	//bm addr a|w|e len
	assert(4 == argc);
	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	if (!bTrace)
	{
		int i = 0;
	}

	DWORD dwAddr = strtoul(&pszBuf[pargv[1]], NULL, 16);
	assert((dwAddr != 0) && (dwAddr != ULONG_MAX));

	char  bpType = pszBuf[pargv[2]];
	DWORD dwSize = strtoul(&pszBuf[pargv[3]], NULL, 10);
	assert((dwSize != 0) && (dwSize != ULONG_MAX));
	assert(('a' == bpType) || ('w' == bpType)|| ('e' == bpType));

	//检查地址有效性，
	tagMemBP       memBP;               //独立内存断点
	memBP.dwAddr = dwAddr;
	memBP.dwSize = dwSize;
	memBP.dwType = ((bpType == 'a') ? MEMBP_ACCESS : MEMBP_WRITE);
	memBP.bTrace = bTrace;
	CheckBMValidity(pEvent,&memBP);

	return TRUE;
}

BOOL CExceptEvent::DoBML(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	assert(pEvent != NULL);
	sprintf_s(g_szBuf, MAXBUF, "----------------内存断点列表----------------\r\n"
		"序号\t地址\t\t长度\t\t类型\r\n");

	list<tagMemBP>::iterator it;
	tagMemBP memBP;
	int i = 0;
	for (it = m_lstMemBP.begin();
		it != m_lstMemBP.end();
		it++, i++)
	{
	
		memBP = *it;
		_snprintf(g_szBuf, MAXBUF, "%s%d\t%p\t%p\t%s\r\n",
			g_szBuf,
			i,
			memBP.dwAddr,
			memBP.dwSize,
			MEMBP_ACCESS == memBP.dwType ? "访问" : "写"
		);
	}
	pEvent->m_pMenu->ShowInfo(g_szBuf);

	return TRUE;
}

BOOL CExceptEvent::DoBMPL(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	assert(pEvent != NULL);
	sprintf_s(g_szBuf, MAXBUF, "----------------分页断点列表----------------\r\n");

	tagPageBP pageBP;
	tagMemBPInPage memBPInPage;
	map<DWORD, tagPageBP>::iterator it;
	list<tagMemBPInPage>::iterator itBPInPage;
	for (it = m_mapPage_PageBP.begin();
		it != m_mapPage_PageBP.end();
		it++)
	{
		pageBP = (*it).second;

		_snprintf(g_szBuf, MAXBUF, "%s分页地址\t旧属性\t\t新属性\r\n"
			"%p\t%p\t%p\r\n"
			"\t偏移\t长度\r\n",
			g_szBuf,
			pageBP.dwPageAddr,
			pageBP.dwOldProtect,
			pageBP.dwNewProtect);
		for (itBPInPage = pageBP.lstMemBP.begin();
			itBPInPage != pageBP.lstMemBP.end();
			itBPInPage++)
		{
			memBPInPage = *itBPInPage;
			_snprintf(g_szBuf, MAXBUF, "%s\t%04X\t%04X\r\n",
				g_szBuf,
				memBPInPage.wOffset,
				memBPInPage.wSize);
		}
	}

	pEvent->m_pMenu->ShowInfo(g_szBuf);
	return TRUE;
}

/************************************************************************/
/*
功能：判断页面内是否有其他mem BP
                                                             */
/************************************************************************/
BOOL CExceptEvent::HasOtherMemBP(CBaseEvent *pEvent,
	DWORD dwPageAddr,
	tagPageBP **ppPageBP,
	DWORD *pnTotal)
{
	assert(ppPageBP != NULL);
	*ppPageBP = &m_mapPage_PageBP[dwPageAddr];

	list<tagMemBPInPage> &lstmemBP = m_mapPage_PageBP[dwPageAddr].lstMemBP;
	list<tagMemBPInPage>::iterator it;
	DWORD i = 0;
	for (it = lstmemBP.begin();
		it != lstmemBP.end();
		it++, i++)
	{

	}

	*pnTotal = i;
	if (i > 1)
	{
		return TRUE;
	}

	return FALSE;
}

/************************************************************************/
/*
Function : 删除指定的内存断点
Params   : bmc id
*/
/************************************************************************/
BOOL CExceptEvent::DoBMC(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//bmc id
	assert(pEvent != NULL);
	assert(pszBuf != NULL);
	assert(2 == argc);
	assert(isdigit(pszBuf[pargv[1]]));

	DWORD i = 0;
	DWORD j = strtoul(&pszBuf[pargv[1]], NULL, 10);  
	DWORD dwAddr = 0;
	DWORD dwSize = 0;
	DWORD dwType = 0;

	//获取 dwAddr, dwSize, dwType
	list<tagMemBP>::iterator itMemBP;
	for (itMemBP = m_lstMemBP.begin();
		itMemBP != m_lstMemBP.end();
		itMemBP++, i++)
	{
		if (j == i)
		{
			dwAddr = (*itMemBP).dwAddr;
			dwSize = (*itMemBP).dwSize;
			dwType = (*itMemBP).dwType;

			//从Mem BP中删除
			m_lstMemBP.remove(*itMemBP);
			break;
		}
	}

	//如果不匹配
	if (0 == dwAddr)
	{
		return FALSE;
	}

	//可以调用多少页面
	DWORD nPages = (dwAddr + dwSize) / m_dwPageSize - dwAddr / m_dwPageSize;
	if (0 == nPages)
	{
		nPages = 1;
	}

	//检查这些页面状态
	MEMORY_BASIC_INFORMATION memInfo;
	tagMemBPInPage memBPInPage;         //断点在分页内信息
	tagPageBP      *ppageBP = NULL;
	map<DWORD, tagPageBP>::iterator it;
	map<DWORD, tagPageBP>::iterator itend = m_mapPage_PageBP.end();

	DWORD dwPageAddr = (dwAddr / m_dwPageSize) * m_dwPageSize;
	DWORD dwOldProtect;
	BOOL bRet;

	//此页是否包含其他membp
	for (i = 0; i < nPages; i++)
	{
		VirtualQueryEx(pEvent->m_hProcess,
			(LPVOID)dwPageAddr,
			&memInfo,
			sizeof(MEMORY_BASIC_INFORMATION)
		);

		//不处理MEM FREE，MEM RESERVE
		if (memInfo.State != MEM_COMMIT)
		{
			pEvent->m_pMenu->ShowInfo("not MEM_COMMIT\r\n");
			break;
		}

		//如果保护已经没有设置
#if 0
		if (PAGE_NOACCESS != memInfo.Protect)
		{
			dwPageAddr += m_dwPageSize;
			continue;
		}
#endif

		//如果不需要设置
		if ((MEMBP_WRITE == dwType)
			&& (PAGE_READONLY == dwType
				|| PAGE_EXECUTE == dwType
				|| PAGE_EXECUTE_READ == dwType)
			
			)
		{
			dwPageAddr += m_dwPageSize;
			continue;
		}

	
		if (i > 0
			&& i < nPages - 1)
		{
			memBPInPage.wOffset = 0;
			memBPInPage.wSize = m_dwPageSize;
		}
		else if (0 == i)
		{
			memBPInPage.wOffset = dwAddr - dwPageAddr;
			memBPInPage.wSize = min(dwSize, m_dwPageSize - memBPInPage.wOffset);
		}
		else    //i = nPages - 1
		{
			memBPInPage.wOffset = 0;
			memBPInPage.wSize = dwAddr + dwSize - dwPageAddr;
		}

		//如果页面内没有其他的mem BP，现在可以恢复保护
		DWORD dwTotal = 0;
		if (!HasOtherMemBP(pEvent, dwPageAddr, &ppageBP, &dwTotal))
		{
			bRet = VirtualProtectEx(pEvent->m_hProcess,
				(LPVOID)dwPageAddr,
				MAX_INSTRUCTION,
				ppageBP->dwOldProtect,
				&dwOldProtect
			);
			if (!bRet)
			{
				CMENU::ShowErrorMessage();
			}
		}

		//从页面BP信息中删除
		m_mapPage_PageBP[dwPageAddr].lstMemBP.remove(memBPInPage);

		//如果没有其他人，则从m地图页面页面中删除BP
		if (1 == dwTotal)
		{
			m_mapPage_PageBP.erase(dwPageAddr);
		}

		dwPageAddr += m_dwPageSize;
	}

	return TRUE;
}

/************************************************************************
Function : 为指定的地址设置硬件断点
/************************************************************************/
BOOL CExceptEvent::SetHWBP(CBaseEvent *pEvent, tagHWBP *pHWBP)
{
	assert(pEvent != NULL);
	assert(pHWBP != NULL);

	//页面是否有效
	BOOL bRet = IsPageValid(pEvent, pHWBP->dwAddr);
	if (!bRet)
	{
		return FALSE;
	}

	//修正对齐
	if (0x01 == (pHWBP->dwAddr & 0x01))
	{
		pHWBP->dwLen = 1;
	}
	else if ((0x2 == (pHWBP->dwAddr & 0x2))
		&& (0x4 == pHWBP->dwLen)
		)
	{
		pHWBP->dwLen = 2;
	}

	//并修复bh addr e 0
	DWORD dwLen = pHWBP->dwLen - 1;  //00 ->1byte, 01 -> 2byte, 11 -> 3byte
	if (HWBP_EXECUTE == pHWBP->dwType)
	{
		pHWBP->dwLen = 0;
		dwLen = 0;
	}

	//
	tagDR7 *pdr7 = (tagDR7 *)(&pEvent->m_Context.Dr7);
	pHWBP->RW[0] = pdr7->RW0;
	pHWBP->RW[1] = pdr7->RW1;
	pHWBP->RW[2] = pdr7->RW2;
	pHWBP->RW[3] = pdr7->RW3;

	
	pEvent->m_Context.Dr7 |= DR7INIT;
	DWORD dwDR7 = pEvent->m_Context.Dr7;
	DWORD dwCheck = 0x03;
	DWORD dwSet = 0x01;
	DWORD dwLENRW = (((dwLen << 2) | pHWBP->dwType) << 16);
	int i = 0;
	for (; i < 4; i++)
	{
		//如果GX，LX都为零，则DRX可用
		if (0 == (dwDR7 & dwCheck))
		{
			*(pHWBP->pDRAddr[i]) = pHWBP->dwAddr;                  //DR0 = dwAddr   
			pEvent->m_Context.Dr7 |= dwSet;                         //pdr7->GL0 = 1;
			pEvent->m_Context.Dr7 |= dwLENRW;
			break;
		}

		//如果相同的地址和类型
		if ((*(pHWBP->pDRAddr[i]) == pHWBP->dwAddr)
			&& pHWBP->RW[i] == pHWBP->dwType)
		{
		//保持相同，没有任何改变
			return FALSE;
		}

		dwCheck <<= 2;
		dwSet <<= 2;
		dwLENRW <<= 4;
	}

	//没有可用的
	if (4 == i)
	{
		pEvent->m_pMenu->ShowInfo("No DRX available\r\n");
		return FALSE;
	}

	return TRUE;

#if 0 //the original readable code
	//find the available DR0~DR3, can be more beautiful
	DWORD *pDRX = NULL;
	int nFree = -1;
	tagDR7 *pdr7 = (tagDR7 *)(&pEvent->m_Context.Dr7);
	if (0 == pdr7->GL0)
	{
		nFree = 0;
		pDRX = &pEvent->m_Context.Dr0;
		pdr7->GL0 = 1;
		pdr7->LEN0 = dwLen;
		pdr7->RW0 = pHWBP->dwType;
	}
	else if (0 == pdr7->GL1)
	{
		nFree = 1;
		pDRX = &pEvent->m_Context.Dr1;
		pdr7->GL1 = 1;
		pdr7->LEN1 = dwLen;
		pdr7->RW1 = pHWBP->dwType;
	}
	else if (0 == pdr7->GL2)
	{
		nFree = 2;
		pDRX = &pEvent->m_Context.Dr2;
		pdr7->GL2 = 1;
		pdr7->LEN2 = dwLen;
		pdr7->RW2 = pHWBP->dwType;
	}
	else if (0 == pdr7->GL3)
	{
		nFree = 3;
		pDRX = &pEvent->m_Context.Dr3;
		pdr7->GL3 = 1;
		pdr7->LEN3 = dwLen;
		pdr7->RW3 = pHWBP->dwType;
	}

	if (-1 == nFree)
	{
		return FALSE;
	}

	return TRUE;
#endif 
}

/************************************************************************/
/*
Function : 响应用户驱动（或调试器驱动）的硬件断点设置
Params   : bh addr e|w|a 1|2|4

注意EXECUTE，应该将其设置为零.
*/
/************************************************************************/
BOOL CExceptEvent::DoBH(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//bh addr e|w|a 1|2|4  
	assert(pEvent != NULL);
	assert(pszBuf != NULL);
	assert(4 == argc);

	DWORD dwAddr = strtoul(&pszBuf[pargv[1]], NULL, 16);//字符串地址转化为dword地址
	assert((dwAddr != 0) && (dwAddr != ULONG_MAX));

	char chType = pszBuf[pargv[2]];
	assert('e' == chType || 'w' == chType || 'a' == chType);
	DWORD dwType = ('e' == chType) ? HWBP_EXECUTE :
		(('w' == chType) ? HWBP_WRITE : HWBP_ACCESS);

	char chLen = pszBuf[pargv[3]];
	assert('0' == chLen || '1' == chLen || '2' == chLen || '4' == chLen);
	DWORD dwLen = strtoul(&chLen, NULL, 10);


	tagHWBP hwBP;
	hwBP.dwAddr = dwAddr;
	hwBP.dwType = dwType;
	hwBP.dwLen = dwLen;
	hwBP.pDRAddr[0] = &pEvent->m_Context.Dr0;
	hwBP.pDRAddr[1] = &pEvent->m_Context.Dr1;
	hwBP.pDRAddr[2] = &pEvent->m_Context.Dr2;
	hwBP.pDRAddr[3] = &pEvent->m_Context.Dr3;

	SetHWBP(pEvent, &hwBP);

	return TRUE;
}

BOOL CExceptEvent::DoBHL(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/)
{
	tagDR7 *pdr7 = (tagDR7 *)(&pEvent->m_Context.Dr7);
	DWORD dwDR7 = pEvent->m_Context.Dr7;
	DWORD dwCheck = 0x03;
	DWORD dwLENRW = dwDR7 >> 16;
	tagHWBP hwBP;
	hwBP.pDRAddr[0] = &pEvent->m_Context.Dr0;   //can be more beautiful
	hwBP.pDRAddr[1] = &pEvent->m_Context.Dr1;
	hwBP.pDRAddr[2] = &pEvent->m_Context.Dr2;
	hwBP.pDRAddr[3] = &pEvent->m_Context.Dr3;

	sprintf_s(g_szBuf, MAXBUF, "----------------硬件断点列表----------------\r\n"
		"序号\t地址\t\t长度\t类型\r\n");
	int i = 0;
	for (; i < 4; i++)
	{
		//if both GX, LX is zero, then DRX is not set
		if (0 == (dwDR7 & dwCheck))
		{
			dwCheck <<= 2;
			dwLENRW >>= 4;
			continue;
		}

		dwCheck <<= 2;

		hwBP.dwAddr = *(hwBP.pDRAddr[i]);
		hwBP.dwType = dwLENRW & 0x3;
		dwLENRW >>= 2;
		hwBP.dwLen = (dwLENRW & 0x03) + 1;
		dwLENRW >>= 2;

		//take care of execute
		if (HWBP_EXECUTE == hwBP.dwType)
		{
			hwBP.dwLen = 0;
		}

		_snprintf(g_szBuf, MAXBUF, "%s%d\t%p\t%d\t%s\r\n",
			g_szBuf,
			i,
			hwBP.dwAddr,
			hwBP.dwLen,
			(HWBP_EXECUTE == hwBP.dwType) ? STREXECUTE :
			((HWBP_WRITE == hwBP.dwType) ? STRWRITE : STRACCESS)
		);
	}

	pEvent->m_pMenu->ShowInfo(g_szBuf);

	return TRUE;
}

/************************************************************************/
/*
Function : 删除指定的HWBP
Params   : bhc id
id is the index shown by bhl                                 */
/************************************************************************/
BOOL CExceptEvent::DoBHC(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//bhc id
	assert(2 == argc);
	assert(pEvent != NULL);
	assert(pszBuf != NULL);
	assert(isdigit(pszBuf[pargv[1]]));

	DWORD dwIndex = strtoul(&pszBuf[pargv[1]], NULL, 10);
	assert(dwIndex < 4);

	DWORD dwSet = 0x3;
	for (DWORD i = 0; i < dwIndex; i++)
	{
		dwSet <<= 2;
	}

	pEvent->m_Context.Dr7 &= (~dwSet);

	return TRUE;
}


//寄存器相关
void CExceptEvent::DoShowRegs(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	//避免频繁询问TIB
	static DWORD dwFS = pEvent->m_Context.SegFs;
	static DWORD dwTIB = 0;
	if (dwFS != pEvent->m_dwFS)
	{
		dwFS = pEvent->m_dwFS;
		dwTIB = GetTIB(pEvent);
	}

	tagEFlags eflg = *(tagEFlags *)&pEvent->m_Context.EFlags;
	_snprintf(g_szBuf, MAXBUF, "EAX=%08X ECX=%08X EDX=%08X EBX=%08X\r\n"
		"ESP=%08X EBP=%08X ESI=%08X EDI=%08X\r\n"
		"EIP=%08X CS=%04X DS=%04X ES=%04X SS=%04X FS=%04X [%p]\r\n"
		"OF=%1X DF=%1X IF=%1X TF=%1X SF=%1X ZF=%1X AF=%1X PF=%1X CF=%1X\r\n",
		pEvent->m_Context.Eax, pEvent->m_Context.Ecx, pEvent->m_Context.Edx, pEvent->m_Context.Ebx,
		pEvent->m_Context.Esp, pEvent->m_Context.Ebp, pEvent->m_Context.Esi, pEvent->m_Context.Edi,
		pEvent->m_Context.Eip,
		pEvent->m_Context.SegCs, pEvent->m_Context.SegDs, pEvent->m_Context.SegEs,
		pEvent->m_Context.SegSs, pEvent->m_Context.SegFs, dwTIB,
		eflg.OF, eflg.DF, eflg.IF, eflg.TF, eflg.SF,
		eflg.ZF, eflg.AF, eflg.PF, eflg.CF);

	pEvent->m_pMenu->ShowInfo(g_szBuf);

	ShowTwoASM(pEvent);
}

/************************************************************************/
/*
功能：获取指定的dwAddr或 eip指向的一条指令（如果dwAddr未设置）
*/
/************************************************************************/
const char * CExceptEvent::GetOneASM(CBaseEvent *pEvent,
	DWORD dwAddr/*=NULL*/,
	UINT *pnCodeSize/*=NULL*/,
	BOOL bGetAPIName/*=TRUE*/)
{
	assert(pEvent != NULL);
	UINT nCodeSize;
	BOOL bRet;

	//从何处开始解码，如果为空则默认为eip
	DWORD dwCodeAddr = pEvent->m_Context.Eip;
	if (dwAddr != NULL)
	{
		dwCodeAddr = dwAddr;
	}

	bRet = ReadBuf(pEvent, pEvent->m_hProcess, (LPVOID)dwCodeAddr, gs_szCodeBuf, sizeof(gs_szCodeBuf));
	if (!bRet)
	{
		CMENU::ShowErrorMessage();
	}

	
	tagNormalBP *pNormalBP = NULL;
	bRet = HasNormalBP(pEvent, dwCodeAddr, &pNormalBP);
	if (bRet)
	{
		assert(pNormalBP != NULL);
		gs_szCodeBuf[0] = pNormalBP->oldvalue;
	}

	Decode2AsmOpcode((PBYTE)gs_szCodeBuf, gs_szASM, gs_szOpcode, &nCodeSize, dwCodeAddr);

	//接收代码大小
	if (pnCodeSize != NULL)
	{
		*pnCodeSize = nCodeSize;
	}

	//如果超出指定的跟踪范围，则忽略该api名称
	if (pEvent->m_bTrace
		&& (dwCodeAddr < pEvent->m_dwTraceBegin
			|| dwCodeAddr >= pEvent->m_dwTraceEnd
			)
		)
	{
		bGetAPIName = FALSE;
	}

	//使用全局变量记录机器码和汇编代码
	if (!bGetAPIName)
	{
		_snprintf(gs_szBuf, MAXBUF, "%p:  %-16s   %-16s\r\n",
			dwCodeAddr,
			gs_szOpcode,
			gs_szASM);
		return gs_szBuf;
	}

	_snprintf(g_szBuf, MAXBUF, "%p:  %-16s   %-16s",
		dwCodeAddr,
		gs_szOpcode,
		gs_szASM);

	char szAPIName[MAXBYTE];
	bRet = FALSE;
	if (bGetAPIName  
		&& (strstr(gs_szASM, "call")
			|| strstr(gs_szASM, "j")
			)
		)
	{
		bRet = GetAPIName(pEvent, dwCodeAddr, gs_szASM, szAPIName);
	}

	if (bRet)
	{
		_snprintf(g_szBuf, MAXBUF, "%s %s",
			g_szBuf,
			szAPIName);
	}

	_snprintf(g_szBuf, MAXBUF, "%s\r\n", g_szBuf);

	return g_szBuf;
}



//查看GetOneAsm                                                  
const char * CExceptEvent::ShowOneASM(CBaseEvent *pEvent,
	DWORD dwAddr/*=NULL*/,
	UINT *pnCodeSize/*=NULL*/)
{
	const char *pInfo = GetOneASM(pEvent, dwAddr, pnCodeSize);
	CMENU::ShowInfo(pInfo);
	return pInfo;
}

/************************************************************************/
/*
Function: 用于显示由dwAddr或（如果dwAddr未设置则为eip指出的两条指令）
*/
/************************************************************************/
void
CExceptEvent::ShowTwoASM(CBaseEvent *pEvent,
	DWORD dwAddr/*=NULL*/)
{
	assert(pEvent != NULL);

	DWORD dwCodeAddr = pEvent->m_Context.Eip;
	if (dwAddr != NULL)
	{
		dwCodeAddr = dwAddr;
	}

	UINT nCodeSize = 0;
// 	ShowOneASM(pEvent, dwCodeAddr, &nCodeSize);
// 	ShowOneASM(pEvent, dwCodeAddr + nCodeSize);

	for (int i = 0; i < 5; ++i)
	{
		ShowOneASM(pEvent, dwCodeAddr, &nCodeSize);
		dwCodeAddr += nCodeSize;
	}
}

/************************************************************************/
/*
Function :显示由指定的addr或eip指向的8条指令（如果未指定addr）
Params   : u [addr]
*/
/************************************************************************/
BOOL CExceptEvent::DoShowASM(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//u or u addr
	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	static DWORD dwLastAddr = pEvent->m_Context.Eip;

	DWORD dwCodeAddr = pEvent->m_Context.Eip;
	if (2 == argc)
	{
		dwCodeAddr = strtoul(&pszBuf[pargv[1]], NULL, 16);
		assert(dwCodeAddr != ULONG_MAX);
	}
	else
	{
		dwCodeAddr = dwLastAddr;
	}

	UINT nCodeSize;
	for (int i = 0; i < 8; i++)
	{
		ShowOneASM(pEvent, dwCodeAddr, &nCodeSize);
		dwCodeAddr += nCodeSize;
	}

	dwLastAddr = dwCodeAddr;
	return TRUE;
}

//修改OPcode
BOOL CExceptEvent::DoModifyOpCode(CBaseEvent * pEvent, int argc, int pargv[], const char * pszBuf)
{
	//显示输入地址的汇编代码
	//ShowTwoASM(pEvent);
	UINT nCodeSize = 0;
	//DWORD temp = pszBuf[pargv[2]];
	//ShowOneASM(pEvent, pszBuf[pargv[1]], &nCodeSize);

	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	//没有输入地址则当前地址
	static DWORD dwLastAddr = pEvent->m_Context.Eip;

	DWORD dwCodeAddr = pEvent->m_Context.Eip;
	if (2 == argc)	//如果有加上地址的话
	{
		dwCodeAddr = strtoul(&pszBuf[pargv[1]], NULL, 16);

		assert(dwCodeAddr != ULONG_MAX);
	}
	else
	{
		dwCodeAddr = dwLastAddr;
	}
	assert(dwCodeAddr != ULONG_MAX);

	ShowOneASM(pEvent, pszBuf[pargv[1]], &nCodeSize);
	
	DWORD	dwOldProtect;	//原内存页属性
	BYTE	bBuffer;		//接收原有数据的缓冲区的指针
	BYTE	bNewBuffer;		//新指令 
	DWORD	dwReadCount;	//传输到缓冲区的字节数
	//char*	szBuffer = new char[10];	//接收用户输入
	DWORD	dwInputValue;
	byte    szBuffer = 0;
	
	//修改内存保护属性
	VirtualProtectEx(pEvent->m_hProcess, (LPVOID)dwCodeAddr, 1, PAGE_READWRITE, &dwOldProtect);
	if (!ReadProcessMemory(pEvent->m_hProcess, (LPVOID)dwCodeAddr, &bBuffer, 1/*读取一个字节*/, &dwReadCount))
	{
		printf("要修改的内存地址无效\r\n");
		VirtualProtectEx(pEvent->m_hProcess, (LPVOID)dwCodeAddr, 1, dwOldProtect, &dwReadCount);
		return FALSE;
	}

	//保存原有数据


	//获取用户输入修改后的值
	scanf_s("%x", &szBuffer);
	

	//输入为空则退出
	if (szBuffer == NULL)
	{
		VirtualProtectEx(pEvent->m_hProcess, (LPVOID)dwCodeAddr, 1, dwOldProtect, &dwReadCount);
		return TRUE;
	}

	//输入转换为数值类型
	dwInputValue = szBuffer;

	//写入修改后的值
	if (!WriteProcessMemory(pEvent->m_hProcess, (LPVOID)dwCodeAddr, &dwInputValue, 1, &dwReadCount))
	{
		printf("修改后的值无写入失败\r\n");
		VirtualProtectEx(pEvent->m_hProcess, (LPVOID)dwCodeAddr, 1, dwOldProtect, &dwReadCount);
		return TRUE;
	}
	//刷新
	ShowTwoASM(pEvent);
// 
// 	//还原值
// 	if (!WriteProcessMemory(pEvent->m_hProcess, (LPVOID)dwCodeAddr, &bBuffer, 1, &dwReadCount))
// 	{
// 		printf("修改后的值无写入失败\r\n");
// 		VirtualProtectEx(pEvent->m_hProcess, (LPVOID)dwCodeAddr, 1, dwOldProtect, &dwReadCount);
// 		return TRUE;
// 	}


	//还原内存属性
	VirtualProtectEx(pEvent->m_hProcess, (LPVOID)dwCodeAddr, 2, dwOldProtect, &dwReadCount);


	
}

//d [addr]
BOOL CExceptEvent::DoShowData(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//d or d addr
	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	static DWORD dwLastAddr = pEvent->m_Context.Eip;
	static tagNormalBP *pNormalBP;

	DWORD dwDataAddr = NULL;
	if (2 == argc)
	{
		dwDataAddr = strtoul(&pszBuf[pargv[1]], NULL, 16);
		assert(dwDataAddr != ULONG_MAX);
	}
	else
	{
		dwDataAddr = dwLastAddr;
	}

	//读取128byte
#define MAXREAD  128
#define MAXLINE   16
	static unsigned char pBuf[MAXREAD];
	DWORD nRead = NULL;
	BOOL bRet = ReadProcessMemory(pEvent->m_hProcess,
		(LPVOID)dwDataAddr,
		pBuf,
		MAXREAD,
		&nRead);
	if (!bRet)
	{
		CMENU::ShowErrorMessage();
	}

	//更新记录
	dwLastAddr = dwDataAddr + nRead;

	//格式和显示
	int i = 0;
	int j = 0;
	sprintf_s(g_szBuf, MAXBUF, "%p  ", dwDataAddr);
	for (i = 0; i < MAXREAD; i++, dwDataAddr++)
	{
		//是否通过Break Point修改
		bRet = HasNormalBP(pEvent, dwDataAddr, &pNormalBP);
		if (bRet)
		{
			pBuf[i] = pNormalBP->oldvalue;
		}

		_snprintf(g_szBuf, MAXBUF, "%s%02X ",
			g_szBuf,
			pBuf[i]);
		if (0 == (i + 1) % MAXLINE
			&& i != 0
			&& i != MAXREAD - 1)
		{
			//显示ascii
			_snprintf(g_szBuf, MAXBUF, "%s  ", g_szBuf);
			for (j = i - MAXLINE + 1; j <= i; j++)
			{
				if (isprint(pBuf[j]))
				{
					_snprintf(g_szBuf, MAXBUF, "%s%c", g_szBuf, pBuf[j]);
				}
				else
				{
					_snprintf(g_szBuf, MAXBUF, "%s.", g_szBuf);
				}
			}

			//下一行
			_snprintf(g_szBuf, MAXBUF, "%s\r\n%p  ",
				g_szBuf,
				dwDataAddr + 1);
		}
	}

	_snprintf(g_szBuf, MAXBUF, "%s\r\n", g_szBuf);
	pEvent->m_pMenu->ShowInfo(g_szBuf);
	return TRUE;
}

/************************************************************************/
/*
功能：启用跟踪功能，
跟踪指定范围内的指令
Params：跟踪addrstart addrend
* /
/************************************************************************/
BOOL
CExceptEvent::DoTrace(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//跟踪addrstart addrend
	assert(argc >= 3);
	assert(pEvent != NULL);
	assert(pszBuf != NULL);

	DWORD dwAddrStart = strtoul(&pszBuf[pargv[1]], NULL, 16);
	DWORD dwAddrEnd = strtoul(&pszBuf[pargv[2]], NULL, 16);

	//实际上不需要检查这个，我们可以使用Mem BP的虚拟查询
	if (dwAddrStart < 0x10000
		|| dwAddrStart >= 0x80000000
		|| dwAddrEnd < 0x10000
		|| dwAddrEnd >= 0x80000000
		|| dwAddrStart > dwAddrEnd)
	{
		pEvent->m_pMenu->ShowInfo("Invalid Trace Range\r\n");
		return FALSE;
	}

	//设置内存断点,  bm 00400000 a len
	int argv[] = { 0, 3, 0x0C, 0x0E };
	sprintf_s(g_szBuf, MAXBUF, "bm %p a %d", dwAddrStart, dwAddrEnd - dwAddrStart);
	DoBM(pEvent, 4, argv, g_szBuf, TRUE);

	pEvent->m_dwTraceBegin = dwAddrStart;
	pEvent->m_dwTraceEnd = dwAddrEnd;

	return TRUE;
}

/************************************************************************/
/*
Function ：通过FS获得TIB                                                                 */
/************************************************************************/
DWORD
CExceptEvent::GetTIB(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	LDT_ENTRY ldtSelectorEntry;
	BOOL bRet = GetThreadSelectorEntry(
		pEvent->m_hThread,
		pEvent->m_Context.SegFs,
		&ldtSelectorEntry);
	if (!bRet)
	{
		CMENU::ShowErrorMessage();
		return 0;
	}

	//BaseHi(BYTE)  BaseMid(BYTE)  BaseLow(WORD)
	//32  24  16  8  0
	DWORD dwRet = 0;
	dwRet = ldtSelectorEntry.BaseLow;
	dwRet += (ldtSelectorEntry.HighWord.Bytes.BaseMid << 16);
	dwRet += (ldtSelectorEntry.HighWord.Bytes.BaseHi << 24);
	return dwRet;
}

/************************************************************************/
/*
Function : 显示SEH链
can also monitor SEH handler calling
by setting MemoryBP and NormalBP on the top most seh handler                                                                     */
/************************************************************************/
BOOL
CExceptEvent::DoShowSEH(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	assert(pEvent != NULL);
	g_szBuf[0] = '\0';

	DWORD dwTIB = GetTIB(pEvent);
	if (0 == dwTIB)
	{
		return FALSE;
	}

	BOOL bRet;
	tagSEH seh;

	bRet = ReadBuf(pEvent,
		pEvent->m_hProcess,
		(LPVOID)dwTIB,
		&seh,
		sizeof(tagSEH)
	);
	if (!bRet)
	{
		return FALSE;
	}

	//FS:[0]---> Pointer to Next SEH Record, 
	//           SEH Handler
	BOOL bTopmost = TRUE;
	tagSEH *pSEH = (tagSEH *)(seh.ptrNext);
	do
	{
		bRet = ReadBuf(pEvent,
			pEvent->m_hProcess,
			(LPVOID)pSEH,
			&seh,
			sizeof(tagSEH)
		);
		if (!bRet)
		{
			break;
		}

		//set normal bp and MEMBP at the topmost seh handler
		//but not a good idea to check within a loop, low efficiency
		if (/*bTopmost*/FALSE)
		{
			bTopmost = FALSE;

			//bp addr
			int argv[] = { 0, 3 };
			sprintf(g_szBuf, "bp %p", seh.dwHandler);
			pEvent->m_bTmpBP = TRUE;
			DoBP(pEvent, 2, argv, g_szBuf);

			//bm addr a len  (how long is okay??)
			int argv1[] = { 0, 3, 0x0C, 0x0E };       //this can be a const, used many times
			sprintf(g_szBuf, "bm %p a 4", seh.dwHandler);
			DoBM(pEvent, 4, argv1, g_szBuf, TRUE);

			sprintf(g_szBuf, "SEH Chain Updated*******\r\n");
		}

		_snprintf(g_szBuf, MAXBUF, "%sAddress: %p   SEH Handler: %p\r\n",
			g_szBuf,
			pSEH,
			seh.dwHandler
		);
		pSEH = (tagSEH *)seh.ptrNext;
	} while ((DWORD)pSEH != 0xFFFFFFFF);

	_snprintf(g_szBuf, MAXBUF, "%s\r\n", g_szBuf);
	pEvent->m_pMenu->ShowInfo(g_szBuf);

	return TRUE;
}

/************************************************************************/
/*
Function :在线程的FS上设置硬件断点：[0]
to monitor change of SEH Chain.
Be helpful for trace

Remarks  : we use HardWare BreakPoint to monitor,
so less DRX                                                                  */
/************************************************************************/
BOOL
CExceptEvent::MonitorSEH(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	DWORD dwTIB = GetTIB(pEvent);
	if (0 == dwTIB)
	{
		return FALSE;
	}

	//bh addr w 4
	int argv[] = { 0, 3, 0x0C, 0x0E };
	sprintf_s(g_szBuf, MAXBUF, "bh %p w 4", dwTIB);
	DoBH(pEvent, 4, argv, g_szBuf);

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
/************************************************************************/
/*
功能：判断是否调用dw Addr指向的指令
Params：pn Len用于接收指令大小
返回：如果是调用则返回TRUE，否则返回FALSE
004012B6  |.  FF15 A8514200 CALL DWORD PTR DS:[<&KERNEL32.GetVersion>;  kernel32.GetVersion
0040130E  |.  E8 9D2A0000   CALL testDbg.00403DB0                    ; \testDbg.00403DB0
*/
/************************************************************************/
BOOL
CExceptEvent::IsCall(CBaseEvent *pEvent, DWORD dwAddr, UINT *pnLen)
{
	assert(pEvent != NULL);
	assert(pnLen != NULL);

	const char *pszASM;
	pszASM = this->GetOneASM(pEvent, dwAddr, pnLen);

	if (strstr(pszASM, "call"))
	{
		return TRUE;
	}

	return FALSE;
}

/*
功能：判断dw Addr是否指向jxx指令
Params：pn Len用于接收指令大小
返回：如果是调用则返回TRUE，否则返回FALSE
*/
/************************************************************************/
BOOL
CExceptEvent::IsJxx(CBaseEvent *pEvent, DWORD dwAddr, UINT *pnLen)
{
	assert(pEvent != NULL);
	assert(pnLen != NULL);

	const char *pszASM;
	pszASM = this->GetOneASM(pEvent, dwAddr, pnLen);

	//" jmp", " jxx"
	if (strstr(pszASM, " j"))
	{
		return TRUE;
	}

	return FALSE;
}

/************************************************************************/
/*
功能：读取内存
考虑到内存断点，先禁用并重新启用内存断点。
*/
/************************************************************************/
BOOL
CExceptEvent::ReadBuf(CBaseEvent *pEvent,
	HANDLE hProcess,
	LPVOID lpAddr,
	LPVOID lpBuf,
	SIZE_T nSize)
{
	assert(pEvent != NULL);

	//以避免读取进程内存失败
	DWORD dwAddr = (DWORD)lpAddr;
	DWORD dwPageAddr = (dwAddr / m_dwPageSize) * m_dwPageSize;
	if (dwAddr + nSize >= dwPageAddr + m_dwPageSize)
	{
		nSize = dwPageAddr + m_dwPageSize - dwAddr;
	}


	//是否存在内存断点
	BOOL bReadable = FALSE;
	BOOL bRet;
	bReadable = IsPageReadable(pEvent, (DWORD)lpAddr);
	if (bReadable)
	{
		bRet = ReadProcessMemory(
			hProcess,
			lpAddr,
			lpBuf,
			nSize,
			NULL);

		if (!bRet)
		{
			CMENU::ShowErrorMessage();
		}
		else
		{
			return TRUE;
		}
	}

	//如果读取失败
	tagPageBP *ppageBP = NULL;
	DWORD dwOldProtect;
	BOOL  bHasMemBP = FALSE;
	bRet = HasMemBP(pEvent, (DWORD)lpAddr, &ppageBP);
	if (bRet)
	{
		bHasMemBP = TRUE;

		//需要恢复保护，（并添加PAGE READWRITE）
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)lpAddr,
			nSize,
			ppageBP->dwOldProtect,
			&dwOldProtect
		);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return FALSE;
		}
	}

	//读取
	bRet = ReadProcessMemory(hProcess, lpAddr, lpBuf, nSize, NULL);

	if (!bRet)
	{
		CMENU::ShowErrorMessage();
		return FALSE;
	}

	//重新启用内存断点
	if (bHasMemBP)
	{
		bRet = VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)lpAddr,
			nSize,
			ppageBP->dwNewProtect,
			&dwOldProtect
		);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
			return FALSE;
		}
	}

	return TRUE;
}

/************************************************************************/
/*
功能：删除用于追踪的Mem BP通常在卸载dll时调用                                                                  */
/************************************************************************/
BOOL
CExceptEvent::RemoveTrace(CBaseEvent *pEvent, tagModule *pModule)
{
	//bm addr a len
	//bmc id
	assert(pEvent != NULL);
	assert(pModule != NULL);

	//find id first, 
	DWORD dwAddr = pModule->dwBaseOfCode;
	DWORD dwSize = pModule->dwSizeOfCode;
	tagMemBP *pMemBP = NULL;
	int argv[] = { 0, 4 };    //bmc id
	int i = 0;

	list<tagMemBP>::iterator itMemBP;
	for (itMemBP = m_lstMemBP.begin();
		itMemBP != m_lstMemBP.end();
		itMemBP++, i++)
	{
		pMemBP = &(*itMemBP);
		if (pMemBP->dwAddr == dwAddr
			&& pMemBP->dwSize == dwSize
			&& pMemBP->bTrace)
		{
			sprintf(g_szBuf, "bmc %d", i);
			((CDebugger *)pEvent)->DoBMC(2, argv, g_szBuf);
			break;
		}
	}

	return TRUE;
}

/************************************************************************/
/*
功能：预取几条指令直到调用或jmp指令，
用于追踪，使追踪更快                                                                 */
/************************************************************************/
void
CExceptEvent::PrefetchCode(CBaseEvent *pEvent)
{
	assert(pEvent != NULL);

	int pargv[] = { 0, 3 };

	DWORD dwAddr = pEvent->m_Context.Eip;
	UINT nCodeLen = 0;
	const char *pszASM;
	while (TRUE)
	{
		pszASM = this->GetOneASM(pEvent, dwAddr, &nCodeLen);
		pEvent->m_pMenu->TraceLog(pszASM);

		if (dwAddr > SYSSPACE)
		{
			int i = 0;
		}

#if 0   //已经获取到asm
		if (IsCall(pEvent, dwAddr, &nCodeLen)
			|| IsJxx(pEvent, dwAddr, &nCodeLen))
#endif
			if (strstr(pszASM, " call")
				|| strstr(pszASM, " j")
				|| strstr(pszASM, " ret"))
			{
				//设置tmp普通BP
				pEvent->m_bTmpBP = TRUE;
				sprintf(g_szBuf, "bp %p", dwAddr);
				DoBP(pEvent, 2, pargv, g_szBuf);

				break;
			}

		dwAddr += nCodeLen;
	}
}

/************************************************************************/
/*
功能：根据disasmed指令获取API名称
/************************************************************************/
BOOL CExceptEvent::GetAPIName(CBaseEvent *pEvent,
	DWORD dwCode,
	const char *pszBuf,
	char szAPIName[])
{
	//strstr返回指向字符串中的搜索字符串的第一个匹配项的指针。
	const char *pIndirect = strstr(pszBuf, "[");
	const char *pIndirectReg = strstr(pszBuf, "[e");
	const char *pCall = strstr(pszBuf, "call");
	const char *pCallReg = strstr(pszBuf, "call e");
	const char *pJxx = strstr(pszBuf, "j");
	char szType[8];
	DWORD dwAddr;
	DWORD dwAddrIndir;
	DWORD dwOldProtect;
	BOOL  bRet;

	//不是寄存器
	if (pIndirect != NULL && NULL == pIndirectReg)
	{
		dwAddrIndir = strtoul(pIndirect + 1, NULL, 16);

		//获取并保存原有属性dwOldProtect
		bRet = VirtualProtectEx(pEvent->m_hProcess, (LPVOID)dwAddrIndir, MAX_INSTRUCTION, PAGE_EXECUTE_READ, &dwOldProtect);
		if (!bRet)
		{
			CMENU::ShowErrorMessage();
		}

		//读取内存
		ReadBuf(pEvent, pEvent->m_hProcess, (LPVOID)dwAddrIndir, &dwAddr, sizeof(DWORD));

		//恢复原属性
		VirtualProtectEx(pEvent->m_hProcess,
			(LPVOID)dwAddrIndir,
			MAX_INSTRUCTION,
			dwOldProtect,
			&dwOldProtect
		);

	}
	else if (pCall != NULL
		&& NULL == pCallReg)
	{
		sscanf(pCall, "%s%p", szType, &dwAddr);
	}
	else if (pJxx != NULL)
	{
		if (strstr(pJxx, " e"))
		{
			return FALSE;
		}
		sscanf(pJxx, "%s%p", szType, &dwAddr);
	}
	else
	{
		return FALSE;
	}

	if (NULL == dwAddr
		|| ULONG_MAX == dwAddr)
	{
		//[ebx] not done yet
		return FALSE;
	}

	//判断是否在同一模块中
	tagModule addrModule;
	bRet = IsSameModule(pEvent, dwCode, dwAddr, &addrModule);
	if (!bRet)
	{
		return GetAPINameFromOuter(pEvent, dwAddr, &addrModule, szAPIName);
	}


	//在同一个模块中
	UINT nSize; 
	const char *pszASM = GetOneASM(pEvent, dwAddr, &nSize, FALSE);
	if (strstr(pszASM, " j")
		|| strstr(pszASM, " call"))
	{
		//递归获取api名称
		return GetAPIName(pEvent, dwAddr, pszASM, szAPIName);
	}

	//现在是否出口，作为其他模块处理自己
	return GetAPINameFromOuter(pEvent, dwAddr, &addrModule, szAPIName);
}

/************************************************************************
Function : 从模块的导出表中获取API名称
/************************************************************************/
BOOL CExceptEvent::GetAPINameFromOuter(CBaseEvent *pEvent, DWORD dwAddr, tagModule *pModule, char szAPIName[])
{
	
	if (strstr(pModule->szName, ".exe"))
	{
		return FALSE;
	}

	//模块的导出信息是否已经获得
	char *pszExportInfo = NULL;
	map<char *, char *, Compare>::iterator itModule;
	itModule = m_mapModule_Export.find(pModule->szName);
	if (itModule == m_mapModule_Export.end())
	{
		//现在搜索目标模块的导出目录，从导出表获取信息
		::SetImageBuf(pModule->hFile);
		::GetExportInfo(&pszExportInfo);

		//没有导出信息
		if (NULL == pszExportInfo)
		{
			return FALSE;
		}
		m_mapModule_Export[pModule->szName] = pModule->szName;
	}

	dwAddr = dwAddr - pModule->modBaseAddr + pModule->dwImageBase;
	char *pszName = /*PE*/::GetAPIName(dwAddr);
	if (NULL == pszName)
	{
		return FALSE;
	}

	sprintf(szAPIName, "%s  !  %s", pModule->szName, pszName);
	return TRUE;
}

/************************************************************************/
/*
Function: 判断dwCode，dwAddr是否在同一模块中
Params：pModule用于接收有关dwAddr的模块信息
如果dwAddr在主应用程序中，pModule设置为NULL！

返回：如果模块相同，则返回TRUE
否则，返回FALSE                                                                  */
/************************************************************************/
BOOL
CExceptEvent::IsSameModule(CBaseEvent *pEvent, DWORD dwCode, DWORD dwAddr, tagModule *pModule)
{
	BOOL bRet = ((CDebugger *)pEvent)->GetModule(pEvent, dwAddr, pModule);
	if (!bRet)
	{
		//无效
		return FALSE;
	}

	//
	if (dwCode >= pModule->modBaseAddr
		&& dwCode < pModule->modBaseAddr + pModule->modBaseSize)
	{
		return TRUE;
	}

	return FALSE;
}




BOOL CExceptEvent::dump(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf)
{
	//dump前不能有断点

	char* strPath = pEvent->m_path;

	HANDLE hFile = pEvent->m_hFileProcess;
	//CloseHandle(hFile);
	//HANDLE hFile = CreateFile(strPath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	

		

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("创建文件失败,\n");
		if (GetLastError() == 0x00000050) {
			printf("文件已存在\n");
		}
		return FALSE;
	}
	IMAGE_DOS_HEADER dos;//dos头

	IMAGE_NT_HEADERS nt;
	//读dos头
	if (ReadProcessMemory(pEvent->m_hProcess, (LPVOID)pEvent->m_dwBaseOfImage, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
	{
		return FALSE;
	}


	//读nt头
	if (ReadProcessMemory(pEvent->m_hProcess, (BYTE *)pEvent->m_dwBaseOfImage + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE)
	{
		return FALSE;
	}


	//读取节区并计算节区大小
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//读取节区
	if (ReadProcessMemory(pEvent->m_hProcess,
		(BYTE *)pEvent->m_dwBaseOfImage + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
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

	if (ReadProcessMemory(pEvent->m_hProcess, (BYTE *)pEvent->m_dwBaseOfImage + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return FALSE;
	}

	nt.OptionalHeader.ImageBase = (DWORD)pEvent->m_dwBaseOfImage;
	//保存NT头
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//保存节区
	memcpy(bpMem + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS), Sections, secNum * sizeof(IMAGE_SECTION_HEADER));

	for (int i = 0; i < secNum; ++i)
	{
		if (ReadProcessMemory(
			pEvent->m_hProcess, (BYTE *)pEvent->m_dwBaseOfImage + Sections[i].VirtualAddress,
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