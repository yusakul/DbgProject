
#pragma once

#include "BaseEvent.h"

/************************************************************************
处理：断点，单步，访问冲突 和硬件断点，存储器断点* /
/************************************************************************/


//关于内存断点的结构
typedef struct _tagMemBP
{
#define MEMBP_ACCESS 0		 //访问断点
#define MEMBP_WRITE  1		 //写入断点
#define MEMBP_EXECUTE  2	 //写入断点

	DWORD dwAddr;
	DWORD dwSize;
	BOOL  bTrace;        //用于追踪
	DWORD dwType;        //断点类型：访问、写入
	bool operator == (const _tagMemBP &obj)
	{
		return ((dwAddr == obj.dwAddr)
			&& (dwSize == obj.dwSize)
			&& (dwType == obj.dwType)
			&& (bTrace == obj.bTrace)
			);
	}
}tagMemBP;


//各分页按照重定位表的结构来维护页内断点信息

//内存断点在分页内的表示
typedef struct _tagMemBPInPage
{
	WORD wOffset;       //在页内的偏移
	WORD wSize;         //在页内的大小
	BOOL bTrace;        //用于追踪
	bool operator == (const _tagMemBPInPage &obj)
	{
		return ((wOffset == obj.wOffset)
			&& (wSize == obj.wSize)
			);
	}
}tagMemBPInPage;

//分页与断点
typedef struct _tagPageBP
{
	DWORD dwPageAddr;   //分页地址
	DWORD dwOldProtect;
	DWORD dwNewProtect;
	list<tagMemBPInPage> lstMemBP;
}tagPageBP;

//////////////////////////////////////////////////////////////////////////
//关于普通断点的结构
//这里称为普通断点，一般断点，而不说是INT3，或者CC，是因为凡是单字节的特权指令，都可以用来处理。
typedef struct _tagNormalBP
{
	byte oldvalue;			//原数据
	byte bTmp : 1;          //临时断点，Debugger内部设置
	byte bPerment : 1;		//用户通过bp设置
	byte bDisabled : 1;     //用于处理对int3，设置普通断点
}tagNormalBP;

//////////////////////////////////////////////////////////////////////////
//关于硬件的结构
typedef struct _tagDR7
{
	unsigned /*char*/ GL0 : 2;
	unsigned /*char*/ GL1 : 2;
	unsigned /*char*/ GL2 : 2;
	unsigned /*char*/ GL3 : 2;
	unsigned /*char*/ GLE : 2;     // 11
	unsigned /*char*/ Reserv0 : 3; // 001
	unsigned /*char*/ GD : 1;     // 0
	unsigned /*char*/ Reserv1 : 2; //00
	unsigned /*char*/ RW0 : 2;
	unsigned /*char*/ LEN0 : 2;
	unsigned /*char*/ RW1 : 2;
	unsigned /*char*/ LEN1 : 2;
	unsigned /*char*/ RW2 : 2;
	unsigned /*char*/ LEN2 : 2;
	unsigned /*char*/ RW3 : 2;
	unsigned /*char*/ LEN3 : 2;
#define DR7INIT 0x00000700  //Reserv1:00 GD:0 Reserv0:001  GELE:11
}tagDR7;

typedef struct _tagDR6
{
	unsigned /*char*/ B0 : 1;
	unsigned /*char*/ B1 : 1;
	unsigned /*char*/ B2 : 1;
	unsigned /*char*/ B3 : 1;
	unsigned /*char*/ Reserv0 : 8;      //11111111
	unsigned /*char*/ Reserv1 : 1;    //0
	unsigned /*char*/ BD : 1;
	unsigned /*char*/ BS : 1;
	unsigned /*char*/ BT : 1;
	unsigned /*char*/ Reserv2 : 16;              //set to 1
}tagDR6;

typedef struct _tagHWBP
{
	DWORD dwAddr;
	DWORD dwType;
	DWORD dwLen;
	DWORD *pDRAddr[4];      //for DR0 ~ DR3
	DWORD RW[4];          //for DR7:RW0 ~ RW3
#define HWBP_EXECUTE 0  //只执行指令
#define HWBP_WRITE   1  //只数据写入
#define HWBP_ACCESS  3  //访问 或 执行
#define STREXECUTE  "Execute"	//执行
#define STRWRITE    "Write"		//写入
#define STRACCESS   "Access"	//访问
}tagHWBP;

//////////////////////////////////////////////////////////////////////////
//请参阅IA1.pdf 3.4.3 EFLAG寄存器
typedef struct _tagEFlags
{
	unsigned /*char*/ CF : 1;
	unsigned /*char*/ Reserv1 : 1; //1
	unsigned /*char*/ PF : 1;
	unsigned /*char*/ Reserv2 : 1; //0
	unsigned /*char*/ AF : 1;
	unsigned /*char*/ Reserv3 : 1; //0
	unsigned /*char*/ ZF : 1;
	unsigned /*char*/ SF : 1;
	unsigned /*char*/ TF : 1;
	unsigned /*char*/ IF : 1;
	unsigned /*char*/ DF : 1;
	unsigned /*char*/ OF : 1;
	//others
	unsigned /*char*/ IOPL : 2;
	unsigned /*char*/ NT : 1;
	unsigned /*char*/ Reserv4 : 1; //0
	unsigned /*char*/ Remain : 16;
}tagEFlags;

//////////////////////////////////////////////////////////////////////////
//about seh
typedef struct _tagSEH
{
	DWORD ptrNext;      //pointer to next seh record
	DWORD dwHandler;    //SEH handler
}tagSEH;

//////////////////////////////////////////////////////////////////////////


//条件断点
typedef	struct tagTJBP
{
	DWORD dwAddr;
	char strExx[4];		//寄存器
	char  strSymbol[4];	//符号
	DWORD   dwValue;	//值
}tagTJBP;


class CExceptEvent : public CBaseEvent
{
public:
	CExceptEvent();
	virtual ~CExceptEvent();

public:
	//debug event
	virtual DWORD OnAccessViolation(CBaseEvent *pEvent);
	virtual DWORD OnBreakPoint(CBaseEvent *pEvent);
	virtual DWORD OnSingleStep(CBaseEvent *pEvent);

	//user input
	virtual BOOL DoStepOver(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/);
	virtual BOOL DoStepInto(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/);
	virtual BOOL DoGo(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL DoBP(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	BOOL DoBPtemp(CBaseEvent * pEvent, DWORD dwAddr);
	virtual BOOL DoBPL(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/);
	virtual BOOL DoBPC(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);

	virtual BOOL DoBM(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf, BOOL bTrace);
	virtual BOOL DoBML(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL DoBMPL(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL DoBMC(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);

	virtual BOOL DoBH(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL DoBHL(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/);
	virtual BOOL DoBHC(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);

	virtual BOOL DoBPtj(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);//条件断点
	virtual BOOL dump(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);


	//show
	virtual BOOL DoShowData(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL DoShowASM(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL DoModifyOpCode(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual void ShowTwoASM(CBaseEvent *pEvent, DWORD dwAddr = NULL);
	virtual void DoShowRegs(CBaseEvent *pEvent);
	virtual const char * ShowOneASM(CBaseEvent *pEvent, DWORD dwAddr = NULL,
		UINT *pnCodeSize = NULL);
	virtual const char * GetOneASM(CBaseEvent *pEvent, DWORD dwAddr = NULL,
		UINT *pnCodeSize = NULL, BOOL bGetAPIName = TRUE);


	//extended function
	virtual BOOL DoTrace(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL RemoveTrace(CBaseEvent *pEvent, tagModule *pModule);
	virtual BOOL DoShowSEH(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);
	virtual BOOL MonitorSEH(CBaseEvent *pEvent);
	virtual DWORD GetTIB(CBaseEvent *pEvent);

	//
	virtual BOOL ReadBuf(CBaseEvent *pEvent, HANDLE hProcess, LPVOID lpAddr, LPVOID lpBuf, SIZE_T nSize);
protected:
	//关于断点
	BOOL CheckHitMemBP(CBaseEvent *pEvent, DWORD dwAddr, tagPageBP *ppageBP);
	BOOL CheckBMValidity(CBaseEvent *pEvent, tagMemBP *pMemBP);
	BOOL IsPageValid(CBaseEvent *pEvent, DWORD dwAddr);
	BOOL IsPageReadable(CBaseEvent *pEvent, DWORD dwAddr);
	BOOL HasMemBP(CBaseEvent *pEvent, DWORD dwAddr, tagPageBP **ppPageBP);
	BOOL HasNormalBP(CBaseEvent *pEvent, DWORD dwAddr, tagNormalBP **ppNormalBP);
	BOOL HasOtherMemBP(CBaseEvent *pEvent, DWORD dwPageAddr, tagPageBP **ppPageBP, DWORD *pnTotal);
	BOOL SetHWBP(CBaseEvent *pEvent, tagHWBP *pHWBP);
	BOOL HasHitHWBP(CBaseEvent *pEvent);
	BOOL CheckHitTJBP(CBaseEvent *pEvent ,DWORD dwAddr);		//是否符合条件断点

	virtual BOOL IsCall(CBaseEvent *pEvent, DWORD dwAddr, UINT *pnLen);	//是否是调用函数
	virtual BOOL IsJxx(CBaseEvent *pEvent, DWORD dwAddr, UINT *pnLen);	//是否是跳转
	virtual BOOL GetAPIName(CBaseEvent *pEvent, DWORD dwCode, const char *pszBuf, char szAPIName[]);
	virtual BOOL GetAPINameFromOuter(CBaseEvent *pEvent, DWORD dwAddr, tagModule *pModule, char szAPIName[]);
	virtual BOOL IsSameModule(CBaseEvent *pEvent, DWORD dwCode, DWORD dwAddr, tagModule *pModule);

	

	//用于追踪
	virtual void PrefetchCode(CBaseEvent *pEvent);

protected:
	list<tagMemBP> m_lstMemBP;                 //独立的内存断点
	map<DWORD, tagPageBP> m_mapPage_PageBP;    //各分页维护的断点

	map<DWORD, tagNormalBP> m_mapAddr_NormBP;  //一般断点

	vector<tagTJBP>m_vecTJBP;	//条件断点

	map<char *, char *, Compare> m_mapModule_Export;  //模块的导出信息

	DWORD m_dwPageSize;

	//用于删除重复指令，如repxx
	char m_szLastASM[MAXBYTE];
};

