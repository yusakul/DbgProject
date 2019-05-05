#pragma once

#include "Menu.h"

//调试事件的封装，作为基类                                                                    

class CBaseEvent
{
public:
	CBaseEvent();
	virtual ~CBaseEvent();

public:
	//调试事件相关
	DEBUG_EVENT m_debugEvent;		//调试事件对象
	CONTEXT m_Context;				//线程上下文
	HANDLE m_hProcess;				
	HANDLE m_hThread;

	DWORD  m_dwOEP;         //程序入口地址
	DWORD  m_dwBaseOfImage; //
	DWORD  m_dwSizeOfImage; //
	DWORD  m_dwBaseOfCode;  //
	DWORD  m_dwSizeOfCode;  //
	HANDLE m_hFileProcess;  //
	DWORD  m_dwFS;          //避免频繁询问TIB

	CMENU *m_pMenu;			//主菜单类指针
	BOOL m_bTalk;           //是否与用户进行交互，用户输入
	DWORD m_dwAddr;         //需要处理的地址

	BOOL  m_bAccessVioTF;   //访问冲突的单步骤
	BOOL  m_bNormalBPTF;    //普通断点单步
	BOOL  m_bUserTF;        //用户设置的TF
	BOOL  m_bHWBPTF;        //用于硬件断点
	BOOL  m_bStepOverTF;    //用于单步步过
	BOOL  m_bTraceTF;       //用于追踪
	BOOL  m_bTJBPTF;	//条件断点

	BOOL  m_bTmpBP;         //临时普通断点

	DWORD m_dwTraceBegin;   //指定要跟踪的范围
	DWORD m_dwTraceEnd;
	BOOL  m_bTrace;         //用于追踪
	BOOL  m_bTraceAll;      //跟踪所有模块

	DWORD m_dwLastAddr;     //保存t，p异常代码

	
	char m_path[MAX_PATH];	//调试进程的路径名

};
