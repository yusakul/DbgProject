// DllEvent.h: interface for the CDllEvent class.
//
//////////////////////////////////////////////////////////////////////


#pragma once
#include "LordPe.h"

#include "BaseEvent.h"

/************************************************************************/
/*处理有关Dll加载，卸载的事件
还包括Out Put Debug String                             */
/************************************************************************/
class CDllEvent : public CBaseEvent
{
public:
	CDllEvent();
	virtual ~CDllEvent();

public:
	//debug event
	virtual DWORD OnOutputString(CBaseEvent *pEvent);
	virtual DWORD OnUnload(CBaseEvent *pEvent);
	virtual DWORD OnLoad(CBaseEvent *pBaseEvent);

	//for module
	virtual BOOL DoListModule(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/);
	virtual BOOL GetModuleInfo(CBaseEvent *pBaseEvent, tagModule *pModule);
	//模块导入表
	BOOL DoListModuleImport(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/);
	//模块导出表
	BOOL DoListModuleExport(CBaseEvent *pEvent/*, int argc, int pargv[], const char *pszBuf*/);
	CLordPe* m_pLordPe;//解析pe类指针


	//for trace
	virtual BOOL DoTrace(CBaseEvent *pEvent, int argc, int pargv[], const char *pszBuf);

	//for API Name
	virtual BOOL GetModule(CBaseEvent *pEvent, DWORD dwAddr, tagModule *pModule);

protected:
	map<DWORD, tagModule> m_mapBase_Module;  //for loaded module
	map<const char *, const char *, Compare> m_mapName_Module;  //used to exclude from tracing
};

