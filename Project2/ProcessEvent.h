// ProcessEvent.h: interface for the CProcessEvent class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PROCESSEVENT_H__FAFADB88_BC73_446F_BE60_76C8F21085E9__INCLUDED_)
#define AFX_PROCESSEVENT_H__FAFADB88_BC73_446F_BE60_76C8F21085E9__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "BaseEvent.h"

/************************************************************************/
/* Deal with Process (Thead) Related, like Create, Exit,                                                                  */
/************************************************************************/
class CProcessEvent : public CBaseEvent
{
public:
	CProcessEvent();
	virtual ~CProcessEvent();

public:
	virtual DWORD OnExitProcess(const CBaseEvent *pEvent);
	virtual DWORD OnExitThread(const CBaseEvent *pEvent);
	virtual DWORD OnCreateThread(const CBaseEvent *pEvent);
	virtual DWORD OnCreateProcess(CBaseEvent *pEvent);
};

#endif // !defined(AFX_PROCESSEVENT_H__FAFADB88_BC73_446F_BE60_76C8F21085E9__INCLUDED_)
