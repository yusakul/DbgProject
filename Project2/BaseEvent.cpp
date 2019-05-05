// BaseEvent.cpp: implementation of the CBaseEvent class.
//
//////////////////////////////////////////////////////////////////////

#include "BaseEvent.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CBaseEvent::CBaseEvent()
{
	m_hProcess = NULL;
	m_hThread = NULL;
	ZeroMemory(&m_debugEvent, sizeof(DEBUG_EVENT));
	ZeroMemory(&m_Context, sizeof(CONTEXT));

	m_pMenu = NULL;
	m_pMenu = new CMENU();
	assert(m_pMenu != NULL);

	m_bTalk = FALSE;

	m_dwAddr = NULL;
	m_dwFS = NULL;

	m_dwBaseOfImage = NULL;
	m_dwSizeOfImage = NULL;
	m_dwBaseOfCode = NULL;
	m_dwSizeOfCode = NULL;

	m_bAccessVioTF = FALSE;
	m_bNormalBPTF = FALSE;
	m_bUserTF = FALSE;
	m_bHWBPTF = FALSE;
	m_bStepOverTF = FALSE;
	m_bTraceTF = FALSE;
	m_bTJBPTF = FALSE;

	m_bTmpBP = FALSE;
	m_bTrace = FALSE;
	m_bTraceAll = FALSE;
	m_dwTraceBegin = NULL;
	m_dwTraceEnd = NULL;

	m_dwLastAddr = NULL;
}

CBaseEvent::~CBaseEvent()
{
	if (m_pMenu != NULL)
	{
		delete m_pMenu;
		m_pMenu = NULL;
	}

	SafeClose(m_hProcess);
	SafeClose(m_hThread);
}

//////////////////////////////////////////////////////////////////////////
