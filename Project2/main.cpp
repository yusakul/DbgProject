#include "Debugger.h"


int main(void)
{
	CDebugger *pDebugger = CDebugger::CreateSystem();
	if (NULL == pDebugger)
	{
		return -1;
	}

	pDebugger->Run();
	pDebugger->DestorySystem();

	return 0;
}