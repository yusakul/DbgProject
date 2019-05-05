#ifndef UI_H_5B3FA45C_79E7_485d_BEAB_07CFCA68BE92
#define UI_H_5B3FA45C_79E7_485d_BEAB_07CFCA68BE92

#include "Common.h"

/************************************************************************/
/* Encapsulation for UI Related
like user input, info alert, file selection                         */
/************************************************************************/
class CMENU
{
public:
	CMENU();
	virtual ~CMENU();

public:
	//display info
	virtual void ShowMainMenu(void);
	static void ShowInfo(const char *pszInfo);
	static void LogInfo(const char *pszInfo, HANDLE hFile);
	static void ShowErrorMessage();

	//
	virtual void ExportScript();
	virtual void ImportScript();
	virtual void Log();
	virtual void PreTrace();
	virtual void TraceLog(const char *pszInfo);

	//
	virtual BOOL SelectFile(char *pszPath, SIZE_T nMaxPath = MAX_PATH);

	//
	virtual void GetCH(char *pch);

	/************************************************************************/
	/*
	Function : get input from user, and decode
	Params   : pargc used to know how many words
	pargv used to receive every start poisition in pszBuf
	pszBuf used to receive the input
	word1 NULL word2 NULL word3 NULL....*/
	/************************************************************************/
	virtual void GetInput(OUT int *pargc,
		OUT int pargv[],
		IN char *pszBuf,
		IN SIZE_T nMaxBuf);

protected:
	static BOOL m_bLog;     //whether log all the operation
	char *m_pFileBuf;       //for script file
	long m_nFileSize;       //for script file
	BOOL m_bImport;         //whether import script
	BOOL m_bTrace;          //whether trace
private:
};

#endif