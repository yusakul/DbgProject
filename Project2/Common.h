#pragma once
#include <windows.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <map>
#include <list>
#include <vector>
#include <algorithm>


#include "Decode2Asm.h"
#pragma comment(lib,"MyDisAsm.lib")


using namespace std;

#define MAXBUF  (1024 * 100)
extern char g_szBuf[MAXBUF];

//////////////////////////////////////////////////////////////////////////
//for map<const char *, value>
class Compare
{
public:
	bool operator() (const char * pszSRC, const char * pszDST) const
	{
		return _stricmp(pszSRC, pszDST) < 0;
	}
};

//////////////////////////////////////////////////////////////////////////
//模块加载结构
typedef struct _tagModule
{
	DWORD   dwImageBase;    //默认加载地址
	DWORD   modBaseAddr;    //实际加载的地址
	DWORD   modBaseSize;
	DWORD   dwOEP;
	HANDLE  hFile;          //LOAD_DLL_DEBUG_INFO
	DWORD   dwBaseOfCode;
	DWORD   dwSizeOfCode;
	char   szName[MAX_MODULE_NAME32 + 1];
	char   szPath[MAX_PATH];
}tagModule;

//原型
extern "C" void __stdcall Decode2AsmOpcode(IN PBYTE pCodeEntry,   // 需要解析指令地址
	OUT char* strAsmCode,        // 得到反汇编指令信息
	OUT char* strOpcode,         // 解析机器码信息
	OUT UINT* pnCodeSize,        // 解析指令长度
 	IN UINT nAddress);

void
SafeClose(HANDLE handle);

/************************************************************************/
/*
Function :尝试将指定的文件加载到内存中，
/************************************************************************/
BOOL
LoadFile(char *pszFileName, char **ppFileBuf, long *pnFileSize);

