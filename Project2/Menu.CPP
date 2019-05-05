#include "Menu.h"

//用于记录命令历史记录
static char gs_szCommand[MAXBUF];

static HANDLE g_hLog = INVALID_HANDLE_VALUE;      //log for all operation
static HANDLE g_hTraceLog = INVALID_HANDLE_VALUE;      //log for trace
													   //////////////////////////////////////////////////////////////////////////
CMENU::CMENU()
{
	m_pFileBuf = NULL;
	m_bImport = FALSE;
	m_bTrace = FALSE;
	m_nFileSize = NULL;
}

BOOL CMENU::m_bLog = FALSE;

CMENU::~CMENU()
{
	SafeClose(g_hLog);
	SafeClose(g_hTraceLog);

	if (m_pFileBuf != NULL)
	{
		free(m_pFileBuf);
		m_pFileBuf = NULL;
	}
}

void CMENU::ShowMainMenu(void)
{
	printf(
		"============DebProject=======\r\n"
		"---------1. 调试进程---------\r\n"
		"---------2. 附加进程---------\r\n"
		"---------3. 帮    助---------\r\n"
		"---------0. 退    出---------\r\n"
		"=============================\r\n"
		"输入选项:\r\n");
}

/*获取用户选择*/
void CMENU::GetCH(char *pch)
{
	scanf_s("%c", pch, 2);
	fflush(stdin); //清空输入缓冲区
}

/************************************************************************
功能：获取用户输入，并将它们逐个存储到pszBuf中
pargc：接收的个数
pargv：接收的字符串数组指针
pszBuf：用来接收输入的缓存
nMaxBuf：最大个数
************************************************************************/
void
CMENU::GetInput(OUT int *pargc,
	OUT int pargv[],
	IN char *pszBuf,
	IN SIZE_T nMaxBuf)
{
	char szBuf[MAXBYTE] = {};
	int nRet;
	int nCount = 0;
	int nIndex = 0;
	char ch;
	static int nCurPos = 0; //用于导入脚本

	ShowInfo(">> ");
	while (TRUE)
	{
		if (m_bImport)	//是否导入脚本
		{
			//从文件中读取
			nRet = sscanf_s(&m_pFileBuf[nCurPos], "%255s", szBuf, (unsigned)_countof(szBuf));
		}
		else//用户输入
		{
			nRet = scanf_s("%255s", szBuf, MAXBYTE);
		}

		if (EOF == nRet)
		{
			break;
		}

		//以避免缓冲区溢出
		if (nIndex + strlen(szBuf) + 1 > nMaxBuf)
		{
			break;
		}

		//用于记录到命令历史记录中
		strcat(gs_szCommand, szBuf);
		strcat(gs_szCommand, " ");

		//命令解码并保存
		strcpy(&pszBuf[nIndex], szBuf);
		pargv[nCount] = nIndex;
		nIndex += (strlen(szBuf) + 1);
		nCount++;

		//记录所有操作
		if (m_bLog)
		{
			LogInfo(szBuf, g_hLog);
			LogInfo(" ", g_hLog);
		}

		//用于导入脚本
		if (m_bImport)
		{
			printf("%s ", szBuf);
			nCurPos += (strlen(szBuf) + 1);
			if ('\n' == m_pFileBuf[nCurPos])
			{
				ch = '\n';
				nCurPos++;
				printf("\r\n");
			}

			//停在es
			if (0 == strncmp(&m_pFileBuf[nCurPos], "es", 2))
			{
				m_bImport = FALSE;
			}
		}
		else
		{
			ch = getchar();
		}

		if ('\n' == ch)
		{
			strcat(gs_szCommand, "\n");

			if (m_bLog)
			{
				LogInfo("\r\n", g_hLog);
			}

			break;
		}
	}

	*pargc = nCount;

	fflush(stdin);
}

//选择要调试的文件
BOOL CMENU::SelectFile(char *pszFilePath, SIZE_T nMaxPath)
{
	BOOL bRet = TRUE;
	char appPath[MAX_PATH] = { 0 }; //应用程序路径

	//创建文件对话框对象
	OPENFILENAME ofn;

	RtlZeroMemory(&ofn, sizeof(ofn));	//内存清零
	ofn.lStructSize = sizeof(ofn);		//结构体的大小
	//过滤文件类型，lpstrFilter：一个空字符结束的过滤字符串的一个缓冲。缓冲中的最后一个字串须以两个NULL字符结束，在编程中使用/0/0。
	ofn.lpstrFilter = TEXT("All Files(*.*)\0*.*\0");

	ofn.lpstrFile = appPath;		//将地址赋值给lpstrFilter
	ofn.nMaxFile = MAX_PATH;		//路径长度
	ofn.Flags = OFN_PATHMUSTEXIST	/*指定用户仅能输入的路径和文件名*/
		| OFN_HIDEREADONLY			/*隐藏只读复选框。*/
		| OFN_LONGNAMES;			/*对话框使用长文件名*/

	//打开对话框
	bRet = GetOpenFileName(&ofn);
	if (bRet)
	{
		lstrcpynA(pszFilePath, appPath, nMaxPath);	//备份路径
	}

	return bRet;
}

static DWORD gs_dwReadWrite;
static BOOL gs_bRet;
//将信息记录到文件中                                                             
void CMENU::LogInfo(const char *pszInfo, HANDLE hFile)
{
	gs_bRet = WriteFile(hFile,
		pszInfo,
		strlen(pszInfo),
		&gs_dwReadWrite,
		NULL);
	if (!gs_bRet)
	{
		printf("记录失败\r\n");
	}
}

//显示信息
void CMENU::ShowInfo(const char *pszInfo)
{
	printf(pszInfo);

	//是否记录
	if (m_bLog)
	{
		LogInfo(pszInfo, g_hLog);
	}
}

//显示错误信息
void CMENU::ShowErrorMessage()
{
	LPVOID lpMsgBuf;
	//将GetLastError函数得到的错误信息代码转化成字符串信息的函数。
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		::GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //默认语言
		(LPSTR)&lpMsgBuf,
		0,
		NULL
	);

	ShowInfo((const char *)lpMsgBuf);	//显示错误信息
	ShowInfo("\r\n");
	LocalFree(lpMsgBuf);
}

/************************************************************************/
/*
Function : export the user's command history                           */
/************************************************************************/
void CMENU::ExportScript()
{
	BOOL bRet;
	DWORD dwWrite;
	char szFilePath[MAX_PATH];
	bRet = SelectFile(szFilePath, MAX_PATH);
	if (!bRet)
	{
		ShowErrorMessage();
		return;
	}

	HANDLE hFile = CreateFile(szFilePath,
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		ShowErrorMessage();
		return;
	}

	bRet = WriteFile(hFile,
		gs_szCommand,
		strlen(gs_szCommand),
		&dwWrite,
		NULL);
	if (!bRet)
	{
		ShowErrorMessage();
	}

	if (hFile != NULL)  //what about invalid
	{
		CloseHandle(hFile);
		hFile = NULL;
	}
}

/************************************************************************/
/*
Function :加载并执行之前保存的脚本                                                                    */
/************************************************************************/
void CMENU::ImportScript()
{
	BOOL bRet;
	char szFilePath[MAX_PATH];
	bRet = SelectFile(szFilePath, MAX_PATH);
	if (!bRet)
	{
		ShowErrorMessage();
		return;
	}

	//load file into memory
	if (!LoadFile(szFilePath, &m_pFileBuf, &m_nFileSize))
	{
		return;
	}

	m_bImport = TRUE;
}

/************************************************************************/
/*
Function :启用运行时记录一切
用户输入，输出，无论你在屏幕上看到什么                                                                 */
/************************************************************************/
void CMENU::Log()
{
	printf("Please Select the File You want to Save the log:\r\n");

	char szFilePath[MAX_PATH];
	BOOL bRet = SelectFile(szFilePath, MAX_PATH);
	if (!bRet)
	{
		ShowErrorMessage();
		return;
	}

	g_hLog = CreateFile(szFilePath,
		FILE_APPEND_DATA |GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (INVALID_HANDLE_VALUE == g_hLog)
	{
		ShowErrorMessage();
		return;
	}

	m_bLog = TRUE;
}

/************************************************************************/
/*
Function : prepare file for trace log                                    */
/************************************************************************/
void
CMENU::PreTrace()
{
	printf("Please Select the File You want to Save the trace log:\r\n");

	char szFilePath[MAX_PATH];
	BOOL bRet = SelectFile(szFilePath, MAX_PATH);
	if (!bRet)
	{
		ShowErrorMessage();
		return;
	}

	g_hTraceLog = CreateFile(szFilePath,
		FILE_APPEND_DATA| GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (INVALID_HANDLE_VALUE == g_hTraceLog)
	{
		ShowErrorMessage();
		return;
	}

	m_bTrace = TRUE;
}

/************************************************************************/
/*
Function : write trace info into file                                                                     */
/************************************************************************/
void
CMENU::TraceLog(const char *pszInfo)
{
	LogInfo(pszInfo, g_hTraceLog);
}