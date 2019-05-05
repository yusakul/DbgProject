#include "Menu.h"

//���ڼ�¼������ʷ��¼
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
		"---------1. ���Խ���---------\r\n"
		"---------2. ���ӽ���---------\r\n"
		"---------3. ��    ��---------\r\n"
		"---------0. ��    ��---------\r\n"
		"=============================\r\n"
		"����ѡ��:\r\n");
}

/*��ȡ�û�ѡ��*/
void CMENU::GetCH(char *pch)
{
	scanf_s("%c", pch, 2);
	fflush(stdin); //������뻺����
}

/************************************************************************
���ܣ���ȡ�û����룬������������洢��pszBuf��
pargc�����յĸ���
pargv�����յ��ַ�������ָ��
pszBuf��������������Ļ���
nMaxBuf��������
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
	static int nCurPos = 0; //���ڵ���ű�

	ShowInfo(">> ");
	while (TRUE)
	{
		if (m_bImport)	//�Ƿ���ű�
		{
			//���ļ��ж�ȡ
			nRet = sscanf_s(&m_pFileBuf[nCurPos], "%255s", szBuf, (unsigned)_countof(szBuf));
		}
		else//�û�����
		{
			nRet = scanf_s("%255s", szBuf, MAXBYTE);
		}

		if (EOF == nRet)
		{
			break;
		}

		//�Ա��⻺�������
		if (nIndex + strlen(szBuf) + 1 > nMaxBuf)
		{
			break;
		}

		//���ڼ�¼��������ʷ��¼��
		strcat(gs_szCommand, szBuf);
		strcat(gs_szCommand, " ");

		//������벢����
		strcpy(&pszBuf[nIndex], szBuf);
		pargv[nCount] = nIndex;
		nIndex += (strlen(szBuf) + 1);
		nCount++;

		//��¼���в���
		if (m_bLog)
		{
			LogInfo(szBuf, g_hLog);
			LogInfo(" ", g_hLog);
		}

		//���ڵ���ű�
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

			//ͣ��es
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

//ѡ��Ҫ���Ե��ļ�
BOOL CMENU::SelectFile(char *pszFilePath, SIZE_T nMaxPath)
{
	BOOL bRet = TRUE;
	char appPath[MAX_PATH] = { 0 }; //Ӧ�ó���·��

	//�����ļ��Ի������
	OPENFILENAME ofn;

	RtlZeroMemory(&ofn, sizeof(ofn));	//�ڴ�����
	ofn.lStructSize = sizeof(ofn);		//�ṹ��Ĵ�С
	//�����ļ����ͣ�lpstrFilter��һ�����ַ������Ĺ����ַ�����һ�����塣�����е����һ���ִ���������NULL�ַ��������ڱ����ʹ��/0/0��
	ofn.lpstrFilter = TEXT("All Files(*.*)\0*.*\0");

	ofn.lpstrFile = appPath;		//����ַ��ֵ��lpstrFilter
	ofn.nMaxFile = MAX_PATH;		//·������
	ofn.Flags = OFN_PATHMUSTEXIST	/*ָ���û����������·�����ļ���*/
		| OFN_HIDEREADONLY			/*����ֻ����ѡ��*/
		| OFN_LONGNAMES;			/*�Ի���ʹ�ó��ļ���*/

	//�򿪶Ի���
	bRet = GetOpenFileName(&ofn);
	if (bRet)
	{
		lstrcpynA(pszFilePath, appPath, nMaxPath);	//����·��
	}

	return bRet;
}

static DWORD gs_dwReadWrite;
static BOOL gs_bRet;
//����Ϣ��¼���ļ���                                                             
void CMENU::LogInfo(const char *pszInfo, HANDLE hFile)
{
	gs_bRet = WriteFile(hFile,
		pszInfo,
		strlen(pszInfo),
		&gs_dwReadWrite,
		NULL);
	if (!gs_bRet)
	{
		printf("��¼ʧ��\r\n");
	}
}

//��ʾ��Ϣ
void CMENU::ShowInfo(const char *pszInfo)
{
	printf(pszInfo);

	//�Ƿ��¼
	if (m_bLog)
	{
		LogInfo(pszInfo, g_hLog);
	}
}

//��ʾ������Ϣ
void CMENU::ShowErrorMessage()
{
	LPVOID lpMsgBuf;
	//��GetLastError�����õ��Ĵ�����Ϣ����ת�����ַ�����Ϣ�ĺ�����
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		::GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //Ĭ������
		(LPSTR)&lpMsgBuf,
		0,
		NULL
	);

	ShowInfo((const char *)lpMsgBuf);	//��ʾ������Ϣ
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
Function :���ز�ִ��֮ǰ����Ľű�                                                                    */
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
Function :��������ʱ��¼һ��
�û����룬���������������Ļ�Ͽ���ʲô                                                                 */
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