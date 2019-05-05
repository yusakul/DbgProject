
#include "LordPe.h"
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

CLordPe::CLordPe()
{
	m_pDosHdr = new IMAGE_DOS_HEADER;
}


CLordPe::~CLordPe()
{
	delete m_pBuf;
	m_pBuf = NULL;

	delete m_pDosHdr;
	m_pDosHdr = NULL;
}


//************************************
// Method:    GetDosHead
// FullName:  CLordPe::GetDosHead
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: LPCTSTR filePath
// Function:  将被调试进程PE文件内容读取进调试器进程内存空间
//************************************
BOOL CLordPe::GetDosHead(LPCTSTR filePath)
{
	// 1. 打开文件,将文件读取到内存.
	// CreateFile,ReadFile.
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);

	// 2. 申请内存空间
	BYTE* pBuf = new BYTE[dwFileSize];
	m_pBuf = pBuf;//保存起来，用于析构释放空间

	// 3. 将文件内容读取到内存中
	DWORD dwRead = 0;
	ReadFile(hFile, pBuf, dwFileSize, &dwRead, NULL);

	// 将缓冲区当成DOS头结构体来解析
	m_pDosHdr = (IMAGE_DOS_HEADER*)pBuf;//将DOS头指针保存起来

										// nt头,包含这文件头和扩展头
	IMAGE_NT_HEADERS* pNtHdr;
	pNtHdr = (IMAGE_NT_HEADERS*)(m_pDosHdr->e_lfanew + (DWORD)m_pDosHdr);

	// 判断是否是一个有效的pe文件
	if (m_pDosHdr->e_magic != IMAGE_DOS_SIGNATURE || pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}

//************************************
// Method:    GetOep
// FullName:  CLordPe::GetOep
// Access:    public 
// Returns:   DWORD
// Qualifier:
// Function:  获取被调试进程OEP
//************************************
DWORD CLordPe::GetOep()
{
	// nt头,包含这文件头和扩展头
	IMAGE_NT_HEADERS* pNtHdr = (IMAGE_NT_HEADERS*)(m_pDosHdr->e_lfanew + (DWORD)m_pDosHdr);

	IMAGE_OPTIONAL_HEADER* pOptHdr = &(pNtHdr->OptionalHeader);//扩展头

	return pOptHdr->AddressOfEntryPoint;

}


//解析导出表
void CLordPe::ExportTable()
{
	// nt头,包含这文件头和扩展头
	IMAGE_NT_HEADERS* pNtHdr;
	pNtHdr = (IMAGE_NT_HEADERS*)(m_pDosHdr->e_lfanew + (DWORD)m_pDosHdr);

	IMAGE_OPTIONAL_HEADER* pOptHdr;// 扩展头
	pOptHdr = &(pNtHdr->OptionalHeader);

	//数据目录表
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHdr->DataDirectory;

	// 5. 找到导出表
 	DWORD dwExpRva = pDataDirectory[0].VirtualAddress;

	// 5.1 得到RVA的文件偏移
	DWORD dwExpOfs = RVAToOffset(m_pDosHdr, dwExpRva);
	IMAGE_EXPORT_DIRECTORY* pExpTab = NULL;
	pExpTab = (IMAGE_EXPORT_DIRECTORY*)(dwExpOfs + (DWORD)m_pDosHdr);

	// 解析DLL的导出表
	/*
	typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name; // dll名[字符串的RVA]
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // 地址表(DWORD数组)的rva
	DWORD   AddressOfNames;         // 名称表(DWORD数组)的rva
	DWORD   AddressOfNameOrdinals;  // 序号表(WORD数组)的rva
	} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
	*/
	// 1. 解析DLL的名
	DWORD dwNameOfs = RVAToOffset(m_pDosHdr, pExpTab->Name);
	char* pDllName = (char*)(dwNameOfs + (DWORD)m_pDosHdr);
	//导出表基本信息
	//ZeroMemory(&m_my_im_ex_di, sizeof(m_my_im_ex_di));//全字段置为零
	m_my_im_ex_di.name = pDllName;
	m_my_im_ex_di.Base = pExpTab->Base;
	m_my_im_ex_di.NumberOfFunctions = pExpTab->NumberOfFunctions;
	m_my_im_ex_di.NumberOfNames = pExpTab->NumberOfNames;
	m_my_im_ex_di.AddressOfFunctions = pExpTab->AddressOfFunctions;
	m_my_im_ex_di.AddressOfNames = pExpTab->AddressOfNames;
	m_my_im_ex_di.AddressOfNameOrdinals = pExpTab->AddressOfNameOrdinals;

	// 解析三张表
	DWORD dwExpAddrTabOfs = RVAToOffset(m_pDosHdr, pExpTab->AddressOfFunctions);
	DWORD dwExpNameTabOfs = RVAToOffset(m_pDosHdr, pExpTab->AddressOfNames);
	DWORD dwExpOrdTabOfs = RVAToOffset(m_pDosHdr, pExpTab->AddressOfNameOrdinals);

	// 地址表,名称表是一个DWORD类型数组
	DWORD* pExpAddr = (DWORD*)(dwExpAddrTabOfs + (DWORD)m_pDosHdr);

	DWORD* pExpName = (DWORD*)(dwExpNameTabOfs + (DWORD)m_pDosHdr);

	// 序号表是WORD类型的数组
	WORD* pExpOrd = (WORD*)(dwExpOrdTabOfs + (DWORD)m_pDosHdr);

	// 遍历所有的函数地址
	m_vecExportFunInfo.clear();
	for (int i = 0; i< pExpTab->NumberOfFunctions; ++i)
	{
		EXPORTFUNINFO exportFunInfo = { 0 };
		exportFunInfo.FunctionRVA = pExpAddr[i];//函数RVA
		exportFunInfo.FunctionOffset = RVAToOffset(m_pDosHdr, pExpAddr[i]);//函数相对文件偏移
																		   // 查找当前遍历到的地址有没有名称
		int j = 0;
		for (; j < pExpTab->NumberOfNames; ++j)
		{
			// 判断地址表的下标是否被被保存于函数名称序号表中.
			// 如果被保存了, 则说明这个下标所保存的地址,是一个有函数名称的地址
			if (i == pExpOrd[j])
				break;
		}
		// 判断循环是自然结束,还是通过break跳出
		if (j < pExpTab->NumberOfNames)
		{
			// 地址有名称,j就是对应的函数名表的下标.通过j可以找到一个函数名称的Rva
			DWORD dwNameRva = pExpName[j];
			DWORD dwNameOfs = RVAToOffset(m_pDosHdr, dwNameRva);
			char* pFunctionName = nullptr;
			pFunctionName = (char*)(dwNameOfs + (DWORD)m_pDosHdr);
			exportFunInfo.FunctionName = pFunctionName;//函数名
			exportFunInfo.ExportOrdinals = pExpTab->Base + i;//函数导出序号
		}
		else
		{
			// 说名地址没有以名称的方式导出.
			if (pExpAddr[i] != 0)
			{
				// 函数的导出序号:
				// 序号基数 + 虚序号(地址标的下标)
				exportFunInfo.FunctionName = L"";//函数名为空
				exportFunInfo.ExportOrdinals = pExpTab->Base + i;//函数导出序号
			}
		}
		m_vecExportFunInfo.push_back(exportFunInfo);
	}
}


//解析导入表
void CLordPe::ImportTable()
{
	// nt头,包含这文件头和扩展头
	IMAGE_NT_HEADERS* pNtHdr;
	pNtHdr = (IMAGE_NT_HEADERS*)(m_pDosHdr->e_lfanew + (DWORD)m_pDosHdr);

	IMAGE_OPTIONAL_HEADER* pOptHdr;// 扩展头
	pOptHdr = &(pNtHdr->OptionalHeader);

	//数据目录表
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHdr->DataDirectory;

	// 5. 找到导入表
	// 5. 得到导入表的RVA
	DWORD dwImpRva = pDataDirectory[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* pImpArray;

	pImpArray = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset(m_pDosHdr, dwImpRva) + (DWORD)m_pDosHdr);

	// 导入表数组的个数并没有其它字段记录.
	// 结束的标志是以一个全0的元素作为结尾
	m_vecImportDescriptor.clear();
	m_vvImportFunInfo.clear();
	while (pImpArray->Name != 0)
	{
		MY_IMPORT_DESCRIPTOR myImportDescriptor;//!!!!!!!注意这里没有初始化结构体
		// 导入的Dll的名字(Rva)
		DWORD dwNameOfs = RVAToOffset(m_pDosHdr, pImpArray->Name);
		char* pDllName = (char*)(dwNameOfs + (DWORD)m_pDosHdr);
		myImportDescriptor.Name = pDllName;

		// 解析,在这个dll中,一共导入哪些函数
		myImportDescriptor.OriginalFirstThunk = pImpArray->OriginalFirstThunk;
		myImportDescriptor.FirstThunk = pImpArray->FirstThunk;

		// IAT(导入名表)记录着一个从一个dll中导入了哪些函数,这些函数要么是以名称导入,要么是以序号导入的
		// 记录在一个数组中. 这个数组是IMAGE_THUNK_DATA类型的结构体数组.
		DWORD INTOfs = RVAToOffset(m_pDosHdr, pImpArray->OriginalFirstThunk);
		myImportDescriptor.OffsetOriginalFirstThunk = INTOfs;

		DWORD IATOfs = RVAToOffset(m_pDosHdr, pImpArray->FirstThunk);
		myImportDescriptor.OffsetFirstThunk = IATOfs;

		m_vecImportDescriptor.push_back(myImportDescriptor);
		/*
		这是一个只有4个字节的结构体.里面联合体中的每一个字段保存的值都是一样.这些值, 就是导入函数的信息.
		导入函数的信息有以下部分:
		1. 导入函数的序号
		2. 导入函数的名称(可能有可能没有)
		可以根据结构体中的字段的最高位判断, 导入信息是以名称导入还是以序号导入
		typedef struct _IMAGE_THUNK_DATA32 {
		union {
		DWORD ForwarderString;      // PBYTE
		DWORD Function;             // PDWORD
		DWORD Ordinal;
		DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
		} u1;
		} IMAGE_THUNK_DATA32;
		*/
		IMAGE_THUNK_DATA* pInt = NULL;
		IMAGE_THUNK_DATA* pIat = NULL;
		pInt = (IMAGE_THUNK_DATA*)(INTOfs + (DWORD)m_pDosHdr);
		pIat = (IMAGE_THUNK_DATA*)(IATOfs + (DWORD)m_pDosHdr);

		//INT可以看做是IAT的备份，存在没有备份的情况，因此解析IAT
		m_vecImportFunInfo.clear();
		while (pInt->u1.Function != 0)
		{
			IMPORTFUNINFO importFunInfo = { 0 };
			// 判断是否是以序号导入
			if (IMAGE_SNAP_BY_ORDINAL32(pInt->u1.Function))
			{
				// 以序号方式导入结构体保存的值低16位就是一个导入的序号
				importFunInfo.Ordinal = pInt->u1.Ordinal & 0xFFFF;
				importFunInfo.Name = L"";
			}
			else
			{
				// 当函数是以名称导入的时候, pInt->u1.Function 保存的是一个rva , 
				//这个RVA指向一个保存函数名称信息的结构体
				DWORD dwImpNameOfs = RVAToOffset(m_pDosHdr, pInt->u1.Function);
				IMAGE_IMPORT_BY_NAME* pImpName;
				pImpName = (IMAGE_IMPORT_BY_NAME*)(dwImpNameOfs + (DWORD)m_pDosHdr);
				importFunInfo.Ordinal = pImpName->Hint;
				importFunInfo.Name = pImpName->Name;
				m_vecImportFunInfo.push_back(importFunInfo);
			}
			++pInt;
		}
		m_vvImportFunInfo.push_back(m_vecImportFunInfo);
		++pImpArray;
	}
}

//RVA转文件偏移
DWORD CLordPe::RVAToOffset(IMAGE_DOS_HEADER* pDos,
	DWORD dwRva)
{
	IMAGE_SECTION_HEADER* pScnHdr;

	IMAGE_NT_HEADERS* pNtHdr = (IMAGE_NT_HEADERS*)(pDos->e_lfanew + (DWORD)pDos);

	pScnHdr = IMAGE_FIRST_SECTION(pNtHdr);
	DWORD dwNumberOfScn = pNtHdr->FileHeader.NumberOfSections;

	// 1. 遍历所有区段找到所在区段
	for (int i = 0; i < dwNumberOfScn; ++i)
	{
		DWORD dwEndOfSection = pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData;
		// 判断这个RVA是否在一个区段的范围内
		if (dwRva >= pScnHdr[i].VirtualAddress
			&& dwRva < dwEndOfSection)
		{
			// 2. 计算该RVA在区段内的偏移:rva 减去首地址
			DWORD dwOffset = dwRva - pScnHdr[i].VirtualAddress;
			// 3. 将区段内偏移加上区段的文件开始偏移
			return dwOffset + pScnHdr[i].PointerToRawData;
		}
	}
	return -1;
}

