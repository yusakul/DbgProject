#include "PE.H"


//define the DIRectory info you want to display in the tree view
#define DOSHEADER   "    Dos Header"
#define NTHEADERS   "    NT Headers"  
#define FILEHEADER  "        File Header"
#define OPTHEADER   "        Optional Header"
#define DATADIRS    "            Data Directories(x)"
#define SECTIONHDR  "    Section Headers(x)"
#define IMPORTDIR   "    Import Directory"
#define FREESPACE   "    Free Space"
#define EXPORTDIR   "    Export Directory"
#define BASERELC    "    Base Relocation"
#define TLSINFO     "    TLS Info"
#define RESINFO     "    Resource"

//define the Header info you want to display in the list view
#define HDRINFO_DOSHEADER   "Member|Offset|Size|Value"
#define HDRINFO_NTHEADERS   "Member|Offset|Size|Value"
#define HDRINFO_FILEHEADER  "Member|Offset|Size|Value|Meaning"  
#define HDRINFO_OPTHEADER   "Member|Offset|Size|Value|Meaning"   
#define HDRINFO_DATADIRS    "Member|Offset|Size|RVA|FA|Section"
#define HDRINFO_SECTIONHDR  "Member|Offset|Size|Value"
//#define HDRINFO_IMPORTDIR  //We decide to show import info by text

//#define MAXBUF  (1024 * 100)
#define STR(x)  #x
#define FIELDINFO(buf, s, m, ptr, off)  sprintf(buf, "%s|+%X|%s|%0*X|",       \
                                                    STR(m),                   \
                                                    off + offsetof(s, m),     \
                                                    sizeof(((s *)ptr)->m) <= 4 ? gs_pszSize[sizeof(((s *)ptr)->m)] : "NULL" , \
                                                    2*sizeof(((s *)ptr)->m),   \
                                                    ((s *)ptr)->m              \
                                                    )

//save pstrSRC->mSRC (RVA) to ptrDST->mDSTRVA, and convert to ptrDST->mDSTFA
//关于这里的RVA2FA及上面的FIELDINFO宏，之所以使用，是考虑到“类型无关性”，或者“通用性”，
//比如，以下场景：
//ptagA->m1, ptagB->m2,  都可以用宏来直接处理；
//而用函数，则需具体的类型信息
#define RVA2FA(ptrDST, mDSTRVA, mDSTFA, ptrSRC, mSRC, pAddrMap)                                \
                                                          ptrDST->mDSTRVA = (DWORD)ptrSRC->mSRC;       \
                                                          pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA; \
                                                          pAddrMap->m_dwRVA  = ptrDST->mDSTRVA;    \
                                                          if (GetAddrMAPByRVA(pAddrMap))        \
                                                          {                                     \
                                                            ptrDST->mDSTFA = pAddrMap->m_dwFA;   \
                                                          }                                      \
                                                          else                                   \
                                                          {                                      \
                                                            ptrDST->mDSTFA = NULL;               \
                                                          }
/*
ptagImportInfo->m_NameRVA = pImportDescript->Name;
pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA;
pAddrMap->m_dwRVA  = ptagImportInfo->m_NameRVA;
if (GetAddrMAPByRVA(pAddrMap))
{
ptagImportInfo->m_NameFA = pAddrMap->m_dwFA;
}
else
{
return FALSE;
}
*/

#define ROUND(addr, align) ( ((addr + (align - 1)) / align) * align )

static HANDLE                       gs_hFileMapping;
static PIMAGE_DOS_HEADER            gs_pDOSHDR;
static PIMAGE_NT_HEADERS32          gs_pNTHDR;
static PIMAGE_FILE_HEADER           gs_pFileHDR;
static PIMAGE_OPTIONAL_HEADER32     gs_pOPTHDR;
static PIMAGE_DATA_DIRECTORY        gs_pDataDIR;
static PIMAGE_SECTION_HEADER        gs_pFirstSectionHDR;
static PIMAGE_DATA_DIRECTORY        gs_pImportDir;
static PIMAGE_DATA_DIRECTORY        gs_pExportDir;

static const char *gs_PETree = DOSHEADER"|"
NTHEADERS"|"
FILEHEADER"|"
OPTHEADER"|"
DATADIRS"|"
SECTIONHDR"|"
IMPORTDIR"|"
FREESPACE"|"
EXPORTDIR"|"
BASERELC"|"
TLSINFO"|"
RESINFO;

static const char *gs_pszSize[] = { "NULL", "Byte", "Word", "NULL", "DWord" };
static const char *gs_pszDataDir[] = {
	"Export_RVA",
	"Export_Size",
	"Import_RVA",
	"Import_Size",
	"RESOURCE_RVA",
	"RESOURCE_Size",
	"EXCEPTION_RVA",
	"EXCEPTION_Size",
	"SECURITY_RVA",
	"SECURITY_Size",
	"BASERELOC_RVA",
	"BASERELOC_Size",
	"DEBUG_RVA",
	"DEBUG_Size",
	"ARCHITECTURE_RVA",
	"ARCHITECTURE_Size",
	"GLOBALPTR_RVA",
	"GLOBALPTR_Size",
	"TLS_RVA",
	"TLS_Size",
	"LOAD_CONFIG_RVA",
	"LOAD_CONFIG_Size",
	"BOUND_IMPORT_RVA",
	"BOUND_IMPORT_Size",
	"IAT_RVA",
	"IAT_Size",
	"DELAY_IMPORT_RVA",
	"DELAY_IMPORT_Size",
	"COM_DESCRIPTOR_RVA",
	"COM_DESCRIPTOR_Size",
	"END_RVA",
	"END_Size"
};


const char *g_pszIMPORT = IMPORTDIR;
const char *g_pszFreeSpace = FREESPACE;
const char *g_pszEXPORT = EXPORTDIR;
const char *g_pszBASERELC = BASERELC;
const char *g_pszTLSINFO = TLSINFO;
const char *g_pszRESINFO = RESINFO;

//define the map between directory and header
//Do not forget to add in the InitMapInfo
#ifdef USE_ALONE
static map<CString, CString> gs_map_DIR_HDR;
#endif

static char *gs_pszBuf = new char[MAXBUF];

//about free space
static tagAllFreeSpace *gs_pAllFreeSpace;

//used to retrieve module info
static list<MODULEENTRY32> gs_ModuleList;
static int gs_nIndex = 0;

//////////////////////////////////////////////////////////////////////////
//used for Debugger
static map<DWORD, char *> gs_mapAddr_ExportName;  //about export Info

												  /************************************************************************/
												  /*
												  Function : Establish the map between directory and header info
												  And some initilization
												  */
												  /************************************************************************/
static void InitMapInfo()
{
#ifdef USE_ALONE
	gs_map_DIR_HDR.clear();
	gs_map_DIR_HDR[DOSHEADER] = HDRINFO_DOSHEADER;
	gs_map_DIR_HDR[NTHEADERS] = HDRINFO_NTHEADERS;
	gs_map_DIR_HDR[FILEHEADER] = HDRINFO_FILEHEADER;
	gs_map_DIR_HDR[OPTHEADER] = HDRINFO_OPTHEADER;
	gs_map_DIR_HDR[DATADIRS] = HDRINFO_DATADIRS;
	gs_map_DIR_HDR[SECTIONHDR] = HDRINFO_SECTIONHDR;
#endif

	if (NULL == gs_pszBuf)
	{
		gs_pszBuf = new char[MAXBUF];
	}

	gs_pNTHDR = (PIMAGE_NT_HEADERS)((unsigned char *)gs_pDOSHDR + gs_pDOSHDR->e_lfanew);
	gs_pFileHDR = (PIMAGE_FILE_HEADER)((unsigned char *)gs_pNTHDR + sizeof(DWORD));
	gs_pOPTHDR = &gs_pNTHDR->OptionalHeader;
	gs_pDataDIR = gs_pOPTHDR->DataDirectory;
	gs_pFirstSectionHDR = IMAGE_FIRST_SECTION(gs_pNTHDR);

	//not good idea, and may not be right to init here; so we recheck it.
	gs_pImportDir = (PIMAGE_DATA_DIRECTORY)
		((unsigned char *)gs_pDataDIR + sizeof(IMAGE_DATA_DIRECTORY));
	gs_pExportDir = (PIMAGE_DATA_DIRECTORY)((unsigned char *)gs_pDataDIR);

	assert(gs_pDOSHDR != NULL);
	assert(gs_pNTHDR != NULL);
	assert(gs_pFileHDR != NULL);
	assert(gs_pOPTHDR != NULL);
	assert(gs_pDataDIR != NULL);
	assert(gs_pFirstSectionHDR != NULL);
	assert(gs_pImportDir != NULL);

	//all free space
	gs_pAllFreeSpace = (tagAllFreeSpace *)
		malloc(sizeof(tagAllFreeSpace)
			+ (gs_pFileHDR->NumberOfSections - 1) * sizeof(tagFreeSpace)
		);
	assert(gs_pAllFreeSpace != NULL);
}

/************************************************************************/
/*
Function : Load the specific file into memory in the way of File Mapping
And make gs_pDOSHDR point to the buf block.

Return   : TRUE if load success, FALSE otherwise

*/
/************************************************************************/
static BOOL gs_bLoaded = FALSE;         //to make sure necessary init is done
BOOL LoadFile(const char *pszFilePath)
{
	HANDLE hFile = NULL;
	HANDLE hFileMapping = NULL;
	LPVOID lpFileBase = NULL;
	BOOL bRet = TRUE;

	gs_bLoaded = TRUE;

	hFile = CreateFile(pszFilePath,
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		bRet = FALSE;
		return bRet;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (NULL == hFileMapping)
	{
		bRet = FALSE;
		goto SAFE_CLEAN;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == lpFileBase)
	{
		bRet = FALSE;
		goto SAFE_CLEAN;
	}

	gs_pDOSHDR = (PIMAGE_DOS_HEADER)lpFileBase;

	InitMapInfo();

SAFE_CLEAN:
	if (hFile != NULL)
	{
		CloseHandle(hFile);
		hFile = NULL;
	}

	//close only if failed
	if (!bRet
		&&hFileMapping != NULL
		&& lpFileBase != NULL
		)
	{
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);

		lpFileBase = NULL;
		hFileMapping = NULL;
	}

	return bRet;
}

/************************************************************************/
/*
Function : Release buf mapped into memory
Should Be Called when the buf no longer needed               */
/************************************************************************/
void ReleaseBuf()
{
	if (gs_pDOSHDR != NULL)
	{
		UnmapViewOfFile(gs_pDOSHDR);
		gs_pDOSHDR = NULL;
	}

	if (gs_hFileMapping != NULL)
	{
		CloseHandle(gs_hFileMapping);
		gs_hFileMapping = NULL;
	}

	if (gs_pszBuf != NULL)
	{
		delete[] gs_pszBuf;
		gs_pszBuf = NULL;
	}

	if (gs_pAllFreeSpace != NULL)
	{
		free(gs_pAllFreeSpace);
		gs_pAllFreeSpace = NULL;
	}

}

/************************************************************************/
/*
Function : Checking whether the File mapped into gs_pDOSHDR is PE
Return   : TRUE if it is, FALSE otherwise                                                                     */
/************************************************************************/
BOOL IsPE()
{
	if (gs_pDOSHDR->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	if (gs_pNTHDR->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	if (gs_pNTHDR->OptionalHeader.SizeOfImage
		<= gs_pNTHDR->OptionalHeader.SizeOfHeaders)
	{
		return FALSE;
	}

	//more checks here

	return TRUE;
}

void GetDOSHDRInfo()
{
	char szBuf[MAXBYTE];

	gs_pszBuf[0] = '\0';

	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_magic, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_cblp, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_cp, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_crlc, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_cparhdr, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_minalloc, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_maxalloc, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_ss, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_sp, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_csum, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_ip, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_cs, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_lfarlc, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_ovno, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_res, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_oemid, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_oeminfo, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_res2, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_DOS_HEADER, e_lfanew, gs_pDOSHDR, 0);
	wsprintf(gs_pszBuf, "%s%s", gs_pszBuf, szBuf);
}

void GetFileHDRInfo()
{
	char szBuf[MAXBYTE];
	DWORD dwOff = 0;

	dwOff = (unsigned char *)gs_pFileHDR - (unsigned char *)gs_pDOSHDR;
	gs_pszBuf[0] = '\0';

	FIELDINFO(szBuf, IMAGE_FILE_HEADER, Machine, gs_pFileHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_FILE_HEADER, NumberOfSections, gs_pFileHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_FILE_HEADER, TimeDateStamp, gs_pFileHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_FILE_HEADER, PointerToSymbolTable, gs_pFileHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_FILE_HEADER, NumberOfSymbols, gs_pFileHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);

	FIELDINFO(szBuf, IMAGE_FILE_HEADER, SizeOfOptionalHeader, gs_pFileHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_FILE_HEADER, Characteristics, gs_pFileHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
}

void GetOPTHDRInfo()
{
	char szBuf[MAXBYTE];
	DWORD dwOff = 0;

	dwOff = (unsigned char *)gs_pOPTHDR - (unsigned char *)gs_pDOSHDR;
	gs_pszBuf[0] = '\0';

	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, Magic, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MajorLinkerVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MinorLinkerVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfCode, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfInitializedData, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfUninitializedData, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, BaseOfCode, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, BaseOfData, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);

	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, ImageBase, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SectionAlignment, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, FileAlignment, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MajorOperatingSystemVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MinorOperatingSystemVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MajorImageVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MinorImageVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MajorSubsystemVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, MinorSubsystemVersion, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, Win32VersionValue, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfImage, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfHeaders, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, CheckSum, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, Subsystem, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, DllCharacteristics, gs_pOPTHDR, dwOff);
	wsprintf(gs_pszBuf, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfStackReserve, gs_pOPTHDR, dwOff);
	//To use buffers larger than 1024 bytes, use _snwprintf. For more information, see the documentation for the C run-time library. 
	_snprintf(gs_pszBuf, MAXBUF, "%s%s |", gs_pszBuf, szBuf);

	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfStackCommit, gs_pOPTHDR, dwOff);
	_snprintf(gs_pszBuf, MAXBUF, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfHeapReserve, gs_pOPTHDR, dwOff);
	_snprintf(gs_pszBuf, MAXBUF, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, SizeOfHeapCommit, gs_pOPTHDR, dwOff);
	_snprintf(gs_pszBuf, MAXBUF, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, LoaderFlags, gs_pOPTHDR, dwOff);
	_snprintf(gs_pszBuf, MAXBUF, "%s%s |", gs_pszBuf, szBuf);
	FIELDINFO(szBuf, IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes, gs_pOPTHDR, dwOff);
	_snprintf(gs_pszBuf, MAXBUF, "%s%s |", gs_pszBuf, szBuf);
}

/************************************************************************/
/*
Function: Retrieve info about Data Directory
Only Care about those not empty                               */
/************************************************************************/
BOOL GetAddrMAPByRVA(tagAddrMAP *pAddrMap);   //Forward Declaring
void GetDataDirectoryInfo()
{
	DWORD dwOff = 0;
	DWORD nDirs = min(gs_pOPTHDR->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	DWORD dwRVA = 0;
	DWORD dwFA = 0;
	BOOL bRet = FALSE;
	static tagAddrMAP *pAddrMap = new tagAddrMAP;
	assert(pAddrMap != NULL);
	pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA;

	dwOff = (unsigned char *)gs_pDataDIR - (unsigned char *)gs_pDOSHDR;
	gs_pszBuf[0] = '\0';
	int i = 0;
	for (; i < nDirs; i++)
	{
		//just ignore those empty
		pDataDir = &gs_pDataDIR[i];
		dwRVA = pDataDir->VirtualAddress;
		if (NULL == dwRVA)
		{
			dwOff += sizeof(IMAGE_DATA_DIRECTORY);
			continue;
		}

		//we also care about FA
		pAddrMap->m_dwRVA = dwRVA;
		bRet = GetAddrMAPByRVA(pAddrMap);
		if (!bRet)
		{
			pAddrMap->m_dwFA = -1;
			strcpy(pAddrMap->m_szSectionName, "Invalid");   //may be in header
		}

		_snprintf(gs_pszBuf, MAXBUF, "%s%s|+%X|Dword|%08X|%08X|%s|",
			gs_pszBuf,
			gs_pszDataDir[i * 2],                   //member
			dwOff,                                  //offset
			dwRVA,                                  //VirtualSize
			pAddrMap->m_dwFA,
			pAddrMap->m_szSectionName
		);

		dwOff += sizeof(DWORD);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s|+%X|Dword|%08X| | |",
			gs_pszBuf,
			gs_pszDataDir[i * 2 + 1],                       //member
			dwOff,                                  //offset
			pDataDir->Size    //value         
		);
		dwOff += sizeof(DWORD);
	}

	for (i = nDirs; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		pDataDir = &gs_pDataDIR[i];
		dwRVA = pDataDir->VirtualAddress;
		if (NULL == dwRVA)
		{
			dwOff += sizeof(IMAGE_DATA_DIRECTORY);
			continue;
		}

		//we also care about FA
		pAddrMap->m_dwRVA = dwRVA;
		bRet = GetAddrMAPByRVA(pAddrMap);
		assert(bRet);

		_snprintf(gs_pszBuf, MAXBUF, "%s%s|+%X|Dword|%08X|%08X|%s|",
			gs_pszBuf,
			"其他",                                 //member
			dwOff,                                  //offset
			dwRVA,                                 //VirtualAddress
			pAddrMap->m_dwFA,
			pAddrMap->m_szSectionName
		);

		dwOff += sizeof(DWORD);     //Size
		_snprintf(gs_pszBuf, MAXBUF, "%s%s|+%X|Dword|%08X| | |",
			gs_pszBuf,
			"其他",                                 //member
			dwOff,                                  //offset
			pDataDir->Size   //value         
		);
		dwOff += sizeof(DWORD);  //RVA
	}
}

void GetSectionInfo()
{
	char szBuf[MAXBYTE];
	DWORD dwOff = 0;
	DWORD nSections = gs_pFileHDR->NumberOfSections;
	IMAGE_SECTION_HEADER *pSectionHDR = NULL;
	tagFreeSpace *pFreeSpace = 0;

	dwOff = (unsigned char *)gs_pFirstSectionHDR - (unsigned char *)gs_pDOSHDR;

	gs_pszBuf[0] = '\0';
	for (int i = 0; i < nSections; i++)
	{
		pSectionHDR = (IMAGE_SECTION_HEADER *)((unsigned char *)gs_pDOSHDR + dwOff);

		//deal with name specially
		lstrcpyn(szBuf, (const char *)pSectionHDR->Name, IMAGE_SIZEOF_SHORT_NAME);
		szBuf[IMAGE_SIZEOF_SHORT_NAME + 1] = '\0';
		_snprintf(gs_pszBuf, MAXBUF, "%sName|+%X|Byte[8]|%s|", gs_pszBuf, dwOff, szBuf);

		//deal with Free Space, through I know not a good idea to do here
		pFreeSpace = (tagFreeSpace *)&(gs_pAllFreeSpace->m_SectionData[i]);
		strcpy(pFreeSpace->m_szName, szBuf);
		pFreeSpace->m_dwFA = pSectionHDR->PointerToRawData;
		pFreeSpace->m_dwSize = pSectionHDR->SizeOfRawData;
		if (pSectionHDR->Misc.VirtualSize > pSectionHDR->SizeOfRawData)
		{
			//not exist, or don't know
			pFreeSpace->m_dwFreeFA = -1;
		}
		else
		{
			pFreeSpace->m_dwFreeFA = pFreeSpace->m_dwFA + pSectionHDR->Misc.VirtualSize;
			pFreeSpace->m_dwFreeSize = pSectionHDR->SizeOfRawData - pSectionHDR->Misc.VirtualSize;
		}

		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, Misc.VirtualSize, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, VirtualAddress, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, SizeOfRawData, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, PointerToRawData, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, PointerToRelocations, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, PointerToLinenumbers, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, NumberOfRelocations, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, NumberOfLinenumbers, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);
		FIELDINFO(szBuf, IMAGE_SECTION_HEADER, Characteristics, pSectionHDR, dwOff);
		_snprintf(gs_pszBuf, MAXBUF, "%s%s", gs_pszBuf, szBuf);

		//split
		_snprintf(gs_pszBuf, MAXBUF, "%s | | | |", gs_pszBuf, szBuf);
		dwOff += sizeof(IMAGE_SECTION_HEADER);
	}
}

/************************************************************************/
/*
Function: Retrieve all the items info to be displayed within ListView
according to Dir (Item) selected within TreeView                                                                     */
/************************************************************************/
const char *GetItemInfoByDir(const char *pszDir)
{
	if (0 == strcmp(pszDir, DOSHEADER))
	{
		GetDOSHDRInfo();
	}
	else if (0 == strcmp(pszDir, NTHEADERS))
	{
		FIELDINFO(gs_pszBuf, IMAGE_NT_HEADERS32,
			Signature, gs_pNTHDR,
			(unsigned char *)gs_pNTHDR - (unsigned char *)gs_pDOSHDR
		);
	}
	else if (0 == strcmp(pszDir, FILEHEADER))
	{
		GetFileHDRInfo();
	}
	else if (0 == strcmp(pszDir, OPTHEADER))
	{
		GetOPTHDRInfo();
	}
	else if (0 == strcmp(pszDir, DATADIRS))
	{
		GetDataDirectoryInfo();
	}
	else if (0 == strcmp(pszDir, SECTIONHDR))
	{
		GetSectionInfo();
	}

	return gs_pszBuf;
}

/************************************************************************/
/*
Function : retrieve info to be displayed within TreeView                                                                     */
/************************************************************************/
const char *GetPETree()
{
	return gs_PETree;
}

#ifdef USE_ALONE
/************************************************************************/
/*
Function : retrieve header info to be displayed within ListView
according to the ItemName selected within TreeView                                                                     */
/************************************************************************/
const char *GetHDRInfoByDir(const char *pszDir)
{
	return gs_map_DIR_HDR[pszDir];
}
#endif

/************************************************************************/
/*
Function : Retrieve tagAddrMAP info by FA
Param    : pAddrMap as IN/OUT param, you should set one of the addrs
Return   : TRUE if get it, FALSE otherwise                                                                     */
/************************************************************************/
BOOL GetAddrMAPByFA(tagAddrMAP *pAddrMap)
{
	char szBuf[MAXBYTE];
	BOOL  bRet = FALSE;
	DWORD dwOff = 0;
	DWORD nSections = gs_pFileHDR->NumberOfSections;
	IMAGE_SECTION_HEADER *pSectionHDR = NULL;

	dwOff = (unsigned char *)gs_pFirstSectionHDR - (unsigned char *)gs_pDOSHDR;

	gs_pszBuf[0] = '\0';
	for (int i = 0; i < nSections; i++)
	{
		pSectionHDR = (IMAGE_SECTION_HEADER *)((unsigned char *)gs_pDOSHDR + dwOff);

		if (pAddrMap->m_dwFA < pSectionHDR->PointerToRawData
			|| pAddrMap->m_dwFA >= pSectionHDR->PointerToRawData + pSectionHDR->SizeOfRawData)
		{
			//not matched, try next
			dwOff += sizeof(IMAGE_SECTION_HEADER);
			continue;
		}

		bRet = TRUE;
		break;
	}

	if (!bRet)
	{
		return bRet;
	}

	//now update info, deal with name specially
	lstrcpyn(szBuf, (const char *)pSectionHDR->Name, IMAGE_SIZEOF_SHORT_NAME);
	szBuf[IMAGE_SIZEOF_SHORT_NAME] = '\0';
	strcpy(pAddrMap->m_szSectionName, szBuf);

	pAddrMap->m_dwRVA = pSectionHDR->VirtualAddress + (pAddrMap->m_dwFA - pSectionHDR->PointerToRawData);
	pAddrMap->m_dwVA = gs_pOPTHDR->ImageBase + pAddrMap->m_dwRVA;

	return bRet;
}

/************************************************************************/
/*
Function : Retrieve tagAddrMAP info by RVA
Param    : pAddrMap as IN/OUT param, you should set one of the addrs
Return   : TRUE if get it, FALSE otherwise                                                                     */
/************************************************************************/
BOOL GetAddrMAPByRVA(tagAddrMAP *pAddrMap)
{
	char szBuf[MAXBYTE];
	BOOL  bRet = FALSE;
	DWORD dwOff = 0;
	DWORD dwRound = 0;
	DWORD nSections = gs_pFileHDR->NumberOfSections;
	IMAGE_SECTION_HEADER *pSectionHDR = NULL;

	dwOff = (unsigned char *)gs_pFirstSectionHDR - (unsigned char *)gs_pDOSHDR;

	for (int i = 0; i < nSections; i++)
	{
		pSectionHDR = (IMAGE_SECTION_HEADER *)((unsigned char *)gs_pDOSHDR + dwOff);

		//对齐后的结束点，
		//dwRound = pSectionHDR->VirtualAddress + ROUND(pSectionHDR->Misc.VirtualSize, gs_pOPTHDR->SectionAlignment);
		dwRound = pSectionHDR->VirtualAddress + pSectionHDR->SizeOfRawData;

		if (pAddrMap->m_dwRVA < pSectionHDR->VirtualAddress
			|| pAddrMap->m_dwRVA >= dwRound
			|| 0 == pSectionHDR->SizeOfRawData  //没有实际的文件映射
												//As for VirtualSize > SizeOfRawData
			)
		{
			//not matched, try next
			dwOff += sizeof(IMAGE_SECTION_HEADER);
			continue;
		}

		bRet = TRUE;
		break;
	}

	if (!bRet)
	{
		return bRet;
	}

	//now update info, deal with name specially
	lstrcpyn(szBuf, (const char *)pSectionHDR->Name, IMAGE_SIZEOF_SHORT_NAME);
	szBuf[IMAGE_SIZEOF_SHORT_NAME] = '\0';
	strcpy(pAddrMap->m_szSectionName, szBuf);

	pAddrMap->m_dwFA = pSectionHDR->PointerToRawData + (pAddrMap->m_dwRVA - pSectionHDR->VirtualAddress);
	pAddrMap->m_dwVA = gs_pOPTHDR->ImageBase + pAddrMap->m_dwRVA;

	return bRet;
}

/************************************************************************/
/*
Function : retrieve tagAddrMAP info according to one of the addrs (VA/RVA/FA)
Param    : pAddrMap as IN/OUT param, you should set one of the addrs
Return   : TRUE if get it, FALSE otherwise                                                                   */
/************************************************************************/
BOOL GetAddrMAP(tagAddrMAP *pAddrMap)
{
	BOOL bRet = TRUE;

	if (NULL == pAddrMap)
	{
		return FALSE;
	}

	if (tagAddrMAP::enu_AddrType::FA == pAddrMap->m_AddrType)
	{
		bRet = GetAddrMAPByFA(pAddrMap);
	}
	else if (tagAddrMAP::enu_AddrType::RVA == pAddrMap->m_AddrType)
	{
		bRet = GetAddrMAPByRVA(pAddrMap);
	}
	else if (tagAddrMAP::enu_AddrType::VA == pAddrMap->m_AddrType)
	{
		pAddrMap->m_dwRVA = pAddrMap->m_dwVA - gs_pOPTHDR->ImageBase;
		bRet = GetAddrMAPByRVA(pAddrMap);
	}

	if (!bRet)
	{
		return bRet;
	}

	//value
	memcpy(pAddrMap->m_HexValue,
		(unsigned char *)gs_pDOSHDR + pAddrMap->m_dwFA,
		2 * IMAGE_SIZEOF_SHORT_NAME);

	strncpy(pAddrMap->m_szValue,
		(char *)((unsigned char *)gs_pDOSHDR + pAddrMap->m_dwFA),
		2 * IMAGE_SIZEOF_SHORT_NAME);
	pAddrMap->m_szValue[2 * IMAGE_SIZEOF_SHORT_NAME - 1] = '\0';

	return bRet;
}

/************************************************************************/
/*
Function : Retrieve Import Info
Param    : ppszBuf used to receive the buf pointer
lpAddr is the memory addr where the exe(or dll) "loaded",
used to fix IAT
you can set it as NULL if you do not need
Return   : TRUE if success, and set ppszBuf point to buf
FALSE otherwise                                        */
/************************************************************************/
BOOL GetImportInfo(char **ppszBuf, LPVOID lpAddr/*=NULL*/)
{
	//recheck
	if (gs_pOPTHDR->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_IMPORT + 1)
	{
		return FALSE;
	}

	gs_pImportDir = &gs_pOPTHDR->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (NULL == gs_pImportDir->VirtualAddress)
	{
		return FALSE;
	}

	assert(ppszBuf != NULL);
	*ppszBuf = NULL;

	//1. Get Import RVA and Size from DataDirectory
	DWORD nDirs = min(gs_pOPTHDR->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	if (nDirs < IMAGE_DIRECTORY_ENTRY_IMPORT)
	{
		*ppszBuf = NULL;
		return FALSE;
	}

	static tagImportInfo *ptagImportInfo = new tagImportInfo;
	assert(ptagImportInfo != NULL);
	static tagAddrMAP *pAddrMap = new tagAddrMAP;
	assert(pAddrMap != NULL);

	//RVA, FA
	RVA2FA(ptagImportInfo, m_dwImpRVA, m_dwImpFA, gs_pImportDir, VirtualAddress, pAddrMap);
	ptagImportInfo->m_dwImpSize = gs_pImportDir->Size;

	wsprintf(gs_pszBuf, "Import Directory: \r\nRVA\t:%p\r\nFA\t:%p\r\nSize\t:%p\r\nSection\t:%s\r\n\r\n",
		ptagImportInfo->m_dwImpRVA,
		ptagImportInfo->m_dwImpFA,
		ptagImportInfo->m_dwImpSize,
		pAddrMap->m_szSectionName);
	DWORD dwDescOff = ptagImportInfo->m_dwImpFA;    //IMAGE_IMPORT_DESCRIPTOR FA

													//we also retrieve IAT info
	PIMAGE_DATA_DIRECTORY pIATDIR = NULL;
	if (gs_pOPTHDR->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
	{
		pIATDIR = &gs_pOPTHDR->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
		pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA;
		pAddrMap->m_dwRVA = pIATDIR->VirtualAddress;
		GetAddrMAPByRVA(pAddrMap);

		wsprintf(gs_pszBuf, "%sIAT Directory:\r\n"
			"RVA\t:%p\r\n"
			"FA\t:%p\r\n"
			"Size\t:%p\r\n"
			"Section\t:%s\r\n\r\n",
			gs_pszBuf,
			pAddrMap->m_dwRVA,
			pAddrMap->m_dwFA,
			pIATDIR->Size,
			pAddrMap->m_szSectionName);
	}


	/*
	typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
	DWORD   Characteristics;            // 0 for terminating null import descriptor
	DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	};
	DWORD   TimeDateStamp;              // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
	} IMAGE_IMPORT_DESCRIPTOR;
	*/
	PIMAGE_IMPORT_DESCRIPTOR pImportDescript = NULL;
	PIMAGE_THUNK_DATA pThunkData = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
	int i = 0;
	int j = 0;
	DWORD dwRVA = 0;
	HMODULE hDll = NULL;
	LPCSTR lpProcName = NULL;
	DWORD dwRet = NULL;
	DWORD pIATInfo = NULL;

	//2. retrieve every import 
LOOP_IMPORT:
	pImportDescript = (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char *)gs_pDOSHDR
		+ ptagImportInfo->m_dwImpFA
		+ i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	assert(pImportDescript != NULL);

	//End only if Name is 0
	if (NULL == pImportDescript->Name)
	{
		goto LOOP_IMPORT_END;
	}

	//2.1 Basic Info about IMAGE_IMPORT_DESCRIPTOR
	//RVA, FA
	RVA2FA(ptagImportInfo, m_OriFirstThunk, m_OriFirstThunkFA, pImportDescript, OriginalFirstThunk, pAddrMap);
	RVA2FA(ptagImportInfo, m_NameRVA, m_NameFA, pImportDescript, Name, pAddrMap);
	RVA2FA(ptagImportInfo, m_FirstThunk, m_FristThunkFA, pImportDescript, FirstThunk, pAddrMap);

	_snprintf(gs_pszBuf, MAXBUF, "%s\r\nThe %d IMAGE_IMPORT_DESCRIPTOR- - - -(FA:%p):\r\n"
		"OriFirstThunk\t: %p\tOriFirstThunkFA\t: %p\r\n"
		"TimeDataStamp\t: %p\r\n"
		"ForwarderChain\t: %p\r\n"
		"Name          \t: %p   NameFA: %p\r\n"
		"FirstThunk    \t: %p   FirstThunkFA: %p\r\n"
		"DllName       \t: %s\r\n\r\n",
		gs_pszBuf,
		i,
		dwDescOff,
		ptagImportInfo->m_OriFirstThunk,
		ptagImportInfo->m_OriFirstThunkFA,
		pImportDescript->TimeDateStamp,
		pImportDescript->ForwarderChain,
		ptagImportInfo->m_NameRVA,
		ptagImportInfo->m_NameFA,
		ptagImportInfo->m_FirstThunk,
		ptagImportInfo->m_FristThunkFA,
		(unsigned char *)gs_pDOSHDR + ptagImportInfo->m_NameFA
	);
	dwDescOff += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	if (pIATDIR != NULL)
	{
		pIATInfo = (DWORD)(ptagImportInfo->m_FristThunkFA + (unsigned char *)gs_pDOSHDR);
	}

	//used to update IAT
	hDll = LoadLibrary((LPCSTR)((unsigned char *)gs_pDOSHDR + ptagImportInfo->m_NameFA));
	if (NULL == hDll)
	{
		MessageBox(NULL, (LPCSTR)((unsigned char *)gs_pDOSHDR + ptagImportInfo->m_NameFA),
			"Load Dll Failed", MB_OK);
		return FALSE;
	}

	//2.2 retrieve every hint and Func Name
	j = 0;

	lstrcat(gs_pszBuf, "Hint\tName1\tThunkOffsetRVA\tThunkOffsetFA\tAddrOfData\tAddrOfDataFA\tIAT\r\n");
LOOP_THUNK:
	pThunkData = (PIMAGE_THUNK_DATA)((unsigned char *)gs_pDOSHDR
		+ ptagImportInfo->m_OriFirstThunkFA
		+ j * sizeof(IMAGE_THUNK_DATA));
	if (NULL == pThunkData->u1.AddressOfData)
	{
		goto LOOP_THUNK_END;
	}

	//make sure it's import by name
	if (0 == (pThunkData->u1.Ordinal & 0x80000000))
	{
		RVA2FA(ptagImportInfo, m_AddrOfData, m_AddrOfDataFA, pThunkData, u1.AddressOfData, pAddrMap);
		pImportByName = (PIMAGE_IMPORT_BY_NAME)((unsigned char *)gs_pDOSHDR
			+ ptagImportInfo->m_AddrOfDataFA);

		_snprintf(gs_pszBuf, MAXBUF, "%s%04X\t%s\t%p\t%p\t%p\t%p\t%p\r\n",
			gs_pszBuf,
			pImportByName->Hint,
			pImportByName->Name,
			ptagImportInfo->m_OriFirstThunk + j * sizeof(IMAGE_THUNK_DATA),
			ptagImportInfo->m_OriFirstThunkFA + j * sizeof(IMAGE_THUNK_DATA),
			ptagImportInfo->m_AddrOfData,
			ptagImportInfo->m_AddrOfDataFA,
			pIATDIR ? *(DWORD *)pIATInfo : NULL
		);
		lpProcName = (LPCSTR)pImportByName->Name;
		pIATInfo += sizeof(DWORD);
	}
	else
	{
		//MessageBox(NULL, "ThunkData 0x8xxxxx", NULL, MB_OK);
		lpProcName = (LPCSTR)(pThunkData->u1.Ordinal & 0x7FFFFFFF);
	}

	//if IAT.RVA == NULL ,(or perhaps IAT.RVA != Thunk.AddrOfData) this will be treated invalid
	dwRVA = *(DWORD *)((unsigned char *)gs_pDOSHDR
		+ ptagImportInfo->m_FristThunkFA
		+ j * sizeof(IMAGE_THUNK_DATA));
	if (NULL == dwRVA
		//|| dwRVA != ptagImportInfo->m_AddrOfData  Bound
		)
	{
		::MessageBox(NULL, "Invalid Import!", NULL, MB_OK);
		lstrcat(gs_pszBuf, "******This import will be treated invalid****\r\n");
	}
	else
	{
		//now we update the IAT in memory
		dwRet = (DWORD)GetProcAddress(hDll, lpProcName);
		if (NULL == dwRet)
		{
			MessageBox(NULL, "GetProcAddr Error", NULL, MB_OK);
		}

		if (lpAddr != NULL)
		{
			*(DWORD *)((unsigned char *)lpAddr
				+ ptagImportInfo->m_FirstThunk
				+ j * sizeof(IMAGE_THUNK_DATA))
				= dwRet;
		}
	}

	j++;
	goto LOOP_THUNK;
LOOP_THUNK_END:

	i++;
	goto LOOP_IMPORT;
LOOP_IMPORT_END:

	*ppszBuf = gs_pszBuf;
	return TRUE;
}

/************************************************************************/
/*
Function : Retrieve FreeSpace Info
Param    : ppszBuf used to receive the buf pointer
Return   : TRUE if success, and set ppszBuf point to buf
FALSE otherwise                                        */
/************************************************************************/
BOOL GetFreeSpaceInfo(char **ppszBuf)
{
	assert(ppszBuf != NULL);

	ZeroMemory((unsigned char *)gs_pAllFreeSpace,
		sizeof(tagAllFreeSpace) + (gs_pFileHDR->NumberOfSections - 1) * sizeof(tagFreeSpace)
	);

	tagFreeSpace *pFreeSpace = NULL;

	//DOS Stub
	pFreeSpace = &gs_pAllFreeSpace->m_DOSStub;
	strcpy(pFreeSpace->m_szName, "DOSStub");
	if (gs_pDOSHDR->e_lfanew <= sizeof(IMAGE_DOS_HEADER))
	{
		//NOT EXIST
		pFreeSpace->m_dwFreeFA = -1;
	}
	else
	{
		pFreeSpace->m_dwFA = sizeof(IMAGE_DOS_HEADER);
		pFreeSpace->m_dwSize = gs_pDOSHDR->e_lfanew - sizeof(IMAGE_DOS_HEADER);
		pFreeSpace->m_dwFreeFA = pFreeSpace->m_dwFA;
		pFreeSpace->m_dwFreeSize = pFreeSpace->m_dwSize;
	}

	//Optional Header :   Opt Hdr ---> 1st Section Table
	pFreeSpace = &gs_pAllFreeSpace->m_OPTHDR;
	strcpy(pFreeSpace->m_szName, "OptHDR");
	pFreeSpace->m_dwFA = (DWORD)gs_pOPTHDR - (DWORD)gs_pDOSHDR;
	pFreeSpace->m_dwSize = gs_pFileHDR->SizeOfOptionalHeader;
	pFreeSpace->m_dwFreeFA = (DWORD)((unsigned char *)gs_pDataDIR +
		sizeof(IMAGE_DATA_DIRECTORY) * gs_pOPTHDR->NumberOfRvaAndSizes
		)
		- (DWORD)gs_pDOSHDR;
	pFreeSpace->m_dwFreeSize = (DWORD)gs_pFirstSectionHDR - (DWORD)gs_pDOSHDR - pFreeSpace->m_dwFreeFA;

	//SectionTable (allign) :  1st Section Table ----> Header End
	pFreeSpace = &gs_pAllFreeSpace->m_SectionTable;
	gs_pAllFreeSpace->m_nSections = gs_pFileHDR->NumberOfSections;

	strcpy(pFreeSpace->m_szName, "SectTbl");
	pFreeSpace->m_dwFA = (DWORD)gs_pFirstSectionHDR - (DWORD)gs_pDOSHDR;
	pFreeSpace->m_dwSize = (DWORD)gs_pOPTHDR->SizeOfHeaders - pFreeSpace->m_dwFA;
	pFreeSpace->m_dwFreeFA = pFreeSpace->m_dwFA + gs_pAllFreeSpace->m_nSections * sizeof(IMAGE_SECTION_HEADER);
	pFreeSpace->m_dwFreeSize = pFreeSpace->m_dwSize - gs_pAllFreeSpace->m_nSections * sizeof(IMAGE_SECTION_HEADER);

	//as for every section data, see GetSectionInfo;
	GetSectionInfo();

	//
	gs_pszBuf[0] = '\0';
	lstrcat(gs_pszBuf, "All Free Space Info:- - - -\r\n"
		"Name\t\tFA\t\tSize\t\tFreeFA\t\tFreeSize\r\n"
	);

	DWORD nCount = 1 /*DOSStub*/ + 1/*OPTHDR*/ + 1/*Section Table*/ + gs_pAllFreeSpace->m_nSections;
	for (DWORD i = 0; i < nCount; i++)
	{
		pFreeSpace = (tagFreeSpace *)((unsigned char *)gs_pAllFreeSpace + i * sizeof(tagFreeSpace));
		if (i >= 3)
		{
			pFreeSpace = &gs_pAllFreeSpace->m_SectionData[i - 3];
		}
		if (-1 == pFreeSpace->m_dwFreeFA)
		{
			_snprintf(gs_pszBuf, MAXBUF, "%s%s\t NOPE\r\n", gs_pszBuf, pFreeSpace->m_szName);
			continue;
		}
		_snprintf(gs_pszBuf, MAXBUF, "%s%s\t%p\t%p\t%p\t%p\r\n",
			gs_pszBuf,
			pFreeSpace->m_szName,
			pFreeSpace->m_dwFA,
			pFreeSpace->m_dwSize,
			pFreeSpace->m_dwFreeFA,
			pFreeSpace->m_dwFreeSize);
	}

	*ppszBuf = gs_pszBuf;

	return TRUE;
}

/************************************************************************/
/*
Function : Map the file (exe, or dll) into memory
Params   : lpAddr is the memory addr you can specify

1) copy headers
2) copy every sections according to section table

Return : TRUE for success, FALSE for failure                  */
/************************************************************************/
BOOL MapFileToMemory(LPVOID lpAddr)
{
	if (NULL == lpAddr)
	{
		return FALSE;
	}

	//copy header directly, change protect of course
	DWORD dwOldProtect;
	DWORD dwHeaderSize = gs_pNTHDR->OptionalHeader.SizeOfHeaders;
	BOOL bRet = VirtualProtect(lpAddr,
		dwHeaderSize,
		PAGE_EXECUTE_READWRITE,
		&dwOldProtect
	);
	if (!bRet)
	{
		return FALSE;
	}

	memcpy(lpAddr, gs_pDOSHDR, dwHeaderSize);

	VirtualProtect(lpAddr,
		gs_pOPTHDR->SizeOfImage,
		PAGE_EXECUTE_READWRITE,
		&dwOldProtect
	);

	//now copy every section data,
	PIMAGE_SECTION_HEADER pSectionHDR = gs_pFirstSectionHDR;
	unsigned char *pDST = (unsigned char *)lpAddr;
	unsigned char *pSRC = (unsigned char *)gs_pDOSHDR;
	WORD nSections = gs_pFileHDR->NumberOfSections;
	for (WORD i = 0; i < nSections; i++, pSectionHDR++)
	{
		if (NULL == pSectionHDR->PointerToRawData)
		{
			continue;
		}

		memcpy(pDST + pSectionHDR->VirtualAddress,
			pSRC + pSectionHDR->PointerToRawData,
			pSectionHDR->SizeOfRawData
		);

		//set characteristics    
	}

	return TRUE;
}

/************************************************************************/
/*
Function: Load Target APP into our space.
Make sure Our ImageBase same with the target's

Param   : gs_pDOSHDR is the target app's info
hSelf is the AppLoader's hinstance

Target App:                         Our Space:
DOS Header                        DOS Header
DOS Stub                          DOS Stub
FileHeader                        File Header
OPT Header                        OPT Header
Section Headers                   Section Headers
Section Datas                     Aligned Free space
(Big enough to contain Target's Section Datas)
Our Own Section Datas



Return  : TRUE if ok, FALSE otherwise                                  */
/************************************************************************/
BOOL LoadAPP(HMODULE hSelf)
{
	//make sure same imagebase
	if (hSelf != (HMODULE)gs_pNTHDR->OptionalHeader.ImageBase)
	{
		MessageBox(NULL, "Different ImageBase", NULL, MB_OK);

		return FALSE;
	}

	//make sure our's SizeOfHeader >= Target APP's SizeOfImage
	PIMAGE_DOS_HEADER pSelfDOSHDR = (IMAGE_DOS_HEADER *)hSelf;
	PIMAGE_NT_HEADERS32 pSelfNTHDR = (IMAGE_NT_HEADERS32 *)((unsigned char *)pSelfDOSHDR + pSelfDOSHDR->e_lfanew);
	if (pSelfNTHDR->OptionalHeader.SizeOfHeaders < gs_pOPTHDR->SizeOfImage)
	{
		MessageBox(NULL, "Our's SizeOfHeaders < His SizeOfImage", NULL, MB_OK);
		return FALSE;
	}

	//1. 
	if (!MapFileToMemory(hSelf))
	{
		return FALSE;
	}

	//2. update IAT, reuse code about Import Table, 
	char *pszBuf;
	GetImportInfo(&pszBuf, hSelf);

	//now jump to the target app's OEP
	DWORD dwOEP = (DWORD)((unsigned char *)gs_pOPTHDR->ImageBase + gs_pOPTHDR->AddressOfEntryPoint);
	_asm
	{
		xor eax, eax
		jmp dwOEP
	}

	return TRUE;
}

/************************************************************************/
/*
Function : Retrieve Export Info
Param    : ppszBuf used to receive the buf pointer
Return   : TRUE if success, and set ppszBuf point to buf
FALSE otherwise                                        */
/************************************************************************/
#define  SIMPLE //for UseDeugger
BOOL GetExportInfo(char **ppszBuf)
{
	DWORD dwAddr;
	//recheck
	if (0 == gs_pOPTHDR->NumberOfRvaAndSizes)
	{
		return FALSE;
	}

	gs_pExportDir = &gs_pOPTHDR->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (NULL == gs_pExportDir->VirtualAddress)
	{
		return FALSE;
	}

	assert(ppszBuf != NULL);
	*ppszBuf = NULL;

	//1. Get Export RVA and Size from DataDirectory
	static tagExportInfo *ptagExportInfo = new tagExportInfo;
	assert(ptagExportInfo != NULL);
	static tagAddrMAP *pAddrMap = new tagAddrMAP;
	assert(pAddrMap != NULL);

	//RVA, FA
	RVA2FA(ptagExportInfo, m_dwExpRVA, m_dwExpFA, gs_pExportDir, VirtualAddress, pAddrMap);
	ptagExportInfo->m_dwExpSize = gs_pExportDir->Size;

#ifndef SIMPLE
	wsprintf(gs_pszBuf, "Export Directory: \r\nRVA\t:%p\r\nFA\t:%p\r\nSize\t:%p\r\nSection\t:%s\r\n\r\n",
		ptagExportInfo->m_dwExpRVA,
		ptagExportInfo->m_dwExpFA,
		ptagExportInfo->m_dwExpSize,
		pAddrMap->m_szSectionName);
#else
	//to help locate
	wsprintf(gs_pszBuf, "%32s", "\r\n");
#endif

	/*
	typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
	} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
	*/
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((unsigned char *)gs_pDOSHDR + ptagExportInfo->m_dwExpFA);
	assert(pExportDir != NULL);

	//2.1 Basic Info about IMAGE_EXPORT_DIRECTORY
	//RVA, FA
	/*
	DWORD m_dwNameRVA;
	DWORD m_dwNameFA;
	DWORD m_AddrOfFunctionsRVA;     // RVA from base of image
	DWORD m_AddrOfFunctionsFA;
	DWORD m_AddrOfNamesRVA;         // RVA from base of image
	DWORD m_AddrOfNamesFA;
	DWORD m_AddrOfNameOrdinalsRVA;  // RVA from base of image
	DWORD m_AddrOfNameOrdinalsFA;
	*/
	RVA2FA(ptagExportInfo, m_dwNameRVA, m_dwNameFA, pExportDir, Name, pAddrMap);
	RVA2FA(ptagExportInfo, m_AddrOfFunctionsRVA, m_AddrOfFunctionsFA, pExportDir, AddressOfFunctions, pAddrMap);
	RVA2FA(ptagExportInfo, m_AddrOfNamesRVA, m_AddrOfNamesFA, pExportDir, AddressOfNames, pAddrMap);
	RVA2FA(ptagExportInfo, m_AddrOfNameOrdinalsRVA, m_AddrOfNameOrdinalsFA, pExportDir, AddressOfNameOrdinals, pAddrMap);

#ifndef SIMPLE
	_snprintf(gs_pszBuf, MAXBUF, "%s\r\nThe IMAGE_EXPORT_DIRECTORY- - - -:\r\n"
		"Characteristics\t: %p\r\n"
		"TimeDataStamp\t: %p\r\n"
		"MajorVersion\t: %04X\r\n"
		"MinorVersion\t: %04X\r\n"
		"Name          \t: %p   NameFA: %p\t%s\r\n"
		"Base          \t: %p\r\n"
		"NumberOfFunctions: %p\r\n"
		"NumberOfNames    : %p\r\n"
		"AddressOfFunctions : %p\tAddressOfFunctionsFA: %p\r\n"
		"AddressOfNames     : %p\tAddressOfNamesFA:%p\r\n"
		"AddressOfNameOrdinals : %p\tAddressOfNameOrdinalsFA: %p\r\n\r\n",
		gs_pszBuf,
		pExportDir->Characteristics,
		pExportDir->TimeDateStamp,
		pExportDir->MajorVersion,
		pExportDir->MinorVersion,
		ptagExportInfo->m_dwNameRVA,
		ptagExportInfo->m_dwNameFA,
		(unsigned char *)gs_pDOSHDR + ptagExportInfo->m_dwNameFA,
		pExportDir->Base,
		pExportDir->NumberOfFunctions,
		pExportDir->NumberOfNames,
		ptagExportInfo->m_AddrOfFunctionsRVA,
		ptagExportInfo->m_AddrOfFunctionsFA,
		ptagExportInfo->m_AddrOfNamesRVA,
		ptagExportInfo->m_AddrOfNamesFA,
		ptagExportInfo->m_AddrOfNameOrdinalsRVA,
		ptagExportInfo->m_AddrOfNameOrdinalsFA
	);
#endif

	//now retrieve every exported func info
	DWORD *pAddrOfFuncs = (DWORD *)((unsigned char *)gs_pDOSHDR + ptagExportInfo->m_AddrOfFunctionsFA);
	DWORD *pAddrOfNames = (DWORD *)((unsigned char *)gs_pDOSHDR + ptagExportInfo->m_AddrOfNamesFA);
	WORD *pAddrOfNameOrd = (WORD *)((unsigned char *)gs_pDOSHDR + ptagExportInfo->m_AddrOfNameOrdinalsFA);

#ifndef SIMPLE
	_snprintf(gs_pszBuf, MAXBUF, "%sExported By Name:\r\n"
		"NameOrd"//(+Base)
		"\tFuncName\tFuncAddrRVA\tFuncAddrFA\tFuncNameRVA\tFuncNameFA\r\n",
		gs_pszBuf);
#endif

	//used for forwarding
	DWORD dwExpBegin = ptagExportInfo->m_dwExpRVA;
	DWORD dwExpEnd = ptagExportInfo->m_dwExpRVA + ptagExportInfo->m_dwExpSize;

	DWORD i = 0;
	for (i = 0; i < pExportDir->NumberOfNames; i++)
	{
		ptagExportInfo->m_FuncNameRVA = pAddrOfNames[i];
		RVA2FA(ptagExportInfo, m_FuncNameRVA, m_FuncNameFA, ptagExportInfo, m_FuncNameRVA, pAddrMap);

		ptagExportInfo->m_FuncAddrRVA = pAddrOfFuncs[pAddrOfNameOrd[i]];
		RVA2FA(ptagExportInfo, m_FuncAddrRVA, m_FuncAddrFA, ptagExportInfo, m_FuncAddrRVA, pAddrMap);
		_snprintf(gs_pszBuf, MAXBUF, "%s%04x"//(+%p)
			"\t%s\t%p"
#ifndef SIMPLE
			"\t%p\t%p\t%p"
#endif
			"\r\n",
			gs_pszBuf,
			pAddrOfNameOrd[i],
			//pExportDir->Base,
			(unsigned char *)gs_pDOSHDR + ptagExportInfo->m_FuncNameFA,
			ptagExportInfo->m_FuncAddrRVA
#ifndef SIMPLE
			,
			ptagExportInfo->m_FuncAddrFA,
			ptagExportInfo->m_FuncNameRVA,
			ptagExportInfo->m_FuncNameFA
#endif
		);
		dwAddr = gs_pOPTHDR->ImageBase + ptagExportInfo->m_FuncAddrRVA;
		gs_mapAddr_ExportName[dwAddr] = (char *)gs_pDOSHDR + ptagExportInfo->m_FuncNameFA;

#ifndef SIMPLE
		//whether forwarding, FuncAddrRVA >= ExpRVA && FuncAddrRVA <ExpRVA + ExpSize
		if (ptagExportInfo->m_FuncAddrRVA >= dwExpBegin
			&& ptagExportInfo->m_FuncAddrRVA < dwExpEnd)
		{
			_snprintf(gs_pszBuf, MAXBUF, "%s\t--->%s\r\n",
				gs_pszBuf,
				(unsigned char *)gs_pDOSHDR + ptagExportInfo->m_FuncAddrFA);
		}
#endif

	}

	//whether exported, but not by name exists
	if (pExportDir->NumberOfNames != pExportDir->NumberOfFunctions)
	{
		DWORD nFunctions = 0;
		for (i = 0; i < pExportDir->NumberOfFunctions; i++)
		{
			if (pAddrOfFuncs[i] != 0)
			{
				nFunctions++;
				//can also record the addr
			}
		}

#ifndef SIMPLE
		if (nFunctions != pExportDir->NumberOfNames)
		{
			_snprintf(gs_pszBuf, MAXBUF, "%sExport By Ord Exists %p\r\n",
				gs_pszBuf,
				nFunctions - pExportDir->NumberOfNames);
		}
#endif
	}

	*ppszBuf = gs_pszBuf;
	return TRUE;
}

int StrCompare(const char *pszSRC, const char *pszDST)
{
	return strcmp(pszSRC, pszDST);
}

DWORD BinSearch(DWORD *pBase, DWORD nCount, const char *pszTarget, HMODULE hModule)
{
	int nRet = 0;
	DWORD l = 0;
	DWORD h = nCount - 1;
	DWORD m = (l + h) / 2;
	while (l <= h)
	{
		nRet = StrCompare(pszTarget, (char *)(pBase[m] + (unsigned char *)hModule));
		if (0 == nRet)
		{
			return m;
		}

		//left search
		if (nRet < 0)
		{
			h = m - 1;
		}
		else
		{
			l = m + 1;
		}

		m = (l + h) / 2;
	}
	return -1;
}

/************************************************************************/
/*
Function : Self Implementation of GetProcAddress
Param    : lpProcName
[in] Pointer to a null-terminated string containing the function or variable name,
or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero.
Return   : NULL for Failure, otherwise the addr of function            */
/************************************************************************/
DWORD DoGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	assert(hModule != NULL);
	assert(lpProcName != NULL);

	DWORD dwRet = NULL;
	PIMAGE_DOS_HEADER pDOSHDR = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNTHDR = (PIMAGE_NT_HEADERS)((unsigned char *)pDOSHDR + pDOSHDR->e_lfanew);
	PIMAGE_DATA_DIRECTORY pExpData = (PIMAGE_DATA_DIRECTORY)(pNTHDR->OptionalHeader.DataDirectory);
	PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)((unsigned char *)pDOSHDR + pExpData->VirtualAddress);

	DWORD *pAddrOfFuncs = (DWORD *)((unsigned char *)pDOSHDR + pExpDir->AddressOfFunctions);
	DWORD *pAddrOfNames = (DWORD *)((unsigned char *)pDOSHDR + pExpDir->AddressOfNames);
	WORD *pAddrOfNameOrd = (WORD *)((unsigned char *)pDOSHDR + pExpDir->AddressOfNameOrdinals);

	//If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero. 
	if (0 == ((DWORD)lpProcName & 0xFFFF0000))
	{
		dwRet = (DWORD)((unsigned char *)pDOSHDR + pAddrOfFuncs[(DWORD)lpProcName - pExpDir->Base]);
		return dwRet;
	}

	//now deal with name, need to compare
	dwRet = BinSearch(pAddrOfNames, pExpDir->NumberOfNames, lpProcName, hModule);
	if (-1 == dwRet)
	{
		return NULL;
	}

	//get NameOrd, also as the index within AddressOfFunctions
	dwRet = pAddrOfNameOrd[dwRet];

	//whether forwarding
	if (pAddrOfFuncs[dwRet] > pExpData->VirtualAddress
		&& pAddrOfFuncs[dwRet] <= pExpData->VirtualAddress + pExpData->Size)
	{
		char pszBuf[MAXBYTE] = { 0 };
		strcpy(pszBuf, (char *)pDOSHDR + pAddrOfFuncs[dwRet]);
		char *p = strchr(pszBuf, '.');
		assert(p != NULL);
		p[0] = '\0';
		p++;

		HMODULE hDll = LoadLibrary(pszBuf);
		if (NULL == hDll)
		{
			return NULL;
		}

		return DoGetProcAddress(hDll, p);
	}

	//now get addr
	dwRet = (DWORD)((unsigned char *)pDOSHDR + pAddrOfFuncs[dwRet]);

	return dwRet;
}

/************************************************************************/
/*
Function : Get Process's ImageBase, ModuleName, Module Size
Params   : szModName is the buf to receive module name
nMAX is the buf's limit
Return   : NULL for FAILURE                                                                 */
/************************************************************************/
BYTE *GetImageBase(DWORD dwPID, char szModName[], DWORD *pdwSize, int nMAX)
{
	//Get Basic Info about the process, ImageBase specially
	HANDLE         hProcessSnap = NULL;
	BOOL           bRet = FALSE;
	MODULEENTRY32 me32 = { 0 };
	char *pszModName;
	BYTE *pRet = NULL;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		return pRet;
	}

	me32.dwSize = sizeof(MODULEENTRY32);
	bRet = Module32First(hProcessSnap, &me32);
	if (!bRet)
	{
		goto SAFE_CLEAN;
	}

	pszModName = me32.szModule;
	assert(strstr(pszModName, ".exe") != NULL); //bad idea

	pRet = me32.modBaseAddr;
	*pdwSize = me32.modBaseSize;
	if (szModName != NULL)
	{
		lstrcpyn(szModName, pszModName, nMAX);
	}

SAFE_CLEAN:
	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hProcessSnap);
		hProcessSnap = NULL;
	}

	return pRet;
}

/************************************************************************/
/*
Function : Get AddressOfEntryPoint  (or Original Entry Point)
Params   : lpAddr is the Base where the exe mapped into
Return   : OEP (RVA)             */
/************************************************************************/
DWORD GetOEP(LPVOID lpAddr)
{
	PIMAGE_DOS_HEADER pDOSHDR = (PIMAGE_DOS_HEADER)lpAddr;
	PIMAGE_NT_HEADERS pNTHDR = (PIMAGE_NT_HEADERS)((unsigned char *)pDOSHDR + pDOSHDR->e_lfanew);
	return pNTHDR->OptionalHeader.AddressOfEntryPoint;
}

/************************************************************************/
/*
Function : Retrieve a process's Import Info only by IAT
Param    : lpAddr is the address the exe mapped into (within our space)
ptr1stIAT [out] used to receive the 1st IAT we found (FF25 XXXX, FF15YYYY)

Return   : the beginning of the page where IAT in

Search for FF25 XXXX,  or FF15 yyyy

HelloWorld.exe
004001E0 > .  EA07D577      DD USER32.MessageBoxA
004001E4      00000000      DD 00000000
004001E8 >/$  6A 00         PUSH 0                                   ; /Style = MB_OK|MB_APPLMODAL
004001EA  |.  6A 00         PUSH 0                                   ; |Title = NULL
004001EC  |.  6A 00         PUSH 0                                   ; |Text = NULL
004001EE  |.  6A 00         PUSH 0                                   ; |hOwner = NULL
004001F0  |.  E8 01000000   CALL <JMP.&USER32.MessageBoxA>           ; \MessageBoxA
004001F5  \.  C3            RETN
004001F6   $- FF25 E0014000 JMP DWORD PTR DS:[<&USER32.MessageBoxA>] ;  USER32.MessageBoxA

Notepad.exe
0100740B   .  FF15 38130001      CALL DWORD PTR DS:[<&msvcrt.__set_app_ty>;  msvcrt.__set_app_type

MSPaint.exe
1000CA65    8B35 58D10110   MOV ESI,DWORD PTR DS:[<&KERNEL32.LCMapSt>; kernel32.LCMapStringW

*/
/************************************************************************/
DWORD SearchIAT(LPVOID lpAddr, DWORD dwImageSize, unsigned char *pImageBase, DWORD *ptr1stIAT)
{
	DWORD *ptrFuncAddr = NULL;     //like xxx in JMP DWORD PTR DS:[XXXX]
	DWORD dwOEP = NULL;
	BYTE *pCode = NULL;
	DWORD i = NULL;
	WORD  wJMP = 0x25FF;
	WORD  wCALL = 0x15FF;

	dwOEP = GetOEP(lpAddr);
	i = dwOEP;
	pCode = (BYTE *)((BYTE *)lpAddr + dwOEP);

	wsprintf(gs_pszBuf, "Found OEP at %p\r\n", dwOEP);

	//search for FF 25 XXXX, FF 15 YYYY from OEP, had better use Disasm engine 
	//but we just do it simply
	while (i < dwImageSize)
	{
		if (memcmp(pCode, &wJMP, sizeof(WORD))
			&& memcmp(pCode, &wCALL, sizeof(WORD)))
		{
			//
			pCode++;
			i++;
			continue;
		}

		//check illegal, *ptrFuncAddr > pImageBase  && *ptrFuncAddr <= pImageBase + dwImageSize
		ptrFuncAddr = (DWORD *)(pCode + sizeof(WORD));
		if (*ptrFuncAddr < (DWORD)pImageBase
			|| *ptrFuncAddr >= (DWORD)pImageBase + dwImageSize)
		{
			pCode += 2;
			i += 2;
			continue;
		}

		//need to fix relocation
		*(DWORD *)ptrFuncAddr = (long)lpAddr + *(long *)ptrFuncAddr - (long)pImageBase;

		//now found one item that may belongs to IAT
		ptrFuncAddr = (DWORD *)*ptrFuncAddr;

		//recheck illegal, 
		//for system dlls, what about user dlls? well, whatever, there must be system dlls
		//what if we found IAT for system dlls, so we found the user dlls.
		//What if the IAT tables are not continous????????
		if (*ptrFuncAddr < 0x70000000)
		{
			pCode += 2;
			i += 2;
			continue;
		}

		//now it seems ptrFuncAddr points some item in IAT, 
		//make ptrFuncAddr point to the beginning of the page
		//we use 0xFFFEFFFF, because ptrFuncAddr is the memory addr we allocated, not by loadlibrary
		*ptr1stIAT = (DWORD)ptrFuncAddr;
		ptrFuncAddr = (DWORD*)(((DWORD)ptrFuncAddr & 0xFFFFF000)
			+ ((DWORD)lpAddr & 0x0FFF)
			);
		return (DWORD)ptrFuncAddr;
	}

	return NULL;
}

BOOL SnapShotModules(DWORD dwPID)
{
	//对进程模块进行遍历，并插入到list view中
	HANDLE         hProcessSnap = NULL;
	BOOL           bRet = TRUE;
	MODULEENTRY32 me32 = { 0 };

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		return FALSE;
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	bRet = Module32First(hProcessSnap, &me32);
	if (!bRet)
	{
		bRet = FALSE;
		goto ERROR_CLEAN;
	}

	gs_ModuleList.clear();
	do
	{
		//record these module info
		gs_ModuleList.push_back(me32);
	} while (Module32Next(hProcessSnap, &me32));

ERROR_CLEAN:
	CloseHandle(hProcessSnap);
	hProcessSnap = NULL;

	return bRet;
}

/************************************************************************/
/*
Function : Retrieve API info by its addr and the module it belongs to
Params   : pBuf points to the image mapped to our space*/
/************************************************************************/
void GetAPIInfo(DWORD ptrAPI, MODULEENTRY32 *pme32, BYTE *pBuf)
{
	//try to load the dll into our space
	HMODULE hDll = LoadLibrary(pme32->szExePath);
	if (NULL == hDll)
	{
		return;
	}

	//now ask for info from Export
	PIMAGE_DOS_HEADER pDOSHDR = (PIMAGE_DOS_HEADER)hDll;
	PIMAGE_NT_HEADERS pNTHDR = (PIMAGE_NT_HEADERS)((BYTE *)pDOSHDR + pDOSHDR->e_lfanew);
	if (pNTHDR->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
	{
		return;
	}

	PIMAGE_EXPORT_DIRECTORY pExpDIR = (PIMAGE_EXPORT_DIRECTORY)
		((BYTE *)pDOSHDR
			+ pNTHDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD dwFunctions = pExpDIR->NumberOfFunctions;
	DWORD *ptrAddrFunc = (DWORD *)((BYTE *)pDOSHDR + pExpDIR->AddressOfFunctions);
	DWORD i = 0;

	//get index by address
	for (i = 0; i < dwFunctions; i++)
	{
		if (((DWORD)pDOSHDR + ptrAddrFunc[i]) == *(DWORD*)ptrAPI)
		{
			break;
		}
	}

	//not match
	if (i == dwFunctions)
	{
		return;
	}

	//get name and ordinal
	DWORD dwNames = pExpDIR->NumberOfNames;
	DWORD *pNames = (DWORD *)((BYTE *)pDOSHDR + pExpDIR->AddressOfNames);
	WORD *pNameOrd = (WORD *)((BYTE *)pDOSHDR + pExpDIR->AddressOfNameOrdinals);
	DWORD j = 0;
	char *pszName = NULL;
	SIZE_T nLen = 0;
	for (j = 0; j < dwNames; j++)
	{
		if (pNameOrd[j] == i)
		{
			pszName = (char *)pDOSHDR + pNames[j];
			nLen = strlen(pszName);
			_snprintf(gs_pszBuf, MAXBUF, "%s%p\t%04X\t%s\r\n",
				gs_pszBuf,
				*(DWORD *)ptrAPI,
				j,
				pszName
			);

#if 0
			//save these info
			* (WORD *)pBuf = j;
			strcpy((char *)pBuf + sizeof(WORD), pszName);
			gs_nIndex += (sizeof(WORD) + nLen);
			if (0 == gs_nIndex % 2)
			{
				//pad with 2 null
				*(WORD *)&pBuf[gs_nIndex] = 0x0000;
				gs_nIndex += 2;
			}
			else
			{
				//pad with 1 null is ok
				pBuf[gs_nIndex] = 0x00;
				gs_nIndex++;
			}
#endif
		}
	}
}

/************************************************************************/
/*
Function : rebuild Import Info according to IAT
Params   : ptrIAT point to the page where IAT in
ppBuf [IN/OUT] is the memory space for the exe, may be updated
dwImageSize is the exe's image size                                                                  */
/************************************************************************/
void FixImport(DWORD dwPID, DWORD ptrIAT, DWORD ptr1stIAT, BYTE **ppBuf, DWORD dwImageSize)
{
	//now verify every DWORD item is a valid FuncPtr with some dll.
	//we need to snapshot the process.
	list<MODULEENTRY32>::iterator it;
	MODULEENTRY32 me32;
	BOOL bRet = SnapShotModules(dwPID);
	if (!bRet)
	{
		return;
	}

	//extend the buf to contain import info
	BYTE *ptmp = new BYTE[dwImageSize * 2];
	if (NULL == ptmp)
	{
		return;
	}

	//     memcpy(ptmp, *ppBuf, dwImageSize);
	//     *ppBuf = ptmp;
	//     gs_nIndex = dwImageSize;

	//
	DWORD ptrIndex = ptrIAT;
	DWORD dwModBase = NULL;  //利用局部性原理，减少比较
	DWORD dwModSize = NULL;
	DWORD dwModHit = NULL;
	while (TRUE)
	{
		//thz should always continue, even if BadPtr or invalid funcptr
		if (ptrIndex <= ptr1stIAT
			&& IsBadReadPtr((const void *)*(DWORD *)ptrIndex, sizeof(DWORD)))
		{
			ptrIndex += sizeof(DWORD);
			continue;
		}

		//now we may end, be careful
		if (ptrIndex > ptr1stIAT
			&& (NULL == *(DWORD*)ptrIndex)
			&& (NULL == *(DWORD*)(ptrIndex + sizeof(DWORD))))
		{
			break;
		}

		if (ptrIndex > ptr1stIAT
			&& IsBadReadPtr((const void *)*(DWORD *)ptrIndex, sizeof(DWORD))
			)
		{
			ptrIndex += sizeof(DWORD);
			continue;
		}

		//////////////////////////////////////////////////////////////////////////
		//whether in a module range
		dwModHit = NULL;

		//局部性原理，减少遍历
		if (*(DWORD *)ptrIndex >= dwModBase
			&& *(DWORD *)ptrIndex < dwModBase + dwModSize)
		{
			dwModHit = dwModBase;
		}

		//have to loop every module
		if (NULL == dwModHit)
		{
			for (it = gs_ModuleList.begin(); it != gs_ModuleList.end(); it++)
			{
				me32 = *it;
				dwModBase = (DWORD)me32.hModule;
				dwModSize = (DWORD)me32.modBaseSize;
				if (*(DWORD *)ptrIndex >= dwModBase
					&& *(DWORD *)ptrIndex < dwModBase + dwModSize)
				{
					_snprintf(gs_pszBuf, MAXBUF, "%s\r\n"
						"Module: %s\r\n",
						gs_pszBuf,
						me32.szModule);
					break;
				}
			}//end for(
		}//end if(NULL == 

		 //now *ptrIndex in dwModBase
		 //now retrieve API info (Hint, name) from the module's export
		GetAPIInfo(ptrIndex, &me32, *ppBuf);

		ptrIndex += sizeof(DWORD);
	}
}

/************************************************************************/
/*
Function : Dump the specified process into file
Param    : bFix indicate whether need to fix the import
if true, will rebuild the import table at the end of the file

ppszBuf is used to receive log.
you can set it as NULL if you do not need.

Suppose AppName.exe --> AppName_dump.exe*/
/************************************************************************/
void DumpPE(DWORD dwPID, BOOL bFix, char **ppszBuf)
{
	char szModName[MAX_MODULE_NAME32 + 1];
	DWORD dwModSize;
	BYTE *pModBase = GetImageBase(dwPID, szModName, &dwModSize, MAX_MODULE_NAME32 + 1);
	if (NULL == pModBase)
	{
		return;
	}

	//仅需最少、最必须的权限即可，否则可能失败
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		dwPID);
	if (NULL == hProcess)
	{
		return;
	}

	//read image into our space
	PIMAGE_DOS_HEADER pDOSHDR = NULL;
	PIMAGE_OPTIONAL_HEADER pOPTHDR = NULL;
	PIMAGE_NT_HEADERS pNTHDR = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;  //used to retrieve every section header
	PIMAGE_SECTION_HEADER pFirstSectionHDR = NULL;
	DWORD dwReadWrite = 0;
	WORD i = 0;
	BOOL bRet = FALSE;
	HANDLE hFile = NULL;
	BYTE *pBuf = new BYTE[dwModSize];

	if (NULL == pBuf)
	{
		goto SAFE_CLEAN;
	}

	bRet = ReadProcessMemory(hProcess, pModBase, pBuf, dwModSize, &dwReadWrite);
	if (!bRet)
	{
		goto SAFE_CLEAN;
	}

	if (bFix)
	{
		//now we do more, retrieve the Page where IAT in
		DWORD ptr1stIAT = NULL;
		DWORD ptrIAT = SearchIAT(pBuf, dwModSize, pModBase, &ptr1stIAT);

		if (ppszBuf != NULL)
		{
			_snprintf(gs_pszBuf, MAXBUF,
				"%sRebuilding IAT........................................................................................\r\n"
				"Found 1stIAT at %p\r\n"
				"IAT in page %p\r\n",
				gs_pszBuf,
				ptr1stIAT,
				ptrIAT);
		}

		FixImport(dwPID, ptrIAT, ptr1stIAT, &pBuf, dwModSize);
	}

	//prepare file to save
	lstrcat(szModName, "_dump.exe");
	hFile = CreateFile(szModName,
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		goto SAFE_CLEAN;
	}

	//////////////////////////////////////////////////////////////////////////
	//now do pe analysis
	pDOSHDR = (PIMAGE_DOS_HEADER)pBuf;
	pNTHDR = (PIMAGE_NT_HEADERS)((BYTE *)pDOSHDR + pDOSHDR->e_lfanew);
	pOPTHDR = (PIMAGE_OPTIONAL_HEADER)(&pNTHDR->OptionalHeader);
	pFirstSectionHDR = IMAGE_FIRST_SECTION(pNTHDR);

	//dump header first
	bRet = WriteFile(hFile, pBuf, pOPTHDR->SizeOfHeaders, &dwReadWrite, NULL);
	if (!bRet)
	{
		goto SAFE_CLEAN;
	}

	//now dump every section
	for (i = 0; i < pNTHDR->FileHeader.NumberOfSections; i++)
	{
		pSection = &pFirstSectionHDR[i];

		//assumes section data one by one?
		bRet = WriteFile(hFile,
			pBuf + pSection->VirtualAddress,
			pSection->SizeOfRawData,
			&dwReadWrite,
			NULL);
		if (!bRet)
		{
			goto SAFE_CLEAN;
		}
	}

SAFE_CLEAN:
	if (pBuf != NULL)
	{
		delete[] pBuf;
		pBuf = NULL;
	}

	if (hProcess != NULL)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
	}

	if (hFile != NULL)
	{
		CloseHandle(hFile);
		hFile = NULL;
	}

	if (ppszBuf != NULL)
	{
		*ppszBuf = gs_pszBuf;
	}
}

/************************************************************************/
/*
Function : Retrieve Base Relocation Info

Params   : ppszBuf is the buf to retrieve log
pRealBase is the memory address the dll really loaded
you can set it NULL if you do not need
pImageBase is the memory address the dll should be loaded,
usually it is the PE.ImageBase
you can set it NULL if you do not need

MAKE SURE pRealBase == NULL && pImageBase == NULL
or pRealBase != NULL && pImageBase != NULL

IMAGE_DIRECTORY_ENTRY_BASERELOC
*/
/************************************************************************/
BOOL GetBaseRelocInfo(char **ppszBuf,
	unsigned char *pRealBase/*=NULL*/,
	unsigned char *pImageBase/*=NULL*/)
{
	//recheck
	if (gs_pOPTHDR->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_BASERELOC + 1)
	{
		return FALSE;
	}

	PIMAGE_DATA_DIRECTORY pBaseRelocDir = &gs_pOPTHDR->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (NULL == pBaseRelocDir->VirtualAddress)
	{
		return FALSE;
	}

	assert(ppszBuf != NULL);
	*ppszBuf = NULL;

	BOOL bRet = TRUE;

	//1. Get BaseReloc RVA and Size from DataDirectory
	static tagAddrMAP *pAddrMap = new tagAddrMAP;
	assert(pAddrMap != NULL);
	pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA;

	pAddrMap->m_dwRVA = pBaseRelocDir->VirtualAddress;
	GetAddrMAPByRVA(pAddrMap);
	DWORD dwBaseRelocRVA = pAddrMap->m_dwRVA;
	DWORD dwBaseRelocFA = pAddrMap->m_dwFA;
	DWORD dwBaseRelocSize = pBaseRelocDir->Size;

	wsprintf(gs_pszBuf, "BaseReloc Directory: \r\nRVA\t:%p\r\nFA\t:%p\r\nSize\t:%p\r\nSection\t:%s\r\n\r\n",
		dwBaseRelocRVA,
		dwBaseRelocFA,
		pBaseRelocDir->Size,
		pAddrMap->m_szSectionName);

	/*
	typedef struct _IMAGE_BASE_RELOCATION {
	DWORD   VirtualAddress;
	DWORD   SizeOfBlock;
	//  WORD    TypeOffset[1];
	} IMAGE_BASE_RELOCATION;
	typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
	*/
	PIMAGE_BASE_RELOCATION pBaseReloc = NULL;
	pBaseReloc = (PIMAGE_BASE_RELOCATION)((unsigned char *)gs_pDOSHDR + pAddrMap->m_dwFA);
	assert(pBaseReloc != NULL);

	//retrieve every relocation info
	DWORD dwSize = 0;
	DWORD nCount = 0;
	DWORD dwRVA = 0;
	DWORD i = 0;
	DWORD dwflg = 0;
	WORD *pTypeOffset = NULL;

	//used for fixing base relocation
	DWORD dwOriValue = NULL;
	DWORD dwAddr = NULL;

	while (dwSize < dwBaseRelocSize)
	{
		nCount = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		_snprintf(gs_pszBuf, MAXBUF, "%s\r\n\r\nIMAGE_BASE_RELOCATION Info:\r\n"
			"VirtualAddress\tnCount\tFA\r\n"
			"%p\t%p\t%p\r\n\r\n"
			"Detail:\r\n",
			gs_pszBuf,
			pBaseReloc->VirtualAddress,
			nCount,
			dwBaseRelocFA);
		pTypeOffset = (WORD *)((unsigned char *)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

		//
		i = 0;
		while (i < nCount)    //loop every every TypeOffset
		{
			dwflg = pTypeOffset[i] & 0x3000;
			if (0x3000 == dwflg)        //high, low relocation
			{
				dwRVA = 0/*gs_pOPTHDR->ImageBase*/
					+ pBaseReloc->VirtualAddress
					+ (pTypeOffset[i] & 0x0FFF);

				if (pRealBase != NULL
					&& pImageBase != NULL)
				{
					dwAddr = (DWORD)(pRealBase + dwRVA);
					dwOriValue = *(DWORD*)dwAddr;
					*(DWORD *)dwAddr = (long)pRealBase + (long)dwOriValue - (long)pImageBase;
				}
			}
			else if (0 == dwflg)
			{
				dwRVA = 0xFFFFFFFF; //absolute, used for align
			}
			else
			{
				//sth wrong?
				dwRVA = 0xCCCCCCCC; //
			}

			_snprintf(gs_pszBuf, MAXBUF, "%s%p  ", gs_pszBuf, dwRVA);
			if (0 == ((i + 1) % 8))
			{
				_snprintf(gs_pszBuf, MAXBUF, "%s\r\n", gs_pszBuf);
			}

			i++;
		}

		dwSize += pBaseReloc->SizeOfBlock;
		dwBaseRelocFA += pBaseReloc->SizeOfBlock;
		pBaseReloc = (PIMAGE_BASE_RELOCATION)((unsigned char *)pBaseReloc + pBaseReloc->SizeOfBlock);
	}

	*ppszBuf = gs_pszBuf;
	return TRUE;
}

/************************************************************************/
/*
Function: Load Target APP into our space.

Param   : gs_pDOSHDR is the target app's info

Return  : NULL for failure, otherwise the hModule                                  */
/************************************************************************/
HMODULE LoadDll()
{
	//1. 
	LPVOID lpAddr = VirtualAlloc(NULL, gs_pOPTHDR->SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == lpAddr)
	{
		return NULL;
	}

	if (!MapFileToMemory(lpAddr))
	{
		return NULL;
	}

	//2. update IAT, reuse code about Import Table, 
	char *pszBuf;
	GetImportInfo(&pszBuf, lpAddr);

	//3. fix Base Relocation
	GetBaseRelocInfo(&pszBuf,
		(unsigned char*)lpAddr,
		(unsigned char *)gs_pOPTHDR->ImageBase);



	//4. now call dllmain
	DWORD dwOEP = (DWORD)((unsigned char *)lpAddr + gs_pOPTHDR->AddressOfEntryPoint);
	_asm
	{
		push NULL
		push DLL_PROCESS_ATTACH
		push lpAddr
		call dwOEP
	}
	return (HMODULE)lpAddr;
}

/************************************************************************/
/*
Function : Entry for retrieving TLS Info
Params   : ppszBuf used to receive the log                             */
/************************************************************************/
BOOL GetTLSInfo(char **ppszBuf)
{
	assert(ppszBuf != NULL);
	*ppszBuf = NULL;

	if (gs_pOPTHDR->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_TLS + 1)
	{
		return FALSE;
	}

	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&gs_pOPTHDR->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (NULL == pDataDir->VirtualAddress)
	{
		return FALSE;
	}

	//1. Get TLS RVA and Size from DataDirectory
	static tagAddrMAP *pAddrMap = new tagAddrMAP;
	assert(pAddrMap != NULL);
	pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA;

	pAddrMap->m_dwRVA = pDataDir->VirtualAddress;
	GetAddrMAPByRVA(pAddrMap);
	DWORD dwTLSRVA = pAddrMap->m_dwRVA;
	DWORD dwTLSFA = pAddrMap->m_dwFA;
	wsprintf(gs_pszBuf, "TLS Directory: -------------------------------\r\n"
		"RVA\t:%p\r\nFA\t:%p\r\n"
		"Size\t:%p\r\n"
		"Section\t:%s\r\n\r\n",
		dwTLSRVA,
		dwTLSFA,
		pDataDir->Size,
		pAddrMap->m_szSectionName);

	//2. Get IMAGE_TLS_DIRECTORY info
	/*
	typedef struct _IMAGE_TLS_DIRECTORY32 {
	DWORD   StartAddressOfRawData;
	DWORD   EndAddressOfRawData;
	PDWORD  AddressOfIndex;
	PIMAGE_TLS_CALLBACK *AddressOfCallBacks;
	DWORD   SizeOfZeroFill;
	DWORD   Characteristics;
	} IMAGE_TLS_DIRECTORY32;
	typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;
	*/
	PIMAGE_TLS_DIRECTORY pTLSDir = (PIMAGE_TLS_DIRECTORY)
		((unsigned char *)gs_pDOSHDR + dwTLSFA);

	DWORD dwFA[4] = { 0 };
	pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::VA;

	//get FA for these addr
	pAddrMap->m_dwVA = pTLSDir->StartAddressOfRawData;
	GetAddrMAP(pAddrMap);
	dwFA[0] = pAddrMap->m_dwFA;
	pAddrMap->m_dwVA = pTLSDir->EndAddressOfRawData;
	GetAddrMAP(pAddrMap);
	dwFA[1] = pAddrMap->m_dwFA;
	pAddrMap->m_dwVA = (DWORD)pTLSDir->AddressOfIndex;
	GetAddrMAP(pAddrMap);
	dwFA[2] = pAddrMap->m_dwFA;
	pAddrMap->m_dwVA = (DWORD)pTLSDir->AddressOfCallBacks;
	GetAddrMAP(pAddrMap);
	dwFA[3] = pAddrMap->m_dwFA;


	//info in IMAGE_TLS_DIRECTORY are absolute, VA
	//这些可用FIELDINFO宏进行获取
	_snprintf(gs_pszBuf, MAXBUF, "%sStarAddrOfRawData:  %p(VA)  %p(FA)\r\n"
		"EndAddrOfRawData:     %p      %p\r\n"
		"AddressOfIndex:       %p      %p\r\n"
		"AddressOfCallBacks:   %p      %p\r\n"
		"SizeOfZeroFill:       %p\r\n"
		"Characteristics:      %p\r\n\r\n",
		gs_pszBuf,
		pTLSDir->StartAddressOfRawData, dwFA[0],
		pTLSDir->EndAddressOfRawData, dwFA[1],
		pTLSDir->AddressOfIndex, dwFA[2],
		pTLSDir->AddressOfCallBacks, dwFA[3],
		pTLSDir->SizeOfZeroFill,
		pTLSDir->Characteristics);

	_snprintf(gs_pszBuf, MAXBUF, "%sCallBacks:\r\n", gs_pszBuf);

	DWORD *pCallBacks = (DWORD *)((unsigned char *)gs_pDOSHDR + dwFA[3]);
	int i = 0;
	while (pCallBacks[i])
	{
		_snprintf(gs_pszBuf, MAXBUF, "%s%p\r\n", gs_pszBuf, pCallBacks[i]);
		i++;
	}


	*ppszBuf = gs_pszBuf;
	return TRUE;
}

/************************************************************************/
/*
Function: Encapsulation of converting WideChar to MultiByte
Param   : lpcwszStr is the source of wide char you want to covert
lpszStr is the dst for multibytes
dwSize is the length of the buffer you provide
Return  : TRUE if dwSize is enough
FALSE otherwise
*/
/************************************************************************/
static BOOL Wide2Multi(LPCWSTR lpcwszStr, LPSTR lpszStr, DWORD dwSize)
{
	DWORD dwMinSize;
	dwMinSize = WideCharToMultiByte(CP_OEMCP,
		NULL,
		lpcwszStr,
		-1,         //设为-1,可获得所需宽字符数组空间的大小
		NULL,
		0,
		NULL,
		FALSE
	);
	if (dwSize < dwMinSize)
	{
		return FALSE;
	}

	WideCharToMultiByte(CP_OEMCP,
		NULL,
		lpcwszStr,
		-1,
		lpszStr,
		dwSize,
		NULL,
		FALSE
	);

	return TRUE;
}

/************************************************************************/
/*
Function : loop every resource directories
Params   : pRESDir points the current resource directory
dwRESFA indicate where the resource starts
pszSplit used to format level*/
/************************************************************************/
void LoopRes(PIMAGE_RESOURCE_DIRECTORY pRESDir, DWORD dwRESFA, const char *pszSplit)
{
	//now loop every entries
	/*
	//
	// Each directory contains the 32-bit Name of the entry and an offset,
	// relative to the beginning of the resource directory of the data associated
	// with this directory entry.

	// If the name of the entry is an actual text
	// string instead of an integer Id, then the high order bit of the name field
	// is set to one and the low order 31-bits are an offset, relative to the
	// beginning of the resource directory of the string, which is of type
	// IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
	// low-order 16-bits are the integer Id that identify this resource directory
	// entry.

	//If the directory entry is yet another resource directory (i.e. a
	// subdirectory), then the high order bit of the offset field will be
	// set to indicate this.  Otherwise the high bit is clear and the offset
	// field points to a resource data entry.
	//

	typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
	union {
	struct {
	DWORD NameOffset:31;
	DWORD NameIsString:1;
	};
	DWORD   Name;
	WORD    Id;
	};
	union {
	DWORD   OffsetToData;
	struct {
	DWORD   OffsetToDirectory:31;
	DWORD   DataIsDirectory:1;
	};
	};
	} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
	*/

	//The first count is the number of entries at
	// beginning of the array that have actual names associated with each entry.
	// The entries are in ascending order, case insensitive strings.  
	// The second count is the number of entries that immediately follow the named entries.
	// This second count identifies the number of entries that have 16-bit integer
	// Ids as their name.  These entries are also sorted in ascending order.

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRESDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((unsigned char *)pRESDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
	PIMAGE_RESOURCE_DIRECTORY pRESDirSub = NULL;
	PIMAGE_RESOURCE_DIR_STRING_U pRESStr = NULL;
	PIMAGE_RESOURCE_DATA_ENTRY pRESDataEntry = NULL;

	static tagAddrMAP *pAddrMap = new tagAddrMAP;
	assert(pAddrMap != NULL);
	pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA;

	DWORD dwOffSetToData = 0;
	WCHAR *pwName = NULL;
	size_t nLen = 0;
	char szName[MAXBYTE] = { NULL };
	char szSplit[MAXBYTE] = { NULL };
	strcpy(szSplit, pszSplit);
	strcat(szSplit, "\t");

	WORD wDirs = pRESDir->NumberOfNamedEntries + pRESDir->NumberOfIdEntries;
	WORD wIndex = 0;
	for (; wIndex < wDirs; wIndex++)
	{
		// If the name of the entry is an actual text
		// string instead of an integer Id, then the high order bit of the name field
		// is set to one and the low order 31-bits are an offset, relative to the
		// beginning of the resource directory of the string, which is of type
		// IMAGE_RESOURCE_DIRECTORY_STRING. 

		if (pRESDirEntry[wIndex].NameIsString == 1)
		{
			//NameIsString = 1 NameOffset  Name
			dwOffSetToData = pRESDirEntry[wIndex].OffsetToData;
			pRESStr = (PIMAGE_RESOURCE_DIR_STRING_U)((unsigned char *)gs_pDOSHDR + dwRESFA + (pRESDirEntry[wIndex].Name & 0x7FFFFFFF));

			strcpy(szName, "Error!");
			nLen = pRESStr->Length * sizeof(WCHAR);
			pwName = new WCHAR[nLen];
			if (pwName != NULL)
			{
				memcpy(pwName, pRESStr->NameString, nLen);
				pwName[pRESStr->Length] = 0;
				Wide2Multi(pwName, szName, MAXBYTE);
				delete[] pwName;
				pwName = NULL;
			}

			_snprintf(gs_pszBuf, MAXBUF, "%s%sResource Directory Entry %04x, Name: %s, OffSetToData: %p(%p)\r\n",
				gs_pszBuf,
				pszSplit,
				wIndex,
				szName,
				dwOffSetToData,
				dwRESFA + (dwOffSetToData & 0x7FFFFFFF));
		}//end for IsName
		else
		{
			//NameIsString = 0 Id
			assert(pRESDirEntry[wIndex].NameIsString == 0);
			dwOffSetToData = pRESDirEntry[wIndex].OffsetToData;
			_snprintf(gs_pszBuf, MAXBUF, "%s%sResource Directory Entry %04x, ID: %04X, OffSetToData: %p(%p)\r\n",
				gs_pszBuf,
				pszSplit,
				wIndex,
				pRESDirEntry[wIndex].Id,
				dwOffSetToData,
				dwRESFA + (dwOffSetToData & 0x7FFFFFFF));
		}//end for Id

		 //offset
		 //If the directory entry is yet another resource directory (i.e. a
		 // subdirectory), then the high order bit of the offset field will be
		 // set to indicate this.  Otherwise the high bit is clear and the offset
		 // field points to a resource data entry.
		 //
		if (pRESDirEntry[wIndex].DataIsDirectory)
		{
			pRESDirSub = (PIMAGE_RESOURCE_DIRECTORY)((unsigned char *)gs_pDOSHDR + dwRESFA + (dwOffSetToData & 0x7FFFFFFF));
			LoopRes(pRESDirSub, dwRESFA, szSplit);
		}
		else
		{
			//now as Data Entry
			/*typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
			DWORD   OffsetToData;
			DWORD   Size;
			DWORD   CodePage;
			DWORD   Reserved;
			} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

			//It contains an offset, relative to the beginning of the resource
			// directory of the data for the resource
			*/
			pRESDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((unsigned char *)gs_pDOSHDR + dwRESFA + dwOffSetToData);

			pAddrMap->m_dwRVA = pRESDataEntry->OffsetToData;
			GetAddrMAPByRVA(pAddrMap);
			_snprintf(gs_pszBuf, MAXBUF, "%s%sOffsetToData: %p(%p), Size: %p, CodePage: %p\r\n\r\n",
				gs_pszBuf,
				szSplit,
				pRESDataEntry->OffsetToData,
				pAddrMap->m_dwFA,
				pRESDataEntry->Size,
				pRESDataEntry->CodePage
			);

		}
	}
}

/************************************************************************/
/*
Function : Entry for Retrieving RES INFO
Params   : ppszBuf used to receive the log info                        */
/************************************************************************/
BOOL GetRESInfo(char **ppszBuf)
{
	assert(ppszBuf != NULL);
	*ppszBuf = NULL;

	if (gs_pOPTHDR->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_RESOURCE + 1)
	{
		return FALSE;
	}

	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&gs_pOPTHDR->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (NULL == pDataDir->VirtualAddress)
	{
		return FALSE;
	}

	//1. Get RES RVA and Size from DataDirectory
	static tagAddrMAP *pAddrMap = new tagAddrMAP;
	assert(pAddrMap != NULL);
	pAddrMap->m_AddrType = tagAddrMAP::enu_AddrType::RVA;

	pAddrMap->m_dwRVA = pDataDir->VirtualAddress;
	GetAddrMAPByRVA(pAddrMap);
	DWORD dwRESRVA = pAddrMap->m_dwRVA;
	DWORD dwRESFA = pAddrMap->m_dwFA;
	wsprintf(gs_pszBuf, "RES Directory: -------------------------------\r\n"
		"RVA\t:%p\r\nFA\t:%p\r\n"
		"Size\t:%p\r\n"
		"Section\t:%s\r\n\r\n",
		dwRESRVA,
		dwRESFA,
		pDataDir->Size,
		pAddrMap->m_szSectionName);

	//2. Get IMAGE_RESOURCE info
	/*
	//
	// Resource directory consists of two counts, following by a variable length
	// array of directory entries.
	//The first count is the number of entries at
	// beginning of the array that have actual names associated with each entry.
	// The entries are in ascending order, case insensitive strings.
	// The second count is the number of entries that immediately follow the named entries.
	// This second count identifies the number of entries that have 16-bit integer
	// Ids as their name.  These entries are also sorted in ascending order.
	//
	// This structure allows fast lookup by either name or number, but for any
	// given resource entry only one form of lookup is supported, not both.
	// This is consistant with the syntax of the .RC file and the .RES file.

	typedef struct _IMAGE_RESOURCE_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	WORD    NumberOfNamedEntries;
	WORD    NumberOfIdEntries;
	//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
	} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
	*/
	PIMAGE_RESOURCE_DIRECTORY pRESDir = (PIMAGE_RESOURCE_DIRECTORY)
		((unsigned char *)gs_pDOSHDR + dwRESFA);

	_snprintf(gs_pszBuf, MAXBUF, "%sCharacteristics:  %p\r\n"
		"TimeDateStamp:     %p\r\n"
		"MajorVersion:      %04X\r\n"
		"MinorVersion:      %04X\r\n"
		"NumberOfNamedEntries:  %04X\r\n"
		"NumberOfIdEntries:     %04x\r\n\r\n",
		gs_pszBuf,
		pRESDir->Characteristics,
		pRESDir->TimeDateStamp,
		pRESDir->MajorVersion,
		pRESDir->MinorVersion,
		pRESDir->NumberOfNamedEntries,
		pRESDir->NumberOfIdEntries);

	LoopRes(pRESDir, dwRESFA, "");

	*ppszBuf = gs_pszBuf;
	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//For Debugger

/************************************************************************/
/*
Function : get and set info about image size, oep,
for Debugger 's purpose                                                                     */
/************************************************************************/
BOOL GetModuleInfo(tagModule *pModule)
{
	assert(pModule != NULL);

	//the LoadFile() should already be called
	assert(gs_bLoaded);
	gs_bLoaded = FALSE;

	GetOPTHDRInfo();
	pModule->dwImageBase = gs_pOPTHDR->ImageBase;
	pModule->dwOEP = pModule->modBaseAddr + gs_pOPTHDR->AddressOfEntryPoint;
	pModule->modBaseSize = gs_pOPTHDR->SizeOfImage;
	pModule->dwBaseOfCode = pModule->modBaseAddr + gs_pOPTHDR->BaseOfCode;
	pModule->dwSizeOfCode = gs_pOPTHDR->SizeOfCode;
	return TRUE;
}


BOOL SetImageBuf(HANDLE hFile)
{
	HANDLE hFileMapping = NULL;
	LPVOID lpFileBase = NULL;
	BOOL bRet = TRUE;

	gs_bLoaded = TRUE;

	assert(hFile != NULL
		&& hFile != INVALID_HANDLE_VALUE
	);

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (NULL == hFileMapping)
	{
		bRet = FALSE;
		goto SAFE_CLEAN;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == lpFileBase)
	{
		bRet = FALSE;
		goto SAFE_CLEAN;
	}

	gs_pDOSHDR = (PIMAGE_DOS_HEADER)lpFileBase;

	InitMapInfo();

SAFE_CLEAN:
	if (hFile != NULL)
	{
		//CloseHandle(hFile);
		//hFile = NULL;

	}

	//失败时关闭
	if (!bRet
		&&hFileMapping != NULL
		&& lpFileBase != NULL
		)
	{
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);

		lpFileBase = NULL;
		hFileMapping = NULL;
	}

	return bRet;
}

/************************************************************************/
/*
Function:获得VA的api名称
Params  : dwAddr = ImageBase(suggested) + RVA                                                                     */
/************************************************************************/
char *GetAPIName(DWORD dwAddr)
{
	map<DWORD, char *>::iterator it;
	it = gs_mapAddr_ExportName.find(dwAddr);
	if (it != gs_mapAddr_ExportName.end())
	{
		return it->second;
	}
	return NULL;
}
