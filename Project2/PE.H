#ifndef PE_H_7C75D8FF_FBEB_4401_8AC3_4B8D0FA000BA
#define PE_H_7C75D8FF_FBEB_4401_8AC3_4B8D0FA000BA

#include "Common.h"

//////////////////////////////////////////////////////////////////////////
//for Debugger

/************************************************************************/
/*
Function : to immulate the load file, set the ptr to image buf
see LOAD_DLL_DEBUG_INFO
we can operate hFile directly, no need to open the file again                                                                     */
/************************************************************************/
BOOL SetImageBuf(HANDLE hImage);

/************************************************************************/
/*
Function : used to retrieve image size, OEP, etc                                                                     */
/************************************************************************/
BOOL GetModuleInfo(tagModule *pModule);

/************************************************************************/
/*
Function : get api name by VA
Params   : dwAddr should be the ImageBase (suggested) + RVA
Return   : api Name if found,
NULL otherwise                                          */
/************************************************************************/
char *GetAPIName(DWORD dwAddr);



//////////////////////////////////////////////////////////////////////////

/************************************************************************/
/*
Function : Load the specific file into memory in the way of File Mapping
And make g_pDOSHDR point to the buf block.

Return   : TRUE if load success, FALSE otherwise

*/
/************************************************************************/
BOOL LoadFile(const char *pszFilePath);

/************************************************************************/
/*
Function : Release buf mapped into memory
Should Be Called when the buf no longer needed               */
/************************************************************************/
void ReleaseBuf();

/************************************************************************/
/*
Function : Checking whether the File mapped into g_pDOSHDR is PE
Return   : TRUE if it is, FALSE otherwise                                                                     */
/************************************************************************/
BOOL IsPE();


//////////////////////////////////////////////////////////////////////////
//Helper Function
//////////////////////////////////////////////////////////////////////////
//

/************************************************************************/
/*
Function : retrieve info to be displayed within TreeView                                                                     */
/************************************************************************/
const char *GetPETree();

/************************************************************************/
/*
Function : retrieve header info to be displayed within ListView
according to the ItemName selected within TreeView                                                                     */
/************************************************************************/
const char *GetHDRInfoByDir(const char *pszDir);

/************************************************************************/
/*
Function: Retrieve all the items info to be displayed within ListView
according to Dir (Item) selected within TreeView                                                                     */
/************************************************************************/
const char *GetItemInfoByDir(const char *pszDir);

//Used for VA, FA, RVA converting
typedef struct _ADDR_MAP
{
	DWORD m_dwVA;
	DWORD m_dwRVA;
	DWORD m_dwFA;
	enum  enu_AddrType { FA = 0, RVA, VA } m_AddrType;
	char m_szSectionName[IMAGE_SIZEOF_SHORT_NAME * 2];
	char m_szValue[IMAGE_SIZEOF_SHORT_NAME * 2];
	unsigned char m_HexValue[IMAGE_SIZEOF_SHORT_NAME * 2];
}tagAddrMAP;

/************************************************************************/
/*
Function : retrieve tagAddrMAP info according to one of the addrs (VA/RVA/FA)
Param    : pAddrMap as IN/OUT param,
you should set one of the addrs,
Return   : TRUE if get it, FALSE otherwise                                                                   */
/************************************************************************/
BOOL GetAddrMAP(tagAddrMAP *pAddrMap);

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
BOOL GetImportInfo(char **ppszBuf, LPVOID lpAddr/*=NULL*/);

//Used for Import Info
typedef struct _IMPORT_INFO
{
	//IMAGE_DIRECTORY_ENTRY_IMPORT
	DWORD m_dwImpRVA;
	DWORD m_dwImpFA;    //file offset
	DWORD m_dwImpSize;


	//IMAGE_IMPORT_DESCRIPTOR
	DWORD m_OriFirstThunk;
	DWORD m_OriFirstThunkFA;
	DWORD m_NameRVA;
	DWORD m_NameFA;
	DWORD m_FirstThunk;
	DWORD m_FristThunkFA;

	//IMAGE_THUNK_DATA
	DWORD m_AddrOfData;
	DWORD m_AddrOfDataFA;
}tagImportInfo;

//Used for adding section, etc
//FREE Space in PE file
typedef struct _FREE_SPACE
{
	DWORD m_dwFA;       //owner's FA
	DWORD m_dwSize;     //owner's total size
	DWORD m_dwFreeSize; //free space size in the owner
	DWORD m_dwFreeFA;   //start of free space start
	char  m_szName[IMAGE_SIZEOF_SHORT_NAME * 2];
}tagFreeSpace;

typedef struct _ALL_FREE_SPACE
{
	//DOS Stub 
	tagFreeSpace m_DOSStub;

	//Option Header (OptionHeader ~ SectionTable)
	tagFreeSpace m_OPTHDR;

	//SectionTable Allign
	tagFreeSpace m_SectionTable;

	//every section  data
	WORD m_nSections;
	tagFreeSpace m_SectionData[1];  //variable

}tagAllFreeSpace;

/************************************************************************/
/*
Function : Retrieve FreeSpace Info
Param    : ppszBuf used to receive the buf pointer
Return   : TRUE if success, and set ppszBuf point to buf
FALSE otherwise                                        */
/************************************************************************/
BOOL GetFreeSpaceInfo(char **ppszBuf);

/************************************************************************/
/*
Function: Load Target APP into our space.
Make sure Our ImageBase same with the target's

Param   : gs_pDOSHDR is the target app's info
hSelf is the AppLoader's hinstance

Return  : TRUE if ok, FALSE otherwise                                  */
/************************************************************************/
BOOL LoadAPP(HMODULE hSelf);

/************************************************************************/
/*
Function : Retrieve Export Info
Param    : ppszBuf used to receive the buf pointer
Return   : TRUE if success, and set ppszBuf point to buf
FALSE otherwise                                        */
/************************************************************************/
BOOL GetExportInfo(char **ppszBuf);

//used for export
typedef struct _EXPORT_INFO
{
	//IMAGE_DIRECTORY_ENTRY_EXPORT
	DWORD m_dwExpRVA;
	DWORD m_dwExpFA;    //file offset
	DWORD m_dwExpSize;

	//IMAGE_EXPORT_DIRECTORY
	DWORD m_dwNameRVA;
	DWORD m_dwNameFA;
	DWORD m_AddrOfFunctionsRVA;     // RVA from base of image
	DWORD m_AddrOfFunctionsFA;
	DWORD m_AddrOfNamesRVA;         // RVA from base of image
	DWORD m_AddrOfNamesFA;
	DWORD m_AddrOfNameOrdinalsRVA;  // RVA from base of image
	DWORD m_AddrOfNameOrdinalsFA;
	DWORD m_FuncNameRVA;            // RVA from base of image, tmp used for every exported func
	DWORD m_FuncNameFA;             //
	DWORD m_FuncAddrRVA;            // RVA from base of image, tmp used for every exported func
	DWORD m_FuncAddrFA;

}tagExportInfo;

/************************************************************************/
/*
Function : Self Implementation of GetProcAddress
Return   : NULL for Failure, otherwise the addr of function            */
/************************************************************************/
DWORD DoGetProcAddress(HMODULE hModule, LPCSTR lpProcName);

/************************************************************************/
/*
Function : Dump the specified process into file

Suppose AppName.exe --> AppName_dump.exe*/
/************************************************************************/
void DumpPE(DWORD dwPID, BOOL bFix, char **ppszBuf);

/************************************************************************/
/*
Function : Retrieve Base Relocation Info

Params   : ppszBuf is the buf to retrieve log
pRealBase is the memory address the dll really loaded
you can set it NULL if you do not need
pImageBase is the memory address the dll should be loaded,
usually it is the PE.ImageBase
you can set it NULL if you do not need

IMAGE_DIRECTORY_ENTRY_BASERELOC
*/
/************************************************************************/
BOOL GetBaseRelocInfo(char **ppszBuf,
	unsigned char *pRealBase/*=NULL*/,
	unsigned char *pImageBase/*=NULL*/);

/************************************************************************/
/*
Function: Load Target APP into our space.

Param   : gs_pDOSHDR is the target app's info

Return  : NULL for failure, otherwise the hModule                                  */
/************************************************************************/
HMODULE LoadDll();

/************************************************************************/
/*
Function : Entry for retrieving TLS Info
Params   : ppszBuf used to receive the log                             */
/************************************************************************/
BOOL GetTLSInfo(char **ppszBuf);

/************************************************************************/
/*
Function : Entry for Retrieving RES INFO
Params   : ppszBuf used to receive the log info                        */
/************************************************************************/
BOOL GetRESInfo(char **ppszBuf);

#endif