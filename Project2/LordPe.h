#pragma once
#include "windows.h"
#include <vector>
#include "atlstr.h"
using std::vector;

//导出表函数信息
typedef struct _EXPORTFUNINFO
{
	DWORD ExportOrdinals;//导出序号
	DWORD FunctionRVA;//函数RVA
	DWORD FunctionOffset;//函数文件偏移
	CString FunctionName;//函数名
}EXPORTFUNINFO, *PEXPORTFUNINFO;

//导出表基本信息
typedef struct _MY_IM_EX_DI
{
	CString name;//dll名
	DWORD Base;//序号基数
	DWORD NumberOfFunctions;//函数数量
	DWORD NumberOfNames;//函数名称数量
	DWORD AddressOfFunctions;//地址表RVA
	DWORD AddressOfNames;//名称表RVA
	DWORD AddressOfNameOrdinals;//序号表RVA
}MY_IM_EX_DI, *PMY_IM_EX_DI;

//导入表基本信息
typedef struct _MY_IMPORT_DESCRIPTOR
{
	CString Name;//DLL名称
	DWORD OriginalFirstThunk;//INT(导入名称表RVA)
	DWORD OffsetOriginalFirstThunk;//INT(导入名称表偏移)
	DWORD FirstThunk;//IAT(导入地址表RVA)
	DWORD OffsetFirstThunk;//IAT(导入地址表偏移)

}MY_IMPORT_DESCRIPTOR, *PMY_IMPORT_DESCRIPTOR;

//导入函数信息
typedef struct _IMPORTFUNINFO
{
	DWORD Ordinal;
	CString Name;

}IMPORTFUNINFO, *PIMPORTFUNINFO;

class CLordPe
{
public:
	CLordPe();
	~CLordPe();
	BOOL GetDosHead(LPCTSTR filePath);
	DWORD GetOep();
	void ExportTable();
	void ImportTable();
	DWORD RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva);
public:
	//----------------导出表---------------------//
	vector<EXPORTFUNINFO> m_vecExportFunInfo;
	MY_IM_EX_DI m_my_im_ex_di;

	//----------------导入表---------------------//
	vector<MY_IMPORT_DESCRIPTOR> m_vecImportDescriptor;
	vector<IMPORTFUNINFO> m_vecImportFunInfo;
	vector<vector<IMPORTFUNINFO>> m_vvImportFunInfo;

	BYTE* m_pBuf;//用于释放申请的空间
	PIMAGE_DOS_HEADER m_pDosHdr;//DOS头地址
};