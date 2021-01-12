// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>  
#include<cstring>

using namespace std;
LONG IATHook(
	__in_opt void* pImageBase,			// ��ǰ���̵Ļ�ַ
	__in_opt char* pszImportDllName,	// Ҫ����iathook��dll�ļ���
	__in char* pszRoutineName,			// Ҫ����iathook�ĺ�����
	__in void* pFakeRoutine,			// �Լ�����ĺ����ĺ�����ַ
	__out HANDLE* phHook				
);

// �ָ�iathook
LONG UnIATHook(__in HANDLE hHook);

void* GetIATHookOrign(__in HANDLE hHook);

typedef COLORREF(* LPFN_SetTextColor)(__in HDC hdc, __in COLORREF color);


HANDLE g_hHook_SetTextColor = NULL;  
//////////////////////////////////////////////////////////////////////////

// �Լ������Fake_SetTextColor�������õ�ԭʼ��SetTextColor�����ĵ�ַ�����ҵ��øú�����
COLORREF   Fake_SetTextColor(__in HDC hdc,__in COLORREF color)
{
	// ��g_hHook_SetTextColor��IATHOOK_BLOCK���ĵõ� pOriginֵ��SetTextColor�ĺ�����ַ��
	LPFN_SetTextColor fnOrigin = (LPFN_SetTextColor)GetIATHookOrign(g_hHook_SetTextColor);
	// ����fnOrigin��������ԭʼ��SetTextColor����������ʵ�������൱�ڸı���notepad++.exe����SetTextColor����ʱ�Ĳ����� 
	return fnOrigin(hdc, (COLORREF)"DC143C");
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		CHAR szInfo[MAX_PATH + 100];
		wsprintfA(szInfo, "Fake_SetTextColor��ַΪ  (%p)", &Fake_SetTextColor);
		MessageBoxA(NULL, szInfo, "2021-01-12", 0);

		IATHook(
			GetModuleHandleW(NULL),  //��ȡ��ǰexe�����ַ��If this parameter is NULL, GetModuleHandle returns a handle to the file used to create the calling process (.exe file).
			(char*)"GDI32.dll",
			(char*)"SetTextColor", 
			Fake_SetTextColor,
			&g_hHook_SetTextColor
		);

		break;
	case DLL_PROCESS_DETACH:

		UnIATHook(g_hHook_SetTextColor);

		MessageBox(NULL, L"Process detach!", L"Inject All The Things!", 0);
		break;
	}
	return TRUE;
}
////////////////////////////////////////////////
#ifdef _RING0
#include <ntddk.h>
#include <ntimage.h>
#else
#include <windows.h>
#include <stdlib.h>
#endif //#ifdef _RING0
#include <cstring>
#include <string>

//////////////////////////////////////////////////////////////////////////

typedef struct _IATHOOK_BLOCK
{
	void* pOrigin; // Ҫ�����ĺ����ĵ�ַ

	void* pImageBase;
	char* pszImportDllName; // Ҫ������dll����
	char* pszRoutineName;	// Ҫ��������������

	void* pFake;			// ��ð�����ĵ�ַ

}IATHOOK_BLOCK;

//////////////////////////////////////////////////////////////////////////

void* _IATHook_Alloc(__in ULONG nNeedSize)
{
	void* pMemory = NULL;

	do
	{
		if (0 == nNeedSize)
		{
			break;
		}

#ifdef _RING0
		pMemory = ExAllocatePoolWithTag(NonPagedPool, nNeedSize, 'iath');

#else
		pMemory = malloc(nNeedSize);
#endif // #ifdef _RING0

		if (NULL == pMemory)
		{
			break;
		}

		RtlZeroMemory(pMemory, nNeedSize);

	} while (FALSE);

	return pMemory;
}


ULONG _IATHook_Free(__in void* pMemory)
{

	do
	{
		if (NULL == pMemory)
		{
			break;
		}

#ifdef _RING0
		ExFreePool(pMemory);

#else
		free(pMemory);
#endif // #ifdef _RING0

		pMemory = NULL;

	} while (FALSE);

	return 0;
}

//////////////////////////////////////////////////////////////////////////
#ifdef _RING0


#ifndef LOWORD
#define LOWORD(l)           ((USHORT)((ULONG_PTR)(l) & 0xffff))
#endif // #ifndef LOWORD


void* _IATHook_InterlockedExchangePointer(__in void* pAddress, __in void* pValue)
{
	void* pWriteableAddr = NULL;
	PMDL	pNewMDL = NULL;
	void* pOld = NULL;

	do
	{
		if ((NULL == pAddress))
		{
			break;
		}

		if (!NT_SUCCESS(MmIsAddressValid(pAddress)))
		{
			break;
		}

		pNewMDL = IoAllocateMdl(pAddress, sizeof(void*), FALSE, FALSE, NULL);
		if (pNewMDL == NULL)
		{
			break;
		}

		__try
		{
			MmProbeAndLockPages(pNewMDL, KernelMode, IoWriteAccess);

			pNewMDL->MdlFlags |= MDL_MAPPING_CAN_FAIL;

			pWriteableAddr = MmMapLockedPagesSpecifyCache(
				pNewMDL,
				KernelMode,
				MmNonCached,
				NULL,
				FALSE,
				HighPagePriority
			);

			//pWriteableAddr = MmMapLockedPages(pNewMDL, KernelMode);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		if (pWriteableAddr == NULL)
		{
			MmUnlockPages(pNewMDL);
			IoFreeMdl(pNewMDL);

			break;
		}

		pOld = InterlockedExchangePointer(pWriteableAddr, pValue);

		MmUnmapLockedPages(pWriteableAddr, pNewMDL);
		MmUnlockPages(pNewMDL);
		IoFreeMdl(pNewMDL);

	} while (FALSE);

	return pOld;
}
//////////////////////////////////////////////////////////////////////////
#else

void* _IATHook_InterlockedExchangePointer(__in void* pAddress, __in void* pValue)
{
	void* pWriteableAddr = NULL;
	void* nOldValue = NULL;
	ULONG	nOldProtect = 0;
	BOOL	bFlag = FALSE;

	do
	{
		if ((NULL == pAddress))
		{
			break;
		}

		bFlag = VirtualProtect(pAddress, sizeof(void*), PAGE_EXECUTE_READWRITE, &nOldProtect);
		if (!bFlag)
		{
			break;
		}
		pWriteableAddr = pAddress;
		nOldValue = InterlockedExchangePointer((volatile PVOID *)pWriteableAddr, pValue);

		VirtualProtect(pAddress, sizeof(void*), nOldProtect, &nOldProtect);
	} while (FALSE);

	return nOldValue;
}

#endif // #ifdef _RING0


LONG _IATHook_Single
(
	__in IATHOOK_BLOCK* pHookBlock,					
	__in IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor, // ָ������ָ�룬Ҳ����һ��Image_Import_Directory
	__in BOOLEAN bHook		// true
)
{
	LONG				nFinalRet = -1;

	IMAGE_THUNK_DATA* pOriginThunk = NULL;
	IMAGE_THUNK_DATA* pRealThunk = NULL;

	IMAGE_IMPORT_BY_NAME* pImportByName = NULL;


	CHAR szInfo[MAX_PATH + 100];
	do
	{
		pOriginThunk = (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase + pImportDescriptor->OriginalFirstThunk); // ��Ҫ�޸ĵ�ģ���HNT���λ��
		pRealThunk = (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase + pImportDescriptor->FirstThunk);			// ��Ҫ�޸ĵ�ģ���IAT���λ��

		for (; 0 != pOriginThunk->u1.Function; pOriginThunk++, pRealThunk++)
		{
			if (IMAGE_ORDINAL_FLAG == (pOriginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))  //0x0 pOriginThunk->u1.Ordinal =0x28d406
			{

				if ((USHORT)pHookBlock->pszRoutineName == LOWORD(pOriginThunk->u1.Ordinal))   //����ҵ���Ҫ�����ĺ���
				{
					// pszRoutineName:Ҫ��������������
					if (bHook)
					{
						pHookBlock->pOrigin = (void*)pRealThunk->u1.Function;	

						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pFake);  // ��IAT����Ҫ�����ĺ����ĵ�ַ�ĳ�pFake��Ҳ���Ǽ�ð�ĺ����ĵ�ַ��
					}
					else
					{
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pOrigin);
					}

					nFinalRet = 0;
					break;
				}
			}
			else
			{
				pImportByName = (IMAGE_IMPORT_BY_NAME*)((char*)pHookBlock->pImageBase + pOriginThunk->u1.AddressOfData);

				if (0 == _stricmp(pImportByName->Name, pHookBlock->pszRoutineName))
				{
					memset(szInfo, 0, sizeof(szInfo));
					wsprintfA(szInfo, "pImportByName->Name is (%s)", pImportByName->Name);
					MessageBoxA(NULL, szInfo, "2021-01-12", 0);

					if (bHook)
					{
						pHookBlock->pOrigin = (void*)pRealThunk->u1.Function;

						memset(szInfo, 0, sizeof(szInfo));
						wsprintfA(szInfo, "pRealThunk->u1.Function is (%p)", pHookBlock->pOrigin);
						MessageBoxA(NULL, szInfo, "2021-01-12", 0);

						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pFake);
						
					
						memset(szInfo, 0, sizeof(szInfo));
						wsprintfA(szInfo, "IAT hook֮��SetTextColor�ĵ�ַ is (%p)", (void*)pRealThunk->u1.Function);
						MessageBoxA(NULL, szInfo, "2021-01-12", 0);

						memset(szInfo, 0, sizeof(szInfo));
						wsprintfA(szInfo, "IAT hook֮��ԭʼSetTextColor�ĵ�ַ is (%p)", pHookBlock->pOrigin);
						MessageBoxA(NULL, szInfo, "2021-01-12", 0);

					}
					else
					{
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pOrigin);
					}

					nFinalRet = 0;

					break;
				}
			}

		}
	} while (FALSE);

	return nFinalRet;
}


LONG _IATHook_Internal(__in IATHOOK_BLOCK* pHookBlock, __in BOOLEAN bHook)
{
	LONG				nFinalRet = -1;
	LONG				nRet = -1;
	IMAGE_DOS_HEADER* pDosHeader = NULL;
	IMAGE_NT_HEADERS* pNTHeaders = NULL;

	IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = NULL;
	char* pszImportDllName = NULL;


	do
	{
		if (NULL == pHookBlock)
		{
			break;
		}

		pDosHeader = (IMAGE_DOS_HEADER*)pHookBlock->pImageBase;
		if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic)
		{
			break;
		}

		pNTHeaders = (IMAGE_NT_HEADERS*)((UCHAR*)pHookBlock->pImageBase + pDosHeader->e_lfanew);
		if (IMAGE_NT_SIGNATURE != pNTHeaders->Signature)
		{
			break;
		}

		if (0 == pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			break;
		}

		if (0 == pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			break;
		}

		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((UCHAR*)pHookBlock->pImageBase + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


		// Find pszRoutineName in every Import descriptor
		nFinalRet = -1;

		for (; (pImportDescriptor->Name != 0); pImportDescriptor++) // �������еĵ���ģ�� 
		{
			pszImportDllName = (char*)pHookBlock->pImageBase + pImportDescriptor->Name; // �õ���ģ�������

			if (NULL != pHookBlock->pszImportDllName)
			{
				if (0 != _stricmp(pszImportDllName, pHookBlock->pszImportDllName)) // �Ƚϸõ���ģ������ƺ�����Ҫ�ı��ģ�������Ƿ���ͬ������ͬ�������һ��ģ��
				{
					continue;
				}
			}

			nRet = _IATHook_Single(		// �����Ľ���IAT��ı�ĺ���
				pHookBlock,			// ���ڴ˴�hook����Ϣ�ṹ�� 
				pImportDescriptor, // �Ѿ��ҵ���Ҫ�޸ĵĵ���ģ��
				bHook				// һ��boolֵ��Ϊtrue
			);

			if (0 == nRet)
			{
				nFinalRet = 0;
				break;
			}
		}

	} while (FALSE);

	return nFinalRet;
}

LONG IATHook
(
	__in void* pImageBase,
	__in_opt char* pszImportDllName,
	__in char* pszRoutineName,
	__in void* pFakeRoutine,
	__out HANDLE* Param_phHook
)
{
	LONG				nFinalRet = -1;
	IATHOOK_BLOCK* pHookBlock = NULL;

	do
	{
		if ((NULL == pImageBase) || (NULL == pszRoutineName) || (NULL == pFakeRoutine))
		{
			break;
		}

		pHookBlock = (IATHOOK_BLOCK*)_IATHook_Alloc(sizeof(IATHOOK_BLOCK));
		if (NULL == pHookBlock)
		{
			break;
		}
		RtlZeroMemory(pHookBlock, sizeof(IATHOOK_BLOCK));  // ��IATHOOK_BLOCK��pHookBlock��������ռ�

		pHookBlock->pImageBase = pImageBase;
		pHookBlock->pszImportDllName = pszImportDllName;
		pHookBlock->pszRoutineName = pszRoutineName;
		pHookBlock->pFake = pFakeRoutine;

		__try
		{
			nFinalRet = _IATHook_Internal(pHookBlock, TRUE);	// ��������IAT hook�Ĳ��֣��ɹ�ʱ����0
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			nFinalRet = -1;				// IAT hook û�гɹ�
		}
		CHAR szInfo[MAX_PATH + 100];
		wsprintfA(szInfo, "nFinalRet  (%d)", nFinalRet);
		MessageBoxA(NULL, szInfo, "2021-01-12", 0);

	} while (FALSE);

	if (0 != nFinalRet)
	{
		if (NULL != pHookBlock)
		{
			_IATHook_Free(pHookBlock);
			pHookBlock = NULL;
		}
	}

	if (NULL != Param_phHook)
	{
		*Param_phHook = pHookBlock;
	}

	return nFinalRet;
}

LONG UnIATHook(__in HANDLE hHook)
{
	IATHOOK_BLOCK* pHookBlock = (IATHOOK_BLOCK*)hHook;
	LONG				nFinalRet = -1;

	do
	{
		if (NULL == pHookBlock)
		{
			break;
		}

		__try
		{
			nFinalRet = _IATHook_Internal(pHookBlock, FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			nFinalRet = -1;
		}

	} while (FALSE);

	if (NULL != pHookBlock)
	{
		_IATHook_Free(pHookBlock);
		pHookBlock = NULL;
	}

	return nFinalRet;
}

void* GetIATHookOrign(__in HANDLE hHook)  // ����IATHOOK_BLOCK�ṹ���pOriginֵ��
{
	IATHOOK_BLOCK* pHookBlock = (IATHOOK_BLOCK*)hHook;
	void* pOrigin = NULL;

	do
	{
		if (NULL == pHookBlock) // ��������ֵ�ǿգ��ͷ���NULL
		{
			break;
		}

		pOrigin = pHookBlock->pOrigin; 

	} while (FALSE);

	return pOrigin;
}
