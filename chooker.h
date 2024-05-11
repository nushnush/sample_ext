
/***
 *  Copyright 2012 Carlos Sola, Vincent Herbet.
 *
 *  This file is part of CHooker library.
 *
 *  CHooker library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  CHooker library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with CHooker library. If not, see <http://www.gnu.org/licenses/>.
 */

 /* HookByCall array format
  *
 CHOOKER_SIG_CALL custom_array[] =
 {
	 { "0x12,0x13,0x14,?,0x15,*,0x16", -2 },
	 { NULL, NULL }
 };
 */

#ifndef _CHOOKER_H_
#define _CHOOKER_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined __linux__

#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#ifndef uint32
#define uint32	unsigned int
#endif

#ifndef byte
#define byte	unsigned char
#endif

#ifndef FALSE
#define FALSE	0
#endif

#ifndef TRUE
#define TRUE	1
#endif

#ifndef PAGESIZE
#define PAGESIZE sysconf(_SC_PAGESIZE)
#endif

inline void* Align(void* address)
{
	return (void*)((long)address & ~(PAGESIZE - 1));
}

inline uint32 IAlign(uint32 address)
{
	return (address & ~(PAGESIZE - 1));
}

inline uint32 IAlign2(uint32 address)
{
	return (IAlign(address) + PAGESIZE);
}


//#define GET_EAX_POINTER(x) __asm volatile ("movl %%edx, %0; lea 0x01020304, %%edx;" : "=m" (x):)
#define GET_EAX_POINTER(x) __asm volatile ("movl %%edx, %0;" : "=m" (x):)

const unsigned long PAGE_EXECUTE_READWRITE = PROT_READ | PROT_WRITE | PROT_EXEC;
const unsigned long PAGE_READWRITE = PROT_READ | PROT_WRITE;

static int dl_callback(struct dl_phdr_info* info, size_t size, void* data);

#else

#pragma comment( lib, "Psapi.lib" ) 
#pragma comment( lib, "Kernel32.lib" ) 

#define PSAPI_VERSION 1

#include <windows.h>
#include <Psapi.h>
#include <WinBase.h>
#include <io.h>

#define GET_EAX_POINTER(x) __asm mov x, edx;
#define PAGESIZE 4096

typedef int DUMMY;
#define DUMMY_VAL 0

#endif

#define GET_ORIG_FUNC(x) CFunc *x; GET_EAX_POINTER(x);

typedef int BOOL;

typedef enum
{
	ReturnOnError,
	ReturnOnFirst,
	ContinueOnError
} PatchActionType;

typedef enum
{
	SpecificByte,
	AnyByteOrNothing,
	AnyByte
} SignatureEntryType;

#define CHOOKER_NONE	0
#define CHOOKER_FOUND	1
#define CHOOKER_PATCHED	2

class CMemory
{
public:

	unsigned char* signature;
	unsigned char* signatureData;

	int sigsize;

	char* baseadd;
	char* endadd;
	char* library;

	CMemory() : signature(0), signatureData(0), sigsize(0), baseadd((char*)0xffffffff), endadd(0), library(0) {}

	BOOL ChangeMemoryProtection(void* function, unsigned int size, unsigned long newProtection)
	{
#ifdef __linux__

		void* alignedAddress = Align(function);
		return !mprotect(alignedAddress, size, newProtection);

#else

		FlushInstructionCache(GetCurrentProcess(), function, size);

		static DWORD oldProtection;
		return VirtualProtect(function, size, newProtection, &oldProtection);

#endif
	}

	BOOL ChangeMemoryProtection(void* address, unsigned int size, unsigned long newProtection, unsigned long& oldProtection)
	{
#ifdef __linux__

		void* alignedAddress = Align(address);

		oldProtection = newProtection;

		return !mprotect(alignedAddress, size, newProtection);

#else

		FlushInstructionCache(GetCurrentProcess(), address, size);

		return VirtualProtect(address, size, newProtection, &oldProtection);

#endif
	}
};

class CFunc
{
private:

	void* address;
	void* detour;

	CMemory* memFunc;

	unsigned char i_original[5];
	unsigned char i_patched[5];
	unsigned char* original;
	unsigned char* patched;

	BOOL ispatched;
	BOOL ishooked;

public:

	CFunc(void* src, void* dst)
	{
		address = src;
		detour = dst;
		ishooked = ispatched = 0;
		original = &i_original[0];
		patched = &i_patched[0];

		memFunc = new CMemory;
	};

	~CFunc()
	{
		delete memFunc;
	};

	void* Hook(void* dst, BOOL hook)
	{
		if (!ishooked && !ispatched)
		{
			unsigned int* p;
			detour = dst;

			memcpy(original, address, 5);

			// lea    this ,%edx
			// movl    this ,%edx
			//patched[0] = 0x8d;
			//patched[1] = 0x15;

			//p = ( unsigned int* )( patched + 2 );
			//*p = ( unsigned int )this;

			// nop
			//patched[6] = 0x90;

			// jmp detour
			//patched[7] = 0xE9;
			//p = ( unsigned int* )( patched + 8 );
			//*p = ( unsigned int )dst - ( unsigned int )address - 12;

			patched[0] = 0xE9;
			p = (unsigned int*)(patched + 1);
			*p = (unsigned int)dst - (unsigned int)address - 5;

			if (hook && Patch())
			{
				return address;
			}

			ishooked = FALSE;
		}

		return NULL;
	}

	void* GetOriginal()
	{
		return address;
	}

	BOOL Patch()
	{
		if (!ispatched)
		{
			if (memFunc->ChangeMemoryProtection(address, PAGESIZE, PAGE_EXECUTE_READWRITE))
			{
				//memcpy( address, patched, 12 );
				memcpy(address, patched, 5);
				ispatched = TRUE;
			}
		}

		return ispatched;
	}

	BOOL Restore()
	{
		if (ispatched)
		{
			if (memFunc->ChangeMemoryProtection(address, PAGESIZE, PAGE_EXECUTE_READWRITE))
			{
				//memcpy( address, original, 12 );
				memcpy(address, original, 5);
				ispatched = FALSE;
			}
		}

		return !ispatched;
	}
};

class CHooker
{
private:

	struct Obj
	{
		void* src;
		CFunc* func;
		Obj* next;
	} *head;

public:

	CMemory* memFunc;

	CHooker() : head(0)
	{
		memFunc = new CMemory;
	};

	~CHooker()
	{
		Clear();
	}

	void Clear()
	{
		while (head)
		{
			Obj* obj = head->next;

			delete head->func;
			delete head;

			head = obj;
		}

		delete memFunc;
	}

	template <typename Tsrc, typename Tdst>
	CFunc* CreateHook(Tsrc src, Tdst dst, BOOL hook)
	{
		if (!src || !dst)
			return NULL;

		Obj* obj = head;

		if (!obj)
		{
			head = new Obj();
			obj = head;

			obj->src = (void*)src;
			obj->func = new CFunc((void*)src, (void*)dst);
			obj->next = NULL;
		}
		else
		{
			while (obj)
			{
				if (obj->src == (void*)src)
				{
					break;
				}
				else if (!obj->next)
				{
					obj->next = new Obj();
					obj = obj->next;

					obj->src = (void*)src;
					obj->func = new CFunc((void*)src, (void*)dst);
					obj->next = NULL;

					break;
				}
				obj = obj->next;
			}
		}

		if (obj->func)
			obj->func->Hook((void*)dst, hook);

		return obj->func;
	}
};

#ifdef __linux__

static int dl_callback(struct dl_phdr_info* info, size_t size, void* data)
{
	CMemory* obj = (CMemory*)data;

	if ((!obj->library) || strstr(info->dlpi_name, (char*)obj->library) > 0)
	{
		int i;
		BOOL ismain = FALSE;

		if (info->dlpi_addr == 0x00)
			ismain = TRUE;
		else
			obj->baseadd = (char*)info->dlpi_addr;

		for (i = 0; i < info->dlpi_phnum; i++)
		{
			if (info->dlpi_phdr[i].p_memsz && IAlign(info->dlpi_phdr[i].p_vaddr))
			{
				if (ismain && (uint32)obj->baseadd > IAlign(info->dlpi_phdr[i].p_vaddr))
					obj->baseadd = (char*)IAlign(info->dlpi_phdr[i].p_vaddr);

				if ((uint32)obj->endadd < (info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz))
					obj->endadd = (char*)IAlign2((info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz));
			}
		}

		obj->endadd += info->dlpi_addr;

		return (int)obj->baseadd;
	}

	return 0;
}

#endif

#endif // _CHOOKER_H_