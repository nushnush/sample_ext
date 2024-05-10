/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod Sample Extension
 * Copyright (C) 2004-2008 AlliedModders LLC.  All rights reserved.
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 3.0, as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, AlliedModders LLC gives you permission to link the
 * code of this program (as well as its derivative works) to "Half-Life 2," the
 * "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
 * by the Valve Corporation.  You must obey the GNU General Public License in
 * all respects for all other code used.  Additionally, AlliedModders LLC grants
 * this exception to all derivative works.  AlliedModders LLC defines further
 * exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
 * or <http://www.sourcemod.net/license.php>.
 *
 * Version: $Id$
 */

#include "extension.h"
#include "Player.h"
#include <list>

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

BotPlaytime g_Sample;		/**< Global singleton for extension's main interface */
SMEXT_LINK(&g_Sample);

CHooker* Hooker = new CHooker;
Func_Sendto SendtoOriginal = NULL;
CFunc* SendtoHook = NULL;
std::list<Player> players;

static cell_t add_player(IPluginContext* pContext, const cell_t* params) /* 1 param */
{
	Player p;
	p.number = params[1];
	pContext->LocalToString(params[2], &p.name);
	p.score = params[3];
	p.time = sp_ctof(params[4]);

	players.push_back(p);
	return 1;
}

static cell_t remove_player(IPluginContext* pContext, const cell_t* params) /* 1 param */
{
	auto it = players.begin();
	advance(it, params[1]-1);
	players.erase(it);
	return 1;
}

size_t PASCAL OnNewSendto(int socket, const void* message, size_t length, int flags, const struct sockaddr* dest_addr, socklen_t dest_len)
{
	const unsigned char* origMessage = (unsigned char*)message;
	size_t ret = 0;

	if (length > 5 && origMessage[0] == 0xff && origMessage[1] == 0xff && origMessage[2] == 0xff && origMessage[3] == 0xff)
	{
		if (origMessage[4] == 'D')
		{
            /*
			(byte)		Character 'D'
			(byte)		Player Count
			--
			(byte)		Player Number
			(string)	Player Name
			(long)		Player Score
			(float)		Player Time
			--
			*/
			
			char* pszMessage = new char[(int)length];
			pszMessage[0] = 0xff;
			pszMessage[1] = 0xff;
			pszMessage[2] = 0xff;
			pszMessage[3] = 0xff;
			pszMessage[4] = 'D';
			pszMessage[5] = (unsigned char)players.size();

			union {
				long b;
				unsigned char byte[4];
			} thingB;

			union {
				float c;
				unsigned char byte[4];
			} thingC;

			int iCurrPos = 6;

            for(int i = 0; i < (int)players.size(); i++)
            {
				pszMessage[iCurrPos] = (unsigned char)(i+1);
				iCurrPos++;

				auto it = players.begin();
				advance(it, i);

				for (int j = 0; (*it).name[j] != '\x00'; j++) // Copy Player Name
				{
					pszMessage[iCurrPos] = (*it).name[j];
					iCurrPos++;
				}

				pszMessage[iCurrPos] = 0x00;
				iCurrPos++;

				thingB.b = (*it).score;
				pszMessage[iCurrPos] = thingB.byte[0];
				iCurrPos++;
				pszMessage[iCurrPos] = thingB.byte[1];
				iCurrPos++;
				pszMessage[iCurrPos] = thingB.byte[2];
				iCurrPos++;
				pszMessage[iCurrPos] = thingB.byte[3];
				iCurrPos++;

				thingC.c = (*it).time;
				pszMessage[iCurrPos] = thingC.byte[0];
				iCurrPos++;
				pszMessage[iCurrPos] = thingC.byte[1];
				iCurrPos++;
				pszMessage[iCurrPos] = thingC.byte[2];
				iCurrPos++;
				pszMessage[iCurrPos] = thingC.byte[3];
				iCurrPos++;
            }

			if (SendtoHook->Restore())
			{
				ret = SendtoOriginal(socket, pszMessage, iCurrPos, flags, dest_addr, dest_len);
				SendtoHook->Patch();
			}

			return ret;
		}
	}

	if (SendtoHook->Restore())
	{
		ret = SendtoOriginal(socket, message, length, flags, dest_addr, dest_len);
		SendtoHook->Patch();
	}

	return ret;
}

bool hookSendto(void)
{
#ifdef WIN32

	SendtoOriginal = (Func_Sendto)GetProcAddress(GetModuleHandle("wsock32.dll"), "sendto");

#else

	// metamod-p parses elf structures, we find function easier & better way
	void* sym_ptr = (void*)&sendto;

	while (*(unsigned short*)sym_ptr == 0x25ff)
	{
		sym_ptr = **(void***)((char*)sym_ptr + 2);
	}

	SendtoOriginal = (Func_Sendto)sym_ptr;

#endif

	SendtoHook = Hooker->CreateHook(SendtoOriginal, (void*)OnNewSendto, TRUE);
	return SendtoHook ? true : false;
}

const sp_nativeinfo_t MyNatives[] =
{
	{ "BotTime_AddPlayer",			add_player},
	{ "BotTime_DeletePlayer",		remove_player},
	{ NULL, NULL }
};

void BotPlaytime::SDK_OnUnload()
{
	SendtoHook->Restore();
}

void BotPlaytime::SDK_OnAllLoaded()
{
	sharesys->AddNatives(myself, MyNatives);
}