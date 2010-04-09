/*++
    Copyright  (c) 2004 SafeGen Software
    Contact information:
        mail: kab@safegen.com

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

 
Module Name:
    common.h

Abstract: Common definitions

Revision History:

 kab        21/09/2004
      Initial release

--*/

#pragma once
#include "stdafx.h"
#include "shlwapi.h"

#include "ver.h"

#include ".\TinyXML\TinyXML.h"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <expr.hpp>
#include <xref.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <frame.hpp>
#include <struct.hpp>
#include <enum.hpp>
#include <allins.hpp>
#include "moves.hpp"


enum OP_TYPE
{
// code flags
OP_VOID		= 0x0,			// Void (unknown)?
OP_NUMH		= 0x1,			// Hexadecimal number?
OP_NUMD		= 0x2,          // Decimal number?
OP_CHAR		= 0x3,          // Char ('x')?
OP_SEG		= 0x4,          // Segment?
OP_OFF		= 0x5,          // Offset?
OP_NUMB		= 0x6,          // Binary number?
OP_NUMO		= 0x7,          // Octal number?
OP_ENUM		= 0x8,          // Enumeration?
OP_FOP		= 0x9,          // Forced operand?
OP_STRO		= 0xA,          // Struct offset?
OP_STK		= 0xB,          // Stack variable?
OP_FLT		= 0xC,          // Floating point number?
// data flags
OP_BYTE     = 0x00,			// byte
OP_WORD     = 0x10,			// word
OP_DWRD     = 0x20,			// double word
OP_QWRD     = 0x30,			// quadro word
OP_TBYT     = 0x40,			// tbyte
OP_ASCI     = 0x50,			// ASCII ?
OP_STRU     = 0x60,			// Struct ?
OP_OWRD     = 0x70,			// octaword (16 bytes)
OP_FLOAT    = 0x80,			// float
OP_DOUBLE   = 0x90,			// double
OP_PACKREAL = 0xA0,			// packed decimal real
OP_ALIGN    = 0xB0,			// alignment directive
};

#define FLAG_SHOW_DEBUG	1
#define FLAG_IGNORE_CALLTO 2
#define FLAG_DONT_CHECK_NAMES 4
#define FLAG_ALL_FUNC 8
#define FLAG_NOT_SAVE_STRUCTURES 16
#define FLAG_FORCE_LOAD 32

// Show debug info
inline bool isShowDebug(int F)   { return (F & FLAG_SHOW_DEBUG) == FLAG_SHOW_DEBUG; }
// Ignore CallTo names
inline bool isIgnoreCallTo(int F)   { return (F & FLAG_IGNORE_CALLTO) == FLAG_IGNORE_CALLTO; }
// Ignore names (don't check, that function have user-name)
inline bool isDontCheckNames(int F)   { return (F & FLAG_DONT_CHECK_NAMES) == FLAG_DONT_CHECK_NAMES; }
// All range
inline bool isAllFuncs(int F)   { return (F & FLAG_ALL_FUNC) == FLAG_ALL_FUNC; }
// Don't save/restore structures and enums
inline bool isNotSaveStructures(int F)   { return (F & FLAG_NOT_SAVE_STRUCTURES) == FLAG_NOT_SAVE_STRUCTURES; }
// Force loading
inline bool isForceLoad(int F)   { return (F & FLAG_FORCE_LOAD) == FLAG_FORCE_LOAD; }

bool IsFuncPresent(LPSTR lpName);
bool IsDummyName(LPSTR lpName);

typedef struct _INSTR
{
	TiXmlNode *node;			// pointer to instruction node
	unsigned char Data[16];		// data
	int iLen;					// full len
	int iMaskLen;				// mask len
} INSTR, *PINSTR;

typedef struct _FUNC
{
	_FUNC *prev;

	TiXmlNode *node;			// pointer to function node
	PINSTR insArray;			// instructions array
	int iCount;					// count of instructions

	_FUNC *next;
} FUNC, *PFUNC;
