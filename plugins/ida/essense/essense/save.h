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
    save.h

Abstract: Save functions definitions

Revision History:

 kab        21/09/2004
      Initial release

--*/

#pragma once
#include "common.h"

void SaveFunction(ea_t start_addr, ea_t end_addr, LPCSTR lpFileName);
void SaveInstruction(ea_t addr, TiXmlElement &xmlInstr, func_t *func);
bool SaveOperand(ea_t addr, int iIndex, TiXmlElement &xmlOperand);
bool SaveStructure(struc_t *s, TiXmlElement &xmlStruct, bool bSave=true);
bool SaveEnum(enum_t e, TiXmlElement &xmlEnum);
bool SaveTypeInfo(typeinfo_t *ti, int iIndex, flags_t flags, TiXmlElement &xmlTypeInfo);
bool IsJump(ea_t addr);
int GetMaskLen(ea_t addr, func_t *func);
int IsMark(ea_t addr, LPSTR &desc);
void AddToXml(TiXmlElement &xmlElement);
