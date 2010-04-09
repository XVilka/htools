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
    load.cpp

Abstract: Load functions

Revision History:

 kab	21/09/2004
		Initial release
		01/10/2004
		Added loading function frame sizes

--*/

#include "stdafx.h"
#include "load.h"

extern TiXmlDocument xmlDoc;
extern int iPluginFlags;		// flags

void LoadFunction(ea_t begin, ea_t end, LPCSTR lpFileName)
{
	TiXmlNode *xmlFunction;
	TiXmlNode *xmlInstr;
	char buf[MAX_PATH];
	ea_t addr;
	bool bFound;

	PFUNC pFirst=NULL, pCurr=NULL, pLast=NULL;

	if (!xmlDoc.LoadFile(lpFileName))
	{
		msg("Error: cannot find XML file: %s\n", lpFileName);
		return;
	}

	show_wait_box("Loading functions from XML...");

	for (xmlFunction=xmlDoc.FirstChild("Essense")->IterateChildren("Function", 0); 
		xmlFunction; 
		xmlFunction=xmlDoc.FirstChild("Essense")->IterateChildren("Function", xmlFunction))
	{
		pCurr=new FUNC;
		pCurr->node=xmlFunction;
		pCurr->next=NULL;

		if (!pFirst)
		{
			pFirst=pCurr;
			pLast=pCurr;
			pFirst->prev=NULL;

		}
		else
		{
            pLast->next=pCurr;
			pCurr->prev=pLast;
			pLast=pCurr;
		}

		pCurr->iCount = 0;

		for (xmlInstr=xmlFunction->IterateChildren("Instruction", 0); 
			xmlInstr; 
			xmlInstr=xmlFunction->IterateChildren("Instruction", xmlInstr))
		{
			pCurr->iCount++;
		}

		pCurr->insArray=new INSTR[pCurr->iCount];

		int iCnt=0;
		for (xmlInstr=xmlFunction->IterateChildren("Instruction", 0); 
			xmlInstr; 
			xmlInstr=xmlFunction->IterateChildren("Instruction", xmlInstr))
		{			
			pCurr->insArray[iCnt].node=xmlInstr;
			ToBinary(pCurr->insArray[iCnt].Data, xmlInstr->FirstChildElement("Code")->FirstChild()->Value());
			xmlInstr->ToElement()->Attribute("MaskLen", (int *)&(pCurr->insArray[iCnt].iMaskLen));
			xmlInstr->ToElement()->Attribute("Length", (int *)&(pCurr->insArray[iCnt].iLen));
			iCnt++;
		}

	}


	for (ea_t i=begin; i<=end; i++)
	{
		showAddr(i);

		if (wasBreak())
		{
			hide_wait_box();
			return;
		}

		for (pCurr=pFirst; pCurr; pCurr=pCurr->next)
		{
			addr = i;
			bFound = true;
			
			for (int j=0;j<pCurr->iCount;j++)
			{
				if (!CheckInstr(addr, &(pCurr->insArray[j])))
				{
					bFound=false;
					break;
				}
				addr+=pCurr->insArray[j].iLen;
			}

			if (bFound)
			{
				xmlFunction=pCurr->node;

				msg("Function %s match at 0x%X\n", xmlFunction->ToElement()->Attribute("Name"), i);
				jumpto(i);
				add_func(i, addr);

				get_name(BADADDR, i, buf, MAX_PATH);

				if (IsDummyName(buf) || isForceLoad(iPluginFlags))		// already user-defined function
				{

					set_name(i, xmlFunction->ToElement()->Attribute("Name"));

					if (xmlFunction->FirstChild("Comment"))
					{
						for (TiXmlNode *xmlCmt=xmlFunction->IterateChildren("Comment", 0); 
							xmlCmt; 
							xmlCmt=xmlFunction->IterateChildren("Comment", xmlCmt))
						{
							int iRepeatable=0;
							xmlCmt->ToElement()->Attribute("Repeatable", (int *)&iRepeatable);
							set_func_comment(get_func(i), xmlCmt->FirstChild()->Value(), iRepeatable!=0);
						}
					}

					if (xmlFunction->FirstChild("Frame"))	// restore frame
					{
						asize_t argsize, frsize, frregs;
						xmlFunction->ToElement()->Attribute("Frsize", (int *)&frsize);
						xmlFunction->ToElement()->Attribute("Frregs", (int *)&frregs);
						xmlFunction->ToElement()->Attribute("Argsize", (int *)&argsize);
						set_frame_size(get_func(i), frsize, (ushort)frregs, argsize);

						LoadStructure(get_frame(i), xmlFunction->FirstChild("Frame"));
					}

					addr = i;

					for (xmlInstr=xmlFunction->IterateChildren("Instruction", 0); 
						xmlInstr; 
						xmlInstr=xmlFunction->IterateChildren("Instruction", xmlInstr))
					{
						RestoreInstr(addr, xmlInstr);

						int j;
						xmlInstr->ToElement()->Attribute("Length", &j);
						addr+=j;
					}
				}
			}
			else
			{
				if (addr!=i && isShowDebug(iPluginFlags))	// At least 1 instruction match
				{
					msg("Function: %s - mismatch at %x\n", xmlFunction->ToElement()->Attribute("Name"), addr);
				}
			}
		}
	}

	while (pFirst)
	{
        pCurr=pFirst;
		pFirst=pFirst->next;
		delete [] pCurr->insArray;
		delete pCurr;
	}

	hide_wait_box();
}

enum_t LoadEnum(const char *EnumName)
{
	enum_t e;

	e=get_enum(EnumName);

	if (e!=BADNODE)
		return e;

	for (TiXmlNode *xmlEnum=xmlDoc.FirstChild("Essense")->IterateChildren("Enum", 0); 
		xmlEnum; 
		xmlEnum=xmlDoc.FirstChild("Essense")->IterateChildren("Enum", xmlEnum))
	{
		if (strcmp(EnumName, xmlEnum->ToElement()->Attribute("Name"))!=0)
			continue;

		flags_t flags;
		xmlEnum->ToElement()->Attribute("Flags", (int *)&flags);

		e=add_enum(BADADDR, xmlEnum->ToElement()->Attribute("Name"), flags);

		for (TiXmlNode *xmlConst=xmlEnum->IterateChildren("Const", 0); xmlConst; xmlConst=xmlEnum->IterateChildren("Const", xmlConst))
		{
			bmask_t bmask=DEFMASK;
			uval_t v;
			xmlConst->ToElement()->Attribute("Value", (int*)&v);
			add_const(e, xmlConst->ToElement()->Attribute("Name"), v, bmask);
		}

		return e;
	}

	return BADNODE;
}

struc_t *LoadStructure(const char *StructName)
{
	struc_t *s=NULL;
	tid_t tid=get_struc_id(StructName);
	int iUnion=0;

	if (tid!=BADNODE)
	{
		s=get_struc(tid);
		if (isShowDebug(iPluginFlags))
			msg("Structure: %s found, tid=%X, s=%X\n", StructName, tid, s);
		return s;
	}

	if (isNotSaveStructures(iPluginFlags))
	{
		if (isShowDebug(iPluginFlags))
			msg("Structure: %s not found\n", StructName);

		return NULL;
	}

	for (TiXmlNode *xmlStruct=xmlDoc.FirstChild("Essense")->IterateChildren("Structure", 0); 
		xmlStruct; 
		xmlStruct=xmlDoc.FirstChild("Essense")->IterateChildren("Structure", xmlStruct))
	{
		if (strcmp(xmlStruct->ToElement()->Attribute("Name"), StructName)!=0)						// name match?
			continue;

		xmlStruct->ToElement()->Attribute("Union", &iUnion);
		tid=add_struc(BADADDR, NULL, iUnion>0);
		s=get_struc(tid);
		LoadStructure(s, xmlStruct);

		if (isShowDebug(iPluginFlags))
			msg("Structure: %s added\n", StructName);

		return s;
	}

	return NULL;
}

void LoadStructure(struc_t *s, TiXmlNode *node)
{
	int iCnt=0;
	TiXmlNode *xmlMember;

	if (node->ToElement()->Attribute("Name"))
		set_struc_name(s->id, node->ToElement()->Attribute("Name"));

	node->ToElement()->Attribute("MemQty", &iCnt);

	for (xmlMember=node->IterateChildren("Member", 0); xmlMember; xmlMember=node->IterateChildren("Member", xmlMember))
	{
		typeinfo_t ti;
		ea_t start_ofs;
		ea_t end_ofs;
		flags_t flags;
		TiXmlNode *xmlTypeInfo;

		memset(&ti, 0, sizeof(typeinfo_t));

		xmlMember->ToElement()->Attribute("Soff", (int*)&start_ofs);
		xmlMember->ToElement()->Attribute("Eoff", (int*)&end_ofs);
		xmlMember->ToElement()->Attribute("Flags", (int*)&flags);

		if (xmlTypeInfo=xmlMember->FirstChildElement("TypeInfo"))
			LoadTypeInfo(&ti, xmlTypeInfo);
		
		member_t *mptr=get_member(s, start_ofs);				// member at this offset present

		if (s->is_union())
			start_ofs=0;
		else
		{
			if (mptr)
				if (!(strcmp(" r", get_member_name(mptr->id))==0 || strcmp(" s", get_member_name(mptr->id))==0))	// standard " r" or " s" ? skip it if so...
					if (!del_struc_members(s, start_ofs, end_ofs))	// try to delete members
						if (isShowDebug(iPluginFlags))
							msg("Cannot delete struct member (struct: %s, member: %s, offset: %d)\n", get_struc_name(s->id),get_member_name(get_member(s, start_ofs)->id), start_ofs);
		}

		if (!
			(strcmp(" r", xmlMember->ToElement()->Attribute("Name"))==0 || strcmp(" s", xmlMember->ToElement()->Attribute("Name"))==0)
			)	// standard " r" or " s" ? skip it if so...
		{
			int err=add_struc_member(s, xmlMember->ToElement()->Attribute("Name"), start_ofs, flags, &ti, end_ofs-start_ofs);

			if (err && isShowDebug(iPluginFlags))
				msg("Add struct member error: %d (Struct: %s, Member: %s, Offset: %d)\n", err, get_struc_name(s->id), xmlMember->ToElement()->Attribute("Name"), start_ofs);
		}

		if (xmlMember->FirstChildElement("Comment"))
		{
			for (TiXmlNode *xmlCmt=xmlMember->IterateChildren("Comment", 0); xmlCmt; xmlCmt=xmlMember->IterateChildren("Comment", xmlCmt))
			{
				int iRepeatable=0;
				member_t *member=get_member(s, start_ofs);
				xmlCmt->ToElement()->Attribute("Repeatable", (int *)&iRepeatable);
				set_member_cmt(member, xmlCmt->FirstChild()->Value(), iRepeatable!=0);
			}
		}
	}
}

bool LoadTypeInfo(typeinfo_t *ti, TiXmlNode *xmlTypeInfo, LPSTR lpName)
{
	OP_TYPE type;
//	char buf[MAX_PATH];

	xmlTypeInfo->ToElement()->Attribute("Type", (int *)&type);

	switch(type)
	{
	case OP_OFF:
		{
			xmlTypeInfo->ToElement()->Attribute("RefType", (int*)&ti->ri.type);
			xmlTypeInfo->ToElement()->Attribute("TargetPresent", (int*)&ti->ri.target_present);
			xmlTypeInfo->ToElement()->Attribute("Target", (int*)&ti->ri.target);
			xmlTypeInfo->ToElement()->Attribute("Base", (int*)&ti->ri.base);
			xmlTypeInfo->ToElement()->Attribute("TDelta", (int*)&ti->ri.tdelta);
			if (xmlTypeInfo->ToElement()->Attribute("Name") && lpName)
				strcpy(lpName, xmlTypeInfo->ToElement()->Attribute("Name"));
			break;
		}
	case OP_CHAR:
		{
			break;
		}
	case OP_SEG:
		{
			break;
		}
	case OP_ENUM:
		{
			xmlTypeInfo->ToElement()->Attribute("Serial", (int *)&ti->ec.serial);
			ti->ec.tid=LoadEnum(xmlTypeInfo->ToElement()->Attribute("Name"));

			if (ti->ec.tid==BADNODE)
			{
				msg("Error! Cannot find enum %s\n", xmlTypeInfo->ToElement()->Attribute("Name"));
				return false;
			}

			break;
		}
	case OP_FOP:
		{
			break;
		}
	case OP_STRO:
		{
			xmlTypeInfo->ToElement()->Attribute("PathLen", (int *)&ti->path.len);
			xmlTypeInfo->ToElement()->Attribute("Delta", (int *)&ti->path.delta);
			for (TiXmlNode *xmlPath=xmlTypeInfo->IterateChildren("Path", 0); xmlPath; xmlPath=xmlTypeInfo->IterateChildren("Path", xmlPath))
			{
				int i;
				tid_t tid;
				struc_t *sptr;
				member_t *mptr;

				xmlPath->ToElement()->Attribute("Index", &i);

				if (i)	// not first element
				{
					mptr=get_member_by_fullname(xmlPath->ToElement()->Attribute("Name"), &sptr);
					if (!mptr || !sptr)
					{
						msg("Error! Cannot find member: %s\n", xmlPath->ToElement()->Attribute("Name"));
						return false;
					}

					tid=mptr->id;
				}
				else
				{
					sptr=LoadStructure(xmlPath->ToElement()->Attribute("Name"));
					if (!sptr)
					{
						msg("Error! Cannot find structure: %s\n", xmlPath->ToElement()->Attribute("Name"));
						return false;
					}

					tid = sptr->id;
				}

				if (tid!=BADNODE)
					ti->path.ids[i]=tid;
			}
			break;
		}
	case OP_STK:
		{
			break;
		}
	case OP_FLT:
		{
			break;
		}
	case OP_NUMH:
	case OP_NUMD:
	case OP_NUMO:
	case OP_NUMB:
		{
			break;
		}
	case OP_BYTE:
	case OP_WORD:
	case OP_DWRD:
	case OP_QWRD:
	case OP_OWRD:
	case OP_TBYT:
	case OP_FLOAT:
	case OP_DOUBLE:
	case OP_PACKREAL:
		{
			break;
		}
	case OP_STRU:
		{
			struc_t *s=LoadStructure(xmlTypeInfo->ToElement()->Attribute("Name"));

			if (!s)
			{
				msg("Error! Cannot find structure: %s\n", xmlTypeInfo->ToElement()->Attribute("Name"));
				return false;
			}
			
			ti->tid=s->id;

			break;
		}
	case OP_ASCI:
		{
			xmlTypeInfo->ToElement()->Attribute("Value", (int *)&ti->strtype);
			break;
		}
	case OP_ALIGN:
		{
			break;
		}
	default:
		return false;
	}
	return true;
}

void RestoreInstr(ea_t addr, TiXmlNode *node)
{
	int iIndex;
	TiXmlNode *xmlOperand;
//	TiXmlNode *xmlPath;
//	member_t *member;
	typeinfo_t ti;
	ea_t o_addr;
	flags_t flags;
	char buf[MAX_PATH];

	memset(buf, 0, MAX_PATH);

	ua_ana0(addr);
	//msg("Addr: %x\n", addr);

	if (node->ToElement()->Attribute("Name"))
		set_name(addr, node->ToElement()->Attribute("Name"));

	if (node->FirstChildElement("Comment"))
	{
		for (TiXmlNode *xmlCmt=node->IterateChildren("Comment", 0); xmlCmt; xmlCmt=node->IterateChildren("Comment", xmlCmt))
		{
			int iRepeatable=0;
			xmlCmt->ToElement()->Attribute("Repeatable", (int *)&iRepeatable);
			set_cmt(addr, xmlCmt->FirstChild()->Value(), iRepeatable!=0);
		}
	}

	if (node->FirstChildElement("Mark"))
	{
		TiXmlNode *xmlMark=node->FirstChild("Mark");
		curloc loc("IDAView-A");
		int i;

		for (i=1; i < MAX_MARK_SLOT; i++ )
		{
			ea_t ea = loc.markedpos(&i);
			if (ea==BADADDR)
				break;
		}

		loc.ea=addr;
		loc.mark(i, NULL, xmlMark->FirstChild()->Value());
	}

	node->ToElement()->Attribute("Flags", (int *)&flags);
	setFlags(addr, flags);

	if (node->FirstChildElement("Operand"))
	{
		for (xmlOperand=node->IterateChildren("Operand", 0); xmlOperand; xmlOperand=node->IterateChildren("Operand", xmlOperand))
		{
			xmlOperand->ToElement()->Attribute("Index", &iIndex);
			if (xmlOperand->FirstChildElement("TypeInfo"))
			{
				if (LoadTypeInfo(&ti, xmlOperand->FirstChildElement("TypeInfo"), buf))
				{
					set_typeinfo(addr, iIndex, flags, &ti);

					if (isOff(flags, iIndex) && buf[0])
					{

						ua_ana0(addr);

						switch(cmd.Operands[iIndex].type)
						{
						case o_displ:
						case o_mem:
							{
								o_addr=calc_reference_target(cmd.ea, ti.ri, cmd.Operands[iIndex].addr);
								break;
							}
						case o_imm:
							{
								o_addr=calc_reference_target(cmd.ea, ti.ri, cmd.Operands[iIndex].value);
								break;
							}
						default:
							{
								o_addr=BADADDR;
								break;
							}
						}

						if (o_addr!=BADADDR)
							set_name(o_addr, buf);
					}
				}
			}
		}
	}

}

bool CheckInstr(ea_t addr, PINSTR pInstr)
{
	bool bRes=true;

	for (int i=0; i<pInstr->iMaskLen; i++)
	{
		if (get_byte(addr + i)!=pInstr->Data[i])
		{
			bRes=false;
			break;
		}
	}

	if (bRes && isCode(getFlags(addr)) && pInstr->node->ToElement()->Attribute("ToName") && !isIgnoreCallTo(iPluginFlags))
	{
		bRes=false;

		ua_ana0(addr);

		if (cmd.itype==NN_call)
		{
			ea_t ref=get_first_fcref_from(addr);
			char buf[MAX_PATH];
			get_name(BADADDR, ref, buf, MAX_PATH);
			if (strcmp(buf, pInstr->node->ToElement()->Attribute("ToName"))==0)
				bRes=true;
		}
	}

	return bRes;
}

UINT ToBinary(LPBYTE lpDstBuf, LPCTSTR lpSrcString)
{
	UINT iRes=0;
	UINT i;

	for (iRes=0; iRes < strlen(lpSrcString)/2 ; iRes++)
	{
		sscanf(lpSrcString+iRes*2, "%02X", &i);
		if (lpDstBuf)
			lpDstBuf[iRes]=(BYTE)i;
	}

	return iRes;
}
