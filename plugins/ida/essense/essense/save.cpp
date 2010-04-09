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
    save.cpp

Abstract: Save functions

Revision History:

 kab        21/09/2004
			Initial release
			01/10/2004
			Improved GetMaskLen
			Added saving function frame sizes

--*/

#include "stdafx.h"
#include "save.h"

extern TiXmlDocument xmlDoc;
extern int iPluginFlags;		// flags

int iStructCnt=0;
tid_t StructID[1024];
int iEnumCnt=0;
tid_t EnumID[1024];

void SaveFunction(ea_t start_addr, ea_t end_addr, LPCSTR lpFileName)
{
	char buf[MAX_PATH];

	xmlDoc.SetTabSize(8);

	if (PathFileExists(lpFileName))
		xmlDoc.LoadFile(lpFileName);

	show_wait_box("Saving functions to XML...");

	for (size_t cnt=0;cnt<get_func_qty();cnt++)
	{
		if (wasBreak())
		{
			hide_wait_box();
			xmlDoc.SaveFile(lpFileName);
			return;
		}

		func_t *func=getn_func(cnt);

		if ((isAllFuncs(iPluginFlags)) || (func->startEA>=start_addr && func->endEA<=end_addr))
		{

			showAddr(func->startEA);

			get_name(BADADDR, func->startEA, buf, MAX_PATH);

			if ( 
				(!IsFuncPresent(buf))  && 
				(isDontCheckNames(iPluginFlags) || !IsDummyName(buf))
				)
			{

				if (isShowDebug(iPluginFlags))
					msg("Storing: %s at %x\n", buf, func->startEA);

				TiXmlElement xmlFunction("Function");
				TiXmlElement xmlFrame("Frame");

				xmlFunction.SetAttribute("Name", buf);

				if (get_func_comment(func, true))
				{
					TiXmlElement xmlCmt("Comment");
					TiXmlText xmlText("");
					xmlCmt.SetAttribute("Repeatable", true);
					xmlText.SetValue(get_func_comment(func, true));
					xmlCmt.InsertEndChild(xmlText);
					xmlFunction.InsertEndChild(xmlCmt);
				}

				if (get_func_comment(func, false))
				{
					TiXmlElement xmlCmt("Comment");
					TiXmlText xmlText("");
					xmlCmt.SetAttribute("Repeatable", false);
					xmlText.SetValue(get_func_comment(func, false));
					xmlCmt.InsertEndChild(xmlText);
					xmlFunction.InsertEndChild(xmlCmt);
				}

				if (get_frame(func))
				{
					xmlFunction.SetAttribute("Frsize", func->frsize);
					xmlFunction.SetAttribute("Frregs", func->frregs);
					xmlFunction.SetAttribute("Argsize", func->argsize);
					SaveStructure(get_frame(func), xmlFrame, false);
					xmlFunction.InsertEndChild(xmlFrame);
				}

				for (ea_t i=func->startEA; i<func->endEA; i+=cmd.size > 0 ? cmd.size : 1)
				{
					TiXmlElement xmlInstr("Instruction");
					TiXmlElement xmlCode("Code");
					TiXmlText xmlText("");

					ua_ana0(i);

					SaveInstruction(i, xmlInstr, func);

					memset(buf, 0, MAX_PATH);

					for (ea_t j=i; j<i+cmd.size; j++)
					{
						sprintf(buf, "%s%02X", buf, get_byte(j));
					}

					xmlText.SetValue(buf);
					xmlCode.InsertEndChild(xmlText);
					xmlInstr.InsertEndChild(xmlCode);
					xmlFunction.InsertEndChild(xmlInstr);
				}

				AddToXml(xmlFunction);
			}

		}
	}

	xmlDoc.SaveFile(lpFileName);

	hide_wait_box();
}

void AddToXml(TiXmlElement &xmlElement)
{
	TiXmlElement *xmlEssense;

	xmlEssense=xmlDoc.FirstChildElement("Essense");
	if (!xmlEssense)
	{
		TiXmlElement xmlNode("Essense");
		xmlNode.SetAttribute("Version", ESSENSE_VERSION);
		xmlDoc.InsertEndChild(xmlNode);
		xmlEssense=xmlDoc.FirstChildElement("Essense");
	}
	xmlEssense->InsertEndChild(xmlElement);
}

bool SaveStructure(struc_t *s, TiXmlElement &xmlStruct, bool bSave)
{
	if (isNotSaveStructures(iPluginFlags))
		return false;

	if (!s)
	{
		if (isShowDebug(iPluginFlags))
			msg("Error! Null struct!\n");
		return false;
	}

	if (bSave)
	{
		for (int i=0;i<iStructCnt;i++)
			if (StructID[i]==s->id)
				return false;

		StructID[iStructCnt]=s->id;
		iStructCnt++;

		xmlStruct.SetAttribute("Name", get_struc_name(s->id));
	}

	xmlStruct.SetAttribute("Props", s->props);
	xmlStruct.SetAttribute("MemQty", s->memqty);
	xmlStruct.SetAttribute("Union", s->is_union());
	for (UINT i=0;i<s->memqty;i++)
	{
		TiXmlElement xmlMember("Member");
		typeinfo_t ti;
//		type_t t;

		memset(&ti, 0, sizeof(typeinfo_t));

		xmlMember.SetAttribute("Name", get_member_name(s->members[i].id));
		xmlMember.SetAttribute("Soff", s->members[i].soff);
		xmlMember.SetAttribute("Eoff", s->members[i].eoff);
		xmlMember.SetAttribute("Flags", s->members[i].flag);
		xmlMember.SetAttribute("Props", s->members[i].props);

		if (get_member_cmt(s->members[i].id, false))
		{
			TiXmlElement xmlCmt("Comment");
			TiXmlText xmlText("");
			xmlCmt.SetAttribute("Repeatable", false);
			xmlText.SetValue(get_member_cmt(s->members[i].id, false));
			xmlCmt.InsertEndChild(xmlText);
			xmlMember.InsertEndChild(xmlCmt);
		}

		if (get_member_cmt(s->members[i].id, true))
		{
			TiXmlElement xmlCmt("Comment");
			TiXmlText xmlText("");
			xmlCmt.SetAttribute("Repeatable", true);
			xmlText.SetValue(get_member_cmt(s->members[i].id, true));
			xmlCmt.InsertEndChild(xmlText);
			xmlMember.InsertEndChild(xmlCmt);
		}

		//if (s->members[i].has_ti())
		//{
		//	get_member_ti(&s->members[i], &t);
		//	xmlMember.SetAttribute("Type", t); 
		//}

		if (retrieve_member_info(&s->members[i], &ti))
		{
			TiXmlElement xmlTypeInfo("TypeInfo");

			SaveTypeInfo(&ti, 0, s->members[i].flag, xmlTypeInfo);
            
			xmlMember.InsertEndChild(xmlTypeInfo);
		}

		xmlStruct.InsertEndChild(xmlMember);
	}

	return true;
}

bool SaveEnum(enum_t e, TiXmlElement &xmlEnum)
{
	for (int i=0;i<iEnumCnt;i++)
		if (EnumID[i]==e)
			return false;

	EnumID[iEnumCnt]=e;
	iEnumCnt++;

	xmlEnum.SetAttribute("Name", get_enum_name(e));
	xmlEnum.SetAttribute("Flags", get_enum_flag(e));

	const_t main_cid;
	uval_t v=0;
	uchar serial;
	bmask_t bmask=DEFMASK;

	for (v=get_first_const(e, bmask); v!=BADNODE; v=get_next_const(e, v, bmask))
	{
		for ( const_t cid=main_cid=get_first_serial_const(e, v, &serial, bmask);
			cid != BADNODE;
			cid = get_next_serial_const(main_cid, &serial) )
		{
			TiXmlElement xmlConst("Const");
			xmlConst.SetAttribute("Name", get_const_name(cid));
			xmlConst.SetAttribute("Value", get_const_value(cid));
			xmlConst.SetAttribute("Serial", get_const_serial(cid));
			xmlEnum.InsertEndChild(xmlConst);
		}
	}

	return true;
}

bool SaveTypeInfo(typeinfo_t *ti, int iIndex, flags_t flags, TiXmlElement &xmlTypeInfo)
{
	char buf[MAX_PATH];
	TiXmlText xmlText("");
	ea_t o_addr;

	if (isOff(flags, iIndex))			// offset
	{
		xmlTypeInfo.SetAttribute("Type", OP_OFF);

		if (isCode(flags))				// code? save offset name. need to call ua_ana0() first.
		{
			switch(cmd.Operands[iIndex].type)
			{
			case o_displ:
			case o_mem:
				{
					o_addr=calc_reference_target(cmd.ea, ti->ri, cmd.Operands[iIndex].addr);
					break;
				}
			case o_imm:
				{
					o_addr=calc_reference_target(cmd.ea, ti->ri, cmd.Operands[iIndex].value);
					break;
				}
			default:
				{
					o_addr=BADADDR;
					break;
				}
			}

			if (get_name(BADADDR, o_addr, buf, MAX_PATH))
				xmlTypeInfo.SetAttribute("Name", buf);
		}

		xmlTypeInfo.SetAttribute("RefType", (int)ti->ri.type);
		xmlTypeInfo.SetAttribute("TargetPresent", (int)ti->ri.target_present);
		xmlTypeInfo.SetAttribute("Target", (int)ti->ri.target);
		xmlTypeInfo.SetAttribute("Base", (int)ti->ri.base);
		xmlTypeInfo.SetAttribute("TDelta", (int)ti->ri.tdelta);

	}
	else if (isChar(flags, iIndex))		// char
	{
		xmlTypeInfo.SetAttribute("Type", OP_CHAR);
	}
	else if (isSeg(flags, iIndex))		// segment
	{
		xmlTypeInfo.SetAttribute("Type", OP_SEG);
	}
	else if (isEnum(flags, iIndex))		// enum
	{
		xmlTypeInfo.SetAttribute("Type", OP_ENUM);
		xmlTypeInfo.SetAttribute("Name", get_enum_name(ti->ec.tid));
		xmlTypeInfo.SetAttribute("Serial", ti->ec.serial);

		TiXmlElement xmlEnum("Enum");
		if (SaveEnum(ti->ec.tid, xmlEnum))
			AddToXml(xmlEnum);
			//xmlDoc.InsertEndChild(xmlEnum);
	}
	else if (isFop(flags, iIndex))		// forced operand
	{
		xmlTypeInfo.SetAttribute("Type", OP_FOP);
	}
	else if (isStroff(flags, iIndex))	// structure offset
	{
		xmlTypeInfo.SetAttribute("Type", OP_STRO);
		xmlTypeInfo.SetAttribute("PathLen", ti->path.len);
		xmlTypeInfo.SetAttribute("Delta", ti->path.delta);
		for (int i=0;i<ti->path.len;i++)
		{
			tid_t tid=ti->path.ids[i];

//			if (i)						// not first element
//				tid=get_strid(tid);
//				tid=get_struc_by_idx(tid);

			if (tid!=BADNODE && netnode(tid).name())
			{
				TiXmlElement xmlPath("Path");
				TiXmlElement xmlStruct("Structure");
				
				if (i)
				{
					if (get_struc(get_strid(tid)))
						if (SaveStructure(get_struc(get_strid(tid)), xmlStruct))
							AddToXml(xmlStruct);
//							xmlDoc.InsertEndChild(xmlStruct);
				}
				else
				{
					if (get_struc(tid))
						if (SaveStructure(get_struc(tid), xmlStruct))
							AddToXml(xmlStruct);
//							xmlDoc.InsertEndChild(xmlStruct);
				}

				xmlPath.SetAttribute("Name", netnode(tid).name());
				xmlPath.SetAttribute("Index", i);
				xmlTypeInfo.InsertEndChild(xmlPath);
			}
		}
	}
	else if (isStkvar(flags, iIndex))	// stack var
	{
		xmlTypeInfo.SetAttribute("Type", OP_STK);
	}
	else if (isFltnum(flags, iIndex))	// float number
	{
		xmlTypeInfo.SetAttribute("Type", OP_FLT);
	}
	else if (isNum(flags, iIndex))		// number
	{
		if (flags & hexflag())
			xmlTypeInfo.SetAttribute("Type", OP_NUMH);
		else if (flags & decflag())
			xmlTypeInfo.SetAttribute("Type", OP_NUMD);
		else if (flags & octflag())
			xmlTypeInfo.SetAttribute("Type", OP_NUMO);
		else if (flags & binflag())
			xmlTypeInfo.SetAttribute("Type", OP_NUMB);
	}
	// Data only types
	else if (isByte(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_BYTE);
	}
	else if (isWord(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_WORD);
	}
	else if (isDwrd(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_DWRD);
	}
	else if (isQwrd(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_QWRD);
	}
	else if (isOwrd(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_OWRD);
	}
	else if (isTbyt(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_TBYT);
	}
	else if (isFloat(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_FLOAT);
	}
	else if (isDouble(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_DOUBLE);
	}
	else if (isPackReal(flags))
	{
		xmlTypeInfo.SetAttribute("Type", OP_PACKREAL);
	}
	else if (isStruct(flags))							// struct
	{
		TiXmlElement xmlStruct("Structure");
		if (SaveStructure(get_struc(ti->tid), xmlStruct))
			AddToXml(xmlStruct);
//			xmlDoc.InsertEndChild(xmlStruct);

		xmlTypeInfo.SetAttribute("Type", OP_STRU);
		xmlTypeInfo.SetAttribute("Name", get_struc_name(ti->tid));

	}
	else if (isASCII(flags))						// string
	{
		xmlTypeInfo.SetAttribute("Type", OP_ASCI);
		xmlTypeInfo.SetAttribute("Value", ti->strtype);
	}
	else if (isAlign(flags))						// align
	{
		xmlTypeInfo.SetAttribute("Type", OP_ALIGN);
	}
	else
		return false;

	return true;
}

void SaveInstruction(ea_t addr, TiXmlElement &xmlInstr, func_t *func)
{
	flags_t flags;
	char buf[MAX_PATH];

	flags = getFlags(addr);

	if (has_name(flags))
	{
		get_name(BADADDR, addr, buf, MAX_PATH);
		xmlInstr.SetAttribute("Name", buf);
	}

	xmlInstr.SetAttribute("Length", cmd.size);
	xmlInstr.SetAttribute("MaskLen", GetMaskLen(addr, func));
	xmlInstr.SetAttribute("Flags", flags);

	if (!isIgnoreCallTo(iPluginFlags) && cmd.itype==NN_call)
	{
		ea_t ref=get_first_fcref_from(addr);
		get_name(BADADDR, ref, buf, MAX_PATH);
		if (is_uname(buf))
			xmlInstr.SetAttribute("ToName", buf);
	}

	if (has_cmt(flags))
	{

		if (get_cmt(addr, false))
		{
			TiXmlElement xmlCmt("Comment");
			TiXmlText xmlText("");
			xmlCmt.SetAttribute("Repeatable", false);
			xmlText.SetValue(get_cmt(addr, false));
			xmlCmt.InsertEndChild(xmlText);
			xmlInstr.InsertEndChild(xmlCmt);
		}
		
		if (get_cmt(addr, true))
		{
			TiXmlElement xmlCmt("Comment");
			TiXmlText xmlText("");
			xmlCmt.SetAttribute("Repeatable", true);
			xmlText.SetValue(get_cmt(addr, true));
			xmlCmt.InsertEndChild(xmlText);
			xmlInstr.InsertEndChild(xmlCmt);
		}
	}

	char *desc=NULL;
	int i=IsMark(addr, desc);

	if (i && desc)
	{
		TiXmlElement xmlMark("Mark");
		TiXmlText xmlText("");
		xmlMark.SetAttribute("Index", i);
		xmlText.SetValue(desc);
		xmlMark.InsertEndChild(xmlText);
		xmlInstr.InsertEndChild(xmlMark);
	}

	for (int j=0;j<2;j++)
	{
		if (isDefArg(flags, j))	// defined?
		{
			TiXmlElement xmlOperand("Operand");

			if (SaveOperand(addr, j, xmlOperand))
				xmlInstr.InsertEndChild(xmlOperand);
		}
	}
}

bool SaveOperand(ea_t addr, int iIndex, TiXmlElement &xmlOperand)
{
	typeinfo_t ti;
	flags_t flags;

	flags = getFlags(addr);

	get_typeinfo(addr, iIndex, flags, &ti);

	xmlOperand.SetAttribute("Index", iIndex);

	TiXmlElement xmlTypeInfo("TypeInfo");

	if (!SaveTypeInfo(&ti, iIndex, flags, xmlTypeInfo))
		return false;
    
	xmlOperand.InsertEndChild(xmlTypeInfo);

	return true;
}

int GetMaskLen(ea_t addr, func_t *func)
{
	int iMaskLen=0;

	ua_ana0(addr);

	iMaskLen=cmd.size;

	for (int i=0;i<6;i++)
	{
		if (cmd.Operands[i].type==o_void)
			break;

		if (	cmd.Operands[i].type==o_mem ||
				cmd.Operands[i].type==o_displ ||
				cmd.Operands[i].type==o_far ||
				cmd.Operands[i].type==o_near
			)	// memory, memory with displ, far or near code
		{
			if (IsJump(addr))	// jump?
			{
				ea_t dest=get_first_fcref_from(addr);
				if ((dest>=func->startEA) && (dest<=func->endEA))	// inside our func?
					break;											// save it with addr
			}

			iMaskLen=cmd.Operands[i].offb != 0 ? cmd.Operands[i].offb : iMaskLen;
//			msg("addr: %x, type: %x, mask: %x\n", addr, cmd.Operands[i].type, iMaskLen);
			break;
		}
	}

	return iMaskLen;
}

bool IsJump(ea_t addr)
{
	if (get_byte(addr)==0xe9)
		return true;
	if (get_byte(addr)==0xeb)
		return true;
	if ((get_byte(addr) & 0xf0)==0x70)
		return true;
	if (get_byte(addr)==0x0f && ((get_byte(addr+1) & 0xf0)==0x80))
		return true;

	return false;
}

int IsMark(ea_t addr, LPSTR &desc)
{
	curloc loc("IDAView-A");

	for ( int i=1; i < MAX_MARK_SLOT; i++ )
	{
		ea_t ea = loc.markedpos(&i);
		if (ea==addr)
		{
			if (isShowDebug(iPluginFlags))
				msg("Mark: %x, Desc: %s\n", i, loc.markdesc(i));

			desc=loc.markdesc(i);
			return i;
		}
	}

	return 0;
}