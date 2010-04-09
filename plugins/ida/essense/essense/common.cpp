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
    common.cpp

Abstract: Common funcs

Revision History:

 kab	05/10/2004
		Initial release

--*/

#include "stdafx.h"
#include "common.h"

extern TiXmlDocument xmlDoc;
extern int iPluginFlags;		// flags

bool IsFuncPresent(LPSTR lpName)
{
	TiXmlNode *xmlFunction;
	TiXmlNode *xmlEssense=xmlDoc.FirstChildElement("essense");

	if (!xmlEssense)
		return false;

	for (xmlFunction=xmlEssense->IterateChildren("Function", 0); 
		xmlFunction; 
		xmlFunction=xmlEssense->IterateChildren("Function", xmlFunction))
	{
		if (strcmp(xmlFunction->ToElement()->Attribute("Name"), lpName)==0)
			return true;
	}

	return false;
}

bool IsDummyName(LPSTR lpName)
{
	if (strstr(lpName, "unknown_libname"))
		return true;
	if (strstr(lpName, "nullsub"))
		return true;

#ifdef DEBUG
// warning!!! This will skip all names begin with '?'
	if (*lpName=='?')
		return true;
#endif

	if (!is_uname(lpName))
		return true;

	return false;
}
