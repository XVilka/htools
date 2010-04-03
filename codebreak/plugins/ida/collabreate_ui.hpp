/*
    Collabreate GUI and communications layer
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation; either version 2 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    this program; if not, write to the Free Software Foundation, Inc., 59 Temple
    Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifndef __COLLABREATE_GUI_H__
#define __COLLABREATE_GUI_H__

#include "idanet.hpp"
#include "buffer.h"
#include "collabreate.h"

ssize_t getGpid(unsigned char *gpid, int sz);
void setGpid(unsigned char *gpid, int sz);
bool getFileMd5(unsigned char *md5, int len);

int do_choose_command();
bool do_project_select(Buffer &b);
void do_project_rejoin(void);
void do_project_leave(void);
bool do_connect(Dispatcher d);
int  do_auth(unsigned char *challenge, int challenge_len);
void sendProjectGetList(void);
void sendProjectLeave(void);
void do_get_req_perms(Buffer &b);
void do_set_req_perms(void);
void do_get_proj_perms(Buffer &b);
void do_set_proj_perms(void);
bool do_choose_perms(Buffer &b);

void showOptionsDlg(HWND parent, Options *in, Options *out, Options *mask, char * title);

extern HWND mainWindow;
extern HMODULE hModule;
extern bool publish;
extern bool subscribe;

#endif
