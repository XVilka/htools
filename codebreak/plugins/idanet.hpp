/*
    Asynchronous IDA communications handler
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

#ifndef __IDACONNECTOR_H__
#define __IDACONNECTOR_H__

#define WINVER 0x5000

#define DEBUG 0 

#include <windows.h>
#include <winsock.h>
#include <pro.h>
#include "buffer.h"

typedef bool (*Dispatcher)(Buffer &b);

void killWindow();
bool init_network();
bool term_network();

SOCKET connect_to(const char *host, short port);

bool is_connected();
int send_data(Buffer &b);

void cleanup(bool warn = false);

#ifndef __NT__
typedef int SOCKET
#define closesocket close
#endif

bool createSocketWindow(SOCKET s, Dispatcher d);

#endif
