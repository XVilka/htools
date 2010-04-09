/*
    Asynchronous IDA communications handler
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>
    Copyright (C) 2008 Tim Vidas <tvidas at gmail d0t com>


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

#include "idanet.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <md5.h>

#include "sdk_versions.h"
#include "buffer.h"

#if IDA_SDK_VERSION < 500
#include <fpro.h>
#endif

#define SOCKET_MSG WM_USER
#define PLUGIN_NAME "collabREate"

static SOCKET conn = INVALID_SOCKET;
static HWND msg_hwnd;
static WNDPROC old_proc;
static Dispatcher dispatch;

bool is_connected() {
   return conn != INVALID_SOCKET;
}

//buffer to cache data in the case WSAEWOULDBLOCK
static Buffer sendBuf;

//how large if the current data packet under construction
int requiredSize(Buffer &b) {
   if (b.size() >= (int)sizeof(int)) {
      return qntohl(*(int*)b.get_buf());
   }
   return -1;
}

//does the buffer containa a complete data packet?
bool isComplete(Buffer &b) {
   int rs = requiredSize(b);
   return rs > 0 && b.size() >= rs;
}

//shift the content of a buffer left by one data packet
void shift(Buffer &b) {
   if (isComplete(b)) {
      unsigned int rs = requiredSize(b);
      unsigned int extra = b.size() - rs;
      const unsigned char *buf = b.get_buf();
      b.reset();
      if (extra) {
         b.write(buf + rs, extra);
      }
   }
}

//shift the content of a buffer left by len bytes
void shift(Buffer &b, int len) {
   if (len <= b.size()) {
      int extra = b.size() - len;
      const unsigned char *buf = b.get_buf();
      b.reset();
      if (extra) {
         b.write(buf + len, extra);
      }
   }
}

/*
 * socket_callback()
 *
 * this is the proc handler we register with our invisible window for hooking the
 * socket notification messages.
 *
 * returns:   boolean value representing success or failure.
 */
BOOL CALLBACK socket_callback(HWND hWnd, UINT message, WPARAM wparam, LPARAM lparam) {
   if (message == SOCKET_MSG) {
      if (WSAGETSELECTERROR(lparam)) {
         msg(PLUGIN_NAME": connection to server severed at WSAGETSELECTERROR %d.\n", WSAGetLastError());
         cleanup(true);
         return FALSE;
      }
      switch(WSAGETSELECTEVENT(lparam)) {
         case FD_READ:   //receiving data.
            //msg(PLUGIN_NAME": receiving data.\n");
            if (dispatch) {
               static Buffer b;
               char buf[2048];  //read a large chunk, we'll be notified if there is more
               int len = recv(conn, buf, sizeof(buf), 0);
               //connection closed.
               if (len <= 0) {
                  cleanup();
                  msg(PLUGIN_NAME": Socket read failed. connection closed. %d\n", WSAGetLastError());
                  return false;
               }
               //msg(PLUGIN_NAME": received: %d bytes \n", len);
               b.write(buf, len);   //copy new data into static buffer
               //now dispatch any complete data packets to user dispatcher
               //it is important to understand that the recv above may receive 
               //partial data packets
               //if (isComplete(b)) {
               //      msg(PLUGIN_NAME": b is complete.\n");
               //}
               //else {
               //      msg(PLUGIN_NAME": b is not compelete.\n");
               //}
               while (isComplete(b)) {
                  Buffer data(b.get_buf() + sizeof(int), requiredSize(b) - sizeof(int));
                  //msg("dispatching a %d sized buffer (expected %d out of %d)\n", data.size(), requiredSize(b) - sizeof(int), b.size());
                  if (!(*dispatch)(data)) {  //not sure we really care what is returned here
                     msg(PLUGIN_NAME": connection to server severed at dispatch.\n");
                     cleanup(true);
                     break;
                  }
                  else {
                     //msg(PLUGIN_NAME": dispatch routine called successfully.\n");
                  }
                  shift(b);  //shift any remaining portions of the buffer to the front
               }
            }
            break;
         case FD_WRITE: {   //sending data.
            //msg(PLUGIN_NAME": writing data.\n");
            if (sendBuf.size() == 0) break;  //nothing to send
            int len = send(conn, (const char*)sendBuf.get_buf(), sendBuf.size(), 0);
            //remember, send is not guaranteed to send complete buffer
            if (len == SOCKET_ERROR) {
               int error = WSAGetLastError();
               if (error != WSAEWOULDBLOCK) {
                  cleanup(true);
               }
            }
            else if (len != sendBuf.size()) {
               //partial read, so shift remainder of buffer to front
               shift(sendBuf, (unsigned int)len);
               //msg(PLUGIN_NAME": wrote: %d bytes \n", len);
            }
            else {
               //entire buffer was sent, so clear the buffer
               sendBuf.reset();
               //msg(PLUGIN_NAME": wrote: %d bytes \n", len);
            }
            break;
         }
         case FD_CLOSE:  //server connection closed.
            cleanup(true);
            msg(PLUGIN_NAME": connection to server severed at FD_CLOSE.\n");
            break;
      }
   }
   return FALSE;
}

/////////////////////////////////////////////////////////////////////////////////////////
//cleanup(bool warn)
//
//cancel all notifications, close the socket and destroy the hook notification window.
//
//arguments: warn true displays a warning that cleanup is being called, false no warning
//returns:   none.
//
void cleanup(bool warn) {
   //cancel all notifications. if we don't do this ida will crash on exit.
   msg(PLUGIN_NAME": cleanup called.\n");
   if (conn != INVALID_SOCKET) {
      if (msg_hwnd) {
         WSAAsyncSelect(conn, msg_hwnd, 0, 0);
         dispatch = NULL;
      }
      closesocket(conn);
      conn = INVALID_SOCKET;
      if (warn) {
         warning("Connection to collabREate server has been closed.\n"
                 "You should reconnect to the server before sending\n"
                 "additional updates.");
      }
   }
}

//connect to a remote host as specified by host and port
//host may be wither an ip address or a host name
SOCKET connect_to(const char *host, short port) {
   SOCKET sock;
   sockaddr_in server;
   memset(&server, 0, sizeof(server));
   server.sin_family = AF_INET;
   server.sin_addr.s_addr = inet_addr(host);
   server.sin_port = htons(port);

   //If a domain name was specified, we may not have an IP.
   if (server.sin_addr.s_addr == INADDR_NONE) {
      hostent *he = gethostbyname(host);
      if (he == NULL) {
         msg(PLUGIN_NAME": Unable to resolve name: %s\n", host);
         return INVALID_SOCKET;
      }
      server.sin_addr = *(in_addr*) he->h_addr;
   }

   //create a socket.
   if ((sock = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET) {
      if (connect(sock, (sockaddr *) &server, sizeof(server)) == SOCKET_ERROR) {
         msg(PLUGIN_NAME": Failed to connect to server.\n");
         closesocket(sock);
         sock = INVALID_SOCKET;
      }
   }
   else {
      msg(PLUGIN_NAME": Failed to create socket.\n");
   }
      
   return sock;
}

//create a window for the async socket, this window
//receives the WM_xxx messages associated with the socket
bool createSocketWindow(SOCKET s, Dispatcher d) {
   //create a message handling window for the async socket.
   msg_hwnd = CreateWindowEx(0, "STATIC", PLUGIN_NAME, 0, 0, 0, 0, 0, HWND_MESSAGE, 0, 0, 0);
   if (msg_hwnd == NULL) {
      msg(PLUGIN_NAME": CreateWindowEx() failed.\n");
      return false;
   }
   
   //register the callback function for our invisible window.
   old_proc = (WNDPROC)SetWindowLong(msg_hwnd, GWL_WNDPROC, (long) socket_callback);
   if (old_proc == 0) {
      killWindow();
      msg(PLUGIN_NAME": SetWindowLong() failed.\n");
      return false;
   }

   conn = s;
   dispatch = d;
   
   //make the socket a non-blocking asynchronous socket hooked with our socket_callback handler.
   if (WSAAsyncSelect(conn, msg_hwnd, SOCKET_MSG, FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR) {
      killWindow();
      dispatch = NULL;
      conn = INVALID_SOCKET;
      msg(PLUGIN_NAME": Failed to create asynchronous connection to server.\n");
      return false;
   }
   //asynchronous socket properly configured
   #if DEBUG 
      msg(PLUGIN_NAME": Successfully configured async socket\n");
   #endif
   return true;
}

//array to track send and receive stats for all of the collabreate commands
extern int stats[2][256];

//Send a buffer of data
int send_data(Buffer &b) {
   if (conn == INVALID_SOCKET) return 0;   //silently fail
   Buffer out;
   int sz = b.size() + sizeof(int);
   out.writeInt(sz);
   int command = b.readInt();
   stats[1][command]++;
   out << b;
   int len = send(conn, (const char*)out.get_buf(), out.size(), 0);
   if (len == SOCKET_ERROR) {
      int error = WSAGetLastError();
      if (error == WSAEWOULDBLOCK) {
         sendBuf << out;
         return 0;
      }
      else {
         cleanup();
         killWindow();
         msg(PLUGIN_NAME": Failed to send requested data. %d != %d. Error: %x, %d\n", len, out.size(), error, error);
         return -1;
      }
   }
   else if (len != out.size()) {
      //move the remainder into sendBuf
      shift(out, len);
      sendBuf << out;
      //msg(PLUGIN_NAME": Short send. %d != %d.", len, out.size());
   }
   return len;
}

void killWindow() {
   if (msg_hwnd) {
      DestroyWindow(msg_hwnd);
      msg_hwnd = NULL;
   }
}

bool init_network() {
#ifdef __NT__
   //initialize winsock.
   WSADATA wsock;
   if (WSAStartup(MAKEWORD(2, 2), &wsock) != 0) {
      msg(PLUGIN_NAME": init_network() failed.\n");
      return false;
   }

   //check requested version
   if (LOBYTE(wsock.wVersion) != 2 || HIBYTE(wsock.wVersion) != 2) {
      WSACleanup();
      msg(PLUGIN_NAME": Winsock version 2.2 not found.\n");
      return false;
   }
#endif
   return true;
}

bool term_network() {
#ifdef __NT__
   killWindow();
   return WSACleanup() == 0;
#else
   //non-Windows need no initialization
   return true;
#endif
}
