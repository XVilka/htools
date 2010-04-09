/*
    Collabreate GUI and communications layer
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

#include "resource.h"
#include "idanet.hpp"
#include "collabreate.h"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <md5.h>
#include <netnode.hpp>

#include "sdk_versions.h"
#include "buffer.h"

#if IDA_SDK_VERSION < 500
#include <fpro.h>
#endif

#define SOCKET_MSG WM_USER
#define PLUGIN_NAME "collabREate"

#define CB_PUBLISH_BIT 1
#define CB_SUBSCRIBE_BIT 2

HWND mainWindow;
HMODULE hModule;

bool publish  = true;
bool subscribe = true;

void showOptionsDlg(HWND parent, char **optionLabels, int numOptions, Options *in, Options *out, Options *mask);

static Dispatcher tempDispatcher;
static char username[64];
static unsigned char pwhash[16];
//global pointer to the incoming project list buffer.  Used to fill
//the project list dialog
static Buffer *projectBuffer;
//global buffer that receives the description of the project selected
//by the user.
static char description[1024];
//global array of integer project ids that map to the project 
//descriptions sent by the server.
static int *projects;
static unsigned long long *snapUpdateIDs;
static Options *optMasks;
static int numProjectsGlobal = 0;
static int isSnapShotGlobal = 0;
static int numOptionsGlobal = 0;
static char *defLabels[] = {"Undefine", "Make code", "Make data"};
static char **optLabels = defLabels;

//global used to hold user's selected project permissions
static Options userOpts;
static Options tempOpts; //temporary

/*
 * Function: hmac_md5
 */

void hmac_md5(unsigned char *msg, int msg_len, 
              unsigned char *key, int key_len,
              unsigned char *digest) {
   MD5Context ctx;
   unsigned char ipad[64];
   unsigned char opad[64];
   unsigned char tk[MD5_LEN];
   int i;
   if (key_len > 64) {
      MD5Init(&ctx);
      MD5Update(&ctx, key, key_len);
      MD5Final(tk, &ctx);
      key = tk;
      key_len = MD5_LEN;
   }
   
   /* start out by storing key in pads */
   memset(ipad, 0, sizeof(ipad));
   memcpy(ipad, key, key_len);
   memcpy(opad, ipad, sizeof(opad));
   
   /* XOR key with ipad and opad values */
   for (i = 0; i < 64; i++) {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
   }
   /*
   * perform inner MD5
   */
   MD5Init(&ctx);
   MD5Update(&ctx, ipad, 64);
   MD5Update(&ctx, msg, msg_len);
   MD5Final(digest, &ctx);
   /*
   * perform outer MD5
   */
   MD5Init(&ctx);
   MD5Update(&ctx, opad, 64);
   MD5Update(&ctx, digest, MD5_LEN);
   MD5Final(digest, &ctx);
   memset(ipad, 0, sizeof(ipad));
   memset(opad, 0, sizeof(opad));
   
}

//message handler for the server connection dialog
BOOL CALLBACK ConnectDlgProc(HWND hwndDlg, UINT message, 
                             WPARAM wParam, LPARAM lParam) { 
   char host[128];
   char sport[16];
   int port;
   switch (message) { 
      case WM_INITDIALOG: {
         port = cnn.altval(LAST_PORT_ALTVAL);
         if (port == 0) {
            port = 5042;
         }
         
         host[0] = 0;
         cnn.supstr(LAST_SERVER_SUPVAL, host, sizeof(host));

         qsnprintf(sport, sizeof(sport), "%d", port);
         SetDlgItemText(hwndDlg, IDC_SERVER, host);
         SetDlgItemText(hwndDlg, IDC_PORT, sport);
         return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
         case IDOK: {//OK Button 
            GetDlgItemText(hwndDlg, IDC_SERVER, host, sizeof(host));
            GetDlgItemText(hwndDlg, IDC_PORT, sport, sizeof(sport));
            port = atoi(sport);

            cnn.altset(LAST_PORT_ALTVAL, port);
            cnn.supset(LAST_SERVER_SUPVAL, host);

            //connect to the server.
            SOCKET conn = connect_to(host, port);
            if (conn == INVALID_SOCKET) {
               EndDialog(hwndDlg, 0);
            }            
            else if (createSocketWindow(conn, tempDispatcher)) {
               msg(PLUGIN_NAME": successfully connected to %s:%d\n", host, port);
               EndDialog(hwndDlg, 1);
            }
            else {
               closesocket(conn);
               EndDialog(hwndDlg, 0);
            }
            return TRUE; 
         }
         case IDCANCEL: //Cancel Button 
            EndDialog(hwndDlg, 0);
            return TRUE; 
         } 
   } 
   return FALSE; 
}

//message handler for the client authentication dialog
BOOL CALLBACK AuthDlgProc(HWND hwndDlg, UINT message,
                          WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG: {
         username[0] = 0;
         cnn.supstr(LAST_USER_SUPVAL, username, sizeof(username));
         SetDlgItemText(hwndDlg, IDC_USERNAME, username);
         return TRUE;
      }
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
         case IDOK: {//OK Button
            char password[64];
            GetDlgItemText(hwndDlg, IDC_USERNAME, username, sizeof(username));
            GetDlgItemText(hwndDlg, IDC_PASSWORD, password, sizeof(password));

            cnn.supset(LAST_USER_SUPVAL, username);

            int pwlen = strlen(password);

            MD5Context ctx;
            MD5Init(&ctx);
            MD5Update(&ctx, (unsigned char*)password, pwlen);
            MD5Final(pwhash, &ctx);
            memset(password, 0, sizeof(password));

            EndDialog(hwndDlg, 1);
            return TRUE;
         }
         case IDCANCEL: //Cancel Button
            EndDialog(hwndDlg, 0);
            return TRUE;
         }
   }
   return FALSE;
}

//The global projectBuffer pointer should be initialized to point to 
//the incoming buffer that contains the project list to be displayed in
//the project list dialog PRIOR to calling DialogBox
BOOL CALLBACK ProjectDlgProc(HWND hwndDlg, UINT message,
                             WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG: {
         int numProjects = projectBuffer->readInt();
         numProjectsGlobal = numProjects;
         
         projects = (int*)qalloc(numProjects * sizeof(int));
         snapUpdateIDs = (unsigned long long*)qalloc(numProjects * sizeof(unsigned long long));
         optMasks = (Options*)qalloc(numProjects * sizeof(Options));
         
         SetDlgItemText(hwndDlg, IDC_PROJECT_LIST, "");
         SetDlgItemText(hwndDlg, IDC_DESCRIPTION, "");
         //the New project is always listed as the first option
         SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_ADDSTRING, (WPARAM)0, (LPARAM)"<New project>");
         for (int i = 0; i < numProjects; i++) {
            projects[i] = projectBuffer->readInt();
            snapUpdateIDs[i] = projectBuffer->readLong();
            //if (snapUpdateIDs[i] > 0 ) {
            //   msg(PLUGIN_NAME": project %d is a snapshot\n", i+1);
            //}
            char *desc = projectBuffer->readUTF8();
            int isSnapShot = 0;
            if ( snapUpdateIDs[i] !=0 ) {
               isSnapShot = 1;
            }
            #if DEBUG
               msg(PLUGIN_NAME": %d : %d - %s (%d) ", i, projects[i], desc, isSnapShot);
            #endif
            SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_ADDSTRING, (WPARAM)0, (LPARAM)desc);
            qfree(desc);
            
            //need to read options mask for this project
            //but for now everything is enabled
            //memset(optMasks + i, 0xFF, sizeof(Options));
            optMasks[i].pub = projectBuffer->readLong();
            optMasks[i].sub = projectBuffer->readLong();
            #if DEBUG
               msg(PLUGIN_NAME": P %x  S %x \n", (unsigned int)optMasks[i].pub, (unsigned int)optMasks[i].sub);
            #endif
         }
         int numOptions = projectBuffer->readInt();
         numOptionsGlobal = numOptions;

         optLabels = (char**)qalloc(numOptions * sizeof(char*));
         for (int i = 0; i < numOptions; i++) {
            optLabels[i] = projectBuffer->readUTF8();
         }

         CheckDlgButton(hwndDlg, IDC_PUBLISH, BST_CHECKED);
         CheckDlgButton(hwndDlg, IDC_SUBSCRIBE, BST_CHECKED);
         return TRUE;
      }
      case WM_COMMAND: {
         switch (LOWORD(wParam)) {
            case IDOK: {//OK Button
               int selected = SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_GETCURSEL, 0, 0);
               if (selected != LB_ERR) {
                  if (selected != 0) {
                     if (numProjectsGlobal > 1) {
                        if (snapUpdateIDs[selected - 1] > 0) {
                           GetDlgItemText(hwndDlg, IDC_DESCRIPTION, description, sizeof(description));
                           isSnapShotGlobal = 1;
                        }
                     }
                     selected = projects[selected - 1];
                  }
                  else { // selected == 0, new project
                     GetDlgItemText(hwndDlg, IDC_DESCRIPTION, description, sizeof(description));
                  }
               }
               else {
                  selected = -1;
               }
               //there is still some value in keeping these as they limit the
               //amount of traffic the client will generate to some extent
               publish = userOpts.pub != 0;
               subscribe = userOpts.sub != 0;
               //remember these as the current options
               setUserOpts(userOpts);
//               publish = IsDlgButtonChecked(hwndDlg, IDC_PUBLISH) == BST_CHECKED;
//               subscribe = IsDlgButtonChecked(hwndDlg, IDC_SUBSCRIBE) == BST_CHECKED;
               EndDialog(hwndDlg, selected);
               return TRUE;
            }
            case IDCANCEL: { //Cancel Button
               EndDialog(hwndDlg, -1);
               return TRUE;
            }
            case IDC_PROJECT_LIST: {
               if (HIWORD(wParam) == CBN_SELCHANGE) {
                  int selected = SendDlgItemMessage(hwndDlg, IDC_PROJECT_LIST, CB_GETCURSEL, 0, 0);
                  HWND desc = GetDlgItem(hwndDlg, IDC_DESCRIPTION);
                  if (selected == 0) {   //New project
                     //enable all persmissions for new projects
                     memset(&userOpts, 0xFF, sizeof(userOpts));
                     //enable description control for new projects
                     EnableWindow(desc, TRUE);
                  }
//                  else if (numProjectsGlobal > 1) {
                  else if (numProjectsGlobal > 0) {
                     if (snapUpdateIDs[selected - 1] != 0) {
                        //enable all persmissions for new projects
                        memset(&userOpts, 0xFF, sizeof(userOpts));
                        EnableWindow(desc, TRUE);
                     }
                     else {
                        userOpts = optMasks[selected - 1];
                        EnableWindow(desc, FALSE);
                     }
                  }
                  else {
                     //unreachable?
                     msg(PLUGIN_NAME": unkown desc window state entered, please tell developers\n");
                     EnableWindow(desc, FALSE);
                  }
                  return TRUE;
               }
               break;
            }
            case IDC_OPTIONS: {
               #if DEBUG
                  msg(PLUGIN_NAME": calling showOptionsDlg\n");
               #endif
               showOptionsDlg(hwndDlg, optLabels, numOptionsGlobal, &userOpts, &userOpts, &userOpts);
               return TRUE;
            }
         }
      }
   }
   return FALSE;
}

//the order of these is important, the callback returns the ordinal of the selected string
static char *commands[] = {
   "Fork project",
   "Set checkpoint",
   "Manage requested permissions",
   "Manage project permissions (owner only)",
   #if DEBUG
      "Disconnect from server",
      "Show collab netnode",
      "Clean collab netnode"
   #else
      "Disconnect from server"
   #endif
};

BOOL CALLBACK CommandsDlgProc(HWND hwndDlg, UINT message,
                             WPARAM wParam, LPARAM lParam) {   
   switch (message) {
      case WM_INITDIALOG: {
         int num_cmds = sizeof(commands) / sizeof(commands[0]);
         for (int i = 0; i < num_cmds; i++) {
            SendDlgItemMessage(hwndDlg, IDC_COMMAND_LIST, LB_ADDSTRING, (WPARAM)0, (LPARAM)commands[i]);
         }
         return TRUE;
      }
      case WM_COMMAND: {
         switch (LOWORD(wParam)) {
            case IDOK: {//OK Button
               int selected = SendDlgItemMessage(hwndDlg, IDC_COMMAND_LIST, LB_GETCURSEL, 0, 0);
               if (selected == LB_ERR) selected = -1;
               EndDialog(hwndDlg, selected);
               return TRUE;
            }
            case IDCANCEL: { //Cancel Button
               EndDialog(hwndDlg, -1);
               return TRUE;
            }
         }
      }
   }
   return FALSE;
}

//sz should be 32 and gpid should be large enough
//returns -1 if no value exists
ssize_t getGpid(unsigned char *gpid, int sz) {
   return cnn.supval(GPID_SUPVAL, gpid, sz);
}

//sz should be 32 and gpid should be large enough
void setGpid(unsigned char *gpid, int sz) {
   cnn.supset(GPID_SUPVAL, gpid, sz);
}

bool getFileMd5(unsigned char *md5, int len) {
   if (len < MD5_LEN) {
      return false;
   }
   
#if IDA_SDK_VERSION >= 500
   retrieve_input_file_md5(md5);
#else
#define RIDX_MD5                  1302  //MD5 of the input file
   if (RootNode.supval(RIDX_MD5, md5, MD5_LEN) != MD5_LEN) {
      char buf[512];
      get_input_file_path(buf, sizeof(buf));
      FILE *f = qfopen(buf, "rb");
      if (f) {
         MD5Context ctx;
         MD5Init(&ctx);
         int len;
         while ((len = qfread(f, buf, sizeof(buf))) > 0) {
            MD5Update(&ctx, (unsigned char*)buf, len);
         }
         MD5Final(md5, &ctx);
         RootNode.supset(RIDX_MD5, md5, MD5_LEN);
         qfclose(f);
      }
      else {
         //failed to open input file
         return false;
      }
   }
#endif
   return true;
}

void do_project_rejoin() { //(unsigned char * gpid) {
   Buffer b;
   b.writeInt(MSG_PROJECT_REJOIN_REQUEST);
   unsigned char gpid[GPID_SIZE];
   if (getGpid(gpid, sizeof(gpid)) && getUserOpts(userOpts)) {
      b.write(gpid, sizeof(gpid));
      b.writeLong(userOpts.pub);
      b.writeLong(userOpts.sub);
      send_data(b);
   }
}

void sendProjectLeave ( void ) {
   Buffer b;
   b.writeInt(MSG_PROJECT_LEAVE);
   send_data(b);
}

void do_project_leave( void ) {
   sendProjectLeave();
}

//void do_clean_netnode( void ) {
//}

void sendProjectChoice(int project) {
   Buffer b;
   b.writeInt(MSG_PROJECT_JOIN_REQUEST);
   b.writeInt(project);
   b.writeLong(userOpts.pub);
   b.writeLong(userOpts.sub);
   send_data(b);
}

void sendProjectSnapFork(int project, char *desc) {
   Buffer b;
   b.writeInt(MSG_PROJECT_SNAPFORK_REQUEST);
   b.writeInt(project);
   b.writeUTF8(desc);
   b.writeLong(userOpts.pub);
   b.writeLong(userOpts.sub);
   send_data(b);
}

void sendProjectGetList() {
   Buffer b;
   b.writeInt(MSG_PROJECT_LIST);
   unsigned char md5[MD5_LEN];
   if (getFileMd5(md5, sizeof(md5))) {
      b.write(md5, sizeof(md5));
      send_data(b);
   }
}

void sendNewProjectCreate(char *description) {
   Buffer b;
   b.writeInt(MSG_PROJECT_NEW_REQUEST);
   unsigned char md5[MD5_LEN];
   if (getFileMd5(md5, sizeof(md5))) {
      b.write(md5, sizeof(md5));
      b.writeUTF8(description);
      b.writeLong(userOpts.pub);
      b.writeLong(userOpts.sub);
      send_data(b);
   }
}

void sendReqPermsChoice() {
   Buffer b;
   b.writeInt(MSG_SET_REQ_PERMS);
   b.writeLong(tempOpts.pub);
   b.writeLong(tempOpts.sub);
   send_data(b);
}

void sendProjPermsChoice() {
   Buffer b;
   b.writeInt(MSG_SET_PROJ_PERMS);
   b.writeLong(tempOpts.pub);
   b.writeLong(tempOpts.sub);
   send_data(b);
}

bool do_project_select(Buffer &b) {
   projects = NULL;
   snapUpdateIDs = NULL;
   projectBuffer = &b;
   int rval = 0;
   int index = DialogBox(hModule, MAKEINTRESOURCE(IDD_PROJECT_SELECT), mainWindow, ProjectDlgProc);

   if (index == -1) {
      #if DEBUG
         msg(PLUGIN_NAME": project select cancelled\n");
      #endif
      return false;
   }
   else if (index == NEW_PROJECT_INDEX) {
      #if DEBUG
         msg(PLUGIN_NAME": new project selected: %s\n", description);
      #endif
      sendNewProjectCreate(description);
   }
   //else if (snapUpdateIDs[index + 1] != 0) {
   else if (isSnapShotGlobal == 1) {
      #if DEBUG
         msg(PLUGIN_NAME": snapshot %d selected\n", index);
      #endif
      sendProjectSnapFork(index,description);
   }
   else {
      #if DEBUG
         msg(PLUGIN_NAME": project %d selected\n", index);
      #endif
      sendProjectChoice(index);
   }
   
   qfree(snapUpdateIDs);
   snapUpdateIDs = NULL;
   qfree(projects);
   projects = NULL;
   qfree(optMasks);
   optMasks = NULL;

   for (int i = 0; i < numOptionsGlobal; i++) {
      qfree(optLabels[i]);
   }
   qfree(optLabels);
   optLabels = NULL;

   
   return true;
}

int do_auth(unsigned char *challenge, int challenge_len) {
   int rval = 0;
   if (DialogBox(hModule, MAKEINTRESOURCE(IDD_AUTH), mainWindow, AuthDlgProc) == 1) {
      uchar hmac[16];
      hmac_md5(challenge, challenge_len, pwhash, sizeof(pwhash), hmac);
      memset(pwhash, 0, sizeof(pwhash));
      
      //connection to server successful.
      Buffer auth;
      auth.writeInt(MSG_AUTH_REQUEST);
      //send plugin protocol version
      auth.writeInt(PROTOCOL_VERSION);
      //send user name
      auth.writeUTF8(username);
      //send hmac
      auth.write(hmac, sizeof(hmac));
   
      send_data(auth);
   }
   else {
      msg(PLUGIN_NAME": authentication cancelled.\n");
      rval = 1;
   }         
   return rval;
}

bool do_connect(Dispatcher d) {
   //if we are already connected then do nothing.
   if (is_connected()) return true;

   tempDispatcher = d;
   return DialogBox(hModule, MAKEINTRESOURCE(IDD_CONNECT), mainWindow, ConnectDlgProc) == 1;
}

int do_choose_command() {
   return DialogBox(hModule, MAKEINTRESOURCE(IDD_COMMANDS), mainWindow, CommandsDlgProc);
}

bool do_choose_perms(Buffer &b) {
   #if DEBUG
      //msg(PLUGIN_NAME": in do_choose_perms");
   #endif
   Options mask;
   projectBuffer = &b;
   tempOpts.pub = projectBuffer->readLong();
   tempOpts.sub = projectBuffer->readLong();
   mask.pub = projectBuffer->readLong();
   mask.sub = projectBuffer->readLong();

   Options current = tempOpts;

   #if DEBUG
      msg(PLUGIN_NAME":  P %x  S %x \n", (unsigned int)tempOpts.pub, (unsigned int)tempOpts.sub);
   #endif

   int numOptions = projectBuffer->readInt();
   numOptionsGlobal = numOptions;

   optLabels = (char**)qalloc(numOptions * sizeof(char*));
   for (int i = 0; i < numOptions; i++) {
      optLabels[i] = projectBuffer->readUTF8();
   }
   showOptionsDlg(mainWindow, optLabels, numOptionsGlobal, &tempOpts, &tempOpts, &mask);

   for (int i = 0; i < numOptionsGlobal; i++) {
      qfree(optLabels[i]);
   }
   qfree(optLabels);
   optLabels = NULL;
   
   return memcmp(&current, &tempOpts, sizeof(Options)) != 0;
}

void do_get_req_perms(Buffer &b) {
   //display permission selection UI
   //tempOpts.pub = 0xAAAAAAAA;
   //tempOpts.sub = 0x55555555;
   if (do_choose_perms(b)) {
      sendReqPermsChoice();
   }
}

void do_get_proj_perms(Buffer &b) {
   //display permission selection UI
   //tempOpts.pub = 0xAAAAAAAA;
   //tempOpts.sub = 0x55555555;
   Options oldOpts = tempOpts;
   if (do_choose_perms(b)) {
      //only call this if perms actually changed
      sendProjPermsChoice();
   }
}
