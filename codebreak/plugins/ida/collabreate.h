/*
    IDA Pro Collabreation/Synchronization Plugin
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
#ifndef __COLLABREATE_H__
#define __COLLABREATE_H__

#define PLUGIN_NAME "collabREate"

#define DEBUG                        0 

#define PROTOCOL_VERSION             1 

#define COMMAND_BYTE_PATCHED         1
#define COMMAND_CMT_CHANGED          2
#define COMMAND_TI_CHANGED           3
#define COMMAND_OP_TI_CHANGED        4
#define COMMAND_OP_TYPE_CHANGED      5
#define COMMAND_ENUM_CREATED         6
#define COMMAND_ENUM_DELETED         7
#define COMMAND_ENUM_BF_CHANGED      8
#define COMMAND_ENUM_RENAMED         9
#define COMMAND_ENUM_CMT_CHANGED     10
#define COMMAND_ENUM_CONST_CREATED   11
#define COMMAND_ENUM_CONST_DELETED   12
#define COMMAND_STRUC_CREATED        13
#define COMMAND_STRUC_DELETED        14
#define COMMAND_STRUC_RENAMED        15
#define COMMAND_STRUC_EXPANDED       16
#define COMMAND_STRUC_CMT_CHANGED    17

#define COMMAND_CREATE_STRUC_MEMBER_DATA 18
#define COMMAND_CREATE_STRUC_MEMBER_STRUCT 19
#define COMMAND_CREATE_STRUC_MEMBER_REF 20
#define COMMAND_CREATE_STRUC_MEMBER_STROFF 21
#define COMMAND_CREATE_STRUC_MEMBER_STR 22
#define COMMAND_CREATE_STRUC_MEMBER_ENUM 23

#define COMMAND_STRUC_MEMBER_DELETED 24

//#define COMMAND_STRUC_MEMBER_RENAMED
#define COMMAND_SET_STACK_VAR_NAME     25
#define COMMAND_SET_STRUCT_MEMBER_NAME 26

//#define COMMAND_STRUC_MEMBER_CHANGED
#define COMMAND_STRUC_MEMBER_CHANGED_DATA 27
#define COMMAND_STRUC_MEMBER_CHANGED_STRUCT 28
#define COMMAND_STRUC_MEMBER_CHANGED_STR 29

#define COMMAND_THUNK_CREATED        30
#define COMMAND_FUNC_TAIL_APPENDED   31
#define COMMAND_FUNC_TAIL_REMOVED    32
#define COMMAND_TAIL_OWNER_CHANGED   33
#define COMMAND_FUNC_NORET_CHANGED   34
#define COMMAND_SEGM_ADDED           35
#define COMMAND_SEGM_DELETED         36
#define COMMAND_SEGM_START_CHANGED   37
#define COMMAND_SEGM_END_CHANGED     38
#define COMMAND_SEGM_MOVED           39     
#define COMMAND_AREA_CMT_CHANGED     40
#define COMMAND_STRUC_MEMBER_CHANGED_OFFSET 41
#define COMMAND_STRUC_MEMBER_CHANGED_ENUM 42
#define COMMAND_CREATE_STRUC_MEMBER_OFFSET 43

#define AREACB_FUNCS                  1
#define AREACB_SEGS                   2

#define COMMAND_IDP                 128
#define COMMAND_UNDEFINE            129
#define COMMAND_MAKE_CODE           130
#define COMMAND_MAKE_DATA           131
#define COMMAND_MOVE_SEGM           132
#define COMMAND_RENAMED             133
#define COMMAND_ADD_FUNC            134
#define COMMAND_DEL_FUNC            135
#define COMMAND_SET_FUNC_START      137
#define COMMAND_SET_FUNC_END        138
#define COMMAND_VALIDATE_FLIRT_FUNC 139
#define COMMAND_ADD_CREF            140
#define COMMAND_ADD_DREF            141
#define COMMAND_DEL_CREF            142
#define COMMAND_DEL_DREF            143

#define SERVER_MAP_TID              200
#define SERVER_RENAME_STRUCT        201


#define MSG_CONTROL_FIRST            1000
#define MSG_INITIAL_CHALLENGE        1000
#define MSG_AUTH_REQUEST             1001
#define MSG_AUTH_REPLY               1002
#define AUTH_REPLY_SUCCESS           0
#define AUTH_REPLY_FAIL              1
#define MSG_PROJECT_LIST             1003
#define MSG_PROJECT_JOIN_REQUEST     1004
#define MSG_PROJECT_JOIN_REPLY       1005   //should include gpid of the project
#define JOIN_REPLY_SUCCESS           0
#define JOIN_REPLY_FAIL              1
#define MSG_PROJECT_NEW_REQUEST      1006
#define MSG_SEND_UPDATES             1007
#define MSG_PROJECT_REJOIN_REQUEST   1008
#define MSG_ACK_UPDATEID             1009
#define MSG_PROJECT_SNAPSHOT_REQUEST 1010
#define MSG_PROJECT_SNAPSHOT_REPLY   1011
#define MSG_PROJECT_SNAPSHOT_SUCCESS 0
#define MSG_PROJECT_SNAPSHOT_FAIL    1
#define MSG_PROJECT_FORK_REQUEST     1012
#define MSG_PROJECT_SNAPFORK_REQUEST 1013
#define MSG_PROJECT_FORK_FOLLOW      1014
#define MSG_PROJECT_LEAVE            1015
#define MSG_GET_REQ_PERMS            1016
#define MSG_GET_REQ_PERMS_REPLY      1017
#define MSG_SET_REQ_PERMS            1018
#define MSG_SET_REQ_PERMS_REPLY      1019
#define MSG_GET_PROJ_PERMS           1020
#define MSG_GET_PROJ_PERMS_REPLY     1021
#define MSG_SET_PROJ_PERMS           1022
#define MSG_SET_PROJ_PERMS_REPLY     1023

#define MSG_ERROR                    1100
#define MSG_FATAL                    1101

class netnode;
extern netnode cnn;

#define COLLABREATE_NETNODE "$ COLLABREATE NETNODE"

#define COLLABREATE_ENUMS_TAG 'E'
#define COLLABREATE_STRUCTS_TAG 'T'

#define GPID_SUPVAL 1
#define LAST_SERVER_SUPVAL 2
#define LAST_USER_SUPVAL 3
#define LASTUPDATE_SUPVAL 4
#define OPTIONS_SUPVAL 5

#define LASTUPDATE_ALTVAL 1
#define LAST_PORT_ALTVAL 2

#define CHALLENGE_SIZE 32
#define GPID_SIZE 32

#define MD5_LEN 16

#define NEW_PROJECT_INDEX 0

//User commands available via plugin activate, once connected to a server
#define USER_FORK       0
#define USER_CHECKPOINT 1
#define USER_PERMS      2
#define PROJECT_PERMS   3
#define USER_DISCONNECT 4
#define SHOW_NETNODE    5
#define CLEAN_NETNODE   6

struct Options {
   unsigned long long pub;
   unsigned long long sub;
};

bool setUserOpts(Options &user);
bool getUserOpts(Options &user);

#endif
