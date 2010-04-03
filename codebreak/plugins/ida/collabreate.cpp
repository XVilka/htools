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
/*
 *  This is the collabREate plugin
 *
 *  It is known to compile with
 *
 *   Microsoft Visual C++
 *   cygwin g++/make
 *
 */

#include "idanet.hpp"
#include "collabreate_ui.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <area.hpp>
#include <frame.hpp>
#include <segment.hpp>
#include <enum.hpp>
#include <xref.hpp>
#include <nalt.hpp>
#include <offset.hpp>

#include "sdk_versions.h"
#include "collabreate.h"

static bool authenticated = false;
static bool fork_pending = false;

static bool isHooked = false;
void hookAll();
void unhookAll();
bool msg_dispatcher(Buffer &);

//where we stash collab specific infoze
netnode cnn(COLLABREATE_NETNODE, 0, true);

//Linked list of datagrams
struct PacketNode {
   Buffer *buf;
   PacketNode *next;

   PacketNode(Buffer &b);
};

PacketNode::PacketNode(Buffer &b) : next(NULL) {
   //need to duplicate the buffer because b may get destroyed
   buf = new Buffer();
   buf->append(b);
}

static PacketNode *updatesHead, *updatesTail;

/**
 * empty the pending updates queue with no additional action
 * this is usually done following a successful fork
 */
void clearPendingUpdates() {
   PacketNode *n;
   while (updatesHead) {
      n = updatesHead->next;
      delete updatesHead->buf;
      updatesHead = n;
   }
   updatesTail = NULL;
}

/**
 * Flush pending updates to database.
 * this is usually done following a failed fork when the
 * user elects to continue with the current project
 */
void flushPendingUpdates() {
   PacketNode *n;
   while (updatesHead) {
      n = updatesHead->next;
      msg_dispatcher(*(updatesHead->buf));
      delete updatesHead->buf;
      updatesHead = n;
   }
   updatesTail = NULL;
}

/**
 * Add an update packete to the pending updates queue
 */
void queueUpdate(Buffer &b) {
   if (updatesTail) {
      updatesTail->next = new PacketNode(b);
      updatesTail = updatesTail->next;
   }
   else {
      updatesHead = updatesTail = new PacketNode(b);
   }
}

//Caution: returns a pointer to a static string
char *formatLongLong(unsigned long long val) {
   static char buf[24];
   unsigned int *p = (unsigned int *)&val;
   qsnprintf(buf, sizeof(buf), "%08.8x%08.8x", p[1], p[0]);
   return buf;
}

//Save the user options bits into our netnode
bool setUserOpts(Options &user) {
   return cnn.supset(OPTIONS_SUPVAL, &user, sizeof(Options));
}

//Load the user options bits from our netnode
bool getUserOpts(Options &user) {
   return cnn.supval(OPTIONS_SUPVAL, &user, sizeof(Options));
}

//Load the last update id from our netnode
unsigned long long getLastUpdate() {
   unsigned long long val;
   cnn.supval(LASTUPDATE_SUPVAL, &val, sizeof(val));
   //msg(PLUGIN_NAME":lastupdate supval is 0x%s\n", formatLongLong(val));
   return val;
}

//localize writes to LASTUPDATE_SUPVAL to a single function 
void writeUpdateValue(unsigned long long uid) {
   cnn.supset(LASTUPDATE_SUPVAL, &uid, sizeof(uid));
}

//Save an update id only if it is larger than the most recently saved id
void setLastUpdate(unsigned long long uid) {
   if (uid > getLastUpdate()) {
      //msg(PLUGIN_NAME": ## setting last update to 0x%s ## \n", formatLongLong(uid));
      writeUpdateValue(uid);
   }
}

//Make sure our netnode exists
void initNetNode(void) {
   writeUpdateValue(0);
}

/*
 * This function recurses through all calls made by a known library function
 * and flags them as library functions as well under the premise that library
 * functions only call other library functions.
 */
void recursive_update(func_t *f) {
   if (f == NULL || f->flags & FUNC_LIB) return;
   f->flags |= FUNC_LIB;
   update_func(f);
   func_item_iterator_t fi(f);
   do {
      ea_t ea = fi.current();
      
      xrefblk_t xb;
      for (bool ok = xb.first_from(ea, XREF_FAR); ok && xb.iscode; ok = xb.next_from()) {
         if (xb.type != fl_CN && xb.type != fl_CF) continue;
         func_t *pfn = get_func(xb.to);
         recursive_update(pfn);
      }
   } while (fi.next_code());
}

//array that holds counters of all the commands that have been sent and
//received in the current session
int stats[2][256];

/*
 * Handle idp notifications received remotely
 */
bool handle_idp_msg(Buffer &b, int command) {
   char *name;
   ea_t ea = 0;
   size_t sz;
   int val, len;
   bool rep;
   struc_t *stk_frame;
   
   //
   // handle the received command appropriately.
   //
   switch(command) {
      case COMMAND_UNDEFINE: {
         ea = b.readInt();
#if IDA_SDK_VERSION >= 510         
         do_unknown(ea, DOUNK_SIMPLE);
#else
         do_unknown(ea, false);
#endif
         break;
      }
      case COMMAND_MAKE_CODE: {
         ea = b.readInt();
         sz = b.readInt();
         ua_code(ea);
         break;
      }
      case COMMAND_MAKE_DATA: {
         ea = b.readInt();
         flags_t f = b.readInt();
         asize_t a = b.readInt();
         name = b.readUTF8();
         tid_t t = (name && *name) ? get_struc_id(name) : BADNODE;
         qfree(name);
         do_data_ex(ea, f, a, t);
         break;
      }
      case COMMAND_MOVE_SEGM: {
         ea = b.readInt();
         segment_t *s = getseg(ea);
         ea_t new_start = b.readInt();
         move_segm(s, new_start);
         break;
      }
      case COMMAND_RENAMED: {
         ea = b.readInt();
         int flag = b.read() ? SN_LOCAL : 0;
         name = b.readUTF8();
         if (name) {
            set_name(ea, name, flag | SN_NOWARN);
         }
         qfree(name);
         break;
      }
      case COMMAND_ADD_FUNC: {
         ea = b.readInt();
         ea_t end = b.readInt();
         if (b.has_error()) {
            //old form, didn't get a start and end address
            add_func(ea, BADADDR);
         }
         else {
            //new form, got start and end addresses
            add_func(ea, end);
         }
         break;
      }
      case COMMAND_DEL_FUNC: {
         ea = b.readInt();
         del_func(ea);
         break;
      }
      case COMMAND_SET_FUNC_START: {
         ea = b.readInt();
         ea_t newstart = b.readInt();
         func_setstart(ea, newstart);
         break;
      }
      case COMMAND_SET_FUNC_END: {
         ea = b.readInt();
         ea_t newend = b.readInt();
         func_setend(ea, newend);
         break;
      }
      case COMMAND_VALIDATE_FLIRT_FUNC: {
         ea = b.readInt();
         name = b.readUTF8();
         if (name) {
            set_name(ea, name, SN_NOWARN);
         }
         ea_t end = b.readInt();
         if (b.has_error()) {
            //old form, didn't get a start and end address
            add_func(ea, BADADDR);
         }
         else {
            //new form, got start and end addresses
            add_func(ea, end);
         }
         func_t *f = get_func(ea);
         if (f) {
            //any function this calls is also a library (support) function
            recursive_update(f);
         }
         qfree(name);
         break;
      }
      case COMMAND_ADD_CREF: {
         // args: ea_t from, ea_t to, cref_t type
         ea_t from = b.readInt();
         ea_t to = b.readInt();
         cref_t type = (cref_t)b.readInt();
         add_cref(from, to, type);
         break;
      }
      case COMMAND_ADD_DREF: {
         // args: ea_t from, ea_t to, dref_t type
         ea_t from = b.readInt();
         ea_t to = b.readInt();
         dref_t type = (dref_t)b.readInt();
         add_dref(from, to, type);
         break;
      }
      case COMMAND_DEL_CREF: {
         // args: ea_t from, ea_t to, bool expand
         ea_t from = b.readInt();
         ea_t to = b.readInt();
         bool expand = b.read();
         del_cref(from, to, expand);
         break;
      }
      case COMMAND_DEL_DREF: {
         // args: ea_t from, ea_t to
         ea_t from = b.readInt();
         ea_t to = b.readInt();
         del_dref(from, to);
         break;
      }
      default:
         msg(PLUGIN_NAME": Received unknown command code: %d, ignoring.\n", command);
   }
   return true;
}

/*
 * Handle idb notifications received remotely
 */
bool handle_idb_msg(Buffer &b, int command) {
   ea_t ea = 0;
   size_t sz;
   int val;
   bool rep;
   struc_t *stk_frame;
   //
   // handle the received command appropriately.
   //
   switch(command) {
      case COMMAND_BYTE_PATCHED: {
         ea = b.readInt();
         val = b.readInt();
         patch_byte(ea, val);
         break;
      }
      case COMMAND_CMT_CHANGED: {
         ea = b.readInt();
         rep = b.read() ? 1 : 0;
         char *cmt = b.readUTF8();
//         msg(PLUGIN_NAME":read comment %s\n", cmt);
         if (cmt) {
            set_cmt(ea, cmt, rep);
         }
         qfree(cmt);
         break;
      }
      case COMMAND_TI_CHANGED: {
         ea_t ea = b.readInt();
         const type_t *ti = (const uchar*)b.readUTF8();
         const p_list *fnames = (const uchar*)b.readUTF8();
#if IDA_SDK_VERSION >= 520
         set_tinfo(ea, ti, fnames);
#else
         set_ti(ea, ti, fnames);
#endif
         qfree((void*)ti);
         qfree((void*)fnames);
         break;
      }
      case COMMAND_OP_TI_CHANGED: {
         ea_t ea = b.readInt();
         int n = b.readInt();
         const type_t *ti = (const uchar*)b.readUTF8();
         const p_list *fnames = (const uchar*)b.readUTF8();
#if IDA_SDK_VERSION >= 520
         set_op_tinfo(ea, n, ti, fnames);
#else
         set_op_ti(ea, n, ti, fnames);
#endif
         qfree((void*)ti);
         qfree((void*)fnames);
         break;
      }
      case COMMAND_OP_TYPE_CHANGED: {
         ea_t ea = b.readInt();
         int n = b.readInt();
         flags_t f = b.readInt();
         if (isOff(f, n)) {
            op_offset(ea, n, REF_OFF32);
         }
         else if (isEnum(f, n)) {
            //this is a protocol addition so we need to check whether
            //the appropriate extra fields are present
            char *ename = b.readUTF8();
            if (ename != NULL) {
               uchar serial = b.read();
               enum_t id = get_enum(ename);
               op_enum(ea, n, id, serial);
               qfree(ename);
            }
         }
         else if (isStroff(f, n)) {
            //this is a protocol addition so we need to check whether
            //the appropriate extra fields are present
            int path_len = b.readInt();
            if (!b.has_error()) {
               adiff_t delta = b.readInt();
               tid_t *path = (tid_t*) qalloc(path_len * sizeof(tid_t));
               for (int i = 0; i < path_len; i++) {
                  char *sname = b.readUTF8();
                  path[i] = get_struc_id(sname);
                  qfree(sname);
               }
               op_stroff(ea, n, path, path_len, delta);
               qfree(path);
            }
         }
         else {
            set_op_type(ea, f, n);
         }
         break;
      }
      case COMMAND_ENUM_CREATED: {
         char *ename = b.readUTF8();
         add_enum(BADADDR, ename, 0);
         //Perhaps should report tid to server in case it is renamed???
         //server maintains tid map
         qfree(ename);
         break;
      }
      case COMMAND_ENUM_DELETED: {
         char *ename = b.readUTF8();
         enum_t id = get_enum(ename);
         del_enum(id);
         qfree(ename);
         break;
      }
      case COMMAND_ENUM_BF_CHANGED: {
         //******
         break;
      }
      case COMMAND_ENUM_RENAMED: {
         char localname[MAXNAMESIZE];
         char *newname = b.readUTF8();
         char *oldname = b.readUTF8();
         if (oldname) {
            for (nodeidx_t n = cnn.sup1st(COLLABREATE_ENUMS_TAG); 
                    n != BADNODE; n = cnn.supnxt(n, COLLABREATE_ENUMS_TAG)) {
               cnn.supstr(n, localname, sizeof(localname), COLLABREATE_ENUMS_TAG);
               if (strcmp(localname, oldname) == 0) {
                  cnn.supset(n, newname, 0, COLLABREATE_ENUMS_TAG);
                  set_struc_name(n, newname);
                  break;
               }
            }
            qfree(oldname);
         }
         qfree(newname);
         break;
      }
      case COMMAND_ENUM_CMT_CHANGED: {
         char *name = b.readUTF8();
         char *cmt = b.readUTF8();
         enum_t id = get_enum(name);
         set_enum_cmt(id, cmt, false);
         qfree(name);
         qfree(cmt);
         break;
      }
      case COMMAND_ENUM_CONST_CREATED: {
         uval_t value = b.readInt();
         char *ename = b.readUTF8();
         char *mname = b.readUTF8();
         enum_t id = get_enum(ename);
         add_const(id, mname, value);
         qfree(ename);
         qfree(mname);
         break;
      }
      case COMMAND_ENUM_CONST_DELETED: {
         uval_t value = b.readInt();
         bmask_t bmask = b.readInt();
         uchar serial = b.read();
         char *ename = b.readUTF8();
         enum_t id = get_enum(ename);
         del_const(id, value, serial, bmask);
         qfree(ename);
         break;
      }
      case COMMAND_STRUC_CREATED: {
         //Perhaps should report tid to server in case it is renamed???
         //server maintains tid map
         tid_t s1 = b.readInt();   //read the tid (this is actually not used)
         bool is_union = (bool)b.read();
         char *sname = b.readUTF8();
         tid_t s2 = add_struc(BADADDR, sname, is_union);

         //remember the name of the struct in case it is renamed later
         cnn.supset(s2, sname, 0, COLLABREATE_STRUCTS_TAG);
//         msg(PLUGIN_NAME": received COMMAND_STRUC_CREATED message for %s\n", sname);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_DELETED: {
         char *name = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         del_struc(s);
         qfree(name);
         break;
      }
      case COMMAND_STRUC_RENAMED: {
         char localname[MAXNAMESIZE];
         tid_t t = b.readInt();   //need to try to map struct id to other instances ID
         char *newname = b.readUTF8();
         char *oldname = b.readUTF8();
         if (oldname) {
            for (nodeidx_t n = cnn.sup1st(COLLABREATE_STRUCTS_TAG); 
                    n != BADNODE; n = cnn.supnxt(n, COLLABREATE_STRUCTS_TAG)) {
               cnn.supstr(n, localname, sizeof(localname), COLLABREATE_STRUCTS_TAG);
               if (strcmp(localname, oldname) == 0) {
                  cnn.supset(n, newname, 0, COLLABREATE_STRUCTS_TAG);
                  set_struc_name(n, newname);
                  break;
               }
            }
            qfree(oldname);
         }
         qfree(newname);
         break;
      }
      case COMMAND_STRUC_EXPANDED: {
         tid_t s1 = b.readInt();   //send the tid to create map on the server
         char *sname = b.readUTF8();
//         msg(PLUGIN_NAME": received COMMAND_STRUC_EXPANDED message for %s\n", sname);
         //******
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_CMT_CHANGED: {
         char *name = b.readUTF8();
         tid_t t = get_struc_id(name);
         char *cmt = b.readUTF8();
         set_struc_cmt(t, cmt, false);
         qfree(name);
         qfree(cmt);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_DATA: {
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, NULL, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_DATA message for %s.%s, offset %d\n", name, mbr, soff);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_STRUCT: {
         char *ti_name = b.readUTF8();
         typeinfo_t ti;
         ti.tid = get_struc_id(ti_name);
         unsigned long p = b.readInt();    //props
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send typeinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STRUCT message for %s.%s (%s)\n", name, mbr, ti_name);
         qfree(ti_name);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_STR: {
         typeinfo_t ti;
         ti.strtype = b.readInt();
         unsigned long p = b.readInt();    //props
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send typeinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STR message for %s.%s\n", name, mbr);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_ENUM: {
         char *ti_name = b.readUTF8();
         typeinfo_t ti;
         ti.ec.tid = get_struc_id(ti_name);
         ti.ec.serial = b.read();
         unsigned long p = b.readInt();    //props
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send typeinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STRUCT message for %s.%s (%s)\n", name, mbr, ti_name);
         qfree(ti_name);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_OFFSET: {
         typeinfo_t ti;
         b.read(&ti.ri, sizeof(refinfo_t));
         unsigned long p = b.readInt();    //props
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send typeinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_OFFSET message for %s.%s (%s)\n", name, mbr, ti_name);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_STRUC_MEMBER_DELETED: {
         ea_t off = b.readInt();
         char *name = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         del_struc_member(s, off);
         qfree(name);
         break;
      }
      case COMMAND_SET_STACK_VAR_NAME: {
         ea = b.readInt();  //lookup function on remote side
         stk_frame = get_frame(ea);
         ea_t soff = b.readInt();
         char *name = b.readUTF8();
         if (name) {
            set_member_name(stk_frame, soff, name);
         }
         qfree(name);
         break;
      }
      case COMMAND_SET_STRUCT_MEMBER_NAME: {
         ea_t soff = b.readInt();
         char *sname = b.readUTF8();
         char *mname = b.readUTF8();
         if (sname && mname) {
            struc_t *struc = get_struc(get_struc_id(sname));
            set_member_name(struc, soff, mname);
//            msg(PLUGIN_NAME": received COMMAND_SET_STRUCT_MEMBER_NAME message for %s.%s\n", sname, mname);
         }
         qfree(sname);
         qfree(mname);
      }
      case COMMAND_STRUC_MEMBER_CHANGED_DATA: {
//         tid_t s1 = b.readInt();   //send the tid to create map on the server
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t flags = b.readInt();
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, flags, NULL, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_DATA message for %s.%s\n", sname, mname);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_STRUCT: {
         char *ti_name = b.readUTF8();
         typeinfo_t ti;
         ti.tid = get_struc_id(ti_name);
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send typeinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STRUCT message for %s.%d (%s)\n", sname, soff, ti_name);
         qfree(ti_name);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_STR: {
         typeinfo_t ti;
         ti.strtype = b.readInt();
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send typeinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STR message for %s.%d\n", sname, soff);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_OFFSET: {
         typeinfo_t ti;
         b.read(&ti, sizeof(refinfo_t));
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send typeinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STR message for %s.%d\n", sname, soff);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_ENUM: {
         char *ti_name = b.readUTF8();
         typeinfo_t ti;
         ti.ec.tid = get_struc_id(ti_name);
         ti.ec.serial = b.read();
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send typeinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STRUCT message for %s.%d (%s)\n", sname, soff, ti_name);
         qfree(ti_name);
         qfree(sname);
         break;
      }
      case COMMAND_THUNK_CREATED: {
         ea_t startEA = b.readInt();
         func_t *f = get_func(startEA);
         if (f) {
            f->flags |= FUNC_THUNK;
            update_func(f);
         }
         break;
      }
      case COMMAND_FUNC_TAIL_APPENDED: {
         ea_t startEA = b.readInt();
         func_t *f = get_func(startEA);
         ea_t tail_start = b.readInt();
         ea_t tail_end = b.readInt();
         if (f) {
            append_func_tail(f, tail_start, tail_end);
         }
         break;
      }
      case COMMAND_FUNC_TAIL_REMOVED: {
         ea_t startEA = b.readInt();
         func_t *f = get_func(startEA);
         ea_t tail = b.readInt();
         if (f) {
            remove_func_tail(f, tail);
         }
         break;
      }
      case COMMAND_TAIL_OWNER_CHANGED: {
         ea_t startEA = b.readInt();
         func_t *tail = get_func(startEA);
         ea_t owner = b.readInt();
         if (tail) {
            set_tail_owner(tail, owner);
         }
         break;
      }
      case COMMAND_FUNC_NORET_CHANGED: {
         ea_t startEA = b.readInt();
         func_t *f = get_func(startEA);
         if (f) {
            f->flags ^= FUNC_NORET;
            update_func(f);
         }
         break;
      }
      case COMMAND_SEGM_ADDED: {
         segment_t s;
         memset(&s, 0, sizeof(segment_t));
         s.startEA = b.readInt();
         s.endEA = b.readInt();
         s.orgbase = b.readInt();
         s.align= b.read();
         s.comb = b.read();
         s.perm = b.read();
         s.bitness = b.read();
         s.flags = b.readShort();
         s.color = DEFCOLOR;
         char *name = b.readUTF8();
         char *clazz = b.readUTF8();
         add_segm_ex(&s, name, clazz, ADDSEG_QUIET | ADDSEG_NOSREG);
         qfree(name);
         qfree(clazz);
         break;
      }
      case COMMAND_SEGM_DELETED: {
         ea_t ea = b.readInt();
#if IDA_SDK_VERSION >= 500
         del_segm(ea, SEGDEL_KEEP | SEGDEL_SILENT);
#else
         del_segm(ea, 0);
#endif
         break;
      }
      case COMMAND_SEGM_START_CHANGED: {
         ea_t old_end = b.readInt();
         ea_t new_start = b.readInt();
         set_segm_start(old_end, new_start, 0);
         break;
      }
      case COMMAND_SEGM_END_CHANGED: {
         ea_t old_start = b.readInt();
         ea_t new_end = b.readInt();
         set_segm_start(old_start, new_end, 0);
         break;
      }
      case COMMAND_SEGM_MOVED: {
         ea_t from = b.readInt();
         ea_t to = b.readInt();
         asize_t sz = b.readInt();
         segment_t *s = getseg(from);
         move_segm(s, to, MSF_SILENT);
         break;
      }
      case COMMAND_AREA_CMT_CHANGED: {
         unsigned char cbType = b.read();
         areacb_t *cb = NULL;
         if (cbType == AREACB_FUNCS) {
            cb = &funcs;
         }
         else if (cbType == AREACB_SEGS) {
            cb = &segs;
         }
         else {
            break;
         }
         ea_t ea = b.readInt();
         area_t *a = cb->get_area(ea);
         if (a) {  //only change comment if we found the area
            unsigned char rep = b.read();
            char *cmt = b.readUTF8();
            cb->set_area_cmt(a, cmt, rep);
            qfree(cmt);
         }
         break;
      }
      default:
         msg(PLUGIN_NAME": Received unknown command code: %d, ignoring.\n", command);
   }
   return true;
}

//Tell the server the last update that we have received so that
//it can send us all newer updates
void sendLastUpdate() {
   Buffer b;
   b.writeInt(MSG_SEND_UPDATES);
   unsigned long long last = getLastUpdate();
   msg(PLUGIN_NAME": Requesting all updates greater than %s\n", formatLongLong(last));
   b.writeLong(last);
   send_data(b);
}

//Process collabREate control messages
void handle_control_msg(Buffer &b, int command) {
   static unsigned char challenge[CHALLENGE_SIZE];
   switch (command) {
      case MSG_INITIAL_CHALLENGE: {
         #if DEBUG
           msg(PLUGIN_NAME": Recieved Auth Challenge\n");
         #endif
         if (b.read(challenge, sizeof(challenge))) {
            if (do_auth(challenge, sizeof(challenge)) != 0) {
               cleanup();         //user canceled dialog 
            }
         }
         else {
            //challenge too short
         }
         break;
      }
      case MSG_AUTH_REPLY: {
         #if DEBUG
           msg(PLUGIN_NAME": in AUTH_REPLY.\n");
         #endif
         int reply = b.readInt();
         if (reply == AUTH_REPLY_FAIL) {
            //use saved challenge from initial_challenge message
            if (do_auth(challenge, sizeof(challenge)) != 0) {
               cleanup();       //user cancelled dialog
            }
            authenticated = false;
            msg(PLUGIN_NAME": authentication failed.\n");
         }
         else {
            authenticated = true;
            msg(PLUGIN_NAME": Successfully authenticated.\n");
            unsigned char gpid[GPID_SIZE];
            ssize_t sz= getGpid(gpid, sizeof(gpid));
            if (sz > 0) {
               msg(PLUGIN_NAME": Existing project found.\n");
               do_project_rejoin();  //could pass gpid
            }
            else {
               msg(PLUGIN_NAME": Virgin idb detected.\n");
               initNetNode();
               sendProjectGetList();
            }
         }
         break;
      }
      case MSG_PROJECT_LIST: {
         #if DEBUG
            msg(PLUGIN_NAME": in PROJECT_LIST\n");
         #endif
         if (!do_project_select(b)) {
            cleanup();
         }
         break;
      }
      case MSG_PROJECT_JOIN_REPLY: {
         #if DEBUG
            msg(PLUGIN_NAME": in PROJECT_JOIN_REPLY\n");
         #endif
         int reply = b.readInt();
         if (reply == JOIN_REPLY_SUCCESS) {
            //we are joined to a project
            unsigned char gpid[GPID_SIZE];
            if (b.read(gpid, sizeof(gpid))) {
               msg(PLUGIN_NAME": Successfully joined project.\n"); 
               setGpid(gpid, sizeof(gpid));
               hookAll();
               fork_pending = false;
               clearPendingUpdates();  //delete all pending updates from previous project
               //need to send a MSG_SEND_UPDATES message
               sendLastUpdate();
            }
            else {
               msg(PLUGIN_NAME": Project join failed, server sent bad GPID.\n");
               //is this a "HARD" error condition?  without this it's impossible to re-join later
               //gpid too short
            }
         }
         else if (reply == JOIN_REPLY_FAIL) {
            //if fork_pending is true, then this is a failed fork
            //what options should we offer the user?
            msg(PLUGIN_NAME": Project join explicitly failed\n");
            hookAll();
            fork_pending = false;
            clearPendingUpdates();  //delete all pending updates from previous project
            //need to send a MSG_SEND_UPDATES message
            sendLastUpdate();
         }
         else {
            msg(PLUGIN_NAME": Project join implicitly failed\n");
         }
         break;
      }
      case MSG_PROJECT_FORK_FOLLOW: {
         #if DEBUG
            msg(PLUGIN_NAME": in PROJECT_FORK_FOLLOW\n");
         #endif
         unsigned char gpid[GPID_SIZE];
         char * user = b.readUTF8();
         b.read(gpid, sizeof(gpid));
         unsigned long long lastupdateid = b.readLong();
         char * desc = b.readUTF8(); 
         
         //check to make sure this idb is in the correct state to follow the fork
         if(lastupdateid == getLastUpdate()) {
         #if DEBUG
            msg(PLUGIN_NAME":user %s forked at 0x%s to new project: %s\n",user,formatLongLong(lastupdateid),desc);
            //msg(PLUGIN_NAME":would you like to follow the forked project? Y/N");
         #endif
            if (askbuttons_c("Yes","No","",0,"User %s forked to a new project: %s, would you like to follow?",user,desc) == 1) {
               msg(PLUGIN_NAME":join new project");
               do_project_leave();
               setGpid(gpid, sizeof(gpid));
               clearPendingUpdates();
               do_project_rejoin();  
            }
            else {
               msg(PLUGIN_NAME":staying with the current project...");
            }
         }
         else {
            msg(PLUGIN_NAME":user %s forked at 0x%s but the current ipdateid is 0x%s\n",user,formatLongLong(lastupdateid),formatLongLong(getLastUpdate()));
            msg(PLUGIN_NAME":to follow you need to re-open from the original binary and join the new project:\n");
            msg(PLUGIN_NAME": \"%s\" \n",desc);
         }    
         qfree(desc);
         qfree(user);
         break;
      }
      case MSG_GET_REQ_PERMS_REPLY: {
         #if DEBUG
            msg(PLUGIN_NAME": Got a GET_REQ_PERMS_REPLY" );
         #endif
         do_get_req_perms(b);
         break;
      }
      case MSG_SET_REQ_PERMS_REPLY: {
         #if DEBUG
            msg(PLUGIN_NAME": Got a SET_REQ_PERMS_REPLY now what?" ); //TMV
         #endif
         break;
      }
      case MSG_GET_PROJ_PERMS_REPLY: {
         #if DEBUG
            msg(PLUGIN_NAME": Got a GET_PROJ_PERMS_REPLY" );
         #endif
         do_get_proj_perms(b);
         break;
      }
      case MSG_SET_PROJ_PERMS_REPLY: {
         #if DEBUG
            msg(PLUGIN_NAME": Got a SET_PROJ_PERMS_REPLY now what?" );
         #endif
         break;
      }

      case MSG_ACK_UPDATEID: {
        //msg(PLUGIN_NAME": in ACK_UPDATEID \n");
        unsigned long long updateid = b.readLong();
        #if DEBUG
           //msg(PLUGIN_NAME": got updateid: %d \n",updateid);
        #endif
        setLastUpdate(updateid);
        break;
      }
      case MSG_AUTH_REQUEST:  //client should never receive this
      case MSG_PROJECT_JOIN_REQUEST:  //client should never receive this
      case MSG_PROJECT_NEW_REQUEST:  //client should never receive this
      case MSG_SEND_UPDATES:  //client should never receive this
      case MSG_GET_REQ_PERMS:
      case MSG_SET_REQ_PERMS:
      case MSG_GET_PROJ_PERMS:
      case MSG_SET_PROJ_PERMS:
         msg(PLUGIN_NAME": Error! Plugin recieved a server message: %d", command );
         break;
      case MSG_ERROR: {
         char *error_msg = b.readUTF8();
         msg(PLUGIN_NAME": error: %s\n", error_msg);
         qfree(error_msg);
         break;
      }
      case MSG_FATAL: {
         char *error_msg = b.readUTF8();
         msg(PLUGIN_NAME": fatal error: %s\n", error_msg);
         warning(error_msg);
         qfree(error_msg);
         authenticated = false;
         cleanup();
         break;
      }
      default: {
         msg(PLUGIN_NAME": unkown message type: 0x%x\n", command);
      }
   }
}

/*
 * Main dispatch routine for received remote notifications
 */
bool msg_dispatcher(Buffer &b) {
   int command = b.readInt();
   if (command >= MSG_CONTROL_FIRST) {
      handle_control_msg(b, command);
   }
   else if (subscribe) {
      if (fork_pending) {
         queueUpdate(b);
      }
      else {
         unsigned long long updateid = b.readLong();
         //msg(PLUGIN_NAME":Received command %d, updateid 0x%s, b.size() %d\n", command, formatLongLong(updateid), b.size());
         stats[0][command]++;
         unhookAll();
         if (command < COMMAND_IDP) {
            handle_idb_msg(b, command);
         }
         else {
            handle_idp_msg(b, command);
         }
         if (updateid) {
            //msg(PLUGIN_NAME":calling setLastUpdate with uid: %s\n", formatLongLong(updateid));
            setLastUpdate(updateid);
         }
         //msg(PLUGIN_NAME":refreshing...\n");
         // force a refresh.
         refresh_idaview_anyway();
         hookAll();
      }
   }
   return true;
}

//Given a frame pointer, determine which if any function owns it.
//This is a reverse lookup on stack frame structures
func_t *func_from_frame(struc_t *frame) {
   size_t qty = get_func_qty();
   for (size_t i = 0; i < qty; i++) {
      func_t *f = getn_func(i);
      if (f->frame == frame->id) return f;
   }
   return NULL;
}

void comment_changed(ea_t ea, bool rep) {
   size_t sz = get_cmt(ea, rep, NULL, 0) + 1;
   char *cmt = (char*) qalloc(sz);
   if (cmt || sz == 0) {
      if (sz) {
         get_cmt(ea, rep, cmt, sz);
      }
      //send comment to server
      Buffer b;
      b.writeInt(COMMAND_CMT_CHANGED);
      b.writeInt(ea);
      b.write(&rep, 1);
      if (sz) {
         b.writeUTF8(cmt);
      }
      else {
         b.writeShort(0);   //send zero length string
      }
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on comment_changed %x, %s\n", ea, cmt);
      }
      qfree(cmt);
   }
}

void byte_patched(ea_t ea) {
   Buffer b;
   int val = get_byte(ea);
   //send value to server
   b.writeInt(COMMAND_BYTE_PATCHED);
   b.writeInt(ea);
   b.writeInt(val);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on byte_patched %x, %x\n", ea, val);
   }
}

void change_ti(ea_t ea, const type_t *type, const p_list *fnames) {
   Buffer b;
   b.writeInt(COMMAND_TI_CHANGED);
   b.writeInt(ea);
   b.writeUTF8((const char*)type);
   b.writeUTF8((const char*)fnames);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_ti %x\n", ea);
   }
}

void change_op_ti(ea_t ea, int n, const type_t *type, const p_list *fnames) {
   Buffer b;
   b.writeInt(COMMAND_OP_TI_CHANGED);
   b.writeInt(ea);
   b.writeInt(n);
   b.writeUTF8((const char*)type);
   b.writeUTF8((const char*)fnames);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_op_ti %x\n", ea);
   }
}

//lookup structure offset info about operand n at address ea and
//add the information into the provided buffer
void gatherStructOffsetInfo(Buffer &b, ea_t ea, int n) {
   char name[MAXNAMESIZE];
   tid_t path[MAXSTRUCPATH];
   adiff_t delta;
   int path_len = get_stroff_path(ea, n, path, &delta);
   b.writeInt(path_len);
   b.writeInt(delta);
   //iterate over the structure path, adding the name of each struct
   //the the provided buffer.  We pass names here rather than tid
   //because different versions of IDA may assign different tid values
   //the the same struct type
   for (int i = 0; i < path_len; i++) {
      ssize_t sz = get_struc_name(path[i], name, sizeof(name));
      b.writeUTF8(name);
   }
}

//lookup enum type info about operand n at address ea and
//add the information into the provided buffer
void gatherEnumInfo(Buffer &b, ea_t ea, int n) {
   char name[MAXNAMESIZE];
   uchar serial;
   enum_t id = get_enum_id(ea, n, &serial);
   ssize_t len = get_enum_name(id, name, sizeof(name));
   if (len > 0) {
      //We pass a name here rather than enum_t because different
      //versions of IDA may assign different enum_t values
      //the the same enum type
      b.writeUTF8(name);
      b.write(serial);
   }
}

void change_op_type(ea_t ea, int n) {
   char name[MAXNAMESIZE];
   Buffer b, extra;
   //send value to server
   flags_t f = get_flags_novalue(ea);
   if (n) {
      f = get_optype_flags1(f);
      if (isEnum1(f)) {
         //need to figure out what enum it is
         gatherEnumInfo(extra, ea, n);
      }
      else if (isStroff1(f)) {
         //need to figure out what struct it is
         gatherStructOffsetInfo(extra, ea, n);
      }
   }
   else {
      f = get_optype_flags0(f);
      if (isEnum0(f)) {
         //need to figure out what enum it is
         gatherEnumInfo(extra, ea, n);
      }
      else if (isStroff0(f)) {
         //need to figure out what struct it is
         gatherStructOffsetInfo(extra, ea, n);
      }
   }
   b.writeInt(COMMAND_OP_TYPE_CHANGED);
   b.writeInt(ea);
   b.writeInt(n);
   b.writeInt(f);
   b << extra;           //append any additional type specific info
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_op_type %x, %x, %x\n", ea, n, f);
   }
}

void create_enum(enum_t id) {
   //get enum name (and fields?) and send to server
   Buffer b;
   char name[MAXNAMESIZE];
   ssize_t sz = get_enum_name(id, name, sizeof(name));
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_CREATED);
      b.writeUTF8(name);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on create_enum %s\n", name);
      }
      cnn.supset(id, name, 0, COLLABREATE_ENUMS_TAG);
   }
}

void delete_enum(enum_t id) {
   //get enum name and send to server
   Buffer b;
   char name[MAXNAMESIZE];
   ssize_t sz = get_enum_name(id, name, sizeof(name));
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_DELETED);
      b.writeUTF8(name);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on delete_enum %s\n", name);
      }
      cnn.supdel(id, COLLABREATE_ENUMS_TAG);
   }
}

/***
 * NOT HANDLING THIS YET
 ***/
void change_enum_bf(enum_t id) {
   Buffer b;
   char name[MAXNAMESIZE];
   ssize_t sz = get_enum_name(id, name, sizeof(name));
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_BF_CHANGED);
      b.writeUTF8(name);
/*      
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on change_enum %s\n", name);
      }
*/
   }
}

void rename_enum(tid_t t) {
   Buffer b;
   char newname[MAXNAMESIZE];
   char oldname[MAXNAMESIZE];
   ssize_t sz = get_enum_name(t, newname, sizeof(newname));
   ssize_t len = cnn.supstr(t, oldname, sizeof(oldname), COLLABREATE_ENUMS_TAG);
   if (sz > 0 && len > 0) {
      b.writeInt(COMMAND_ENUM_RENAMED);
      b.writeUTF8(newname);
      b.writeUTF8(oldname);
      cnn.supset(t, newname, 0, COLLABREATE_ENUMS_TAG);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on rename_enum %s\n", newname);
      }
   }
}

void change_enum_cmt(tid_t t) {
   Buffer b;
   char name[MAXNAMESIZE];
   char cmt[MAXNAMESIZE];
   ssize_t sz = get_enum_name(t, name, sizeof(name));
   ssize_t csz = get_enum_cmt(t, false, cmt, sizeof(cmt));
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_CMT_CHANGED);
      b.writeUTF8(name);
      b.writeUTF8(cmt);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on change_enum_cmt %s\n", name);
      }
   }
}

void create_enum_member(enum_t id, const_t cid) {
   //get enum name and member name/val and send to server
   Buffer b;
   uval_t value = get_const_value(cid);
   char ename[MAXNAMESIZE];
   char mname[MAXNAMESIZE];
   get_enum_name(id, ename, MAXNAMESIZE);
   get_const_name(cid, mname, MAXNAMESIZE);
   b.writeInt(COMMAND_ENUM_CONST_CREATED);
   b.writeInt(value);
   b.writeUTF8(ename);
   b.writeUTF8(mname);
   send_data(b);
}

void delete_enum_member(enum_t id, const_t cid) {
   //get enum name and member name/val and send to server
   Buffer b;
   uval_t value = get_const_value(cid);
   bmask_t bmask = get_const_bmask(cid);
   uchar serial = get_const_serial(cid);
   char ename[MAXNAMESIZE];
   get_enum_name(id, ename, MAXNAMESIZE);
   b.writeInt(COMMAND_ENUM_CONST_DELETED);
   b.writeInt(value);
   b.writeInt(bmask);
   b.write(serial);   
   b.writeUTF8(ename);
   send_data(b);
}

void create_struct(tid_t t) {
   //get struct name (and fields?) and send to server
   Buffer b;
   char name[MAXNAMESIZE];
   ssize_t sz = get_struc_name(t, name, sizeof(name));
   if (sz > 0) {
      struc_t *s = get_struc(t);
      b.writeInt(COMMAND_STRUC_CREATED);
      b.writeInt(t);   //send the tid to create map on the server
      b.write(s->is_union());
      b.writeUTF8(name);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on create_struct %s\n", name);
      }
      //remember the name of the struct in case it is renamed later
      cnn.supset(t, name, 0, COLLABREATE_STRUCTS_TAG);
   }
}

void delete_struct(tid_t s) {
   //get struct name and send to server
   Buffer b;
   char name[MAXNAMESIZE];
   ssize_t sz = get_struc_name(s, name, sizeof(name));
   if (sz > 0) {
      b.writeInt(COMMAND_STRUC_DELETED);
      b.writeUTF8(name);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on delete_struct %s\n", name);
      }
   }
}

void rename_struct(struc_t *s) {
   //get struct name (and fields?) and send to server
   //how do we know old struct name
   Buffer b;
   char newname[MAXNAMESIZE];
   char oldname[MAXNAMESIZE];
   ssize_t sz = get_struc_name(s->id, newname, sizeof(newname));
   ssize_t len = cnn.supstr(s->id, oldname, sizeof(oldname), COLLABREATE_STRUCTS_TAG);
   if (sz > 0 && len > 0) {
      b.writeInt(COMMAND_STRUC_RENAMED);
      //tids are never guaranteed to map beween any two IDBs
      b.writeInt(s->id);   //need to try to map struct id to other instances ID
      b.writeUTF8(newname);
      b.writeUTF8(oldname);
      cnn.supset(s->id, newname, 0, COLLABREATE_STRUCTS_TAG);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on rename_struct %s\n", newname);
      }
   }
}

void expand_struct(struc_t *s) {
   //what info to send to indicate expansion?
   Buffer b;
   char name[MAXNAMESIZE];
   ssize_t sz = get_struc_name(s->id, name, sizeof(name));
   if (sz > 0) {
//      msg(PLUGIN_NAME":struct %s has been expanded\n", name);
      b.writeInt(COMMAND_STRUC_EXPANDED);
      b.writeInt(s->id);   //need to try to map struct id to other instances ID
      b.writeUTF8(name);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on rename_struct %s\n", name);
      }
   }
}

void change_struc_cmt(tid_t t) {
   Buffer b;
   char cmt[MAXNAMESIZE];
   char name[MAXNAMESIZE];
   ssize_t sz = get_struc_name(t, name, sizeof(name));
   ssize_t csz = get_struc_cmt(t, false, cmt, sizeof(cmt));
   b.writeInt(COMMAND_STRUC_CMT_CHANGED);
   b.writeUTF8(name);
   b.writeUTF8(cmt);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_struc_cmt %s\n", name);
   }
}

void create_struct_member(struc_t *s, member_t *m) {
   //get struct name and member name/offs and send to server
   Buffer b;
   typeinfo_t ti, *pti;
   char mbr[MAXNAMESIZE];
   char name[MAXNAMESIZE];

   pti = retrieve_member_info(m, &ti);
/*
   msg(PLUGIN_NAME":create_struct_member, tid %x\n", m->id);
   netnode mn(m->id);
   for (nodeidx_t i = mn.alt1st(); i != BADNODE; i = mn.altnxt(i)) {
      msg(PLUGIN_NAME":create_struct_member %x.altval[%d] == %d\n", m, i, mn.altval(i));
   }
*/   
   if (pti) {
      //in this case, we need to send the ti info in some manner
      if (isStruct(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_STRUCT);
         ssize_t tsz = get_struc_name(ti.tid, name, sizeof(name));
         b.writeUTF8(name);
      }
      else if (isASCII(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_STR);
         b.writeInt(ti.strtype);
      }

      else if (isOff0(m->flag) || isOff1(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_OFFSET);
         b.write(&ti.ri, sizeof(refinfo_t));
      }
      else if (isEnum0(m->flag) || isEnum1(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_ENUM);
         ssize_t tsz = get_struc_name(ti.ec.tid, name, sizeof(name));
         b.writeUTF8(name);
         b.write(ti.ec.serial);
      }
      else {
         //need a command to write in this case??
         //is it even possible to have refinfo_t, strpath_t, or enum_const_t here?
         msg(PLUGIN_NAME":create_struct_member at unknown typeinfo\n");
         msg(PLUGIN_NAME":create_struct_member flags = %x, props = %x\n", m->flag, m->props);
         return;  //don't know how to handle this type yet
      }
      b.writeInt(m->props);
   }
   else {
      b.writeInt(COMMAND_CREATE_STRUC_MEMBER_DATA);
   }
   
   b.writeInt(m->unimem() ? 0 : m->soff);
   b.writeInt(m->flag);
   b.writeInt(m->unimem() ? m->eoff : (m->eoff - m->soff));

   //should send typeinfo_t as well
   ssize_t ssz = get_struc_name(s->id, name, sizeof(name));
   ssize_t msz = get_member_name(m->id, mbr, sizeof(mbr));
   b.writeUTF8(name);
   b.writeUTF8(mbr);
//   msg(PLUGIN_NAME":create_struct_member %s.%s off: %d, sz: %d\n", name, mbr, m->soff, m->eoff - m->soff);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on create_struct_member %s\n", name);
   }
}

void delete_struct_member(struc_t *s, tid_t m, ea_t offset) {
   //get struct name and member name/offs and send to server
   Buffer b;
   char name[MAXNAMESIZE];
   ssize_t ssz = get_struc_name(s->id, name, sizeof(name));
//   msg(PLUGIN_NAME":delete_struct_member %s, tid %x, offset %x\n", name, m, offset);
   b.writeInt(COMMAND_STRUC_MEMBER_DELETED);
   b.writeInt(offset);
   b.writeUTF8(name);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on delete_struct_member %s\n", name);
   }
}

void rename_struct_member(struc_t *s, member_t *m) {
   //get struct name and member name/offs and send to server
   Buffer b;
   func_t *pfn = func_from_frame(s);
   if (pfn) {   
//   if (s->props & SF_FRAME) {   //SF_FRAME is only available in SDK520 and later
//      func_t *pfn = func_from_frame(s);
      //send func ea, member offset, name
      char name[MAXNAMESIZE];
      get_member_name(m->id, name, MAXNAMESIZE);
      b.writeInt(COMMAND_SET_STACK_VAR_NAME);
      b.writeInt(pfn->startEA);  //lookup function on remote side
      b.writeInt(m->soff);
      b.writeUTF8(name);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on rename_stack_member %x, %x, %s\n", pfn->startEA, m->soff, name);
      }
   }
   else {
      //send struct name and member name and offset
      char sname[MAXNAMESIZE];
      char mname[MAXNAMESIZE];
      get_struc_name(s->id, sname, MAXNAMESIZE);
      get_member_name(m->id, mname, MAXNAMESIZE);
      b.writeInt(COMMAND_SET_STRUCT_MEMBER_NAME);
      b.writeInt(m->soff);
      b.writeUTF8(sname);
      b.writeUTF8(mname);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME":send error on rename_struct_member %x, %s, %s\n", m->soff, sname, mname);
      }
   }
}

void change_struct_member(struc_t *s, member_t *m) {
   //what exactly constitutes a change? what info to send?
   //get struct name and member name/offs and send to server
   Buffer b;
   typeinfo_t ti, *pti;
   char mbr[MAXNAMESIZE];
   char name[MAXNAMESIZE];

   pti = retrieve_member_info(m, &ti);
   
   if (pti) {
      //in this case, we need to send the ti info in some manner
      if (isStruct(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_STRUCT);
         ssize_t tsz = get_struc_name(ti.tid, name, sizeof(name));
         b.writeUTF8(name);
      }
      else if (isASCII(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_STR);
         b.writeInt(ti.strtype);
      }
      else if (isOff0(m->flag) || isOff1(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_OFFSET);
         b.write(&ti.ri, sizeof(refinfo_t));
      }
      else if (isEnum0(m->flag) || isEnum1(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_ENUM);
         ssize_t tsz = get_struc_name(ti.ec.tid, name, sizeof(name));
         b.writeUTF8(name);
         b.write(ti.ec.serial);
      }
      else {
         //need a command to write in this case??
         //is it even possible to have refinfo_t, strpath_t, or enum_const_t here?
         msg(PLUGIN_NAME":change_struct_member at unknown typeinfo\n");
         msg(PLUGIN_NAME":change_struct_member flags = %x, props = %x\n", m->flag, m->props);
         
         //simply return since we don't know what to write yet.  FIX THIS
         return;
      }
   }
   else {
      b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_DATA);
   }
   
   b.writeInt(m->unimem() ? 0 : m->soff);
   b.writeInt(m->eoff);
   b.writeInt(m->flag);

   //should send typeinfo_t as well
   ssize_t ssz = get_struc_name(s->id, name, sizeof(name));
   b.writeUTF8(name);
//   msg(PLUGIN_NAME":create_struct_member %s.%s off: %d, sz: %d\n", name, mbr, m->soff, m->eoff - m->soff);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on create_struct_member %s\n", name);
   }
}

void create_thunk(func_t *pfn) {
   Buffer b;
   b.writeInt(COMMAND_THUNK_CREATED);
   b.writeInt(pfn->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on create_thunk %x\n", pfn->startEA);
   }
}

void append_func_tail(func_t *pfn, func_t *tail) {
   Buffer b;
   b.writeInt(COMMAND_FUNC_TAIL_APPENDED);
   b.writeInt(pfn->startEA);
   b.writeInt(tail->startEA);
   b.writeInt(tail->endEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on append_func_tail %x, %x\n", pfn->startEA, tail->startEA);
   }
}

void remove_function_tail(func_t *pfn, ea_t ea) {
   Buffer b;
   b.writeInt(COMMAND_FUNC_TAIL_REMOVED);
   b.writeInt(pfn->startEA);
   b.writeInt(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on remove_function_tail %x, %x\n", pfn->startEA, ea);
   }
}

void change_tail_owner(func_t *tail, ea_t ea) {
   Buffer b;
   b.writeInt(COMMAND_TAIL_OWNER_CHANGED);
   b.writeInt(tail->startEA);
   b.writeInt(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_tail_owner %x, %x\n", tail->startEA, ea);
   }
}

void change_func_noret(func_t *pfn) {
   Buffer b;
   b.writeInt(COMMAND_FUNC_NORET_CHANGED);
   b.writeInt(pfn->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_func_noret %d\n", pfn->startEA);
   }
}

void add_segment(segment_t *seg) {
   Buffer b;
   char name[MAXNAMESIZE];
   char clazz[MAXNAMESIZE];
   b.writeInt(COMMAND_SEGM_ADDED);
   b.writeInt(seg->startEA);
   b.writeInt(seg->endEA);
   b.writeInt(seg->orgbase);
   b.write(seg->align);
   b.write(seg->comb);
   b.write(seg->perm);
   b.write(seg->bitness);
   b.writeShort(seg->flags);
   get_segm_name(seg, name, sizeof(name));
   b.writeUTF8(name);
   get_segm_class(seg, clazz, sizeof(clazz));
   b.writeUTF8(clazz);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on add_segment %d\n", seg->startEA);
   }
}

void del_segment(ea_t ea) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_DELETED);
   b.writeInt(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on del_segment %d\n", ea);
   }
}

void change_seg_start(segment_t *seg) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_START_CHANGED);
   b.writeInt(seg->endEA);     //old end
   b.writeInt(seg->startEA);   //new start
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_seg_start\n");
   }
}

void change_seg_end(segment_t *seg) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_END_CHANGED);
   b.writeInt(seg->startEA);     //old start
   b.writeInt(seg->endEA);   //new end
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_seg_end\n");
   }
}

void move_segment(ea_t from, ea_t to, asize_t sz) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_MOVED);
   b.writeInt(from);
   b.writeInt(to);
   b.writeInt(sz);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on move_segment\n");
   }
}

void change_area_comment(areacb_t *cb, const area_t *a, const char *cmt, bool rep) {
   Buffer b;
   int cbType = 0;
   if (cb == &funcs) {
      cbType = AREACB_FUNCS;
   }
   else if (cb == &segs) {
      cbType = AREACB_SEGS;
   }
   else {
      msg(PLUGIN_NAME":unknown areacb_t in change_area_comment\n");
      return;
   } 
   b.writeInt(COMMAND_AREA_CMT_CHANGED);
   b.write(cbType);
   b.writeInt(a->startEA);
   b.write(&rep, 1);
   b.writeUTF8(cmt);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on change_area_comment %x, %s\n", a->startEA, cmt);
   }
}

//notification hook function for idb notifications
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
int idaapi idb_hook(void *user_data, int notification_code, va_list va) {
   if (!publish) {
      //should only be called if we are publishing
      return 0;
   }
   switch (notification_code) {
      case idb_event::byte_patched: {          // A byte has been patched                      
                                               // in: ea_t ea                                  
         ea_t ea = va_arg(va, ea_t);
         byte_patched(ea);
         break;
      }
      case idb_event::cmt_changed: {           // An item comment has been changed             
                                               // in: ea_t ea, bool repeatable_cmt             
         ea_t ea = va_arg(va, ea_t);
         bool rep = (bool)va_arg(va, int);
         comment_changed(ea, rep);
         break;
      }
      case idb_event::ti_changed: {            // An item typestring (c/c++ prototype) has been changed
                                               // in: ea_t ea, const type_t *type, const p_list *fnames
         ea_t ea = va_arg(va, ea_t);
         const type_t *type = va_arg(va, const type_t*);
         const p_list *fnames = va_arg(va, const p_list*);
         change_ti(ea, type, fnames);
         break;
      }
      case idb_event::op_ti_changed: {          // An operand typestring (c/c++ prototype) has been changed
                                                // in: ea_t ea, int n, const type_t *type, const p_list *fnames
         ea_t ea = va_arg(va, ea_t);
         int n = va_arg(va, int);
         const type_t *type = va_arg(va, const type_t*);
         const p_list *fnames = va_arg(va, const p_list*);
         change_op_ti(ea, n, type, fnames);
         break;
      }
      case idb_event::op_type_changed: {       // An operand type (offset, hex, etc...) has been changed
                                               // in: ea_t ea, int n                           
         ea_t ea = va_arg(va, ea_t);
         int n = va_arg(va, int);
         change_op_type(ea, n);
         break;
      }
      case idb_event::enum_created: {          // A enum type has been created                 
                                               // in: enum_t id                                
         enum_t id = va_arg(va, enum_t);
         create_enum(id);
         break;
      }
      case idb_event::enum_deleted: {          // A enum type has been deleted                 
                                               // in: enum_t id                                
         enum_t id = va_arg(va, enum_t);
         delete_enum(id);
         break;
      }
      case idb_event::enum_bf_changed: {       // A enum type 'bitfield' attribute has been cha
                                               // in: enum_t id                                
         enum_t id = va_arg(va, enum_t);
         change_enum_bf(id);
         break;
      }
      case idb_event::enum_renamed: {          // A enum or member has been renamed            
                                               // in: tid_t id                                 
         tid_t t = va_arg(va, tid_t);
         rename_enum(t);
         break;
      }
      case idb_event::enum_cmt_changed: {      // A enum or member type comment has been change
                                               // in: tid_t id                                 
         tid_t t = va_arg(va, tid_t);
         change_enum_cmt(t);
         break;
      }
      case idb_event::enum_const_created: {    // A enum member has been created               
                                               // in: enum_t id: const_t cid                   
         enum_t id = va_arg(va, enum_t);
         const_t cid = va_arg(va, const_t);
         create_enum_member(id, cid);
         break;
      }
      case idb_event::enum_const_deleted: {    // A enum member has been deleted               
                                               // in: enum_t id: const_t cid                   
         enum_t id = va_arg(va, enum_t);
         const_t cid = va_arg(va, const_t);
         delete_enum_member(id, cid);
         break;
      }
      case idb_event::struc_created: {         // A new structure type has been created        
                                               // in: tid_t struc_id                           
         tid_t t = va_arg(va, tid_t);
         create_struct(t);
         break;
      }
      case idb_event::struc_deleted: {         // A structure type has been deleted            
                                               // in: tid_t struc_id                           
         tid_t t = va_arg(va, tid_t);
         delete_struct(t);
         break;
      }
      case idb_event::struc_renamed: {         // A structure type has been renamed            
                                               // in: struc_t *sptr                            
         struc_t *struc = va_arg(va, struc_t*);
         rename_struct(struc);
         break;
      }
      case idb_event::struc_expanded: {        // A structure type has been expanded/shrank    
                                               // in: struc_t *sptr                            
         struc_t *struc = va_arg(va, struc_t*);
         expand_struct(struc);
         break;
      }
      case idb_event::struc_cmt_changed: {     // A structure type comment has been changed    
                                               // in: tid_t struc_id                           
         tid_t t = va_arg(va, tid_t);
         change_struc_cmt(t);
         break;
      }
      case idb_event::struc_member_created: {  // A structure member has been created          
                                               // in: struc_t *sptr, member_t *mptr            
         struc_t *struc = va_arg(va, struc_t*);
         member_t *m = va_arg(va, member_t*);
         create_struct_member(struc, m);
         break;
      }
      case idb_event::struc_member_deleted: {  // A structure member has been deleted          
                                               // in: struc_t *sptr, tid_t member_id           
         struc_t *struc = va_arg(va, struc_t*);
         tid_t t = va_arg(va, tid_t);
         ea_t offs = va_arg(va, ea_t);
         delete_struct_member(struc, t, offs);
         break;
      }
      case idb_event::struc_member_renamed: {  // A structure member has been renamed          
                                               // in: struc_t *sptr, member_t *mptr      
         //this receives notifications for stack frames, structure names for
         //stack frames look like  "$ frN"  where N varies by function      
         struc_t *struc = va_arg(va, struc_t*);
         member_t *m = va_arg(va, member_t*);
         rename_struct_member(struc, m);
         break;
      }
      case idb_event::struc_member_changed: {  // A structure member has been changed          
                                               // in: struc_t *sptr, member_t *mptr            
         struc_t *struc = va_arg(va, struc_t*);
         member_t *m = va_arg(va, member_t*);
         change_struct_member(struc, m);
         break;
      }
      case idb_event::thunk_func_created: {    // A thunk bit has been set for a function      
                                               // in: func_t *pfn                              
         func_t *pfn = va_arg(va, func_t*);
         create_thunk(pfn);
         break;
      }
      case idb_event::func_tail_appended: {    // A function tail chunk has been appended      
                                               // in: func_t *pfn, func_t *tail                
         func_t *pfn = va_arg(va, func_t*);
         func_t *tail = va_arg(va, func_t*);
         append_func_tail(pfn, tail);
         break;
      }
      case idb_event::func_tail_removed: {     // A function tail chunk has been removed       
                                               // in: func_t *pfn, ea_t tail_ea                
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         remove_function_tail(pfn, ea);
         break;
      }
      case idb_event::tail_owner_changed: {    // A tail chunk owner has been changed          
                                               // in: func_t *tail, ea_t owner_func            
         func_t *tail = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         change_tail_owner(tail, ea);
         break;
      }
      case idb_event::func_noret_changed: {    // FUNC_NORET bit has been changed              
                                               // in: func_t *pfn                              
         func_t *pfn = va_arg(va, func_t*);
         change_func_noret(pfn);
         break;
      }
      case idb_event::segm_added: {            // A new segment has been created               
                                               // in: segment_t *s                             
         segment_t *seg = va_arg(va, segment_t*);
         add_segment(seg);
         break;
      }
      case idb_event::segm_deleted: {          // A segment has been deleted                   
                                               // in: ea_t startEA                             
         ea_t ea = va_arg(va, ea_t);
         del_segment(ea);
         break;
      }
      case idb_event::segm_start_changed: {    // Segment start address has been changed       
                                               // in: segment_t *s                             
         segment_t *seg = va_arg(va, segment_t*);
         change_seg_start(seg);
         break;
      }
      case idb_event::segm_end_changed: {      // Segment end address has been changed         
                                               // in: segment_t *s                             
         segment_t *seg = va_arg(va, segment_t*);
         change_seg_end(seg);
         break;
      }
      case idb_event::segm_moved: {            // Segment has been moved                       
                                               // in: ea_t from, ea_t to, asize_t size         
         ea_t ea = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         asize_t sz = va_arg(va, asize_t);
         move_segment(ea, to, sz);
         break;
      }
#if IDA_SDK_VERSION >= 530
      case idb_event::area_cmt_changed: {
         // in: areacb_t *cb, const area_t *a, const char *cmt, bool repeatable
         areacb_t *cb = va_arg(va, areacb_t*);
         const area_t *a = va_arg(va, const area_t*);
         const char *cmt = va_arg(va, const char*);
         bool rep = (bool)va_arg(va, int);
         change_area_comment(cb, a, cmt, rep);
         break;
      }
#endif
   }
   return 0;
}
#endif  //IDA_SDK_VERSION >= 510

void idp_undefine(ea_t ea) {
   //send address to server
   Buffer b;
   b.writeInt(COMMAND_UNDEFINE);
   b.writeInt(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on undefine %x\n", ea);
   }
}

void idp_make_code(ea_t ea, asize_t len) {
   //send address and length to server
   //send address to server
   Buffer b;
   b.writeInt(COMMAND_MAKE_CODE);
   b.writeInt(ea);
   b.writeInt(len);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on make_code %x, %d\n", ea, len);
   }
}

void idp_make_data(ea_t ea, flags_t f, tid_t t, asize_t len) {
   //send all to server
   Buffer b;
   char name[MAXNAMESIZE];
   b.writeInt(COMMAND_MAKE_DATA);
   b.writeInt(ea);
   b.writeInt(f);
   b.writeInt(len);
   if (t != BADNODE) {
      get_struc_name(t, name, sizeof(name));
      b.writeUTF8(name);
   }
   else {
      b.writeUTF8("");
   }
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on make_data %x, %x, %x, %d\n", ea, f, t, len);
   }
}

void idp_move_segm(ea_t ea, segment_t *seg) {
   Buffer b;
   b.writeInt(COMMAND_MOVE_SEGM);
   b.writeInt(ea);
   b.writeInt(seg->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on move_segm %x, %x\n", ea, seg->startEA);
   }
}

void idp_renamed(ea_t ea, const char *new_name, bool is_local) {
   //send all to server
   Buffer b;
   char name[3 * sizeof(int) + 1 + MAXNAMESIZE];
   ssize_t sz = strlen(new_name);
   b.writeInt(COMMAND_RENAMED);
   b.writeInt(ea);
   b.write(&is_local, 1);
   b.writeUTF8(new_name);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on rename %x, %s, %d\n", ea, new_name, is_local);
   }
}

void idp_add_func(func_t *pfn) {
   //send start, end address, name, flags (bp etc), purged, locals, delta, args
   Buffer b;
   b.writeInt(COMMAND_ADD_FUNC);
   b.writeInt(pfn->startEA);
   b.writeInt(pfn->endEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on add_func %x\n", pfn->startEA);
   }
}

void idp_del_func(func_t *pfn) {
   //send start, end address, name, flags (bp etc), purged, locals, delta, args
   Buffer b;
   b.writeInt(COMMAND_DEL_FUNC);
   b.writeInt(pfn->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on del_func %x\n", pfn->startEA);
   }
}

void idp_set_func_start(func_t *pfn, ea_t ea) {
   //send pfn->startEA and ea to server
   Buffer b;
   b.writeInt(COMMAND_SET_FUNC_START);
   b.writeInt(pfn->startEA);
   b.writeInt(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on set_func_start %x, %x\n", pfn->startEA, ea);
   }
}

void idp_set_func_end(func_t *pfn, ea_t ea) {
   //send pfn->startEA and ea to server
   Buffer b;
   b.writeInt(COMMAND_SET_FUNC_END);
   b.writeInt(pfn->startEA);
   b.writeInt(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on set_func_end %x, %x\n", pfn->startEA, ea);
   }
}

void idp_validate_flirt(ea_t ea, const char *name) {
   //send ea and name to server, apply name and set library func flag on remote side
   Buffer b;
   b.writeInt(COMMAND_VALIDATE_FLIRT_FUNC);
   b.writeInt(ea);
   b.writeUTF8(name);
   func_t *f = get_func(ea);
   if (f) {
      b.writeInt(f->endEA);
   }
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on validate_flirt %x, %s\n", ea, name);
   }
}

void idp_add_cref(ea_t from, ea_t to, cref_t type) {
   Buffer b;
   b.writeInt(COMMAND_ADD_CREF);
   b.writeInt(from);
   b.writeInt(to);
   b.writeInt(type);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on add_cref %x, %x, %x\n", from, to, type);
   }
}

void idp_add_dref(ea_t from, ea_t to, dref_t type) {
   Buffer b;
   b.writeInt(COMMAND_ADD_DREF);
   b.writeInt(from);
   b.writeInt(to);
   b.writeInt(type);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on add_dref %x, %x, %x\n", from, to, type);
   }
}

void idp_del_cref(ea_t from, ea_t to, bool expand) {
   Buffer b;
   b.writeInt(COMMAND_DEL_CREF);
   b.writeInt(from);
   b.writeInt(to);
   b.write(expand);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on del_cref %x, %x, %x\n", from, to, expand);
   }
}

void idp_del_dref(ea_t from, ea_t to) {
   Buffer b;
   b.writeInt(COMMAND_DEL_DREF);
   b.writeInt(from);
   b.writeInt(to);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME":send error on del_dref %x, %x, %x\n", from, to);
   }
}

//notification hook function for idp notifications
int idaapi idp_hook(void *user_data, int notification_code, va_list va) {
   if (!publish) {
      //should only be called if we are publishing
      return 0;
   }
   switch (notification_code) {
      case processor_t::undefine: {
         ea_t ea = va_arg(va, ea_t);
//         msg(PLUGIN_NAME":%x undefined\n", ea);
         idp_undefine(ea);
         break;
      }
      case processor_t::make_code: {
         ea_t ea = va_arg(va, ea_t);
         asize_t len = va_arg(va, asize_t);
         idp_make_code(ea, len);
         break;
      }
      case processor_t::make_data: {
         ea_t ea = va_arg(va, ea_t);
         flags_t f = va_arg(va, flags_t);
         tid_t t = va_arg(va, tid_t);
         asize_t len = va_arg(va, asize_t);
         idp_make_data(ea, f, t, len);
         break;
      }
      case processor_t::move_segm: {
         ea_t ea = va_arg(va, ea_t);
         segment_t *seg = va_arg(va, segment_t*);
         idp_move_segm(ea, seg);
         break;
      }
#if IDA_SDK_VERSION >= 510
      case processor_t::renamed: {
         //this receives notifications for stack variables as well
         ea_t ea = va_arg(va, ea_t);
         const char *name = va_arg(va, const char *);
         bool local = (bool)va_arg(va, int);
         idp_renamed(ea, name, local);
         break;
      }
      case processor_t::add_func: {
         func_t *pfn = va_arg(va, func_t*);
         idp_add_func(pfn);
         break;
      }
      case processor_t::del_func: {
         func_t *pfn = va_arg(va, func_t*);
         idp_del_func(pfn);
         break;
      }
      case processor_t::set_func_start: {
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         idp_set_func_start(pfn, ea);
         break;
      }
      case processor_t::set_func_end: {
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         idp_set_func_end(pfn, ea);
         break;
      }
#endif
#if IDA_SDK_VERSION >= 520
      case processor_t::validate_flirt_func: {
         ea_t ea = va_arg(va, ea_t);
         const char *name = va_arg(va, const char *);
         idp_validate_flirt(ea, name);
         return 1;  //trust IDA's validation
      }
#endif
#if IDA_SDK_VERSION >= 530
      case processor_t::add_cref: {
         // args: ea_t from, ea_t to, cref_t type
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         cref_t type = (cref_t)va_arg(va, int);
         idp_add_cref(from, to, type);
         break;
      }
      case processor_t::add_dref: {
         // args: ea_t from, ea_t to, dref_t type
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         dref_t type = (dref_t)va_arg(va, int);
         idp_add_dref(from, to, type);
         break;
      }
      case processor_t::del_cref: {
         // args: ea_t from, ea_t to, bool expand
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         bool expand = (bool)va_arg(va, int);
         idp_del_cref(from, to, expand);
         break;
      }
      case processor_t::del_dref: {
         // args: ea_t from, ea_t to
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         idp_del_dref(from, to);
         break;
      }
#endif
   }   
   return 0;
}

int idaapi ui_hook(void *user_data, int notification_code, va_list va) {
   return 0;
}

//hook to all ida notification types
void hookAll() {
   if (isHooked) return;
   if (publish) { //the only reason to hook is if we are publishing
      hook_to_notification_point(HT_IDP, idp_hook, NULL);
      hook_to_notification_point(HT_UI, ui_hook, NULL);
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
      hook_to_notification_point(HT_IDB, idb_hook, NULL);
#endif
   }
   isHooked = true;
}

//unhook from all ida notification types
void unhookAll() {
   if (!isHooked) return;
   if (publish) { //the only reason to unhook is if we are publishing
      unhook_from_notification_point(HT_IDP, idp_hook, NULL);
      unhook_from_notification_point(HT_UI, ui_hook, NULL);
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
      unhook_from_notification_point(HT_IDB, idb_hook, NULL);
#endif
   }
   isHooked = false;
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void) {
   unsigned char md5[MD5_LEN];
   msg(PLUGIN_NAME":collabREate has been loaded\n");
   //while the md5 is not used here, it has the side effect of ensuring
   //that the md5 is taken at the earliest opportunity for storage in 
   //the database in the event that the original binary is deleted
   getFileMd5(md5, sizeof(md5));
   if (init_network()) {
      mainWindow = (HWND)callui(ui_get_hwnd).vptr;
      hModule = GetModuleHandle("collabreate.plw");
      return PLUGIN_KEEP;
   }
   else {
      return PLUGIN_SKIP;
   }
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void) {
   msg(PLUGIN_NAME":collabREate is being unloaded\n");
   authenticated = false;
   if (is_connected()) {
      cleanup();
   }
   unhookAll();
   term_network();
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user activates the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.

void idaapi run(int arg) {
   if (is_connected()) {
      char *desc;
      Buffer req;
      switch (do_choose_command()) {
         case USER_FORK:
            desc = askstr(HIST_CMT, "", "Please enter a forked project description");
            if (desc) {
               req.writeInt(MSG_PROJECT_FORK_REQUEST);
               req.writeLong(getLastUpdate());
               req.writeUTF8(desc);
               send_data(req);
               fork_pending = true;  //flag to temporarily disable updates
               unhookAll();  //will rehook when new project is joined
            }
            msg(PLUGIN_NAME": Fork request sent.\n");
            break;
         case USER_CHECKPOINT:
            desc = askstr(HIST_CMT, "", "Please enter a checkpoint description");
            if (desc) {
               req.writeInt(MSG_PROJECT_SNAPSHOT_REQUEST);
               req.writeLong(getLastUpdate());
               req.writeUTF8(desc);
               send_data(req);
            }
            msg(PLUGIN_NAME": Checkpoint request sent.\n");
            break;
         case USER_PERMS: {
            req.writeInt(MSG_GET_REQ_PERMS);
            send_data(req);
            //allow user to edit their requested permissions for the project
            break;
         }
         case PROJECT_PERMS: {
            req.writeInt(MSG_GET_PROJ_PERMS);
            send_data(req);
            //allow an owner to edit the default permissions for the project
            break;
         }
         #if DEBUG
         case SHOW_NETNODE: { 
            unsigned char sgpid[GPID_SIZE];
            memset( sgpid, 0, sizeof(sgpid));
            ssize_t sz= getGpid(sgpid, sizeof(sgpid));
            if (sz > 0) {
               msg(PLUGIN_NAME": Netnode gpid: ");
               unsigned char * gpidptr = sgpid;
               for(unsigned int i = 0; i < sizeof(sgpid); i++) {
                  msg("%x", *gpidptr++);
               }
               msg("\n");
               unsigned long long last = getLastUpdate();
               msg(PLUGIN_NAME": Netnode lastUpdate: %s\n", formatLongLong(last));
            }
            else {
               msg(PLUGIN_NAME": GPID not found in netnode. hrm...\n");
            }
            break;
         }
         case CLEAN_NETNODE: {
            unsigned char egpid[GPID_SIZE];
            memset( egpid, 0, sizeof(egpid));
            setGpid(egpid, sizeof(egpid)); 
            writeUpdateValue(0);
            //do_clean_netnode();  //maybe put in _ui.cpp
            break;
         }
         #endif

         case USER_DISCONNECT: {
            authenticated = false;
            msg(PLUGIN_NAME":De-activating collabREate\n");
            cleanup();
            killWindow();
            unhookAll();
            msg(PLUGIN_NAME":command   rx   tx\n");
            for (int i = 0; i < 256; i++) {
               if (stats[0][i] || stats[1][i]) {
                  msg(PLUGIN_NAME":%5d   %4d %4d\n", i, stats[0][i], stats[1][i]);
               }
            }
            break;
         }
      }
   }
   else {
      authenticated = false;
      killWindow();  //just to be safe
      memset(stats, 0, sizeof(stats));
      if (do_connect(msg_dispatcher)) {
         msg(PLUGIN_NAME": collabREate activated\n");
      }
      else {
         warning("collabREate failed to connect to server\n");
      }
   }
}

//--------------------------------------------------------------------------
//char comment[] = "This is a skeleton plugin. It doesn't do a thing.";
char *comment = NULL;
char *help = NULL;

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "collabREate";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F6";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
