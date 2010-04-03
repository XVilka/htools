/*
   Source for collabreate IdaPro plugin
   File: buffer.cpp
   Copyright (c) 2005,2006 Chris Eagle
   
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
 * this file was derived from similar code in the ida-x86emu project
 */

#include <string.h>
#include <pro.h>
#include <kernwin.hpp>
#include "buffer.h"

#define BLOCK_SIZE 0x100   //keep this a power of two

Buffer::Buffer() {
   init(BLOCK_SIZE);
}

Buffer::Buffer(const void *data, unsigned int len) {
   init(len);
   write(data, len);
}

void Buffer::init(unsigned int size) {
   bptr = (unsigned char *)qalloc(size);
   sz = bptr ? size : 0;
   rptr = 0;
   wptr = 0;
   error = bptr == NULL;
}

Buffer::~Buffer() {
   qfree(bptr);
}

void Buffer::append(Buffer &b) {
   write(b.bptr, b.wptr);
}

Buffer &Buffer::operator<<(Buffer &b) {
   append(b);
   return *this;
}

bool Buffer::read(void *data, unsigned int len) {
   if ((rptr + len) <= wptr) {
      memcpy(data, bptr + rptr, len);
      rptr += len;
      return true;
   }
   error = true;
   return false;
}

unsigned long long Buffer::readLong() {
   unsigned long long val = 0;
   int *p = (int*)&val;
   p[1] = readInt();
   p[0] = readInt();
   //msg("Buffer::readLong p[0] is %08.8x, and p[1] is %08.8x\n", p[0], p[1]);
   return val;
}

int Buffer::readInt() {
   int val = 0;
   read(&val, sizeof(val));
   return qntohl(val);
}

short Buffer::readShort() {
   short val = 0;
   read(&val, sizeof(val));
   return qntohs(val);
}

unsigned char Buffer::read() {
   unsigned char val = 0;
   read(&val, sizeof(val));
   return val;
}

//This does not adhere strictly to the UTF8 encoding standard
//this is more like pascal style 16-bit length + content strings
char *Buffer::readUTF8() {   //must qfree this
   unsigned short len = readShort();
   char *str = NULL;
   if (!error) {
      str = (char*)qalloc(len + 1);
      if (str && read(str, len)) {
         str[len] = 0;
      }
      else {
         qfree(str);
         str = NULL;
      }
   }
   return str;
}

bool Buffer::rewind(unsigned int amt) {
   if (rptr >= amt) {
      rptr -= amt;
      return true;
   }
   return false;
}

bool Buffer::reset() {
   rptr = 0;
   wptr = 0;
   error = false;
   return true;
}

bool Buffer::write(const void *data, unsigned int len) {
   if (!check_size(wptr + len)) {
      memcpy(bptr + wptr, data, len);
      wptr += len;
      return true;
   }
   error = true;
   return false;
}

bool Buffer::writeLong(unsigned long long val) {
   int *p = (int*)&val;
   writeInt(p[1]);
   return writeInt(p[0]);
}

bool Buffer::writeInt(int val) {
   val = qhtonl(val);
   return write(&val, sizeof(val));
}

bool Buffer::writeShort(int val) {
   short s = (short)val;
   s = qhtons(s);
   return write(&s, sizeof(s));
}

bool Buffer::write(int val) {
   char c = (char)val;
   return write(&c, sizeof(c));
}

//This does not adhere strictly to the UTF8 encoding standard
//this is more like pascal style 16-bit length + content strings
bool Buffer::writeUTF8(const char *data) {
   unsigned short len = data ? strlen(data) : 0;
   if (writeShort(len)) {
      return write(data, len);
   }
   return false;
}

//write a null termianted string as a null terminated
//wdie character (16-bit) string
bool Buffer::writeWide(const char *data) {
   short val = 0;
   do {
      val = *data++;
      if (!write(&val, sizeof(val))) return false;
   } while (val);
   return true;
}

const unsigned char *Buffer::get_buf() {
//   *(int*)bptr = qhtonl(wptr);
   return bptr;
}

int Buffer::check_size(unsigned int max) {
   if (max <= sz) return 0;
   max = (max + BLOCK_SIZE) & ~(BLOCK_SIZE - 1);   //round up to next BLOCK_SIZE
   unsigned char *tmp = (unsigned char *)qrealloc(bptr, max);
   if (tmp) {
      bptr = tmp;
      sz = max;
      return 0;
   }
   error = true;
   return 1;
}
