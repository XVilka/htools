/*
   Source for x86 emulator IdaPro plugin
   File: buffer.h
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

#ifndef __BUFFER_H
#define __BUFFER_H

class Buffer {
public:
   Buffer();
   Buffer(const void *data, unsigned int len);
   ~Buffer();
   
   void append(Buffer &b);
   Buffer &operator<<(Buffer &b);
   
   bool read(void *data, unsigned int len);
   unsigned char read();
   unsigned long long readLong();
   int readInt();
   short readShort();
   char *readUTF8();   //must qfree this
   bool rewind(unsigned int amt);
   bool reset();
   bool write(const void *data, unsigned int len);
   bool writeLong(unsigned long long val);
   bool writeInt(int val);
   bool writeShort(int val);
   bool write(int val);
   bool writeUTF8(const char *data);
   bool writeWide(const char *data);
   int size() {return wptr;};
   
   const unsigned char *get_buf();
   unsigned int get_wlen() {return wptr;};
   unsigned int get_rlen() {return rptr;};
   bool has_error() {return error;};
   void reset_error() {error = false;};

private:
   Buffer(const Buffer &b) {};
   int check_size(unsigned int max);
   void init(unsigned int size);
   
   unsigned char *bptr;
   unsigned int rptr;
   unsigned int wptr;
   unsigned int sz;
   bool error;
};

#endif

