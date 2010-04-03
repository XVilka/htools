#Set this variable to point to your SDK directory
IDA=../../

#Set this variable to the desired name of your compiled loader
PROC=collabreate

ifndef __LINUX__
PLATFORM_CFLAGS=-D__NT__ -D__IDP__ -mno-cygwin
PLATFORM_LDFLAGS=-mno-cygwin
IDALIB=$(shell find ../../ -type d -name \*gcc.w32 | grep lib)/ida.a
PLUGIN_EXT=.plw
RESOURCES=collabreate.res
else
PLATFORM_CFLAGS=-D__LINUX__
IDALIB=$(shell find ../../ -type d -name \*gcc32.lnx | grep lib)/pro.a
PLUGIN_EXT=.plx
endif

#Platform specific compiler flags
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS)

#Platform specific ld flags
LDFLAGS=-Wl -shared -s $(PLATFORM_LDFLAGS) 

#specify any additional libraries that you may need
EXTRALIBS=-lws2_32 -lgdi32

# Destination directory for compiled plugins
OUTDIR=$(IDA)bin/plugins/

#list out the object files in your project here
OBJS=collabreate.o collabreate_ui.o collabreate_options_dlg.o idanet.o buffer.o $(RESOURCES)

BINARY=$(OUTDIR)$(PROC)$(PLUGIN_EXT)

all: $(OUTDIR) $(BINARY)

clean:
	-@rm *.o
	-@rm $(BINARY)

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

CC=g++
INC=-I$(IDA)include/

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

RC=windres

$(F)%.res: %.rc
	$(RC) -O coff $< $@

LD=g++

$(BINARY): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(IDALIB) $(EXTRALIBS) 

#change collabreate below to the name of your plugin, make sure to add any 
#additional files that your plugin is dependent on
collabreate.o: collabreate.cpp idanet.hpp buffer.h
collabreate_ui.o: collabreate_ui.cpp collabreate_ui.hpp idanet.hpp
collabreate_options_dlg.cpp: collabreate.h collabreate_ui.hpp buffer.h
idanet.o: idanet.cpp idanet.hpp buffer.h
buffer.o: buffer.cpp buffer.h
collabreate.res: collabreate.rc
