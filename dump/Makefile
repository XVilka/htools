# In this string we need to use -D__SOME__ command for define which platform we use
# And C preprocessor use only code for platform, we defined
# For example if we use Texas Instruments OMAP 3430 - we should use
# EXTRA_CFLAGS += -D__PLAT_TI_OMAP3430__

KERNEL_SOURCES = $(HOME)/Documents/android/hack/kernel-mi

EXTRA_CFLAGS += -D__PLAT_TI_OMAP3430__ -Wall -march=armv7-a -mtune=cortex-a8 -mfpu=neon

obj-m += mtd-dumpall.o mtd-hack.o

all:
	make -C $(KERNEL_SOURCES) M=$(PWD) modules

clean:
	make -C $(KERNEL_SOURCES) M=$(PWD) clean
	rm -f *.order
