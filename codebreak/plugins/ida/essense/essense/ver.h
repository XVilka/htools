#ifndef __VER_H__
#define __VER_H__

#define ESSENSE_VERSION_MAJOR                0
#define ESSENSE_VERSION_MINOR               06
#define ESSENSE_VERSION_EXTRA          ""

#define ESSENSE_VERSION_STRINGIZE(str) #str
#define ESSENSE_VERSION_STRING(num)    ESSENSE_VERSION_STRINGIZE(num)

#define ESSENSE_VERSION	              ESSENSE_VERSION_STRING(ESSENSE_VERSION_MAJOR) "."  \
				      ESSENSE_VERSION_STRING(ESSENSE_VERSION_MINOR)      \
			              ESSENSE_VERSION_EXTRA

#endif
