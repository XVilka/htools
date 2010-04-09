#pragma once

#include <windows.h>

class CStopWatch
{
public:
	CStopWatch(void);
	~CStopWatch(void);

	void    Start();
	void    Stop();

	DWORD   GetMSeconds();
	DWORD   GetSeconds();
	DWORD   GetMinutes();

	DWORD   GetTimeMSeconds();
	DWORD   GetTimeSeconds();
	DWORD   GetTimeMinutes();

private:
	DWORD  dwStartTime, dwEndTime;
};
