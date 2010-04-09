#include "stdafx.h"
#include "stopwatch.h"

CStopWatch::CStopWatch(void)
{
	dwStartTime = dwEndTime = 0;
}

CStopWatch::~CStopWatch(void)
{
}

void CStopWatch::Start()
{
	dwStartTime = GetTickCount();
	return;
}

void CStopWatch::Stop()
{
	dwEndTime = GetTickCount();
	return;
}

DWORD CStopWatch::GetMSeconds()
{
	if ( !dwStartTime || !dwEndTime )
		return 0; // ERR

	return (dwEndTime - dwStartTime);
}

DWORD CStopWatch::GetSeconds()
{
	if ( !dwStartTime || !dwEndTime )
		return 0; // ERR

	return (dwEndTime - dwStartTime) / 1000;
}

DWORD CStopWatch::GetMinutes()
{
	if ( !dwStartTime || !dwEndTime )
		return 0; // ERR

	return (dwEndTime - dwStartTime) / 60000;
}

DWORD CStopWatch::GetTimeMSeconds()
{
	if ( !dwStartTime || !dwEndTime )
		return 0; // ERR

	return (dwEndTime - dwStartTime) % 1000;
}

DWORD CStopWatch::GetTimeSeconds()
{
	if ( !dwStartTime || !dwEndTime )
		return 0; // ERR

	return ((dwEndTime - dwStartTime) / 1000) % 60;
}

DWORD CStopWatch::GetTimeMinutes()
{
	if ( !dwStartTime || !dwEndTime )
		return 0; // ERR

	return (dwEndTime - dwStartTime) / 60000;
}
