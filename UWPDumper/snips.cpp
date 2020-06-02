//----------------------------------------------------------------------------------
void IterateThreads(ThreadCallback ThreadProc, std::uint32_t ProcessID, void* Data)
{
	void* hSnapShot = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,
		ProcessID);

	if (hSnapShot == INVALID_HANDLE_VALUE)
		return;

	THREADENTRY32 ThreadEntry = { 0 };
	ThreadEntry.dwSize = sizeof(THREADENTRY32);
	Thread32First(hSnapShot, &ThreadEntry);
	do
	{
		if( ThreadEntry.th32OwnerProcessID == ProcessID )
		{
			if (ThreadProc(ThreadEntry.th32ThreadID, Data) == false)
				break;
		}
	}
	while (Thread32Next(hSnapShot, &ThreadEntry));

	CloseHandle(hSnapShot);
}
