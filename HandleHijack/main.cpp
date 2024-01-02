#include "Nt.h"
#include <string>
#include <atlconv.h>
SYSTEM_HANDLE_INFORMATION* t_SYSTEM_HANDLE_INFORMATION;
HANDLE Source_Process = NULL;
HANDLE target_handle = NULL;
HANDLE p_HANDLE = NULL;
DWORD GetProcessIdByName(std::string ProcessName)
{
	PROCESSENTRY32 ProcessInfoPE;
	ProcessInfoPE.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(15, 0);
	Process32First(hSnapshot, &ProcessInfoPE);
	USES_CONVERSION;
	do {
		if (strcmp(W2A(ProcessInfoPE.szExeFile), ProcessName.c_str()) == 0)
		{
			CloseHandle(hSnapshot);
			return ProcessInfoPE.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &ProcessInfoPE));
	CloseHandle(hSnapshot);
	return 0;
}
int main() {
	DWORD ProcessId = GetProcessIdByName("cs2.exe");

	auto ObjectAttributes = [](UNICODE_STRING_Ptr ObjectName, HANDLE RootDirectory, ULONG Attributes, PSECURITY_DESCRIPTOR SecurityDescriptor)->_OBJECT_ATTRIBUTES {
		OBJECT_ATTRIBUTES object;
		object.Length = sizeof(OBJECT_ATTRIBUTES);
		object.Attributes = Attributes;
		object.RootDirectory = RootDirectory;
		object.SecurityDescriptor = SecurityDescriptor;
		object.ObjectName = ObjectName;
		return object;
	};

	FUNC_RtlAdjustPrivilege f_RtlAdjustPrivilege = (FUNC_RtlAdjustPrivilege)GetProcAddress(GetModuleHandleA("ntdll"), "RtlAdjustPrivilege");
	FUNC_NtDuplicateObject f_NtDuplicateObject = (FUNC_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll"), "NtDuplicateObject");
	FUNC_NtOpenProcess f_NtOpenProcess = (FUNC_NtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenProcess");
	FUNC_NtQuerySystemInformation f_NtQuerySystemInformation = (FUNC_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");

	_OBJECT_ATTRIBUTES R_Attributes = ObjectAttributes(NULL, NULL, NULL, NULL);
	CLIENT_ID t_CLIENT_ID = { 0 };
	boolean OldPriv;

	f_RtlAdjustPrivilege(20, TRUE, FALSE, &OldPriv);

	DWORD Sizeof_SYSTEM_HANDLE_INFORMATION = sizeof(SYSTEM_HANDLE_INFORMATION);

	NTSTATUS NTAPIReturn = NULL;
	do {
		delete[] t_SYSTEM_HANDLE_INFORMATION;

		Sizeof_SYSTEM_HANDLE_INFORMATION *= 1.5;

		try
		{
			t_SYSTEM_HANDLE_INFORMATION = (PSYSTEM_HANDLE_INFORMATION) new byte[Sizeof_SYSTEM_HANDLE_INFORMATION];
		}
		catch (std::bad_alloc)
		{

			printf("[-] Bad Alloc!");
			break;
		}
		Sleep(1);

	} while ((NTAPIReturn = f_NtQuerySystemInformation(16, t_SYSTEM_HANDLE_INFORMATION, Sizeof_SYSTEM_HANDLE_INFORMATION, NULL)) == (NTSTATUS)0xC0000004);

	if (!NT_SUCCESS(NTAPIReturn))
	{
		printf("[-] NtQuerySystemInformation return: 0x%x", NTAPIReturn);
	}

	for (int i = 0; i < t_SYSTEM_HANDLE_INFORMATION->HandleCount; ++i) {
		static int n = i;
		if (n > 100) {
			printf("[-] Out of HANDLE Range");
			break;
		}

		if (t_SYSTEM_HANDLE_INFORMATION->Handles[i].ProcessId == 4) //Pid 4 = System
			continue;

		if (t_SYSTEM_HANDLE_INFORMATION->Handles[i].ObjectTypeNumber != 0x7)
			continue;
		if ((HANDLE)t_SYSTEM_HANDLE_INFORMATION->Handles[i].Handle == INVALID_HANDLE_VALUE)
			continue;

		t_CLIENT_ID.UniqueProcess = (DWORD*)t_SYSTEM_HANDLE_INFORMATION->Handles[i].ProcessId;

		NTAPIReturn = f_NtOpenProcess(&Source_Process, PROCESS_DUP_HANDLE, &R_Attributes, &t_CLIENT_ID);

		if (Source_Process == INVALID_HANDLE_VALUE || !NT_SUCCESS(NTAPIReturn))
			continue;
		NTAPIReturn = f_NtDuplicateObject(Source_Process, (HANDLE)t_SYSTEM_HANDLE_INFORMATION->Handles[i].Handle, (HANDLE)(LONG_PTR)-1, &target_handle, PROCESS_ALL_ACCESS, 0, 0);

		if (target_handle == INVALID_HANDLE_VALUE || !NT_SUCCESS(NTAPIReturn))
			continue;

		if (GetProcessId(target_handle) == ProcessId) {
			p_HANDLE = target_handle;
			delete[] t_SYSTEM_HANDLE_INFORMATION;
			break;
		}
		else
		{
			CloseHandle(target_handle);
			CloseHandle(Source_Process);
			continue;
		}
	}

	if (p_HANDLE != INVALID_HANDLE_VALUE)
		printf("[+] Success! HANDLE:%p", p_HANDLE);
	else
		printf("[-] Failed to GetHandle!");
	

}