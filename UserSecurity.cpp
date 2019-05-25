#include "Type_of_data.h"
#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>
#include <sddl.h>  


using namespace std;
const wchar_t* g_PrivilegeArray[] =
{
	TEXT("SeAssignPrimaryTokenPrivilege"),
	TEXT("SeAuditPrivilege"),
	TEXT("SeBackupPrivilege"),
	TEXT("SeChangeNotifyPrivilege"),
	TEXT("SeCreateGlobalPrivilege"),
	TEXT("SeCreatePagefilePrivilege"),
	TEXT("SeCreatePermanentPrivilege"),
	TEXT("SeCreateSymbolicLinkPrivilege"),
	TEXT("SeCreateTokenPrivilege"),
	TEXT("SeDebugPrivilege"),
	TEXT("SeEnableDelegationPrivilege"),
	TEXT("SeImpersonatePrivilege"),
	TEXT("SeIncreaseBasePriorityPrivilege"),
	TEXT("SeIncreaseQuotaPrivilege"),
	TEXT("SeIncreaseWorkingSetPrivilege"),
	TEXT("SeLoadDriverPrivilege"),
	TEXT("SeLockMemoryPrivilege"),
	TEXT("SeMachineAccountPrivilege"),
	TEXT("SeManageVolumePrivilege"),
	TEXT("SeProfileSingleProcessPrivilege"),
	TEXT("SeRelabelPrivilege"),
	TEXT("SeRemoteShutdownPrivilege"),
	TEXT("SeRestorePrivilege"),
	TEXT("SeSecurityPrivilege"),
	TEXT("SeShutdownPrivilege"),
	TEXT("SeSyncAgentPrivilege"),
	TEXT("SeSystemEnvironmentPrivilege"),
	TEXT("SeSystemProfilePrivilege"),
	TEXT("SeSystemtimePrivilege"),
	TEXT("SeTakeOwnershipPrivilege"),
	TEXT("SeTcbPrivilege"),
	TEXT("SeTimeZonePrivilege"),
	TEXT("SeTrustedCredManAccessPrivilege"),
	TEXT("SeUnsolicitedInputPrivilege"),
	TEXT("SeUndockPrivilege"),
	TEXT("SeNetworkLogonRight"),
	TEXT("SeInteractiveLogonRight")
};
void show_account_rights(PSID sid);


LSA_HANDLE GetPolicyHandle(void)
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE lsahPolicyHandle;

	HMODULE hLib = LoadLibrary("Advapi32.dll");
	typedef NTSTATUS(NET_API_FUNCTION *_LsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	_LsaOpenPolicy LsaOpenPolicy = 0;
	LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(hLib, "LsaOpenPolicy");

	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	NTSTATUS ntsResult = LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_LOOKUP_NAMES,
		&lsahPolicyHandle
	);

	FreeLibrary(hLib);
	return lsahPolicyHandle;
}
PSID GetSID(WCHAR *username)
{
	DWORD dwSidLength = 0;
	DWORD dwLengthOfDomainName = 0;
	SID_NAME_USE typeOfSid;
	DWORD dwRetCode = 0;
	PSID lpSid = NULL;
	char name_of_user[150] = { 0 };
	if (username[0] >= 1040 && username[0] <= 1071)
		for (int i = 0; i < 150; i++)
		{
			if (username[i] != '\0')
				if (username[i] != ' ' && (username[i] < 48 || username[i] > 57) && (username[i] < 65 || username[i] > 90) && (username[i] < 97 || username[i] > 122))
					name_of_user[i] = username[i] - 1104;
				else if ((username[i] >= 48 && username[i] <= 57) || (username[i] >= 65 && username[i] <= 90) || (username[i] >= 97 && username[i] <= 122))
					name_of_user[i] = username[i];
				else
					name_of_user[i] = ' ';
			else 
				break;
		}
	else
		for (int i = 0; i < 150; i++)
			name_of_user[i] = username[i];
	LPTSTR lpDomainName = NULL;
	if (!LookupAccountName(
		NULL,
		name_of_user,
		NULL,
		&dwSidLength,
		NULL,
		&dwLengthOfDomainName,
		&typeOfSid))
	{
		dwRetCode = GetLastError();
		if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
		{
			lpSid = (SID*) new char[dwSidLength];
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
		}
		else
		{
			printf("Lookup account name failed.\n");
			printf("Error %d\n", dwRetCode);
			return NULL;
		}
	}
	if (!LookupAccountName(
		NULL,
		name_of_user,
		lpSid,
		&dwSidLength,
		lpDomainName,
		&dwLengthOfDomainName,
		&typeOfSid))
	{
		dwRetCode = GetLastError();
		printf("Lookup account name failed.\n");
		printf("Error %d\n", dwRetCode);
		return NULL;
	}
	return lpSid;
}
bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)
			return FALSE;
	}

	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}
void printPrivileges(WCHAR *username)
{
	DWORD dwUserBuf = 256;
	ULONG CountOfRights = 0;

	BYTE bySidBuffer[1024];
	TCHAR  lpDomainName[256];
	SID_NAME_USE typeOfSid;
	PLSA_UNICODE_STRING pUserRights;
	PSID lpSid = (PSID)bySidBuffer;

	DWORD dwSidLength = sizeof(bySidBuffer);
	DWORD dwLengthOfDomainName = sizeof(lpDomainName);
	char name_of_user[150] = { 0 };
	if (username[0] >= 1040 && username[0] <= 1071)
		for (int i = 0; i < 150; i++)
		{
			if (username[i] != '\0')
				if (username[i] != ' ' && (username[i] < 48 || username[i] > 57) && (username[i] < 65 || username[i] > 90) && (username[i] < 97 || username[i] > 122))
					name_of_user[i] = username[i] - 1104;
				else if ((username[i] >= 48 && username[i] <= 57) || (username[i] >= 65 && username[i] <= 90) || (username[i] >= 97 && username[i] <= 122))
					name_of_user[i] = username[i];
				else
					name_of_user[i] = ' ';
			else
				break;
		}
	else
		for (int i = 0; i < 150; i++)
			name_of_user[i] = username[i];

	if (!LookupAccountName(NULL, name_of_user, lpSid, &dwSidLength,
		(LPTSTR)lpDomainName, &dwLengthOfDomainName, &typeOfSid)) {
		fprintf(stderr, "Lookup account name failed: %d\n", GetLastError());
		return;
	}

	LSA_HANDLE pHandle = GetPolicyHandle();
	if (!pHandle) {

		fprintf(stderr, "Get policy handle failed: %d\n", GetLastError());
		return;
	}
	
	HMODULE hLib = LoadLibrary("Advapi32.dll");
	typedef NTSTATUS(NET_API_FUNCTION *_LsaEnumerateAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING*, PULONG);
	_LsaEnumerateAccountRights LsaEnumerateAccountRights = 0;
	LsaEnumerateAccountRights = (_LsaEnumerateAccountRights)GetProcAddress(hLib, "LsaEnumerateAccountRights");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaClose)(LSA_HANDLE);
	_LsaClose LsaClose = 0;
	LsaClose = (_LsaClose)GetProcAddress(hLib, "LsaClose");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaFreeMemory)(PVOID);
	_LsaFreeMemory LsaFreeMemory = 0;
	LsaFreeMemory = (_LsaFreeMemory)GetProcAddress(hLib, "LsaFreeMemory");

	LsaEnumerateAccountRights(pHandle, lpSid, &pUserRights, &CountOfRights);
	if (CountOfRights != 0) {
		wprintf(L"\t\tPrivileges:\n");
		for (size_t i = 0; i < CountOfRights; i++)
			wprintf(L"\t\t   %s\n", pUserRights[i].Buffer);
	}
	LsaClose(pHandle);
	LsaFreeMemory(pUserRights);
	FreeLibrary(hLib);
}
void printGroups(LPCWSTR userName)
{
	
	typedef NET_API_STATUS (NET_API_FUNCTION *_NetUserGetLocalGroups)(LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD);
	_NetUserGetLocalGroups NetUserGetLocalGroups = 0;
	HMODULE hLib = LoadLibrary("Netapi32.dll");
	NetUserGetLocalGroups = (_NetUserGetLocalGroups)GetProcAddress(hLib, "NetUserGetLocalGroups");

	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL, pTmpBuf;
	DWORD dwEntriesRead, dwTotalEntries, dwTotalCount = 0, i;

	NET_API_STATUS nStatus = NetUserGetLocalGroups(NULL,
		userName,
		0,
		LG_INCLUDE_INDIRECT,
		(LPBYTE *)&pBuf,
		MAX_PREFERRED_LENGTH,
		&dwEntriesRead,
		&dwTotalEntries);
	if (nStatus == NERR_Success) {
		if ((pTmpBuf = pBuf) != NULL) {
			for (i = 0; i < dwEntriesRead; i++) {

				if (pTmpBuf == NULL) {
					fprintf(stderr, "An access violation has occurred\n");
					break;
				}
				wprintf(L"\t\t-- %s\n", pTmpBuf->lgrui0_name);
				pTmpBuf++;
				dwTotalCount++;
			}
		}
	}
	else
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetApiBufferFree)(LPVOID);
	_NetApiBufferFree NetApiBufferFree = 0;
	NetApiBufferFree = (_NetApiBufferFree)GetProcAddress(hLib, "NetApiBufferFree");
	if (pBuf != NULL) {
		NetApiBufferFree(pBuf);
		pBuf = NULL;
	}
	FreeLibrary(hLib);
}

PSID GetSIDInformation(LPCTSTR userName)
{
	DWORD dwSidLength = 0, dwLengthOfDomainName = 0, dwRetCode = 0;
	SID_NAME_USE typeOfSid;
	PSID lpSid = NULL;
	LPTSTR lpDomainName = NULL;
	//    Узнаем необходимые размеры буферов
	if (!LookupAccountName(NULL, userName, NULL, &dwSidLength,
		NULL, &dwLengthOfDomainName, &typeOfSid)) {

		dwRetCode = GetLastError();
		//    Выделим память под буферы
		if (dwRetCode == ERROR_INSUFFICIENT_BUFFER) {
			lpSid = (SID*) new char[dwSidLength];
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
		}
		else {
			fprintf(stderr, "Lookup account name failed: %d\n", GetLastError());
			return NULL;
		}
	}
	//    Получим описатель безопасности
	if (!LookupAccountName(NULL, userName, lpSid, &dwSidLength,
		lpDomainName, &dwLengthOfDomainName, &typeOfSid)) {

		fprintf(stderr, "Lookup account name failed: %d\n", GetLastError());
		return NULL;
	}
	return lpSid;
}

bool add_user_to_group(wchar_t *name)
{
	wchar_t name_gr[32] = { 0 }; char name1[32] = { 0 };
	cout << "Group name: "; cin >> name1;
	for (int i = 0; i < 32; i++)
		if (name1[i] != '\0')
			name_gr[i] = name1[i] + 1104;
		else
			break;
	LOCALGROUP_MEMBERS_INFO_3 users_group;
	users_group.lgrmi3_domainandname = name;

	HMODULE hLib = LoadLibrary("Netapi32.dll");
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetLocalGroupAddMembers)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
	_NetLocalGroupAddMembers NetLocalGroupAddMembers = 0;
	NetLocalGroupAddMembers = (_NetLocalGroupAddMembers)GetProcAddress(hLib, "NetLocalGroupAddMembers");
	NTSTATUS status = NetLocalGroupAddMembers(NULL, name_gr, 3, (LPBYTE)&users_group, 1);
	if (status != NERR_Success)
	{
		fprintf(stderr, "Net local group add members failed: %d\n", GetLastError());
		return false;
	}
	else
	{
		cout << "This user successfully adding in group." << endl;
		return true;
	}
	FreeLibrary(hLib);
}

struct User_info
{
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nUserStatus;
	LPTSTR pszServerName = NULL;
};
struct User_info_group
{
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwLevel = 0;
	DWORD dwFlags = LG_INCLUDE_INDIRECT;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	NET_API_STATUS nStatus;
	LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
	DWORD i;
	DWORD dwTotalCount = 0;
};
struct User_info_sid
{
	DWORD dwLevel = 23;
	NET_API_STATUS nStatus;
	LPTSTR sStringSid = NULL;
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_23 pBuf23 = NULL;
};
struct New_user_info
{
	USER_INFO_1 ui;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	NET_API_STATUS nStatus;
};
struct User_account_rights
{
	PLSA_UNICODE_STRING SystemName = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	ACCESS_MASK DesiredAccess = POLICY_LOOKUP_NAMES;
	LSA_HANDLE PolicyHandle;
};
struct New_info_user
{
	DWORD dwLevel = 0;
	USER_INFO_0 ui;
	NET_API_STATUS nStatus;
};
struct New_user_rights
{
	LSA_HANDLE PolicyHandle;
	LSA_UNICODE_STRING UserRights;
	ULONG CountOfRights = 1;
};

struct Group_info
{
	LPLOCALGROUP_INFO_0 pBuf = NULL;
	LPLOCALGROUP_INFO_0  pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nGroupStatus;
	LPTSTR pszServerName = NULL;
};
struct New_group_info
{
	GROUP_INFO_0 ui;
	DWORD level = 0;
	wchar_t name[32];
	NET_API_STATUS nStatus;
};
struct New_info_group
{
	GROUP_INFO_0 ui;
	DWORD dwLevel = 0;
	NET_API_STATUS nStatus;
};


void list_of_all_users()
{
	cout << "Users list: " << endl;
	LPUSER_INFO_3 pBuf = NULL, pTmpBuf;
	DWORD dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0, dwTotalCount = 0, i;
	NET_API_STATUS nStatus;
	HMODULE hLib = LoadLibrary("Netapi32.dll");

	typedef NET_API_STATUS(NET_API_FUNCTION *_NetUserEnum)(LPCWSTR, DWORD, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, PDWORD);
	_NetUserEnum NetUserEnum = 0;
	NetUserEnum = (_NetUserEnum)GetProcAddress(hLib, "NetUserEnum");

	typedef NET_API_STATUS(NET_API_FUNCTION *_NetApiBufferFree)(LPVOID);
	_NetApiBufferFree NetApiBufferFree = 0;
	NetApiBufferFree = (_NetApiBufferFree)GetProcAddress(hLib, "NetApiBufferFree");

	do {
		nStatus = NetUserEnum(NULL,
			3,
			FILTER_NORMAL_ACCOUNT,
			(LPBYTE*)&pBuf,
			MAX_PREFERRED_LENGTH,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle);

		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
			if ((pTmpBuf = pBuf) != NULL) {
				for (i = 0; i < dwEntriesRead; i++) {
					if (pTmpBuf == NULL) {
						fprintf(stderr, "An access violation has occurred\n");
						break;
					}

					wprintf(L"\t-- %s\n", pTmpBuf->usri3_name);
					printGroups(pTmpBuf->usri3_name);

					PSID lpSid = GetSID(pTmpBuf->usri3_name);
					LPWSTR  lpStringSID = NULL;
					ConvertSidToStringSidW(lpSid, &lpStringSID);
					wprintf(L"\n\t\tUser's SID: %s\n", lpStringSID);

					PLSA_UNICODE_STRING UserRights = NULL;;
					ULONG CountOfRights = 0;
					printPrivileges(pTmpBuf->usri3_name);
					wprintf(L"\n");

					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}
		else
			fprintf(stderr, "A system error has occurred: %d\n", nStatus);

		if (pBuf != NULL) {
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	} while (nStatus == ERROR_MORE_DATA);

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
	FreeLibrary(hLib);
}
void list_of_all_groups()
{
	Group_info groups;
	HMODULE hLib = LoadLibrary("Netapi32.dll");

	typedef NET_API_STATUS(NET_API_FUNCTION *_NetLocalGroupEnum)(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
	_NetLocalGroupEnum NetLocalGroupEnum = 0;
	NetLocalGroupEnum = (_NetLocalGroupEnum)GetProcAddress(hLib, "NetLocalGroupEnum");

	typedef NET_API_STATUS(NET_API_FUNCTION *_NetApiBufferFree)(LPVOID);
	_NetApiBufferFree NetApiBufferFree = 0;
	NetApiBufferFree = (_NetApiBufferFree)GetProcAddress(hLib, "NetApiBufferFree");

	groups.nGroupStatus = NetLocalGroupEnum((LPCWSTR)groups.pszServerName,
		groups.dwLevel,
		(LPBYTE *)&groups.pBuf,
		groups.dwPrefMaxLen,
		&groups.dwEntriesRead,
		&groups.dwTotalEntries,
		&groups.dwResumeHandle);
	if ((groups.nGroupStatus == NERR_Success) || (groups.nGroupStatus == ERROR_MORE_DATA))
	{
		groups.pTmpBuf = groups.pBuf;
		cout << "Group list: " << endl;
		for (groups.i = 0; (groups.i < groups.dwEntriesRead); groups.i++)
		{
			if (groups.pTmpBuf == NULL)
			{
				fprintf(stderr, "An access violation has occurred\n");
				break;
			}

			wprintf(L"\t-- %s\n", groups.pTmpBuf->lgrpi0_name);
			show_account_rights(GetSID(groups.pTmpBuf->lgrpi0_name));
			PSID gr_sid = GetSID(groups.pTmpBuf->lgrpi0_name);
			LPWSTR string_sid;
			if (ConvertSidToStringSid(gr_sid, &string_sid))
				wcout << "\t\tSID: " << string_sid << endl;
			groups.pTmpBuf++;
			groups.dwTotalCount++;
		}
	}
	if (groups.pBuf != NULL)
	{
		NetApiBufferFree(groups.pBuf);
		groups.pBuf = NULL;
	}
	FreeLibrary(hLib);
}
 
void add_new_user()
{
	New_user_info new_user;
	wchar_t name[32] = { 0 }, password[64] = { 0 }; char name1[32] = { 0 }, password1[64];
	cout << "Enter name of new user: "; cin >> name1;
	for (int i = 0; i < 32; i++)
		name[i] = name1[i];

	new_user.ui.usri1_name = name;
	cout << "Enter password for " << name << " : "; cin >> password1;
	for (int i = 0; i < 64; i++)
		password[i] = password1[i];
	cout << "Do you want add this user in somthing group?[Y\N]" << endl;
	char q; cin >> q;
	
	
	new_user.ui.usri1_password = password;

	new_user.ui.usri1_priv = USER_PRIV_USER;
	new_user.ui.usri1_home_dir = NULL;
	new_user.ui.usri1_comment = NULL;
	new_user.ui.usri1_flags = UF_SCRIPT;
	new_user.ui.usri1_script_path = NULL;

	HMODULE hLib = LoadLibrary("Netapi32.dll");
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetUserAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
	_NetUserAdd NetUserAdd = 0;
	NetUserAdd = (_NetUserAdd)GetProcAddress(hLib, "NetUserAdd");

	new_user.nStatus = NetUserAdd(NULL,
		new_user.dwLevel,
		(LPBYTE)&new_user.ui,
		&new_user.dwError);

	if (new_user.nStatus == NERR_Success)
	{
		cout << "User with name " << name << " successfully created." << endl;
		if (q == 'Y' || q == 'y')
			add_user_to_group(new_user.ui.usri1_name);
	}
	else
		cout << "Error: Cant add new user." << endl;
	FreeLibrary(hLib);
}
void add_new_group()
{
	char name[32]; New_group_info new_groupe;
	cout << "Enter name of new group: "; cin >> name;
	for (int i = 0; i < 32; i++)
		new_groupe.name[i] = name[i];
	new_groupe.ui.grpi0_name = new_groupe.name;

	HMODULE hLib = LoadLibrary("Netapi32.dll");
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetLocalGroupAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
	_NetLocalGroupAdd NetLocalGroupAdd = 0;
	NetLocalGroupAdd = (_NetLocalGroupAdd)GetProcAddress(hLib, "NetLocalGroupAdd");

	new_groupe.nStatus = NetLocalGroupAdd(NULL, new_groupe.level, (LPBYTE)&new_groupe.ui, NULL);
	if (new_groupe.nStatus == NERR_Success)
		cout << "Group with name " << name << " successfully created." << endl;
	else
		cout << "Error: Cant add new group." << endl;
	FreeLibrary(hLib);
};

void change_info_user()
{
	New_info_user new_info_user;
	wchar_t new_name[32] = { 0 }, old_name[32] = { 0 }; char new_name1[32] = { 0 }, old_name1[32] = { 0 };
	cout << "Enter user name, which you want change: "; cin >> old_name1;
	cout << "Enter new user name: "; cin >> new_name1;
	for (int i = 0; i < 32; i++)
	{
		old_name[i] = old_name1[i];
		new_name[i] = new_name1[i];
	}

	HMODULE hLib = LoadLibrary("Netapi32.dll");
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetUserSetInfo)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);
	_NetUserSetInfo NetUserSetInfo = 0;
	NetUserSetInfo = (_NetUserSetInfo)GetProcAddress(hLib, "NetUserSetInfo");

	new_info_user.ui.usri0_name = new_name;
	new_info_user.nStatus = NetUserSetInfo(NULL, old_name, new_info_user.dwLevel, (LPBYTE)&new_info_user.ui, NULL);

	if (new_info_user.nStatus == NERR_Success)
		cout << "Changed successfully!" << endl;
	else
		cout << "Error." << endl;
	FreeLibrary(hLib);
}
void change_info_group()
{
	New_info_group new_info_group;
	wchar_t old_name[32] = { 0 }, new_name[32] = { 0 };
	char old_name1[32] = { 0 }, new_name1[32] = { 0 };
	cout << "Enter name group, which you want change: "; cin >> old_name1;
	cout << "Enter new name group: "; cin >> new_name1;

	for (int i = 0; i < 32; i++)
	{
		old_name[i] = old_name1[i];
		new_name[i] = new_name1[i];
	}

	HMODULE hLib = LoadLibrary("Netapi32.dll");
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetLocalGroupSetInfo)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);
	_NetLocalGroupSetInfo NetLocalGroupSetInfo = 0;
	NetLocalGroupSetInfo = (_NetLocalGroupSetInfo)GetProcAddress(hLib, "NetLocalGroupSetInfo");

	new_info_group.ui.grpi0_name = new_name;
	new_info_group.nStatus = NetLocalGroupSetInfo(NULL, old_name, new_info_group.dwLevel, (LPBYTE)&new_info_group.ui, NULL);
	if (new_info_group.nStatus == NERR_Success)
		cout << "Changed Successfully!" << endl;
	else
	{
		if (new_info_group.nStatus == ERROR_ACCESS_DENIED)
			cout << "ERROR_ACCESS_DENIED" << endl;
		else if (new_info_group.nStatus == ERROR_INVALID_PARAMETER)
			cout << "ERROR_INVALID_PARAMETER" << endl;
		else
			cout << "Error." << endl;
	}
	FreeLibrary(hLib);
}

void del_user()
{
	DWORD dwError = 0;
	NET_API_STATUS nStatus;
	wchar_t name[32] = { 0 }; char name1[32] = { 0 };
	cout << "Enter name of user: "; cin >> name1;

	for (int i = 0; i < 32; i++)
		name[i] = name1[i];

	HMODULE hLib = LoadLibrary("Netapi32.dll");
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetUserDel)(LPCWSTR, LPCWSTR);
	_NetUserDel NetUserDel = 0;
	NetUserDel = (_NetUserDel)GetProcAddress(hLib, "NetUserDel");

	nStatus = NetUserDel(NULL, name);

	if (nStatus == NERR_Success)
		cout << "This user is seccessfully deleted." << endl;
	else
		cout << "This user wasn't deleted." << endl;
	FreeLibrary(hLib);
}
void del_group()
{
	wchar_t name[32] = { 0 }; char name1[32] = { 0 };
	cout << "Enter name group: "; cin >> name1;
	for (int i = 0; i < 32; i++)
		name[i] = name1[i];

	HMODULE hLib = LoadLibrary("Netapi32.dll");
	typedef NET_API_STATUS(NET_API_FUNCTION *_NetLocalGroupDel)(LPCWSTR, LPCWSTR);
	_NetLocalGroupDel NetLocalGroupDel = 0;
	NetLocalGroupDel = (_NetLocalGroupDel)GetProcAddress(hLib, "NetLocalGroupDel");

	NET_API_STATUS nStatus = NetLocalGroupDel(NULL, name);
	if (nStatus == NERR_Success)
		cout << "This group is seccessfully deleted." << endl;
	else
		cout << "This group wasn't deleted." << endl;
	FreeLibrary(hLib);
}

void show_account_rights(PSID sid)
{
	User_account_rights user_policy;
	ZeroMemory(&user_policy.ObjectAttributes, sizeof(user_policy.ObjectAttributes));

	HMODULE hLib = LoadLibrary("Advapi32.dll");
	typedef NTSTATUS(NET_API_FUNCTION *_LsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	_LsaOpenPolicy LsaOpenPolicy = 0;
	LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(hLib, "LsaOpenPolicy");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaEnumerateAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING*, PULONG);
	_LsaEnumerateAccountRights LsaEnumerateAccountRights = 0;
	LsaEnumerateAccountRights = (_LsaEnumerateAccountRights)GetProcAddress(hLib, "LsaEnumerateAccountRights");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaClose)(LSA_HANDLE);
	_LsaClose LsaClose = 0;
	LsaClose = (_LsaClose)GetProcAddress(hLib, "LsaClose");

	NTSTATUS Status = LsaOpenPolicy(user_policy.SystemName, &user_policy.ObjectAttributes, user_policy.DesiredAccess, &user_policy.PolicyHandle);
	if (Status == ERROR_SUCCESS)
	{
		PLSA_UNICODE_STRING pUserRights = NULL, UserRights; ULONG CountOfRights;
		NTSTATUS EnumStat = LsaEnumerateAccountRights(user_policy.PolicyHandle, sid, &pUserRights, &CountOfRights);

		if (EnumStat == ERROR_SUCCESS)
		{
			if (CountOfRights != 0)
			{
				UserRights = pUserRights;
				cout << "\t\tRights: " << endl;
				for (ULONG i = 0; i < CountOfRights; i++)
				{
					wprintf(L"\t\t %s\n", pUserRights->Buffer);
					pUserRights++;
				}
			}
		}
	//	LsaFreeMemory(pUserRights);
	}
	LsaClose(user_policy.PolicyHandle);
	FreeLibrary(hLib);
}
void add_account_right()
{
	wchar_t userNameW[50] = { 0 };
	char userName[50] = { 0 };
	wprintf(L"Enter name of user, which you want to add privilege: ");
	std::cin >> userName;

	OemToCharW(userName, userNameW);
	PSID lpSid = GetSIDInformation(userName);

	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	LSA_HANDLE lsahPolicyHandle;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

	HMODULE lib = LoadLibrary("NetApi32.dll");
	typedef NET_API_STATUS(__stdcall *_NetUserGetInfo)(LPCWSTR servername, LPCWSTR username, DWORD   level, LPBYTE  *bufptr);
	_NetUserGetInfo NetUserGetInfo = 0;
	NetUserGetInfo = (_NetUserGetInfo)GetProcAddress(lib, "NetUserGetInfo");

	HMODULE hLib = LoadLibrary("Advapi32.dll");
	typedef NTSTATUS(NET_API_FUNCTION *_LsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	_LsaOpenPolicy LsaOpenPolicy = 0;
	LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(hLib, "LsaOpenPolicy");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaAddAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
	_LsaAddAccountRights LsaAddAccountRights = 0;
	LsaAddAccountRights = (_LsaAddAccountRights)GetProcAddress(hLib, "LsaAddAccountRights");


	PUSER_INFO_4 userstruct = NULL;
	NetUserGetInfo(0, userNameW, 4, (LPBYTE *)&userstruct);

	NTSTATUS ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
	if (ntsResult != 0x00000000)
		fprintf(stderr, "Lsa open policy failed: %d\n", GetLastError());

	for (size_t i = 0; i < 37; i++)
		wprintf(L"%d. %s\r\n", i + 1, g_PrivilegeArray[i]);

	DWORD privNum = 0;
	while (privNum <= 0 || privNum > 37) {
		wprintf(L"\nEnter number of privilege: ");
		getchar();
		std::wcin >> privNum;
	}

	LSA_UNICODE_STRING lsaString;
	InitLsaString(&lsaString, g_PrivilegeArray[privNum - 1]);

	if (LsaAddAccountRights(lsahPolicyHandle, userstruct->usri4_user_sid, &lsaString, 1))
		fprintf(stderr, "Add privilege failed: %d\n", GetLastError()); 
	else
	{
		//HANDLE hToken;
		//OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		//if (SetPrivilege(hToken, "SeRestorePrivilege", true) == -1) return;
		cout << "Enable this privilege is successful." << endl;
	}
}
void del_account_rights()
{
	wchar_t name_acc[32] = { 0 }; char name[32] = { 0 };
	cout << "Enter user's name, which you want delete right: "; cin >> name;
	for (int i = 0; i < 32; i++)
		name_acc[i] = name[i];

	HMODULE hLib = LoadLibrary("Advapi32.dll");
	typedef NTSTATUS(NET_API_FUNCTION *_LsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	_LsaOpenPolicy LsaOpenPolicy = 0;
	LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(hLib, "LsaOpenPolicy");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaRemoveAccountRights)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
	_LsaRemoveAccountRights LsaRemoveAccountRights = 0;
	LsaRemoveAccountRights = (_LsaRemoveAccountRights)GetProcAddress(hLib, "LsaRemoveAccountRights");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaClose)(LSA_HANDLE);
	_LsaClose LsaClose = 0;
	LsaClose = (_LsaClose)GetProcAddress(hLib, "LsaClose");

	User_account_rights user_policy;
	ZeroMemory(&user_policy.ObjectAttributes, sizeof(user_policy.ObjectAttributes));
	NTSTATUS Status = LsaOpenPolicy(user_policy.SystemName, &user_policy.ObjectAttributes, user_policy.DesiredAccess, &user_policy.PolicyHandle);
	if (Status == NERR_Success)
	{
		for (int i = 0; i < 37; i++)
			wcout << i + 1 << ") " << g_PrivilegeArray[i] << endl;
		int change = 0;
		cout << "What privelege you want delete: "; cin >> change;

		PSID sid = GetSID(name_acc);

		PLSA_UNICODE_STRING right = new LSA_UNICODE_STRING;
		InitLsaString(right, g_PrivilegeArray[change - 1]);

		if (NTSTATUS ch = LsaRemoveAccountRights(user_policy.PolicyHandle, sid, FALSE, right, 1) != 0x00000000)
			cout << "This user haven't got this right." << endl;
		else
			cout << "Delete this right is successfully." << endl;
		delete right;
	}
	LsaClose(user_policy.PolicyHandle);
	FreeLibrary(hLib);
}

void add_group_acc_right()
{
	wchar_t name_gr[32] = { 0 }; char name[32] = { 0 };
	cout << "Enter name of group: "; cin >> name;
	for (int i = 0; i < 32; i++)
		name_gr[i] = name[i];

	PSID sid = GetSID(name_gr);



	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	LSA_HANDLE hPolicyHandle;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

	HMODULE hLib = LoadLibrary("Advapi32.dll");
	typedef NTSTATUS(NET_API_FUNCTION *_LsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	_LsaOpenPolicy LsaOpenPolicy = 0;
	LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(hLib, "LsaOpenPolicy");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaAddAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
	_LsaAddAccountRights LsaAddAccountRights = 0;
	LsaAddAccountRights = (_LsaAddAccountRights)GetProcAddress(hLib, "LsaAddAccountRights");

	typedef ULONG(NET_API_FUNCTION *_LsaNtStatusToWinError)(NTSTATUS);
	_LsaNtStatusToWinError LsaNtStatusToWinError = 0;
	LsaNtStatusToWinError = (_LsaNtStatusToWinError)GetProcAddress(hLib, "LsaNtStatusToWinError");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaClose)(LSA_HANDLE);
	_LsaClose LsaClose = 0;
	LsaClose = (_LsaClose)GetProcAddress(hLib, "LsaClose");

	NTSTATUS nStatus = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &hPolicyHandle);
	if (nStatus == NERR_Success)
	{
		for (int i = 0; i < 37; i++)
			wcout << i + 1 << ") " << g_PrivilegeArray[i] << endl;
		int change = 0;
		cout << "What privelege you want add: "; cin >> change;

		PLSA_UNICODE_STRING right = new LSA_UNICODE_STRING;
		InitLsaString(right, g_PrivilegeArray[change - 1]);

		if (NTSTATUS ch = LsaAddAccountRights(hPolicyHandle, sid, right, 1) != 0x00000000)
		{
			fprintf(stderr, "Add privilege failed: %d\n", GetLastError());
			if (LsaNtStatusToWinError(ch) == ERROR_ACCESS_DENIED)
				cout << "ERROR_ACCESS_DENIED";
			if (LsaNtStatusToWinError(ch) == ERROR_NO_SYSTEM_RESOURCES)
				cout << "ERROR_NO_SYSTEM_RESOURCES";
			if (LsaNtStatusToWinError(ch) == ERROR_INTERNAL_DB_ERROR)
				cout << "ERROR_INTERNAL_DB_ERROR";
			if (LsaNtStatusToWinError(ch) == ERROR_INVALID_HANDLE)
				cout << "ERROR_INVALID_HANDLE";
			if (LsaNtStatusToWinError(ch) == ERROR_INVALID_SERVER_STATE)
				cout << "ERROR_INVALID_SERVER_STATE";
			if (LsaNtStatusToWinError(ch) == ERROR_INVALID_PARAMETER)
				cout << "ERROR_INVALID_PARAMETER";
			if (LsaNtStatusToWinError(ch) == ERROR_NO_SUCH_PRIVILEGE)
				cout << "ERROR_NO_SUCH_PRIVILEGE";
			if (LsaNtStatusToWinError(ch) == ERROR_FILE_NOT_FOUND)
				cout << "ERROR_FILE_NOT_FOUND";
			if (LsaNtStatusToWinError(ch) == ERROR_GEN_FAILURE)
				cout << "ERROR_GEN_FAILURE";
		}
		else
			cout << "Add new right is successfully." << endl;
		delete right;
	}
	LsaClose(hPolicyHandle);
	FreeLibrary(hLib);
}
void del_group_acc_right()
{
	wchar_t name_acc[32] = { 0 }; char name[32] = { 0 };
	cout << "Enter name of group, which you want delete right: "; cin >> name;
	for (int i = 0; i < 32; i++)
		name_acc[i] = name[i];

	PSID sid = GetSID(name_acc);

	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	LSA_HANDLE hPolicyHandle;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

	HMODULE hLib = LoadLibrary("Advapi32.dll");
	typedef NTSTATUS(NET_API_FUNCTION *_LsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	_LsaOpenPolicy LsaOpenPolicy = 0;
	LsaOpenPolicy = (_LsaOpenPolicy)GetProcAddress(hLib, "LsaOpenPolicy");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaRemoveAccountRights)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
	_LsaRemoveAccountRights LsaRemoveAccountRights = 0;
	LsaRemoveAccountRights = (_LsaRemoveAccountRights)GetProcAddress(hLib, "LsaRemoveAccountRights");

	typedef NTSTATUS(NET_API_FUNCTION *_LsaClose)(LSA_HANDLE);
	_LsaClose LsaClose = 0;
	LsaClose = (_LsaClose)GetProcAddress(hLib, "LsaClose");

	NTSTATUS nStatus = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &hPolicyHandle);
	if (nStatus == NERR_Success)
	{
		for (int i = 0; i < 37; i++)
			wcout << i + 1 << ") " << g_PrivilegeArray[i] << endl;
		int change = 0;
		cout << "What privelege you want delete: "; cin >> change;

		PLSA_UNICODE_STRING right = new LSA_UNICODE_STRING;
		InitLsaString(right, g_PrivilegeArray[change - 1]);


		if (NTSTATUS ch = LsaRemoveAccountRights(hPolicyHandle, sid, FALSE, right, 1) != 0x00000000)
			cout << "This user haven't got this right." << endl;
		else
			cout << "Delete this right is successfully." << endl;
		delete right;
	}
	LsaClose(hPolicyHandle);
	FreeLibrary(hLib);
}

void main()
{
	
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	while (true)
	{
		char Case[3] = {0};
		cout << "1. Users list." << endl;
		cout << "2. Groups list." << endl;
		cout << "3. Add new user." << endl;
		cout << "4. Add new group." << endl;
		cout << "5. Delete user." << endl;
		cout << "6. Delete groupe." << endl;
		cout << "7. Change user's information." << endl;
		cout << "8. Change group's information." << endl;
		cout << "9. Add user right." << endl;
		cout << "10. Delete user right." << endl;
		cout << "11. Add group right." << endl;
		cout << "12. Delete group right." << endl;
		cout << "0. Exit." << endl;
		
		cout << endl << "Enter number of case: "; cin >> Case; 
		int _case = atoi(Case);
		switch (_case)
		{
		case 1:
		{
			list_of_all_users();
			break;
		}
		case 2:
		{
			list_of_all_groups();
			break;
		}
		case 3:
		{
			add_new_user();
			break;
		}
		case 4:
		{
			add_new_group();
			break;
		}
		case 5:
		{
			del_user();
			break;
		}
		case 6:
		{
			del_group();
			break;
		}
		case 7:
		{
			change_info_user();
			break;
		}
		case 8:
		{
			change_info_group();
			break;
		}
		case 9:
		{
			add_account_right();
			break;
		}
		case 10:
		{
			del_account_rights();
			break;
		}
		case 11:
		{
			add_group_acc_right();
			break;
		}
		case 12:
		{
			del_group_acc_right();
			break;
		}
		case 0:
		{
			return;
		}
		}
		std::system("pause");
		std::system("cls");
	}
}