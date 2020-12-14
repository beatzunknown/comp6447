
re_this:
 push   ebp
 mov    ebp,esp
 mov    edx,DWORD [ebp+0x8]
 mov    eax,DWORD [ebp+0xc]
 lea    ecx,[edx+eax*1]
 mov    edx,0x2aaaaaab
 mov    eax,ecx
 imul   edx
 mov    eax,ecx
 sar    eax,0x1f
 sub    edx,eax
 mov    eax,edx
 add    eax,eax
 add    eax,eax
 add    eax,edx
 add    eax,eax
 sub    ecx,eax
 mov    edx,ecx
 mov    eax,edx
 pop    ebp
 ret    