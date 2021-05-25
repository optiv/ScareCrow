
<h1 align="center">
<br>
<img src=Screenshots/ScareCrow.png >
<br>
ScareCrow
</h1>



## More Information
If you want to learn more about the techniques utilized in this framework please take a look at [Part 1](https://www.optiv.com/explore-optiv-insights/source-zero/endpoint-detection-and-response-how-hackers-have-evolved) and [Part 2](https://www.optiv.com/explore-optiv-insights/source-zero/edr-and-blending-how-attackers-avoid-getting-caught)
#

## Description
ScareCrow is a payload creation framework for side loading (not injecting) into a legitimate Windows process (bypassing Application Whitelisting controls). Once the DLL loader is loaded into memory, it utilizes a technique to flush an EDR’s hook out of the system DLLs running in the process's memory. This works because we know the EDR’s hooks are placed when a process is spawned. ScareCrow can target these DLLs and manipulate them in memory by using the API function VirtualProtect, which changes a section of a process’ memory permissions to a different value, specifically from Execute–Read to Read-Write-Execute. 

When executed, ScareCrow will copy the bytes of the system DLLs stored on disk in `C:\Windows\System32\`. These DLLs are stored on disk “clean” of EDR hooks because they are used by the system to load an unaltered copy into a new process when it’s spawned. Since EDR’s only hook these processes in memory, they remain unaltered. ScareCrow does not copy the entire DLL file, instead only focuses on the .text section of the DLLs. This section of a DLL contains the executable assembly, and by doing this ScareCrow helps reduce the likelihood of detection as re-reading entire files can cause an EDR to detect that there is a modification to a system resource. The data is then copied into the right region of memory by using each function’s offset. Each function has an offset which denotes the exact number of bytes from the base address where they reside, providing the function’s location on the stack. To do this, ScareCrow changes the permissions of the .text region of memory using VirtualProtect. Even though this is a system DLL, since it has been loaded into our process (that we control), we can change the memory permissions without requiring elevated privileges. 

Once these the hooks are removed, ScareCrow then utilizes custom System Calls to load and run shellcode in memory. ScareCrow does this even after the EDR hooks are removed to help avoid detection by non-userland, hook-based telemetry gathering tools such as Event Tracing for Windows (ETW) or other event logging mechanisms. These custom system calls are also used to perform the VirtualProtect call to remove the hooks placed by EDRs, described above, to avoid detection by any EDR’s anti-tamper controls. This is done by calling a custom version of the VirtualProtect syscall, NtProtectVirtualMemory. ScareCrow utilizes Golang to generate these loaders and then assembly for these custom syscall functions.

ScareCrow loads the shellcode into memory by first decrypting the shellcode, which is encrypted by default using AES encryption with a decryption and initialization vector key. Once decrypted and loaded, the shellcode is then executed. Depending on the loader options specified ScareCrow will set up different export functions for the DLL. The loaded DLL also does not contain the standard DLLmain function which all DLLs typically need to operate. The DLL will still execute without any issue because the process we load into will look for those export functions and not worry about DLLMain being there. 

### Binary Sample
<p align="center"> <img src=Screenshots/PreRefreshed_Dlls.png border="2px solid #555">
After
<p align="center"> <img src=Screenshots/Refreshed_Dlls.png border="2px solid #555">


During the creation process of the loader, ScareCrow utilizes a library for blending into the background after a beacon calls home. This library does two things:
* Code signs the Loader:
Files that are signed with code signing certificates are often put under less scrutiny, making it easier to be executed without being challenged, as files signed by a trusted name are often less suspicious than others. Most antimalware products don’t have the time to validate and verify these certificates (now some do but typically the common vendor names are included in a whitelist). ScareCrow creates these certificates by using a go package version of the tool `limelighter` to create a pfx12 file. This package takes an inputted domain name, specified by the user, to create a code signing certificate for that domain. If needed, you can also use your own code signing certificate if you have one, using the valid command-line option. 
* Spoof the attributes of the loader:
      This is done by using syso files which are a form of embedded resource files that when compiled along with our loader, will modify the attribute portions of our compiled code. Prior to generating a syso file, ScareCrow will generate a random file name (based on the loader type) to use. Once chosen, this file name will map to the associated attributes for that file name, ensuring that the right values are assigned.  

### File Attribute Sample

<p align="center"> <img src=Screenshots/File_Attributes.png border="2px solid #555">

With these files and the go code, ScareCrow will cross compile them into DLLs using the c-shared library option. Once the DLL is compiled, it is obfuscated into a broken base64 string that will be embedded into a file. This allows for the file to be remotely pulled, accessed, and programmatically executed. 


## Install
The first step as always is to clone the repo. Before you compile ScareCrow, you'll need to install the dependencies. 

To install them, run following commands:

```
go get github.com/fatih/color
go get github.com/yeka/zip
go get github.com/josephspurrier/goversioninfo
```
Make sure that the following are installed on your OS:
```
openssl
osslsigncode
mingw-w64
```

Then build it

```
go build ScareCrow.go
```

## Help

```

./ScareCrow -h

  _________                           _________                       
 /   _____/ ____ _____ _______   ____ \_   ___ \_______  ______  _  __
 \_____  \_/ ___\\__  \\_  __ \_/ __ \/    \  \/\_  __ \/  _ \ \/ \/ /
 /        \  \___ / __ \|  | \/\  ___/\     \____|  | \(  <_> )     / 
/_______  /\___  >____  /__|    \___  >\______  /|__|   \____/ \/\_/  
        \/     \/     \/            \/        \/                      
                                                        (@Tyl0us)
        “Fear, you must understand is more than a mere obstacle. 
        Fear is a TEACHER. the first one you ever had.”

Usage of ./ScareCrow:
  -I string
        Path to the raw 64-bit shellcode.
  -Loader string
        Sets the type of process that will sideload the malicious payload:
        [*] binary - Generates a binary based payload. (This type does not benefit from any sideloading)
        [*] control - Loads a hidden control applet - the process name would be rundll32 if -O is specified. A JScript loader will be generated.
        [*] dll - Generates just a DLL file. Can be executed with commands such as rundll32 or regsvr32 with DllRegisterServer, DllGetClassObject as export functions.
        [*] excel - Loads into a hidden Excel process using a JScript loader.
        [*] msiexec - Loads into MSIexec process using a JScript loader.
        [*] wscript - Loads into WScript process using a JScript loader.
         (default "binary")
  -O string
        Name of output file (e.g. loader.js or loader.hta). If Loader is set to dll or binary this option is not required.
  -configfile string
        The path to a json based configuration file to generate custom file attributes. This will not use the default ones.
  -console
        Only for Binary Payloads - Generates verbose console information when the payload is executed. This will disable the hidden window feature.
  -delivery string
        Generates a one-liner command to download and execute the payload remotely:
        [*] bits - Generates a Bitsadmin one liner command to download, execute and remove the loader (Compatible with Binary, Control, Excel and Wscript Loaders).
        [*] hta - Generates a blank hta file containing the loader along with a MSHTA command to execute the loader remotely in the background (Compatible with Control and Excel Loaders). 
        [*] macro - Generates an office macro that will download and execute the loader remotely (Compatible with Control, Excel and Wscript Loaders)
  -domain string
        The domain name to use for creating a fake code signing cert. (e.g. www.acme.com) 
  -etw
        Enables ETW patching to prevent ETW events from being generated
  -injection string
        Enables Process Injection Mode and specifies the path to the process to create/inject into (use \ for the path).
  -password string
        The password for the code signing cert. Required when -valid is used.
  -sandbox
        Enables sandbox evasion using IsDomainedJoined calls.
  -unmodified
        When enabled will generate a DLL loader that WILL NOT remove the EDR hooks in system DLLs and only use custom syscalls (set to false by default)
  -url string
        URL associated with the Delivery option to retrieve the payload. (e.g. https://acme.com/)
  -valid string
        The path to a valid code signing cert. Used instead of -domain if a valid code signing cert is desired.
```
## Loader
The Loader determines the type of technique to load the shellcode into the target system. If no Loader option is chosen, ScareCrow will just compile a standard DLL file, that can be used by rundll32, regsvr32, or other techniques that utilize a DLL. ScareCrow utilizes three different types of loaders to load shellcode into memory: 
* Control Panel – This generates a control panel applet (i.e. Program and Features, or AutoPlay). By compiling the loader to have specific DLL export functions in combination with a file extension .cpl, it will spawn a control panel process (rundll32.exe) and the loader will be loaded into memory.
* WScript – Spawns a WScript process that utilizes a manifest file and registration-free Com techniques to load (not injected) DLL loader into its own process, side-by-side. This avoids registering the DLL in memory as the manifest file tells the process which, where, and what version of a DLL to load.
* Excel – Generates an XLL file which are Excel-based DLL files that when loaded into Excel will execute the loader. A hidden Excel process will be spawned, forcing the XLL file to be loaded.
* Msiexec - Spawns a hidden MSIExec process that will load the DLL into memory and execute the shellcode.


ScareCrow can also generate binary based payloads if needed by using the `-loader` command line option. These binaries do not benefit from any side-by-side loading techniques but serve as an additional technique to execute shellcode depending on the situation. 


## Console
ScareCrow utilizes a technique to first create the process and then move it into the background. This does two things, first it helps keep the process hidden and second, avoids being detected by any EDR product. Spawning a process right away in the background can be very suspiciousness and an indicator of maliciousness. ScareCrow does this by calling the ‘GetConsoleWindow’ and ‘ShowWindow’ Windows function after the process is created and the EDR’s hooks are loaded, and then changes the windows attributes to hidden. ScareCrow utilizes these APIs rather than using the traditional ` -ldflags -H=windowsgui` as this is highly signatured and classified in most security products as an Indicator of Compromise. 

If the `-console` command-line option is selected, ScareCrow will not hide the process in the background. Instead, ScareCrow will add several debug messages displaying what the loader is doing.

## Process Injection
ScareCrow contains the ability to do process injection attacks. To avoid any hooking or detection in either the loader process or the injected process itself, ScareCrow first unhooks the loader process as it would normally, to ensure there are no hooks in the process. Once completed, the loader will then spawn the process specified in the creation command. Once spawned, the loader will then create a handle to the process to retrieve a list of loaded DLLs. Once it finds DLLs, it will enumerate the base address of each DLL in the remote process. Using the function WriteProcessMemory the loader will then write the bytes of the system DLLs stored on disk (since they are “clean” of EDR hooks) without the need to change the memory permissions first. ScareCrow uses WriteProcessMemory because this function contains a feature primarily used in debugging where even if a section of memory is read-only, if everything is correct in the call to Write­Process­Memory, it will temporarily change the permission to read-write, update the memory section and then restore the original permissions. Once this is done, the loader can inject shellcode into the spawned process with no issue, as there are no EDR hooks in either process.

This option can be used with any of the loader options. To enable process injection, use the `-injection` command-line option along with the full path to the process you want to use to inject into. When putting the path in as an argument, it is important to either surround the full path with `""` or use double `\` for each directory in the path. 


## ETW Bypass
ScareCrow contains the ability to patch ETW functions, preventing any event from being generated by the process. ETW utilizes built-in Syscalls to generate this telemetry. Since ETW is a native feature built into Windows, security products do not need to "hook" the ETW syscalls to gain the information. As a result, to prevent ETW, ScareCrow patches numerous ETW syscalls, flushing out the registers and returning the execution flow to the next instruction.  Use the `-etw` command-line option to enable this in your loader.


## Delivery 
The deliver command line argument allows you to generate a command or string of code (in the macro case) to remotely pull the file from a remote source to the victim’s host. These delivery methods include:
* Bits – This will generate a bitsadmin command that while download the loader remotely, execute it and remove it. This delivery command is compatible with Binary, Control, Excel and Wscript loaders.
* HTA – This will generate a blank HTA file containing the loader. This option will also provide a command line that will execute the HTA remotely. This delivery command is compatible with Control and Excel loaders.
* Macro – This will generate an Office macro that can be put into an Excel or Word macro document. When this macro is executed, the loader will be downloaded from a remote source and executed, and then removed. This delivery command is compatible with Control, Excel and Wscript loaders.

## Custom Attribute Files 
While ScareCrow has an extensive list of file attributes, there are some circumstances where a custom (maybe environment-specific) set of attributes is required. To accommodate this, ScareCrow allows for the inputting of a JSON file containing attributes. Using the `-configfile` command-line option, ScareCrow will use these attributes and filename instead of the pre-existing ones in ScareCrow. The file `main.json` contains a sample template of what the JSON structure needs to be to properly work. Note whatever you use as the "InternalName" will be the file name.


## To Do
* Currently only supports x64 payloads 
* Some older versions of Window's OSes (i.e. Windows 7 or Windows 8.1), have issues reloading the systems DLLs, as a result a version check is built in to ensure stability

## Credit 
* Special thanks to josephspurrier for his [repo](https://github.com/josephspurrier/goversioninfo)
