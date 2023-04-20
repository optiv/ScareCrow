package Cryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	crand "math/rand"
	"time"

	"github.com/ulikunitz/xz"
)

const capletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const hexchar = "abcef12345678890"

var (
	ErrInvalidBlockSize = errors.New("[-] Invalid Blocksize")

	ErrInvalidPKCS7Data = errors.New("[-] Invalid PKCS7 Data (Empty or Not Padded)")

	ErrInvalidPKCS7Padding = errors.New("[-] Invalid Padding on Input")
)

func EncryptShellcode(inputFile string, encryptionmode string) (string, string, string) {
	var rawbyte []byte
	var b64ciphertext, b64key, b64iv string
	src, _ := ioutil.ReadFile(inputFile)
	if encryptionmode == "AES" {
		rawbyte = src
		key := RandomBuffer(32)
		iv := RandomBuffer(16)

		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}
		paddedInput, err := Pkcs7Pad([]byte(rawbyte), aes.BlockSize)
		if err != nil {
			log.Fatal(err)
		}
		cipherText := make([]byte, len(paddedInput))
		ciphermode := cipher.NewCBCEncrypter(block, iv)
		ciphermode.CryptBlocks(cipherText, paddedInput)
		b64ciphertext = fmt.Sprintf("%x", cipherText)
		b64key = fmt.Sprintf("%x", key)
		b64iv = fmt.Sprintf("%x", iv)
		return b64ciphertext, b64key, b64iv
	}
	if encryptionmode == "ELZMA" {
		var buf bytes.Buffer
		fmt.Println("[*] Encrypting Shellcode Using ELZMA Encryption")
		w, err := xz.NewWriter(&buf)
		if err != nil {
			log.Fatalf("xz.NewWriter error %s", err)
		}
		if _, err := io.WriteString(w, string(src)); err != nil {
			log.Fatalf("WriteString error %s", err)
		}
		if err := w.Close(); err != nil {
			log.Fatalf("w.Close error %s", err)
		}
		fart := fmt.Sprintf("%x", buf.Bytes())
		b64ciphertext = fart
		return b64ciphertext, b64key, b64key
	}
	if encryptionmode == "RC4" {
		plaintext := []byte(src)
		fmt.Println("[*] Encrypting Shellcode Using RC4 Encryption")
		key, _ := generateRandomBytes(32)
		block, _ := rc4.NewCipher(key)
		ciphertext := make([]byte, len(plaintext))
		block.XORKeyStream(ciphertext, plaintext)

		b64ciphertext = fmt.Sprintf("%x", ciphertext)
		b64key = fmt.Sprintf("%x", key)

	}
	return b64ciphertext, b64key, b64iv

}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func Pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func RandomBuffer(size int) []byte {
	buffer := make([]byte, size)
	_, err := rand.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	return buffer
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[crand.Intn(len(letters))]

	}
	return string(b)
}

func Mangle(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = hexchar[crand.Intn(len(hexchar))]

	}
	return string(b)
}

func VarNumberLength(min, max int) string {
	var r string
	crand.Seed(time.Now().UnixNano())
	num := crand.Intn(max-min) + min
	n := num
	r = RandStringBytes(n)
	return r
}

func printHexOutput(input ...[]byte) {
	for _, i := range input {
		fmt.Println(hex.EncodeToString(i))
	}
}

func GenerateNumer(min, max int) int {
	crand.Seed(time.Now().UnixNano())
	num := crand.Intn(max-min) + min
	n := num
	return n

}

func CapLetter() string {
	n := 1
	b := make([]byte, n)
	for i := range b {
		b[i] = capletters[crand.Intn(len(capletters))]

	}
	return string(b)
}
