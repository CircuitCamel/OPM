package main

import (
	"fmt"
	cipher "opm/internal/crypto"
	"os"
)

func main() {
	key := []byte(os.Args[1])
	text := []byte(os.Args[2])

	ciphertext, err := cipher.Encrypt(key, text)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		fmt.Println(string(ciphertext))
	}

	plaintext, err := cipher.Decrypt(key, ciphertext)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		fmt.Println(string(plaintext))
	}

}
