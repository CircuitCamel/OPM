package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	derivedKey := sha256.Sum256(key)
	text := plaintext

	c, err := aes.NewCipher(derivedKey[:])

	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("unable to create cipher")
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("unable to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)

	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("unable to create nonce")
	}

	return gcm.Seal(nonce, nonce, text, nil), nil
}

func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	// Derive the same 32-byte key from the input key
	derivedKey := sha256.Sum256(key)

	block, err := aes.NewCipher(derivedKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the nonce from the beginning of the ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
