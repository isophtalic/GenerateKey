package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func Encrypt(block cipher.Block, iv []byte, plaintext []byte) []byte {
	// Create a new AES cipher block mode for CBC encryption
	mode := cipher.NewCBCEncrypter(block, iv)

	// Create a buffer to hold the encrypted data
	cipherText := make([]byte, len(plaintext))

	// Perform the encryption
	mode.CryptBlocks(cipherText, plaintext)

	return cipherText
}

func Decrypt(block cipher.Block, iv []byte, cipherText []byte) []byte {
	// Create a new AES cipher block mode for CBC decryption
	mode := cipher.NewCBCDecrypter(block, iv)

	// Create a buffer to hold the decrypted data
	plaintext := make([]byte, len(cipherText))

	// Perform the decryption
	mode.CryptBlocks(plaintext, cipherText)

	return plaintext
}

// Generate a random 32-byte key for AES-256
func GenerateKeyBYTES(numberKeyByte int) []byte {
	var err error
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		er := fmt.Sprintf("Error generating key: %s", err)
		panic(er)
	}
	return key
}

// Create a new AES cipher block
func MakeCipherBlock(key []byte) cipher.Block {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		er := fmt.Sprintf("Error creating cipher block: %s", err)
		panic(er)
	}
	return block
}

// Generate a random 16-byte IV (Initialization Vector)
func GenerateInitializationVector() []byte {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		er := fmt.Sprintf("Error generating IV: %s", err)
		panic(er)
	}
	return iv
}
