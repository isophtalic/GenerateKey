package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type AES struct{}

func (*AES) Encrypt(block cipher.Block, iv []byte, plaintext []byte) []byte {
	mode := cipher.NewCBCEncrypter(block, iv)

	plaintext = pad(plaintext, aes.BlockSize)

	cipherText := make([]byte, len(plaintext))

	mode.CryptBlocks(cipherText, plaintext)

	return cipherText
}

func (*AES) Decrypt(block cipher.Block, iv []byte, cipherText []byte) []byte {

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(cipherText))

	mode.CryptBlocks(plaintext, cipherText)

	plaintext = unPad(plaintext)

	return plaintext
}

// Generate a random 32-byte key for AES-256
func (*AES) GenerateKeyBYTES(numberKeyByte int) []byte {
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
func (*AES) MakeCipherBlock(key []byte) cipher.Block {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		er := fmt.Sprintf("Error creating cipher block: %s", err)
		panic(er)
	}
	return block
}

// Generate a random 16-byte IV (Initialization Vector)
func (*AES) GenerateInitializationVector() []byte {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		er := fmt.Sprintf("Error generating IV: %s", err)
		panic(er)
	}
	return iv
}

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func unPad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
