package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
  "bytes"
)

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	plaintext = pkcs7Pad(plaintext, blockSize)

	ciphertext := make([]byte, blockSize+len(plaintext))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[blockSize:], plaintext)

	return ciphertext, nil
}

// pkcs7Pad pads the input to be a multiple of blockSize using PKCS7 padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpad the decrypted data
	ciphertext = pkcs7Unpad(ciphertext)

	return ciphertext, nil
}

// pkcs7Unpad removes PKCS#7 padding from the text.
func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

func main() {
	// Replace this key with a secure key of appropriate size (16, 24, or 32 bytes)
	key := []byte("examplekey123456")

	password := "userPassword123"

	// Encrypt the password
	encryptedPassword, err := encrypt([]byte(password), key)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	// Convert the encrypted password to base64 for storage or transmission
	encodedPassword := base64.StdEncoding.EncodeToString(encryptedPassword)
	fmt.Println("Encrypted password:", encodedPassword)

	// Decrypt the password
	decodedPassword, err := base64.StdEncoding.DecodeString(encodedPassword)
	if err != nil {
		fmt.Println("Base64 decoding error:", err)
		return
	}

	decryptedPassword, err := decrypt(decodedPassword, key)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted password:", string(decryptedPassword))
}

