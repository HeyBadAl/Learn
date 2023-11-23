package main

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("examplekey123456")
	password := "userPassword123"

	// Encrypt the password
	encryptedPassword, err := encrypt([]byte(password), key)
	if err != nil {
		t.Fatalf("Encryption error: %v", err)
	}

	// Convert the encrypted password to base64 for storage or transmission
	encodedPassword := base64.StdEncoding.EncodeToString(encryptedPassword)

	// Decrypt the password
	decodedPassword, err := base64.StdEncoding.DecodeString(encodedPassword)
	if err != nil {
		t.Fatalf("Base64 decoding error: %v", err)
	}

	decryptedPassword, err := decrypt(decodedPassword, key)
	if err != nil {
		t.Fatalf("Decryption error: %v", err)
	}

	// Print debug information
	fmt.Printf("Original password: %v\n", []byte(password))
	fmt.Printf("Decrypted password: %v\n", decryptedPassword)

	// Ensure the decrypted password matches the original password
	if !reflect.DeepEqual([]byte(password), decryptedPassword) {
		t.Fatal("Decrypted password does not match original password")
	}
}

