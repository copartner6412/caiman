package caiman_test

import (
	"crypto/rand"
	"crypto/subtle"
	"testing"

	"github.com/copartner6412/caiman"
)

func setRandomMasterKeyFor(f *testing.F, c *caiman.Crypt) {
	f.Helper()
	key := make([]byte, 32) // Assuming AES-256, so a 32-byte key
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("Failed to generate random master key: %v", err)
	}

	c.SetMasterKey(key)
}

func setRandomMasterKey(f *testing.F) {
	f.Helper()
	key := make([]byte, 32) // Assuming AES-256, so a 32-byte key
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("Failed to generate random master key: %v", err)
	}

	caiman.SetMasterKey(key)
}

func FuzzPackageObject(f *testing.F) {
	c := caiman.NewCrypt()
	setRandomMasterKeyFor(f, c)
	f.Fuzz(func(t *testing.T, data []byte) {
		t.Parallel()
		if len(data) == 0 {
			t.Skip("Skipping empty input test case.")
		}

		encryptedData, err := c.Encrypt(data)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt the data
		decryptedData, err := c.Decrypt(encryptedData)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Compare original and decrypted data
		if subtle.ConstantTimeCompare(data, decryptedData) == 0 {
			t.Fatalf("Decrypted data does not match original data.\nOriginal: %v\nDecrypted: %v", data, decryptedData)
		}
	})
}

func FuzzPackageDefault(f *testing.F) {
	setRandomMasterKey(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		t.Parallel()
		if len(data) == 0 {
			t.Skip("Skipping empty input test case.")
		}

		encryptedData, err := caiman.Encrypt(data)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt the data
		decryptedData, err := caiman.Decrypt(encryptedData)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Compare original and decrypted data
		if subtle.ConstantTimeCompare(data, decryptedData) == 0 {
			t.Fatalf("Decrypted data does not match original data.\nOriginal: %v\nDecrypted: %v", data, decryptedData)
		}
	})
}
