// PasswordCrypter: is a helper for encrypting and decrypting passwords based on
// AES encryption standard
//
// usage:
// 	func main() {
//		// create a new instance of PasswordCrypter using a secret
//		ncp := NewPasswordCrypter("samplepass")
//		// call the encryption with the 'password' that should be encrypted
//		cryptstr := ncp.EncryptString("Hello World!")
//	}
//
// The secret must be at minimum 6 characters long
//
package password

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

// PasswordCrypter is a helper for encrypting and decrypting passwords based on
// AES encryption standard
type PasswordCrypter struct {
	passphrase string // holds the secret passphrase
}

// NewPasswordCrypter creates a new instance of PasswordCrypter with a new secret string.
// the length of the secret passphrase must be at lease 6 characters long
func NewPasswordCrypter(secretpassphrase string) (pc PasswordCrypter) {

	if len(secretpassphrase) < 6 {
		log.Panic("Length of passphrase is too short (less than 6 characters)")
	}
	pc = PasswordCrypter{passphrase: secretpassphrase}

	return pc
}

// createHash hashes a key and returns the hexadecimal representation
func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// encrypt a []byte array using a passphrase and returns the encrypted []byte array
func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panicf("Encrypt Cipher: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Panicf("Nonce: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// decrypt a []byte array using a passphrase and and returns the decrypted []byte array
func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panicf("Get Cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panicf("Decrypt Cipher: %v", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Panicf("Decrypt Message: %v", err)
	}
	return plaintext
}

// EncryptString encrypts a password string based on AES encryption standard
// the PasswordCrypter has to be initialized with a passphrase first
func (pc PasswordCrypter) EncryptString(data string) (encodedstring string) {
	ciphertext := encrypt([]byte(data), pc.passphrase)
	encoded := hex.EncodeToString(ciphertext)

	return encoded
}

// DecryptString decrypts a password string based on AES encryption standard
// the PasswordCrypter has to be initialized with a passphrase first
func (pc PasswordCrypter) DecryptString(data string) (plaintext string) {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		log.Printf("Decrypt String failed: %v", err)
		return ""
	}
	plain := decrypt(decoded, pc.passphrase)

	return string(plain)
}
