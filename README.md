# Package password

[![GoDoc](https://pkg.go.dev/github.com/archeopternix/password?status.svg)](https://pkg.go.dev/github.com/archeopternix/password)

install:
```
go get github.com/archeopternix/password
```

usage:
```
package main

import (
	"fmt"

	. "github.com/archeopternix/password"
)

func main() {
	// create a new instance of PasswordCrypter using a secret
	ncp := NewPasswordCrypter("samplepass")

	// call the encryption with the 'string' that should be encrypted
	cryptstr := ncp.EncryptString("Hello World!")
	fmt.Println("Encrypted string: " + cryptstr)

	fmt.Println("Decrypted string: " + ncp.DecryptString((cryptstr)))
}
```

## PasswordCrypter
PasswordCrypter is a helper for encrypting and decrypting passwords based on
AES encryption standard and stores the secret for further calls. The secret 
must be at minimum 6 characters long

## EncryptString
EncryptString encrypts a password string based on AES encryption standard
the PasswordCrypter has to be initialized with a passphrase first
```
func (pc PasswordCrypter) EncryptString(data string) (encodedstring string)
```
	
## DecryptString
DecryptString decrypts a password string based on AES encryption standard
the PasswordCrypter has to be initialized with a passphrase first
```
func (pc PasswordCrypter) DecryptString(data string) (plaintext string) 
```
