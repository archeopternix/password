# Package password
## PasswordCrypter
PasswordCrypter is a helper for encrypting and decrypting passwords based on
AES encryption standard

usage:
```func main() {
// create a new instance of PasswordCrypter using a secret
ncp := NewPasswordCrypter("samplepass")
// call the encryption with the 'password' that should be encrypted
cryptstr := ncp.EncryptString("Hello World!")
}
```

The secret must be at minimum 6 characters long

## EncryptString
EncryptString encrypts a password string based on AES encryption standard
the PasswordCrypter has to be initialized with a passphrase first
```func (pc PasswordCrypter) EncryptString(data string) (encodedstring string)
```
	
## DecryptString
DecryptString decrypts a password string based on AES encryption standard
the PasswordCrypter has to be initialized with a passphrase first
```func (pc PasswordCrypter) DecryptString(data string) (plaintext string) 
```