package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPasswordCrypterSuccess(t *testing.T) {
	npc := NewPasswordCrypter("123456")
	if npc.passphrase != "123456" {
		t.Errorf("The password is not matching. Expected: '123456' provided: %v", npc.passphrase)
	} else {
		t.Logf("The passwords are matching.")
	}
}

func TestNewPasswordCrypterFail(t *testing.T) {
	if assert.Panics(t, func() { NewPasswordCrypter("123") }, "The code did panic") {
		t.Logf("Expected panic due to violated password policy.")
	}
}

func TestEncryptString(t *testing.T) {
	ncp := NewPasswordCrypter("samplepass")
	cryptstr := ncp.EncryptString("Hello World!")
	if ncp.DecryptString(cryptstr) != "Hello World!" {
		t.Errorf("Encrypted strings are not matching. Expected(decrypted): 'Hello World!' provided: %v", ncp.DecryptString(cryptstr))
	} else {
		t.Logf("Encrypted strings are matching.")
	}
}

func TestDecryptString(t *testing.T) {
	ncp := NewPasswordCrypter("samplepass")
	decryptstr := ncp.DecryptString("3cdefbaafff866061aa702c34c20379aedd39a747bda0081515f9c78ad33b134390dcaf199bdb613")
	if decryptstr != "Hello World!" {
		t.Errorf("Decrypted strings are not matching. Expected: 'Hello World!' provided: %v", decryptstr)
	} else {
		t.Logf("Decrypted strings are matching.")
	}
}

func TestDecryptStringFail(t *testing.T) {
	ncp := NewPasswordCrypter("samplepass")
	decryptstr := ncp.DecryptString("cdefbaafff866061aa702c34c20379aedd39a747bda0081515f9c78ad33b134390dcaf199bdb613")
	if len(decryptstr) < 1 {
		t.Logf("Expected outcome: decryption failed.")
	} else {
		t.Errorf("Decryption should have been failed. Corrupt decrypt string")
	}
}
