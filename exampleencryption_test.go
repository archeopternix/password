package password

import (
	"fmt"
)

func Example() {
	ncp := NewCrypter("samplepass")
	cryptstr := ncp.EncryptString("Hello World!")

	fmt.Println(ncp.DecryptString(cryptstr))
	// Output: Hello World!
}

func ExampleCryperDecryptString() {
	ncp := NewCrypter("samplepass")

	decryptstr := ncp.DecryptString("3cdefbaafff866061aa702c34c20379aedd39a747bda0081515f9c78ad33b134390dcaf199bdb613")

	fmt.Println(decryptstr)
	// Output: Hello World!

}
