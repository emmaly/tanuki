package tanuki

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"encoding/binary"
	"strings"

	"golang.org/x/crypto/sha3"
)

// KeyFingerprint represents the fingerprint of the rsa.PublicKey
type KeyFingerprint []byte

// NewPrivateKey returns an rsa.PrivateKey (defaulting to 4096 if ≤ 0)
func NewPrivateKey(bits int) (*rsa.PrivateKey, error) {
	if bits <= 0 {
		bits = 4096
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	RegisterPublicKey(privateKey.Public().(*rsa.PublicKey))
	return privateKey, nil
}

// PublicKeyFingerprint returns a Bumble-specific SHA256 fingerprint of the rsa.PublicKey
func PublicKeyFingerprint(pk *rsa.PublicKey) KeyFingerprint {
	// FIXME: This is possibly crap and absolutely needs to be tested!  I have not tested that the below does what I think it should be doing.
	// This is based on the method public keys are formatted in OpenSSL for use in ~/.ssh/authorized_keys files, et al
	h := sha3.NewShake256()
	fpType := "bumble-rsa"
	binary.Write(h, binary.BigEndian, binary.Size(fpType))
	binary.Write(h, binary.BigEndian, fpType)
	binary.Write(h, binary.BigEndian, binary.Size(pk.E))
	binary.Write(h, binary.BigEndian, pk.E)
	binary.Write(h, binary.BigEndian, binary.Size(pk.N.Bytes()))
	h.Write(pk.N.Bytes()) // this is BigEndian coming from (*big.Int).Bytes()
	out := make([]byte, 64)
	h.Read(out)
	return out
	//return h.Sum(nil)
}

func (pkf *KeyFingerprint) String() string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(*pkf), "=")
}
