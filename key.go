package tanuki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"strings"
)

// KeyFingerprint represents the fingerprint of the rsa.PublicKey
type KeyFingerprint []byte

// NewPrivateKey returns an rsa.PrivateKey (defaulting to 4096 if ≤ 0)
func NewPrivateKey(bits int) (*rsa.PrivateKey, error) {
	if bits <= 0 {
		bits = 4096
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// PublicKeyFingerprint returns a Bumble-specific SHA256 fingerprint of the rsa.PublicKey
func PublicKeyFingerprint(pk *rsa.PublicKey) KeyFingerprint {
	// FIXME: This is possibly crap and absolutely needs to be tested!  I have not tested that the below does what I think it should be doing.
	// This is based on the method public keys are formatted in OpenSSL for use in ~/.ssh/authorized_keys files, et al
	h := sha256.New()
	fpType := "bumble-rsa"
	binary.Write(h, binary.BigEndian, binary.Size(fpType))
	binary.Write(h, binary.BigEndian, fpType)
	binary.Write(h, binary.BigEndian, binary.Size(pk.E))
	binary.Write(h, binary.BigEndian, pk.E)
	binary.Write(h, binary.BigEndian, binary.Size(pk.N.Bytes()))
	h.Write(pk.N.Bytes()) // this is BigEndian coming from (*big.Int).Bytes()
	return h.Sum(nil)
}

func (pkf *KeyFingerprint) String() string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(*pkf), "=")
}