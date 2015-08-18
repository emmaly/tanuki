package tanuki

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
)

var registrationDirectory = "/tmp/tanuki-registration"

func init() {
	err := os.MkdirAll(registrationDirectory, os.FileMode(0755))
	if err != nil {
		panic(err)
	}
}

// RegisterService is NOT how this will be done in the end.  This is just some duct tape to hold things together until we get a real key registration service going. FIXME!
func RegisterService(service string, serviceURL string, publicKey *rsa.PublicKey) error {
	fingerprint := PublicKeyFingerprint(publicKey)
	publicKeyMarshaled, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(registrationDirectory, fingerprint.String()+".key"), publicKeyMarshaled, os.FileMode(0644))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(registrationDirectory, fingerprint.String()+".url"), []byte(serviceURL), os.FileMode(0644))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(registrationDirectory, service), []byte(fingerprint.String()), os.FileMode(0644))
	if err != nil {
		return err
	}
	return nil
}

// LookupService is NOT how this will be done in the end.  This is just some duct tape to hold things together until we get a real key registration service going. FIXME!
func LookupService(service string) (*rsa.PublicKey, string, error) {
	fingerprint, err := ioutil.ReadFile(filepath.Join(registrationDirectory, service))
	if err != nil {
		return nil, "", err
	}
	publicKeyMarshaled, err := ioutil.ReadFile(filepath.Join(registrationDirectory, string(fingerprint)+".key"))
	if err != nil {
		return nil, "", err
	}
	serviceURL, err := ioutil.ReadFile(filepath.Join(registrationDirectory, string(fingerprint)+".url"))
	if err != nil {
		return nil, "", err
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyMarshaled)
	if err != nil {
		return nil, "", err
	}
	return publicKey.(*rsa.PublicKey), string(serviceURL), nil
}

// RegisterPublicKey is NOT how this will be done in the end.  This is just some duct tape to hold things together until we get a real key registration service going. FIXME!
func RegisterPublicKey(publicKey *rsa.PublicKey) error {
	fingerprint := PublicKeyFingerprint(publicKey)
	publicKeyMarshaled, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(registrationDirectory, fingerprint.String()+".key"), publicKeyMarshaled, os.FileMode(0644))
	if err != nil {
		return err
	}
	return nil
}

// LookupPublicKey is NOT how this will be done in the end.  This is just some duct tape to hold things together until we get a real key registration service going. FIXME!
func LookupPublicKey(fingerprint string) (*rsa.PublicKey, error) {
	publicKeyMarshaled, err := ioutil.ReadFile(filepath.Join(registrationDirectory, fingerprint+".key"))
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyMarshaled)
	if err != nil {
		return nil, err
	}
	return publicKey.(*rsa.PublicKey), nil
}
