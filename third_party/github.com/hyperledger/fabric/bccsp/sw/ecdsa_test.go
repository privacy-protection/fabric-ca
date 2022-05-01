package sw

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSAEncrypt(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("hello world")
	encryptor := &ecdsaEncryptor{}
	ciphertext, err := encryptor.Encrypt(&ecdsaPublicKey{&privKey.PublicKey}, data, nil)
	require.NoError(t, err)

	decryptor := &ecdsaDecryptor{}
	plaintext, err := decryptor.Decrypt(&ecdsaPrivateKey{privKey}, ciphertext, nil)
	require.NoError(t, err)

	require.True(t, bytes.Equal(data, plaintext))
}
