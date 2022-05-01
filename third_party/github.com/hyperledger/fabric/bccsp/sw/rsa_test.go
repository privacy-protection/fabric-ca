package sw

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRSAEncrypt(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data := []byte("hello world")
	encryptor := &rsaEncryptor{}
	ciphertext, err := encryptor.Encrypt(&rsaPublicKey{&privKey.PublicKey}, data, nil)
	require.NoError(t, err)

	decryptor := &rsaDecryptor{}
	plaintext, err := decryptor.Decrypt(&rsaPrivateKey{privKey}, ciphertext, nil)
	require.NoError(t, err)

	require.True(t, bytes.Equal(data, plaintext))
}
