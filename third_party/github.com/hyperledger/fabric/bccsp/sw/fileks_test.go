package sw

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacy-protection/cp-abe/core"
	"github.com/stretchr/testify/require"
)

func TestCPABEKeyStore(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "bccspks")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	require.NoError(t, err)

	masterKey, err := core.Init()
	require.NoError(t, err)

	attributeID := []int32{0, 2}
	key, err := core.Generate(masterKey, attributeID)
	require.NoError(t, err)

	masterK := &cpabeMasterKey{masterKey}
	err = ks.StoreKey(masterK)
	require.NoError(t, err)
	kk, err := ks.GetKey(masterK.SKI())
	require.NoError(t, err)
	mk := kk.(*cpabeMasterKey).key
	require.True(t, bytes.Equal(masterKey.Beta, mk.Beta))
	require.True(t, bytes.Equal(masterKey.GOneAlpha, mk.GOneAlpha))

	privK := &cpabePrivateKey{key}
	err = ks.StoreKey(privK)
	require.NoError(t, err)
	kk, err = ks.GetKey(privK.SKI())
	require.NoError(t, err)
	sk := kk.(*cpabePrivateKey).key
	for i := range sk.DOne {
		require.True(t, bytes.Equal(key.DOne[i], sk.DOne[i]))
	}
	for i := range sk.DOne {
		require.True(t, bytes.Equal(key.DTwo[i], sk.DTwo[i]))
	}
	require.True(t, bytes.Equal(key.D, sk.D))
}
