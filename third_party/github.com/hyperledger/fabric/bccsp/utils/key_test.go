package utils

import (
	"bytes"
	"testing"

	"github.com/privacy-protection/common/abe/protos/cpabe"
	"github.com/privacy-protection/cp-abe/core"
	"github.com/stretchr/testify/require"
)

func TestCPABEKey(t *testing.T) {
	masterKey, err := core.Init()
	require.NoError(t, err)

	b, err := PrivateKeyToPEM(masterKey, nil)
	require.NoError(t, err)

	k, err := PEMtoPrivateKey(b, nil)
	require.NoError(t, err)

	mk, ok := k.(*cpabe.MasterKey)
	require.True(t, ok)
	require.True(t, bytes.Equal(masterKey.Beta, mk.Beta))
	require.True(t, bytes.Equal(masterKey.GOneAlpha, mk.GOneAlpha))

	key, err := core.Generate(masterKey, []int32{1, 2})
	require.NoError(t, err)

	b, err = PrivateKeyToPEM(key, nil)
	require.NoError(t, err)

	k, err = PEMtoPrivateKey(b, nil)
	require.NoError(t, err)

	sk, ok := k.(*cpabe.Key)
	require.True(t, ok)
	for i := range sk.DOne {
		require.True(t, bytes.Equal(key.DOne[i], sk.DOne[i]))
	}
	for i := range sk.DOne {
		require.True(t, bytes.Equal(key.DTwo[i], sk.DTwo[i]))
	}
	require.True(t, bytes.Equal(key.D, sk.D))
}
