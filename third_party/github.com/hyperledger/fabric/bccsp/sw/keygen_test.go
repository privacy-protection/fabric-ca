package sw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCPABEKeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &cpabeMasterKeyGenerator{}

	k, err := kg.KeyGen(nil)
	require.NoError(t, err)

	masterKey, ok := k.(*cpabeMasterKey)
	require.True(t, ok)
	require.NotNil(t, masterKey.key)
}
