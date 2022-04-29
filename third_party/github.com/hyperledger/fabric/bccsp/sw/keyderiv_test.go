package sw

import (
	"testing"

	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp"
	"github.com/stretchr/testify/require"
)

func TestCPABEKeyDeriver(t *testing.T) {
	t.Parallel()

	kg := &cpabeMasterKeyGenerator{}

	k, err := kg.KeyGen(nil)
	require.NoError(t, err)

	masterKey, ok := k.(*cpabeMasterKey)
	require.True(t, ok)
	require.NotNil(t, masterKey.key)

	kd := &cpabeMasterKeyDeriver{}
	k, err = kd.KeyDeriv(k, &bccsp.CPABEDeriverOpts{
		AttributeID: []int32{1, 2},
		Temporary:   true,
	})
	privateKey, ok := k.(*cpabePrivateKey)
	require.True(t, ok)
	require.NotNil(t, privateKey.key)
}
