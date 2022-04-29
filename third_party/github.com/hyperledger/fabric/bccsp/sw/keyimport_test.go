package sw

import (
	"encoding/pem"
	"testing"

	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp/utils"
	"github.com/privacy-protection/cp-abe/core"
	"github.com/stretchr/testify/require"
)

func TestCPABEKeyImport(t *testing.T) {
	masterKey, err := core.Init()
	require.NoError(t, err)

	attributeID := []int32{0, 2}
	key, err := core.Generate(masterKey, attributeID)
	require.NoError(t, err)

	ki := &cpabePrivateKeyImportOptsKeyImporter{}

	b, err := utils.PrivateKeyToPEM(masterKey, nil)
	require.NoError(t, err)
	block, _ := pem.Decode(b)
	require.NoError(t, err)
	k, err := ki.KeyImport(block.Bytes, nil)
	require.NoError(t, err)
	_, ok := k.(*cpabeMasterKey)
	require.True(t, ok)

	b, err = utils.PrivateKeyToPEM(key, nil)
	require.NoError(t, err)
	block, _ = pem.Decode(b)
	require.NoError(t, err)
	k, err = ki.KeyImport(block.Bytes, nil)
	require.NoError(t, err)
	_, ok = k.(*cpabePrivateKey)
	require.True(t, ok)

}
