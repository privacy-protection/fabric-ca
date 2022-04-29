package sw

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp"
	"github.com/privacy-protection/common/abe/protos/common"
	"github.com/privacy-protection/cp-abe/core"
	"github.com/stretchr/testify/require"
)

func TestCPABEEncrypt(t *testing.T) {
	masterKey, err := core.Init()
	require.NoError(t, err)

	attributeID := []int32{0, 2}
	key, err := core.Generate(masterKey, attributeID)
	require.NoError(t, err)

	tree := &common.Tree{
		Father:    []int32{0, 0, 1, 1},
		Threshold: []int32{2, 1, 0, 0, 0},
		LeafId:    []int32{2, 3, 4},
		Leaf: []*common.Leaf{
			&common.Leaf{AttributeId: 0},
			&common.Leaf{AttributeId: 1},
			&common.Leaf{AttributeId: 2},
		},
	}

	data := []byte("hello world")
	encryptor := &cpabeEncryptor{}
	ciphertext, err := encryptor.Encrypt(&cpabeParams{key.Param}, data, &bccsp.CPABEEcnryptOpts{tree})
	require.NoError(t, err)

	decryptor := &cpabeDecryptor{}
	plaintext, err := decryptor.Decrypt(&cpabePrivateKey{key}, ciphertext, nil)
	require.NoError(t, err)

	require.True(t, bytes.Equal(data, plaintext))
}
