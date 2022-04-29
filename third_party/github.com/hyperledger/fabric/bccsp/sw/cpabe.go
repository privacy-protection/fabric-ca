package sw

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp"
	"github.com/privacy-protection/common/abe/protos/cpabe"
	"github.com/privacy-protection/cp-abe/core"
)

type cpabeEncryptor struct{}

func (e *cpabeEncryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	params := k.(*cpabeParams).params
	cpabeOpts, ok := opts.(*bccsp.CPABEEcnryptOpts)
	if !ok {
		return nil, fmt.Errorf("invalid opts, must be *bccsp.CPABEEcnryptOpts, but got %T", opts)
	}

	ciphertext, err := core.Encrypt(plaintext, cpabeOpts.Tree, params)
	if err != nil {
		return nil, fmt.Errorf("cpabe encrypt error, %v", err)
	}
	b, err := proto.Marshal(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("marshal Ciphertext error, %v", err)
	}
	return b, nil
}

type cpabeDecryptor struct{}

func (d *cpabeDecryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	key := k.(*cpabePrivateKey).key
	c := &cpabe.Ciphertext{}
	if err := proto.Unmarshal(ciphertext, c); err != nil {
		return nil, fmt.Errorf("unmarshal Ciphertext error, %v", err)
	}
	plaintext, err := core.Decrypt(key, c)
	if err != nil {
		return nil, fmt.Errorf("cpabe decrypt error, %v", err)
	}
	return plaintext, nil
}
