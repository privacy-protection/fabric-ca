package sw

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp"
	"github.com/privacy-protection/common/abe/protos/cpabe"
)

type cpabePrivateKey struct {
	key *cpabe.Key
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *cpabePrivateKey) Bytes() (raw []byte, err error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *cpabePrivateKey) SKI() []byte {
	if k.key == nil {
		return nil
	}

	// Marshall
	raw, err := proto.Marshal(k.key.Param)
	if err != nil {
		panic(err)
	}
	attrLen := len(k.key.Attribute)
	attrBytes := make([]byte, attrLen<<2)
	for i, attr := range k.key.Attribute {
		binary.BigEndian.PutUint32(attrBytes[i<<2:], uint32(attr))
	}

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	hash.Write(attrBytes)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *cpabePrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *cpabePrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *cpabePrivateKey) PublicKey() (bccsp.Key, error) {
	return &cpabeParams{k.key.Param}, nil
}

type cpabeMasterKey struct {
	key *cpabe.MasterKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *cpabeMasterKey) Bytes() (raw []byte, err error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *cpabeMasterKey) SKI() []byte {
	if k.key == nil {
		return nil
	}

	// Marshall
	raw, err := proto.Marshal(k.key.Param)
	if err != nil {
		panic(err)
	}

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *cpabeMasterKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *cpabeMasterKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *cpabeMasterKey) PublicKey() (bccsp.Key, error) {
	return &cpabeParams{k.key.Param}, nil
}

type cpabeParams struct {
	params *cpabe.Params
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (p *cpabeParams) Bytes() (raw []byte, err error) {
	raw, err = proto.Marshal(p.params)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling params [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (p *cpabeParams) SKI() []byte {
	if p.params == nil {
		return nil
	}

	// Marshall
	raw, err := proto.Marshal(p.params)
	panic(err)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (p *cpabeParams) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (p *cpabeParams) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (p *cpabeParams) PublicKey() (bccsp.Key, error) {
	return p, nil
}
