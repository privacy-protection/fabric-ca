/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp/utils"
)

func signECDSA(k *ecdsa.PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}

	s, err = utils.ToLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func verifyECDSA(k *ecdsa.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := utils.IsLowS(k, s)
	if err != nil {
		return false, err
	}

	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, utils.GetCurveHalfOrdersAt(k.Curve))
	}

	return ecdsa.Verify(k, digest, r, s), nil
}

type ecdsaSigner struct{}

func (s *ecdsaSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signECDSA(k.(*ecdsaPrivateKey).privKey, digest, opts)
}

type ecdsaPrivateKeyVerifier struct{}

func (v *ecdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyECDSA(&(k.(*ecdsaPrivateKey).privKey.PublicKey), signature, digest, opts)
}

type ecdsaPublicKeyKeyVerifier struct{}

func (v *ecdsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyECDSA(k.(*ecdsaPublicKey).pubKey, signature, digest, opts)
}

type ecdsaEncryptor struct{}

func (e *ecdsaEncryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	pubKey := k.(*ecdsaPublicKey).pubKey
	eciesPubKey := &ecies.PublicKey{
		X:      pubKey.X,
		Y:      pubKey.Y,
		Curve:  pubKey.Curve,
		Params: ecies.ParamsFromCurve(pubKey.Curve),
	}
	ciphertext, err := ecies.Encrypt(rand.Reader, eciesPubKey, plaintext, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("ecies encrypt error, %v", err)
	}
	return ciphertext, nil
}

type ecdsaDecryptor struct{}

func (d *ecdsaDecryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	privKey := k.(*ecdsaPrivateKey).privKey
	eciesPrivKey := &ecies.PrivateKey{
		D: privKey.D,
		PublicKey: ecies.PublicKey{
			X:      privKey.X,
			Y:      privKey.Y,
			Curve:  privKey.Curve,
			Params: ecies.ParamsFromCurve(privKey.Curve),
		},
	}
	plaintext, err := eciesPrivKey.Decrypt(ciphertext, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("ecies decrypt error, %v", err)
	}
	return plaintext, nil
}
