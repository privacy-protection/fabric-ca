/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	_ "time" // for ocspSignerFromConfig

	"github.com/hyperledger/fabric-ca/lib/attrmgr"
	"github.com/hyperledger/fabric-ca/lib/cpabe"
	_ "github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/cli" // for ocspSignerFromConfig
	"github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/config"
	"github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/helpers"
	"github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/log"
	_ "github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/ocsp" // for ocspSignerFromConfig
	"github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/third_party/github.com/cloudflare/cfssl/signer/local"
	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp/factory"
	cspsigner "github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric-ca/third_party/github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
	abeutils "github.com/privacy-protection/common/abe/utils"
)

// GetDefaultBCCSP returns the default BCCSP
func GetDefaultBCCSP() bccsp.BCCSP {
	return factory.GetDefault()
}

// InitBCCSP initializes BCCSP
func InitBCCSP(optsPtr **factory.FactoryOpts, mspDir, homeDir string) (bccsp.BCCSP, error) {
	err := ConfigureBCCSP(optsPtr, mspDir, homeDir)
	if err != nil {
		return nil, err
	}
	csp, err := GetBCCSP(*optsPtr, homeDir)
	if err != nil {
		return nil, err
	}
	return csp, nil
}

// GetBCCSP returns BCCSP
func GetBCCSP(opts *factory.FactoryOpts, homeDir string) (bccsp.BCCSP, error) {

	// Get BCCSP from the opts
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get BCCSP with opts")
	}
	return csp, nil
}

// makeFileNamesAbsolute makes all relative file names associated with CSP absolute,
// relative to 'homeDir'.
func makeFileNamesAbsolute(opts *factory.FactoryOpts, homeDir string) error {
	var err error
	if opts != nil && opts.SwOpts != nil && opts.SwOpts.FileKeystore != nil {
		fks := opts.SwOpts.FileKeystore
		fks.KeyStorePath, err = MakeFileAbs(fks.KeyStorePath, homeDir)
	}
	return err
}

// BccspBackedSigner attempts to create a signer using csp bccsp.BCCSP. This csp could be SW (golang crypto)
// PKCS11 or whatever BCCSP-conformant library is configured
func BccspBackedSigner(caFile, keyFile string, policy *config.Signing, csp bccsp.BCCSP) (signer.Signer, error) {
	_, cspSigner, parsedCa, err := GetSignerFromCertFile(caFile, csp)
	if err != nil {
		// Fallback: attempt to read out of keyFile and import
		log.Debugf("No key found in BCCSP keystore, attempting fallback")
		var key bccsp.Key
		var signer crypto.Signer

		key, err = ImportBCCSPKeyFromPEM(keyFile, csp, false)
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Could not find the private key in BCCSP keystore nor in keyfile '%s'", keyFile))
		}

		signer, err = cspsigner.New(csp, key)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
		}
		cspSigner = signer
	}

	signer, err := local.NewSigner(cspSigner, parsedCa, signer.DefaultSigAlgo(cspSigner), policy)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create new signer")
	}
	return signer, nil
}

// BccspBackedCPABEMasterKey attempts to get the master key using csp bccsp.BCCSP.
func BccspBackedCPABEMasterKey(certFile string, csp bccsp.BCCSP) (bccsp.Key, error) {
	// Get the params
	params, err := BccspBackedCPABEParams(certFile, csp)
	if err != nil {
		return nil, fmt.Errorf("backed cpabe params error, %v", err)
	}
	if params == nil {
		return nil, nil
	}
	// Get the cpabe master key
	return csp.GetKey(params.SKI())
}

// BccspBackedCPABEPrivateKey attempts to get the private key using csp bccsp.BCCSP.
func BccspBackedCPABEPrivateKey(certFile string, csp bccsp.BCCSP) (bccsp.Key, error) {
	// Load cert file
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read file error, %v", err)
	}
	// Parse certificate
	parsedCert, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate error, %v", err)
	}
	// Get cpabe params and attribute id
	var paramsBytes []byte
	var attributeID []int32
	for _, extensions := range parsedCert.Extensions {
		if extensions.Id.String() == cpabe.ParamsOIDString {
			paramsBytes = extensions.Value
		}
		if extensions.Id.String() == attrmgr.AttrOIDString {
			attrs := &attrmgr.Attributes{}
			if err := json.Unmarshal(extensions.Value, attrs); err != nil {
				return nil, fmt.Errorf("unmarshal Attributes error, %v", err)
			}
			keys := []string{}
			for key := range attrs.Attrs {
				keys = append(keys, key)
			}
			sort.Sort(sort.StringSlice(keys))
			for _, key := range keys {
				attrString := fmt.Sprintf("%s.%s", key, attrs.Attrs[key])
				attributeID = append(attributeID, int32(abeutils.Hash(attrString)))
			}
		}
	}
	if paramsBytes == nil {
		log.Warningf("The certificate in [%s] not support cpabe", certFile)
		return nil, nil
	}
	// Marshall
	raw := paramsBytes
	attrLen := len(attributeID)
	attrBytes := make([]byte, attrLen<<2)
	for i, attr := range attributeID {
		binary.BigEndian.PutUint32(attrBytes[i<<2:], uint32(attr))
	}
	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	hash.Write(attrBytes)
	ski := hash.Sum(nil)
	// Get the cpabe private key
	return csp.GetKey(ski)
}

// BccspBackedCPABEParams attempts to get the params using csp bccsp.BCCSP.
func BccspBackedCPABEParams(certFile string, csp bccsp.BCCSP) (bccsp.Key, error) {
	// Load cert file
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read file error, %v", err)
	}
	// Parse certificate
	parsedCert, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate error, %v", err)
	}
	// Get cpabe params
	var paramsBytes []byte
	for _, extensions := range parsedCert.Extensions {
		if extensions.Id.String() == cpabe.ParamsOIDString {
			paramsBytes = extensions.Value
		}
	}
	if paramsBytes == nil {
		log.Warningf("The certificate in [%s] not support cpabe", certFile)
		return nil, nil
	}
	// Import the cpabe params
	params, err := csp.KeyImport(paramsBytes, &bccsp.CPABEParamsImportOpts{Temporary: true})
	if err != nil {
		return nil, fmt.Errorf("import params error, %v", err)
	}
	return params, nil
}

// getBCCSPKeyOpts generates a key as specified in the request.
// This supports ECDSA and RSA.
func getBCCSPKeyOpts(kr *csr.KeyRequest, ephemeral bool) (opts bccsp.KeyGenOpts, err error) {
	if kr == nil {
		return &bccsp.ECDSAKeyGenOpts{Temporary: ephemeral}, nil
	}
	log.Debugf("generate key from request: algo=%s, size=%d", kr.Algo(), kr.Size())
	switch kr.Algo() {
	case "rsa":
		switch kr.Size() {
		case 2048:
			return &bccsp.RSA2048KeyGenOpts{Temporary: ephemeral}, nil
		case 3072:
			return &bccsp.RSA3072KeyGenOpts{Temporary: ephemeral}, nil
		case 4096:
			return &bccsp.RSA4096KeyGenOpts{Temporary: ephemeral}, nil
		default:
			// Need to add a way to specify arbitrary RSA key size to bccsp
			return nil, errors.Errorf("Invalid RSA key size: %d", kr.Size())
		}
	case "ecdsa":
		switch kr.Size() {
		case 256:
			return &bccsp.ECDSAP256KeyGenOpts{Temporary: ephemeral}, nil
		case 384:
			return &bccsp.ECDSAP384KeyGenOpts{Temporary: ephemeral}, nil
		case 521:
			// Need to add curve P521 to bccsp
			// return &bccsp.ECDSAP512KeyGenOpts{Temporary: false}, nil
			return nil, errors.New("Unsupported ECDSA key size: 521")
		default:
			return nil, errors.Errorf("Invalid ECDSA key size: %d", kr.Size())
		}
	default:
		return nil, errors.Errorf("Invalid algorithm: %s", kr.Algo())
	}
}

// GetSignerFromCert load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCert(cert *x509.Certificate, csp bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	if csp == nil {
		return nil, nil, errors.New("CSP was not initialized")
	}
	// get the public key in the right format
	certPubK, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to import certificate's public key")
	}
	// Get the key given the SKI value
	ski := certPubK.SKI()
	privateKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Could not find matching private key for SKI")
	}
	// BCCSP returns a public key if the private key for the SKI wasn't found, so
	// we need to return an error in that case.
	if !privateKey.Private() {
		return nil, nil, errors.Errorf("The private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(ski))
	}
	// Construct and initialize the signer
	signer, err := cspsigner.New(csp, privateKey)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to load ski from bccsp")
	}
	return privateKey, signer, nil
}

// GetSignerFromCertFile load skiFile and load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCertFile(certFile string, csp bccsp.BCCSP) (bccsp.Key, crypto.Signer, *x509.Certificate, error) {
	// Load cert file
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "Could not read certFile '%s'", certFile)
	}
	// Parse certificate
	parsedCa, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	// Get the signer from the cert
	key, cspSigner, err := GetSignerFromCert(parsedCa, csp)
	return key, cspSigner, parsedCa, err
}

// BCCSPKeyRequestGenerate generates keys through BCCSP
// somewhat mirroring to cfssl/req.KeyRequest.Generate()
func BCCSPKeyRequestGenerate(req *csr.CertificateRequest, myCSP bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	log.Infof("generating key: %+v", req.KeyRequest)
	keyOpts, err := getBCCSPKeyOpts(req.KeyRequest, false)
	if err != nil {
		return nil, nil, err
	}
	key, err := myCSP.KeyGen(keyOpts)
	if err != nil {
		return nil, nil, err
	}
	cspSigner, err := cspsigner.New(myCSP, key)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
	}
	return key, cspSigner, nil
}

// CPABEMasterKeyGenerate generates the cpabe master key, and returns the key and the params
func CPABEMasterKeyGenerate(myCSP bccsp.BCCSP) (bccsp.Key, string, error) {
	// Generate the cpabe master key
	k, err := myCSP.KeyGen(&bccsp.CPABEKeyGenOpts{Temporary: false})
	if err != nil {
		return nil, "", fmt.Errorf("bccsp generate cpabe master key error, %v", err)
	}
	// Get the cpabe params
	params, err := k.PublicKey()
	if err != nil {
		return nil, "", fmt.Errorf("get the cpabe params from master key error, %v", err)
	}
	// Marshal the cpabe params
	paramsBytes, err := params.Bytes()
	if err != nil {
		return nil, "", fmt.Errorf("marshal cpabe params error, %v", err)
	}
	return k, hex.EncodeToString(paramsBytes), nil
}

// ImportBCCSPKeyFromPEM attempts to create a private BCCSP key from a pem file keyFile
func ImportBCCSPKeyFromPEM(keyFile string, myCSP bccsp.BCCSP, temporary bool) (bccsp.Key, error) {
	keyBuff, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := utils.PEMtoPrivateKey(keyBuff, nil)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed parsing private key from %s", keyFile))
	}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		priv, err := utils.PrivateKeyToDER(key)
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Failed to convert ECDSA private key for '%s'", keyFile))
		}
		sk, err := myCSP.KeyImport(priv, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: temporary})
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Failed to import ECDSA private key for '%s'", keyFile))
		}
		return sk, nil
	case *rsa.PrivateKey:
		return nil, errors.Errorf("Failed to import RSA key from %s; RSA private key import is not supported", keyFile)
	default:
		return nil, errors.Errorf("Failed to import key from %s: invalid secret key type", keyFile)
	}
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
//
// This function originated from crypto/tls/tls.go and was adapted to use a
// BCCSP Signer
func LoadX509KeyPair(certFile, keyFile string, csp bccsp.BCCSP) (*tls.Certificate, error) {

	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{}
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.Errorf("Failed to find PEM block in file %s", certFile)
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.Errorf("Failed to find certificate PEM data in file %s, but did find a private key; PEM inputs may have been switched", certFile)
		}
		return nil, errors.Errorf("Failed to find \"CERTIFICATE\" PEM block in file %s after skipping PEM blocks of the following types: %v", certFile, skippedBlockTypes)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	_, cert.PrivateKey, err = GetSignerFromCert(x509Cert, csp)
	if err != nil {
		if keyFile != "" {
			log.Debugf("Could not load TLS certificate with BCCSP: %s", err)
			log.Debugf("Attempting fallback with certfile %s and keyfile %s", certFile, keyFile)
			fallbackCerts, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrapf(err, "Could not get the private key %s that matches %s", keyFile, certFile)
			}
			cert = &fallbackCerts
		} else {
			return nil, errors.WithMessage(err, "Could not load TLS certificate with BCCSP")
		}

	}

	return cert, nil
}

// EncryptData encrypts the data using the public key
func EncryptData(pk interface{}, data []byte, csp bccsp.BCCSP) ([]byte, error) {
	k, err := csp.KeyImport(pk, &bccsp.PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, fmt.Errorf("import public key error, %v", err)
	}
	b, err := csp.Encrypt(k, data, nil)
	if err != nil {
		return nil, fmt.Errorf("csp encrypt error, %v", err)
	}
	return b, nil
}
