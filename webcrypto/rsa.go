package webcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"

	"github.com/grafana/sobek"
)

// RsaKeyAlgorithm describes the algorithm for which RSA key can be used in the [specification]
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#RsaKeyAlgorithm-dictionary
type RsaKeyAlgorithm struct {
	KeyAlgorithm

	// The length, in bits, of the RSA modulus
	ModulusLength uint64 `js:"modulusLength"`

	// A `Uint8Array` of the RSA public exponent. The `Uint8Array` (a BigInteger) holds an arbitrary
	// magnitude unsigned integer in big-endian order.
	PublicExponent sobek.ArrayBuffer `js:"publicExponent"`
}

// RsaHashedKeyAlgorithm describes
type RsaHashedKeyAlgorithm struct {
	RsaKeyAlgorithm

	// Hash holds the hash algorithm that is used with this key
	// You can use any of the following:
	//   * [Sha256]
	//   * [Sha384]
	//   * [Sha512]
	Hash Algorithm `js:"hash"`
}

// RsaHashedImportParams represents the object that should be passed as the algorithm
// parameter into `SubtleCrypto.ImportKey` or `SubtleCrypto.UnwrapKey`, when importing
// any RSA-based key pair: that is, when the algorithm is identified as any of RSASSA-PKCS1-v1_5
// RSA-PSS, or RSA-OAEP.
type RsaHashedImportParams struct {
	Algorithm

	// Hash holds (a string) the hash algorithm to use
	Hash HashAlgorithmIdentifier `js:"hash"`

	// newArrayBuffer if a function that creates a js `ArrayBuffer`.`
	// RSA-based CryptoKey requires the `PublicExponent` represented as `Uint8Array`,
	// one approach is to store a pointer to `sobek.Runtime`, another approach is to
	// store a func that captures `sobek.Runtime` internally and return `ArrayBuffer`.
	// FIXME: is there a better way? e.g. Can `PublicExponent` be `[]byte`?
	newArrayBuffer func([]byte) sobek.ArrayBuffer
}

func newRsaHashedImportParams(rt *sobek.Runtime, normalized Algorithm, params sobek.Value) (*RsaHashedImportParams, error) {
	hash, err := traverseObject(rt, params, "hash")
	if err != nil {
		return nil, NewError(SyntaxError, "could not get hash from algorithm parameter")
	}

	return &RsaHashedImportParams{
		Algorithm: normalized,
		Hash:      HashAlgorithmIdentifier(hash.String()),
		newArrayBuffer: func(b []byte) sobek.ArrayBuffer {
			return rt.NewArrayBuffer(b)
		},
	}, nil
}

// Ensure that RsaHashedImportParams implements the KeyImporter interface
var _ KeyImporter = (*RsaHashedImportParams)(nil)

// ImportKey imports a key according to the algorithm described in the specification
// https://www.w3.org/TR/WebCryptoAPI/#rsassa-pkcs1-operations
func (r *RsaHashedImportParams) ImportKey(
	format string,
	keyData []byte,
	keyUsages []string,
) (*CryptoKey, error) {
	var importFn func(keyData []byte, keyUsages []string) (any, CryptoKeyType, *rsa.PublicKey, error)
	switch {
	case r.Algorithm.Name == RSASsaPkcs1v15 && format == Pkcs8KeyFormat:
		importFn = importRSAPrivateKey
	case r.Algorithm.Name == RSASsaPkcs1v15 && format == SpkiKeyFormat:
		importFn = importRSAPublicKey
	case r.Algorithm.Name == RSASsaPkcs1v15 && format == JwkKeyFormat:
		importFn = importRSAJWK
	case r.Algorithm.Name == RSAPss && format == Pkcs8KeyFormat:
		importFn = importRSAPrivateKey
	case r.Algorithm.Name == RSAPss && format == SpkiKeyFormat:
		importFn = importRSAPublicKey
	case r.Algorithm.Name == RSAPss && format == JwkKeyFormat:
		importFn = importRSAJWK
	case r.Algorithm.Name == RSAOaep && format == Pkcs8KeyFormat:
		importFn = importRSAPrivateKey
	case r.Algorithm.Name == RSAOaep && format == SpkiKeyFormat:
		importFn = importRSAPublicKey
	case r.Algorithm.Name == RSAOaep && format == JwkKeyFormat:
		importFn = importRSAJWK
	default:
		return nil, NewError(NotSupportedError, unsupportedKeyFormatErrorMsg+" "+format+" for algorithm "+r.Algorithm.Name)
	}

	handle, keyType, publicKey, err := importFn(keyData, keyUsages)
	if err != nil {
		return nil, err
	}

	return &CryptoKey{
		Algorithm: RsaHashedKeyAlgorithm{
			RsaKeyAlgorithm: RsaKeyAlgorithm{
				KeyAlgorithm: KeyAlgorithm{
					Algorithm: r.Algorithm,
				},
				ModulusLength:  publicKey.N.Uint64(),
				PublicExponent: r.newArrayBuffer(big.NewInt(int64(publicKey.E)).Bytes()),
			},
			Hash: Algorithm{
				Name: r.Hash,
			},
		},
		Type:   keyType,
		handle: handle,
	}, nil
}

func importRSAPublicKey(keyData []byte, keyUsages []string) (any, CryptoKeyType, *rsa.PublicKey, error) {
	// 2.1
	for _, usage := range keyUsages {
		switch usage {
		case VerifyCryptoKeyUsage:
			continue
		default:
			return nil, UnknownCryptoKeyType, nil, NewError(SyntaxError, "invalid key usage: "+usage)
		}
	}

	parsedKey, err := x509.ParsePKIXPublicKey(keyData)
	if err != nil {
		return nil, UnknownCryptoKeyType, nil, NewError(DataError, "unable to import RSA public key data: "+err.Error())
	}

	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, UnknownCryptoKeyType, nil, NewError(DataError, "a public key is not an RSA key")
	}

	return rsaKey, PublicCryptoKeyType, rsaKey, nil
}

func importRSAPrivateKey(keyData []byte, keyUsages []string) (any, CryptoKeyType, *rsa.PublicKey, error) {
	// 2.1
	for _, usage := range keyUsages {
		switch usage {
		case SignCryptoKeyUsage:
			continue
		default:
			return nil, UnknownCryptoKeyType, nil, NewError(SyntaxError, "invalid key usage: "+usage)
		}
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, UnknownCryptoKeyType, nil, NewError(DataError, "unable to import RSA private key data: "+err.Error())
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, UnknownCryptoKeyType, nil, NewError(DataError, "a private key is not an RSA key")
	}

	handle := rsaKey
	return handle, PrivateCryptoKeyType, &rsaKey.PublicKey, nil
}

func importRSAJWK(keyDate []byte, keyUsages []string) (any, CryptoKeyType, *rsa.PublicKey, error) {
	panic("unimplemented")
}

type RsaKeyGenParams struct {
	Algorithm

	// The length, in bits, of the RSA modulus
	ModulusLength uint64 `js:"modulusLength"`

	// A `Uint8Array` of the RSA public exponent. The `Uint8Array` (a BigInteger) holds an arbitrary
	// magnitude unsigned integer in big-endian order.
	PublicExponent sobek.ArrayBuffer `js:"publicExponent"`
}

type RsaHashedKeyGenParams struct {
	RsaKeyGenParams

	// Hash holds (a string) the hash algorithm to use
	Hash HashAlgorithmIdentifier `js:"hash"`
}

type rsaSsaPkcs1v15SignerVerifier struct{}

// Ensure tha rsaSsaPkcs1v15SignerVerifier impleemnts the SignerVerifier interface
var _ SignerVerifier = (*rsaSsaPkcs1v15SignerVerifier)(nil)

// Sign implements SignerVerifier.
func (r *rsaSsaPkcs1v15SignerVerifier) Sign(key CryptoKey, dataToSign []byte) ([]byte, error) {
	if key.Type != PrivateCryptoKeyType {
		return nil, NewError(InvalidAccessError, "key is not a valid RSA private key")
	}

	k, ok := key.handle.(*rsa.PrivateKey)
	if !ok {
		return nil, NewError(InvalidAccessError, "key is not a valid RSA private key")
	}

	hashName := key.Algorithm.(RsaHashedKeyAlgorithm).Hash.Name
	hash, ok := getCryptoHash(hashName)
	if !ok {
		return nil, NewError(NotSupportedError, "unsupported hash algorithm: "+hashName)
	}

	hasher := hash.New()
	hasher.Write(dataToSign)

	return rsa.SignPKCS1v15(rand.Reader, k, hash, hasher.Sum(nil))
}

// Verify implements SignerVerifier.
func (r *rsaSsaPkcs1v15SignerVerifier) Verify(key CryptoKey, signature []byte, dataToVerify []byte) (bool, error) {
	if key.Type != PublicCryptoKeyType {
		return false, NewError(InvalidAccessError, "key is not a valid RSA public key")
	}

	k, ok := key.handle.(*rsa.PublicKey)
	if !ok {
		return false, NewError(InvalidAccessError, "key is not a valid RSA public key")
	}

	hashName := key.Algorithm.(RsaHashedKeyAlgorithm).Hash.Name
	hash, ok := getCryptoHash(hashName)
	if !ok {
		return false, NewError(NotSupportedError, "unsupported hash algorithm: "+hashName)
	}

	hasher := hash.New()
	hasher.Write(dataToVerify)

	if err := rsa.VerifyPKCS1v15(k, hash, hasher.Sum(nil), signature); err != nil {
		return false, err
	}
	return true, nil
}

// RsaPssParams describes the params passed to the `RSA-PSS` sign and verify operations,
// as defined in the [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#RsaPssParams-dictionary
type RsaPssParams struct {
	Name AlgorithmIdentifier

	// SaltLength is the desired length of the random salt
	SaltLength uint64 `js:"saltLength"`
}

var _ SignerVerifier = (*RsaPssParams)(nil)

func newRsaPssParams(rt *sobek.Runtime, normalized Algorithm, params sobek.Value) (*RsaPssParams, error) {
	saltLengthValue, err := traverseObject(rt, params, "saltLength")
	if err != nil {
		return nil, NewError(SyntaxError, "could not get saltLength from algorithm parameter")
	}

	var saltLength uint64
	if err := rt.ExportTo(saltLengthValue, &saltLength); err != nil {
		return nil, NewError(SyntaxError, "saltLength cannot be interpreted as an unsigned long")
	}

	return &RsaPssParams{
		Name:       normalized.Name,
		SaltLength: saltLength,
	}, nil
}

// Sign implements SignerVerifier.
func (r *RsaPssParams) Sign(key CryptoKey, dataToSign []byte) ([]byte, error) {
	panic("unimplemented")
}

// Verify implements SignerVerifier.
func (r *RsaPssParams) Verify(key CryptoKey, signature []byte, dataToVerify []byte) (bool, error) {
	panic("unimplemented")
}
