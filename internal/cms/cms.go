// Package cms wraps smallstep/pkcs7 for SCEP: it enforces an algorithm
// allowlist and separates "signature intact" from "signer trusted".
package cms

import (
	"crypto"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/smallstep/pkcs7"
)

// The library picks content encryption from a global defaulting to DES-CBC.
// Set once here: there is no per-call option and mutating it later would race.
// Reply envelopes for a 3DES request never touch this global — see
// EncryptWithAlg, which builds the 3DES envelope without the library.
func init() {
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
}

// ErrAlgorithmNotPermitted is returned when a message uses a digest outside the
// configured allowlist.
var ErrAlgorithmNotPermitted = errors.New("cms: digest algorithm not permitted")

// Digest OIDs, named so callers configure an allowlist without importing asn1.
var (
	SHA1   = pkcs7.OIDDigestAlgorithmSHA1
	SHA256 = pkcs7.OIDDigestAlgorithmSHA256
	SHA384 = pkcs7.OIDDigestAlgorithmSHA384
	SHA512 = pkcs7.OIDDigestAlgorithmSHA512
)

// DefaultDigests excludes SHA-1: it is collision-broken, so admitting it must
// be a recorded decision rather than a default.
var DefaultDigests = []asn1.ObjectIdentifier{SHA256, SHA384, SHA512}

// Verifier checks CMS SignedData against an algorithm allowlist.
type Verifier struct {
	// Digests permits these digest algorithms; empty means DefaultDigests.
	Digests []asn1.ObjectIdentifier
}

// Signed is a parsed, signature-verified CMS SignedData.
type Signed struct {
	// Content is the encapsulated payload.
	Content []byte
	// Signer is the certificate whose signature was verified. Whether that
	// certificate means anything depends on which verify call produced it.
	Signer *x509.Certificate
	// Chained is true when the signer was verified against a trust anchor.
	Chained bool

	p7 *pkcs7.PKCS7
}

// UnmarshalAttribute decodes an authenticated attribute into out. Only
// attributes covered by the verified signature are readable.
func (s *Signed) UnmarshalAttribute(oid asn1.ObjectIdentifier, out any) error {
	if s.p7 == nil {
		return errors.New("cms: no parsed message")
	}
	return s.p7.UnmarshalSignedAttribute(oid, out)
}

// VerifySignature checks the signature is intact but establishes NO trust — the
// signer may be self-signed. Correct for a PKCSReq; the Signer is not an identity.
func (v *Verifier) VerifySignature(der []byte) (*Signed, error) {
	p7, err := v.parse(der)
	if err != nil {
		return nil, err
	}
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("cms: signature verification failed: %w", err)
	}
	return v.signed(p7, false)
}

// VerifyChain also verifies the signer against roots, so an accepted signer IS
// an identity. Correct for a RenewalReq, whose signer is the device cert.
func (v *Verifier) VerifyChain(der []byte, roots *x509.CertPool) (*Signed, error) {
	if roots == nil {
		return nil, errors.New("cms: no trust anchor configured for this operation")
	}
	p7, err := v.parse(der)
	if err != nil {
		return nil, err
	}
	if err := p7.VerifyWithChain(roots); err != nil {
		return nil, fmt.Errorf("cms: signature or chain verification failed: %w", err)
	}
	return v.signed(p7, true)
}

// parse decodes the message and applies the algorithm allowlist before any
// signature is checked, so an unwanted algorithm costs nothing to reject.
func (v *Verifier) parse(der []byte) (*pkcs7.PKCS7, error) {
	if len(der) == 0 {
		return nil, errors.New("cms: empty message")
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("cms: parse: %w", err)
	}
	if len(p7.Signers) == 0 {
		return nil, errors.New("cms: message has no signers")
	}
	// Exactly one signer. SCEP defines a single signer per message, and
	// tolerating more invites confusion over which one was authenticated.
	if len(p7.Signers) > 1 {
		return nil, fmt.Errorf("cms: expected 1 signer, got %d", len(p7.Signers))
	}
	if err := v.checkDigest(p7.Signers[0].DigestAlgorithm.Algorithm); err != nil {
		return nil, err
	}
	return p7, nil
}

func (v *Verifier) checkDigest(oid asn1.ObjectIdentifier) error {
	allowed := v.Digests
	if len(allowed) == 0 {
		allowed = DefaultDigests
	}
	for _, a := range allowed {
		if a.Equal(oid) {
			return nil
		}
	}
	return fmt.Errorf("%w: %v", ErrAlgorithmNotPermitted, oid)
}

func (v *Verifier) signed(p7 *pkcs7.PKCS7, chained bool) (*Signed, error) {
	signer := p7.GetOnlySigner()
	if signer == nil {
		return nil, errors.New("cms: no signer certificate in message")
	}
	return &Signed{Content: p7.Content, Signer: signer, Chained: chained, p7: p7}, nil
}

// Decrypt opens an EnvelopedData addressed to cert. Runs an RSA private-key
// operation on unauthenticated input: callers must rate-limit and size-bound it.
func Decrypt(der []byte, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	if len(der) == 0 {
		return nil, errors.New("cms: empty enveloped message")
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("cms: parse enveloped: %w", err)
	}
	content, err := p7.Decrypt(cert, key)
	if err != nil {
		// Deliberately unwrapped: decryption failure detail is a padding-oracle
		// hint, so callers get an opaque error and log the cause themselves.
		return nil, errors.New("cms: decryption failed")
	}
	return content, nil
}

// Encrypt seals content to a single recipient as EnvelopedData, using the
// content-encryption algorithm pinned in init.
func Encrypt(content []byte, recipient *x509.Certificate) ([]byte, error) {
	return EncryptWithAlg(content, recipient, pkcs7.EncryptionAlgorithmAES256CBC)
}

// EncryptionAlg names a content-encryption algorithm for reply envelopes.
// smallstep/pkcs7's constants are untyped ints, so the alias is int.
type EncryptionAlg = int

// EncryptionAlgorithmDESEDE3CBC is absent from smallstep/pkcs7's encrypt
// constants (the library can decrypt 3DES but not encrypt it). It occupies an
// unused iota slot; the value is private to this process.
const EncryptionAlgorithmDESEDE3CBC = pkcs7.EncryptionAlgorithmAES256GCM + 1

// RFC 8894 §3.5: the reply SHALL be encrypted with the same content-encryption
// algorithm as the request. Apple's SCEP client (mdmclient) always sends
// 3DES — its own code says "SCEP doesn't support DES3 but we're going to use
// it anyway" — so a 3DES request must get a 3DES reply or the client cannot
// decrypt it. smallstep/pkcs7 can only DECRYPT 3DES (its Encrypt switch has no
// 3DES case), so the 3DES envelope is built here with the same wire format.
func EncryptWithAlg(content []byte, recipient *x509.Certificate, alg EncryptionAlg) ([]byte, error) {
	switch alg {
	case EncryptionAlgorithmDESEDE3CBC:
		return encryptDES3(content, recipient)
	default:
		// Unknown / unsupported request cipher: fall back to the pinned
		// default rather than inventing a reply cipher the client never
		// asked for.
		if recipient == nil {
			return nil, errors.New("cms: no recipient certificate")
		}
		der, err := pkcs7.Encrypt(content, []*x509.Certificate{recipient})
		if err != nil {
			return nil, fmt.Errorf("cms: encrypt: %w", err)
		}
		return der, nil
	}
}

// DetectContentAlg reports the content-encryption algorithm of a
// ContentInfo(EnvelopedData) message, as used in an SCEP request envelope.
// found is false when the algorithm is not recognized (or the shape is
// unexpected), in which case callers reply with the default cipher.
func DetectContentAlg(der []byte) (alg EncryptionAlg, found bool) {
	if len(der) == 0 {
		return 0, false
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return 0, false
	}
	var env struct {
		Version        int
		RecipientInfos asn1.RawValue `asn1:"set"`
		ECI            struct {
			ContentType                asn1.ObjectIdentifier
			ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
			EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
		}
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &env); err != nil {
		return 0, false
	}
	oid := env.ECI.ContentEncryptionAlgorithm.Algorithm
	switch {
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmDESEDE3CBC):
		return EncryptionAlgorithmDESEDE3CBC, true
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmAES256CBC):
		return pkcs7.EncryptionAlgorithmAES256CBC, true
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmAES128CBC):
		return pkcs7.EncryptionAlgorithmAES128CBC, true
	default:
		return 0, false
	}
}

// 3DES EnvelopedData, mirroring smallstep/pkcs7's wire format exactly
// (struct shapes, PKCS#1 v1.5 key transport, PKCS#7 block padding).
type des3IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type des3RecipientInfo struct {
	Version                int
	IssuerAndSerialNumber  des3IssuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type des3EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type des3EnvelopedData struct {
	Version              int
	RecipientInfos       []des3RecipientInfo `asn1:"set"`
	EncryptedContentInfo des3EncryptedContentInfo
}

type des3ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// encryptDES3 seals content as ContentInfo(EnvelopedData) with 3DES-CBC and an
// RSA PKCS#1 v1.5-wrapped 3DES key — the exact format Apple's SCEP client
// produces for its requests and expects in replies.
func encryptDES3(content []byte, recipient *x509.Certificate) ([]byte, error) {
	if recipient == nil {
		return nil, errors.New("cms: no recipient certificate")
	}
	pub, ok := recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cms: 3DES envelope needs an RSA recipient, got %T", recipient.PublicKey)
	}
	key := make([]byte, 24) // 3DES = 24-byte key (K3=K1 for 2-key variants)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("cms: 3des key: %w", err)
	}
	iv := make([]byte, des.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("cms: 3des iv: %w", err)
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cms: 3des cipher: %w", err)
	}
	padded := pkcs7Pad(content, block.BlockSize())
	if padded == nil {
		return nil, errors.New("cms: 3des padding failed")
	}
	enc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, padded)
	wrappedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	if err != nil {
		return nil, fmt.Errorf("cms: 3des key wrap: %w", err)
	}
	env := des3EnvelopedData{
		Version: 0,
		RecipientInfos: []des3RecipientInfo{{
			Version: 0,
			IssuerAndSerialNumber: des3IssuerAndSerial{
				IssuerName:   asn1.RawValue{FullBytes: recipient.RawIssuer},
				SerialNumber: recipient.SerialNumber,
			},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: pkcs7.OIDEncryptionAlgorithmRSA,
			},
			EncryptedKey: wrappedKey,
		}},
		EncryptedContentInfo: des3EncryptedContentInfo{
			ContentType: pkcs7.OIDData,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: pkcs7.OIDEncryptionAlgorithmDESEDE3CBC,
				Parameters: asn1.RawValue{
					Tag:   asn1.TagOctetString,
					Bytes: iv,
				},
			},
			EncryptedContent: marshalEncryptedContent(enc),
		},
	}
	inner, err := asn1.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("cms: 3des envelope: %w", err)
	}
	ci := des3ContentInfo{
		ContentType: pkcs7.OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner},
	}
	der, err := asn1.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("cms: 3des contentinfo: %w", err)
	}
	return der, nil
}

// pkcs7Pad pads a block-aligned buffer per PKCS#7 (RFC 5652 §6.3).
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

// marshalEncryptedContent wraps ciphertext in the primitive context tag [0]
// the library uses (IsCompound: false in smallstep/pkcs7 v0.2.2 — the bytes
// go directly under the tag, not inside an OCTET STRING).
func marshalEncryptedContent(content []byte) asn1.RawValue {
	return asn1.RawValue{Bytes: content, Class: 2, IsCompound: false}
}

// SignOptions configures Sign.
type SignOptions struct {
	// Attributes are authenticated attributes to embed (SCEP message type,
	// transaction ID, nonces).
	Attributes []Attribute
	// Digest selects the digest algorithm; zero uses SHA-256.
	Digest asn1.ObjectIdentifier
}

// Attribute is an authenticated attribute carried in the signature.
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value any
}

// Sign wraps content in SignedData signed by cert/key.
func Sign(content []byte, cert *x509.Certificate, key crypto.PrivateKey, opts SignOptions) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("cms: no signing certificate")
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("cms: new signed data: %w", err)
	}
	digest := opts.Digest
	if digest == nil {
		digest = SHA256
	}
	sd.SetDigestAlgorithm(digest)

	attrs := make([]pkcs7.Attribute, 0, len(opts.Attributes))
	for _, a := range opts.Attributes {
		attrs = append(attrs, pkcs7.Attribute{Type: a.Type, Value: a.Value})
	}
	cfg := pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}
	if err := sd.AddSigner(cert, key, cfg); err != nil {
		return nil, fmt.Errorf("cms: add signer: %w", err)
	}
	der, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("cms: finish: %w", err)
	}
	return der, nil
}

// DegenerateCertsOnly encodes certificates as a certs-only SignedData, the form
// SCEP GetCACert uses to carry the RA and CA certificates together.
func DegenerateCertsOnly(certs ...*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("cms: at least one certificate is required")
	}
	var der []byte
	for _, c := range certs {
		der = append(der, c.Raw...)
	}
	out, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cms: degenerate: %w", err)
	}
	return out, nil
}
