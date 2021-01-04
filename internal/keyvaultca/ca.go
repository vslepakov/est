package keyvaultca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/globalsign/est"
)

// Global constants.
const (
	triggerErrorsAPS = "triggererrors"
	csrAttrsAPS      = "csrattrs"
)

// KeyVaultCA is a mock, non-production certificate authority useful for testing
// purposes only.
type KeyVaultCA struct {
	url string
}

// CACerts returns the CA certificates, unless the additional path segment is
// "triggererrors", in which case an error is returned for testing purposes.
func (ca *KeyVaultCA) CACerts(
	ctx context.Context,
	aps string,
	r *http.Request,
) ([]*x509.Certificate, error) {
	if aps == triggerErrorsAPS {
		return nil, errors.New("triggered error")
	}

	resp, err := http.Get(ca.url + "/KeyVault/cacerts")
	if err != nil {
		fmt.Println("HTTP call failed:", err)
		return nil, err
	}

	defer resp.Body.Close()

	// Success is indicated with 2xx status codes:
	statusOK := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !statusOK {
		fmt.Println("Non-OK HTTP status:", resp.StatusCode)
		// You may read / inspect response body
		return nil, fmt.Errorf("http: %v", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Read Body failed:", err)
		return nil, err
	}

	var certs []string
	if err := json.Unmarshal(body, &certs); err != nil {
		fmt.Println("Error:", err)
	}

	var caCerts []*x509.Certificate
	for _, cert := range certs {
		block, _ := pem.Decode([]byte(cert))
		if err != nil {
			return nil, fmt.Errorf("pem.Decode: %w", err)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		caCerts = append(caCerts, cert)
	}

	return caCerts, nil
}

// Enroll issues a new certificate with:
//   - a 90 day duration from the current time
//   - a randomly generated 128-bit serial number
//   - a subject and subject alternative name copied from the provided CSR
//   - a default set of key usages and extended key usages
//   - a basic constraints extension with cA flag set to FALSE
//
// unless the additional path segment is "triggererrors", in which case the
// following errors will be returned for testing purposes, depending on the
// common name in the CSR:
//
//   - "Trigger Error Forbidden", HTTP status 403
//   - "Trigger Error Deferred", HTTP status 202 with retry of 600 seconds
//   - "Trigger Error Unknown", untyped error expected to be interpreted as
//     an internal server error.
func (ca *KeyVaultCA) Enroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	// Process any requested triggered errors.
	if aps == triggerErrorsAPS {
		switch csr.Subject.CommonName {
		case "Trigger Error Forbidden":
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "triggered forbidden response",
			}

		case "Trigger Error Deferred":
			return nil, caError{
				status:     http.StatusAccepted,
				desc:       "triggered deferred response",
				retryAfter: 600,
			}

		case "Trigger Error Unknown":
			return nil, errors.New("triggered error")
		}
	}

	data := map[string]string{"certificateRequest": base64.StdEncoding.EncodeToString(csr.Raw), "issuerCertificateName": "ContosoRootCA"}
	json, _ := json.Marshal(data)

	resp, err := http.Post(ca.url+"/KeyVault/enroll", "application/json", bytes.NewBuffer(json))
	if err != nil {
		fmt.Println("HTTP call failed:", err)
		return nil, err
	}

	defer resp.Body.Close()

	// Success is indicated with 2xx status codes:
	statusOK := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !statusOK {
		fmt.Println("Non-OK HTTP status:", resp.StatusCode)
		// You may read / inspect response body
		return nil, fmt.Errorf("http: %v", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Read Body failed:", err)
		return nil, err
	}

	block, _ := pem.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("pem.Decode: %w", err)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Reenroll implements est.CA but simply passes the request through to Enroll.
func (ca *KeyVaultCA) Reenroll(
	ctx context.Context,
	cert *x509.Certificate,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	return ca.Enroll(ctx, csr, aps, r)
}

// CSRAttrs returns an empty sequence of CSR attributes, unless the additional
// path segment is:
//  - "csrattrs", in which case it returns the same example sequence described
//    in RFC7030 4.5.2; or
//  - "triggererrors", in which case an error is returned for testing purposes.
func (ca *KeyVaultCA) CSRAttrs(
	ctx context.Context,
	aps string,
	r *http.Request,
) (attrs est.CSRAttrs, err error) {
	switch aps {
	case csrAttrsAPS:
		attrs = est.CSRAttrs{
			OIDs: []asn1.ObjectIdentifier{
				{1, 2, 840, 113549, 1, 9, 7},
				{1, 2, 840, 10045, 4, 3, 3},
			},
			Attributes: []est.Attribute{
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}},
				},
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
				},
			},
		}

	case triggerErrorsAPS:
		err = errors.New("triggered error")
	}

	return attrs, err
}

// ServerKeyGen creates a new RSA private key and then calls Enroll. It returns
// the key in PKCS8 DER-encoding, unless the additional path segment is set to
// "pkcs7", in which case it is returned wrapped in a CMS SignedData structure
// signed by the CA certificate(s), itself wrapped in a CMS EnvelopedData
// encrypted with the pre-shared key "pseudohistorical". A "Bit-Size" HTTP
// header may be passed with the values 2048, 3072 or 4096.
func (ca *KeyVaultCA) ServerKeyGen(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, []byte, error) {

	return nil, nil, errors.New("Not Implemented")
}

// TPMEnroll requests a new certificate using the TPM 2.0 privacy-preserving
// protocol. An EK certificate chain with a length of at least one must be
// provided, along with the EK and AK public areas. The return values are an
// encrypted credential, a wrapped encryption key, and the certificate itself
// encrypted with the encrypted credential in AES 128 Galois Counter Mode
// inside a CMS EnvelopedData structure.
func (ca *KeyVaultCA) TPMEnroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	ekcerts []*x509.Certificate,
	ekPub, akPub []byte,
	aps string,
	r *http.Request,
) ([]byte, []byte, []byte, error) {

	return nil, nil, nil, errors.New("Not Implemented")
}

// New creates an instance of KeyVaultCA
func New(url string) (*KeyVaultCA, error) {
	return &KeyVaultCA{
		url: url,
	}, nil
}
