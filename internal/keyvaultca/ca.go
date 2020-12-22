/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keyvaultca

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
)

// Global constants.
const (
	triggerErrorsAPS = "triggererrors"
)

// KeyVaultCA is a mock, non-production certificate authority useful for testing
// purposes only.
type KeyVaultCA struct {
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

	return nil, nil
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
		// switch csr.Subject.CommonName {
		// case "Trigger Error Forbidden":
		// 	return nil, caError{
		// 		status: http.StatusForbidden,
		// 		desc:   "triggered forbidden response",
		// 	}

		// case "Trigger Error Deferred":
		// 	return nil, caError{
		// 		status:     http.StatusAccepted,
		// 		desc:       "triggered deferred response",
		// 		retryAfter: 600,
		// 	}

		// case "Trigger Error Unknown":
		// 	return nil, errors.New("triggered error")
		// }
	}

	// cert, err := x509.ParseCertificate(der)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to parse certificate: %w", err)
	// }

	// return cert, nil

	return nil, nil
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
