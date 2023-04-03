// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/url"

	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.

const GenerateTestData = false

// Information supplied by the UVM specific to running Pod

type UvmInformation struct {
	EncodedSecurityPolicy   string  // customer security policy
	CertChain               string  // platform certificates for the actual physical host, ascii PEM
	VCEKURL                 url.URL //The location to fetch updated VCEK certificates
	EncodedUvmReferenceInfo string  // endorsements for the particular UVM image
}

//GetVCEK returns the certificate chain
func (u UvmInformation) GetVCEK() string {
	return u.CertChain
}

//RefreshVCEK fetches a new VCEK from the configured source and stores it in the local cache
func (u *UvmInformation) RefreshVCEK() error {
	return nil
}

//ErrNoVCEKCertFound is returned if the cached certificate does not include a VCEK leaf certificate
var ErrNoVCEKCertFound error = errors.New("No PEM Certificate found encoded in VCEK chain")

//GetVCEKCertificate returns the parsed certificate for the cached VCEK
func (u *UvmInformation) GetVCEKCertificate() (*x509.Certificate, error) {
	byteChain := []byte(u.CertChain)
	var cert *x509.Certificate
	for len(byteChain) > 0 {
		var p *pem.Block
		p, byteChain = pem.Decode(byteChain)
		if p == nil {
			return nil, ErrNoVCEKCertFound
		}
		if p.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}

		if cert.Subject.CommonName != "SEV-VCEK" { //https://www.amd.com/system/files/TechDocs/57230.pdf page 13
			cert = nil
		}
	}
	if cert == nil {
		return nil, ErrNoVCEKCertFound
	}
	return nil, nil
}

// format of the json provided to the UVM by hcsshim. Comes fro the THIM endpoint
// and is a base64 encoded json string

type THIMCerts struct {
	VcekCert         string `json:"vcekCert"`
	Tcbm             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

func THIMtoPEM(encodedHostCertsFromTHIM string) (string, error) {
	hostCertsFromTHIM, err := base64.StdEncoding.DecodeString(encodedHostCertsFromTHIM)
	if err != nil {
		return "", errors.Wrapf(err, "base64 decoding platform certs failed")
	}

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.json", hostCertsFromTHIM, 0644)
	}

	var certsFromTHIM THIMCerts
	err = json.Unmarshal(hostCertsFromTHIM, &certsFromTHIM)
	if err != nil {
		return "", errors.Wrapf(err, "json unmarshal platform certs failed")
	}

	certsString := certsFromTHIM.VcekCert + certsFromTHIM.CertificateChain

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.pem", []byte(certsString), 0644)
	}

	logrus.Debugf("certsFromTHIM:\n\n%s\n\n", certsString)

	return certsString, nil
}

func GetUvmInfomation() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation
	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		certChain, err := THIMtoPEM(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
		encodedUvmInformation.CertChain = certChain
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")

	if GenerateTestData {
		ioutil.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		ioutil.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
	}

	return encodedUvmInformation, nil
}
