//  Copyright 2021-Present Couchbase, Inc.
//
//  Use of this software is governed by the Business Source License included
//  in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
//  in that file, in accordance with the Business Source License, use of this
//  software will be governed by the Apache License, Version 2.0, included in
//  the file licenses/APL2.txt.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/youmark/pkcs8"
)

// The following two APIs are modified versions of golang's crypto/tls APIs to
// accommodate PKCS#8 encrypted private keys ..
//  - https://pkg.go.dev/crypto/tls#LoadX509KeyPair
//  - https://pkg.go.dev/crypto/tls#X509KeyPair

func LoadX509KeyPair(certFile, keyFile string,
	privateKeyPassphrase []byte) (tls.Certificate, error) {
	if len(certFile) == 0 || len(keyFile) == 0 {
		err := fmt.Errorf("LoadX509KeyPair: cert/key files not available")
		return tls.Certificate{}, err
	}

	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		err = fmt.Errorf("LoadX509KeyPair: error reading cert, %v", err)
		return tls.Certificate{}, err
	}

	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("LoadX509KeyPair: error reading pkey, %v", err)
		return tls.Certificate{}, err
	}

	return x509KeyPair(certPEMBlock, keyPEMBlock, privateKeyPassphrase)
}

func x509KeyPair(certPEMBlock, keyPEMBlock, privateKeyPassphrase []byte) (
	tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	var cert tls.Certificate
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
			return fail(errors.New("x509KeyPair: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("x509KeyPair: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("x509KeyPair: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("x509KeyPair: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("x509KeyPair: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("x509KeyPair: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(fmt.Errorf("x509KeyPair: ParseCertificate returned err: %v", err))
	}

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes, privateKeyPassphrase)
	if err != nil {
		return fail(fmt.Errorf("x509KeyPair: parsePrivateKey returned err: %v", err))
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("x509KeyPair: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("x509KeyPair: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("x509KeyPair: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("x509KeyPair: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("x509KeyPair: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("x509KeyPair: private key does not match public key"))
		}
	default:
		return fail(errors.New("x509KeyPair: unknown public key algorithm"))
	}

	return cert, nil
}

// uses ParsePKCS8PrivateKey from youmark/pkcs8 package to add support for encrypted pkcs#8 private keys.
func parsePrivateKey(der, privateKeyPassphrase []byte) (crypto.PrivateKey, error) {
	// Adding some error logging in case none of the parseKey functions work
	// this would help in quickly finding issues with key being incorrect
	var errstr string
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	} else {
		errstr = err.Error()
	}
	// youmark ParsePKCS8PrivateKey in the stable version v1.1 that we use has a bug; it does not check correctly for nil passphrase
	// due to which it does not check for unencrypted pkcs8 key so we do it here.
	if len(privateKeyPassphrase) == 0 {
		if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			return key, nil
		} else {
			errstr += "; " + err.Error()
		}
	} else {
		if key, err := pkcs8.ParsePKCS8PrivateKey(der, privateKeyPassphrase); err == nil {
			switch key := key.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
				return key, nil
			default:
				return nil, fmt.Errorf("parsePrivateKey: unknown private key type")
			}
		} else {
			errstr += "; " + err.Error()
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	} else {
		errstr += "; " + err.Error()
	}
	return nil, fmt.Errorf("parsePrivateKey: failed to parse private key. Error: %v", errstr)
}
