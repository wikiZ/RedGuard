/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: CreateSSL.go
 * @Time: 2022/5/8 12:51
 **/

package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"time"

	"RedGuard/core/parameter"
)

// GenerateSelfSignedCert Generate a self-signed CA certificate
// @param	cert	*parameter.Cert		Certificate Configuration
// NOTE: The *.aliyun.com certificate is used by default.
// You can customize the certificate information by initializing the configuration file
// By default, the certificate is stored in the cert-RSA directory in the tool directory
func GenerateSelfSignedCert(cert *parameter.Cert) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // Generating a key pair
	if err != nil {
		panic(err)
	}
	// Creating a Certificate Template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), // CA Certificate Serial number
		// Issuer information, same as consumer information
		Issuer: pkix.Name{},
		// Consumer certificate Information
		Subject: pkix.Name{
			CommonName:   cert.CommonName,             // Cert CommonName
			Locality:     []string{cert.Locality},     // Cert Locality
			Organization: []string{cert.Organization}, // Cert Organization
			Country:      []string{cert.Country},      // Cert Country
		},
		// Start time of validity
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365), // failure time
		// Indicates that the certificate is used for server authentication
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// User Optional name
	template.DNSNames = append(template.DNSNames, cert.DNSName...)
	// Create a certificate, where the second parameter is the same
	// the third parameter means that the certificate is self-certificate.
	// return value is DER encoded certificate
	certificate, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		panic(err)
	}
	// Place the resulting certificate into the pem.Block structure
	block := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   certificate,
	}
	// Encoded by PEM and written to disk files
	file, _ := os.Create("cert-rsa/ca.crt")
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	_ = pem.Encode(file, &block)
	// Put the key pair from the private key into the pem.Block structure
	block = pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(priv),
	}
	// Encoded by PEM and written to disk files
	file, _ = os.Create("cert-rsa/ca.key")
	_ = pem.Encode(file, &block)
}

func InitGenerateSelfSignedCert() {
	// Example Create a CA certificate storage directory
	if _, err := os.Stat("cert-rsa"); err != nil {
		_ = os.Mkdir("cert-rsa", 0766) // Directory permissions
	}
	var cert parameter.Cert
	cfg := InitConfig() // init config file object
	// Get the information in the configuration file
	cert.CommonName = ReadConfig(`cert`, `CommonName`, cfg)
	cert.Locality = ReadConfig(`cert`, `Locality`, cfg)
	cert.Organization = ReadConfig(`cert`, `Organization`, cfg)
	cert.DNSName = strings.Split(ReadConfig(`cert`, `DNSName`, cfg), `,`)
	cert.Country = ReadConfig(`cert`, `Country`, cfg)
	// Generate a self-signed certificate method
	GenerateSelfSignedCert(&cert)
	logger.Critical("A default SSL certificate is being generated for the reverse proxy...")
}
