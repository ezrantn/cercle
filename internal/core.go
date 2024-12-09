package internal

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)

func AnalyzeCertificate(hostname, port string, config *Config) (*CertificateAnalysis, error) {
	dialer := &net.Dialer{
		Timeout: config.Timeout,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	address := net.JoinHostPort(hostname, port)
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	mainCert := certs[0]
	now := time.Now()

	var pubKeyBits int
	var pubKeyType string
	switch key := mainCert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubKeyBits = key.N.BitLen()
		pubKeyType = "RSA"
	case *ecdsa.PublicKey:
		pubKeyBits = key.Curve.Params().BitSize
		pubKeyType = "ECDSA"
	}

	ips, _ := net.LookupIP(hostname)
	ipAddress := ""
	if len(ips) > 0 {
		ipAddress = ips[0].String()
	}

	vulnerabilities := checkVulnerabilities(state, mainCert)

	return &CertificateAnalysis{
		Hostname:  hostname,
		IPAddress: ipAddress,
		Port:      port,
		CertificateDetails: &CertDetails{
			Subject:       mainCert.Subject.String(),
			Issuer:        mainCert.Issuer.String(),
			NotBefore:     mainCert.NotBefore,
			NotAfter:      mainCert.NotAfter,
			DaysRemaining: int(mainCert.NotAfter.Sub(now).Hours() / 24),
			SignatureAlgo: mainCert.SignatureAlgorithm.String(),
			PublicKeyType: pubKeyType,
			PublicKeyBits: pubKeyBits,
			SerialNumber:  mainCert.SerialNumber.String(),
		},
		Vulnerabilities: vulnerabilities,
	}, nil
}

func checkVulnerabilities(state tls.ConnectionState, cert *x509.Certificate) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	if state.Version < tls.VersionTLS12 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "TLS Version",
			Description: "Outdated TLS version detected",
			Severity:    "HIGH",
		})
	}

	daysRemaining := int(time.Until(time.Now()).Hours() / 24)
	if daysRemaining <= 30 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Certificate Expiration",
			Description: fmt.Sprintf("Certificate expires in %d days", daysRemaining),
			Severity:    "MEDIUM",
		})
	}

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Key Strength",
				Description: "RSA key less than 2048 bits",
				Severity:    "HIGH",
			})
		}
	}

	return vulnerabilities
}

func OutputResults(analysis *CertificateAnalysis, config *Config) error {
	switch config.OutputFormat {
	case "json":
		return outputJSON(analysis, config.OutputFile)
	case "yaml":
		return outputYAML(analysis, config.OutputFile)
	default:
		return outputText(analysis)
	}
}

func outputJSON(analysis *CertificateAnalysis, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", " ")
	return encoder.Encode(analysis)
}

func outputYAML(analysis *CertificateAnalysis, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create YAML file: %v", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()
	return encoder.Encode(analysis)
}

func outputText(analysis *CertificateAnalysis) error {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("🔒 SSL Certificate Analysis for %s\n", green(analysis.Hostname))
	fmt.Printf("IP Address: %s\n", analysis.IPAddress)
	fmt.Printf("Port: %s\n\n", analysis.Port)

	cert := analysis.CertificateDetails
	fmt.Printf("Certificate Details:\n")
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Issuer: %s\n", cert.Issuer)
	fmt.Printf("  Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("  Public Key: %s (%d bits)\n", cert.PublicKeyType, cert.PublicKeyBits)
	fmt.Printf("  Signature Algorithm: %s\n\n", cert.SignatureAlgo)

	fmt.Printf("Validity:\n")
	fmt.Printf("  Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After:  %s\n", cert.NotAfter.Format(time.RFC3339))

	if cert.DaysRemaining <= 30 {
		fmt.Printf("  Expires In: %s days %s\n\n",
			red(fmt.Sprintf("%d", cert.DaysRemaining)),
			red("⚠️ EXPIRING SOON"),
		)
	} else {
		fmt.Printf("  Expires In: %s days\n\n", green(fmt.Sprintf("%d", cert.DaysRemaining)))
	}

	if len(analysis.Vulnerabilities) > 0 {
		fmt.Printf("Vulnerabilities:\n")
		for _, vuln := range analysis.Vulnerabilities {
			severityColor := yellow
			if vuln.Severity == "HIGH" {
				severityColor = red
			}
			fmt.Printf("  - %s [%s]: %s\n",
				severityColor(vuln.Type),
				severityColor(vuln.Severity),
				vuln.Description,
			)
		}
	}

	return nil
}
