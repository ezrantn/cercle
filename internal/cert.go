package internal

import "time"

type CertificateAnalysis struct {
	Hostname           string          `json:"hostname" yaml:"hostname"`
	IPAddress          string          `json:"ip_address" yaml:"ip_address"`
	Port               string          `json:"port" yaml:"port"`
	CertificateDetails *CertDetails    `json:"certificate" yaml:"certificate"`
	Vulnerabilities    []Vulnerability `json:"vulnerabilities" yaml:"vulnerabilities"`
}

type CertDetails struct {
	Subject       string    `json:"subject" yaml:"subject"`
	Issuer        string    `json:"issuer" yaml:"issuer"`
	NotBefore     time.Time `json:"not_before" yaml:"not_before"`
	NotAfter      time.Time `json:"not_after" yaml:"not_after"`
	DaysRemaining int       `json:"days_remaining" yaml:"days_remaining"`
	SignatureAlgo string    `json:"signature_algo" yaml:"signature_algo"`
	PublicKeyType string    `json:"public_key_type" yaml:"public_key_type"`
	PublicKeyBits int       `json:"public_key_bits" yaml:"public_key_bits"`
	SerialNumber  string    `json:"serial_number" yaml:"serial_number"`
}

type Vulnerability struct {
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description" yaml:"description"`
	Severity    string `json:"severity" yaml:"severity"`
}

type Config struct {
	Timeout            time.Duration `yaml:"timeout"`
	OutputFormat       string        `yaml:"output_format"`
	OutputFile         string        `yaml:"output_file"`
	LogLevel           string        `yaml:"log_level"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
}
