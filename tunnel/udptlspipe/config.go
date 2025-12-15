/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 AmneziaWG. All Rights Reserved.
 */

package udptlspipe

// Config represents the udptlspipe TLS wrapper configuration
type Config struct {
	// Enabled indicates whether udptlspipe is enabled for this peer
	Enabled bool

	// Password for authentication with the udptlspipe server
	Password string

	// TlsServerName for SNI (Server Name Indication)
	// If empty, the endpoint hostname will be used
	TlsServerName string

	// Secure enables TLS certificate verification
	Secure bool

	// Proxy URL (e.g., "socks5://user:pass@host:port")
	Proxy string

	// FingerprintProfile for TLS fingerprint evading
	// Valid values: "chrome", "firefox", "safari", "edge", "okhttp", "ios", "randomized"
	// Default is "okhttp"
	FingerprintProfile string
}

// IsValid returns true if the configuration is valid and can be used
func (c *Config) IsValid() bool {
	return c != nil && c.Enabled
}

// GetFingerprintProfile returns the fingerprint profile, defaulting to "okhttp"
func (c *Config) GetFingerprintProfile() string {
	if c.FingerprintProfile == "" {
		return "okhttp"
	}
	return c.FingerprintProfile
}
