package utils

import (
	"crypto/tls"
)

// ModernBrowserTLSConfig returns a tls.Config with cipher suites, curve preferences,
// and TLS versions custom-tailored to mimic modern web browsers (Chrome/Firefox),
// effectively spoofing default JA3/JA4 fingerprints to bypass automated network blacklists.
func ModernBrowserTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // required for scanner/prober
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		PreferServerCipherSuites: false,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		CipherSuites: []uint16{
			// TLS 1.3 Ciphers
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			// TLS 1.2 ECDHE Ciphers (Chrome-aligned preference order)
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}
