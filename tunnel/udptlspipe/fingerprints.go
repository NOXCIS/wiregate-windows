/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 AmneziaWG. All Rights Reserved.
 */

package udptlspipe

import (
	"crypto/rand"
	"math/big"
	"strings"
	"sync"

	tls "github.com/refraction-networking/utls"
)

// FingerprintProfile represents a TLS fingerprint profile name
type FingerprintProfile string

const (
	// ProfileChrome mimics Google Chrome browser
	ProfileChrome FingerprintProfile = "chrome"
	// ProfileFirefox mimics Mozilla Firefox browser
	ProfileFirefox FingerprintProfile = "firefox"
	// ProfileSafari mimics Apple Safari browser
	ProfileSafari FingerprintProfile = "safari"
	// ProfileEdge mimics Microsoft Edge browser
	ProfileEdge FingerprintProfile = "edge"
	// ProfileOkhttp mimics Android okhttp library (default)
	ProfileOkhttp FingerprintProfile = "okhttp"
	// ProfileiOS mimics iOS app fingerprint
	ProfileiOS FingerprintProfile = "ios"
	// ProfileRandomized generates random fingerprint per connection
	ProfileRandomized FingerprintProfile = "randomized"
	// ProfileDefault uses okhttp for backward compatibility
	ProfileDefault FingerprintProfile = "default"
)

// fingerprintPair holds a matched TLS fingerprint and User-Agent
type fingerprintPair struct {
	clientHelloID tls.ClientHelloID
	userAgent     string
}

// Predefined fingerprint pairs that are always in sync
var fingerprintPairs = []fingerprintPair{
	{tls.HelloChrome_Auto, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
	{tls.HelloChrome_100, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"},
	{tls.HelloChrome_106_Shuffle, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36"},
	{tls.HelloFirefox_Auto, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"},
	{tls.HelloFirefox_105, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"},
	{tls.HelloSafari_Auto, "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"},
	{tls.HelloEdge_Auto, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"},
	{tls.HelloIOS_Auto, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"},
	{tls.HelloAndroid_11_OkHttp, "okhttp/4.12.0"},
}

// randomizedPairCache stores the current randomized pair for consistency within a session
var (
	randomizedPairMu    sync.RWMutex
	currentRandomPair   *fingerprintPair
	randomPairGenerated bool
)

// GetFingerprintPair returns a matched ClientHelloID and User-Agent for the given profile.
// For "randomized" profile, returns a consistent pair that was randomly selected.
func GetFingerprintPair(profile string) (tls.ClientHelloID, string) {
	switch FingerprintProfile(strings.ToLower(profile)) {
	case ProfileChrome:
		return tls.HelloChrome_Auto, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	case ProfileFirefox:
		return tls.HelloFirefox_Auto, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
	case ProfileSafari:
		return tls.HelloSafari_Auto, "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
	case ProfileEdge:
		return tls.HelloEdge_Auto, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
	case ProfileiOS:
		return tls.HelloIOS_Auto, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
	case ProfileRandomized:
		return getRandomizedPair()
	case ProfileOkhttp, ProfileDefault, "":
		return tls.HelloAndroid_11_OkHttp, "okhttp/4.12.0"
	default:
		// Unknown profile, default to okhttp
		return tls.HelloAndroid_11_OkHttp, "okhttp/4.12.0"
	}
}

// GetClientHelloID returns the utls.ClientHelloID for the given profile
func GetClientHelloID(profile string) tls.ClientHelloID {
	clientHelloID, _ := GetFingerprintPair(profile)
	return clientHelloID
}

// GetUserAgent returns an appropriate User-Agent for the given profile
func GetUserAgent(profile string) string {
	_, userAgent := GetFingerprintPair(profile)
	return userAgent
}

// getRandomizedPair returns a randomly selected but matched fingerprint pair.
// The pair is cached so repeated calls return the same pair within a session.
func getRandomizedPair() (tls.ClientHelloID, string) {
	randomizedPairMu.RLock()
	if randomPairGenerated && currentRandomPair != nil {
		pair := currentRandomPair
		randomizedPairMu.RUnlock()
		return pair.clientHelloID, pair.userAgent
	}
	randomizedPairMu.RUnlock()

	// Need to generate a new random pair
	randomizedPairMu.Lock()
	defer randomizedPairMu.Unlock()

	// Double-check after acquiring write lock
	if randomPairGenerated && currentRandomPair != nil {
		return currentRandomPair.clientHelloID, currentRandomPair.userAgent
	}

	// Select a random pair from our predefined list
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(fingerprintPairs))))
	if err != nil {
		// Fallback to okhttp on error
		currentRandomPair = &fingerprintPairs[len(fingerprintPairs)-1] // okhttp is last
	} else {
		pair := fingerprintPairs[idx.Int64()]
		currentRandomPair = &pair
	}
	randomPairGenerated = true

	return currentRandomPair.clientHelloID, currentRandomPair.userAgent
}

// ResetRandomizedPair clears the cached randomized pair, causing a new one to be
// selected on the next call. This can be called on reconnection to get a fresh fingerprint.
func ResetRandomizedPair() {
	randomizedPairMu.Lock()
	defer randomizedPairMu.Unlock()
	currentRandomPair = nil
	randomPairGenerated = false
}

// ValidProfiles returns the list of valid fingerprint profile names
func ValidProfiles() []string {
	return []string{"chrome", "firefox", "safari", "edge", "okhttp", "ios", "randomized"}
}

// IsValidProfile checks if the given profile name is valid
func IsValidProfile(profile string) bool {
	lower := strings.ToLower(profile)
	for _, valid := range ValidProfiles() {
		if lower == valid {
			return true
		}
	}
	// Also accept "default" and empty string
	return lower == "default" || lower == ""
}
