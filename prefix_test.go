package main

import (
	"testing"

	"github.com/xannythepleb/onion-vanity-address/internal/assert"
)

func TestDecodePrefixBits(t *testing.T) {
	tests := []struct {
		input         string
		expectedBytes []byte
		expectedBits  int
	}{
		{
			input:         "7",
			expectedBytes: []byte{0b11111_000, 0, 0, 0, 0},
			expectedBits:  5,
		},
		{
			input:         "77",
			expectedBytes: []byte{0b11111_111, 0b11_00000_0, 0, 0, 0},
			expectedBits:  10,
		},
		{
			input:         "b",
			expectedBytes: []byte{0b00001_000, 0, 0, 0, 0},
			expectedBits:  5,
		},
		{
			input:         "ay",
			expectedBytes: []byte{0b00000_110, 0b00_00000_0, 0, 0, 0},
			expectedBits:  10,
		},
		{
			input:         "abc",
			expectedBytes: []byte{0b00000_000, 0b01_00010_0, 0, 0, 0},
			expectedBits:  15,
		},
		{
			input:         "ayay",
			expectedBytes: []byte{0b00000_110, 0b00_00000_1, 0b1000_0000, 0, 0},
			expectedBits:  20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			b, n, err := decodePrefixBits(tt.input, onionBase32Encoding)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBits, n)
			assert.Equal(t, tt.expectedBytes, b)
		})
	}
}

func TestStringMatcherModes(t *testing.T) {
	validate := func(string) error { return nil }

	prefix, err := stringMatcher([]string{"abc", "def"}, matchPrefix, validate)
	assert.NoError(t, err)
	assert.True(t, prefix("abcdef"))
	assert.False(t, prefix("xyzdef"))

	suffix, err := stringMatcher([]string{"abc", "def"}, matchSuffix, validate)
	assert.NoError(t, err)
	assert.True(t, suffix("xyzdef"))
	assert.False(t, suffix("defxyz"))

	both, err := stringMatcher([]string{"abc", "def"}, matchBoth, validate)
	assert.NoError(t, err)
	assert.True(t, both("abcdef"))
	assert.False(t, both("abcxyz"))
}

func TestMatchDescription(t *testing.T) {
	patterns := []string{"ab", "abc", "yz"}

	assert.Equal(t, "abc...", matchDescription(patterns, "abcdef", matchPrefix))
	assert.Equal(t, "...yz", matchDescription(patterns, "wxyz", matchSuffix))
	assert.Equal(t, "abc...yz", matchDescription(patterns, "abcxyz", matchBoth))
}

func TestAddressSuffixMatcherChecksBothSignBits(t *testing.T) {
	unsignedPublicKey := make([]byte, 32)
	signedPublicKey := append([]byte(nil), unsignedPublicKey...)
	signedPublicKey[31] |= 0x80

	unsignedBody := onionAddressBody(encodeOnionAddress(unsignedPublicKey))
	signedBody := onionAddressBody(encodeOnionAddress(signedPublicKey))
	assert.False(t, unsignedBody == signedBody)

	suffix := signedBody[len(signedBody)-8:]

	candidateMatch, err := addressMatcher([]string{suffix}, matchSuffix)
	assert.NoError(t, err)
	assert.True(t, candidateMatch(unsignedPublicKey))

	exactMatch, err := exactAddressMatcher([]string{suffix}, matchSuffix)
	assert.NoError(t, err)
	assert.False(t, exactMatch(unsignedPublicKey))
	assert.True(t, exactMatch(signedPublicKey))
}
