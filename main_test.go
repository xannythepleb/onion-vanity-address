package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xannythepleb/onion-vanity-address/internal/assert"
	"github.com/xannythepleb/onion-vanity-address/internal/require"
)

func TestFixture(t *testing.T) {
	const fixture = "onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhdl5zid.onion"

	secretKeyBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hs_ed25519_secret_key"))
	require.NoError(t, err)

	secretKeyBytes = bytes.TrimPrefix(secretKeyBytes, []byte(secretKeyFilePrefix))
	require.Equal(t, 64, len(secretKeyBytes))

	publicKeyBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hs_ed25519_public_key"))
	require.NoError(t, err)

	expectedPublicKey := bytes.TrimPrefix(publicKeyBytes, []byte(publicKeyFilePrefix))
	require.Equal(t, 32, len(expectedPublicKey))

	secretKey := secretKeyBytes[:32]
	t.Logf("Secret key: %s", onionBase32Encoding.EncodeToString(secretKey))

	publicKey, err := publicKeyFor(secretKey)
	require.NoError(t, err)

	t.Logf("Public key: %s", onionBase32Encoding.EncodeToString(publicKey))

	assert.Equal(t, expectedPublicKey, publicKey)

	onionAddress := encodeOnionAddress(publicKey)
	assert.Equal(t, fixture, onionAddress)

	hostnameBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hostname"))
	require.NoError(t, err)

	assert.Equal(t, []byte(fixture+"\n"), hostnameBytes)
}

func TestStart9ServiceSecretKeyEncoding(t *testing.T) {
	const fixture = "onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhdl5zid.onion"

	secretKeyBytes, err := os.ReadFile(filepath.Join("testdata", fixture, secretKeyFileName))
	require.NoError(t, err)

	secretKeyBytes = bytes.TrimPrefix(secretKeyBytes, []byte(secretKeyFilePrefix))
	secretKey := secretKeyBytes[:32]

	encoded := encodeStart9ServiceSecretKey(secretKey)
	assert.Equal(t, 88, len(encoded))
	assert.True(t, strings.HasSuffix(encoded, "=="))

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, expandServiceSecretKey(secretKey), decoded)
}

func TestWriteServiceKeyTorFiles(t *testing.T) {
	const fixture = "onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhdl5zid.onion"

	secretFile, err := os.ReadFile(filepath.Join("testdata", fixture, secretKeyFileName))
	require.NoError(t, err)
	publicFile, err := os.ReadFile(filepath.Join("testdata", fixture, publicKeyFileName))
	require.NoError(t, err)

	secretKey := bytes.TrimPrefix(secretFile, []byte(secretKeyFilePrefix))[:32]
	publicKey := bytes.TrimPrefix(publicFile, []byte(publicKeyFilePrefix))

	cwd, err := os.Getwd()
	require.NoError(t, err)
	tmp := t.TempDir()
	require.NoError(t, os.Chdir(tmp))
	defer func() { require.NoError(t, os.Chdir(cwd)) }()

	path, err := writeServiceKey(fixture, publicKey, secretKey, false)
	require.NoError(t, err)
	assert.Equal(t, fixture+string(os.PathSeparator), path)

	hostname, err := os.ReadFile(filepath.Join(fixture, hostnameFileName))
	require.NoError(t, err)
	assert.Equal(t, []byte(fixture+"\n"), hostname)

	writtenPublic, err := os.ReadFile(filepath.Join(fixture, publicKeyFileName))
	require.NoError(t, err)
	assert.Equal(t, serializeServicePublicKey(publicKey), writtenPublic)

	writtenSecret, err := os.ReadFile(filepath.Join(fixture, secretKeyFileName))
	require.NoError(t, err)
	assert.Equal(t, serializeServiceSecretKey(secretKey), writtenSecret)
}

func TestWriteServiceKeyStart9File(t *testing.T) {
	const fixture = "onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhdl5zid.onion"

	secretFile, err := os.ReadFile(filepath.Join("testdata", fixture, secretKeyFileName))
	require.NoError(t, err)
	secretKey := bytes.TrimPrefix(secretFile, []byte(secretKeyFilePrefix))[:32]

	cwd, err := os.Getwd()
	require.NoError(t, err)
	tmp := t.TempDir()
	require.NoError(t, os.Chdir(tmp))
	defer func() { require.NoError(t, os.Chdir(cwd)) }()

	path, err := writeServiceKey(fixture, nil, secretKey, true)
	require.NoError(t, err)
	assert.Equal(t, fixture, path)

	written, err := os.ReadFile(fixture)
	require.NoError(t, err)
	assert.Equal(t, encodeStart9ServiceSecretKey(secretKey), string(written))
}

func TestFormatCompactUint(t *testing.T) {
	assert.Equal(t, "999", formatCompactUint(999))
	assert.Equal(t, "1.5K", formatCompactUint(1500))
	assert.Equal(t, "56.4M", formatCompactUint(56353081))
	assert.Equal(t, "75.5B", formatCompactUint(75522209283))
}
