package tls

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cipher suites, extensions and signature algorithms of the example in the JA4 specification.
var (
	ja4SpecCiphers    = []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	ja4SpecExtensions = []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	ja4SpecSignatures = []tls.SignatureScheme{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
)

func TestJA4(t *testing.T) {
	testCases := []struct {
		desc     string
		hello    *tls.ClientHelloInfo
		expected string
	}{
		{
			desc: "specification example",
			hello: &tls.ClientHelloInfo{
				CipherSuites:      ja4SpecCiphers,
				Extensions:        ja4SpecExtensions,
				SignatureSchemes:  ja4SpecSignatures,
				SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
				SupportedProtos:   []string{"h2", "http/1.1"},
			},
			expected: "t13d1516h2_8daaf6152771_e5627efa2ab1",
		},
		{
			desc: "GREASE values are ignored",
			hello: &tls.ClientHelloInfo{
				CipherSuites:      append([]uint16{0x0a0a}, ja4SpecCiphers...),
				Extensions:        append([]uint16{0x1a1a}, append(ja4SpecExtensions, 0xfafa)...),
				SignatureSchemes:  append([]tls.SignatureScheme{0x2a2a}, ja4SpecSignatures...),
				SupportedVersions: []uint16{0x3a3a, tls.VersionTLS13, tls.VersionTLS12},
				SupportedProtos:   []string{"h2", "http/1.1"},
			},
			expected: "t13d1516h2_8daaf6152771_e5627efa2ab1",
		},
		{
			desc: "no signature algorithms",
			hello: &tls.ClientHelloInfo{
				CipherSuites:      ja4SpecCiphers,
				Extensions:        ja4SpecExtensions,
				SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
				SupportedProtos:   []string{"h2", "http/1.1"},
			},
			expected: "t13d1516h2_8daaf6152771_6d807ffa2a79",
		},
		{
			desc: "no SNI and no ALPN",
			hello: &tls.ClientHelloInfo{
				CipherSuites:      ja4SpecCiphers,
				Extensions:        []uint16{0x001b, 0x0033, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
				SignatureSchemes:  ja4SpecSignatures,
				SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
			},
			expected: "t13i151400_8daaf6152771_e5627efa2ab1",
		},
		{
			desc:     "empty hello",
			hello:    &tls.ClientHelloInfo{},
			expected: "t00i000000_000000000000_000000000000",
		},
		{
			desc: "more than 99 cipher suites",
			hello: &tls.ClientHelloInfo{
				CipherSuites:      make([]uint16, 120),
				SupportedVersions: []uint16{tls.VersionTLS12},
			},
			expected: "t12i990000_" + ja4Hash(bytes.Repeat([]byte("0000,"), 119), "0000") + "_000000000000",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.expected, JA4(test.hello))
		})
	}
}

// TestJA4_referenceClientHellos checks JA4 against ClientHellos from the pcap files of the reference implementation
// (https://github.com/FoxIO-LLC/ja4/tree/main/pcap), and the fingerprints it computes for them.
// The ClientHello records were extracted from the TCP streams of the pcap files.
func TestJA4_referenceClientHellos(t *testing.T) {
	testCases := []struct {
		fixture  string
		expected string
	}{
		{fixture: "chrome-h2.hex", expected: "t13d1516h2_8daaf6152771_e5627efa2ab1"},
		{fixture: "chrome-http11.hex", expected: "t13d1516h1_8daaf6152771_e5627efa2ab1"},
		{fixture: "chrome-no-alpn.hex", expected: "t13d151400_8daaf6152771_de4a06bb82e3"},
		// The first ALPN value is 0xBA 0xAD: the specification prints the hex characters "bd",
		// while the reference implementation prints "99" for non-ASCII characters.
		{fixture: "chrome-non-ascii-alpn.hex", expected: "t13d1516bd_8daaf6152771_e5627efa2ab1"},
		{fixture: "chrome-h2-other-sigalgs.hex", expected: "t13d1516h2_8daaf6152771_9b887d9acb53"},
		{fixture: "chrome-mlkem-sigalg-grease.hex", expected: "t13d1517h2_8daaf6152771_cb7bf5808d99"},
		{fixture: "firefox.hex", expected: "t13d1715h2_5b57614c22b0_3d5424432f57"},
		{fixture: "tls12-alpn-h2.hex", expected: "t12d4605h2_85626a9a5f7f_aaf95bb78ec9"},
		{fixture: "tls12-no-alpn.hex", expected: "t12d190800_d83cc789557e_7af1ed941c26"},
		{fixture: "no-sni.hex", expected: "t12i860500_e18388e7f3a3_a1e935682795"},
	}

	for _, test := range testCases {
		t.Run(test.fixture, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(filepath.Join("fixtures", "ja4", test.fixture))
			require.NoError(t, err)

			record, err := hex.DecodeString(string(content))
			require.NoError(t, err)

			hello := readClientHelloInfo(t, record)

			assert.Equal(t, test.expected, JA4(hello))
		})
	}
}

func TestJA4ALPN(t *testing.T) {
	testCases := []struct {
		desc     string
		protos   []string
		expected string
	}{
		{desc: "no ALPN", expected: "00"},
		{desc: "empty first value", protos: []string{"", "h2"}, expected: "00"},
		{desc: "h2", protos: []string{"h2", "http/1.1"}, expected: "h2"},
		{desc: "http/1.1", protos: []string{"http/1.1"}, expected: "h1"},
		{desc: "single character", protos: []string{"h"}, expected: "hh"},
		{desc: "0xAB", protos: []string{"\xab"}, expected: "ab"},
		{desc: "0x20", protos: []string{"\x20"}, expected: "20"},
		{desc: "0xAB 0xCD", protos: []string{"\xab\xcd"}, expected: "ad"},
		{desc: "0x20 0x61", protos: []string{"\x20\x61"}, expected: "21"},
		{desc: "0x30 0xAB", protos: []string{"\x30\xab"}, expected: "3b"},
		{desc: "0x61 0x20", protos: []string{"\x61\x20"}, expected: "60"},
		{desc: "0x30 0x31 0xAB 0xCD", protos: []string{"\x30\x31\xab\xcd"}, expected: "3d"},
		{desc: "0x30 0xAB 0xCD 0x31", protos: []string{"\x30\xab\xcd\x31"}, expected: "01"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.expected, string(appendJA4ALPN(nil, test.protos)))
		})
	}
}

func TestJA4Version(t *testing.T) {
	testCases := []struct {
		desc     string
		versions []uint16
		expected string
	}{
		{desc: "none", expected: "00"},
		{desc: "TLS 1.3", versions: []uint16{tls.VersionTLS12, tls.VersionTLS13}, expected: "13"},
		{desc: "TLS 1.2", versions: []uint16{tls.VersionTLS12, tls.VersionTLS11}, expected: "12"},
		{desc: "TLS 1.1", versions: []uint16{tls.VersionTLS11}, expected: "11"},
		{desc: "TLS 1.0", versions: []uint16{tls.VersionTLS10}, expected: "10"},
		{desc: "SSL 3.0", versions: []uint16{0x0300}, expected: "s3"},
		{desc: "SSL 2.0", versions: []uint16{0x0002}, expected: "s2"},
		{desc: "unknown", versions: []uint16{0x0305}, expected: "00"},
		{desc: "GREASE only", versions: []uint16{0x7a7a}, expected: "00"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.expected, ja4Version(test.versions))
		})
	}
}

func TestJA4FromContext(t *testing.T) {
	assert.Empty(t, JA4FromContext(t.Context()))

	ctx := ContextWithJA4(t.Context(), "t13d1516h2_8daaf6152771_e5627efa2ab1")
	assert.Equal(t, "t13d1516h2_8daaf6152771_e5627efa2ab1", JA4FromContext(ctx))
}

func BenchmarkJA4(b *testing.B) {
	content, err := os.ReadFile(filepath.Join("fixtures", "ja4", "chrome-mlkem-sigalg-grease.hex"))
	require.NoError(b, err)

	record, err := hex.DecodeString(string(content))
	require.NoError(b, err)

	hello := readClientHelloInfo(b, record)

	b.ReportAllocs()
	for b.Loop() {
		JA4(hello)
	}
}

func ja4Hash(raw []byte, suffix string) string {
	return string(appendJA4Hash(nil, append(raw, suffix...)))
}

// readClientHelloInfo parses the ClientHello TLS record with crypto/tls, as the TCP router does.
func readClientHelloInfo(tb testing.TB, record []byte) *tls.ClientHelloInfo {
	tb.Helper()

	var hello *tls.ClientHelloInfo
	server := tls.Server(recordConn{r: bytes.NewReader(record)}, &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = info
			return nil, nil
		},
	})
	_ = server.HandshakeContext(tb.Context())

	require.NotNil(tb, hello, "ClientHello not parsed")

	return hello
}

// recordConn is a net.Conn that reads from r and fails on writes.
type recordConn struct {
	net.Conn // nil; crash on any unexpected use

	r io.Reader
}

func (c recordConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (recordConn) Write([]byte) (int, error) { return 0, io.EOF }
