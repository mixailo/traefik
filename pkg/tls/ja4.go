package tls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"slices"
)

const (
	extensionServerName uint16 = 0x0000
	extensionALPN       uint16 = 0x0010
)

const ja4EmptyHash = "000000000000"

type ja4ContextKey struct{}

// ContextWithJA4 returns a copy of ctx carrying the JA4 fingerprint of the connection's ClientHello.
func ContextWithJA4(ctx context.Context, ja4 string) context.Context {
	return context.WithValue(ctx, ja4ContextKey{}, ja4)
}

// JA4FromContext returns the JA4 fingerprint stored in ctx by ContextWithJA4, or an empty string.
func JA4FromContext(ctx context.Context) string {
	ja4, _ := ctx.Value(ja4ContextKey{}).(string)
	return ja4
}

// JA4 returns the JA4 fingerprint of a ClientHello received over TCP.
// The algorithm is specified in https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md,
// JA4 (TLS client fingerprinting) is licensed under the BSD 3-Clause license.
func JA4(hello *tls.ClientHelloInfo) string {
	ciphers := withoutGREASE(hello.CipherSuites)
	extensions := withoutGREASE(hello.Extensions)
	signatures := withoutGREASE(hello.SignatureSchemes)

	fp := make([]byte, 0, 36)
	fp = append(fp, 't')
	fp = append(fp, ja4Version(hello.SupportedVersions)...)
	if slices.Contains(extensions, extensionServerName) {
		fp = append(fp, 'd')
	} else {
		fp = append(fp, 'i')
	}
	fp = appendJA4Count(fp, len(ciphers))
	fp = appendJA4Count(fp, len(extensions))
	fp = appendJA4ALPN(fp, hello.SupportedProtos)

	slices.Sort(ciphers)
	fp = append(fp, '_')
	fp = appendJA4Hash(fp, appendHexList(nil, ciphers))

	extensions = slices.DeleteFunc(extensions, func(ext uint16) bool {
		return ext == extensionServerName || ext == extensionALPN
	})
	slices.Sort(extensions)
	raw := appendHexList(nil, extensions)
	if len(signatures) > 0 {
		raw = append(raw, '_')
		raw = appendHexList(raw, signatures)
	}
	fp = append(fp, '_')
	fp = appendJA4Hash(fp, raw)

	return string(fp)
}

// withoutGREASE returns a copy of values without the GREASE values (RFC 8701).
func withoutGREASE[T ~uint16](values []T) []uint16 {
	res := make([]uint16, 0, len(values))
	for _, v := range values {
		if v&0x0f0f == 0x0a0a && v>>8 == v&0xff {
			continue
		}
		res = append(res, uint16(v))
	}
	return res
}

// ja4Version returns the two characters code of the highest TLS version supported by the client.
// When the supported_versions extension is absent,
// crypto/tls derives the supported versions from the ClientHello legacy version.
func ja4Version(versions []uint16) string {
	versions = withoutGREASE(versions)
	if len(versions) == 0 {
		return "00"
	}

	switch slices.Max(versions) {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300: // SSL 3.0
		return "s3"
	case 0x0002: // SSL 2.0
		return "s2"
	default:
		return "00"
	}
}

func appendJA4Count(dst []byte, n int) []byte {
	n = min(n, 99)
	return append(dst, byte('0'+n/10), byte('0'+n%10))
}

// appendJA4ALPN appends the first and last characters of the first ALPN value,
// or the first and last characters of its hex representation if one of them is not alphanumeric.
func appendJA4ALPN(dst []byte, protos []string) []byte {
	if len(protos) == 0 || protos[0] == "" {
		return append(dst, '0', '0')
	}

	first, last := protos[0][0], protos[0][len(protos[0])-1]
	if isAlphanumeric(first) && isAlphanumeric(last) {
		return append(dst, first, last)
	}

	const hexDigits = "0123456789abcdef"
	return append(dst, hexDigits[first>>4], hexDigits[last&0x0f])
}

func isAlphanumeric(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// appendHexList appends values as comma-separated 4-character lowercase hex codes.
func appendHexList(dst []byte, values []uint16) []byte {
	for i, v := range values {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = hex.AppendEncode(dst, []byte{byte(v >> 8), byte(v)})
	}
	return dst
}

// appendJA4Hash appends the first 12 hex characters of the SHA-256 hash of raw,
// or 12 zeros if raw is empty.
func appendJA4Hash(dst, raw []byte) []byte {
	if len(raw) == 0 {
		return append(dst, ja4EmptyHash...)
	}

	sum := sha256.Sum256(raw)
	return hex.AppendEncode(dst, sum[:6])
}
