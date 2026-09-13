package agentauth

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// vectorSeed is the 32-byte seed SIGNING.md publishes: 00 01 02 … 1f.
func vectorSeed() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// TestTheDocumentedVectorsStillHold.
//
// SIGNING.md is the contract for anybody implementing an agent in another
// language, and it is worth exactly as much as its test vectors. Somebody
// writing a Python agent has no other way to tell a correct implementation
// from one that verifies fine against its own matching bug — the core answers
// every authentication failure with the same flat 401 and no detail, on
// purpose.
//
// So the vectors are checked here rather than pasted. A change that makes this
// test fail has changed the scheme, and a changed scheme needs a new name —
// certpilot-agent-v2 — because every deployed agent signs under the old one.
// Quietly editing the document to match new output would leave every existing
// agent unable to authenticate and the document still looking correct.
func TestTheDocumentedVectorsStillHold(t *testing.T) {
	key := vectorSeed()
	pub := key.Public().(ed25519.PublicKey)

	if got := hex.EncodeToString(pub); got != "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8" {
		t.Fatalf("the published public key no longer derives from the published seed: %s", got)
	}
	if got := KeyID(pub); got != "a050837d85070582" {
		t.Errorf("key id: SIGNING.md says a050837d85070582, got %s", got)
	}

	for _, v := range []struct {
		name, method, path, body string
		timestamp                int64
		signingString, signature string
	}{
		{
			name: "a body", method: "POST", path: "/api/v1/agent/heartbeat",
			body: `{"status":"ok"}`, timestamp: 1767225600,
			signingString: "certpilot-agent-v1\nPOST\n/api/v1/agent/heartbeat\n1767225600\na29ee2b15c494311c52521766e44af56a3ad2248e7a8ab465e5206463c13d288",
			signature:     "iTjTV/pEPOdexLzQtUy7Fo2E2z6XbhI7STzuet0Bj1b6KGrVvVZW+NImAz03lJHvg+2OxYiyUVrInM7GiO1FBQ==",
		},
		{
			// The vector SIGNING.md tells an implementer to check first: an
			// empty body is hashed like any other, and a signer that skips the
			// line agrees with itself perfectly.
			name: "empty body", method: "POST", path: "/api/v1/agent/certificates",
			body: "", timestamp: 1767225600,
			signingString: "certpilot-agent-v1\nPOST\n/api/v1/agent/certificates\n1767225600\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			signature:     "V76KKzQosvCLrvdpljSEipiqbFQL7mFmNH2P8P/K1ernzPOZHA+efr5Ex1CCAZNfHRRjkXmGwMjh6IcNldF5AQ==",
		},
		{
			// Given a lowercase method, the signing string carries POST.
			name: "method uppercased", method: "post", path: "/api/v1/agent/inventory",
			body: "{}", timestamp: 1767225600,
			signingString: "certpilot-agent-v1\nPOST\n/api/v1/agent/inventory\n1767225600\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			signature:     "/7Llzg+yT8gDnBo9pInvNARFhOCBTZwBzdT8VGeiFmUvVqR/s74Jrqjvi9Okj25xtiz/WXYibh5ckUnhZld4CA==",
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			if got := SigningString(v.method, v.path, v.timestamp, []byte(v.body)); got != v.signingString {
				t.Errorf("signing string changed.\n  SIGNING.md: %q\n  code:       %q", v.signingString, got)
			}
			if got := Sign(key, v.method, v.path, v.timestamp, []byte(v.body)); got != v.signature {
				t.Errorf("signature changed.\n  SIGNING.md: %s\n  code:       %s", v.signature, got)
			}
		})
	}
}

// TestTheVectorsAreActuallyInTheDocument.
//
// The test above would keep passing if somebody deleted the vectors from
// SIGNING.md, which is the failure that matters: the code would still be
// correct and the contract would have become unpublishable. Reading the file
// is the only way to check that what is asserted here is what a stranger
// actually finds.
func TestTheVectorsAreActuallyInTheDocument(t *testing.T) {
	doc, err := os.ReadFile("../SIGNING.md")
	if err != nil {
		t.Fatalf("SIGNING.md is the published contract and could not be read: %v", err)
	}
	for _, must := range []string{
		"iTjTV/pEPOdexLzQtUy7Fo2E2z6XbhI7STzuet0Bj1b6KGrVvVZW+NImAz03lJHvg+2OxYiyUVrInM7GiO1FBQ==",
		"V76KKzQosvCLrvdpljSEipiqbFQL7mFmNH2P8P/K1ernzPOZHA+efr5Ex1CCAZNfHRRjkXmGwMjh6IcNldF5AQ==",
		"/7Llzg+yT8gDnBo9pInvNARFhOCBTZwBzdT8VGeiFmUvVqR/s74Jrqjvi9Okj25xtiz/WXYibh5ckUnhZld4CA==",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"a050837d85070582",
		Scheme,
	} {
		if !strings.Contains(string(doc), must) {
			t.Errorf("SIGNING.md no longer contains %q, so the document and this test disagree", must)
		}
	}
}
