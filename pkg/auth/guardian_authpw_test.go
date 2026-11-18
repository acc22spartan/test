package auth

import (
	"encoding/hex"
	"testing"
)

func TestDeriveAuthPWV2MozillaVector(t *testing.T) {
	const salt = "identity.mozilla.com/picl/v1/quickStretchV2:0123456789abcdef0123456789abcdef"
	got, err := deriveAuthPWV2("Correct Horse Battery Staple", salt)
	if err != nil {
		t.Fatalf("deriveAuthPWV2() error = %v", err)
	}
	const want = "89da39d10de8ee2f5ebad05ad6126aa0516397c76fa385c670f010d796745826"
	if hex.EncodeToString(got) != want {
		t.Fatalf("deriveAuthPWV2() = %x, want %s", got, want)
	}
}

func TestDeriveAuthPWV2RejectsInvalidSalt(t *testing.T) {
	cases := []string{
		"",
		"identity.mozilla.com/picl/v1/quickStretch:person@example.com",
		"identity.mozilla.com/picl/v1/quickStretchV2:0123456789abcdef",
		"identity.mozilla.com/picl/v1/quickStretchV2:0123456789abcdef0123456789abcdeg",
	}
	for _, salt := range cases {
		if _, err := deriveAuthPWV2("password", salt); err == nil {
			t.Errorf("deriveAuthPWV2(%q) expected error", salt)
		}
	}
}

func TestDeriveAuthPWV1Compatibility(t *testing.T) {
	got, err := deriveAuthPW("person@example.com", "Correct Horse Battery Staple")
	if err != nil {
		t.Fatalf("deriveAuthPW() error = %v", err)
	}
	const want = "0f071a44d5fa5a452b57d1d2b8d36f30deedd94e474c1d9725a21688f563dfa2"
	if hex.EncodeToString(got) != want {
		t.Fatalf("deriveAuthPW() = %x, want %s", got, want)
	}
}
