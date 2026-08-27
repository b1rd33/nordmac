package credentials

import "testing"

func TestKindValidate(t *testing.T) {
	for _, kind := range []Kind{AccessToken, NordLynxPrivateKey} {
		if err := kind.Validate(); err != nil {
			t.Fatalf("Validate(%q): %v", kind, err)
		}
	}
	if err := Kind("arbitrary-account").Validate(); err == nil {
		t.Fatal("expected an arbitrary account name to be rejected")
	}
}

func TestWipe(t *testing.T) {
	secret := []byte("synthetic-secret")
	Wipe(secret)
	for index, value := range secret {
		if value != 0 {
			t.Fatalf("byte %d was not wiped", index)
		}
	}
}
