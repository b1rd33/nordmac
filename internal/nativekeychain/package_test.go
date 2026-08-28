package nativekeychain

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLocatePackagedHelperAuthenticatesResolvedSibling(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(bin, "nordmac")
	if err := os.WriteFile(executable, []byte("cli"), 0o500); err != nil {
		t.Fatal(err)
	}
	libexec := filepath.Join(bin, "libexec")
	if err := os.Mkdir(libexec, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(libexec, packagedHelperName)
	contents := []byte("synthetic helper")
	if err := os.WriteFile(helper, contents, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	got, err := locatePackagedHelper(func() (string, error) { return executable, nil }, filepath.EvalSymlinks, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(helper)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("helper = %q, want %q", got, want)
	}
}

func TestLocatePackagedHelperRejectsMismatchAndWritableFile(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "nordmac")
	if err := os.WriteFile(executable, []byte("cli"), 0o500); err != nil {
		t.Fatal(err)
	}
	libexec := filepath.Join(root, "libexec")
	if err := os.Mkdir(libexec, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(libexec, packagedHelperName)
	if err := os.WriteFile(helper, []byte("helper"), 0o522); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, 0o522); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("helper"))
	if _, err := locatePackagedHelper(func() (string, error) { return executable, nil }, filepath.EvalSymlinks, hex.EncodeToString(digest[:])); err == nil {
		t.Fatal("group/world-writable helper unexpectedly accepted")
	}
	if err := os.Chmod(helper, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := locatePackagedHelper(func() (string, error) { return executable, nil }, filepath.EvalSymlinks, hex.EncodeToString(make([]byte, sha256.Size))); err == nil {
		t.Fatal("mismatched helper unexpectedly accepted")
	}
}

func TestLocatePackagedHelperRejectsNonExecutableAndWritableDirectory(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "nordmac")
	if err := os.WriteFile(executable, []byte("cli"), 0o500); err != nil {
		t.Fatal(err)
	}
	libexec := filepath.Join(root, "libexec")
	if err := os.Mkdir(libexec, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(libexec, packagedHelperName)
	contents := []byte("helper")
	if err := os.WriteFile(helper, contents, 0o400); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	locate := func() error {
		_, err := locatePackagedHelper(func() (string, error) { return executable, nil }, filepath.EvalSymlinks, hex.EncodeToString(digest[:]))
		return err
	}
	if err := locate(); err == nil {
		t.Fatal("non-executable helper unexpectedly accepted")
	}
	if err := os.Chmod(helper, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(libexec, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := locate(); err == nil {
		t.Fatal("group/world-writable helper directory unexpectedly accepted")
	}
}
