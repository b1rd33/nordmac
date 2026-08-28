package nativekeychain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/b1rd33/nordmac/internal/buildinfo"
)

const packagedHelperName = "nordmac-keychain-helper"

// LocatePackagedHelper returns the helper shipped beside the resolved nordmac
// executable only when it exactly matches the SHA-256 embedded in that CLI.
// Development builds intentionally have no accepted packaged helper.
func LocatePackagedHelper() (string, error) {
	return locatePackagedHelper(os.Executable, filepath.EvalSymlinks, buildinfo.HelperSHA256)
}

func locatePackagedHelper(executable func() (string, error), resolve func(string) (string, error), expectedHex string) (string, error) {
	want, err := hex.DecodeString(expectedHex)
	if err != nil || len(want) != sha256.Size {
		return "", errors.New("packaged native Keychain helper is unavailable")
	}
	path, err := executable()
	if err != nil {
		return "", errors.New("locate nordmac executable")
	}
	path, err = resolve(path)
	if err != nil || !filepath.IsAbs(path) {
		return "", errors.New("resolve nordmac executable")
	}
	candidate := filepath.Join(filepath.Dir(path), "libexec", packagedHelperName)
	parentInfo, err := os.Stat(filepath.Dir(candidate))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return "", errors.New("packaged native Keychain helper directory is unsafe")
	}
	info, err := os.Lstat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("packaged native Keychain helper has unsafe type or mode")
	}
	if !safeOwner(info) || !sameOwner(info, parentInfo) {
		return "", errors.New("packaged native Keychain helper has unsafe ownership")
	}
	file, err := os.Open(candidate)
	if err != nil {
		return "", errors.New("open packaged native Keychain helper")
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", errors.New("hash packaged native Keychain helper")
	}
	if !equalDigest(digest.Sum(nil), want) {
		return "", errors.New("packaged native Keychain helper digest mismatch")
	}
	return candidate, nil
}

func safeOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func sameOwner(first, second os.FileInfo) bool {
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && firstStat.Uid == secondStat.Uid
}

func equalDigest(actual, expected []byte) bool {
	if len(actual) != len(expected) {
		return false
	}
	var difference byte
	for index := range actual {
		difference |= actual[index] ^ expected[index]
	}
	return difference == 0
}
