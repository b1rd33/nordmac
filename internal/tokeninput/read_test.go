package tokeninput

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadStdinAcceptsOneLowercaseHexLine(t *testing.T) {
	token, err := ReadStdin(strings.NewReader("0123456789abcdef\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(token) != "0123456789abcdef" {
		t.Fatalf("token = %q", token)
	}
}

func TestReadStdinRejectsUnsafeForms(t *testing.T) {
	for name, input := range map[string]string{
		"empty": "", "uppercase": "ABCDEF", "space": "abcd ef", "multiple lines": "abcd\nef01\n",
		"oversize": strings.Repeat("a", maxTokenBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if token, err := ReadStdin(strings.NewReader(input)); err == nil {
				t.Fatalf("token %q unexpectedly accepted", token)
			}
		})
	}
}

func TestReadHiddenUsesNoEchoReaderAndPrompt(t *testing.T) {
	var prompt bytes.Buffer
	token, err := ReadHidden(9, &prompt, Terminal{
		IsTerminal: func(fd int) bool { return fd == 9 },
		ReadPassword: func(fd int) ([]byte, error) {
			if fd != 9 {
				return nil, errors.New("wrong fd")
			}
			return []byte("0123456789abcdef"), nil
		},
	})
	if err != nil || string(token) != "0123456789abcdef" || prompt.String() != "Nord access token: \n" {
		t.Fatalf("token=%q prompt=%q err=%v", token, prompt.String(), err)
	}
}

func TestReadHiddenRefusesNonTerminal(t *testing.T) {
	var prompt bytes.Buffer
	_, err := ReadHidden(0, &prompt, Terminal{IsTerminal: func(int) bool { return false }})
	if err == nil || prompt.Len() != 0 {
		t.Fatalf("prompt=%q err=%v", prompt.String(), err)
	}
}
