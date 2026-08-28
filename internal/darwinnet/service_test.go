package darwinnet

import (
	"context"
	"testing"
)

func TestNetworkServiceResolvesInterface(t *testing.T) {
	runner := &fakeRunner{results: []runnerResult{{output: `An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
`}}}
	service, err := NetworkService(context.Background(), runner, "en0")
	if err != nil || service != "Wi-Fi" {
		t.Fatalf("NetworkService = %q, %v", service, err)
	}
}

func TestNetworkServiceRejectsDisabledOrMissing(t *testing.T) {
	for name, output := range map[string]string{
		"disabled": "(*) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n",
		"missing":  "(1) Ethernet\n(Hardware Port: Ethernet, Device: en4)\n",
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{results: []runnerResult{{output: output}}}
			if _, err := NetworkService(context.Background(), runner, "en0"); err == nil {
				t.Fatal("NetworkService unexpectedly succeeded")
			}
		})
	}
}
