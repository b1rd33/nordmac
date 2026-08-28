package darwinnet

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var serviceDevicePattern = regexp.MustCompile(`^\(Hardware Port: .+, Device: ([a-zA-Z][a-zA-Z0-9]{0,15})\)$`)

// NetworkService resolves a BSD interface to the enabled network service whose
// static DNS settings networksetup can safely snapshot and restore.
func NetworkService(ctx context.Context, runner Runner, physicalInterface string) (string, error) {
	if runner == nil {
		return "", errors.New("Darwin network service runner is missing")
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,15}$`).MatchString(physicalInterface) {
		return "", errors.New("physical interface is invalid")
	}
	output, err := runner.Run(ctx, defaultNetworkSetupPath, "-listnetworkserviceorder")
	if err != nil {
		return "", fmt.Errorf("list network service order: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for index := 0; index+1 < len(lines); index++ {
		serviceLine := strings.TrimSpace(lines[index])
		deviceLine := strings.TrimSpace(lines[index+1])
		matches := serviceDevicePattern.FindStringSubmatch(deviceLine)
		if len(matches) != 2 || matches[1] != physicalInterface {
			continue
		}
		separator := strings.Index(serviceLine, ") ")
		if separator < 0 {
			return "", errors.New("malformed network service order")
		}
		service := strings.TrimSpace(serviceLine[separator+2:])
		if strings.HasPrefix(serviceLine, "(*") || strings.HasPrefix(service, "*") {
			return "", fmt.Errorf("network service for %s is disabled", physicalInterface)
		}
		if service == "" || len(service) > 256 || strings.ContainsAny(service, "\r\n\x00") {
			return "", errors.New("invalid network service name")
		}
		return service, nil
	}
	return "", fmt.Errorf("no enabled network service owns interface %s", physicalInterface)
}
