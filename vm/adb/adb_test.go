// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package adb

import (
	"encoding/json"
	"testing"

	"github.com/google/syzkaller/pkg/config"
)

func TestConfigParseBootService(t *testing.T) {
	testCases := []struct {
		name        string
		jsonConfig  string
		wantDefault bool
		expected    string
	}{
		{
			name: "default value when not specified",
			jsonConfig: `{
                "devices": ["test-device"]
            }`,
			wantDefault: true,
			expected:    "systemui",
		},
		{
			name: "custom boot_service value",
			jsonConfig: `{
                "devices": ["test-device"],
                "boot_service": "servicemanager"
            }`,
			wantDefault: false,
			expected:    "servicemanager",
		},
		{
			name: "empty boot_service uses default",
			jsonConfig: `{
                "devices": ["test-device"],
                "boot_service": ""
            }`,
			wantDefault: false,
			expected:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rawConfig := json.RawMessage(tc.jsonConfig)

			cfg := &Config{
				Adb:          "adb",
				BatteryCheck: true,
				TargetReboot: true,
				BootService:  "systemui", // default value
			}

			if err := config.LoadData(rawConfig, cfg); err != nil {
				t.Fatalf("failed to parse config: %v", err)
			}

			if tc.wantDefault {
				if cfg.BootService != "systemui" {
					t.Errorf("expected default BootService 'systemui', got '%s'", cfg.BootService)
				}
			} else {
				if cfg.BootService != tc.expected {
					t.Errorf("expected BootService '%s', got '%s'", tc.expected, cfg.BootService)
				}
			}
		})
	}
}

func TestConfigParseAllFields(t *testing.T) {
	jsonConfig := `{
        "adb": "/custom/path/adb",
        "devices": ["device1", "device2"],
        "battery_check": false,
        "target_reboot": false,
        "repair_script": "/path/to/repair.sh",
        "startup_script": "/path/to/startup.sh",
        "boot_service": "customservice"
    }`

	rawConfig := json.RawMessage(jsonConfig)

	cfg := &Config{
		Adb:          "adb",
		BatteryCheck: true,
		TargetReboot: true,
		BootService:  "systemui",
	}

	if err := config.LoadData(rawConfig, cfg); err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.Adb != "/custom/path/adb" {
		t.Errorf("expected Adb '/custom/path/adb', got '%s'", cfg.Adb)
	}
	if len(cfg.Devices) != 2 {
		t.Errorf("expected 2 devices, got %d", len(cfg.Devices))
	}
	if cfg.BatteryCheck != false {
		t.Errorf("expected BatteryCheck false, got %v", cfg.BatteryCheck)
	}
	if cfg.TargetReboot != false {
		t.Errorf("expected TargetReboot false, got %v", cfg.TargetReboot)
	}
	if cfg.RepairScript != "/path/to/repair.sh" {
		t.Errorf("expected RepairScript '/path/to/repair.sh', got '%s'", cfg.RepairScript)
	}
	if cfg.StartupScript != "/path/to/startup.sh" {
		t.Errorf("expected StartupScript '/path/to/startup.sh', got '%s'", cfg.StartupScript)
	}
	if cfg.BootService != "customservice" {
		t.Errorf("expected BootService 'customservice', got '%s'", cfg.BootService)
	}
}

func TestDeviceParse(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected Device
	}{
		{
			name:  "simple serial string",
			input: `"device123"`,
			expected: Device{
				Serial: "device123",
			},
		},
		{
			name:  "device object with serial",
			input: `{"serial": "device456", "console": "/dev/ttyUSB0"}`,
			expected: Device{
				Serial:  "device456",
				Console: "/dev/ttyUSB0",
			},
		},
		{
			name:  "device object with console_cmd",
			input: `{"serial": "device789", "console_cmd": ["cmd", "arg1"]}`,
			expected: Device{
				Serial:     "device789",
				ConsoleCmd: []string{"cmd", "arg1"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			device, err := loadDevice([]byte(tc.input))
			if err != nil {
				t.Fatalf("failed to parse device: %v", err)
			}

			if device.Serial != tc.expected.Serial {
				t.Errorf("expected Serial '%s', got '%s'", tc.expected.Serial, device.Serial)
			}
			if device.Console != tc.expected.Console {
				t.Errorf("expected Console '%s', got '%s'", tc.expected.Console, device.Console)
			}
			if len(device.ConsoleCmd) != len(tc.expected.ConsoleCmd) {
				t.Errorf("expected ConsoleCmd len %d, got %d", len(tc.expected.ConsoleCmd), len(device.ConsoleCmd))
			}
		})
	}
}
