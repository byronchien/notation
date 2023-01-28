package main

import (
	"testing"

	"github.com/notaryproject/notation/internal/ioutil"
)

func TestInspectCommand_SecretsFromArgs(t *testing.T) {
	opts := &inspectOpts{}
	cmd := inspectCommand(opts)
	expected := &inspectOpts{
		reference: "ref",
		SecureFlagOpts: SecureFlagOpts{
			Password:  "password",
			PlainHTTP: true,
			Username:  "user",
		},
		outputFormat: ioutil.OutputPlaintext,
	}
	if err := cmd.ParseFlags([]string{
		"--password", expected.Password,
		expected.reference,
		"-u", expected.Username,
		"--plain-http",
		"--output", "text"}); err != nil {
		t.Fatalf("Parse Flag failed: %v", err)
	}
	if err := cmd.Args(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Parse Args failed: %v", err)
	}
	if *opts != *expected {
		t.Fatalf("Expect inspect opts: %v, got: %v", expected, opts)
	}
}

func TestInspectCommand_SecretsFromEnv(t *testing.T) {
	t.Setenv(defaultUsernameEnv, "user")
	t.Setenv(defaultPasswordEnv, "password")
	opts := &inspectOpts{}
	expected := &inspectOpts{
		reference: "ref",
		SecureFlagOpts: SecureFlagOpts{
			Password: "password",
			Username: "user",
		},
		outputFormat: ioutil.OutputJson,
	}
	cmd := inspectCommand(opts)
	if err := cmd.ParseFlags([]string{
		expected.reference,
		"--output", "json"}); err != nil {
		t.Fatalf("Parse Flag failed: %v", err)
	}
	if err := cmd.Args(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Parse Args failed: %v", err)
	}
	if *opts != *expected {
		t.Fatalf("Expect inspect opts: %v, got: %v", expected, opts)
	}
}

func TestInspectCommand_MissingArgs(t *testing.T) {
	cmd := inspectCommand(nil)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("Parse Flag failed: %v", err)
	}
	if err := cmd.Args(cmd, cmd.Flags().Args()); err == nil {
		t.Fatal("Parse Args expected error, but ok")
	}
}
