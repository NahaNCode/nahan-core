package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestExclusiveBinaryRegistrationProcess(t *testing.T) {
	if os.Getenv("NAHAN_EXCLUSIVE_BINARY_FIXTURE") != "1" {
		return
	}
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestExclusiveBinaryExcludesRegistrarButRejectsSharedCore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exclusiveBinary(binary) == nil {
		t.Fatal("registrar alone must not count as a running core")
	}
	start := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		command := exec.CommandContext(ctx, binary, "-test.run=^TestExclusiveBinaryRegistrationProcess$")
		command.Env = append(os.Environ(), "NAHAN_EXCLUSIVE_BINARY_FIXTURE=1")
		input, err := command.StdinPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		output, err := command.StdoutPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := command.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = input.Close()
			cancel()
			_ = command.Wait()
		})
		line, err := bufio.NewReader(output).ReadString('\n')
		if err != nil || line != "READY\n" {
			t.Fatalf("fixture failed to start: %q, %v", line, err)
		}
	}
	start()
	if err := exclusiveBinary(binary); err != nil {
		t.Fatalf("one running core plus its registrar must be accepted: %v", err)
	}
	start()
	if exclusiveBinary(binary) == nil {
		t.Fatal("two running core processes must still be rejected")
	}
}
