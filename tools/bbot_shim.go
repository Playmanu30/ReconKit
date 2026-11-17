// bbot.exe shim: forward BBOT args from Windows into the WSL Ubuntu install.
package main

import (
	"os"
	"os/exec"
	"strings"
)

func wsl(args ...string) *exec.Cmd {
	base := []string{"-d", "Ubuntu", "-u", "root", "--"}
	return exec.Command("wsl.exe", append(base, args...)...)
}

func main() {
	// BBOT needs Redis; WSL does not run an init system for this imported distro.
	out, _ := wsl("redis-cli", "ping").Output()
	if !strings.Contains(string(out), "PONG") {
		_ = wsl("redis-server", "--daemonize", "yes").Run()
	}

	cmd := wsl(append([]string{"/usr/local/bin/bbot"}, os.Args[1:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
