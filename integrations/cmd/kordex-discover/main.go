// kordex-discover reads a supplied host root/snapshot or prints driver metadata.
// It never contacts a remote host, starts a process on a node, or mutates it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"kordex.local/api/lifecycle"
	"os"
)

func main() {
	root := flag.String("root", "", "explicit host filesystem root or snapshot (never assume a container root is the host)")
	architecture := flag.String("architecture", "", "recorded host architecture: amd64 or arm64")
	matrix := flag.Bool("matrix", false, "print built-in driver metadata; does not qualify or enable adapters")
	flag.Parse()
	if err := run(*root, *architecture, *matrix); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(root, architecture string, matrix bool) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if matrix {
		return encoder.Encode(lifecycle.BuiltinRegistry().Drivers())
	}
	if root == "" || architecture != "amd64" && architecture != "arm64" {
		return fmt.Errorf("require explicit -root and -architecture amd64|arm64; discovery never authorizes an upgrade")
	}
	hostRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer hostRoot.Close()
	host, err := lifecycle.DiscoverHost(hostRoot.FS(), architecture)
	if err != nil {
		return err
	}
	return encoder.Encode(host)
}
