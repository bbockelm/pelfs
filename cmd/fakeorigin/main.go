// Command fakeorigin runs a minimal Pelican-origin-like HTTP server over a
// local directory, for testing pelfs without a federation.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
)

func main() {
	root := flag.String("root", ".", "directory backing the namespace")
	listen := flag.String("listen", "127.0.0.1:0", "listen address")
	delay := flag.Duration("delay", 0, "sleep this long before answering each request, standing in for a round trip")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fakeorigin: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("LISTENING %s\n", ln.Addr().String())
	if err := http.Serve(ln, fakeorigin.HandlerWithDelay(*root, *delay)); err != nil {
		fmt.Fprintf(os.Stderr, "fakeorigin: %v\n", err)
		os.Exit(1)
	}
}
