package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/sdnotify"
	"github.com/danielbodart/frisket/project"
)

// runDNS is `frisket dns`: a project's name under .internal answered on the
// host, from the name alone (dns.Host). Its sockets are systemd's, a
// datagram and a stream one, so it binds port 53 holding no privilege; run
// by hand, it binds -listen itself.
func runDNS(argv []string) error {
	fs := flag.NewFlagSet("dns", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.153:53", "the address to answer on, UDP and TCP, when systemd has passed no socket")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	log := slog.New(slog.NewJSONHandler(&lockedWriter{w: os.Stderr}, nil))
	h := &dns.Host{Lookup: projectAddress, Log: log}

	inherited, err := sdnotify.Listen()
	if err != nil {
		return err
	}
	var pcs []net.PacketConn
	var lns []net.Listener
	for _, fd := range inherited {
		if pc, err := net.FilePacketConn(fd.File); err == nil {
			pcs = append(pcs, pc)
		} else if ln, err := net.FileListener(fd.File); err == nil {
			lns = append(lns, ln)
		} else {
			return fmt.Errorf("socket %s that systemd passed is neither a datagram nor a listening one", fd.Name)
		}
		_ = fd.File.Close()
	}
	if len(inherited) == 0 {
		pc, err := net.ListenPacket("udp", *listen)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		pcs, lns = append(pcs, pc), append(lns, ln)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, len(pcs)+len(lns))
	for _, pc := range pcs {
		log.Info("frisket dns", "version", version, "udp", pc.LocalAddr().String())
		go func() { errs <- h.ServeUDP(ctx, pc) }()
	}
	for _, ln := range lns {
		log.Info("frisket dns", "version", version, "tcp", ln.Addr().String())
		go func() { errs <- h.ServeTCP(ctx, ln) }()
	}
	if n := sdnotify.FromEnv(); n != nil {
		_ = n.Ready("answering")
	}
	var first error
	for range len(pcs) + len(lns) {
		if err := <-errs; err != nil && first == nil {
			first = err
			stop()
		}
	}
	if first != nil && !errors.Is(first, net.ErrClosed) {
		return first
	}
	return nil
}

// projectAddress is the address of the project a name is, if it is one.
func projectAddress(name string) (netip.Addr, bool) {
	p, ok := project.FromName(name)
	if !ok {
		return netip.Addr{}, false
	}
	return project.Address(p), true
}
