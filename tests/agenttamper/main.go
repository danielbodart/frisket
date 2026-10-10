// Command agenttamper binds one session on $SSH_AUTH_SOCK, then asks for a
// userauth signature for another session and for the bound one. It exits 0
// only when the first is refused and the second is signed.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "agenttamper: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	c, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return err
	}
	defer c.Close()
	a := agent.NewClient(c)
	keys, err := a.List()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("the agent has no keys")
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	host, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	bound, other := make([]byte, 32), make([]byte, 32)
	rand.Read(bound)
	rand.Read(other)
	sig, err := host.Sign(rand.Reader, bound)
	if err != nil {
		return err
	}
	bind := ssh.Marshal(struct {
		Key, SID, Sig []byte
		Fwd           bool
	}{host.PublicKey().Marshal(), bound, ssh.Marshal(sig), false})
	if _, err := a.Extension("session-bind@openssh.com", bind); err != nil {
		return fmt.Errorf("session-bind: %w", err)
	}

	userauth := func(sid []byte) []byte {
		return ssh.Marshal(struct {
			SID                   []byte
			Msg                   byte
			User, Service, Method string
			HasSig                bool
			Alg                   string
			Key                   []byte
		}{sid, 50, "dan", "ssh-connection", "publickey", true, keys[0].Format, keys[0].Blob})
	}
	if _, err := a.Sign(keys[0], userauth(other)); err == nil {
		return errors.New("a sign for another session than the bound one was made")
	}
	fmt.Println("another session: refused")
	if _, err := a.Sign(keys[0], userauth(bound)); err != nil {
		return fmt.Errorf("the bound session: %w", err)
	}
	fmt.Println("the bound session: signed")
	return nil
}
