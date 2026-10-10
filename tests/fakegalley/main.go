// Command fakegalley stands in for galley's window on the services socket in
// the VM tests, answering each question with the next line of a script.
//
//	fakegalley -socket PATH -script FILE [-log FILE]
//
// Script actions, one per question, the last line repeating: `ok <field>…`
// answers the fields in order, `cancel`, `answer N` presses extra button N,
// and `never` leaves the question up until its client hangs up.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/danielbodart/galley/wire"
	"golang.org/x/sys/unix"
)

type action struct {
	answer string
	index  int
	fields []string
}

type galley struct {
	mu     sync.Mutex
	script []action
	next   int
	log    io.Writer
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fakegalley: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", "", "the services socket to bind")
	script := flag.String("script", "", "the answers, one action a line")
	logPath := flag.String("log", "", "where to write one JSON line per question and answer")
	flag.Parse()
	if *socket == "" || *script == "" {
		return errors.New("-socket and -script are required")
	}

	g := &galley{log: io.Discard}
	var err error
	if g.script, err = readScript(*script); err != nil {
		return err
	}
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		g.log = f
	}

	if err := os.Remove(*socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socket, 0o666); err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go g.serve(c.(*net.UnixConn))
	}
}

func readScript(path string) ([]action, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var script []action
	for _, line := range strings.Split(string(b), "\n") {
		words := strings.Fields(line)
		if len(words) == 0 {
			continue
		}
		switch {
		case words[0] == "ok":
			script = append(script, action{answer: wire.AnswerOK, fields: words[1:]})
		case words[0] == "cancel" && len(words) == 1:
			script = append(script, action{answer: wire.AnswerCancel})
		case words[0] == "never" && len(words) == 1:
			script = append(script, action{})
		case words[0] == "answer" && len(words) == 2:
			n, err := strconv.Atoi(words[1])
			if err != nil {
				return nil, fmt.Errorf("%s: %q: %w", path, line, err)
			}
			script = append(script, action{answer: wire.AnswerExtra, index: n})
		default:
			return nil, fmt.Errorf("%s: %q is not an action", path, line)
		}
	}
	if len(script) == 0 {
		return nil, fmt.Errorf("%s has no actions", path)
	}
	return script, nil
}

func (g *galley) serve(c *net.UnixConn) {
	defer c.Close()
	cred, err := peer(c)
	if err != nil {
		g.write(map[string]any{"event": "error", "error": err.Error()})
		return
	}
	var hello wire.Hello
	if err := json.NewDecoder(c).Decode(&hello); err != nil || hello.Item == nil {
		g.write(map[string]any{"event": "error", "error": fmt.Sprintf("no item: %v", err), "uid": cred.Uid, "pid": cred.Pid})
		return
	}
	it := hello.Item
	var fields []wire.Field
	if it.Forms != nil {
		fields = it.Forms.Fields
	}

	g.mu.Lock()
	a := g.script[min(g.next, len(g.script)-1)]
	g.next++
	g.mu.Unlock()

	g.write(map[string]any{"event": "question", "title": it.Title, "text": it.Text, "kind": it.Kind,
		"level": it.Level, "buttons": it.Buttons, "fields": fields, "uid": cred.Uid, "pid": cred.Pid})

	if a.answer == "" {
		io.Copy(io.Discard, c)
		g.write(map[string]any{"event": "close", "uid": cred.Uid, "pid": cred.Pid})
		return
	}
	answer := wire.Answer{Answer: a.answer, Index: a.index}
	logged := []any{}
	for i, f := range a.fields {
		answer.Fields = append(answer.Fields, wire.FieldValue{Text: &f})
		if i < len(fields) && fields[i].Kind == wire.FieldPassword {
			logged = append(logged, len(f))
		} else {
			logged = append(logged, f)
		}
	}
	line, _ := json.Marshal(answer)
	if _, err := c.Write(append(line, '\n')); err != nil {
		g.write(map[string]any{"event": "close", "uid": cred.Uid, "pid": cred.Pid})
		return
	}
	g.write(map[string]any{"event": "answer", "answer": a.answer, "index": a.index, "fields": logged,
		"uid": cred.Uid, "pid": cred.Pid})
}

func peer(c *net.UnixConn) (*unix.Ucred, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := rc.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, credErr
}

func (g *galley) write(v map[string]any) {
	line, _ := json.Marshal(v)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.log.Write(append(line, '\n'))
}
