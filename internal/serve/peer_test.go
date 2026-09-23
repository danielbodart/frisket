package serve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/frisket/internal/control"
)

// roleCaller is the test binary re-run as a control client: it asks for the
// session list on the socket named after it and prints what came back.
const roleCaller = "frisket-test-control-caller"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == roleCaller {
		_, err := control.Call(context.Background(), os.Args[2], control.Request{Op: control.OpList}, nil)
		fmt.Println(err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// callFrom asks the daemon for its sessions from a child of this process,
// set up by attr, and returns the error the child saw ("<nil>" for none).
func callFrom(t *testing.T, path string, attr *syscall.SysProcAttr) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], roleCaller, path)
	cmd.SysProcAttr = attr
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// The same uid from a user namespace of its own is refused: that is what a
// sandbox's workload looks like to SO_PEERCRED, mapped back to the launcher's
// uid. And from the daemon's namespace it is answered, so the refusal is the
// namespace and nothing else about a child process.
func TestTheControlSocketRefusesItsOwnerFromAnotherUserNamespace(t *testing.T) {
	f := startDaemon(t, nil, &recorder{}, nil, nil)

	here, err := callFrom(t, f.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if here != "<nil>" {
		t.Fatalf("from this user namespace: %s", here)
	}

	uid, gid := os.Getuid(), os.Getgid()
	nested, err := callFrom(t, f.path, &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
	})
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Skipf("this kernel will not make an unprivileged user namespace: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nested, "another user namespace") {
		t.Errorf("from a nested user namespace: %s, want a refusal of the namespace", nested)
	}
}
