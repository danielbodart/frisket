package sshroute

import "time"

// previewIdle is how long stdin may send nothing before the command is
// asked about with what it has sent -- from the start, unlike an HTTP body's
// preview, which waits for its first byte. ssh without -n holds stdin open
// and sends nothing, and a channel cannot say beforehand whether it ever
// will: a preview that waited for a first byte would wait for ever on every
// `ssh host command` typed by hand. A variable only so a test can shrink it.
var previewIdle = 500 * time.Millisecond
