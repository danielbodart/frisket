// Package projpolicy is a project's signed policy file: the canonical JSON
// it is signed in, the JSON Merge Patch that layers it, the SSHSIG sidecar
// beside it (file.sig, as stock ssh-keygen -Y sign writes it), the
// allowed_signers file that says whose signature counts, the namespace that
// binds a signature to the project's directory, and finding the file above
// a working directory.
//
// It is public so that chase, which reads, formats, merges and signs the
// same file, uses these functions rather than a copy that could drift: a
// policy chase signs is one frisket verifies. docs/policy.md says what each
// means.
//
// Everything here is a pure function of its arguments and the files it is
// pointed at; nothing reads the environment.
package projpolicy
