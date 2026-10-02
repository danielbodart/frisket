// Package execrule is how an SSH route decides a command: the grammar a
// command is read by, and the route's exec rules, env names and unmatched
// matched against what it reads. frisket decides every command a sandbox
// sends with it, and chase tests the catalogue of commands it writes rules
// for with it too, rather than a copy of it that could drift: what chase's
// tests say a command is is what frisket will say.
//
// Everything here is a pure function of its arguments. Compile reads a
// route's Exec, Env and Unmatched -- nothing else of it -- and refuses what
// frisket would refuse to load; Rules.Decide answers one command. docs/ssh.md
// is the reference for what both mean.
package execrule
