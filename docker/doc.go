// Package docker is what frisket shares with the programs that configure it:
// the loopback address and the .internal name a project is known by, the
// names no project may take, and which images a route may name. chase
// derives a project's address and names at launch, and checks the images a
// project lists, with these same functions rather than a copy of them, so
// the three cannot disagree -- frisket refuses a route whose address or
// names are not the ones Address and Names give.
//
// Everything here is a pure function of its arguments and of reserved.json,
// which the flake also exports as lib.docker.reserved. A name reads back as
// its project (Project), so `frisket dns` answers any project's name on the
// host with nothing to look it up in.
package docker
