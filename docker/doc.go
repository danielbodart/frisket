// Package docker is what frisket shares, for its Docker route, with the
// programs that configure it: which images a route may name. chase checks
// the images a project lists with these same functions rather than a copy
// of them, so the two cannot disagree.
//
// A Docker project's address and name are not this package's: they are the
// project address (package project), which the Docker route is one user
// of -- frisket refuses a route whose address or names are not the ones
// project.Address and project.Names give.
package docker
