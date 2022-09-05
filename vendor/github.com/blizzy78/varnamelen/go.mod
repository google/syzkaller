module github.com/blizzy78/varnamelen

go 1.16

require (
	github.com/matryer/is v1.4.0
	golang.org/x/sys v0.0.0-20211105183446-c75c47738b0c // indirect
	golang.org/x/tools v0.1.10
)

retract (
	v0.6.1 // see https://github.com/blizzy78/varnamelen/issues/13, use 0.6.2 or later instead
)
