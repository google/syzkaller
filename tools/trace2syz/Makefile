adefault:
	(cd trace2syz; ragel -Z -G2 -o lex.go straceLex.rl)
	(cd trace2syz; goyacc -o strace.go -p Strace strace.y)
	mkdir -p bin deserialized
	go build -o ./bin/moonshine main.go
clean:
	rm -f trace2syz/lex.go
	rm -f trace2syz/strace.go
