# inamedparam

A linter that reports interfaces with unnamed method parameters.

## Usage 

### Standalone
You can also run it standalone through `go vet`.  

You must install the binary to your `$GOBIN` folder like so:
```sh
$ go install github.com/macabu/inamedparam/cmd/inamedparam
```

And then navigate to your Go project's root folder, where can run `go vet` in the following way:
```sh
$ go vet -vettool=$(which inamedparam) ./...
```
