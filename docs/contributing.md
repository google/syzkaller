# How to contribute to syzkaller

## Guidelines

If you want to contribute to the project, feel free to send a pull request.

Before sending a pull request you need to [sign Google CLA](https://cla.developers.google.com/)
(if you don't a bot will ask you to do that) and add yourself to
[AUTHORS](/AUTHORS)/[CONTRIBUTORS](/CONTRIBUTORS) files (in case this is your
first pull request to syzkaller).

Some guildelines to follow:

- Commit messages should follow the following template:
```
dir/path: one-line description
<empty line>
Extended multi-line description that includes
the problem you are solving and how it is solved.
```
`dir/path` is a relative path to the main dir this commit changes
(look at examples in the [commit history](https://github.com/google/syzkaller/commits/master)).\
Please pay attention to punctuation. In particular:
- `one-line description` does *not* start with a Capital letter.
- there is *no dot* at the end of `one-line description`.
- `Extended multi-line description` is full English sentenses with Capital letters and dots.

Also:
- If you commit fixes an issue, please include `Fixes #NNN` line into commit message
(where `NNN` is issue number). This will auto-close the issue. If you need to mention
an issue without closing it, add `Update #NNN`.
- The pull request text is mostly irrelevant.
- Run `make presubmit` and ensure that it passes before sending a PR. It may require some additional packages to be installed (try `sudo make install_prerequisites`).
- _All_ generated files (`*.const`, `*.go`, `*.h`) are checked-in with the
`*.txt` changes in the same commit. Namely, `make generate` must not produce
_any_ diff in the tree.
- Rebase your pull request onto the master branch before submitting.
- If you're asked to add some fixes to your pull requested, please squash the new commits with the old ones.

## What to work on

Extending/improving [system call descriptions](syscall_descriptions.md) is always a good idea.

Unassigned issues from the [bug tracker](https://github.com/google/syzkaller/issues) are worth doing, but some of them might be complicated.

If you want to work on something non-trivial, please briefly describe it on the [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller) mailing list first,
so that there is agreement on high level approach and no duplication of work between contributors.

## Go

`syzkaller` is written in [Go](https://golang.org), and a `Go 1.11` or `Go 1.12`
toolchain is required for build. The toolchain can be installed with:

```
go get golang.org/dl/go1.12
go1.12 download
# Default download path is here.
~/sdk/go1.12/bin/go version
export GOROOT=$HOME/sdk/go1.12
export PATH=$HOME/sdk/go1.12/bin:$PATH
```

Then get and build `syzkaller`:

``` bash
go get -u -d github.com/google/syzkaller/...
cd $HOME?/go/src/github.com/google/syzkaller/
make
```

Note: older versions of Go toolchain formatted code in a slightly
[different way](https://github.com/golang/go/issues/25161).
So if you are seeing unrelated code formatting diffs after running `make generate`
or `make format`, you may be using Go 1.10 or older. In such case update to Go 1.11+.

## How to create a pull request

- First, you need an own git fork of syzkaller repository. Nagivate to [github.com/google/syzkaller](https://github.com/google/syzkaller) and press `Fork` button in the top-right corner of the page. This will create `https://github.com/YOUR_GITHUB_USERNAME/syzkaller` repository.
- Checkout main syzkaller repository if you have not already. To work with `go` command the checkout must be under `$GOPATH`. The simplest way to do it is to run `go get github.com/google/syzkaller`, this will checkout the repository in `$GOPATH/src/github.com/google/syzkaller`.
- Remember to `export PATH=$GOPATH/bin:$PATH` if you have not already.
- Then add your repository as an additional origin:

```shell
cd $GOPATH/src/github.com/google/syzkaller
git remote add my-origin https://github.com/YOUR_GITHUB_USERNAME/syzkaller.git
git fetch my-origin
git checkout -b my-branch my-origin/master
```

This adds git origin `my-origin` with your repository and checks out new branch `my-branch` based on `master` branch.

- Change/add files as necessary.
- Commit changes locally. For this you need to run `git add` for all changed files, e.g. `git add sys/linux/sys.txt`. You can run `git status` to see what files were changed/created. When all files are added (`git status` shows no files in `Changes not staged for commit` section and no relevant files in `Untracked files` section), run `git commit` and enter commit description in your editor.
- Run tests locally (`make install_prerequisites` followed by `make presubmit`).
- Push the commit to your fork on github with `git push my-origin my-branch`.
- Nagivate to [github.com/google/syzkaller](https://github.com/google/syzkaller) and you should see green `Compare & pull request` button, press it. Then press `Create pull request`. Now your pull request should show up on [pull requests page](https://github.com/google/syzkaller/pulls).
- If you don't see `Create pull request` button for any reason, you can create pull request manually. For that nagivate to [pull requests page](https://github.com/google/syzkaller/pulls), press `New pull request`, then `compare across forks` and choose `google/syzkaller`/`master` as base and `YOUR_GITHUB_USERNAME/syzkaller`/`my-branch` as compare and press `Create pull request`.
- If you decided to rebase commits in `my-branch` (e.g. to rebase them onto updated master) after you created a pull-request, you will need to do a force push: `git push -f my-origin my-branch`.
