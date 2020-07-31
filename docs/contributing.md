# How to contribute to syzkaller

If you want to contribute to the project, feel free to send a pull request following the [guidelines](contributing.md#guidelines) below.

## What to work on

Extending/improving [system call descriptions](syscall_descriptions.md) is always a good idea.

Unassigned issues from the [bug tracker](https://github.com/google/syzkaller/issues) are worth doing, but some of them might be complicated.

To contribute code or syscall descriptions, at the very least you need to be able to build and run syzkaller, see the instructions [here](/docs/setup.md).

If you want to work on something non-trivial, please briefly describe it on the [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller) mailing list first,
so that there is agreement on high level approach and no duplication of work between contributors.

## Guidelines

In case this is your first pull request to syzkaller, you need to:

- Sign [Google CLA](https://cla.developers.google.com/) (if you don't a bot will ask you to do that).
- Add yourself to [AUTHORS](/AUTHORS)/[CONTRIBUTORS](/CONTRIBUTORS) files in the first commit.

### Commits

Commit messages should follow the following template:

```
dir/path: one-line description
<empty line>
Extended multi-line description that includes
the problem you are solving and how it is solved.
```

`dir/path` is a relative path to the main dir this commit changes
(look at examples in the [commit history](https://github.com/google/syzkaller/commits/master)).
If several packages/dirs are significantly affected, then the following format is allowed:
```
dir1/path1, dir2/path2: one-line description
```
Though, dirs should not be included if they have only minor changes.
For pervasive changes the following format is allowed:
```
all: one-line description
```

Please pay attention to punctuation. In particular:

- `one-line description` should *not* start with a Capital letter.
- There is *no dot* at the end of `one-line description`.
- `Extended multi-line description` is full English sentences with Capital letters and dots.

Commit message line length is limited to 120 characters.

Also:

- If you commit fixes an issue, please include `Fixes #NNN` line into commit message
(where `NNN` is the issue number). This will auto-close the issue. If you need to mention
an issue without closing it, add `Update #NNN`.
- For syscall descriptions `*.const` files are checked-in with the `*.txt` changes
in the same commit.

### Pull requests

- Rebase your working branch onto the master branch before sending a pull request to avoid merge conflicts.
- Run `make presubmit` and ensure that it passes before sending a PR.
  It may require some additional packages to be installed (try `sudo make install_prerequisites`).
- Provide a brief high-level description in the pull request title.
  The pull request text is mostly irrelevant, all the details should be in the commit messages.
- If you're asked to add some fixes to your pull request, please squash the fixes into the old commits.

### How to create a pull request on Github

- First, you need an own git fork of syzkaller repository. Nagivate to
[github.com/google/syzkaller](https://github.com/google/syzkaller) and press `Fork` button in the top-right corner of
the page. This will create `https://github.com/YOUR_GITHUB_USERNAME/syzkaller` repository.

- Checkout main syzkaller repository if you have not already. To work with `go` command the checkout must be under
`$GOPATH`. The simplest way to do it is to run `go get -u -d github.com/google/syzkaller/prog`, this will checkout
the repository in `$GOPATH/src/github.com/google/syzkaller`.
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

### Using syz-env

Developing syzkaller requires a number of tools installed (Go toolchain, C/C++ cross-compilers, golangci-lint, etc).
Installing all of them may be cumbersome, e.g. due broken/missing packages.
[syz-env](/tools/syz-env) provides a working hermetic development environment based on a Docker container.
If you don't yet have Docker installed, see [documentation](https://docs.docker.com/engine/install),
in particular regarding enabling [sudo-less](https://docs.docker.com/engine/install/linux-postinstall)
Docker (Googlers see go/docker).

It's recommended to create an alias for `syz-env` script:
```
alias syz-env="$(go env GOPATH)/src/github.com/google/syzkaller/tools/syz-env"
```
Then it can be used to wrap almost any make invocation as:
```
syz-env make format
syz-env make presubmit
syz-env make extract SOURCEDIR=~/linux
```
Or other commands/scripts, e.g.:
```
syz-env go test -short ./pkg/csource
```
Or you may run the shell inside of the container with just `syz-env` and look around.

To update `syz-env` container to the latest version do:

``` bash
docker pull gcr.io/syzkaller/env
```
