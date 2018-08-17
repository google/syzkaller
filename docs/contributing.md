# How to contribute to syzkaller

## Guidelines

If you want to contribute to the project, feel free to send a pull request.

Before sending a pull request you need to [sign Google CLA](https://cla.developers.google.com/) (if you don't a bot will ask you to do that)
and add yourself to [AUTHORS](/AUTHORS)/[CONTRIBUTORS](/CONTRIBUTORS) files (in case this is your first pull request to syzkaller).

Some guildelines to follow:

- Commit messages should follow the following template:
```
package: one-line description
<empty line>
Extended multi-line description that includes
the problem you are solving and how it is solved.
```
`package` is the package/tool this commit changes
(look at examples in the [commit history](https://github.com/google/syzkaller/commits/master))
- The pull request text is mostly irrelevant
- Run `make presubmit` and ensure that it passes before sending a PR. It may require some additional packages to be installed (try `sudo make install_prerequisites`)
- Rebase your pull request onto the master branch before submitting
- If you're asked to add some fixes to your pull requested, please squash the new commits with the old ones

## What to work on

Extending/improving [system call descriptions](syscall_descriptions.md) is always a good idea.

Unassigned issues from the [bug tracker](https://github.com/google/syzkaller/issues) are worth doing, but some of them might be complicated.

If you want to work on something non-trivial, please briefly describe it on the [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller) mailing list first,
so that there is agreement on high level approach and no duplication of work between contributors.

## How to create a pull request

- First, you need an own git fork of syzkaller repository. Nagivate to [github.com/google/syzkaller](https://github.com/google/syzkaller) and press `Fork` button in the top-right corner of the page. This will create `https://github.com/YOUR_GITHUB_USERNAME/syzkaller` repository.
- Checkout main syzkaller repository if you have not already. To work with `go` command the checkout must be under `$GOPATH`. The simplest way to do it is to run `go get github.com/google/syzkaller`, this will checkout the repository in `$GOPATH/src/github.com/google/syzkaller`.
- Then add your repository as an additional origin:

```shell
cd $GOPATH/src/github.com/google/syzkaller
git remote add my-origin https://github.com/YOUR_GITHUB_USERNAME/syzkaller.git
git fetch my-origin
git checkout -b my-branch master
```

This adds git origin `my-origin` with your repository and checks out new branch `my-branch` based on `master` branch.

- Change/add files as necessary.
- Commit changes locally. For this you need to run `git add` for all changed files, e.g. `git add sys/linux/sys.txt`. You can run `git status` to see what files were changed/created. When all files are added (`git status` shows no files in `Changes not staged for commit` section and no relevant files in `Untracked files` section), run `git commit` and enter commit description in your editor.
- Run tests locally (`make install_prerequisites` followed by `make presubmit`).
- *Important* If you've run `go fmt` and you're seeing the presubmit fail on
  `check_diff`, then you may need to use an older version of go to format your
  code. (Version 1.11 in particular introduced a breaking change, see
  [here](https://github.com/golang/go/issues/25161) and
  [here](https://github.com/golang/go/issues/26228) for details). A
  simple way to do this is:
  ```go get golang.org/dl/go1.10
  go1.10 download
  # Default download path is here.
  ~/sdk/go1.10/bin/go fmt [target files]```
- Push the commit to your fork on github with `git push my-origin my-branch`.
- Nagivate to [github.com/google/syzkaller](https://github.com/google/syzkaller) and you should see green `Compare & pull request` button, press it. Then press `Create pull request`. Now your pull request should show up on [pull requests page](https://github.com/google/syzkaller/pulls).
- If you don't see `Create pull request` button for any reason, you can create pull request manually. For that nagivate to [pull requests page](https://github.com/google/syzkaller/pulls), press `New pull request`, then `compare across forks` and choose `google/syzkaller`/`master` as base and `YOUR_GITHUB_USERNAME/syzkaller`/`my-branch` as compare and press `Create pull request`.
- If you decided to rebase commits in `my-branch` (e.g. to rebase them onto updated master) after you created a pull-request, you will need to do a force push: `git push -f my-origin my-branch`.
