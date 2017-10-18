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
