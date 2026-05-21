# AI-generated patches

`syzbot` tries to automatically generate and send patches for found bugs using AI.

Patches mailed to the kernel mailing lists were reviewed and `Signed-off-by`
by at least one human developer in accordance with
[AI Coding Assistants](https://docs.kernel.org/process/coding-assistants.html)
guidelines.

You can comment on the patches as usual, and ask for changes to the code and/or
description, ask to include tags, or ask clarifying questions.
`syzbot` will try to address the comments and send a new version of the patch
if necessary. Comments may be batched, so the reply may take up to
several hours.

## The Intended Workflow

syzbot's AI patch reporting follows a two-stage pipeline to refine the patch
before publishing it to the wider community.

### 1. Moderation Stage

Newly generated patches are first sent to an internal moderation mailing list
(`syzkaller-upstream-moderation@googlegroups.com`) where the bot actively
listens and participates. You can:

* Reply to the patch email with text comments to provide feedback and request
changes. The AI model will read the comments and reply or send a new patch
version (e.g. an RFC v2) if necessary.

* Reject a fundamentally flawed patch:
```
#syz reject
```
You can provide the reason for rejection in the email body for better accounting.

* If you accidentally rejected a patch, you can undo it:
```
#syz unreject
```

* Approve a patch and send it to the public list:
```
#syz upstream
```

### 2. Linux Kernel Mailing List (LKML)

Once a patch is upstreamed from the moderation list, it is sent to the public
LKML.

**Note**: in this stage, the syzbot AI's automatic reaction to code review
comments is currently disabled to avoid spamming the public mailing
list. However, syzbot administrators actively monitor these patches and can
manually force the agent to incorporate mailing list feedback and send newer
versions.

## System Invariants and Rules

`syzbot` maintains strict rules about tracking and handling AI patches based on
email replies.

### Which patch version am I interacting with?

Each patch version (e.g., v1, v2) is sent as a separate email thread. `syzbot`
uses the `In-Reply-To` email header to identify exactly which version of the
patch you are interacting with.

You can reply to any patch version's thread, not just the latest one. Commands
like `#syz upstream` or `#syz reject` will only apply to the specific version
you are replying to.

### Can I upstream multiple versions of the same patch?

No. `syzbot` prevents upstreaming multiple patch iterations for the same bug
simultaneously to avoid spamming the upstream list.

If you upstream "v1" and later decide "v2" is better, an attempt to
`#syz upstream` "v2" will be blocked. You must first reply to the previously
upstreamed version ("v1") with:
```
#syz reject
```
Once rejected, the system clears the conflict, and you can successfully
`#syz upstream` the new version.

### What happens to my tags (Reviewed-by, Acked-by)?

During the review process, reviewers often provide standard tags like
`Reviewed-by:`, `Acked-by:`, `Tested-by:`, or `Reported-by:`.

`syzbot` automatically parses and accumulates these tags from review comments.
When a newer iteration of the patch is generated, these tags are reliably
preserved and appended to the commit message's trailer.

### Who gets the Signed-off-by tag?

When you approve a patch by replying with `#syz upstream`, `syzbot` incorporates
your email and name into a standard `Signed-off-by:` tag and appends it to the
commit message when sending the patch to the next stage (e.g., LKML).

If the patch goes through further iterations on the public list, this
`Signed-off-by:` tag is preserved.

### What happens if I reply without a command?

If you reply to the patch without `#syz upstream` or `#syz reject`, your reply
is simply recorded as a comment on that specific AI patch job in the dashboard.
It does not advance or reject the patch on its own.

**Note**: AI will evaluate your comment to decide if a new version is needed.
Simply providing a tag (like `Reviewed-by`) will not trigger the generation of
a new patch version on its own.

### What are the requirements for upstreaming?

The AI job must have successfully produced a patch. You cannot use
`#syz upstream` on an AI run that only replied with a textual comment and no
code changes.

If you send `#syz upstream` and do not receive a reply, the command was
processed successfully. The system does not reply back to confirm; it simply
pushes the patch to the next reporting stage.
