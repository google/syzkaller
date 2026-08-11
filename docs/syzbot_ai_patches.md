# AI-generated patches

`syzbot` investigates kernel bugs and tries to generate fix patches using AI.

To ensure patch quality and adhere to kernel community standards, the AI
patching process follows a two-stage workflow:

1. **Moderation**: Newly generated patches are first posted to an internal moderation
   list, where human reviewers can collaborate with the AI, provide feedback, and
   trigger automated revisions.
2. **Upstream submission**: Once reviewed and signed off by a human developer
   (in accordance with the kernel's [AI Coding Assistants](https://docs.kernel.org/process/coding-assistants.html)
   guidelines), the patch is sent to the Linux Kernel Mailing List (LKML) and
   relevant subsystem lists.

Once sent upstream, patches follow the standard kernel review process: the developer
who signed off on the patch acts as the submitter and handles reviewer feedback,
discussion, and any follow-up revisions.

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
Once a patch is rejected, the AI will stop reacting to further comments on this patch version.

* If you accidentally rejected a patch, you can undo it:
```
#syz unreject
```

* Approve a patch and send it to the public mailing lists:
```
#syz upstream
```

### 2. Linux Kernel Mailing List (LKML)

Once a patch is approved and upstreamed from the moderation list, it is sent to
the public mailing lists (LKML / subsystem lists).

**Important**: `syzbot` does not automatically reply to review comments or send
patch iterations on LKML. The developer who signed off on the patch is
responsible for addressing review feedback, answering questions, and submitting
any necessary follow-up versions.

While syzbot administrators actively monitor upstream patches and can manually
trigger AI iterations internally if appropriate, all interactions and patch
submissions on LKML remain human-driven.

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
`Reviewed-by:`, `Acked-by:`, `Tested-by:`, `Reported-by:`, or `Suggested-by:`.

`syzbot` automatically parses and accumulates these tags from review comments.
When a newer iteration of the patch is generated, these tags are reliably
preserved and appended to the commit message's trailer.

### Who gets the Signed-off-by tag?

When you approve a patch by replying with `#syz upstream`, `syzbot` incorporates
your email and name into a standard `Signed-off-by:` tag and appends it to the
commit message when sending the patch to the next stage (e.g., LKML).

If the patch goes through further iterations on public mailing lists, this
`Signed-off-by:` tag is preserved.

### What happens if I reply without a command?

* **On the moderation mailing list**: Your reply is recorded as review feedback
  on the AI patch job. `syzbot` triggers an iteration job where the AI evaluates
  your comments, addresses questions or change requests, and sends a new version
  of the patch if appropriate (accumulating any provided tags like `Reviewed-by`).
  A plain reply does not advance (`#syz upstream`) or reject (`#syz reject`) the patch.
* **On LKML / public lists**: `syzbot` does not automatically reply or iterate;
  feedback is handled directly by the developer who signed off on the patch.

### What are the requirements for upstreaming?

The AI job must have successfully produced a patch. You cannot use
`#syz upstream` on an AI run that only replied with a textual comment and no
code changes.

If you send `#syz upstream` and do not receive a reply, the command was
processed successfully. The system does not reply back to confirm; it simply
pushes the patch to the next reporting stage.
