// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/sys/targets"
	"golang.org/x/net/context"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	aemail "google.golang.org/appengine/v2/mail"
)

// Email reporting interface.

func initEmailReporting() {
	http.HandleFunc("/cron/email_poll", handleEmailPoll)
	http.HandleFunc("/_ah/mail/", handleIncomingMail)
	http.HandleFunc("/_ah/bounce", handleEmailBounce)

	mailingLists = make(map[string]bool)
	for _, cfg := range getConfig(context.Background()).Namespaces {
		for _, reporting := range cfg.Reporting {
			if cfg, ok := reporting.Config.(*EmailConfig); ok {
				mailingLists[email.CanonicalEmail(cfg.Email)] = true
			}
		}
	}
}

const (
	emailType = "email"
	// This plays an important role at least for job replies.
	// If we CC a kernel mailing list and it uses Patchwork,
	// then any emails with a patch attached create a new patch
	// entry pending for review. The prefix makes Patchwork
	// treat it as a comment for a previous patch.
	replySubjectPrefix = "Re: "

	replyNoBugID = "I see the command but can't find the corresponding bug.\n" +
		"Please resend the email to %[1]v address\n" +
		"that is the sender of the bug report (also present in the Reported-by tag)."
	replyAmbiguousBugID = "I see the command, but I cannot identify the bug that was meant.\n" +
		"Several bugs with the exact same title were earlier sent to the mailing list.\n" +
		"Please resend the email to %[1]v address\n" +
		"that is the sender of the original bug report (also present in the Reported-by tag)."
	replyBadBugID = "I see the command but can't find the corresponding bug.\n" +
		"The email is sent to  %[1]v address\n" +
		"but the HASH does not correspond to any known bug.\n" +
		"Please double check the address."
)

var mailingLists map[string]bool

type EmailConfig struct {
	Email              string
	HandleListEmails   bool // This is a temporary option to simplify the feature deployment.
	MailMaintainers    bool
	DefaultMaintainers []string
	SubjectPrefix      string
}

func (cfg *EmailConfig) Type() string {
	return emailType
}

func (cfg *EmailConfig) Validate() error {
	if _, err := mail.ParseAddress(cfg.Email); err != nil {
		return fmt.Errorf("bad email address %q: %w", cfg.Email, err)
	}
	for _, email := range cfg.DefaultMaintainers {
		if _, err := mail.ParseAddress(email); err != nil {
			return fmt.Errorf("bad email address %q: %w", email, err)
		}
	}
	if cfg.MailMaintainers && len(cfg.DefaultMaintainers) == 0 {
		return fmt.Errorf("email config: MailMaintainers is set but no DefaultMaintainers")
	}
	if cfg.SubjectPrefix != strings.TrimSpace(cfg.SubjectPrefix) {
		return fmt.Errorf("email config: subject prefix %q contains leading/trailing spaces", cfg.SubjectPrefix)
	}
	return nil
}

// handleEmailPoll is called by cron and sends emails for new bugs, if any.
func handleEmailPoll(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if err := emailPollJobs(c); err != nil {
		log.Errorf(c, "job poll failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := emailPollNotifications(c); err != nil {
		log.Errorf(c, "notif poll failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := emailPollBugs(c); err != nil {
		log.Errorf(c, "bug poll failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := emailPollBugLists(c); err != nil {
		log.Errorf(c, "bug list poll failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("OK"))
}

func emailPollBugLists(c context.Context) error {
	reports := reportingPollBugLists(c, emailType)
	for _, rep := range reports {
		if err := emailSendBugListReport(c, rep); err != nil {
			log.Errorf(c, "emailPollBugLists: %v", err)
		}
	}
	return nil
}

func emailPollBugs(c context.Context) error {
	reports := reportingPollBugs(c, emailType)
	for _, rep := range reports {
		if err := emailSendBugReport(c, rep); err != nil {
			log.Errorf(c, "emailPollBugs: %v", err)
		}
	}
	return nil
}

func emailSendBugReport(c context.Context, rep *dashapi.BugReport) error {
	cfg := new(EmailConfig)
	if err := json.Unmarshal(rep.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %w", err)
	}
	if err := emailReport(c, rep); err != nil {
		return fmt.Errorf("failed to report bug: %w", err)
	}
	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		ReproLevel: dashapi.ReproLevelNone,
		CrashID:    rep.CrashID,
	}
	if len(rep.ReproC) != 0 {
		cmd.ReproLevel = dashapi.ReproLevelC
	} else if len(rep.ReproSyz) != 0 {
		cmd.ReproLevel = dashapi.ReproLevelSyz
	}
	for label := range rep.LabelMessages {
		cmd.Labels = append(cmd.Labels, label)
	}
	ok, reason, err := incomingCommand(c, cmd)
	if !ok || err != nil {
		return fmt.Errorf("failed to update reported bug: ok=%v reason=%v err=%w", ok, reason, err)
	}
	return nil
}

func emailSendBugListReport(c context.Context, rep *dashapi.BugListReport) error {
	cfg := new(EmailConfig)
	if err := json.Unmarshal(rep.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %w", err)
	}
	err := emailListReport(c, rep, cfg)
	if err != nil {
		return fmt.Errorf("failed to send the bug list message: %w", err)
	}
	upd := &dashapi.BugListUpdate{
		ID:      rep.ID,
		Command: dashapi.BugListSentCmd,
	}
	_, err = reportingBugListCommand(c, upd)
	if err != nil {
		return fmt.Errorf("failed to update the bug list: %w", err)
	}
	return nil
}

func emailPollNotifications(c context.Context) error {
	notifs := reportingPollNotifications(c, emailType)
	for _, notif := range notifs {
		if err := emailSendBugNotif(c, notif); err != nil {
			log.Errorf(c, "emailPollNotifications: %v", err)
		}
	}
	return nil
}

func emailSendBugNotif(c context.Context, notif *dashapi.BugNotification) error {
	status, body := dashapi.BugStatusOpen, ""
	var statusReason dashapi.BugStatusReason
	switch notif.Type {
	case dashapi.BugNotifUpstream:
		body = "Sending this report to the next reporting stage."
		status = dashapi.BugStatusUpstream
	case dashapi.BugNotifBadCommit:
		var err error
		body, err = buildBadCommitMessage(c, notif)
		if err != nil {
			return err
		}
	case dashapi.BugNotifObsoleted:
		body = "Auto-closing this bug as obsolete.\n"
		statusReason = dashapi.BugStatusReason(notif.Text)
		if statusReason == dashapi.InvalidatedByRevokedRepro {
			body += "No recent activity, existing reproducers are no longer triggering the issue."
		} else {
			body += "Crashes did not happen for a while, no reproducer and no activity."
		}
		status = dashapi.BugStatusInvalid
	case dashapi.BugNotifLabel:
		bodyBuf := new(bytes.Buffer)
		if err := mailTemplates.ExecuteTemplate(bodyBuf, "mail_label_notif.txt", notif); err != nil {
			return fmt.Errorf("failed to execute mail_label_notif.txt: %w", err)
		}
		body = bodyBuf.String()
	default:
		return fmt.Errorf("bad notification type %v", notif.Type)
	}
	cfg := new(EmailConfig)
	if err := json.Unmarshal(notif.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %w", err)
	}
	to := email.MergeEmailLists([]string{cfg.Email}, notif.CC)
	if cfg.MailMaintainers && notif.Public {
		to = email.MergeEmailLists(to, notif.Maintainers, cfg.DefaultMaintainers)
	}
	from, err := email.AddAddrContext(fromAddr(c), notif.ID)
	if err != nil {
		return err
	}
	log.Infof(c, "sending notif %v for %q to %q: %v", notif.Type, notif.Title, to, body)
	if err := sendMailText(c, cfg, notif.Title, from, to, notif.ExtID, body); err != nil {
		return err
	}
	cmd := &dashapi.BugUpdate{
		ID:           notif.ID,
		Status:       status,
		StatusReason: statusReason,
		Notification: true,
	}
	if notif.Label != "" {
		cmd.Labels = []string{notif.Label}
	}
	ok, reason, err := incomingCommand(c, cmd)
	if !ok || err != nil {
		return fmt.Errorf("notif update failed: ok=%v reason=%v err=%w", ok, reason, err)
	}
	return nil
}

func buildBadCommitMessage(c context.Context, notif *dashapi.BugNotification) (string, error) {
	var sb strings.Builder
	days := int(notifyAboutBadCommitPeriod / time.Hour / 24)
	nsConfig := getNsConfig(c, notif.Namespace)
	fmt.Fprintf(&sb, `This bug is marked as fixed by commit:
%v

But I can't find it in the tested trees[1] for more than %v days.
Is it a correct commit? Please update it by replying:

#syz fix: exact-commit-title

Until then the bug is still considered open and new crashes with
the same signature are ignored.

Kernel: %s
Dashboard link: %s

---
[1] I expect the commit to be present in:
`, notif.Text, days, nsConfig.DisplayTitle, notif.Link)

	repos, err := loadRepos(c, notif.Namespace)
	if err != nil {
		return "", err
	}
	const maxShow = 4
	for i, repo := range repos {
		if i >= maxShow {
			break
		}
		fmt.Fprintf(&sb, "\n%d. %s branch of\n%s\n", i+1, repo.Branch, repo.URL)
	}
	if len(repos) > maxShow {
		fmt.Fprintf(&sb, "\nThe full list of %d trees can be found at\n%s\n",
			len(repos), fmt.Sprintf("%v/%v/repos", appURL(c), notif.Namespace))
	}
	return sb.String(), nil
}

func emailPollJobs(c context.Context) error {
	jobs, err := pollCompletedJobs(c, emailType)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if err := emailReport(c, job); err != nil {
			log.Errorf(c, "failed to report job: %v", err)
			continue
		}
		if err := jobReported(c, job.JobID); err != nil {
			log.Errorf(c, "failed to mark job reported: %v", err)
			continue
		}
	}
	return nil
}

func emailReport(c context.Context, rep *dashapi.BugReport) error {
	cfg := new(EmailConfig)
	if err := json.Unmarshal(rep.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %w", err)
	}
	if rep.UserSpaceArch == targets.AMD64 {
		// This is default, so don't include the info.
		rep.UserSpaceArch = ""
	}
	templ := ""
	switch rep.Type {
	case dashapi.ReportNew, dashapi.ReportRepro:
		templ = "mail_bug.txt"
	case dashapi.ReportTestPatch:
		templ = "mail_test_result.txt"
		cfg.MailMaintainers = false
	case dashapi.ReportBisectCause:
		templ = "mail_bisect_result.txt"
	case dashapi.ReportBisectFix:
		if rep.BisectFix.CrossTree {
			templ = "mail_fix_candidate.txt"
			if rep.BisectFix.Commit == nil {
				return fmt.Errorf("reporting failed fix candidate bisection for %s", rep.ID)
			}
		} else {
			templ = "mail_bisect_result.txt"
		}
	default:
		return fmt.Errorf("unknown report type %v", rep.Type)
	}
	return sendMailTemplate(c, &mailSendParams{
		templateName: templ,
		templateArg:  rep,
		cfg:          cfg,
		title:        generateEmailBugTitle(rep, cfg),
		reportID:     rep.ID,
		replyTo:      rep.ExtID,
		cc:           rep.CC,
		maintainers:  rep.Maintainers,
	})
}

func emailListReport(c context.Context, rep *dashapi.BugListReport, cfg *EmailConfig) error {
	if rep.Moderation {
		cfg.MailMaintainers = false
	}
	args := struct {
		*dashapi.BugListReport
		Table string
	}{BugListReport: rep}

	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "Ref\tCrashes\tRepro\tTitle")
	for i, bug := range rep.Bugs {
		repro := "No"
		if bug.ReproLevel > dashapi.ReproLevelNone {
			repro = "Yes"
		}
		fmt.Fprintf(w, "<%d>\t%d\t%s\t%s\n", i+1, bug.Hits, repro, bug.Title)
		fmt.Fprintf(w, "\t\t\t%s\n", bug.Link)
	}
	w.Flush()
	args.Table = b.String()

	return sendMailTemplate(c, &mailSendParams{
		templateName: "mail_subsystem.txt",
		templateArg:  args,
		cfg:          cfg,
		title: fmt.Sprintf("Monthly %s report (%s)",
			rep.Subsystem, rep.Created.Format("Jan 2006")),
		reportID:    rep.ID,
		maintainers: rep.Maintainers,
	})
}

type mailSendParams struct {
	templateName string
	templateArg  any
	cfg          *EmailConfig
	title        string
	reportID     string
	replyTo      string
	cc           []string
	maintainers  []string
}

func sendMailTemplate(c context.Context, params *mailSendParams) error {
	cfg := params.cfg
	to := email.MergeEmailLists([]string{cfg.Email}, params.cc)
	if cfg.MailMaintainers {
		to = email.MergeEmailLists(to, params.maintainers, cfg.DefaultMaintainers)
	}
	from, err := email.AddAddrContext(fromAddr(c), params.reportID)
	if err != nil {
		return err
	}
	body := new(bytes.Buffer)
	if err := mailTemplates.ExecuteTemplate(body, params.templateName, params.templateArg); err != nil {
		return fmt.Errorf("failed to execute %v template: %w", params.templateName, err)
	}
	log.Infof(c, "sending email %q to %q", params.title, to)
	return sendMailText(c, params.cfg, params.title, from, to, params.replyTo, body.String())
}
func generateEmailBugTitle(rep *dashapi.BugReport, emailConfig *EmailConfig) string {
	title := ""
	for i := len(rep.Subsystems) - 1; i >= 0; i-- {
		question := ""
		if rep.Subsystems[i].SetBy == "" {
			// Include the question mark for automatically created tags.
			question = "?"
		}
		title = fmt.Sprintf("[%s%s] %s", rep.Subsystems[i].Name, question, title)
	}
	return title + rep.Title
}

// handleIncomingMail is the entry point for incoming emails.
func handleIncomingMail(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	url := r.URL.RequestURI()
	myEmail := ""
	if index := strings.LastIndex(url, "/"); index >= 0 {
		myEmail = url[index+1:]
	} else {
		log.Errorf(c, "invalid email handler URL: %s", url)
		return
	}
	source := dashapi.NoDiscussion
	for _, item := range getConfig(c).DiscussionEmails {
		if item.ReceiveAddress != myEmail {
			continue
		}
		source = item.Source
		break
	}
	msg, err := email.Parse(r.Body, ownEmails(c), ownMailingLists(c), []string{
		appURL(c),
	})
	if err != nil {
		// Malformed emails constantly appear from spammers.
		// But we have not seen errors parsing legit emails.
		// These errors are annoying. Warn and ignore them.
		log.Warningf(c, "failed to parse email: %v", err)
		return
	}
	log.Infof(c, "received email at %q, source %q", myEmail, source)
	if source == dashapi.NoDiscussion {
		err = processIncomingEmail(c, msg)
	} else {
		err = processDiscussionEmail(c, msg, source)
	}
	if err != nil {
		log.Errorf(c, "email processing failed: %s", err)
	}
}

// nolint: gocyclo
func processIncomingEmail(c context.Context, msg *email.Email) error {
	// Ignore any incoming emails from syzbot itself.
	if ownEmail(c) == msg.Author {
		// But we still want to remember the id of our own message, so just neutralize the command.
		msg.Commands = nil
	}
	log.Infof(c, "received email: subject %q, author %q, cc %q, msg %q, bug %v, %d cmds, link %q, list %q",
		msg.Subject, msg.Author, msg.Cc, msg.MessageID, msg.BugIDs, len(msg.Commands), msg.Link, msg.MailingList)
	excludeSampleCommands(msg)
	bugInfo, bugListInfo, emailConfig := identifyEmail(c, msg)
	if bugInfo == nil && bugListInfo == nil {
		return nil // error was already logged
	}
	// A mailing list can send us a duplicate email, to not process/reply
	// to such duplicate emails, we ignore emails coming from our mailing lists.
	fromMailingList := msg.MailingList != ""
	missingLists := missingMailingLists(c, msg, emailConfig)
	log.Infof(c, "from/cc mailing list: %v (missing: %v)", fromMailingList, missingLists)
	if fromMailingList && len(msg.BugIDs) > 0 && len(msg.Commands) > 0 {
		// Note that if syzbot was not directly mentioned in To or Cc, this is not really
		// a duplicate message, so it must be processed. We detect it by looking at BugID.

		// There's also a chance that the user mentioned syzbot directly, but without BugID.
		// We don't need to worry about this case, as we won't recognize the bug anyway.
		log.Infof(c, "duplicate email from mailing list, ignoring")
		return nil
	}

	var replies []string
	if bugListInfo != nil {
		const maxCommands = 10
		if len(msg.Commands) > maxCommands {
			return replyTo(c, msg, bugListInfo.id,
				fmt.Sprintf("Too many commands (%d > %d)", len(msg.Commands), maxCommands))
		}
		for _, command := range msg.Commands {
			replies = append(replies, handleBugListCommand(c, bugListInfo, msg, command))
		}
		if reply := groupEmailReplies(replies); reply != "" {
			return replyTo(c, msg, bugListInfo.id, reply)
		}
	} else {
		const maxCommands = 3
		if len(msg.Commands) > maxCommands {
			return replyTo(c, msg, bugInfo.bugReporting.ID,
				fmt.Sprintf("Too many commands (%d > %d)", len(msg.Commands), maxCommands))
		}
		unCc := false
		for _, command := range msg.Commands {
			if command.Command == email.CmdUnCC {
				unCc = true
			}
			replies = append(replies, handleBugCommand(c, bugInfo, msg, command))
		}
		if len(msg.Commands) == 0 {
			// Even if there are 0 commands we'd still like to just ping the bug.
			replies = append(replies, handleBugCommand(c, bugInfo, msg, nil))
		}
		reply := groupEmailReplies(replies)
		if reply == "" && len(msg.Commands) > 0 && len(missingLists) > 0 && !unCc {
			return forwardEmail(c, emailConfig, msg, bugInfo, missingLists)
		}
		if reply != "" {
			return replyTo(c, msg, bugInfo.bugReporting.ID, reply)
		}
	}
	return nil
}

func excludeSampleCommands(msg *email.Email) {
	// Sometimes it happens that somebody sends us our own text back, ignore it.
	var newCommands []*email.SingleCommand
	for _, cmd := range msg.Commands {
		ok := true
		switch cmd.Command {
		case email.CmdFix:
			ok = cmd.Args != "exact-commit-title"
		case email.CmdTest:
			ok = cmd.Args != "git://repo/address.git branch-or-commit-hash"
		case email.CmdSet:
			ok = cmd.Args != "subsystems: new-subsystem"
		case email.CmdUnset:
			ok = cmd.Args != "some-label"
		case email.CmdDup:
			ok = cmd.Args != "exact-subject-of-another-report"
		}
		if ok {
			newCommands = append(newCommands, cmd)
		}
	}
	msg.Commands = newCommands
}

func groupEmailReplies(replies []string) string {
	// If there's just one reply, return it.
	if len(replies) == 1 {
		return replies[0]
	}
	var totalReply strings.Builder
	for i, reply := range replies {
		if reply == "" {
			continue
		}
		if totalReply.Len() > 0 {
			totalReply.WriteString("\n\n")
		}
		totalReply.WriteString(fmt.Sprintf("Command #%d:\n", i+1))
		totalReply.WriteString(reply)
	}
	return totalReply.String()
}

func handleBugCommand(c context.Context, bugInfo *bugInfoResult, msg *email.Email,
	command *email.SingleCommand) string {
	status := dashapi.BugStatusUpdate
	if command != nil {
		status = emailCmdToStatus[command.Command]
	}
	cmd := &dashapi.BugUpdate{
		Status: status,
		ID:     bugInfo.bugReporting.ID,
		ExtID:  msg.MessageID,
		Link:   msg.Link,
		CC:     msg.Cc,
	}
	if command != nil {
		switch command.Command {
		case email.CmdTest:
			return handleTestCommand(c, bugInfo, msg, command)
		case email.CmdSet:
			return handleSetCommand(c, bugInfo.bug, msg, command)
		case email.CmdUnset:
			return handleUnsetCommand(c, bugInfo.bug, msg, command)
		case email.CmdUpstream, email.CmdInvalid, email.CmdUnDup:
		case email.CmdFix:
			if command.Args == "" {
				return "no commit title"
			}
			cmd.FixCommits = []string{command.Args}
		case email.CmdUnFix:
			cmd.ResetFixCommits = true
		case email.CmdDup:
			if command.Args == "" {
				return "no dup title"
			}
			var err error
			cmd.DupOf, err = getSubjectParser(c).parseFullTitle(command.Args)
			if err != nil {
				return "failed to parse the dup title"
			}
		case email.CmdUnCC:
			cmd.CC = []string{msg.Author}
		default:
			if command.Command != email.CmdUnknown {
				log.Errorf(c, "unknown email command %v %q", command.Command, command.Str)
			}
			return fmt.Sprintf("unknown command %q", command.Str)
		}
	}
	ok, reply, err := incomingCommand(c, cmd)
	if err != nil {
		return "" // the error was already logged
	}
	if !ok && reply != "" {
		return reply
	}
	return ""
}

func processDiscussionEmail(c context.Context, msg *email.Email, source dashapi.DiscussionSource) error {
	log.Debugf(c, "processDiscussionEmail %s from source %v", msg.MessageID, source)
	if len(msg.BugIDs) == 0 {
		return nil
	}
	const limitIDs = 10
	if len(msg.BugIDs) > limitIDs {
		msg.BugIDs = msg.BugIDs[:limitIDs]
	}
	log.Debugf(c, "saving to discussions for %q", msg.BugIDs)
	dType := dashapi.DiscussionMention
	if source == dashapi.DiscussionLore {
		dType = lore.DiscussionType(msg)
	}
	extIDs := []string{}
	for _, id := range msg.BugIDs {
		if isBugListHash(id) {
			dType = dashapi.DiscussionReminder
			continue
		}
		_, _, err := findBugByReportingID(c, id)
		if err == nil {
			extIDs = append(extIDs, id)
		}
	}
	msg.BugIDs = extIDs
	err := saveDiscussionMessage(c, msg, source, dType)
	if err != nil {
		return fmt.Errorf("failed to save in discussions: %w", err)
	}
	return nil
}

var emailCmdToStatus = map[email.Command]dashapi.BugStatus{
	email.CmdUpstream: dashapi.BugStatusUpstream,
	email.CmdInvalid:  dashapi.BugStatusInvalid,
	email.CmdUnDup:    dashapi.BugStatusOpen,
	email.CmdFix:      dashapi.BugStatusOpen,
	email.CmdUnFix:    dashapi.BugStatusUpdate,
	email.CmdDup:      dashapi.BugStatusDup,
	email.CmdUnCC:     dashapi.BugStatusUnCC,
}

func handleTestCommand(c context.Context, info *bugInfoResult,
	msg *email.Email, command *email.SingleCommand) string {
	args := strings.Fields(command.Args)
	if len(args) != 0 && len(args) != 2 {
		return fmt.Sprintf("want either no args or 2 args (repo, branch), got %v", len(args))
	}
	repo, branch := "", ""
	if len(args) == 2 {
		repo, branch = args[0], args[1]
	}
	if info.bug.sanitizeAccess(c, AccessPublic) != AccessPublic {
		log.Warningf(c, "%v: bug is not AccessPublic, patch testing request is denied", info.bug.Title)
		return ""
	}
	reply := ""
	err := handleTestRequest(c, &testReqArgs{
		bug: info.bug, bugKey: info.bugKey, bugReporting: info.bugReporting,
		user: msg.Author, extID: msg.MessageID, link: msg.Link,
		patch: []byte(msg.Patch), repo: repo, branch: branch, jobCC: msg.Cc})
	if err != nil {
		var testDenied *TestRequestDeniedError
		var badTest *BadTestRequestError
		switch {
		case errors.As(err, &testDenied):
			// Don't send a reply in this case.
			log.Errorf(c, "patch test request denied: %v", testDenied)
		case errors.As(err, &badTest):
			reply = badTest.Error()
		default:
			// Don't leak any details to the reply email.
			reply = "Processing failed due to an internal error"
			// .. but they are useful for debugging, so we'd like to see it on the Admin page.
			log.Errorf(c, "handleTestRequest error: %v", err)
		}
	}
	return reply
}

var (
	// The supported formats are:
	// For bugs:
	// #syz set LABEL[: value_1, [value_2, ....]]
	// For bug lists:
	// #syz set <N> LABEL[: value_1, [value_2, ....]]
	setCmdRe         = regexp.MustCompile(`(?m)\s*([-\w]+)\s*(?:\:\s*([,\-\w\s]*?))?$`)
	setCmdArgSplitRe = regexp.MustCompile(`[\s,]+`)
	setBugCmdFormat  = `I've failed to parse your command. Please use the following format(s):
#syz set some-flag
#syz set label: value
#syz set subsystems: one-subsystem, another-subsystem

Or, for bug lists,
#syz set <Ref> some-flag
#syz set <Ref> label: value
#syz set <Ref> subsystems: one-subsystem, another-subsystem

The following labels are suported:
%s`
	setCmdUnknownLabel = `The specified label %q is unknown.
Please use one of the supported labels.

The following labels are suported:
%s`
	setCmdUnknownValue = `The specified label value is incorrect.
%s.
Please use one of the supported label values.

The following labels are suported:
%s`
	cmdInternalErrorReply = `The command was not executed due to an internal error.
Please contact the bot's maintainers.`
)

func handleSetCommand(c context.Context, bug *Bug, msg *email.Email,
	command *email.SingleCommand) string {
	labelSet := makeLabelSet(c, bug.Namespace)

	match := setCmdRe.FindStringSubmatch(command.Args)
	if match == nil {
		return fmt.Sprintf(setBugCmdFormat, labelSet.Help())
	}
	label, values := BugLabelType(match[1]), match[2]
	log.Infof(c, "bug=%q label=%s values=%s", bug.displayTitle(), label, values)
	if !labelSet.FindLabel(label) {
		return fmt.Sprintf(setCmdUnknownLabel, label, labelSet.Help())
	}
	var labels []BugLabel
	for _, value := range unique(setCmdArgSplitRe.Split(values, -1)) {
		labels = append(labels, BugLabel{
			Label: label,
			Value: value,
			SetBy: msg.Author,
			Link:  msg.Link,
		})
	}
	var setError error
	err := updateSingleBug(c, bug.key(c), func(bug *Bug) error {
		setError = bug.SetLabels(labelSet, labels)
		return setError
	})
	if setError != nil {
		return fmt.Sprintf(setCmdUnknownValue, setError, labelSet.Help())
	}
	if err != nil {
		log.Errorf(c, "failed to set bug tags: %s", err)
		return cmdInternalErrorReply
	}
	return ""
}

var (
	unsetBugCmdFormat = `I've failed to parse your command. Please use the following format(s):
#syz unset any-label

Or, for bug lists,
#syz unset <Ref> any-label
`
	unsetLabelsNotFound = `The following labels did not exist: %s`
)

func handleUnsetCommand(c context.Context, bug *Bug, msg *email.Email,
	command *email.SingleCommand) string {
	match := setCmdRe.FindStringSubmatch(command.Args)
	if match == nil {
		return unsetBugCmdFormat
	}
	var labels []BugLabelType
	for _, name := range unique(setCmdArgSplitRe.Split(command.Args, -1)) {
		labels = append(labels, BugLabelType(name))
	}

	var notFound map[BugLabelType]struct{}
	var notFoundErr = fmt.Errorf("some labels were not found")
	err := updateSingleBug(c, bug.key(c), func(bug *Bug) error {
		notFound = bug.UnsetLabels(labels...)
		if len(notFound) > 0 {
			return notFoundErr
		}
		return nil
	})
	if err == notFoundErr {
		var names []string
		for label := range notFound {
			names = append(names, string(label))
		}
		return fmt.Sprintf(unsetLabelsNotFound, strings.Join(names, ", "))
	} else if err != nil {
		log.Errorf(c, "failed to unset bug labels: %s", err)
		return cmdInternalErrorReply
	}
	return ""
}

func handleEmailBounce(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf(c, "email bounced: failed to read body: %v", err)
		return
	}
	if nonCriticalBounceRe.Match(body) {
		log.Infof(c, "email bounced: address not found")
	} else {
		log.Errorf(c, "email bounced")
	}
	log.Infof(c, "%s", body)
}

var (
	setGroupCmdRe     = regexp.MustCompile(`(?m)\s*<(\d+)>\s*(.*)$`)
	setGroupCmdFormat = `I've failed to parse your command. Please use the following format(s):
#syz set <Ref> some-label, another-label
#syz set <Ref> subsystems: one-subsystem, another-subsystem
#syz unset <Ref> some-label
`
	setGroupCmdBadRef = `The specified <Ref> number is invalid. It must be one of the <NUM> values
listed in the bug list table.
`
)

func handleBugListCommand(c context.Context, bugListInfo *bugListInfoResult,
	msg *email.Email, command *email.SingleCommand) string {
	upd := &dashapi.BugListUpdate{
		ID:    bugListInfo.id,
		ExtID: msg.MessageID,
		Link:  msg.Link,
	}
	switch command.Command {
	case email.CmdUpstream:
		upd.Command = dashapi.BugListUpstreamCmd
	case email.CmdRegenerate:
		upd.Command = dashapi.BugListRegenerateCmd
	case email.CmdSet, email.CmdUnset:
		// Extract and cut the <Ref> part.
		match := setGroupCmdRe.FindStringSubmatch(command.Args)
		if match == nil {
			return setGroupCmdFormat
		}
		ref, args := match[1], match[2]
		numRef, err := strconv.Atoi(ref)
		if err != nil {
			return setGroupCmdFormat
		}
		if numRef < 1 || numRef > len(bugListInfo.keys) {
			return setGroupCmdBadRef
		}
		bugKey := bugListInfo.keys[numRef-1]
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			log.Errorf(c, "failed to fetch bug by key %s: %s", bugKey, err)
			return cmdInternalErrorReply
		}
		command.Args = args
		switch command.Command {
		case email.CmdSet:
			return handleSetCommand(c, bug, msg, command)
		case email.CmdUnset:
			return handleUnsetCommand(c, bug, msg, command)
		}
	default:
		upd.Command = dashapi.BugListUpdateCmd
	}
	log.Infof(c, "bug list update: id=%s, cmd=%v", upd.ID, upd.Command)
	reply, err := reportingBugListCommand(c, upd)
	if err != nil {
		log.Errorf(c, "bug list command failed: %s", err)
		return cmdInternalErrorReply
	}
	return reply
}

// These are just stale emails in MAINTAINERS.
var nonCriticalBounceRe = regexp.MustCompile(`\*\* Address not found \*\*|550 #5\.1\.0 Address rejected`)

type bugListInfoResult struct {
	id     string
	config *EmailConfig
	keys   []*db.Key
}

func identifyEmail(c context.Context, msg *email.Email) (*bugInfoResult, *bugListInfoResult, *EmailConfig) {
	bugID := ""
	if len(msg.BugIDs) > 0 {
		// For now let's only consider one of them.
		bugID = msg.BugIDs[0]
	}
	if isBugListHash(bugID) {
		subsystem, report, stage, err := findSubsystemReportByID(c, bugID)
		if err != nil {
			log.Errorf(c, "findBugListByID failed: %s", err)
			return nil, nil, nil
		}
		if subsystem == nil {
			log.Errorf(c, "no bug list with the %v ID found", bugID)
			return nil, nil, nil
		}
		reminderConfig := getNsConfig(c, subsystem.Namespace).Subsystems.Reminder
		if reminderConfig == nil {
			log.Errorf(c, "reminder configuration is empty")
			return nil, nil, nil
		}
		emailConfig, ok := bugListReportingConfig(c, subsystem.Namespace, stage).(*EmailConfig)
		if !ok {
			log.Errorf(c, "bug list's reporting config is not EmailConfig (id=%v)", bugID)
			return nil, nil, nil
		}
		keys, err := report.getBugKeys()
		if err != nil {
			log.Errorf(c, "failed to extract keys from bug list: %s", err)
			return nil, nil, nil
		}
		return nil, &bugListInfoResult{
			id:     bugID,
			config: emailConfig,
			keys:   keys,
		}, emailConfig
	}
	bugInfo := loadBugInfo(c, msg)
	if bugInfo == nil {
		return nil, nil, nil
	}
	return bugInfo, nil, bugInfo.reporting.Config.(*EmailConfig)
}

type bugInfoResult struct {
	bug          *Bug
	bugKey       *db.Key
	bugReporting *BugReporting
	reporting    *Reporting
}

func loadBugInfo(c context.Context, msg *email.Email) *bugInfoResult {
	bugID := ""
	if len(msg.BugIDs) > 0 {
		// For now let's only consider one of them.
		bugID = msg.BugIDs[0]
	}
	if bugID == "" {
		var matchingErr error
		// Give it one more try -- maybe we can determine the bug from the subject + mailing list.
		if msg.MailingList != "" {
			var ret *bugInfoResult
			ret, matchingErr = matchBugFromList(c, msg.MailingList, msg.Subject)
			if matchingErr == nil {
				return ret
			}
			log.Infof(c, "mailing list matching failed: %s", matchingErr)
		}
		if len(msg.Commands) == 0 {
			// This happens when people CC syzbot on unrelated emails.
			log.Infof(c, "no bug ID (%q)", msg.Subject)
		} else {
			log.Errorf(c, "no bug ID (%q)", msg.Subject)
			from, err := email.AddAddrContext(ownEmail(c), "HASH")
			if err != nil {
				log.Errorf(c, "failed to format sender email address: %v", err)
				from = "ERROR"
			}
			message := fmt.Sprintf(replyNoBugID, from)
			if matchingErr == errAmbiguousTitle {
				message = fmt.Sprintf(replyAmbiguousBugID, from)
			}
			if err := replyTo(c, msg, "", message); err != nil {
				log.Errorf(c, "failed to send reply: %v", err)
			}
		}
		return nil
	}
	bug, bugKey, err := findBugByReportingID(c, bugID)
	if err != nil {
		log.Errorf(c, "can't find bug: %v", err)
		from, err := email.AddAddrContext(ownEmail(c), "HASH")
		if err != nil {
			log.Errorf(c, "failed to format sender email address: %v", err)
			from = "ERROR"
		}
		if err := replyTo(c, msg, "", fmt.Sprintf(replyBadBugID, from)); err != nil {
			log.Errorf(c, "failed to send reply: %v", err)
		}
		return nil
	}
	bugReporting, _ := bugReportingByID(bug, bugID)
	if bugReporting == nil {
		log.Errorf(c, "can't find bug reporting: %v", err)
		if err := replyTo(c, msg, "", "Can't find the corresponding bug."); err != nil {
			log.Errorf(c, "failed to send reply: %v", err)
		}
		return nil
	}
	reporting := getNsConfig(c, bug.Namespace).ReportingByName(bugReporting.Name)
	if reporting == nil {
		log.Errorf(c, "can't find reporting for this bug: namespace=%q reporting=%q",
			bug.Namespace, bugReporting.Name)
		return nil
	}
	if reporting.Config.Type() != emailType {
		log.Errorf(c, "reporting is not email: namespace=%q reporting=%q config=%q",
			bug.Namespace, bugReporting.Name, reporting.Config.Type())
		return nil
	}
	return &bugInfoResult{bug, bugKey, bugReporting, reporting}
}

func ownMailingLists(c context.Context) []string {
	configs := []ReportingType{}
	for _, ns := range getConfig(c).Namespaces {
		for _, rep := range ns.Reporting {
			configs = append(configs, rep.Config)
		}
		if ns.Subsystems.Reminder == nil {
			continue
		}
		reminderConfig := ns.Subsystems.Reminder
		if reminderConfig.ModerationConfig != nil {
			configs = append(configs, reminderConfig.ModerationConfig)
		}
		if reminderConfig.Config != nil {
			configs = append(configs, reminderConfig.Config)
		}
	}
	ret := []string{}
	for _, config := range configs {
		emailConfig, ok := config.(*EmailConfig)
		if !ok {
			continue
		}
		ret = append(ret, emailConfig.Email)
	}
	return ret
}

var (
	// Use getSubjectParser(c) instead.
	defaultSubjectParser *subjectTitleParser
	subjectParserInit    sync.Once
	errAmbiguousTitle    = errors.New("ambiguous bug title")
)

func getSubjectParser(c context.Context) *subjectTitleParser {
	if getConfig(c) != getConfig(context.Background()) {
		// For the non-default config, do not cache the parser.
		return makeSubjectTitleParser(c)
	}
	subjectParserInit.Do(func() {
		defaultSubjectParser = makeSubjectTitleParser(c)
	})
	return defaultSubjectParser
}

func matchBugFromList(c context.Context, sender, subject string) (*bugInfoResult, error) {
	title, seq, err := getSubjectParser(c).parseTitle(subject)
	if err != nil {
		return nil, err
	}
	// Query all bugs with this title.
	var bugs []*Bug
	bugKeys, err := db.NewQuery("Bug").
		Filter("Title=", title).
		GetAll(c, &bugs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bugs: %w", err)
	}
	// Filter the bugs by the email.
	candidates := []*bugInfoResult{}
	for i, bug := range bugs {
		log.Infof(c, "processing bug %v", bug.displayTitle())
		// We could add it to the query, but it's probably not worth it - we already have
		// tons of db indexes while the number of matching bugs should not be large anyway.
		if bug.Seq != seq {
			log.Infof(c, "bug's seq is %v, wanted %d", bug.Seq, seq)
			continue
		}
		if bug.sanitizeAccess(c, AccessPublic) != AccessPublic {
			log.Infof(c, "access denied")
			continue
		}
		reporting, bugReporting, _, _, err := currentReporting(c, bug)
		if err != nil || reporting == nil {
			log.Infof(c, "could not query reporting: %s", err)
			continue
		}
		emailConfig, ok := reporting.Config.(*EmailConfig)
		if !ok {
			log.Infof(c, "reporting is not EmailConfig (%q)", subject)
			continue
		}
		if !emailConfig.HandleListEmails {
			log.Infof(c, "the feature is disabled for the config")
			continue
		}
		if emailConfig.Email != sender {
			log.Infof(c, "config's Email is %v, wanted %v", emailConfig.Email, sender)
			continue
		}
		candidates = append(candidates, &bugInfoResult{
			bug: bug, bugKey: bugKeys[i],
			bugReporting: bugReporting, reporting: reporting,
		})
	}
	if len(candidates) > 1 {
		return nil, errAmbiguousTitle
	} else if len(candidates) == 0 {
		return nil, fmt.Errorf("unable to determine the bug")
	}
	return candidates[0], nil
}

type subjectTitleParser struct {
	pattern *regexp.Regexp
}

func makeSubjectTitleParser(c context.Context) *subjectTitleParser {
	stripPrefixes := []string{`R[eE]:`}
	for _, ns := range getConfig(c).Namespaces {
		for _, rep := range ns.Reporting {
			emailConfig, ok := rep.Config.(*EmailConfig)
			if !ok {
				continue
			}
			if ok && emailConfig.SubjectPrefix != "" {
				stripPrefixes = append(stripPrefixes,
					regexp.QuoteMeta(emailConfig.SubjectPrefix))
			}
		}
	}
	rePrefixes := `^(?:(?:` + strings.Join(stripPrefixes, "|") + `)\s*)*`
	pattern := regexp.MustCompile(rePrefixes + `(?:\[[^\]]+\]\s*)*\s*(.*)$`)
	return &subjectTitleParser{pattern}
}

func (p *subjectTitleParser) parseTitle(subject string) (string, int64, error) {
	rawTitle, err := p.parseFullTitle(subject)
	if err != nil {
		return "", 0, err
	}
	return splitDisplayTitle(rawTitle)
}

func (p *subjectTitleParser) parseFullTitle(subject string) (string, error) {
	subject = strings.TrimSpace(subject)
	parts := p.pattern.FindStringSubmatch(subject)
	if parts == nil || parts[len(parts)-1] == "" {
		return "", fmt.Errorf("failed to extract the title")
	}
	return parts[len(parts)-1], nil
}

func missingMailingLists(c context.Context, msg *email.Email, emailConfig *EmailConfig) []string {
	// We want to ensure that the incoming message is recorded on both our mailing list
	// and the archive mailing list (in case of Linux -- linux-kernel@vger.kernel.org).
	mailingLists := []string{
		email.CanonicalEmail(emailConfig.Email),
	}
	if emailConfig.MailMaintainers {
		mailingLists = append(mailingLists, emailConfig.DefaultMaintainers...)
	}
	// Consider all recipients.
	exists := map[string]struct{}{}
	if msg.MailingList != "" {
		exists[msg.MailingList] = struct{}{}
	}
	for _, email := range msg.Cc {
		exists[email] = struct{}{}
	}
	var missing []string
	for _, list := range mailingLists {
		if _, ok := exists[list]; !ok {
			missing = append(missing, list)
		}
	}
	sort.Strings(missing)
	msg.Cc = append(msg.Cc, missing...)
	return missing
}

func forwardEmail(c context.Context, cfg *EmailConfig, msg *email.Email,
	info *bugInfoResult, mailingLists []string) error {
	log.Infof(c, "forwarding email: id=%q from=%q to=%q", msg.MessageID, msg.Author, mailingLists)
	body := fmt.Sprintf(`For archival purposes, forwarding an incoming command email to
%v.

***

Subject: %s
Author: %s

%s`, strings.Join(mailingLists, ", "), msg.Subject, msg.Author, msg.Body)
	from, err := email.AddAddrContext(fromAddr(c), info.bugReporting.ID)
	if err != nil {
		return err
	}
	return sendMailText(c, cfg, msg.Subject, from, mailingLists, info.bugReporting.ExtID, body)
}

func sendMailText(c context.Context, cfg *EmailConfig, subject, from string, to []string, replyTo, body string) error {
	msg := &aemail.Message{
		Sender:  from,
		To:      to,
		Subject: subject,
		Body:    body,
	}
	if cfg.SubjectPrefix != "" {
		msg.Subject = cfg.SubjectPrefix + " " + msg.Subject
	}
	if replyTo != "" {
		msg.Headers = mail.Header{"In-Reply-To": []string{replyTo}}
		msg.Subject = replySubject(msg.Subject)
	}
	return sendEmail(c, msg)
}

func replyTo(c context.Context, msg *email.Email, bugID, reply string) error {
	from, err := email.AddAddrContext(fromAddr(c), bugID)
	if err != nil {
		log.Errorf(c, "failed to build the From address: %v", err)
		return err
	}
	log.Infof(c, "sending reply: to=%q cc=%q subject=%q reply=%q",
		msg.Author, msg.Cc, msg.Subject, reply)
	replyMsg := &aemail.Message{
		Sender:  from,
		To:      []string{msg.Author},
		Cc:      msg.Cc,
		Subject: replySubject(msg.Subject),
		Body:    email.FormReply(msg, reply),
		Headers: mail.Header{"In-Reply-To": []string{msg.MessageID}},
	}
	return sendEmail(c, replyMsg)
}

// Sends email, can be stubbed for testing.
var sendEmail = func(c context.Context, msg *aemail.Message) error {
	if err := aemail.Send(c, msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}

func replySubject(subject string) string {
	if !strings.HasPrefix(subject, replySubjectPrefix) {
		return replySubjectPrefix + subject
	}
	return subject
}

func ownEmail(c context.Context) string {
	if getConfig(c).OwnEmailAddress != "" {
		return getConfig(c).OwnEmailAddress
	}
	return fmt.Sprintf("syzbot@%v.appspotmail.com", appengine.AppID(c))
}

func fromAddr(c context.Context) string {
	return fmt.Sprintf("\"syzbot\" <%v>", ownEmail(c))
}

func ownEmails(c context.Context) []string {
	emails := []string{ownEmail(c)}
	config := getConfig(c)
	if config.ExtraOwnEmailAddresses != nil {
		emails = append(emails, config.ExtraOwnEmailAddresses...)
	} else if config.OwnEmailAddress == "" {
		// Now we use syzbot@ but we used to use bot@, so we add them both.
		emails = append(emails, fmt.Sprintf("bot@%v.appspotmail.com", appengine.AppID(c)))
	}
	return emails
}

func sanitizeCC(c context.Context, cc []string) []string {
	var res []string
	for _, addr := range cc {
		mail, err := mail.ParseAddress(addr)
		if err != nil {
			continue
		}
		if email.CanonicalEmail(mail.Address) == ownEmail(c) {
			continue
		}
		res = append(res, mail.Address)
	}
	return res
}

func externalLink(c context.Context, tag string, id int64) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("%v/x/%v?x=%v", appURL(c), textFilename(tag), strconv.FormatUint(uint64(id), 16))
}

func appURL(c context.Context) string {
	appURL := getConfig(c).AppURL
	if appURL != "" {
		return appURL
	}
	return fmt.Sprintf("https://%v.appspot.com", appengine.AppID(c))
}

var mailTemplates = html.CreateTextGlob("mail_*.txt")
