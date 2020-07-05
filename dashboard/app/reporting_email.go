// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/html"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	aemail "google.golang.org/appengine/mail"
)

// Email reporting interface.

func initEmailReporting() {
	http.HandleFunc("/email_poll", handleEmailPoll)
	http.HandleFunc("/_ah/mail/", handleIncomingMail)
	http.HandleFunc("/_ah/bounce", handleEmailBounce)

	mailingLists = make(map[string]bool)
	for _, cfg := range config.Namespaces {
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
	replyBadBugID = "I see the command but can't find the corresponding bug.\n" +
		"The email is sent to  %[1]v address\n" +
		"but the HASH does not correspond to any known bug.\n" +
		"Please double check the address."
)

var mailingLists map[string]bool

type EmailConfig struct {
	Email              string
	MailMaintainers    bool
	DefaultMaintainers []string
}

func (cfg *EmailConfig) Type() string {
	return emailType
}

func (cfg *EmailConfig) Validate() error {
	if _, err := mail.ParseAddress(cfg.Email); err != nil {
		return fmt.Errorf("bad email address %q: %v", cfg.Email, err)
	}
	for _, email := range cfg.DefaultMaintainers {
		if _, err := mail.ParseAddress(email); err != nil {
			return fmt.Errorf("bad email address %q: %v", email, err)
		}
	}
	if cfg.MailMaintainers && len(cfg.DefaultMaintainers) == 0 {
		return fmt.Errorf("email config: MailMaintainers is set but no DefaultMaintainers")
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
	w.Write([]byte("OK"))
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
		return fmt.Errorf("failed to unmarshal email config: %v", err)
	}
	if err := emailReport(c, rep); err != nil {
		return fmt.Errorf("failed to report bug: %v", err)
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
	ok, reason, err := incomingCommand(c, cmd)
	if !ok || err != nil {
		return fmt.Errorf("failed to update reported bug: ok=%v reason=%v err=%v", ok, reason, err)
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
	switch notif.Type {
	case dashapi.BugNotifUpstream:
		body = "Sending this report upstream."
		status = dashapi.BugStatusUpstream
	case dashapi.BugNotifBadCommit:
		days := int(notifyAboutBadCommitPeriod / time.Hour / 24)
		body = fmt.Sprintf("This bug is marked as fixed by commit:\n%v\n"+
			"But I can't find it in any tested tree for more than %v days.\n"+
			"Is it a correct commit? Please update it by replying:\n"+
			"#syz fix: exact-commit-title\n"+
			"Until then the bug is still considered open and\n"+
			"new crashes with the same signature are ignored.\n",
			notif.Text, days)
	case dashapi.BugNotifObsoleted:
		body = "Auto-closing this bug as obsolete.\n" +
			"Crashes did not happen for a while, no reproducer and no activity."
		status = dashapi.BugStatusInvalid
	default:
		return fmt.Errorf("bad notification type %v", notif.Type)
	}
	cfg := new(EmailConfig)
	if err := json.Unmarshal(notif.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %v", err)
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
	if err := sendMailText(c, notif.Title, from, to, notif.ExtID, nil, body); err != nil {
		return err
	}
	cmd := &dashapi.BugUpdate{
		ID:           notif.ID,
		Status:       status,
		Notification: true,
	}
	ok, reason, err := incomingCommand(c, cmd)
	if !ok || err != nil {
		return fmt.Errorf("notif update failed: ok=%v reason=%v err=%v", ok, reason, err)
	}
	return nil
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
	templ, public := "", false
	switch rep.Type {
	case dashapi.ReportNew, dashapi.ReportRepro:
		templ = "mail_bug.txt"
		public = true
	case dashapi.ReportTestPatch:
		templ = "mail_test_result.txt"
	case dashapi.ReportBisectCause, dashapi.ReportBisectFix:
		templ = "mail_bisect_result.txt"
		public = true
	default:
		return fmt.Errorf("unknown report type %v", rep.Type)
	}
	cfg := new(EmailConfig)
	if err := json.Unmarshal(rep.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %v", err)
	}
	to := email.MergeEmailLists([]string{cfg.Email}, rep.CC)
	if cfg.MailMaintainers && public {
		to = email.MergeEmailLists(to, rep.Maintainers, cfg.DefaultMaintainers)
	}
	from, err := email.AddAddrContext(fromAddr(c), rep.ID)
	if err != nil {
		return err
	}

	log.Infof(c, "sending email %q to %q", rep.Title, to)
	return sendMailTemplate(c, rep.Title, from, to, rep.ExtID, nil, templ, rep)
}

// handleIncomingMail is the entry point for incoming emails.
func handleIncomingMail(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if err := incomingMail(c, r); err != nil {
		log.Errorf(c, "handleIncomingMail: %v", err)
	}
}

func incomingMail(c context.Context, r *http.Request) error {
	msg, err := email.Parse(r.Body, ownEmails(c))
	if err != nil {
		// Malformed emails constantly appear from spammers.
		// But we have not seen errors parsing legit emails.
		// These errors are annoying. Warn and ignore them.
		log.Warningf(c, "failed to parse email: %v", err)
		return nil
	}
	// Ignore any incoming emails from syzbot itself.
	if ownEmail(c) == msg.From {
		return nil
	}
	log.Infof(c, "received email: subject %q, from %q, cc %q, msg %q, bug %q, cmd %q, link %q",
		msg.Subject, msg.From, msg.Cc, msg.MessageID, msg.BugID, msg.Command, msg.Link)
	if msg.Command == email.CmdFix && msg.CommandArgs == "exact-commit-title" {
		// Sometimes it happens that somebody sends us our own text back, ignore it.
		msg.Command, msg.CommandArgs = email.CmdNone, ""
	}
	bug, _, reporting := loadBugInfo(c, msg)
	if bug == nil {
		return nil // error was already logged
	}
	emailConfig := reporting.Config.(*EmailConfig)
	// A mailing list can send us a duplicate email, to not process/reply
	// to such duplicate emails, we ignore emails coming from our mailing lists.
	mailingList := email.CanonicalEmail(emailConfig.Email)
	fromMailingList := email.CanonicalEmail(msg.From) == mailingList
	mailingListInCC := checkMailingListInCC(c, msg, mailingList)
	log.Infof(c, "from/cc mailing list: %v/%v", fromMailingList, mailingListInCC)
	if msg.Command == email.CmdTest {
		return handleTestCommand(c, msg)
	}
	if fromMailingList && msg.Command != email.CmdNone {
		log.Infof(c, "duplicate email from mailing list, ignoring")
		return nil
	}
	cmd := &dashapi.BugUpdate{
		Status: emailCmdToStatus[msg.Command],
		ID:     msg.BugID,
		ExtID:  msg.MessageID,
		Link:   msg.Link,
		CC:     msg.Cc,
	}
	switch msg.Command {
	case email.CmdNone, email.CmdUpstream, email.CmdInvalid, email.CmdUnDup:
	case email.CmdFix:
		if msg.CommandArgs == "" {
			return replyTo(c, msg, "no commit title", nil)
		}
		cmd.FixCommits = []string{msg.CommandArgs}
	case email.CmdDup:
		if msg.CommandArgs == "" {
			return replyTo(c, msg, "no dup title", nil)
		}
		cmd.DupOf = msg.CommandArgs
	case email.CmdUnCC:
		cmd.CC = []string{email.CanonicalEmail(msg.From)}
	default:
		if msg.Command != email.CmdUnknown {
			log.Errorf(c, "unknown email command %v %q", msg.Command, msg.CommandStr)
		}
		return replyTo(c, msg, fmt.Sprintf("unknown command %q", msg.CommandStr), nil)
	}
	ok, reply, err := incomingCommand(c, cmd)
	if err != nil {
		return nil // the error was already logged
	}
	if !ok && reply != "" {
		return replyTo(c, msg, reply, nil)
	}
	if !mailingListInCC && msg.Command != email.CmdNone && msg.Command != email.CmdUnCC {
		warnMailingListInCC(c, msg, mailingList)
	}
	return nil
}

var emailCmdToStatus = map[email.Command]dashapi.BugStatus{
	email.CmdNone:     dashapi.BugStatusUpdate,
	email.CmdUpstream: dashapi.BugStatusUpstream,
	email.CmdInvalid:  dashapi.BugStatusInvalid,
	email.CmdUnDup:    dashapi.BugStatusOpen,
	email.CmdFix:      dashapi.BugStatusOpen,
	email.CmdDup:      dashapi.BugStatusDup,
	email.CmdUnCC:     dashapi.BugStatusUnCC,
}

func handleTestCommand(c context.Context, msg *email.Email) error {
	args := strings.Split(msg.CommandArgs, " ")
	if len(args) != 2 {
		return replyTo(c, msg, fmt.Sprintf("want 2 args (repo, branch), got %v", len(args)), nil)
	}
	reply := handleTestRequest(c, msg.BugID, email.CanonicalEmail(msg.From),
		msg.MessageID, msg.Link, msg.Patch, args[0], args[1], msg.Cc)
	if reply != "" {
		return replyTo(c, msg, reply, nil)
	}
	return nil
}

func handleEmailBounce(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	body, err := ioutil.ReadAll(r.Body)
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

// These are just stale emails in MAINTAINERS.
var nonCriticalBounceRe = regexp.MustCompile(`\*\* Address not found \*\*|550 #5\.1\.0 Address rejected`)

func loadBugInfo(c context.Context, msg *email.Email) (bug *Bug, bugReporting *BugReporting, reporting *Reporting) {
	if msg.BugID == "" {
		if msg.Command == email.CmdNone {
			// This happens when people CC syzbot on unrelated emails.
			log.Infof(c, "no bug ID (%q)", msg.Subject)
		} else {
			log.Errorf(c, "no bug ID (%q)", msg.Subject)
			from, err := email.AddAddrContext(ownEmail(c), "HASH")
			if err != nil {
				log.Errorf(c, "failed to format sender email address: %v", err)
				from = "ERROR"
			}
			if err := replyTo(c, msg, fmt.Sprintf(replyNoBugID, from), nil); err != nil {
				log.Errorf(c, "failed to send reply: %v", err)
			}
		}
		return nil, nil, nil
	}
	bug, _, err := findBugByReportingID(c, msg.BugID)
	if err != nil {
		log.Errorf(c, "can't find bug: %v", err)
		from, err := email.AddAddrContext(ownEmail(c), "HASH")
		if err != nil {
			log.Errorf(c, "failed to format sender email address: %v", err)
			from = "ERROR"
		}
		if err := replyTo(c, msg, fmt.Sprintf(replyBadBugID, from), nil); err != nil {
			log.Errorf(c, "failed to send reply: %v", err)
		}
		return nil, nil, nil
	}
	bugReporting, _ = bugReportingByID(bug, msg.BugID)
	if bugReporting == nil {
		log.Errorf(c, "can't find bug reporting: %v", err)
		if err := replyTo(c, msg, "Can't find the corresponding bug.", nil); err != nil {
			log.Errorf(c, "failed to send reply: %v", err)
		}
		return nil, nil, nil
	}
	reporting = config.Namespaces[bug.Namespace].ReportingByName(bugReporting.Name)
	if reporting == nil {
		log.Errorf(c, "can't find reporting for this bug: namespace=%q reporting=%q",
			bug.Namespace, bugReporting.Name)
		return nil, nil, nil
	}
	if reporting.Config.Type() != emailType {
		log.Errorf(c, "reporting is not email: namespace=%q reporting=%q config=%q",
			bug.Namespace, bugReporting.Name, reporting.Config.Type())
		return nil, nil, nil
	}
	return bug, bugReporting, reporting
}

func checkMailingListInCC(c context.Context, msg *email.Email, mailingList string) bool {
	if email.CanonicalEmail(msg.From) == mailingList {
		return true
	}
	for _, cc := range msg.Cc {
		if email.CanonicalEmail(cc) == mailingList {
			return true
		}
	}
	msg.Cc = append(msg.Cc, mailingList)
	return false
}

func warnMailingListInCC(c context.Context, msg *email.Email, mailingList string) {
	reply := fmt.Sprintf("Your '%v' command is accepted, but please keep %v mailing list"+
		" in CC next time. It serves as a history of what happened with each bug report."+
		" Thank you.",
		msg.CommandStr, mailingList)
	if err := replyTo(c, msg, reply, nil); err != nil {
		log.Errorf(c, "failed to send email reply: %v", err)
	}
}

func sendMailTemplate(c context.Context, subject, from string, to []string, replyTo string,
	attachments []aemail.Attachment, template string, data interface{}) error {
	body := new(bytes.Buffer)
	if err := mailTemplates.ExecuteTemplate(body, template, data); err != nil {
		return fmt.Errorf("failed to execute %v template: %v", template, err)
	}
	return sendMailText(c, subject, from, to, replyTo, attachments, body.String())
}

func sendMailText(c context.Context, subject, from string, to []string, replyTo string,
	attachments []aemail.Attachment, body string) error {
	msg := &aemail.Message{
		Sender:      from,
		To:          to,
		Subject:     subject,
		Body:        body,
		Attachments: attachments,
	}
	if replyTo != "" {
		msg.Headers = mail.Header{"In-Reply-To": []string{replyTo}}
		msg.Subject = replySubjectPrefix + msg.Subject
	}
	return sendEmail(c, msg)
}

func replyTo(c context.Context, msg *email.Email, reply string, attachment *aemail.Attachment) error {
	var attachments []aemail.Attachment
	if attachment != nil {
		attachments = append(attachments, *attachment)
	}
	from, err := email.AddAddrContext(fromAddr(c), msg.BugID)
	if err != nil {
		return err
	}
	log.Infof(c, "sending reply: to=%q cc=%q subject=%q reply=%q",
		msg.From, msg.Cc, msg.Subject, reply)
	replyMsg := &aemail.Message{
		Sender:      from,
		To:          []string{msg.From},
		Cc:          msg.Cc,
		Subject:     replySubjectPrefix + msg.Subject,
		Body:        email.FormReply(msg.Body, reply),
		Attachments: attachments,
		Headers:     mail.Header{"In-Reply-To": []string{msg.MessageID}},
	}
	return sendEmail(c, replyMsg)
}

// Sends email, can be stubbed for testing.
var sendEmail = func(c context.Context, msg *aemail.Message) error {
	if err := aemail.Send(c, msg); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
}

func ownEmail(c context.Context) string {
	return fmt.Sprintf("syzbot@%v.appspotmail.com", appengine.AppID(c))
}

func fromAddr(c context.Context) string {
	return fmt.Sprintf("\"syzbot\" <%v>", ownEmail(c))
}

func ownEmails(c context.Context) []string {
	// Now we use syzbot@ but we used to use bot@, so we add them both.
	return []string{
		ownEmail(c),
		fmt.Sprintf("bot@%v.appspotmail.com", appengine.AppID(c)),
	}
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
	return fmt.Sprintf("https://%v.appspot.com", appengine.AppID(c))
}

var mailTemplates = html.CreateTextGlob("mail_*.txt")
