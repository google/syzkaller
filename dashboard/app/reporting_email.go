// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"strings"
	"text/template"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	aemail "google.golang.org/appengine/mail"
)

// Email reporting interface.

func init() {
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

const emailType = "email"

var mailingLists map[string]bool

type EmailConfig struct {
	Email              string
	Moderation         bool
	MailMaintainers    bool
	DefaultMaintainers []string
}

func (cfg *EmailConfig) Type() string {
	return emailType
}

func (cfg *EmailConfig) NeedMaintainers() bool {
	return cfg.MailMaintainers && len(cfg.DefaultMaintainers) == 0
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
	if cfg.Moderation && cfg.MailMaintainers {
		return fmt.Errorf("both Moderation and MailMaintainers set")
	}
	return nil
}

// handleEmailPoll is called by cron and sends emails for new bugs, if any.
func handleEmailPoll(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if err := emailPollBugs(c); err != nil {
		log.Errorf(c, "bug poll failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := emailPollJobs(c); err != nil {
		log.Errorf(c, "job poll failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("OK"))
}

func emailPollBugs(c context.Context) error {
	reports := reportingPollBugs(c, emailType)
	for _, rep := range reports {
		if err := emailReport(c, rep, "mail_bug.txt"); err != nil {
			log.Errorf(c, "failed to report bug: %v", err)
			continue
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
			log.Errorf(c, "failed to update reported bug: ok=%v reason=%v err=%v", ok, reason, err)
		}
	}
	return nil
}

func emailPollJobs(c context.Context) error {
	jobs, err := pollCompletedJobs(c, emailType)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if err := emailReport(c, job, "mail_test_result.txt"); err != nil {
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

func emailReport(c context.Context, rep *dashapi.BugReport, templ string) error {
	cfg := new(EmailConfig)
	if err := json.Unmarshal(rep.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %v", err)
	}
	to := []string{cfg.Email}
	if cfg.MailMaintainers {
		to = email.MergeEmailLists(to, rep.Maintainers, cfg.DefaultMaintainers)
	}
	to = email.MergeEmailLists(to, rep.CC)
	var attachments []aemail.Attachment
	if len(rep.KernelConfig) != 0 {
		attachments = append(attachments, aemail.Attachment{
			Name: "config.txt",
			Data: rep.KernelConfig,
		})
	}
	if len(rep.Patch) != 0 {
		attachments = append(attachments, aemail.Attachment{
			Name: "patch.diff",
			Data: rep.Patch,
		})
	}
	if len(rep.Log) != 0 {
		attachments = append(attachments, aemail.Attachment{
			Name: "raw.log.txt",
			Data: rep.Log,
		})
	}
	if len(rep.ReproSyz) != 0 {
		attachments = append(attachments, aemail.Attachment{
			Name: "repro.syz.txt",
			Data: rep.ReproSyz,
		})
	}
	if len(rep.ReproC) != 0 {
		attachments = append(attachments, aemail.Attachment{
			Name: "repro.c.txt",
			Data: rep.ReproC,
		})
	}
	// Build error output and failing VM boot log can be way too long to inline.
	const maxInlineError = 16 << 10
	errorText, errorTruncated := rep.Error, false
	if len(errorText) > maxInlineError {
		errorTruncated = true
		attachments = append(attachments, aemail.Attachment{
			Name: "error.txt",
			Data: errorText,
		})
		errorText = errorText[len(errorText)-maxInlineError:]
	}
	from, err := email.AddAddrContext(fromAddr(c), rep.ID)
	if err != nil {
		return err
	}
	creditEmail, err := email.AddAddrContext(ownEmail(c), rep.ID)
	if err != nil {
		return err
	}
	userspaceArch := ""
	if rep.Arch == "386" {
		userspaceArch = "i386"
	}
	// Data passed to the template.
	type BugReportData struct {
		First             bool
		CreditEmail       string
		Moderation        bool
		Maintainers       []string
		CompilerID        string
		KernelRepo        string
		KernelCommit      string
		KernelCommitTitle string
		KernelCommitDate  string
		UserSpaceArch     string
		CrashTitle        string
		Report            []byte
		Error             []byte
		ErrorTruncated    bool
		HasLog            bool
		HasKernelConfig   bool
		ReproSyz          bool
		ReproC            bool
		NumCrashes        int64
		HappenedOn        []string
	}
	data := &BugReportData{
		First:             rep.First,
		CreditEmail:       creditEmail,
		Moderation:        cfg.Moderation,
		Maintainers:       rep.Maintainers,
		CompilerID:        rep.CompilerID,
		KernelRepo:        rep.KernelRepoAlias,
		KernelCommit:      rep.KernelCommit,
		KernelCommitTitle: rep.KernelCommitTitle,
		KernelCommitDate:  formatKernelTime(rep.KernelCommitDate),
		UserSpaceArch:     userspaceArch,
		CrashTitle:        rep.CrashTitle,
		Report:            rep.Report,
		Error:             errorText,
		ErrorTruncated:    errorTruncated,
		HasLog:            len(rep.Log) != 0,
		HasKernelConfig:   len(rep.KernelConfig) != 0,
		ReproSyz:          len(rep.ReproSyz) != 0,
		ReproC:            len(rep.ReproC) != 0,
		NumCrashes:        rep.NumCrashes,
		HappenedOn:        rep.HappenedOn,
	}
	log.Infof(c, "sending email %q to %q", rep.Title, to)
	err = sendMailTemplate(c, rep.Title, from, to, rep.ExtID, attachments, templ, data)
	if err != nil {
		return err
	}
	return nil
}

// handleIncomingMail is the entry point for incoming emails.
func handleIncomingMail(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if err := incomingMail(c, r); err != nil {
		log.Errorf(c, "%v", err)
	}
}

func incomingMail(c context.Context, r *http.Request) error {
	msg, err := email.Parse(r.Body, ownEmails(c))
	if err != nil {
		return err
	}
	log.Infof(c, "received email: subject %q, from %q, cc %q, msg %q, bug %q, cmd %q, link %q",
		msg.Subject, msg.From, msg.Cc, msg.MessageID, msg.BugID, msg.Command, msg.Link)
	if msg.Command == "fix:" && msg.CommandArgs == "exact-commit-title" {
		// Sometimes it happens that somebody sends us our own text back, ignore it.
		msg.Command, msg.CommandArgs = "", ""
	}
	bug, _, reporting := loadBugInfo(c, msg)
	if bug == nil {
		return nil // error was already logged
	}
	emailConfig := reporting.Config.(*EmailConfig)
	mailingList := email.CanonicalEmail(emailConfig.Email)
	fromMailingList := email.CanonicalEmail(msg.From) == mailingList
	mailingListInCC := checkMailingListInCC(c, msg, mailingList)
	log.Infof(c, "from/cc mailing list: %v/%v", fromMailingList, mailingListInCC)
	// A mailing list can send us a duplicate email, to not process/reply
	// to such duplicate emails, we ignore emails coming from our mailing lists.
	if msg.Command == "test:" {
		if fromMailingList {
			if msg.Link != "" {
				if err := updateTestJob(c, msg.MessageID, msg.Link); err != nil {
					log.Errorf(c, "failed to update job: %v", err)
				}
			}
			return nil
		}
		args := strings.Split(msg.CommandArgs, " ")
		if len(args) != 2 {
			return replyTo(c, msg, fmt.Sprintf("want 2 args (repo, branch), got %v",
				len(args)), nil)
		}
		reply := handleTestRequest(c, msg.BugID, email.CanonicalEmail(msg.From),
			msg.MessageID, msg.Patch, args[0], args[1])
		if reply != "" {
			return replyTo(c, msg, reply, nil)
		}
		if !mailingListInCC {
			warnMailingListInCC(c, msg, mailingList)
		}
		return nil
	}
	if fromMailingList && msg.Command != "" {
		log.Infof(c, "duplicate email from mailing list, ignoring")
		return nil
	}
	cmd := &dashapi.BugUpdate{
		ID:    msg.BugID,
		ExtID: msg.MessageID,
		Link:  msg.Link,
		CC:    msg.Cc,
	}
	switch msg.Command {
	case "":
		cmd.Status = dashapi.BugStatusUpdate
	case "upstream":
		cmd.Status = dashapi.BugStatusUpstream
	case "invalid":
		cmd.Status = dashapi.BugStatusInvalid
	case "fix:":
		if msg.CommandArgs == "" {
			return replyTo(c, msg, fmt.Sprintf("no commit title"), nil)
		}
		cmd.Status = dashapi.BugStatusOpen
		cmd.FixCommits = []string{msg.CommandArgs}
	case "dup:":
		if msg.CommandArgs == "" {
			return replyTo(c, msg, fmt.Sprintf("no dup title"), nil)
		}
		cmd.Status = dashapi.BugStatusDup
		cmd.DupOf = msg.CommandArgs
	default:
		return replyTo(c, msg, fmt.Sprintf("unknown command %q", msg.Command), nil)
	}
	ok, reply, err := incomingCommand(c, cmd)
	if err != nil {
		return nil // the error was already logged
	}
	if !ok && reply != "" {
		return replyTo(c, msg, reply, nil)
	}
	if !mailingListInCC && msg.Command != "" {
		warnMailingListInCC(c, msg, mailingList)
	}
	return nil
}

func handleEmailBounce(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	log.Errorf(c, "email bounced")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf(c, "failed to read body: %v", err)
		return
	}
	log.Infof(c, "%s", body)
}

func loadBugInfo(c context.Context, msg *email.Email) (bug *Bug, bugReporting *BugReporting, reporting *Reporting) {
	if msg.BugID == "" {
		if msg.Command == "" {
			// This happens when people CC syzbot on unrelated emails.
			log.Infof(c, "no bug ID (%q)", msg.Subject)
		} else {
			log.Warningf(c, "no bug ID (%q)", msg.Subject)
			replyTo(c, msg, "Can't find the corresponding bug.", nil)
		}
		return nil, nil, nil
	}
	bug, _, err := findBugByReportingID(c, msg.BugID)
	if err != nil {
		log.Errorf(c, "can't find bug: %v", err)
		replyTo(c, msg, "Can't find the corresponding bug.", nil)
		return nil, nil, nil
	}
	bugReporting, _ = bugReportingByID(bug, msg.BugID)
	if bugReporting == nil {
		log.Errorf(c, "can't find bug reporting: %v", err)
		replyTo(c, msg, "Can't find the corresponding bug.", nil)
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
		msg.Command, mailingList)
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
	msg := &aemail.Message{
		Sender:      from,
		To:          to,
		Subject:     subject,
		Body:        body.String(),
		Attachments: attachments,
	}
	if replyTo != "" {
		msg.Headers = mail.Header{"In-Reply-To": []string{replyTo}}
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
		Subject:     msg.Subject,
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

func formatKernelTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	// This is how dates appear in git log.
	return t.Format("Mon Jan 2 15:04:05 2006 -0700")
}

func formatStringList(list []string) string {
	return strings.Join(list, ", ")
}

var (
	mailTemplates = template.Must(template.New("").Funcs(mailFuncs).ParseGlob("mail_*.txt"))

	mailFuncs = template.FuncMap{
		"formatTime": formatKernelTime,
		"formatList": formatStringList,
	}
)
