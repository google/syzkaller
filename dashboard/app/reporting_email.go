// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/html"
	"golang.org/x/net/context"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	aemail "google.golang.org/appengine/v2/mail"
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
	if err := sendMailText(c, cfg, notif.Title, from, to, notif.ExtID, body); err != nil {
		return err
	}
	cmd := &dashapi.BugUpdate{
		ID:           notif.ID,
		Status:       status,
		StatusReason: statusReason,
		Notification: true,
	}
	ok, reason, err := incomingCommand(c, cmd)
	if !ok || err != nil {
		return fmt.Errorf("notif update failed: ok=%v reason=%v err=%v", ok, reason, err)
	}
	return nil
}

func buildBadCommitMessage(c context.Context, notif *dashapi.BugNotification) (string, error) {
	var sb strings.Builder
	days := int(notifyAboutBadCommitPeriod / time.Hour / 24)
	nsConfig := config.Namespaces[notif.Namespace]
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

	repos, err := loadRepos(c, AccessPublic, notif.Namespace)
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
	body := new(bytes.Buffer)
	if err := mailTemplates.ExecuteTemplate(body, templ, rep); err != nil {
		return fmt.Errorf("failed to execute %v template: %v", templ, err)
	}
	title := generateEmailBugTitle(rep, cfg)
	log.Infof(c, "sending email %q to %q", title, to)
	return sendMailText(c, cfg, title, from, to, rep.ExtID, body.String())
}

func generateEmailBugTitle(rep *dashapi.BugReport, emailConfig *EmailConfig) string {
	title := ""
	for i := len(rep.Subsystems) - 1; i >= 0; i-- {
		title = fmt.Sprintf("[%s?] %s", rep.Subsystems[i].Name, title)
	}
	return title + rep.Title
}

// handleIncomingMail is the entry point for incoming emails.
func handleIncomingMail(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if err := incomingMail(c, r); err != nil {
		log.Errorf(c, "handleIncomingMail: %v", err)
	}
}

func incomingMail(c context.Context, r *http.Request) error {
	msg, err := email.Parse(r.Body, ownEmails(c), ownMailingLists())
	if err != nil {
		// Malformed emails constantly appear from spammers.
		// But we have not seen errors parsing legit emails.
		// These errors are annoying. Warn and ignore them.
		log.Warningf(c, "failed to parse email: %v", err)
		return nil
	}
	// Ignore any incoming emails from syzbot itself.
	if ownEmail(c) == msg.Author {
		// But we still want to remember the id of our own message, so just neutralize the command.
		msg.Command, msg.CommandArgs = email.CmdNone, ""
	}
	log.Infof(c, "received email: subject %q, author %q, cc %q, msg %q, bug %q, cmd %q, link %q, list %q",
		msg.Subject, msg.Author, msg.Cc, msg.MessageID, msg.BugID, msg.Command, msg.Link, msg.MailingList)
	if msg.Command == email.CmdFix && msg.CommandArgs == "exact-commit-title" {
		// Sometimes it happens that somebody sends us our own text back, ignore it.
		msg.Command, msg.CommandArgs = email.CmdNone, ""
	}
	bugInfo := loadBugInfo(c, msg)
	if bugInfo == nil {
		return nil // error was already logged
	}
	emailConfig := bugInfo.reporting.Config.(*EmailConfig)
	// A mailing list can send us a duplicate email, to not process/reply
	// to such duplicate emails, we ignore emails coming from our mailing lists.
	fromMailingList := msg.MailingList != ""
	mailingList := email.CanonicalEmail(emailConfig.Email)
	mailingListInCC := checkMailingListInCC(c, msg, mailingList)
	log.Infof(c, "from/cc mailing list: %v/%v", fromMailingList, mailingListInCC)
	if fromMailingList && msg.BugID != "" && msg.Command != email.CmdNone {
		// Note that if syzbot was not directly mentioned in To or Cc, this is not really
		// a duplicate message, so it must be processed. We detect it by looking at BugID.

		// There's also a chance that the user mentioned syzbot directly, but without BugID.
		// We don't need to worry about this case, as we won't recognize the bug anyway.
		log.Infof(c, "duplicate email from mailing list, ignoring")
		return nil
	}
	if msg.Command == email.CmdTest {
		return handleTestCommand(c, bugInfo, msg)
	}
	cmd := &dashapi.BugUpdate{
		Status: emailCmdToStatus[msg.Command],
		ID:     bugInfo.bugReporting.ID,
		ExtID:  msg.MessageID,
		Link:   msg.Link,
		CC:     msg.Cc,
	}
	bugID := bugInfo.bugReporting.ID
	switch msg.Command {
	case email.CmdNone, email.CmdUpstream, email.CmdInvalid, email.CmdUnDup:
	case email.CmdFix:
		if msg.CommandArgs == "" {
			return replyTo(c, msg, bugID, "no commit title")
		}
		cmd.FixCommits = []string{msg.CommandArgs}
	case email.CmdUnFix:
		cmd.ResetFixCommits = true
	case email.CmdDup:
		if msg.CommandArgs == "" {
			return replyTo(c, msg, bugID, "no dup title")
		}
		cmd.DupOf = msg.CommandArgs
		cmd.DupOf = strings.TrimSpace(strings.TrimPrefix(cmd.DupOf, replySubjectPrefix))
		cmd.DupOf = strings.TrimSpace(strings.TrimPrefix(cmd.DupOf, emailConfig.SubjectPrefix))
	case email.CmdUnCC:
		cmd.CC = []string{msg.Author}
	default:
		if msg.Command != email.CmdUnknown {
			log.Errorf(c, "unknown email command %v %q", msg.Command, msg.CommandStr)
		}
		return replyTo(c, msg, bugID, fmt.Sprintf("unknown command %q", msg.CommandStr))
	}
	ok, reply, err := incomingCommand(c, cmd)
	if err != nil {
		return nil // the error was already logged
	}
	if !ok && reply != "" {
		return replyTo(c, msg, bugID, reply)
	}
	if !mailingListInCC && msg.Command != email.CmdNone && msg.Command != email.CmdUnCC {
		warnMailingListInCC(c, msg, bugID, mailingList)
	}
	return nil
}

var emailCmdToStatus = map[email.Command]dashapi.BugStatus{
	email.CmdNone:     dashapi.BugStatusUpdate,
	email.CmdUpstream: dashapi.BugStatusUpstream,
	email.CmdInvalid:  dashapi.BugStatusInvalid,
	email.CmdUnDup:    dashapi.BugStatusOpen,
	email.CmdFix:      dashapi.BugStatusOpen,
	email.CmdUnFix:    dashapi.BugStatusUpdate,
	email.CmdDup:      dashapi.BugStatusDup,
	email.CmdUnCC:     dashapi.BugStatusUnCC,
}

func handleTestCommand(c context.Context, info *bugInfoResult, msg *email.Email) error {
	args := strings.Split(msg.CommandArgs, " ")
	if len(args) != 2 {
		return replyTo(c, msg, info.bugReporting.ID,
			fmt.Sprintf("want 2 args (repo, branch), got %v", len(args)))
	}
	if info.bug.sanitizeAccess(AccessPublic) != AccessPublic {
		log.Warningf(c, "%v: bug is not AccessPublic, patch testing request is denied", info.bug.Title)
		return nil
	}
	reply := ""
	err := handleTestRequest(c, &testReqArgs{
		bug: info.bug, bugKey: info.bugKey, bugReporting: info.bugReporting,
		user: msg.Author, extID: msg.MessageID, link: msg.Link,
		patch: []byte(msg.Patch), repo: args[0], branch: args[1], jobCC: msg.Cc})
	if err != nil {
		switch e := err.(type) {
		case *TestRequestDeniedError:
			// Don't send a reply in this case.
			log.Errorf(c, "patch test request denied: %v", e)
		case *BadTestRequestError:
			reply = e.Error()
		default:
			// Don't leak any details to the reply email.
			reply = "Processing failed due to an internal error"
			// .. but they are useful for debugging, so we'd like to see it on the Admin page.
			log.Errorf(c, "handleTestRequest error: %v", e)
		}
	}
	if reply != "" {
		return replyTo(c, msg, info.bugReporting.ID, reply)
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

type bugInfoResult struct {
	bug          *Bug
	bugKey       *db.Key
	bugReporting *BugReporting
	reporting    *Reporting
}

func loadBugInfo(c context.Context, msg *email.Email) *bugInfoResult {
	if msg.BugID == "" {
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
	bug, bugKey, err := findBugByReportingID(c, msg.BugID)
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
	bugReporting, _ := bugReportingByID(bug, msg.BugID)
	if bugReporting == nil {
		log.Errorf(c, "can't find bug reporting: %v", err)
		if err := replyTo(c, msg, "", "Can't find the corresponding bug."); err != nil {
			log.Errorf(c, "failed to send reply: %v", err)
		}
		return nil
	}
	reporting := config.Namespaces[bug.Namespace].ReportingByName(bugReporting.Name)
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

func ownMailingLists() []string {
	ret := []string{}
	for _, ns := range config.Namespaces {
		for _, rep := range ns.Reporting {
			emailConfig, ok := rep.Config.(*EmailConfig)
			if !ok {
				continue
			}
			ret = append(ret, emailConfig.Email)
		}
	}
	return ret
}

var (
	subjectParser     subjectTitleParser
	errAmbiguousTitle = errors.New("ambiguous bug title")
)

func matchBugFromList(c context.Context, sender, subject string) (*bugInfoResult, error) {
	title, seq, err := subjectParser.parseTitle(subject)
	if err != nil {
		return nil, err
	}
	// Query all bugs with this title.
	var bugs []*Bug
	bugKeys, err := db.NewQuery("Bug").
		Filter("Title=", title).
		GetAll(c, &bugs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bugs: %v", err)
	}
	// Filter the bugs by the email.
	candidates := []*bugInfoResult{}
	for i, bug := range bugs {
		log.Infof(c, "processing bug %v", bug.displayTitle())
		// We could add it to the query, but it's probably not worth it - we already have
		// tons of db indexes while the number of matching bugs should not be large anyway.
		if bug.Seq != int64(seq) {
			log.Infof(c, "bug's seq is %v, wanted %d", bug.Seq, seq)
			continue
		}
		if bug.sanitizeAccess(AccessPublic) != AccessPublic {
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
	ready   sync.Once
}

func (p *subjectTitleParser) parseTitle(subject string) (string, int, error) {
	p.prepareRegexps()
	subject = strings.TrimSpace(subject)
	parts := p.pattern.FindStringSubmatch(subject)
	if parts == nil || parts[1] == "" {
		return "", 0, fmt.Errorf("failed to extract the title")
	}
	title := parts[1]
	seq := 0
	if parts[2] != "" {
		rawSeq, err := strconv.Atoi(parts[2])
		if err != nil {
			return "", 0, fmt.Errorf("failed to parse seq: %w", err)
		}
		seq = rawSeq - 1
	}
	return title, seq, nil
}

func (p *subjectTitleParser) prepareRegexps() {
	p.ready.Do(func() {
		stripPrefixes := []string{`R[eE]:`}
		for _, ns := range config.Namespaces {
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
		p.pattern = regexp.MustCompile(rePrefixes + `(?:\[[^\]]+\]\s*)*(.*?)(?:\s\((\d+)\))?$`)
	})
}

func checkMailingListInCC(c context.Context, msg *email.Email, mailingList string) bool {
	if msg.MailingList == mailingList {
		return true
	}
	for _, cc := range msg.Cc {
		if cc == mailingList {
			return true
		}
	}
	msg.Cc = append(msg.Cc, mailingList)
	return false
}

func warnMailingListInCC(c context.Context, msg *email.Email, bugID, mailingList string) {
	reply := fmt.Sprintf("Your '%v' command is accepted, but please keep %v mailing list"+
		" in CC next time. It serves as a history of what happened with each bug report."+
		" Thank you.",
		msg.CommandStr, mailingList)
	if err := replyTo(c, msg, bugID, reply); err != nil {
		log.Errorf(c, "failed to send email reply: %v", err)
	}
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
		Body:    email.FormReply(msg.Body, reply),
		Headers: mail.Header{"In-Reply-To": []string{msg.MessageID}},
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

func replySubject(subject string) string {
	if !strings.HasPrefix(subject, replySubjectPrefix) {
		return replySubjectPrefix + subject
	}
	return subject
}

func ownEmail(c context.Context) string {
	if config.OwnEmailAddress != "" {
		return config.OwnEmailAddress
	}
	return fmt.Sprintf("syzbot@%v.appspotmail.com", appengine.AppID(c))
}

func fromAddr(c context.Context) string {
	return fmt.Sprintf("\"syzbot\" <%v>", ownEmail(c))
}

func ownEmails(c context.Context) []string {
	emails := []string{ownEmail(c)}
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
	if config.AppURL != "" {
		return config.AppURL
	}
	return fmt.Sprintf("https://%v.appspot.com", appengine.AppID(c))
}

var mailTemplates = html.CreateTextGlob("mail_*.txt")
