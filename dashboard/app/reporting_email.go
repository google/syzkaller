// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"text/template"

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
}

const emailType = "email"

type EmailConfig struct {
	Email           string
	MailMaintainers bool
}

func (cfg *EmailConfig) Type() string {
	return emailType
}

func (cfg *EmailConfig) Validate() error {
	if _, err := mail.ParseAddress(cfg.Email); err != nil {
		return fmt.Errorf("bad email address %q: %v", cfg.Email, err)
	}
	if cfg.MailMaintainers {
		return fmt.Errorf("mailing maintainers is not supported yet")
	}
	return nil
}

// handleEmailPoll is called by cron and sends emails for new bugs, if any.
func handleEmailPoll(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if err := emailPoll(c); err != nil {
		log.Errorf(c, "%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("OK"))
}

func emailPoll(c context.Context) error {
	reports := reportingPoll(c, emailType)
	for _, rep := range reports {
		if err := emailReport(c, rep); err != nil {
			log.Errorf(c, "failed to report: %v", err)
		}
	}
	return nil
}

func emailReport(c context.Context, rep *dashapi.BugReport) error {
	cfg := new(EmailConfig)
	if err := json.Unmarshal(rep.Config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal email config: %v", err)
	}
	to := []string{cfg.Email}
	if cfg.MailMaintainers {
		panic("are you nuts?")
		to = append(to, rep.Maintainers...)
	}
	attachments := []aemail.Attachment{
		{
			Name: "config.txt",
			Data: rep.KernelConfig,
		},
	}
	repro := dashapi.ReproLevelNone
	if len(rep.ReproC) != 0 {
		repro = dashapi.ReproLevelC
		attachments = append(attachments, aemail.Attachment{
			Name: "repro.c",
			Data: rep.ReproC,
		})
	}
	if len(rep.ReproSyz) != 0 {
		repro = dashapi.ReproLevelSyz
		attachments = append(attachments, aemail.Attachment{
			Name: "repro.txt",
			Data: rep.ReproSyz,
		})
	}
	from, err := email.AddAddrContext(fromAddr(c), rep.ID)
	if err != nil {
		return err
	}
	if err := sendMailTemplate(c, rep.Title, from, to, attachments, "mail_bug.txt", rep); err != nil {
		return err
	}
	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		ReproLevel: repro,
	}
	incomingCommand(c, cmd)
	return nil
}

// handleIncomingMail is the entry point for incoming emails.
// TODO: this part is unfinished.
func handleIncomingMail(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if err := incomingMail(c, r); err != nil {
		log.Errorf(c, "%v", err)
	}
}

func incomingMail(c context.Context, r *http.Request) error {
	msg, err := email.Parse(r.Body, fromAddr(c))
	if err != nil {
		return err
	}
	log.Infof(c, "received email: subject '%v', from '%v', cc '%v', msg '%v', bug '%v', cmd '%v'",
		msg.Subject, msg.From, msg.Cc, msg.MessageID, msg.BugID, msg.Command)
	var status dashapi.BugStatus
	switch msg.Command {
	case "":
		return nil
	case "upstream":
		status = dashapi.BugStatusUpstream
	case "invalid":
		status = dashapi.BugStatusInvalid
	default:
		return replyTo(c, msg, fmt.Sprintf("unknown command %q", msg.Command), nil)
	}
	cmd := &dashapi.BugUpdate{
		ID:     msg.BugID,
		Status: status,
	}
	reply, _ := incomingCommand(c, cmd)
	return replyTo(c, msg, reply, nil)
}

var mailTemplates = template.Must(template.New("").ParseGlob("mail_*.txt"))

func sendMailTemplate(c context.Context, subject, from string, to []string,
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
	if err := aemail.Send(c, msg); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
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
	replyMsg := &aemail.Message{
		Sender:      from,
		To:          []string{msg.From},
		Cc:          msg.Cc,
		Subject:     msg.Subject,
		Body:        email.FormReply(msg.Body, reply),
		Attachments: attachments,
		Headers:     mail.Header{"In-Reply-To": []string{msg.MessageID}},
	}
	if err := aemail.Send(c, replyMsg); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
}

func fromAddr(c context.Context) string {
	return fmt.Sprintf("syzbot <bot@%v.appspotmail.com>", appengine.AppID(c))
}
