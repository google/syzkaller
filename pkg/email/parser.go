// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

type Email struct {
	BugID       string
	MessageID   string
	Subject     string
	From        string
	Cc          []string
	Body        string   // text/plain part
	Patch       string   // attached patch, if any
	Command     string   // command to bot (#syzbot is stripped)
	CommandArgs []string // arguments for the command
}

const commandPrefix = "#syzbot "

func Parse(r io.Reader, ownEmail string) (*Email, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read email: %v", err)
	}
	from, err := msg.Header.AddressList("From")
	if err != nil {
		return nil, fmt.Errorf("failed to parse email header 'From': %v", err)
	}
	if len(from) == 0 {
		return nil, fmt.Errorf("failed to parse email header 'To': no senders")
	}
	to, err := msg.Header.AddressList("To")
	if err != nil {
		return nil, fmt.Errorf("failed to parse email header 'To': %v", err)
	}
	// AddressList fails if the header is not present.
	cc, _ := msg.Header.AddressList("Cc")
	bugID := ""
	var ccList []string
	if addr, err := mail.ParseAddress(ownEmail); err == nil {
		ownEmail = addr.Address
	}
	for _, addr := range append(cc, to...) {
		cleaned, context, _ := RemoveAddrContext(addr.Address)
		if addr, err := mail.ParseAddress(cleaned); err == nil {
			cleaned = addr.Address
		}
		if cleaned == ownEmail {
			if bugID == "" {
				bugID = context
			}
		} else {
			ccList = append(ccList, addr.String())
		}
	}
	body, attachments, err := parseBody(msg.Body, msg.Header)
	if err != nil {
		return nil, err
	}
	patch := ""
	for _, a := range attachments {
		_, patch, _ = ParsePatch(string(a))
		if patch != "" {
			break
		}
	}
	if patch == "" {
		_, patch, _ = ParsePatch(string(body))
	}
	cmd, cmdArgs := extractCommand(body)
	email := &Email{
		BugID:       bugID,
		MessageID:   msg.Header.Get("Message-ID"),
		Subject:     msg.Header.Get("Subject"),
		From:        from[0].String(),
		Cc:          ccList,
		Body:        string(body),
		Patch:       patch,
		Command:     cmd,
		CommandArgs: cmdArgs,
	}
	return email, nil
}

// AddAddrContext embeds context into local part of the provided email address using '+'.
// Returns the resulting email address.
func AddAddrContext(email, context string) (string, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", fmt.Errorf("failed to parse %q as email: %v", email, err)
	}
	at := strings.IndexByte(addr.Address, '@')
	if at == -1 {
		return "", fmt.Errorf("failed to parse %q as email: no @", email)
	}
	addr.Address = addr.Address[:at] + "+" + context + addr.Address[at:]
	return addr.String(), nil
}

// RemoveAddrContext extracts context after '+' from the local part of the provided email address.
// Returns address without the context and the context.
func RemoveAddrContext(email string) (string, string, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse %q as email: %v", email, err)
	}
	at := strings.IndexByte(addr.Address, '@')
	if at == -1 {
		return "", "", fmt.Errorf("failed to parse %q as email: no @", email)
	}
	plus := strings.LastIndexByte(addr.Address[:at], '+')
	if plus == -1 {
		return email, "", nil
	}
	context := addr.Address[plus+1 : at]
	addr.Address = addr.Address[:plus] + addr.Address[at:]
	return addr.String(), context, nil
}

// extractCommand extracts command to syzbot from email body.
// Commands are of the following form:
// ^#syzbot cmd args...
func extractCommand(body []byte) (cmd string, args []string) {
	cmdPos := bytes.Index(append([]byte{'\n'}, body...), []byte("\n"+commandPrefix))
	if cmdPos == -1 {
		return
	}
	cmdPos += 8
	cmdEnd := bytes.IndexByte(body[cmdPos:], '\n')
	if cmdEnd == -1 {
		cmdEnd = len(body) - cmdPos
	}
	cmdLine := strings.TrimSpace(string(body[cmdPos : cmdPos+cmdEnd]))
	if cmdLine == "" {
		return
	}
	split := strings.Split(cmdLine, " ")
	cmd = split[0]
	for _, arg := range split[1:] {
		if trimmed := strings.TrimSpace(arg); trimmed != "" {
			args = append(args, trimmed)
		}
	}
	return
}

func parseBody(r io.Reader, headers mail.Header) (body []byte, attachments [][]byte, err error) {
	mediaType, params, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse email header 'Content-Type': %v", err)
	}
	disp, _, _ := mime.ParseMediaType(headers.Get("Content-Disposition"))
	if disp == "attachment" {
		// Note: mime package handles quoted-printable internally.
		if strings.ToLower(headers.Get("Content-Transfer-Encoding")) == "base64" {
			r = base64.NewDecoder(base64.StdEncoding, r)
		}
		attachment, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read email body: %v", err)
		}
		return nil, [][]byte{attachment}, nil
	}
	if mediaType == "text/plain" {
		body, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read email body: %v", err)
		}
		return body, nil, nil
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return nil, nil, nil
	}
	mr := multipart.NewReader(r, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return body, attachments, nil
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse MIME parts: %v", err)
		}
		body1, attachments1, err1 := parseBody(p, mail.Header(p.Header))
		if err1 != nil {
			return nil, nil, err1
		}
		if body == nil {
			body = body1
		}
		attachments = append(attachments, attachments1...)
	}
}
