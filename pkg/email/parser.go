// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type Email struct {
	BugID       string
	MessageID   string
	Link        string
	Subject     string
	MailingList string
	Author      string
	Cc          []string
	Body        string  // text/plain part
	Patch       string  // attached patch, if any
	Command     Command // command to bot
	CommandStr  string  // string representation of the command
	CommandArgs string  // arguments for the command
}

type Command int

const (
	CmdUnknown Command = iota
	CmdNone
	CmdUpstream
	CmdFix
	CmdUnFix
	CmdDup
	CmdUnDup
	CmdTest
	CmdInvalid
	CmdUnCC
	CmdSet

	cmdTest5
)

var groupsLinkRe = regexp.MustCompile("\nTo view this discussion on the web visit" +
	" (https://groups\\.google\\.com/.*?)\\.(?:\r)?\n")

func prepareEmails(list []string) map[string]bool {
	ret := make(map[string]bool)
	for _, email := range list {
		ret[email] = true
		if addr, err := mail.ParseAddress(email); err == nil {
			ret[addr.Address] = true
		}
	}
	return ret
}

func Parse(r io.Reader, ownEmails, goodLists []string) (*Email, error) {
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
	// Ignore errors since To: header may not be present (we've seen such case).
	to, _ := msg.Header.AddressList("To")
	// AddressList fails if the header is not present.
	cc, _ := msg.Header.AddressList("Cc")
	bugID := ""
	var ccList []string
	ownAddrs := prepareEmails(ownEmails)
	fromMe := false
	for _, addr := range from {
		cleaned, _, _ := RemoveAddrContext(addr.Address)
		if addr, err := mail.ParseAddress(cleaned); err == nil && ownAddrs[addr.Address] {
			fromMe = true
		}
	}

	originalFrom := ""
	// Ignore error since the header might not be present.
	originalFroms, _ := msg.Header.AddressList("X-Original-From")
	if len(originalFroms) > 0 {
		originalFrom = originalFroms[0].String()
	}

	rawCcList := append(append(append(cc, to...), from...), originalFroms...)
	for _, addr := range rawCcList {
		cleaned, context, _ := RemoveAddrContext(addr.Address)
		if addr, err := mail.ParseAddress(cleaned); err == nil {
			cleaned = addr.Address
		}
		if ownAddrs[cleaned] {
			if bugID == "" {
				bugID = context
			}
		} else {
			ccList = append(ccList, CanonicalEmail(cleaned))
		}
	}
	ccList = MergeEmailLists(ccList)

	sender := ""
	// Ignore error since the header might not be present.
	senders, _ := msg.Header.AddressList("Sender")
	if len(senders) > 0 {
		sender = senders[0].Address
	}

	body, attachments, err := parseBody(msg.Body, msg.Header)
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)
	subject := msg.Header.Get("Subject")
	cmd := CmdNone
	patch, cmdStr, cmdArgs := "", "", ""
	if !fromMe {
		for _, a := range attachments {
			patch = ParsePatch(a)
			if patch != "" {
				break
			}
		}
		if patch == "" {
			patch = ParsePatch(body)
		}
		cmd, cmdStr, cmdArgs = extractCommand(subject + "\n" + bodyStr)
	}
	link := ""
	if match := groupsLinkRe.FindStringSubmatchIndex(bodyStr); match != nil {
		link = bodyStr[match[2]:match[3]]
	}

	author := CanonicalEmail(from[0].Address)
	mailingList := ""

	goodListsMap := prepareEmails(goodLists)
	if goodListsMap[author] {
		// In some cases, the mailing list would change From and introduce X-Original-From.
		mailingList = author
		if originalFrom != "" {
			author = CanonicalEmail(originalFrom)
		}
		// Not sure if `else` can happen here, but let it be mailingList == author in this case.
	} else if goodListsMap[CanonicalEmail(sender)] {
		// In other cases, the mailing list would preserve From and just change Sender.
		mailingList = CanonicalEmail(sender)
	}

	email := &Email{
		BugID:       bugID,
		MessageID:   msg.Header.Get("Message-ID"),
		Link:        link,
		Author:      author,
		MailingList: mailingList,
		Subject:     subject,
		Cc:          ccList,
		Body:        bodyStr,
		Patch:       patch,
		Command:     cmd,
		CommandStr:  cmdStr,
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
	result := addr.Address[:at] + "+" + context + addr.Address[at:]
	if addr.Name != "" {
		addr.Address = result
		result = addr.String()
	}
	return result, nil
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

func CanonicalEmail(email string) string {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return email
	}
	at := strings.IndexByte(addr.Address, '@')
	if at == -1 {
		return email
	}
	if plus := strings.IndexByte(addr.Address[:at], '+'); plus != -1 {
		addr.Address = addr.Address[:plus] + addr.Address[at:]
	}
	return strings.ToLower(addr.Address)
}

const commandPrefix = "#syz"

// extractCommand extracts command to syzbot from email body.
// Commands are of the following form:
// ^#syz cmd args...
func extractCommand(body string) (cmd Command, str, args string) {
	nbody := "\n" + body
	cmdPos := -1
	for _, delim := range []string{" ", "\t", "-", ":"} {
		cmdPos = strings.Index(nbody, "\n"+commandPrefix+delim)
		if cmdPos != -1 {
			break
		}
	}
	if cmdPos == -1 {
		cmd = CmdNone
		return
	}
	cmdPos += len(commandPrefix) + 1
	for cmdPos < len(body) && unicode.IsSpace(rune(body[cmdPos])) {
		cmdPos++
	}
	cmdEnd := strings.IndexByte(body[cmdPos:], '\n')
	if cmdEnd == -1 {
		cmdEnd = len(body) - cmdPos
	}
	if cmdEnd1 := strings.IndexByte(body[cmdPos:], '\r'); cmdEnd1 != -1 && cmdEnd1 < cmdEnd {
		cmdEnd = cmdEnd1
	}
	if cmdEnd1 := strings.IndexByte(body[cmdPos:], ' '); cmdEnd1 != -1 && cmdEnd1 < cmdEnd {
		cmdEnd = cmdEnd1
	}
	if cmdEnd1 := strings.IndexByte(body[cmdPos:], '\t'); cmdEnd1 != -1 && cmdEnd1 < cmdEnd {
		cmdEnd = cmdEnd1
	}
	str = body[cmdPos : cmdPos+cmdEnd]
	cmd = strToCmd(str)
	// Some email clients split text emails at 80 columns are the transformation is irrevesible.
	// We try hard to restore what was there before.
	// For "test:" command we know that there must be 2 tokens without spaces.
	// For "fix:"/"dup:" we need a whole non-empty line of text.
	switch cmd {
	case CmdTest:
		args = extractArgsTokens(body[cmdPos+cmdEnd:], 2)
	case CmdSet:
		args = extractArgsLine(body[cmdPos+cmdEnd:])
	case cmdTest5:
		args = extractArgsTokens(body[cmdPos+cmdEnd:], 5)
	case CmdFix, CmdDup:
		args = extractArgsLine(body[cmdPos+cmdEnd:])
	}
	return
}

func strToCmd(str string) Command {
	switch str {
	default:
		return CmdUnknown
	case "":
		return CmdNone
	case "upstream":
		return CmdUpstream
	case "fix", "fix:":
		return CmdFix
	case "unfix":
		return CmdUnFix
	case "dup", "dup:":
		return CmdDup
	case "undup":
		return CmdUnDup
	case "test", "test:":
		return CmdTest
	case "invalid":
		return CmdInvalid
	case "uncc", "uncc:":
		return CmdUnCC
	case "set", "set:":
		return CmdSet
	case "test_5_arg_cmd":
		return cmdTest5
	}
}

func extractArgsTokens(body string, num int) string {
	var args []string
	for pos := 0; len(args) < num && pos < len(body); {
		lineEnd := strings.IndexByte(body[pos:], '\n')
		if lineEnd == -1 {
			lineEnd = len(body) - pos
		}
		line := strings.TrimSpace(strings.Replace(body[pos:pos+lineEnd], "\t", " ", -1))
		for {
			line1 := strings.Replace(line, "  ", " ", -1)
			if line == line1 {
				break
			}
			line = line1
		}
		if line != "" {
			args = append(args, strings.Split(line, " ")...)
		}
		pos += lineEnd + 1
	}
	return strings.TrimSpace(strings.Join(args, " "))
}

func extractArgsLine(body string) string {
	pos := 0
	for pos < len(body) && (body[pos] == ' ' || body[pos] == '\t' ||
		body[pos] == '\n' || body[pos] == '\r') {
		pos++
	}
	lineEnd := strings.IndexByte(body[pos:], '\n')
	if lineEnd == -1 {
		lineEnd = len(body) - pos
	}
	return strings.TrimSpace(body[pos : pos+lineEnd])
}

func parseBody(r io.Reader, headers mail.Header) ([]byte, [][]byte, error) {
	// git-send-email sends emails without Content-Type, let's assume it's text.
	mediaType := "text/plain"
	var params map[string]string
	if contentType := headers.Get("Content-Type"); contentType != "" {
		var err error
		mediaType, params, err = mime.ParseMediaType(headers.Get("Content-Type"))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse email header 'Content-Type': %v", err)
		}
	}
	switch strings.ToLower(headers.Get("Content-Transfer-Encoding")) {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	}
	disp, _, _ := mime.ParseMediaType(headers.Get("Content-Disposition"))
	if disp == "attachment" {
		attachment, err := io.ReadAll(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read email body: %v", err)
		}
		return nil, [][]byte{attachment}, nil
	}
	if mediaType == "text/plain" {
		body, err := io.ReadAll(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read email body: %v", err)
		}
		return body, nil, nil
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return nil, nil, nil
	}
	var body []byte
	var attachments [][]byte
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

// MergeEmailLists merges several email lists removing duplicates and invalid entries.
func MergeEmailLists(lists ...[]string) []string {
	const (
		maxEmailLen = 1000
		maxEmails   = 50
	)
	merged := make(map[string]bool)
	for _, list := range lists {
		for _, email := range list {
			addr, err := mail.ParseAddress(email)
			if err != nil || len(addr.Address) > maxEmailLen {
				continue
			}
			merged[addr.Address] = true
		}
	}
	var result []string
	for e := range merged {
		result = append(result, e)
	}
	sort.Strings(result)
	if len(result) > maxEmails {
		result = result[:maxEmails]
	}
	return result
}

func RemoveFromEmailList(list []string, toRemove string) []string {
	var result []string
	toRemove = CanonicalEmail(toRemove)
	for _, email := range list {
		if CanonicalEmail(email) != toRemove {
			result = append(result, email)
		}
	}
	return result
}
