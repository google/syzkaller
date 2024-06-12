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
	"time"
	"unicode"
)

type Email struct {
	BugIDs      []string
	MessageID   string
	InReplyTo   string
	Date        time.Time
	Link        string
	Subject     string
	MailingList string
	Author      string
	OwnEmail    bool
	Cc          []string
	Body        string // text/plain part
	Patch       string // attached patch, if any
	Commands    []*SingleCommand
}

type SingleCommand struct {
	Command Command
	Str     string // string representation
	Args    string // arguments for the command
}

type Command int

const (
	CmdUnknown Command = iota
	CmdUpstream
	CmdFix
	CmdUnFix
	CmdDup
	CmdUnDup
	CmdTest
	CmdInvalid
	CmdUnCC
	CmdSet
	CmdUnset
	CmdRegenerate

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

func Parse(r io.Reader, ownEmails, goodLists, domains []string) (*Email, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read email: %w", err)
	}
	from, err := msg.Header.AddressList("From")
	if err != nil {
		return nil, fmt.Errorf("failed to parse email header 'From': %w", err)
	}
	if len(from) == 0 {
		return nil, fmt.Errorf("failed to parse email header 'To': no senders")
	}
	// Ignore errors since To: header may not be present (we've seen such case).
	to, _ := msg.Header.AddressList("To")
	// AddressList fails if the header is not present.
	cc, _ := msg.Header.AddressList("Cc")
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

	bugIDs := []string{}
	rawCcList := append(append(append(cc, to...), from...), originalFroms...)
	for _, addr := range rawCcList {
		cleaned, context, _ := RemoveAddrContext(addr.Address)
		if addr, err := mail.ParseAddress(cleaned); err == nil {
			cleaned = addr.Address
		}
		if ownAddrs[cleaned] {
			bugIDs = append(bugIDs, context)
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
	var cmds []*SingleCommand
	var patch string
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
		cmds = extractCommands(subject + "\n" + bodyStr)
	}
	bugIDs = append(bugIDs, extractBodyBugIDs(bodyStr, ownAddrs, domains)...)

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
	date, _ := mail.ParseDate(msg.Header.Get("Date"))
	email := &Email{
		BugIDs:      dedupBugIDs(bugIDs),
		MessageID:   msg.Header.Get("Message-ID"),
		InReplyTo:   extractInReplyTo(msg.Header),
		Date:        date,
		Link:        link,
		Author:      author,
		OwnEmail:    fromMe,
		MailingList: mailingList,
		Subject:     subject,
		Cc:          ccList,
		Body:        bodyStr,
		Patch:       patch,
		Commands:    cmds,
	}
	return email, nil
}

// AddAddrContext embeds context into local part of the provided email address using '+'.
// Returns the resulting email address.
func AddAddrContext(email, context string) (string, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", fmt.Errorf("failed to parse %q as email: %w", email, err)
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
		return "", "", fmt.Errorf("failed to parse %q as email: %w", email, err)
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

func extractCommands(body string) []*SingleCommand {
	var ret []*SingleCommand
	for body != "" {
		cmd, end := extractCommand(body)
		if cmd == nil {
			break
		}
		ret = append(ret, cmd)
		body = body[end:]
	}
	return ret
}

const commandPrefix = "#syz"

var commandStartRe = regexp.MustCompile(`(?:^|\n)(` + regexp.QuoteMeta(commandPrefix) + `[ \t-:])`)

// extractCommand extracts command to syzbot from email body.
// Commands are of the following form:
// ^#syz cmd args...
func extractCommand(body string) (*SingleCommand, int) {
	var cmd Command
	var str, args string

	match := commandStartRe.FindStringSubmatchIndex(body)
	if match == nil {
		return nil, 0
	}
	cmdPos := match[2] + len(commandPrefix) + 1
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
		if strings.HasSuffix(str, ":") {
			// For "#syz test:", we do want to query 2 arguments.
			args = extractArgsTokens(body[cmdPos+cmdEnd:], 2)
		} else {
			// For "#syz test", it's likely there won't be anything else, so let's only parse
			// the first line.
			args = extractArgsLine(body[cmdPos+cmdEnd:], false)
		}
	case CmdSet, CmdUnset:
		args = extractArgsLine(body[cmdPos+cmdEnd:], true)
	case cmdTest5:
		args = extractArgsTokens(body[cmdPos+cmdEnd:], 5)
	case CmdFix, CmdDup:
		args = extractArgsLine(body[cmdPos+cmdEnd:], true)
	}
	return &SingleCommand{
		Command: cmd,
		Str:     str,
		Args:    args,
	}, cmdPos + cmdEnd
}

func strToCmd(str string) Command {
	switch str {
	default:
		return CmdUnknown
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
	case "unset", "unset:":
		return CmdUnset
	case "regenerate":
		return CmdRegenerate
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

func extractArgsLine(body string, skipWs bool) string {
	pos := 0
	if skipWs {
		for pos < len(body) && unicode.IsSpace(rune(body[pos])) {
			pos++
		}
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
			return nil, nil, fmt.Errorf("failed to parse email header 'Content-Type': %w", err)
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
			return nil, nil, fmt.Errorf("failed to read email body: %w", err)
		}
		return nil, [][]byte{attachment}, nil
	}
	if mediaType == "text/plain" {
		body, err := io.ReadAll(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read email body: %w", err)
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
			return nil, nil, fmt.Errorf("failed to parse MIME parts: %w", err)
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

var extractMessageIDs = regexp.MustCompile(`<.+?>`)

func extractInReplyTo(header mail.Header) string {
	value := header.Get("In-Reply-To")
	// Normally there should be just one message, to which we reply.
	// However, there have been some cases when multiple addresses were mentioned.
	// For now let's just take the first one.
	ret := extractMessageIDs.FindStringSubmatch(value)
	if ret != nil {
		return ret[0]
	}
	return ""
}

func extractBodyBugIDs(body string, ownEmailMap map[string]bool, domains []string) []string {
	// Let's build a regular expression.
	var rb strings.Builder
	for email := range ownEmailMap {
		escaped := regexp.QuoteMeta(email)
		part := strings.ReplaceAll(escaped, `@`, `\+(\w+?)@`)
		if rb.Len() > 0 {
			rb.WriteString(`|`)
		}
		rb.WriteString(part)
	}
	for _, domain := range domains {
		escaped := regexp.QuoteMeta(domain + "/bug?extid=")
		if rb.Len() > 0 {
			rb.WriteString(`|`)
		}
		rb.WriteString(escaped)
		rb.WriteString(`([\w]+)`)
	}
	rg := regexp.MustCompile(rb.String())
	ids := []string{}
	for _, match := range rg.FindAllStringSubmatch(body, -1) {
		// Take all non-empty group matches.
		for i := 1; i < len(match); i++ {
			if match[i] == "" {
				continue
			}
			ids = append(ids, match[i])
		}
	}
	return ids
}

func dedupBugIDs(list []string) []string {
	// We should preserve the original order of IDs.
	var ret []string
	dup := map[string]struct{}{}
	for _, v := range list {
		if _, ok := dup[v]; ok {
			continue
		}
		dup[v] = struct{}{}
		ret = append(ret, v)
	}
	return ret
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
