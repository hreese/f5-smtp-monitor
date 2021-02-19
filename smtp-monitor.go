package main

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/smtp"
	"os"
	"text/template"
	"time"

	uuid "github.com/satori/go.uuid"
)

// MailConfig stores customization for testmail
type MailConfig struct {
	Sender    string
	Recipient string
	Date      string
	MessageID string
	Subject   string
	Mailbody  string
}

const (
	bodyTemplateText = "To: {{.Recipient}}\r\nFrom: {{.Sender}}\r\nDate: {{.Date}}\r\nPrecedence: bulk\r\nAuto-Submitted: auto-generated\r\nMessage-ID: <{{.MessageID}}>\r\nSubject: {{.Subject}}\r\n\r\n{{.Mailbody}}\r\n"
	helpText         = `This smtp backend check expects two mandatory arguments:

1. ip address (IPv4-mapped IPv6 address for IPv4 address, e.g. "":ffff:a.b.c.d")
2. tcp port number

The rest of the program is controlled by environment variables (defaults in parenthesis):

* DEBUG:     when set to anything than 0 enables debugging output to syslog (0)
* SENDER:    mail sender (sender@example.com)
* RECIPIENT: mail recipient (recipient@example.com)
* SUBJECT:   mail subject ("F5 Loadbalancer Keepalive Test")
* BODY:      mail body ("")
* STARTTLS:  try STARTTLS without certificate verification when set (NOT SET)
* HELO:      use value for HELO/EHLO (localhost)
* TESTAV:    add EICAR test virus to body when set (NOT SET)
* TESTSPAM:  add GTUBE spam string to body when set (NOT SET)
`
)

var (
	hasDebug     = false
	sendEicar    = false
	sendGTube    = false
	syslogWriter io.Writer
	bodyTemplate = template.Must(template.New("mailbody").Parse(bodyTemplateText))
	bodyText     bytes.Buffer
	hostname     string
	mailconfig   = MailConfig{
		Sender:    "sender@example.com",
		Recipient: "recipient@example.com",
		Date:      time.Now().Local().Format("Mon, _2 Jan 2006 15:04:05 -0700"),
		Subject:   "F5 Loadbalancer Keepalive Test",
	}
	// XORKEY is used to obfuscate EICAR and GTUBE to prevent this monitor from being flagged as malware or spam
	XORKEY = sha512.Sum512_256([]byte("f5-smtp-monitor"))
	// EICAR : Anti-Virus Test File (https://en.wikipedia.org/wiki/EICAR_test_file)
	EICAR = string(XOR([]byte{0x2d, 0x7f, 0x8a, 0x20, 0x23, 0x89, 0x60, 0x6a, 0x40, 0x27, 0xa4, 0x4e, 0x7e, 0xc2, 0x57, 0x4f, 0xfc, 0xab, 0x4b, 0xc5, 0x4d, 0xba, 0x67, 0xcd, 0x8e, 0x3d, 0x21, 0x94, 0x5e, 0xd2, 0x7c, 0x76, 0x27, 0x67, 0x96, 0x55, 0x32, 0xe2, 0x64, 0x6a, 0x42, 0x38, 0xbd, 0x53, 0x60, 0xcc, 0x46, 0x2c, 0x81, 0xd1, 0x4e, 0xc8, 0x49, 0xd9, 0x61, 0xdd, 0xf3, 0x27, 0x1a, 0xf9, 0x57, 0xde, 0x1e, 0x13, 0x3d, 0x61, 0x8d, 0x2b}, XORKEY[:]))
	// GTUBE : Generic Test for Unsolicited Bulk Email (https://en.wikipedia.org/wiki/GTUBE)
	GTUBE = string(XOR([]byte{0x2d, 0x0, 0x96, 0x2b, 0x30, 0x98, 0x6a, 0x6f, 0x52, 0x2d, 0xd1, 0x56, 0x60, 0xa9, 0x21, 0x34, 0x9b, 0xc1, 0x55, 0xa8, 0x4e, 0xbf, 0x6d, 0xca, 0xe9, 0x4f, 0x12, 0x9a, 0x5c, 0xcf, 0x6a, 0x75, 0x30, 0x67, 0x96, 0x55, 0x32, 0xe2, 0x64, 0x6a, 0x42, 0x38, 0xbd, 0x53, 0x60, 0xcc, 0x46, 0x57, 0x9d, 0xc1, 0x5e, 0xb6, 0x30, 0xc8, 0x77, 0xda, 0x8a, 0x4f, 0x11, 0xf1, 0x52, 0xd7, 0x15, 0x74, 0x5b, 0x79, 0xf1, 0x59}, XORKEY[:]))
)

// XOR returns (cleartext XOR key), repeating key if it is shorter than cleartext
func XOR(cleartext, key []byte) []byte {
	xor := make([]byte, len(cleartext))
	for idx := 0; idx < len(cleartext); idx++ {
		xor[idx] = cleartext[idx] ^ key[idx%len(key)]
	}
	return xor
}

// setup
func init() {
	var err error
	// get hostname
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "f5-keepalive-test.localdomain"
	}
	// Set custom help message
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, helpText)
		os.Exit(127)
	}
	// extract commandline arguments
	flag.Parse()
	if flag.NArg() != 2 {
		log.Fatalf("Got %d commandline arguments, expected exactly two", flag.NArg())
	}
	// enable syslog for debug runs
	if os.Getenv("DEBUG") != "" && os.Getenv("DEBUG") != "0" {
		hasDebug = true
		syslogWriter, err = syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "smtp-monitor")
		// if syslog fails, silently discard debug output
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Unable to create syslog writer: %s\n", err.Error())
			syslogWriter = ioutil.Discard
		}
	}
	// generate message-id
	mailconfig.MessageID = uuid.NewV4().String() + "@" + hostname
	// get sender
	if os.Getenv("SENDER") != "" {
		mailconfig.Sender = os.Getenv("SENDER")
	}
	// get recipient
	if os.Getenv("RECIPIENT") != "" {
		mailconfig.Recipient = os.Getenv("RECIPIENT")
	}
	// get recipient
	if os.Getenv("SUBJECT") != "" {
		mailconfig.Subject = os.Getenv("SUBJECT")
	}
	// get mailbody
	if os.Getenv("BODY") != "" {
		mailconfig.Mailbody = os.Getenv("BODY")
	}
	// trigger antivirus
	if os.Getenv("TESTAV") != "" {
		sendEicar = true
		mailconfig.Mailbody += string(EICAR) + "\n\r"
	}
	// trigger spam detection
	if os.Getenv("TESTSPAM") != "" {
		sendGTube = true
		mailconfig.Mailbody += string(GTUBE) + "\n\r"
	}
	// render mail body
	bodyTemplate.Execute(&bodyText, mailconfig)
}

// DebugLog is printf for syslog or a NOP, depending on the global hasDebug variable
func DebugLog(format string, args ...interface{}) {
	if hasDebug {
		msg := fmt.Sprintf(format, args...)
		syslogWriter.Write([]byte(msg))
	}
}

// run test
func main() {
	// wrap ipaddress in [] because this is guaranteed to be an ipv6-address
	connectstring := fmt.Sprintf("[%s]:%s", os.Args[1], os.Args[2])

	// Connect to the remote SMTP server.
	c, err := smtp.Dial(connectstring)
	if err != nil {
		DebugLog("Error connecting to %s: %s", connectstring, err.Error())
		os.Exit(1)
	}
	DebugLog("Connected to %s", connectstring)

	// use STARTTLS
	// we don't care for certificate validity (it adds too much complexity for this test)
	// if we can establish any TLS connection, we're happy here
	if os.Getenv("STARTTLS") != "" {
		DebugLog("STARTTLS sent")
		err = c.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			DebugLog("Error after STARTTLS: %s", err.Error())
			os.Exit(16)
		}
	}

	// set custom HELO/EHLO
	var hellostring = os.Getenv("HELO")
	if hellostring == "" {
		hellostring = hostname
	}
	c.Hello(hellostring)
	DebugLog("HELO/EHLO string set to %s", os.Getenv("HELO"))

	// Set the sender
	if err = c.Mail(mailconfig.Sender); err != nil {
		DebugLog("Error setting the sender %s: %s", mailconfig.Sender, err.Error())
		os.Exit(2)
	}
	DebugLog("Sent MAIL FROM %s", mailconfig.Sender)

	// Set the recipient
	if err = c.Rcpt(mailconfig.Recipient); err != nil {
		DebugLog("Error setting the recipient %s: %s", mailconfig.Recipient, err.Error())
		os.Exit(3)
	}
	DebugLog("Sent RCPT TO %s", mailconfig.Recipient)

	// Prepare email DATA
	wc, err := c.Data()
	if err != nil {
		DebugLog(err.Error())
		os.Exit(4)
	}

	_, err = bodyText.WriteTo(wc)
	if err != nil {
		DebugLog(err.Error())
		os.Exit(5)
	}

	// send email DATA
	err = wc.Close()
	if err != nil {
		// signal success on AV/SPAM testing
		switch {
		case sendEicar == true:
			fmt.Printf("Message containg EICAR test virus rejected after data: %s", err)
			DebugLog("Message containg EICAR test virus rejected after data: %s", err)
			os.Exit(0)
		case sendGTube == true:
			fmt.Printf("Message containg GTUBE spam test rejected after data: %s", err)
			DebugLog("Message containg GTUBE spam test rejected after data: %s", err)
			os.Exit(0)
		default:
			DebugLog("Error after sending DATA: %s", err.Error())
			os.Exit(6)
		}
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		// EICAR/GTUBE not prevented
		switch {
		case sendEicar == true:
			DebugLog("Message containg EICAR test virus not rejected")
			os.Exit(7)
		case sendGTube == true:
			DebugLog("Message containg GTUBE spam test not rejected")
			os.Exit(8)
		default:
			DebugLog(err.Error())
			os.Exit(9)
		}
	}

	// EICAR/GTUBE not prevented
	switch {
	case sendEicar == true:
		DebugLog("Message containg EICAR test virus not rejected")
		os.Exit(7)
	case sendGTube == true:
		DebugLog("Message containg GTUBE spam test not rejected")
		os.Exit(8)
	}

	// success
	fmt.Println("OK")
	DebugLog("Sent QUIT and closed connection")
}
