//package f5smtpmonitor
package main

import (
	"bytes"
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
)

// MailConfig stores customization for testmail
type MailConfig struct {
	Sender    string
	Recipient string
	Date      string
	Subject   string
	Mailbody  string
}

const (
	bodyTemplateText = "To: {{.Recipient}}\r\nFrom: {{.Sender}}\r\nDate: {{.Date}}\r\nPrecedence: bulk\r\nAuto-Submitted: auto-generated\r\nSubject: {{.Subject}}\r\n\r\n{{.Mailbody}}\r\n"
	// EICAR : Anti-Virus Test File (https://en.wikipedia.org/wiki/EICAR_test_file)
	EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	// GTUBE : Generic Test for Unsolicited Bulk Email (https://en.wikipedia.org/wiki/GTUBE)
	GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
)

var (
	hasDebug     = false
	syslogWriter io.Writer
	bodyTemplate = template.Must(template.New("mailbody").Parse(bodyTemplateText))
	bodyText     bytes.Buffer
	mailconfig   = MailConfig{
		Sender:    "sender@example.com",
		Recipient: "recipient@example.com",
		Date:      time.Now().Local().Format("Mon, _2 Jan 2006 15:04:05 -0700"),
		Subject:   "F5 Loadbalancer Keepalive Test",
	}
)

func init() {
	var err error
	// exract commandline arguments
	flag.Parse()
	if flag.NArg() < 2 {
		log.Fatalf("Only got %d commandline arguments, expected at least two", flag.NArg())
	}
	// enable syslog for debug runs
	if os.Getenv("DEBUG") != "" && os.Getenv("DEBUG") != "0" {
		hasDebug = true
		syslogWriter, err = syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "smtp-monitor")
		if err != nil {
			syslogWriter = ioutil.Discard
		}
	}
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
		mailconfig.Mailbody += EICAR + "\n\r"
	}
	// trigger spam detection
	if os.Getenv("TESTSPAM") != "" {
		mailconfig.Mailbody += GTUBE + "\n\r"
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

func main() {
	// this expects BIGIP F5 style: ipv6 or ipv4-in-v6-address
	connectstring := fmt.Sprintf("[%s]:%s", os.Args[1], os.Args[2])

	// Connect to the remote SMTP server.
	c, err := smtp.Dial(connectstring)
	if err != nil {
		DebugLog("Error connecting to %s: %s", connectstring, err.Error())
		os.Exit(1)
	}
	DebugLog("Connected to %s", connectstring)

	// use STARTTLS
	// we don't care for certificate validity (too much complexity for this test)
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
	if os.Getenv("HELO") != "" {
		c.Hello(os.Getenv("HELO"))
		DebugLog("HELO/EHLO string set to %s", os.Getenv("HELO"))
	}

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

	// Send the email body.
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
	DebugLog("Sent DATA")

	err = wc.Close()
	if err != nil {
		DebugLog("Error after sending DATA: %s", err.Error())
		os.Exit(6)
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		DebugLog(err.Error())
		os.Exit(7)
	}
	DebugLog("Sent QUIT and closed connection")
}
