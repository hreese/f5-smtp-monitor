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

	"github.com/satori/go.uuid"
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
	// EICAR : Anti-Virus Test File (https://en.wikipedia.org/wiki/EICAR_test_file)
	EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	// GTUBE : Generic Test for Unsolicited Bulk Email (https://en.wikipedia.org/wiki/GTUBE)
	GTUBE    = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
	helpText = `This smtp backend check expects two mandatory arguments:

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

// setup
func init() {
	var err error
	// Set custom help message
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, helpText)
		os.Exit(127)
	}
	// extract commandline arguments
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
	// generate message-id
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "f5-keepalive-test"
	}
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
