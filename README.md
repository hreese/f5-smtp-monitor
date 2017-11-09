The builtin smtp liveness check on BIG-IP F5 has two problems:

1. it only checks if the SMTP server responds to connections and HELO/EHLO
2. It contains a bug (repeatedly sending QUIT instead of once) that makes exim send a TCP RST resulting on backend being marked as down. This is fixed in newer releases.

This test also detects breakage in later stages like contect checks by sending a test email.

Check the buildin help for up-to-date information on switches and usage:

```sh
$ f5-smtp-monitor --help
This smtp backend check expects two mandatory arguments:

1. ip address (IPv4-mapped IPv6 addresses for IPv4, e.g. "":ffff:a.b.c.d")
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
```

# Setting up the monitor on BIG-IP F5

TBD…

# Setting up your MTA

For performance reasons, the recommended way is having a special mailaddress or domain that discards everything.
We'll use `blackhole.example.com` here.

## exim

Add a rcpt-acl to always allow your discard domain:

```
accept
  domains = blackhole.example.com
  endpass
```

Add a discard router:

```
blackhole:
  driver  = redirect
  domains = blackhole.example.com
  data    = :blackhole:
```