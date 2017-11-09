The builtin smtp liveness check on BIG-IP F5 has two problems:

1. it only checks if the SMTP server responds to connections and HELO/EHLO
2. It contains a bug (repeatedly sending QUIT instead of once) that makes exim send a TCP RST resulting on backend being marked as down. This is fixed in newer releases.

This test also detects breakage in later stages like contect checks by sending a test email.

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
