# goutils
Common utility libraries for Couchbase Go code.

* logging

   Package logging implements a simple logging package. It defines a type,
   Logger, with methods for formatting output. The logger writes to standard out
   and prints the date and time in ISO 8601 standard with a timezone postfix
   of each logged message. The logger has option to log message as Json or
   Key-value or Text format.

* platform

  Package platform implements common platform specific routines we often need
  in our Go applications.

## Installation

git clone git@github.com:couchbase/goutils.git

## Development Setup

Before running any `go` commands, configure the Go proxy:

```bash
export GOPROXY=https://go.aikido.io/c09059e8f4b962b0d8ee,https://proxy.golang.org,direct
```
