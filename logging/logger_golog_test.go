//  Copyright 2016-Present Couchbase, Inc.
//
//  Use of this software is governed by the Business Source License included
//  in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
//  in that file, in accordance with the Business Source License, use of this
//  software will be governed by the Apache License, Version 2.0, included in
//  the file licenses/APL2.txt.

package logging

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

var buffer *bytes.Buffer

func setLogWriter(w io.Writer, lvl Level, fmtLogging LogEntryFormatter) {
	logger = NewLogger(w, lvl, fmtLogging)
	SetLogger(logger)
}

func logMessages(logger *goLogger) {
	logger.Debugf("This is a message from %s", "Debugf")
	logger.Tracef("This is a message from %s", "Tracef")
	logger.Requestf(logging.WARN, "This is a message from %s", "Requestf")
	logger.Infof("This is a message from %s", "Infof")
	logger.Warnf("This is a message from %s", "Warnf")
	logger.Errorf("This is a message from %s", "Errorf")
	logger.Severef("This is a message from %s", "Severef")
	logger.Fatalf("This is a message from %s", "Fatalf")

	Debugf("This is a message from %s", "Debugf")
	Tracef("This is a message from %s", "Tracef")
	Requestf(logging.WARN, "This is a message from %s", "Requestf")
	Infof("This is a message from %s", "Infof")
	Warnf("This is a message from %s", "Warnf")
	Errorf("This is a message from %s", "Errorf")
	Severef("This is a message from %s", "Severef")
	Fatalf("This is a message from %s", "Fatalf")

	logger.Debuga(func() string { return "This is a message from Debuga" })
	logger.Tracea(func() string { return "This is a message from Tracea" })
	logger.Requesta(logging.WARN, func() string { return "This is a message from Requesta" })
	logger.Infoa(func() string { return "This is a message from Infoa" })
	logger.Warna(func() string { return "This is a message from Warna" })
	logger.Errora(func() string { return "This is a message from Errora" })
	logger.Severea(func() string { return "This is a message from Severea" })
	logger.Fatala(func() string { return "This is a message from Fatala" })

	Debuga(func() string { return "This is a message from Debuga" })
	Tracea(func() string { return "This is a message from Tracea" })
	Requesta(logging.WARN, func() string { return "This is a message from Requesta" })
	Infoa(func() string { return "This is a message from Infoa" })
	Warna(func() string { return "This is a message from Warna" })
	Errora(func() string { return "This is a message from Errora" })
	Severea(func() string { return "This is a message from Severea" })
	Fatala(func() string { return "This is a message from Fatala" })
}

func TestStub(t *testing.T) {
	logger := NewLogger(os.Stdout, DEBUG, KVFORMATTER)
	SetLogger(logger)

	logMessages(logger)

	logger.SetLevel(WARN)
	fmt.Printf("Log level is %s\n", logger.Level())

	logMessages(logger)

	fmt.Printf("Changing to json formatter\n")
	logger.entryFormatter = &jsonFormatter{}
	logger.SetLevel(DEBUG)

	logMessages(logger)

	fmt.Printf("Changing to Text formatter\n")
	logger.entryFormatter = &textFormatter{}
	logger.SetLevel(DEBUG)

	logMessages(logger)

	fmt.Printf("Changing to Uniform formatter\n")
	logger.entryFormatter = &uniformFormatter{
		callback: ComponentCallback(func() string {
			return "COMPONENT.subcomponent"
		}),
	}
	logger.SetLevel(DEBUG)

	logMessages(logger)

	buffer.Reset()
	logger = NewLogger(buffer, DEBUG, KVFORMATTER)
	logger.Infof("This is a message from test in key-value format")
	if s := string(buffer.Bytes()); strings.Contains(s, "_msg=This is a message from test in key-value format") == false {
		t.Errorf("Infof() failed %v", s)
	}
	buffer.Reset()
	logger.entryFormatter = &jsonFormatter{}
	logger.Infof("This is a message from test in jason format")
	if s := string(buffer.Bytes()); strings.Contains(s, "\"_msg\":\"This is a message from test in jason format\"") == false {
		t.Errorf("Infof() failed %v", s)
	}
	buffer.Reset()
	logger.entryFormatter = &textFormatter{}
	logger.Infof("This is a message from test in text format")
	if s := string(buffer.Bytes()); strings.Contains(s, "[INFO] This is a message from test in text format") == false {
		t.Errorf("Infof() failed %v", s)
	}
	buffer.Reset()
	logger.entryFormatter = &uniformFormatter{
		callback: ComponentCallback(func() string {
			return "COMPONENT.subcomponent"
		}),
	}
	logger.Debugf("This is a message from test in uniform format")
	if s := string(buffer.Bytes()); strings.Contains(s, "DEBU COMPONENT.subcomponent This is a message from test in uniform format") == false {
		t.Errorf("Debugf() failed %v", s)
	}
}

func init() {
	buffer = bytes.NewBuffer([]byte{})
	buffer.Reset()
}

func TestLogNone(t *testing.T) {
	buffer.Reset()
	setLogWriter(buffer, DEBUG, KVFORMATTER)
	Warnf("%s", "test")
	if s := string(buffer.Bytes()); strings.Contains(s, "test") == false {
		t.Errorf("Warnf() failed %v", s)
	}
	SetLevel(NONE)
	Warnf("test")
	if s := string(buffer.Bytes()); s == "" {
		t.Errorf("Warnf() failed %v", s)
	}
}
func TestLogLevelDefault(t *testing.T) {
	buffer.Reset()
	setLogWriter(buffer, INFO, KVFORMATTER)
	SetLevel(INFO)
	Warnf("%s", "warn")
	Errorf("error")
	Severef("severe")
	Infof("info")
	Debugf("debug")
	Tracef("trace")
	s := string(buffer.Bytes())
	if strings.Contains(s, "warn") == false {
		t.Errorf("Warnf() failed %v", s)
	} else if strings.Contains(s, "error") == false {
		t.Errorf("Errorf() failed %v", s)
	} else if strings.Contains(s, "severe") == false {
		t.Errorf("Severef() failed %v", s)
	} else if strings.Contains(s, "info") == false {
		t.Errorf("Infof() failed %v", s)
	} else if strings.Contains(s, "debug") == true {
		t.Errorf("Debugf() failed %v", s)
	} else if strings.Contains(s, "trace") == true {
		t.Errorf("Tracef() failed %v", s)
	}
	setLogWriter(os.Stdout, INFO, KVFORMATTER)
}

func TestLogLevelInfo(t *testing.T) {
	buffer.Reset()
	setLogWriter(buffer, INFO, KVFORMATTER)
	Warnf("warn")
	Infof("info")
	Debugf("debug")
	Tracef("trace")
	s := string(buffer.Bytes())
	if strings.Contains(s, "warn") == false {
		t.Errorf("Warnf() failed %v", s)
	} else if strings.Contains(s, "info") == false {
		t.Errorf("Infof() failed %v", s)
	} else if strings.Contains(s, "debug") == true {
		t.Errorf("Debugf() failed %v", s)
	} else if strings.Contains(s, "trace") == true {
		t.Errorf("Tracef() failed %v", s)
	}
	setLogWriter(os.Stdout, INFO, KVFORMATTER)
}

func TestLogLevelDebug(t *testing.T) {
	buffer.Reset()
	setLogWriter(buffer, DEBUG, KVFORMATTER)
	Warnf("warn")
	Infof("info")
	Debugf("debug")
	Tracef("trace")
	s := string(buffer.Bytes())
	if strings.Contains(s, "warn") == false {
		t.Errorf("Warnf() failed %v", s)
	} else if strings.Contains(s, "info") == false {
		t.Errorf("Infof() failed %v", s)
	} else if strings.Contains(s, "debug") == false {
		t.Errorf("Debugf() failed %v", s)
	} else if strings.Contains(s, "trace") == false {
		t.Errorf("Tracef() failed %v", s)
	}
	setLogWriter(os.Stdout, INFO, KVFORMATTER)
}

func TestLogLevelTrace(t *testing.T) {
	buffer.Reset()
	setLogWriter(buffer, TRACE, KVFORMATTER)
	Warnf("warn")
	Infof("info")
	Debugf("debug")
	Tracef("trace")
	s := string(buffer.Bytes())
	if strings.Contains(s, "warn") == false {
		t.Errorf("Warnf() failed %v", s)
	} else if strings.Contains(s, "info") == false {
		t.Errorf("Infof() failed %v", s)
	} else if strings.Contains(s, "debug") == true {
		t.Errorf("Debugf() failed %v", s)
	} else if strings.Contains(s, "trace") == false {
		t.Errorf("Tracef() failed %v", s)
	}
	setLogWriter(os.Stdout, INFO, KVFORMATTER)
}

func TestDefaultLog(t *testing.T) {
	buffer.Reset()
	setLogWriter(buffer, TRACE, KVFORMATTER)
	sl := logger
	sl.Warnf("warn")
	sl.Infof("info")
	sl.Debugf("debug")
	sl.Tracef("trace")
	s := string(buffer.Bytes())
	if strings.Contains(s, "warn") == false {
		t.Errorf("Warnf() failed %v", s)
	} else if strings.Contains(s, "info") == false {
		t.Errorf("Infof() failed %v", s)
	} else if strings.Contains(s, "trace") == false {
		t.Errorf("Tracef() failed %v", s)
	} else if strings.Contains(s, "debug") == true {
		t.Errorf("Debugf() failed %v", s)
	}
	setLogWriter(os.Stdout, INFO, KVFORMATTER)
}
