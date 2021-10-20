//  Copyright 2021-Present Couchbase, Inc.
//
//  Use of this software is governed by the Business Source License included
//  in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
//  in that file, in accordance with the Business Source License, use of this
//  software will be governed by the Apache License, Version 2.0, included in
//  the file licenses/APL2.txt.

package systemeventlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/couchbase/cbauth"
	"github.com/google/uuid"
	"net/http"
	"time"
)

// System Event Logging:
//
// PRD: https://docs.google.com/document/d/1RbG78jjoWF_q1_pDw6h6aOG3H_-eVHkzSETVU_FSqEc/edit#
//
// Design Doc: https://docs.google.com/document/d/1dMkRVbJFQbGE0cfJl05lYN6qtv_jDv7YEdUfFzQGMbo/edit
//

//
type SystemEventLoggerImpl struct {
	seEndpoint string
	config     SystemEventLoggerConfig
	client     http.Client

	component string

	eventChan chan queuedEvent

	errorLoggerFunc func(message string)
}

//
type SystemEventLoggerConfig struct {
	QueueSize            uint16
	MaxTries             uint16
	MaxRetryIntervalSecs uint16
}

//
type queuedEvent struct {
	uuid  string
	event []byte
}

//
type SystemEventLogger interface {
	Log(event SystemEvent)
}

// Ranges of ids for each component detailed in the NS-Server design doc:
//   https://docs.google.com/document/d/1dMkRVbJFQbGE0cfJl05lYN6qtv_jDv7YEdUfFzQGMbo/edit
type EventId uint16

// Severity
type EventSeverity string

const (
	SEInfo    EventSeverity = "info"
	SEError   EventSeverity = "error"
	SEWarning EventSeverity = "warn"
	SEFatal   EventSeverity = "fatal"
)

//
type baseSystemEvent struct {
	Component string `json:"component"`
	UUID      string `json:"uuid"`
	Timestamp string `json:"timestamp"`
}

//
type SystemEventInfo struct {
	EventId     EventId `json:"event_id"`
	Description string  `json:"description,omitempty"`
}

//
type SystemEvent struct {
	SubComponent string        `json:"sub_component,omitempty"`
	Severity     EventSeverity `json:"severity"`

	SystemEventInfo

	ExtraAttributes interface{} `json:"extra_attributes,omitempty"`
}

type completeSystemEvent struct {
	baseSystemEvent

	SystemEvent
}

//
const (
	eventTimestampFormat = "2006-01-02T15:04:05.000Z"

	systemEventPath = "/_event"
)

//
func NewSystemEventLogger(config SystemEventLoggerConfig, baseNsserverURL string,
	component string, client http.Client,
	errorLoggerFunc func(message string)) SystemEventLogger {

	config = getValidConfig(config)

	eventChan := make(chan queuedEvent, config.QueueSize)

	seli := &SystemEventLoggerImpl{config: config,
		seEndpoint:      baseNsserverURL + systemEventPath,
		client:          client,
		component:       component,
		errorLoggerFunc: errorLoggerFunc,
		eventChan:       eventChan}

	go seli.logEvents()

	return seli
}

//
func (seli *SystemEventLoggerImpl) Log(event SystemEvent) {

	cse := completeSystemEvent{baseSystemEvent: seli.baseSystemEventInfo(),
		SystemEvent: event}

	se, err := json.Marshal(&cse)
	if err != nil {
		seli.logError(
			fmt.Sprintf(
				"SystemEventLoggerImpl.Log: Marshal failed (%v); Unable to log system event: %v",
				err, cse))

		return
	}

	qe := queuedEvent{uuid: cse.UUID, event: se}

	select {
	case seli.eventChan <- qe:
		// System event sent successfully.

	default:
		// chan full; system event will be lost.
		seli.logError(
			fmt.Sprintf(
				"SystemEventLoggerImpl.Log: system event chan full; Unable to log system event: %v",
				string(se)))
	}
}

//
func NewSystemEvent(subComponent string, sei SystemEventInfo,
	severity EventSeverity, extraAttributes interface{}) SystemEvent {

	return SystemEvent{
		SubComponent:    subComponent,
		SystemEventInfo: sei,
		Severity:        severity,
		ExtraAttributes: extraAttributes}
}

//
func (seli *SystemEventLoggerImpl) baseSystemEventInfo() baseSystemEvent {

	return baseSystemEvent{
		Component: seli.component,
		UUID:      uuid.New().String(),
		Timestamp: time.Now().UTC().Format(eventTimestampFormat),
	}
}

// func invoked as a goroutine to flush events in the chan to ns-server.
func (seli *SystemEventLoggerImpl) logEvents() {

	// Till ns-server exposes a bulk-event-POST, deal w/ events one at a time.
	for qe := range seli.eventChan {
		seli.logEventWithRetry(qe)
	}
}

const (
	defaultRetryIntervalSecs = 1

	retryAfterHeader = "Retry-after"
)

// Attempts to log the system event to ns-server endpoint. Max of MAX_TRIES attempts
// will be made to log the event. If the attempt encounters any non-retriable error
// the operation will no longer be retried. If the attempt encounters a retriable
// error (503), the goroutine will sleep for a duration as provided by ns-server via
// the 'Retry-after' response HTTP Header (with a default in case ns-server does not
// provide this response header.)
func (seli *SystemEventLoggerImpl) logEventWithRetry(qe queuedEvent) {

	var tries uint16

	for {
		_, operationComplete, sleepIntervalInSecs := seli.logEvent(qe)

		if operationComplete {
			return
		}

		tries++
		if tries >= seli.config.MaxTries {
			seli.logError(
				fmt.Sprintf(
					"SystemEventLoggerImpl.logEventWithRetry: Max tries exceeded; Unable to log system event: %v",
					string(qe.event)))

			return
		}

		time.Sleep(time.Duration(sleepIntervalInSecs) * time.Second)
	}
}

// Makes a single attempt to log the system event to ns-server endpoint.
// Returns:
// loggedSuccessfully, operationComplete, timeInterval
// true, true, 0: system event was logged successfully
// false, true, 0: system event was not logged but instead encountered a
//   non-triable error.
// false, false, <timeIntervalInSecs>: system event was not logged successfully,
//   the operation encountered a retryable error, to be retried (subject to
//   max-tries) after <timeIntervalInSecs> seconds.
func (seli *SystemEventLoggerImpl) logEvent(qe queuedEvent) (loggedSuccessfully,
	operationComplete bool, timeInterval uint16) {

	request, err := http.NewRequest("POST", seli.seEndpoint, bytes.NewBuffer(qe.event))
	if err != nil {
		seli.logError(
			fmt.Sprintf(
				"SystemEventLoggerImpl.logEvent: HTTP Request instantiation failed (%v); Unable to log system event: %v",
				err, string(qe.event)))

		return false, true, 0
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Idempotency-Key", qe.uuid)
	err = cbauth.SetRequestAuthVia(request, nil)
	if err != nil {
		seli.logError(
			fmt.Sprintf(
				"SystemEventLoggerImpl.logEvent: Set authn creds on HTTP Request failed (%v); Unable to log system event: %v",
				err, string(qe.event)))

		return false, true, 0
	}

	response, err := seli.client.Do(request)
	if err != nil {
		seli.logError(
			fmt.Sprintf(
				"SystemEventLoggerImpl.logEvent: POST to %v failed (%v). Unable to log system event: %v",
				seli.seEndpoint, err, string(qe.event)))

		return false, true, 0
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		return true, true, 0
	}

	if response.StatusCode != http.StatusServiceUnavailable {
		seli.logError(
			fmt.Sprintf(
				"SystemEventLoggerImpl.logEvent: Request failed with HTTP Status code: %v; Unable to log system event: %v",
				response.StatusCode, string(qe.event)))

		return false, true, 0
	}

	return false, false, seli.getSleepInterval(response)
}

//
func (seli *SystemEventLoggerImpl) getSleepInterval(response *http.Response) (sleepInterval uint16) {

	retryAfterHeader := response.Header.Get(retryAfterHeader)
	if retryAfterHeader == "" {
		return defaultRetryIntervalSecs
	}

	var retryAfter uint16

	scanCount, _ := fmt.Sscanf(retryAfterHeader, "%d", &retryAfter)
	if scanCount != 1 {
		return defaultRetryIntervalSecs
	}

	if retryAfter > seli.config.MaxRetryIntervalSecs {
		return seli.config.MaxRetryIntervalSecs
	}

	return retryAfter
}

//
func (seli *SystemEventLoggerImpl) logError(message string) {

	if seli.errorLoggerFunc == nil {
		return
	}

	seli.errorLoggerFunc(message)
}

const (
	defaultQueueSize = 1024

	defaultMaxTries = 3

	defaultMaxRetryIntervalSecs = 10
)

//
func getValidConfig(config SystemEventLoggerConfig) SystemEventLoggerConfig {

	if config.QueueSize == 0 {
		config.QueueSize = defaultQueueSize
	}

	if config.MaxTries == 0 {
		config.MaxTries = defaultMaxTries
	}

	if config.MaxRetryIntervalSecs == 0 {
		config.MaxRetryIntervalSecs = defaultMaxRetryIntervalSecs
	}

	return config
}
