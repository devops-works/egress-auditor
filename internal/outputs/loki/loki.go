package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/devops-works/egress-auditor/internal/entry"
	"github.com/devops-works/egress-auditor/internal/outputs"
)

// Output writes a loki log for every connection seen by upstream inputs
type Output struct {
	url    string
	user   string
	pass   string
	xorgid string
	labels map[string]string
}

// Description returns a description for the module, including the available
// options
func (l *Output) Description() string {
	return `
	loki handler
	Sends logs to loki server
	This is typically used in monitoring mode after you have allow rules in place to allow legitimate trafic.

	Options:
		- "loki:url:<url>": loki URL to ship logs to
		- "loki:user:<str>": loki username for basic auth
		- "loki:pass:<str>": loki password for basic auth
		- "loki:orgid:<id>": X-Org-ID header to add to loki queries (e.g. tenant)
		- "loki:labels:<key>=<value>[,<key>=<value>...]": additional labels for log entries

	Example:
		egress-auditor -i ... -o loki -O loki:url:http://localhost:3100
	`
}

// Process starts handling connections captured by upstream inputs
func (l *Output) Process(ctx context.Context, c <-chan entry.Connection) {
	for {
		select {
		case <-ctx.Done():
			fmt.Println("terminating capture")
			return
		case ent := <-c:
			l.sendLog(ent)
		}
	}
}

// sendLog to loki
func (l *Output) sendLog(e entry.Connection) {
	type lokiStream struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	}

	type lokiEntry struct {
		Streams []lokiStream `json:"streams"`
	}

	// build json message
	jsonMessage, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[loki] error marshalling message: %v\n", err)
		return
	}

	ls := lokiStream{
		Stream: l.labels,
		Values: [][]string{
			{fmt.Sprintf("%d", time.Now().UTC().UnixNano()), string(jsonMessage)},
		},
	}

	host, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[loki] error getting hostname request: %v\n", err)
	}

	ls.Stream["host"] = host

	le := lokiEntry{
		Streams: []lokiStream{ls},
	}

	js, err := json.Marshal(le)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[loki] error marshalling message: %v\n", err)
		return
	}

	// fmt.Println(js)
	req, err := http.NewRequest(http.MethodPost, l.url+"/loki/api/v1/push", bytes.NewBuffer([]byte(js)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[loki] error building request: %v\n", err)
		return
	}

	if l.user != "" {
		req.SetBasicAuth(l.user, l.pass)
	}
	if l.xorgid != "" {
		req.Header.Add("X-Scope-OrgID", l.xorgid)
	}

	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[loki] error sending data to loki: %v\n", err)
		return
	}

	if resp.StatusCode >= 300 {
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[loki] error reading loki response: %v\n", err)
		}
		defer resp.Body.Close()

		fmt.Fprintf(os.Stderr, "[loki] error when talking to loki (returned %s): %v\n", resp.Status, string(responseBody))
		fmt.Fprintf(os.Stderr, "[loki] request body was: %q\n", js)
	}
}

// Cleanup any stuff that needs to be sorted out before exiting
func (l *Output) Cleanup() {
}

// SetOption let caller set specific module suboptions
func (l *Output) SetOption(k, v string) error {
	switch k {
	case "url":
		l.url = v
	case "user":
		l.user = v
	case "pass":
		l.pass = v
	case "orgid":
		l.xorgid = v
	case "labels":
		fmt.Println(k, v)
		if l.labels == nil {
			l.labels = make(map[string]string)
		}
		labels := strings.Split(v, ",")
		for _, entry := range labels {
			parts := strings.SplitN(entry, "=", 2)
			l.labels[parts[0]] = parts[1]
		}
	default:
		return fmt.Errorf("option %q unknow for loki output", k)
	}

	return nil
}

func init() {
	// register in outputs
	outputs.Add("loki", &Output{})
}
