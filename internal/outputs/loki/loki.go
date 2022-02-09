package loki

import (
	"bytes"
	"context"
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
	
	Options:
		- "loki:url:<url>": loki URL to ship logs to
		- "loki:user:<str>": loki username for basic auth
		- "loki:pass:<str>": loki password for basic auth
		- "loki:xorgid:<id>": X-Org-ID header to add to loki queries (e.g. tenant)
		- "loki:label:<key>=<value>[,<key>=<value>...]": additional labels for log entries
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
	json := `{"streams": [{ "stream": { `

	for k, v := range l.labels {
		json = fmt.Sprintf(`%s "%s": "%s",`, json, k, v)
	}

	// add labels for connection
	json = fmt.Sprintf(`%s "%s": "%s",`, json, "destip", e.DestIP)
	json = fmt.Sprintf(`%s "%s": "%d",`, json, "destport", e.DestPort)
	json = fmt.Sprintf(`%s "%s": "%s",`, json, "process", e.Proc.Name)
	json = fmt.Sprintf(`%s "%s": "%s",`, json, "user", e.Proc.User)

	host, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[loki] error getting hostname request: %v\n", err)
	}
	json = fmt.Sprintf(`%s "%s": "%s",`, json, "host", host)

	// Remove last extraneous comma
	json = strings.TrimRight(json, ",")

	// add timestamp and message
	// may be add some infor about parent process ? or in tags ?
	// having logs to read (beides labels) is also nice
	json = fmt.Sprintf(`%s  }, "values": [ [ "%d", "%s" ] ] }]}`, json, time.Now().UTC().UnixNano(), "egress detected")

	// fmt.Println(json)
	req, err := http.NewRequest(http.MethodPost, l.url+"/loki/api/v1/push", bytes.NewBuffer([]byte(json)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[loki] error building request: %v\n", err)
	}

	if l.user != "" {
		req.SetBasicAuth(l.user, l.pass)
	}
	if l.xorgid != "" {
		req.Header.Add("X-Org-ID", l.xorgid)
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
		fmt.Fprintf(os.Stderr, "[loki] request body was: %q\n", json)
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
		l.user = v
	case "xorgid":
		l.user = v
	case "label":
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
