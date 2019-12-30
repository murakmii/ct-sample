package util

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"path"
	"strconv"
)

type (
	Logs interface {
		FindByLogID(logID string) (*Log, error)
	}

	Log struct {
		operator    string
		description string
		id          string
		key         []byte
		url         *url.URL
	}

	logsImpl struct {
		operators []operator
	}

	logList struct {
		Operators []operator `json:"operators"`
	}

	operator struct {
		Name string `json:"name"`
		Logs []log  `json:"logs"`
	}

	log struct {
		Description string `json:"description"`
		ID          string `json:"log_id"`
		Key         []byte `json:"key"`
		URL         string `json:"url"`
	}
)

var (
	defaultLogListURL = "https://www.gstatic.com/ct/log_list/v2/log_list.json"

	ErrNoLog = fmt.Errorf("no log")
)

func NewLogs(logListURL *string) (Logs, error) {
	if logListURL == nil {
		logListURL = &defaultLogListURL
	}

	list := &logList{}
	if err := GetAsJson(*logListURL, list); err != nil {
		return nil, fmt.Errorf("can't load log list: %v", err)
	}

	return &logsImpl{operators: list.Operators}, nil
}

func (logs *logsImpl) FindByLogID(logID string) (*Log, error) {
	for _, op := range logs.operators {
		for _, log := range op.Logs {
			if log.ID == logID {
				logURL, err := url.Parse(log.URL)
				if err != nil {
					return nil, err
				}

				return &Log{
					operator:    op.Name,
					description: log.Description,
					id:          log.ID,
					key:         log.Key,
					url:         logURL,
				}, nil
			}
		}
	}

	return nil, ErrNoLog
}

func (log *Log) Operator() string {
	return log.operator
}

func (log *Log) Description() string {
	return log.description
}

func (log *Log) GetSTHURL() string {
	return log.generateEndpointURL("/ct/v1/get-sth", nil)
}

func (log *Log) GetEntriesURL(start, end uint64) string {
	return log.generateEndpointURL("/ct/v1/get-entries", map[string]string{
		"start": strconv.FormatUint(start, 10),
		"end":   strconv.FormatUint(end, 10),
	})
}

// NOTE: この関数は同人誌では「Certificate Transparency in Action」中では紹介していない
func (log *Log) GetProofByHashURL() string {
	return log.generateEndpointURL("/ct/v1/get-proof-by-hash", nil)
}

func (log *Log) PublicKey() (interface{}, error) {
	return x509.ParsePKIXPublicKey(log.key)
}

func (log *Log) generateEndpointURL(endpoint string, query map[string]string) string {
	values := log.url.Query()
	if query != nil {
		for k, v := range query {
			values.Add(k, v)
		}
	}

	generated := &url.URL{
		Scheme:   log.url.Scheme,
		Opaque:   log.url.Opaque,
		User:     log.url.User,
		Host:     log.url.Host,
		Path:     path.Join(log.url.Path, endpoint),
		RawQuery: values.Encode(),
		Fragment: log.url.Fragment,
	}

	return generated.String()
}
