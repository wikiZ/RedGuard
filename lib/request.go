/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: request.go
 * @Time: 2022/5/5 9:08
 **/

package lib

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/axgle/mahonia"
	"github.com/go-resty/resty/v2"
)

const USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"

// HTTPRequest	HTTP request and gets the response status and the body
// @param		url			string		The URL to request
// @return		respBody	string		HTTP response Body
// @return		status		int			HTTP response status
func HTTPRequest(url string) (status int, respBody string) {
	client := resty.New()
	// The HTTP request timed out for 8 seconds
	client.SetTimeout(8 * time.Minute)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}) // disable security check (https)
	// HTTP request header information
	client.Header = http.Header{
		"User-Agent": {USERAGENT},
		"Accept":     {"text/html, application/xhtml+xml, image/jxr, */*"},
		"RedGuard":   {"True"},
		"charset":    {"UTF-8"},
	}
	resp, err := client.R().
		EnableTrace(). // the Resty client trace for the requests fired
		Get(url)       // HTTP GET requests
	// Check whether the HTTP URL request succeeds
	if err != nil {
		return
	}
	// return HTTP response StatusCode
	return resp.StatusCode(),
		// return response body data
		strings.TrimSpace(mahonia.NewDecoder("gbk").ConvertString(string(resp.Body())))
}
