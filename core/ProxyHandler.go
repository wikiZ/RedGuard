/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: ProxyHandler.go
 * @Time: 2022/5/5 16:53
 **/

package core

import (
	"RedGuard/lib"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"

	"github.com/wxnacy/wgo/arrays"
)

var (
	_addressArray []string                                  // By request list
	_startUp      sync.Mutex                                // mutex lock
	_hostProxy    = make(map[string]*httputil.ReverseProxy) // Used to cache httputil.ReverseProxy
)

type baseHandle struct{}

func NewProxy(proxyURL string, dropType bool) (*httputil.ReverseProxy, error) {
	destinationURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(destinationURL)
	// dropType Check whether the response to the request is changed
	if dropType {
		proxy.ModifyResponse = modifyResponse() // Modifies the response to the request
	}
	return proxy, nil
}

func modifyResponse() func(*http.Response) error {
	return func(resp *http.Response) error {
		defer func(Body io.ReadCloser) {
			_ = Body.Close() // Direct shutdown response
		}(resp.Body)
		return nil
	}
}

// ProxyRequestHandler A reverse proxy processes HTTP requests
func (h *baseHandle) ServeHTTP(write http.ResponseWriter, req *http.Request) {
	host := &req.Host
	// Obtain the domain name and target map
	hostTarget := lib.JsonToMap(lib.ReadConfig(
		"proxy",
		"HostTarget",
		lib.InitConfig()),
	)
	// Determine the URL to be redirected to
	redirectURL := lib.ReadConfig("proxy", "Redirect", lib.InitConfig())
	// Read the configuration file to check whether DROP is enabled
	isDrop, _ := strconv.ParseBool(lib.ReadConfig("proxy", "DROP", lib.InitConfig()))
	ip := lib.ConvertIP(req.RemoteAddr) // IP address of the host that initiates the request
	// Check whether the host is verified
	if IPHash := lib.EncodeMD5(ip); arrays.ContainsString(_addressArray, IPHash) == -1 {
		logger.Noticef("[REQUEST] %s %s", req.Method, req.RequestURI)
		// Request filtering method
		if !ProxyFilterManger(req) {
			goto LOOK // Redirect to the specified site
		}
		logger.Noticef("[REQUEST] %s - %s", ip, req.UserAgent())
		_addressArray = append(_addressArray, IPHash) // Add to the list after verification for the first time
	}
	// Fetch directly from cache
	if fn, ok := _hostProxy[*host]; ok {
		fn.ServeHTTP(write, req)
		return
	}
	// Check whether the domain name is in the whitelist
	if target, ok := hostTarget[*host]; ok {
		proxy, err := NewProxy(target, false)
		if err != nil {
			logger.Error("Proxy Exception")
		}
		_hostProxy[*host] = proxy // Into the cache
		proxy.ServeHTTP(write, req)
		return
	}

LOOK:
	req.URL.Path = "/" // Url rewriting
	// condition is not met, the element is removed from the slice
	// Output The URL of each request for this IP address
	if len(_addressArray) > 0 {
		_addressArray = _addressArray[:len(_addressArray)-1]
	}
	// Determine whether to redirect or intercept intercepted traffic
	proxy, _ := NewProxy(redirectURL, isDrop)
	// TODO: Maybe we need a little optimization here, right?
	if isDrop {
		// DROP Request
		logger.Alertf("[DROP] Source IP: %s", ip)
	} else {
		// REDIRECT Request
		logger.Alertf("[REDIRECT] Source IP: %s -> Destination Site: %s", ip, redirectURL)
	}
	// Unauthorized access is redirected to the specified URL
	proxy.ServeHTTP(write, req)
}

// ProxyManger Initialize the reverse proxy and pass in the address of the real back-end service
// handle all requests to your server using the proxy
// @param	action	  string	reverse proxy listening port type
// @param	port	  string	reverse proxy listening port
// @param	pattern	  string	pattern associated with the listening port type
func ProxyManger(action, port, pattern string) {
	_startUp.Lock() // 我知道这可能是一个bug哈哈哈，但是它可能不影响什么，就不修了。
	handle := &baseHandle{}
	http.Handle(pattern, handle)
	// Cancels the validity verification of the destination TLS certificate
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	server := &http.Server{
		Addr:    port,   // proxy port
		Handler: handle, // Cache structure
	}
	logger.Warningf("Proxy Listen Port %s (%s)", port, action)
	_startUp.Unlock()
	if action == "HTTPS" {
		// HTTPS reverse proxy
		_ = server.ListenAndServeTLS(
			"cert-rsa/ca.crt", // rsa cert crt
			"cert-rsa/ca.key", // rsa cert key
		)
	} else {
		_ = server.ListenAndServe() // HTTP reverse proxy
	}
}
