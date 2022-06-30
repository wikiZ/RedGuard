/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: ProxyHandler.go
 * @Time: 2022/5/5 16:53
 **/

package core

import (
	"io"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"RedGuard/lib"

	"github.com/sleeyax/ja3rp/crypto/tls"
	"github.com/sleeyax/ja3rp/net/http"
	"github.com/sleeyax/ja3rp/net/http/httputil"
	"github.com/wxnacy/wgo/arrays"
)

var (
	ip            string                                    // HTTP remote IP
	redirectURL   string                                    // Proxy redirect URL
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
	proxy.ModifyResponse = modifyResponse(dropType) // Modifies the response to the request
	return proxy, nil
}

func modifyResponse(drop bool) func(*http.Response) error {
	return func(resp *http.Response) error {
		defer func(Body io.ReadCloser) {
			logger.Warningf("[RESPONSE] HTTP %s, length: %d", resp.Status, resp.ContentLength)
			if drop {
				// DROP Request
				logger.Alertf("[DROP] Source IP: %s", ip)
				_ = Body.Close() // Direct shutdown response
				return
			}
		}(resp.Body)
		return nil
	}
}

// ProxyRequestHandler A reverse proxy processes HTTP requests
func (h *baseHandle) ServeHTTP(write http.ResponseWriter, req *http.Request) {
	var (
		host = &req.Host
		cfg  = lib.InitConfig() // config file object
		// Obtain the domain name and target map
		hostTarget = lib.JsonToMap(lib.ReadConfig(
			"proxy",
			"HostTarget",
			cfg),
		)
		// Read the configuration file to check whether DROP is enabled
		dropAction = lib.ReadConfig("proxy", "drop_action", cfg)
		// IP address of the host that initiates the request
	)
	var isDrop bool
	var proxy *httputil.ReverseProxy
	// Determine the URL to be redirected to
	redirectURL = lib.ReadConfig("proxy", "Redirect", cfg)
	ip = lib.ConvertIP(req.RemoteAddr)
	// Obtaining the real IP address
	if req.Header.Get("X-Forwarded-For") != "" {
		ip = req.Header.Get("X-Forwarded-For")
	}
	// Check whether the host is verified
	if IPHash := lib.EncodeMD5(req.JA3); arrays.ContainsString(_addressArray, req.JA3) == -1 {
		logger.Noticef("JA3 FingerPrint: %s", IPHash)
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
	// dropAction Select the reverse proxy interception mode
	switch dropAction {
	// redirect
	case "redirect":
		http.Redirect(write, req, redirectURL, http.StatusTemporaryRedirect)
		goto REDIRECT
	// reset Turning off the HTTP response
	case "reset":
		isDrop = true
	// proxy Hijacking target requests response information
	case "proxy":
		break
	}
	// Determine whether to redirect or intercept intercepted traffic
	proxy, _ = NewProxy(redirectURL, isDrop)
	// Unauthorized access is redirected to the specified URL
	proxy.ServeHTTP(write, req)
REDIRECT:
	// REDIRECT Request
	logger.Alertf("[%s] Source IP: %s -> Destination Site: %s", strings.ToUpper(dropAction), ip, redirectURL)
}

// ProxyManger Initialize the reverse proxy and pass in the address of the real back-end service
// handle all requests to your server using the proxy
// @param	action	  string	reverse proxy listening port type
// @param	port	  string	reverse proxy listening port
// @param	pattern	  string	pattern associated with the listening port type
func ProxyManger(action, port, pattern string) {
	var (
		handle        = &baseHandle{}
		config        = &tls.Config{} // Example Initialize TLS config
		_isHasCert, _ = strconv.ParseBool(lib.ReadConfig("cert", "HasCert", lib.InitConfig()))
	)
	_startUp.Lock() // 我知道这可能是一个bug哈哈哈，但是它可能不影响什么，就不修了。
	http.Handle(pattern, handle)
	// Cancels the validity verification of the destination TLS certificate
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	// Disable client connection caching to connection pools
	http.DefaultTransport.(*http.Transport).DisableKeepAlives = true
	rand.Seed(time.Now().UnixNano())
	if !_isHasCert {
		config = &tls.Config{
			// JARM FingerPrint Random
			CipherSuites: lib.MicsSlice([]uint16{
				0x0005, 0x000a, 0x002f,
				0x0035, 0x003c, 0x009c,
				0x009d, 0xc011, 0xc012,
				0xc013, 0xc014, 0xc027,
				0xc02f, 0xc030, 0xcca8,
			}, rand.Intn(2)+1),
		}
	}
	server := &http.Server{
		Addr:         port,   // proxy port
		Handler:      handle, // Cache structure
		TLSConfig:    config, // TLS Server Config
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 1),
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
