/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: ProxyFilter.go
 * @Time: 2022/5/5 19:17
 **/

package core

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"RedGuard/data"
	"RedGuard/lib"

	parser "github.com/D00Movenok/goMalleable"
	"github.com/sleeyax/ja3rp/net/http"
	"github.com/wxnacy/wgo/arrays"
)

type malleableC2 struct {
	getParamUri    []string // profile get request uri
	postParamUri   []string // profile post request uri
	headerParam    []string // profile HTTP requests header
	reqHeaderParam []string // Header of an HTTP request
}

var _ip string

// isNetworkSegment returns true if The request must be on the same network segment
// @param	ip      string    Request IP
// @param	cidr    string    Network Segment
func isNetworkSegment(ip, cidr string) bool {
	ipAddr := strings.Split(ip, `.`)
	if len(ipAddr) < 4 {
		return false
	}
	cidrArr := strings.Split(cidr, `/`)
	if len(cidrArr) < 2 {
		return false
	}
	var tmp = make([]string, 0)
	for key, value := range strings.Split(`255.255.255.0`, `.`) {
		valueInt, _ := strconv.Atoi(value)
		ipAddrInt, _ := strconv.Atoi(ipAddr[key])
		tmp = append(tmp, strconv.Itoa(valueInt&ipAddrInt))
	}
	return strings.Join(tmp, `.`) == cidrArr[0]
}

// MalleableFilter returns true if The configuration required by Malleable Profile is met
// @param	file    string    Malleable profile path
// @param	req	    string    req *http.Request
func MalleableFilter(file string, req *http.Request) (isFilter bool) {
	malleable := malleableC2{}
	f, _ := ioutil.ReadFile(file)        // Obtain the profile content
	parsed, _ := parser.Parse(string(f)) // goMalleable analysis
	// Parse the GET Requests URI in the profile
	for _, get := range parsed.HttpGet {
		malleable.getParamUri = strings.Split(get.Params["uri"], " ")
	}
	// Parse the POST Requests URI in the profile
	for _, post := range parsed.HttpPost {
		malleable.postParamUri = strings.Split(post.Params["uri"], " ")
	}
	// Parse the headers of the request traffic in the profile
	// TODO: I don't think I implemented POST validation, right?
	for _, j := range parsed.HttpGet {
		for _, i := range j.Client.Headers {
			malleable.headerParam = append(malleable.headerParam, i[1]) // Gets the Malleable Profile header
			// Check whether the request has header information for the response
			if req.Header.Get(i[0]) != "" {
				malleable.reqHeaderParam = append(malleable.reqHeaderParam, req.Header.Get(i[0]))
			}
		}
	}
	// Check whether the requested URL path meets requirements
	// Check that the requested UserAgent meets the requirements
	// Check that the requested Header meets the requirements
	if (len(malleable.postParamUri) > 1 || len(malleable.getParamUri) > 1) && arrays.ContainsString(malleable.getParamUri, req.RequestURI) == -1 && arrays.ContainsString(malleable.postParamUri, req.RequestURI) == -1 {
		logger.Errorf("[DROP] %s Requested URI does not comply with Malleable Profile requirements", _ip)
		return false
	} else if ua := parsed.Globals["useragent"]; req.UserAgent() != ua && ua != "" {
		logger.Errorf("[DROP] %s Requested UserAgent does not meet the Malleable Profile requirements", _ip)
		return false
	} else if len(malleable.reqHeaderParam) >= 1 && len(malleable.headerParam) >= 1 {
		// Traverse the target request header slice
		for _, reqHeader := range malleable.reqHeaderParam {
			var num int // Exception counter
			// Traverse the target profile requirements header slice
			for _, profileHeader := range malleable.headerParam {
				if strings.ToLower(reqHeader) != strings.ToLower(profileHeader) {
					continue
				}
				num += 1 // The same header exists
			}
			// No identical header exists
			if num == 0 {
				logger.Errorf("[DROP] %s Requested Header does not match the Malleable Profile requirements", _ip)
				return false
			}
		}
	}
	// TODO: More rules will be added to profile filtering in the future
	return true
}

func ProxyFilterManger(req *http.Request) (status bool) {
	// The IP address that requests to go online
	var (
		cfg           = lib.InitConfig()
		ip            = lib.ConvertIP(req.RemoteAddr)
		allowLocation = lib.ReadConfig("proxy", "AllowLocation", cfg) // Obtain the location of the host that is allowed to go online
		allowIP       = lib.ReadConfig("proxy", "AllowIP", cfg)       // Obtain the online IP address whitelist
		allowTime     = lib.ReadConfig("proxy", "AllowTime", cfg)     // Gets the allowed online time in the configuration file
		malleableFile = lib.ReadConfig("proxy", "MalleableFile", cfg) // Obtain the profile path
		banIP         = data.BANIP
	)
	// Check whether ban ip is matched
	for _, banAddr := range strings.Split(banIP, "\n") {
		// Check whether the requested IP address is in the correct IP address format or network segment format
		if _, _, err := net.ParseCIDR(banAddr); err == nil || net.ParseIP(banAddr) != nil {
			// Check whether the requested IP address exists in the blacklist
			if banAddr == ip || isNetworkSegment(ip, banAddr) {
				logger.Errorf("[DROP] %s Requested IP is forbidden to access", ip)
				return false
			}
		}
	}
	// Check the location of the requested IP address
	if allowLocation != "" && allowLocation != "*" {
		// @param	allowLocation	string  The territory that is allowed to go online
		// @param	ip	  			string  The IP address from which the request is made
		if !IPLookUp(allowLocation, ip) {
			logger.Errorf("[DROP] %s Does not meet the allowed online geographical restrictions", ip)
			return false
		}
	}
	// Check whitelist filtering rules
	if allowIP != "" && allowIP != "*" {
		// @param	allowIP	  string  allowed Online whitelist
		// @param	ip	  	  string  The IP address from which the request is made
		if !strings.Contains(allowIP, ip) {
			logger.Errorf("[DROP] %s request online IP address is not whitelisted", ip)
			return false
		}
	}
	// Check that the request conforms to the time allowed to go online
	if allowTime != "" && allowTime != "*" {
		// The time range set in the split profile
		num := strings.Split(allowTime, "-")
		afterTime, _ := time.Parse("15:04", strings.TrimSpace(num[0]))  // The amount of time afterTime is allowed to live
		beforeTime, _ := time.Parse("15:04", strings.TrimSpace(num[1])) // The amount of time before Time is allowed to live
		// now time format "15:00"
		nowTime, _ := time.Parse("15:04", strings.TrimSpace(fmt.Sprintf("%d:%d", time.Now().Hour(), time.Now().Minute())))
		if nowTime.After(afterTime) && nowTime.Before(beforeTime) {
		} else {
			logger.Errorf("[DROP] %s Requests are made during prohibited periods of time", ip)
			return false
		}
	}
	// Check whether the malleable profile configuration is correct
	if malleableFile != "" && malleableFile != "*" {
		return MalleableFilter(malleableFile /* malleable profile path */, req)
	}
	return true
}
