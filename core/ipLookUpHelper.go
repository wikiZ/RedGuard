/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: ipLookUp.go
 * @Time: 2022/5/5 9:13
 **/

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"RedGuard/lib"

	"github.com/tidwall/gjson"
)

// IPLookup IP origin,API is defined to extract relevant information
type ipLookup struct {
	allowStatus int    // API http request status code
	hasCount    int    // Check if the first character of location is in English
	body        string // Get THE API response body JSON data
	Tag         string // The json data Tag
	location    string // Restrict the geographical location of the online
}

var (
	_apiUrl = []string{
		// Chinese Users IP API
		"https://sp0.baidu.com/8aQDcjqpAAV3otqbppnN2DJv/api.php?query=%s&co=&resource_id=6006",
		// IP API for users in other countries
		"https://ipapi.co/%s/json/",
	}
	logger = lib.Logger() // logger output model
)

// IPLookUp returns true if Check whether the IP address is the same as the owning place
// @param	ip	  		  string	Specify IP address
// @param	location	  string	Specify location
// NOTE: 	other countries Server You are advised to set location to English
// This will prioritize IP API that are more efficient for you
func IPLookUp(location, ip string) (state bool) {
	var IPLook ipLookup
	for _, url := range _apiUrl {
		// Check preferentially invoked
		if IPLook.hasCount != 1 {
			// Check that the first character of location is in English
			if regexp.MustCompile("[a-zA-Z]").MatchString(location[0:1]) {
				// Other countries IP API are preferentially invoked if conditions are met
				url, IPLook.hasCount = _apiUrl[1], 1
			}
		} else {
			url = _apiUrl[0] // preferentially invoked Chinese Users IP API
		}

		// Get json data for the IP API response body
		IPLook.allowStatus, IPLook.body = lib.HTTPRequest(fmt.Sprintf(url, ip))
		if IPLook.allowStatus == 200 {
			// Select the response JSON tag when json data is available
			if url == _apiUrl[0] {
				IPLook.Tag = `data.#.location` // Chinese Users IP API Tag
				break
			}
			IPLook.Tag = `city`
			IPLook.location += gjson.Get(IPLook.body, `region`).String()
			break
		}
	}
	// Check for valid JSON data
	if gjson.Valid(IPLook.body) {
		// Extracting JSON data
		result := gjson.Get(IPLook.body, IPLook.Tag)
		if result.Exists() {
			for _, name := range result.Array() {
				IPLook.location += name.String()
			}
			var prettyJSON bytes.Buffer
			// Format output JSON data
			_ = json.Indent(&prettyJSON, []byte(IPLook.body), "", "\t")
			logger.Emergency(string(prettyJSON.Bytes()))
			// Check whether the IP address is the same as the specified location
			for _, location := range strings.Split(location, ",") {
				if strings.Contains(strings.ToLower(IPLook.location), strings.ToLower(location)) {
					return true // The query result is true
				}
			}
		}
	}
	return false
}
