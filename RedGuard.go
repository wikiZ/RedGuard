/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: RedGuard.go
 * @Time: 2022/5/4 10:44
 **/

package main

import (
	"fmt"
	"os"
	"strings"

	"RedGuard/config"
	"RedGuard/core"
	"RedGuard/core/parameter"
	"RedGuard/lib"
)

var logger = lib.Logger() // logger output model

type C2 struct {
	Type string //Server interface{}
}

type c2Action interface {
	serverInit()
}

type cobaltStrike struct {
	action string
}

// ServerInit CobaltStrike module core method entry
func (cs *cobaltStrike) serverInit() {
	cs.action = "CobaltStrike"
	var (
		proxy parameter.ProxyConf // Proxy configuration structure
		cfg   = lib.InitConfig()  // config file object
		num   int                 // counting variable
	)
	// HTTPS Reverse proxy SSL certificate is created
	lib.InitGenerateSelfSignedCert()
	for key, value := range map[string]string{
		"HTTPS": "/",
		"HTTP":  "/http",
	} {
		proxy.Action = key    // Gets the reverse proxy listening port type
		proxy.Pattern = value // Gets the pattern associated with the listening type
		proxy.Port = lib.ReadConfig("proxy", fmt.Sprintf("Port_%s", key), cfg)
		// When num is greater than 0, the main program is called out of the loop
		if num > 0 {
			break
		}
		num += 1
		logger.Noticef("HostTarget: %s", lib.ReadConfig("proxy", "HostTarget", cfg))
		// HTTP reverse proxy
		go core.ProxyManger(proxy.Action, proxy.Port, proxy.Pattern)
	}
	// HTTPS reverse proxy
	core.ProxyManger(proxy.Action, proxy.Port, proxy.Pattern)
	// TODO CobaltStrike Core flow control method
}

func (c2 C2) configInit(args *parameter.Parses) {
	c2.Type = args.C2Type
	// Check C2 Server type
	switch strings.ToLower(c2.Type) {
	case "cobaltstrike":
		// CobaltStrike Server initialize method
		(&cobaltStrike{}).serverInit()
	}
	// TODO:Development Pending for other C2 frameworks
}

func main() {
	fmt.Println(fmt.Sprintf(config.BANNER, config.VERSION, config.URL)) // output banner information.
	// Create the tool argument
	var (
		parse  parameter.Parses // Basic parameter structure
		cert   parameter.Cert   // Certificate configuration parameter structure
		_proxy parameter.Proxy  // Proxy configuration parameter structure
	)
	core.CmdParse(&parse, &cert, &_proxy)
	// Check whether RedGuard has been initialized
	if num, isExits := lib.CreateConfig(parse.C2Type /* C2 Facility Type */, parse.ConfigPath); isExits {
		switch {
		case parse.Update:
			lib.UpdateConfig(&cert, &_proxy) // Update RedGuard Config
			logger.Notice("RedGuard Configuration file updated successfully!")
		case parse.IP != "":
			if lib.CheckIP(parse.IP) == false {
				logger.Warning("Please enter a valid IP address")
				os.Exit(0)
			}
			logger.Noticef("Search ipLookUpHelper: %s", parse.IP)
			core.IPLookUp(parse.Location /* owning place to be verified */, parse.IP) // Query the location of an IP address
		case num == 0:
			// Select different C2 Server modes based on user parameters,default CobaltStrike.
			(C2{}).configInit(&parse)
		case num == 1: // Initialization is run for the first time
			os.Exit(0)
		}
	}
}
