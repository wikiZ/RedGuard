/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: handle_config.go
 * @Time: 2022/5/5 9:15
 **/

package lib

import (
	"RedGuard/config"
	"RedGuard/core/parameter"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"

	"github.com/go-ini/ini"
)

var (
	_ConfigFilename string     // Config Filename
	logger          = Logger() // logger output model
	//localPath, _  = os.Getwd() // Current project root directory
)

func InitConfig() *ini.File {
	// Check whether the configuration file has been created
	cfg, err := ini.Load(_ConfigFilename) // Loading a Configuration File
	// Check whether loading failed
	if err != nil {
		logger.Errorf("Fail to read file: %v", err)
		os.Exit(0)
	}
	// return *ini.File object
	return cfg
}

func CreateConfig(C2Server string, ConfigPath string) (int, bool) {
	currentUser, _ := user.Current() // Current operating system user directory
	_ConfigFilename = fmt.Sprintf("%s/.RedGuard_%s.ini", currentUser.HomeDir, C2Server)
	// Verify that the configuration file is customized
	if file, _ := ioutil.ReadFile(ConfigPath); len(file) != 0 {
		_ConfigFilename = ConfigPath // Configuration file using a custom path
	}
	// Check whether the current operating system user directory configuration file exists
	if _, err := os.Stat(_ConfigFilename); err == nil || os.IsExist(err) {
		return 0, true
	}
	destination, err := os.Create(_ConfigFilename) // Operating system user directory location
	_, _ = destination.WriteString(config.RedGuardConfig)
	defer func(destination *os.File) {
		_ = destination.Close() // close destination File
	}(destination)
	logger.Notice("RedGuard initialization is complete!")
	logger.Noticef("RedGuard config path is: %s", _ConfigFilename)
	return 1, err == nil
}

// WriteConfig Write data to config file
func WriteConfig(section, key, value string, cfg *ini.File) bool {
	cfg.Section(section).Key(key).SetValue(value)
	if err := cfg.SaveTo(_ConfigFilename); err != nil {
		return false
	}
	return true
}

// ReadConfig Return Field data specified in the configuration file
func ReadConfig(section, key string, cfg *ini.File) string {
	return cfg.Section(section).Key(key).String()
}

// UpdateConfig Modify the content of the configuration file
// Oh, my God, this is not elegant!
func UpdateConfig(cert *parameter.Cert, proxy *parameter.Proxy) {
	var (
		_certList = map[string]string{
			"Locality": cert.Locality, "Country": cert.Country, "Organization": cert.Organization,
			"CommonName": cert.CommonName, "DNSName": cert.DNSNameTo, "HasCert": cert.HasCert,
		}
		_proxyLIst = map[string]string{
			"Port_HTTP": proxy.HTTPort, "Port_HTTPS": proxy.HTTPSPort, "Redirect": proxy.Redirect,
			"AllowIP": proxy.AllowIP, "AllowTime": proxy.AllowTime, "AllowLocation": proxy.AllowLocation,
			"drop_action": proxy.DropAction, "HostTarget": proxy.HostTarget, "MalleableFile": proxy.MalleableFile,
			"EdgeHost": proxy.EdgeHost, "EdgeTarget": proxy.EdgeTarget,
		}
		cfg = InitConfig()
	)
	// re cert Write Config
	for k, v := range _certList {
		WriteConfig("cert", k, v, cfg)
	}
	// re proxy Write Config
	for k, v := range _proxyLIst {
		WriteConfig("proxy", k, v, cfg)
	}
}
