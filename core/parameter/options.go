/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: options.go
 * @Time: 2022/5/5 9:44
 **/

package parameter

type Parses struct {
	Update   bool
	C2Type   string
	IP       string
	Location string
}

type Cert struct {
	Country      string
	CommonName   string
	Locality     string
	Organization string
	DNSNameTo    string
	DNSName      []string
}

type Proxy struct {
	HostTarget    string
	HTTPSPort     string
	HTTPort       string
	DROP          string
	Redirect      string
	AllowLocation string
	AllowIP       string
	AllowTime     string
	MalleableFile string
}

// ProxyConf Reverse proxy configuration structure
type ProxyConf struct {
	Port    string
	Action  string
	Pattern string
}
