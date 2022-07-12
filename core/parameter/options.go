/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: options.go
 * @Time: 2022/5/5 9:44
 **/

package parameter

type Parses struct {
	Update     bool
	IP         string
	C2Type     string
	Location   string
	ConfigPath string
}

type Cert struct {
	Country      string
	CommonName   string
	Locality     string
	Organization string
	DNSNameTo    string
	HasCert      string
	DNSName      []string
}

type Proxy struct {
	HostTarget    string
	HTTPSPort     string
	HTTPort       string
	DropAction    string
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
