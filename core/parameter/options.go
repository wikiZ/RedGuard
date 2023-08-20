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
	EdgeHost      string
	EdgeTarget    string
	DelHeader     string
}

// ProxyConf Reverse proxy configuration structure
type ProxyConf struct {
	Port    string
	Action  string
	Pattern string
}

// SampleFinger Set listener fingerprint identification rules
// example [Accept-Finger: 866e5289337ab033f89bc57c5274c7ca]
type SampleFinger struct {
	FieldName   string // Set the name of the HTTP Header identification field
	FieldFinger string
}
