/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: arguments.go
 * @Time: 2022/5/5 9:46
 **/

package core

import (
	"flag"

	"RedGuard/core/parameter"
)

func CmdParse(parse *parameter.Parses, cert *parameter.Cert, proxy *parameter.Proxy) {
	flag.BoolVar(&parse.Update, "u", false, `Enable configuration file modification`)
	flag.StringVar(&parse.C2Type, "type", `CobaltStrike`, `C2 Server Type`)
	flag.StringVar(&parse.IP, "ip", ``, `IPLookUP IP`)
	flag.StringVar(&parse.ConfigPath, "config", ``, `Set Config Path`)
	flag.StringVar(&parse.Location, "location", `风起`, `IPLookUP Location`)
	flag.StringVar(&cert.Country, "country", `CN`, `Cert Country`)
	flag.StringVar(&cert.CommonName, "common", `*.aliyun.com`, `Cert CommonName`)
	flag.StringVar(&cert.Organization, "organization", `Alibaba (China) Technology Co., Ltd.`, `Cert Organization`)
	flag.StringVar(&cert.HasCert, "HasCert", `true`, `Whether to use the certificate you have applied for`)
	flag.StringVar(&cert.DNSNameTo, "dns", `*.aliyun.com,manager.channel.aliyun.com,*.acs-internal.aliyuncs.com",*.connect.aliyun.com,aliyun.com,whois.www.net.cn,tianchi-global.com`, `Cert DNSName`)
	flag.StringVar(&cert.Locality, "locality", `HangZhou`, `Cert Locality`)
	flag.StringVar(&proxy.HostTarget, "host", `{"360.net":"http://127.0.0.1:8080","360.com":"https://127.0.0.1:4433"}`, `Set Proxy HostTarget`)
	flag.StringVar(&proxy.HTTPSPort, "https", `:443`, `Set Proxy HTTPS Port`)
	flag.StringVar(&proxy.HTTPort, "http", `:80`, `Set Proxy HTTP Port`)
	flag.StringVar(&proxy.DropAction, "DropAction", "redirect", `RedGuard interception action`)
	flag.StringVar(&proxy.Redirect, "redirect", `https://360.net`, `Proxy redirect URL`)
	flag.StringVar(&proxy.AllowLocation, "allowLocation", "*", "Proxy Requests Allow Location")
	flag.StringVar(&proxy.AllowIP, "allowIP", "*", "Proxy Requests Allow IP")
	flag.StringVar(&proxy.AllowTime, "allowTime", "*", "Proxy Requests Allow Time")
	flag.StringVar(&proxy.MalleableFile, "malleable", "*", "Set Proxy Requests Filter Malleable File")
	flag.Parse()
}
