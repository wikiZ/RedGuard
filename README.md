<h1 align="center">RedGuard - Excellent C2 Front Flow Control tool</h1>

[![GitHub stars](https://img.shields.io/github/stars/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu) [![GitHub issues](https://img.shields.io/github/issues/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu/issues) [![GitHub release](https://img.shields.io/github/release/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu/releases) [![](https://img.shields.io/badge/author-风起-blueviolet)](https://github.com/wikiZ) 

--------------

English | [中文文档](https://github.com/wikiZ/RedGuard/blob/main/doc/README_CN.md)

# 0x00 Introduction

## Tool introduction

RedGuard is a derivative work of the C2 facility pre-flow control technology. It has a lighter design, efficient flow interaction, and reliable compatibility with go language development. The core problem it solves is also in the face of increasingly complex red and blue attack and defense drills, giving the attack team a better C2 infrastructure concealment scheme, giving the interactive traffic of the C2 facility a flow control function, and intercepting those "malicious" analysis traffic, and better complete the entire attack mission.

RedGuard is a C2 facility pre-flow control tool that can avoid Blue Team, AVS, EDR, Cyberspace Search Engine checks.

## Application scenarios

- During the offensive and defensive drills, the defender analyzes and traces the source of C2 interaction traffic according to the situational awareness platform
- Prevent malicious analysis of Trojan samples in cloud sandbox environment
- Block malicious requests to implement replay attacks and achieve the effect of confusing online
- In the case of specifying the IP of the online server, the request to access the interactive traffic is restricted by means of a whitelist
- Prevent the scanning and identification of C2 facilities by cyberspace mapping technology, and redirect or intercept the traffic of scanning probes
- Supports pre-flow control for multiple C2 servers, and can achieve the effect of domain front-end, load balancing online, and achieve the effect of concealment
- Able to perform regional host online restriction according to the attribution of IP address by requesting IP reverse lookup API interface
- Analyze blue team tracing behavior through interception logs of target requests, which can be used to track peer connection events/issues
- It has the function of customizing the time period for the legal interaction of the sample to realize the function of only conducting traffic interaction during the working time period
- Malleable C2 Profile parser capable of validating inbound HTTP/S requests strictly against malleable profile and dropping outgoing packets in case of violation (supports Malleable Profiles 4.0+)
- Built-in blacklist of IPV4 addresses for a large number of devices, honeypots, and cloud sandboxes associated with security vendors to automatically intercept redirection request traffic
- SSL certificate information and redirect URLs that can interact with samples through custom tools to circumvent the fixed characteristics of tool traffic
- ..........

# 0x01 Install

You can directly download and use the compiled version, or you can download the go package remotely for independent compilation and execution.

```bash
git clone https://github.com/wikiZ/RedGuard.git
cd RedGuard
# You can also use upx to compress the compiled file size
go build -ldflags "-s -w"
# Give the tool executable permission and perform initialization operations
chmod +x ./RedGuard&&./RedGuard

```

# 0x02 Configuration Description

## initialization

As shown in the figure below, first grant executable permissions to RedGuard and perform initialization operations. The first run will generate a configuration file in the current user directory to achieve flexible function configuration. Configuration file name: **.RedGuard_CobaltStrike.ini**.

![1653117445(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521151731-13f938b8-d8d6-1.png)

**Configuration file content:**

![1653117707(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521152151-af330f34-d8d6-1.png)

The configuration options of cert are mainly for the configuration information of the HTTPS traffic exchange certificate between the sample and the C2 front-end facility. The proxy is mainly used to configure the control options in the reverse proxy traffic. The specific use will be explained in detail below.

The SSL certificate used in the traffic interaction will be generated in the cert-rsa/ directory under the directory where RedGuard is executed. You can start and stop the basic functions of the tool by modifying the configuration file **(the serial number of the certificate is generated according to the timestamp , don't worry about being associated with this feature)**.If you want to use your own certificate,Just rename them to ca.crt and ca.key.

```bash
openssl x509 -in ca.crt -noout -text
```

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521153216-23d83cd2-d8d8-1.png)

Random TLS JARM fingerprints are updated each time RedGuard is started to prevent this from being used to authenticate C2 facilities.

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/d2d8d30fcd349bd4567c685aaa93451.jpg)

## RedGuard Usage

```bash
root@VM-4-13-ubuntu:~# ./RedGuard -h

Usage of ./RedGuard:
  -allowIP string
        Proxy Requests Allow IP (default "*")
  -allowLocation string
        Proxy Requests Allow Location (default "*")
  -allowTime string
        Proxy Requests Allow Time (default "*")
  -common string
        Cert CommonName (default "*.aliyun.com")
  -country string
        Cert Country (default "CN")
  -dns string
        Cert DNSName
  -drop string
        Proxy Filter Enable DROP (default "false")
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

**P.S. You can use the parameter command to modify the configuration file. Of course, I think it may be more convenient to modify it manually with vim. **

# 0x03 Tool usage

## basic interception

If you directly access the port of the reverse proxy, the interception rule will be triggered. Here you can see the root directory of the client request through the output log, but because the request process does not carry the requested credentials, that is, the correct HOST request header So the basic interception rule is triggered, and the traffic is redirected to https://360.net

Here, in order to facilitate the display of the output effect, the actual use can be run in the background through `nohup ./RedGuard &`.

![1653130661(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521185753-dd1280a6-d8f4-1.png)

```bash
{"360.net":"http://127.0.0.1:8080","360.com":"https://127.0.0.1:4433"}
```

It is not difficult to see from the above slice that 360.net corresponds to the proxy to the local port 8080, 360.com points to the local port 4433, and corresponds to the difference in the HTTP protocol used. In the subsequent online, you need to pay attention to the protocol of the listener. The type needs to be consistent with the one set here, and set the corresponding HOST request header.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521191828-bd41a344-d8f7-1.png)

As shown in the figure above, in the case of unauthorized access, the response information we get is also the return information of the redirected site.

## interception method

In the above basic interception case, the default interception method is used, that is, the illegal traffic is intercepted by redirection. By modifying the configuration file, we can change the interception method and the redirected site URL. In fact, this The other way is a redirect, which might be more aptly described as hijacking, cloning, since the response status code returned is 200, and the response is taken from another website to mimic the cloned/hijacked website as closely as possible.

Invalid packets can be misrouted according to two strategies:

- **reset**: Terminate the TCP connection immediately.
- **proxy**: Get a response from another website to mimic the cloned/hijacked website as closely as possible.

```bash
# Determines whether to intercept intercepted traffic default false / true
DROP = false
# URL to redirect to
Redirect = https://360.net
```

**Redirect = URL** in the configuration file points to the hijacked URL address. RedGuard supports "hot change", which means that while the tool is running in the background through nohup, we can still modify the configuration file. The content is started and stopped in real time.

```bash
./RedGuard -u --drop true
```

Note that when modifying the configuration file through the command line. The -u option should not be too small, otherwise the configuration file cannot be modified successfully. If you need to restore the default configuration file settings, you only need to enter `./RedGuard -u`.

Another interception method is DROP, which directly closes the HTTP communication response and is enabled by setting **DROP = true**. The specific interception effect is as follows:

![1653132755(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521193245-bc078708-d8f9-1.png)

It can be seen that the C2 pre-flow control directly responds to illegal requests without the HTTP response code. In the detection of cyberspace mapping, the DROP method can achieve the function of hiding the opening of ports. The specific effect can be seen in the following case. analyze.

## Proxy port modification

In fact, it is easy to understand here. The configuration of the following two parameters in the configuration file realizes the effect of changing the reverse proxy port. It is recommended to use the default port on the premise of not conflicting with the current server port. If it must be modified, then pay attention to the **:** of the parameter value not to be missing

```bash
# HTTPS Reverse proxy port
Port_HTTPS = :443
# HTTP Reverse proxy port
Port_HTTP = :80
```

## RedGuard logs

The blue team tracing behavior is analyzed through the interception log of the target request, which can be used to track peer connection events/problems. The log file is generated in the directory where RedGuard is running, **file name: RedGuard.log**.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220523104050-c1c67296-da41-1.png)

## Request geographic restrictions

The configuration method takes AllowLocation = Jinan, Beijing as an example. It is worth noting here that RedGuard provides two APIs for IP attribution anti-check, one for domestic users and the other for overseas users. Dynamically assign which API to use. If the target is in China, enter Chinese for the set region. Otherwise, enter English place names. It is recommended that domestic users use Chinese names. In this way, the accuracy of the attribution found and the response speed of the API are both is the best choice.

P.S. Domestic users, do not use **AllowLocation = Jinan,beijing** this way! It doesn't make much sense, the first character of the parameter value determines which API to use!

```bash
# IP address owning restrictions example:AllowLocation = 山东,上海,杭州 or shanghai,beijing
AllowLocation = *
```

![1653134160(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521195609-00f19fb8-d8fd-1.png)

Before deciding to restrict the region, you can manually query the IP address by the following command.

```bash
./RedGuard --ip 111.14.218.206
./RedGuard --ip 111.14.218.206 --location shandong # Use overseas API to query
```

Here we set to allow only the Shandong region to go online

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521200158-d0d34d6c-d8fd-1.png)

**Legit traffic:**

![1653137496(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521205147-c6bb200a-d904-1.png)

**Illegal request area:**

![1653137621(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521205347-0dbc1efa-d905-1.png)

Regarding the launch of geographical restrictions, it may be more practical in the current offensive and defensive drills. Basically, the targets of provincial and municipal protection network restrictions are in designated areas, and the traffic requested by other areas can naturally be ignored, and the function of RedGuard is Not only can a single region be restricted, but multiple online regions can be restricted based on provinces and cities, and traffic requested by other regions can be intercepted.

## Blocking based on whitelist

In addition to the built-in blacklist of security vendor IPs in RedGuard, we can also restrict according to the whitelist. In fact, I also suggest that when doing web management, we can restrict the addresses of the online IPs according to the whitelist, so as to divide multiple IPs way of address.

```bash
# Whitelist list example: AllowIP = 172.16.1.1,192.168.1.1
AllowIP       = 127.0.0.1
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522133017-43a90ce0-d990-1.png)

As shown in the figure above, we only allow 127.0.0.1 to go online, then the request traffic of other IPs will be intercepted.

## Block based on time period

This function is more interesting. Setting the following parameter values in the configuration file means that the traffic control facility can only go online from 8:00 am to 9:00 pm. The specific application scenario here is that during the specified attack time, we allow communication with C2 Traffic interacts, and remains silent at other times. This also allows the red teams to get a good night's sleep without worrying about some blue team on the night shift being bored to analyze your Trojan and then wake up to something indescribable, hahaha.

```bash
# Limit the time of requests example: AllowTime = 8:00 - 16:00
AllowTime     = 8:00 - 21：00
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522133644-2a6054c2-d991-1.png)

## Malleable Profile

RedGuard uses the Malleable C2 profile. It then parses the provided malleable configuration file section to understand the contract and pass only those inbound requests that satisfy it, while misleading others. Parts such as `http-stager`, `http-get` and `http-post` and their corresponding uris, headers, User-Agent etc. are used to distinguish legitimate beacon requests from irrelevant Internet noise or IR/AV/EDR Out-of-bounds packet.

```bash
# C2 Malleable File Path
MalleableFile = /root/cobaltstrike/Malleable.profile
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522134214-ef2c5ae4-d991-1.png)

The profile written by 风起 is recommended to use:

> https://github.com/wikiZ/CobaltStrike-Malleable-Profile

# 0x04 Case Study

## Cyberspace Search Engine

As shown in the figure below, when our interception rule is set to DROP, the spatial mapping system probe will probe the / directory of our reverse proxy port several times. In theory, the request packet sent by mapping is faked as normal traffic. Show. But after several attempts, because the characteristics of the request packet do not meet the release requirements of RedGuard, they are all responded by Close HTTP. The final effect displayed on the surveying and mapping platform is that the reverse proxy port is not open.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522135625-ea658a42-d993-1.png)

The traffic shown in the figure below means that when the interception rule is set to Redirect, we will find that when the mapping probe receives a response, it will continue to scan our directory. UserAgent is random, which seems to be in line with normal traffic requests, but both successfully blocked.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522140326-e5723b4c-d994-1.png)

**Surveying and mapping platform - effect of redirection interception:**

![1653200439(1).jpg](https://github.com/wikiZ/RedGuardImage/raw/main/20220522142048-526e916c-d997-1.png)

## Domain fronting

RedGuard supports Domain fronting. In my opinion, there are two forms of presentation. One is to use the traditional Domain fronting method, which can be achieved by setting the port of our reverse proxy in the site-wide acceleration back-to-source address. On the original basis, the function of traffic control is added to the domain fronting, and it can be redirected to the specified URL according to the setting we set to make it look more real. It should be noted that the RedGuard setting of the HTTPS HOST header must be consistent with the domain name of the site-wide acceleration.

![1653201007(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522143012-a26ab442-d998-1.png)

In individual combat, I suggest that the above method can be used, and in team tasks, it can also be achieved by self-built "Domain fronting".

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522143837-cf77a944-d999-1.png)

In the self-built Domain fronting, keep multiple reverse proxy ports consistent, and the HOST header consistently points to the real C2 server listening port of the backend. In this way, our real C2 server can be well hidden, and the server of the reverse proxy can only open the proxy port by configuring the firewall.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522144944-5cb4032e-d99b-1.png)

This can be achieved through multiple node servers, and configure multiple IPs of our nodes in the CS listener HTTPS online IP.

## CobaltStrike

If there is a problem with the above method, the actual online C2 server cannot be directly intercepted by the firewall, because the actual load balancing request in the reverse proxy is made by the IP of the cloud server manufacturer.

If it is a single soldier, we can set an interception strategy on the cloud server firewall.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522150356-58b9586c-d99d-1.png)

Then set the address pointed to by the proxy to https://127.0.0.1:4433.

```bash
{"360.net":"http://127.0.0.1:8080","360.com":"https://127.0.0.1:4433"}
```

And because our basic verification is based on the HTTP HOST request header, what we see in the HTTP traffic is also the same as the domain fronting method, but the cost is lower, and only one cloud server is needed.

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522150942-26f6c264-d99e-1.png)

For the listener settings, the online port is set to the RedGuard reverse proxy port, and the listening port is the actual online port of the local machine.

# 0x05 Loading

Thank you for your support. RedGuard will continue to improve and update it. I hope that RedGuard can be known to more security practitioners. The tool refers to the design ideas of RedWarden.

**We welcome everyone to put forward your needs, RedGuard will continue to grow and improve in these needs! **

**About the developer 风起 related articles:https://www.anquanke.com/member.html?memberId=148652**

**Kunyu: https://github.com/knownsec/Kunyu**

> 风起于青萍之末，浪成于微澜之间。


# 0x06 Community

If you have any questions or requirements, you can submit an issue under the project, or contact the tool author by adding WeCat.

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/20220522141706-ce37e178-d996-1.png)
