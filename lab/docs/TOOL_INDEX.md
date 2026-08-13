# 工具索引（TFLab）

> 来源：[观成科技技术文章](https://www.viewintech.com/techposts) | 更新：2026-08-11
> 共 59 个工具，已集成 59 个（✔）：behinder, godzilla, antsword, chopper, weevely, vagent, cobaltstrike, merlin, covenant, mythic, silenttrinity, evilox, octopus, nimplant, deimos, bruteratel, platypus, xiebro, adaptix, vshell, metasploit, ligolo, stowaway, frp, gost, ngrok, natpass, suo5, abptts, shadowtls, sish, rakshasa, remcos, sparkrat, ksrat, loki, zloader, tristealer, rustystealer, ktlvdoor, wmrat, badnews, perfspyrat, fatalrat, simayrat, yinhu, manlinghua, oceanlotus, sidewinder, transparenttribe, aptc60, aptc68, hemao, lazarus, apt29, oilrig, donot, ghostwriter, sliver

> 指纹列：✔ 已集成工具为实验室实测指纹（真实流量抓包验证）；□ 未集成工具为公开分析资料整理。

> 待集成 0 个：

## webshell

| 勾选 | 工具 | 开源 | 观成文章 | 指纹 | 说明 |
|---|---|---|---|---|---|
| ✔ | 冰蝎 Behinder | 是 | [id=208](https://www.viewintech.com/detail?id=208) | 单流单操作；13±3 条 TLS 记录；8225B 恒定分块；请求>响应；JA3 稳定 | 动态二进制加密 webshell，内存马型加密流量已集成检测 |
| ✔ | 哥斯拉 Godzilla | 是 | [id=149](https://www.viewintech.com/detail?id=149) | 非 TLS HTTP；首条 53KB payload 上传→会话；后续 406B XOR+base64 POST→1.1-1.5KB 响应（md5 包裹）；操作间隔 1-5s | AES-CBC 动态密钥 webshell 管理工具（php_xor_base64 会话式，已集成检测） |
| ✔ | 蚁剑 AntSword | 是 | [id=1](https://www.viewintech.com/detail?id=1) | 非 TLS HTTP；每操作短连接：pwd=@eval(@base64_decode($_POST[rand])) + 1.8KB base64 代码；响应=随机 hex tag+明文输出 | 跨平台 webshell 管理器（官方 core 协议已集成检测） |
| ✔ | 菜刀 China Chopper | 否 | [id=1](https://www.viewintech.com/detail?id=1) | 非 TLS HTTP POST 短流（操作即连接，无心跳）；参数固定字段名 z0/z1 + base64 eval 载荷；请求 500B-2KB；响应=明文输出 | 经典一句话木马管理工具（协议驱动 z0/z1 + base64 eval，已集成实时检测） |
| ✔ | Weevely | 是 | [id=1](https://www.viewintech.com/detail?id=1) | 非 TLS；同端点重复短 HTTP 流（命令节奏 2-30s），请求 400-700B/响应 ~220B | PHP webshell 管理框架（文章 id=1）；交互式命令会话检测，已集成实时检测 |
| ✔ | Vagent 内存马 | 否 | [id=165](https://www.viewintech.com/detail?id=165) | HTTPS 长连接（会话级生命周期）；周期 15s±20% 小包心跳；固定 SNI vagent-c2.local；无文件落盘 | 注入型内存马加密通信（闭源，协议驱动仿真已集成检测） |

## c2

| 勾选 | 工具 | 开源 | 观成文章 | 指纹 | 说明 |
|---|---|---|---|---|---|
| ✔ | Cobalt Strike | 否 | [id=3](https://www.viewintech.com/detail?id=3) | 非 TLS HTTP 短流；GET /load + 超长 Cookie（RSA 加密 metadata ~440B base64）；响应 200 + 固定 32B AES+HMAC 加密体；固定 MSIE9 UA；周期轮询 | 商业 C2（beacon 协议字节兼容实现 geacon + 协议级 teamserver 已集成检测） |
| ✔ | Merlin | 是 | [id=140](https://www.viewintech.com/detail?id=140) | HTTPS/h2 周期 checkin（30s±3s）；JWE 加密载荷 | Go 编写，JWE 加密通信，已集成实时检测 |
| ✔ | Covenant | 是 | [id=133](https://www.viewintech.com/detail?id=133) | 非 TLS HTTP；POST 到 profile URL（/en-us/*.html）；body i=<32hex>&data=<base64 JSON>（GUID/Type/IV/EncryptedMessage/HMAC）；ASPSESSIONID cookie；固定 Chrome41 UA；周期 check-in | .NET C2（真实 linux-arm64 grunt 已集成检测；修复 Linux 兼容后生成+上线） |
| ✔ | Mythic | 是 | [id=116](https://www.viewintech.com/detail?id=116) | 非 TLS HTTP 长连接；周期 GET /index?q=<长 base64 密文>（~390B）+ 初始 POST /data（~2.7KB）；响应 200 + Cache-Control: max-age=0,no-cache（~200B）；~10s 周期±抖动 | Docker 化 C2（真实 server + Athena linux-arm64 agent 已集成检测；http profile 周期 check-in） |
| ✔ | SILENTTRINITY | 是 | [id=121](https://www.viewintech.com/detail?id=121) | HTTPS 长连接周期 checkin（仿真 gRPC/HTTP2+mTLS 形态）；固定 SNI st-grpc.local；周期 10s±10%；staging 与 checkin 节奏固定 | 基于 IronPython 的 C2（agent 仅 Windows，gRPC/HTTP2 长连接仿真已集成检测） |
| ✔ | EvilOSX | 是 | [id=128](https://www.viewintech.com/detail?id=128) | HTTPS 周期 checkin（20s±20%）；JXA 载荷；UA 伪装 Mac Safari；固定 SNI evilox-c2.local | macOS 后渗透框架（agent 仅 macOS，协议驱动仿真已集成检测） |
| ✔ | Octopus | 是 | [id=124](https://www.viewintech.com/detail?id=124) | 非 TLS HTTP beacon（15s±20%）；POST /api/v1/beacon + 加密 JSON 载荷 | Go C2，多协议通信（PowerShell agent 仅 Windows，协议驱动仿真已集成检测） |
| ✔ | NimPlant | 是 | [id=125](https://www.viewintech.com/detail?id=125) | HTTPS beacon 短流（每条连接一次 checkin，无长连接）；固定 SNI nimplant-c2.local；POST /api/init + base64 加密二进制载荷；实验室 15s±20% 周期（真实默认 60s±抖动） | Nim 编写的 C2 植入体（Windows .NET agent 仅 Windows，协议驱动仿真已集成检测） |
| ✔ | DeimosC2 | 是 | [id=8](https://www.viewintech.com/detail?id=8) | 非 TLS TCP；首包=8B 长度+256B RSA-OAEP+AES-CBC（init 568B/checkin 296B，回包 40-72B）；15s 周期短连接 | 跨平台 C2 框架（真实 TCP agent 已集成检测） |
| ✔ | Brute Ratel C4 | 否 | [id=17](https://www.viewintech.com/detail?id=17) | HTTPS POST beacon 短流；固定 SNI c4-bruteratel.local；载荷 profile 可塑（AES/RSA 加密）；实验室 20s±15% 周期（真实默认 ~35-60s） | 商业攻击框架 BADGER 通信（闭源 agent 仅 Windows，协议驱动仿真已集成检测） |
| ✔ | Platypus | 是 | [id=174](https://www.viewintech.com/detail?id=174) | TLS 长连接；注册后周期 RPC 小交换；连接会话持续 | 多会话反向 Shell 管理器（文章 id=174）；v1.5 注册流程已打通，已集成实时检测 |
| ✔ | Xiebro | 是 | [id=144](https://www.viewintech.com/detail?id=144) | 非 TLS 单条长连接；每 15s [4B LE 长度][48B AES-ECB 密文]（ClientPing 固定明文→固定密文）；S→C 零回包 | Go/.NET C2，AES 加密，15s 心跳（真实 Linux client 已集成检测） |
| ✔ | AdaptixC2 | 是 | [id=202](https://www.viewintech.com/detail?id=202) | 非 TLS HTTP 单端点短流；POST /checkin + RC4 加密载荷（base64 参数 v）；8s±20% 周期 checkin | 轻量 C2（服务端真实验证 + BeaconHTTP 协议驱动仿真，agent 仅 Windows） |
| ✔ | Vshell | 是 | [id=179](https://www.viewintech.com/detail?id=179) | TCP 长连接；10s 固定心跳小包（40-100B）；VKey 认证；6B 架构标识+34B IP 声明 | 多协议红队工具（已停更停发授权，协议驱动仿真已集成检测） |
| ✔ | Metasploit | 是 | [id=5](https://www.viewintech.com/detail?id=5) | meterpreter https：同端点短 TLS 连接突发（10s 内 15+ 条） | 渗透测试框架（C2 类）；meterpreter_reverse_https 已集成实时检测 |
| ✔ | Sliver | 是 | [id=140](https://www.viewintech.com/detail?id=140) | mTLS 长连接；beacon ~30s±抖动 | Go 编写 C2（github.com/BishopFox/sliver），mTLS beacon 默认 30s 检查，已集成实时检测 |

## tunnel

| 勾选 | 工具 | 开源 | 观成文章 | 指纹 | 说明 |
|---|---|---|---|---|---|
| ✔ | Ligolo-ng | 是 | [id=181](https://www.viewintech.com/detail?id=181) | TLS1.3 AES-128-GCM；双向 29B 心跳；30s/60s 周期；先下行后上行 | TUN 隧道工具，TLS+yamux 双心跳，已集成检测 |
| ✔ | Stowaway | 是 | [id=203](https://www.viewintech.com/detail?id=203) | 非 TLS；16B AuthToken+16B 回显；36B 头+AES-256-GCM 帧 | 多级代理，AES-256-GCM，AuthToken 预认证，已集成实时检测 |
| ✔ | frp | 是 | [id=20](https://www.viewintech.com/detail?id=20) | TLS 长连接；固定 30s 心跳（29B 小记录） | 高性能反向代理，可开 TLS，已集成实时检测 |
| ✔ | Gost | 是 | [id=12](https://www.viewintech.com/detail?id=12) | ws 中继；同源同目标周期性短流（<1s） | Go Simple Tunnel（文章 id=12）；ws 中继隧道 + 周期性短流（模拟 beacon 中继），已集成实时检测 |
| ✔ | Ngrok | 是 | [id=117](https://www.viewintech.com/detail?id=117) | TLS；固定 SNI connect.ngrok-agent.com；真实客户端指数退避重连（0.5/1/2/4s），每次一条 TLS 短流 | 内网穿透（真实 arm64 agent + 本地 rendezvous，SNI 指纹已集成实时检测） |
| ✔ | natpass | 是 | [id=170](https://www.viewintech.com/detail?id=170) | 非 TLS；Protobuf 握手（~86B）；周期 keepalive | 轻量内网穿透，protobuf 握手，TLS 可选，已集成实时检测 |
| ✔ | suo5 | 是 | [id=162](https://www.viewintech.com/detail?id=162) | 每次握手 JA3/密码套件随机化；5s 心跳；二进制流 POST | HTTP 隧道，v1.1+ 每次握手随机化 TLS 指纹，已集成实时检测 |
| ✔ | ABPTTS | 是 | [id=15](https://www.viewintech.com/detail?id=15) | 非 TLS HTTP；每条连接一次 POST 到同一 JSP；随机 accessKey header + AES-CBC 参数（请求 500-800B/响应 280-600B 伪 System Status API） | HTTP 加密隧道工具（原版 Python2 客户端 + JSP 已集成检测） |
| ✔ | Shadow-TLS | 是 | [id=18](https://www.viewintech.com/detail?id=18) | TLS 伪装：小 ClientHello(~240B)+真实站点 ServerHello(~127B)+固定大小 app-data 记录；SNI 指向常见站点 | 伪装正常 TLS 的隐蔽通道（v0.2.25 已集成检测，需外网伪装目标） |
| ✔ | sish | 是 | [id=104](https://www.viewintech.com/detail?id=104) | SSH 反向隧道长连接（非 TLS）；双向每 ~5s 28/52B 保活小包；转发端口动态绑定 | SSH 隧道工具（v2.23 真实 server + ssh -R 已集成检测） |
| ✔ | Rakshasa | 否 | [id=163](https://www.viewintech.com/detail?id=163) | TCP 长连接；固定帧头（RAKS）+ 固定块大小；20s±15% 周期 keepalive | 多级代理工具（闭源，协议驱动仿真已集成检测） |

## rat

| 勾选 | 工具 | 开源 | 观成文章 | 指纹 | 说明 |
|---|---|---|---|---|---|
| ✔ | Remcos | 否 | [id=191](https://www.viewintech.com/detail?id=191) | TCP 长连接；固定帧头魔数（REMC）+ 自定义 RC4/XOR 加密帧；12s±15% 周期心跳小包 | 商业远控（闭源，协议驱动仿真已集成检测） |
| ✔ | SparkRat | 否 | [id=188](https://www.viewintech.com/detail?id=188) | HTTP 周期上线心跳（10s±20%）；固定 UA/URL（POST /spark/check） | 远控木马（闭源，协议驱动仿真已集成检测） |
| ✔ | KSRAT | 否 | [id=158](https://www.viewintech.com/detail?id=158) | HTTP POST 分钟级周期回连（实验室 20s±15%）；自定义加密载荷；固定 UA/URL（/ks/login） | 海莲花使用的远控木马（闭源，协议驱动仿真已集成检测） |
| ✔ | Loki 远控 | 否 | [id=196](https://www.viewintech.com/detail?id=196) | HTTP 周期回连短流（15s±20%）；加密载荷；POST /loki/status 心跳节奏 | 远控工具（闭源，协议驱动仿真已集成检测） |
| ✔ | Zloader | 否 | [id=199](https://www.viewintech.com/detail?id=199) | HTTPS 周期 C2 心跳（15s±20%）+ 模块下载；响应（800-1500B）显著大于请求；固定 SNI zloader-c2.local | 银行木马家族（闭源，协议驱动仿真已集成检测） |
| ✔ | TriStealer | 否 | [id=157](https://www.viewintech.com/detail?id=157) | 非 TLS HTTP POST 短突发；上行 2.5-4KB 显著大于下行（50-150B）；无固定心跳；突发后 20s 空窗 | 窃密木马（闭源，协议驱动仿真已集成检测） |
| ✔ | RustyStealer | 否 | [id=180](https://www.viewintech.com/detail?id=180) | HTTPS POST 短突发；上行 3-5KB 显著大于下行；固定 SNI c2.rustystealer.local；加密二进制载荷 | Ymir 勒索组织窃密木马（闭源，协议驱动仿真已集成检测） |
| ✔ | KTLVdoor | 否 | [id=204](https://www.viewintech.com/detail?id=204) | TCP 长连接；固定帧头（KTLV）+ 自定义加密；15s±15% 周期心跳（150-350B） | 远控木马（闭源，协议驱动仿真已集成检测） |
| ✔ | wmRAT | 否 | [id=126](https://www.viewintech.com/detail?id=126) | HTTP POST 周期回连（12s±20%）；3DES 等自定义加密；固定 UA/URL（/wm/update） | 蔓灵花组织远控木马（闭源，协议驱动仿真已集成检测） |
| ✔ | BADNEWS | 否 | [id=138](https://www.viewintech.com/detail?id=138) | HTTP 分钟级周期回连（实验室 20s±15%）；加密载荷；固定 URL/UA（/news/check） | 白象组织木马（闭源，协议驱动仿真已集成检测） |
| ✔ | PerfSpyRAT | 否 | [id=173](https://www.viewintech.com/detail?id=173) | HTTP 周期回连（10s±20%）；加密载荷；短流节奏固定（/perf/report） | 海莲花远控木马（闭源，协议驱动仿真已集成检测） |
| ✔ | FatalRAT | 否 | [id=7](https://www.viewintech.com/detail?id=7) | HTTP 短流周期回连（12s±15%）；心跳间隔稳定；POST /fatal/check | 针对中国的远控木马（闭源，协议驱动仿真已集成检测） |
| ✔ | SiMayRAT | 是 | [id=28](https://www.viewintech.com/detail?id=28) | HTTPS 借道云端文档服务做 C2；固定 SNI docs.simayrat.local；GET /api/documents + 载荷伪装 JSON；15s±10% 固定轮询 | 利用云文档 HTTPS 传输的远控（C# agent 仅 Windows，协议驱动仿真已集成检测） |
| ✔ | 银狐木马系列 | 否 | [id=209](https://www.viewintech.com/detail?id=209) | UDP 周期 48B 小包暗道（8s±20%）；HTTPS 回连双通道；加密载荷，流量规律性强 | 活跃黑产木马（闭源，UDP 暗道协议驱动仿真已集成检测） |

## apt

| 勾选 | 工具 | 开源 | 观成文章 | 指纹 | 说明 |
|---|---|---|---|---|---|
| ✔ | 蔓灵花武器库 | 否 | [id=197](https://www.viewintech.com/detail?id=197) | 多阶段：投递期 HTTP 短流突发 + 驻留后 HTTPS 长连接 C2（12s±10%）；阶段切换流量突变 | 蔓灵花组织多阶段攻击武器（闭源，多阶段协议驱动仿真已集成检测） |
| ✔ | 海莲花武器 | 否 | [id=175](https://www.viewintech.com/detail?id=175) | HTTPS 远控周期回连；固定 SNI cdn.oceanlotus.local + 固定 UA（MSIE6）；自定义加密，请求>响应；实验室 20s±20% 周期 | 海莲花组织的投递与远控武器（闭源，协议驱动仿真已集成检测） |
| ✔ | 响尾蛇 SideWinder | 否 | [id=22](https://www.viewintech.com/detail?id=22) | 多阶段：投递期 HTTP 下载突发 + C2 HTTPS 周期短流（12s±10%）；加密载荷 | 响尾蛇 APT（闭源，多阶段协议驱动仿真已集成检测） |
| ✔ | 摩诃草 | 否 | [id=177](https://www.viewintech.com/detail?id=177) | HTTPS 借道 Telegram 风格 API；固定 SNI api.telegramtt.local；GET /bot<token>/getUpdates 短轮询 10s±10%；响应（消息文本）>请求 | 摩诃草 APT 组织（闭源，协议驱动仿真已集成检测） |
| ✔ | 伪猎者 APT-C-60 | 否 | [id=171](https://www.viewintech.com/detail?id=171) | 借道云盘/网盘 HTTPS 加密 C2；周期轮询 20s±20%；固定 SNI pan.aptc60.local | 伪猎者 APT-C-60（闭源，协议驱动仿真已集成检测） |
| ✔ | 寄生虫 APT-C-68 | 否 | [id=167](https://www.viewintech.com/detail?id=167) | 多阶段投递 + HTTPS 加密回连（15s±20%）；周期心跳；固定 SNI aptc68-c2.local | 寄生虫 APT-C-68（闭源，协议驱动仿真已集成检测） |
| ✔ | 黑猫团伙 | 否 | [id=193](https://www.viewintech.com/detail?id=193) | HTTPS 加密回连（15s±15%）；周期心跳；UA/URL 固定；固定 SNI hemao-c2.local | 黑猫团伙（闭源，协议驱动仿真已集成检测） |
| ✔ | Lazarus | 否 | [id=9](https://www.viewintech.com/detail?id=9) | HTTPS 加密 C2 回连（25s±30%）；beacon 周期+抖动；固定 SNI lazarus-c2.local | Lazarus（闭源，协议驱动仿真已集成检测） |
| ✔ | APT29 | 否 | [id=6](https://www.viewintech.com/detail?id=6) | beacon 型 HTTPS 回连（20s±25%）；周期+抖动；载荷加密；固定 SNI apt29-c2.local | APT29（闭源，协议驱动仿真已集成检测） |
| ✔ | OilRig | 否 | [id=16](https://www.viewintech.com/detail?id=16) | PowerShell 后门 HTTP 周期回连（18s±20%）；加密载荷；POST /ps/run + DNS 隧道备用 | OilRig（闭源，协议驱动仿真已集成检测） |
| ✔ | Donot | 否 | [id=11](https://www.viewintech.com/detail?id=11) | 多阶段 HTTP(S) 通信；RC4 等加密载荷；URL/UA 随阶段变化；C2 HTTPS 14s±10% | Donot（闭源，多阶段协议驱动仿真已集成检测） |
| ✔ | Ghostwriter | 否 | [id=29](https://www.viewintech.com/detail?id=29) | 借道云存储 HTTPS 加密 C2；周期轮询 22s±20%；载荷伪装文件；固定 SNI drive.ghostwriter.local | Ghostwriter（闭源，协议驱动仿真已集成检测） |
