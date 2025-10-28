#!/usr/bin/env python3
"""
README 文档生成脚本
自动生成网络流量监控工具的详细使用文档（纯文本版本）
"""

import os
import datetime
from pathlib import Path

def generate_readme():
    """生成完整的 README 文档（纯文本版本）"""
    
    # 获取当前日期
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    readme_content = f"""网络流量监控工具 - 详细使用文档

最后更新: {current_date}
版本: 1.0.0
工具类型: 网络监控与分析

目录
1. 工具简介
2. 功能特点
3. 系统要求
4. 安装指南
5. 使用方法
6. 参数详解
7. 使用示例
8. 输出结构
9. Web界面
10. 故障排除
11. 注意事项

1. 工具简介

这是一个专业的网络流量监控和分析工具，专门设计用于精准监控特定目标的网络通信。工具能够实时捕获、解析和分类网络数据包，并按出端（请求）和入端（响应）方向分别存储和显示流量数据。

2. 功能特点

核心功能：
- 精准目标监控 - 仅监控指定的域名或IP地址
- 双向流量分析 - 清晰区分出端（请求）和入端（响应）流量
- 实时数据捕获 - 使用scapy库进行实时网络流量捕获
- 多协议解析 - 支持HTTP、DNS、TCP、UDP等协议解析
- 智能分类存储 - 按域名、URL、IP自动分类存储数据
- 实时Web显示 - 通过Web界面实时查看监控数据
- 文件管理 - 自动递增文件名，防止文件过大

高级特性：
- 灵活的过滤条件 - 支持BPF过滤表达式
- 批量目标管理 - 支持从文件读取监控目标
- 跨平台支持 - 可在Linux、Windows、macOS上运行
- 权限管理 - 自动检测和提示权限要求
- 优雅退出 - 支持Ctrl+C安全退出

3. 系统要求

最低要求：
- 操作系统: Debian/Ubuntu, CentOS/RHEL, Windows 10+, macOS 10.14+
- Python: 3.6 或更高版本
- 内存: 至少 512MB RAM
- 存储: 至少 100MB 可用空间
- 权限: 管理员/root权限（用于网络接口访问）

推荐配置：
- 操作系统: Debian 11+ 或 Ubuntu 20.04+
- Python: 3.8 或更高版本
- 内存: 1GB RAM 或更多
- 存储: 1GB 可用空间
- 网络: 千兆以太网或高速WiFi

4. 安装指南

4.1 环境准备

Debian/Ubuntu 系统：
sudo apt update
sudo apt upgrade -y
sudo apt install python3 python3-pip python3-venv git -y
sudo apt install net-tools tcpdump wireshark -y

CentOS/RHEL 系统：
sudo yum install python3 python3-pip git -y
或使用dnf（新版本）：
sudo dnf install python3 python3-pip git -y

Windows 系统：
1. 从 Python官网 (https://www.python.org/downloads/) 下载并安装Python 3.8+
2. 安装时勾选 "Add Python to PATH"
3. 安装 Npcap (https://nmap.org/npcap/) （WinPcap的替代品）

macOS 系统：
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python3

4.2 获取工具
git clone <repository-url>
cd network-monitor
或直接下载Python脚本：
wget https://example.com/network_monitor.py

4.3 安装Python依赖

方法一：使用requirements.txt
python3 -m venv network-monitor-env
source network-monitor-env/bin/activate  # Linux/macOS
或 network-monitor-env\\Scripts\\activate  # Windows
pip install -r requirements.txt

方法二：手动安装
pip install scapy flask requests

4.4 权限配置

Linux/macOS：
sudo python3 network_monitor.py [参数]
或设置CAP_NET_RAW能力（高级用户）：
sudo setcap cap_net_raw=eip $(which python3)

Windows：
以管理员身份运行命令提示符或PowerShell。

5. 使用方法

基本命令格式：
sudo python3 network_monitor.py [选项] -t 目标1 [-t 目标2 ...]

快速开始：
1. 监控单个网站
   sudo python3 network_monitor.py -t example.com

2. 监控多个目标
   sudo python3 network_monitor.py -t example.com -t google.com -t 192.168.1.1

3. 访问Web界面
   打开浏览器访问: http://localhost:8080

6. 参数详解

必需参数：
- -t, --target: 指定监控目标（域名或IP），可多次使用

可选参数：
- -i, --interface: 指定网络接口（如eth0, wlan0, en0），默认：所有接口
- -p, --port: 监控特定端口号，默认：所有端口
- -f, --filter: BPF过滤表达式，默认：无
- -o, --output: 输出目录，默认：captured_data
- -w, --webport: Web服务器端口，默认：8080
- --max-files: 最大文件数限制，默认：1000
- --target-file: 从文件读取监控目标，默认：无

参数示例说明：

网络接口 (-i)：
- 监控无线网络：-i wlan0
- 监控有线网络：-i eth0
- 监控所有接口（默认）：不指定-i参数

端口监控 (-p)：
- 监控HTTP流量：-p 80
- 监控HTTPS流量：-p 443
- 监控DNS查询：-p 53
- 监控自定义端口：-p 8080

BPF过滤表达式 (-f)：
- 仅TCP流量：-f "tcp"
- 排除特定IP：-f "not host 192.168.1.100"
- 组合条件：-f "tcp and port 80 and not net 192.168.0.0/24"
- 复杂表达式：-f "(host example.com or host google.com) and tcp port 443"

7. 使用示例

基础监控场景：

7.1 网站流量分析
sudo python3 network_monitor.py -t amazon.com -t ebay.com -o shopping_analysis
sudo python3 network_monitor.py -t facebook.com -t twitter.com -t instagram.com

7.2 应用性能监控
sudo python3 network_monitor.py -t api.example.com -p 443 -o api_monitor
sudo python3 network_monitor.py -t service1.local -t service2.local -f "tcp"

7.3 网络安全监控
sudo python3 network_monitor.py -t malicious-domain.com -t 192.168.1.100
sudo python3 network_monitor.py -t 10.0.0.5 -t 10.0.0.6 -f "not port 22"

高级使用场景：

7.4 批量目标监控
创建目标列表文件：
echo "example.com" > targets.txt
echo "google.com" >> targets.txt
echo "github.com" >> targets.txt
echo "192.168.1.1" >> targets.txt

使用文件监控：
sudo python3 network_monitor.py --target-file targets.txt -o batch_capture

7.5 特定协议分析
仅监控DNS查询：
sudo python3 network_monitor.py -t example.com -p 53 -f "udp" -o dns_analysis

监控Web流量（HTTP/HTTPS）：
sudo python3 network_monitor.py -t example.com -f "tcp port 80 or tcp port 443"

7.6 长期监控任务
后台运行监控（Linux）：
sudo nohup python3 network_monitor.py -t example.com -o long_term_capture > monitor.log 2>&1 &

查看运行状态：
tail -f monitor.log

停止监控：
sudo pkill -f network_monitor.py

8. 输出结构

目录组织：
captured_data/
├── outbound/
│   ├── domains/
│   │   ├── example.com.json
│   │   └── google.com.json
│   ├── urls/
│   │   ├── -123456789.json
│   │   └── -987654321.json
│   ├── ips/
│   │   ├── 192_168_1_1.json
│   │   └── 93_184_216_34.json
│   └── raw/
│       ├── packet_000001.json
│       └── packet_000002.json
└── inbound/
    ├── domains/
    ├── urls/
    ├── ips/
    └── raw/

数据格式示例：

数据包JSON结构：
{{
  "timestamp": "2023-12-07T10:30:45.123456",
  "direction": "outbound",
  "summary": "TCP 192.168.1.100:54321 > 93.184.216.34:80 SA",
  "raw_data": "4500003c0001000040067a65c0a801645db8d822...",
  "target_info": {{
    "host": "example.com",
    "type": "domain"
  }},
  "src_ip": "192.168.1.100",
  "dst_ip": "93.184.216.34",
  "protocol": 6,
  "src_port": 54321,
  "dst_port": 80,
  "flags": "S",
  "http_method": "GET",
  "http_host": "example.com",
  "http_path": "/",
  "http_url": "http://example.com/"
}}

9. Web界面

访问方式：
1. 启动监控工具
2. 打开Web浏览器
3. 访问: http://localhost:8080 （或指定的端口）

界面功能：

9.1 头部信息区
- 显示当前监控的目标列表
- 工具状态和简介

9.2 统计面板
- 出端流量统计（绿色边框）
  - 域名访问排名
  - URL请求统计
  - 目标IP通信量
- 入端流量统计（蓝色边框）
  - 域名响应排名
  - URL响应统计
  - 源IP通信量

9.3 实时数据流
- 时间戳和流量方向标识
- 源IP:端口 ↔ 目标IP:端口
- 协议类型和详细信息
- 颜色编码区分方向
  - 绿色：出端流量（请求）
  - 蓝色：入端流量（响应）

界面特性：
- 实时更新: 每2秒自动刷新数据
- 响应式设计: 适应不同屏幕尺寸
- 交互式显示: 鼠标悬停显示完整信息
- 可视化标识: 使用颜色增强可读性

10. 故障排除

常见问题及解决方案：

10.1 权限错误
问题: PermissionError: [Errno 1] Operation not permitted
解决: 
Linux/macOS: 使用sudo
sudo python3 network_monitor.py [参数]
Windows: 以管理员身份运行

10.2 接口找不到
问题: OSError: [Errno 19] No such device
解决:
查看可用接口：
ip link show        # Linux
ifconfig           # macOS
ipconfig           # Windows
指定正确的接口：
sudo python3 network_monitor.py -i eth0 -t example.com

10.3 依赖安装失败
问题: ModuleNotFoundError: No module named 'scapy'
解决:
使用pip安装：
pip install scapy flask requests
或使用系统包管理器：
sudo apt install python3-scapy    # Debian/Ubuntu
sudo yum install python3-scapy    # CentOS/RHEL

10.4 端口被占用
问题: OSError: [Errno 98] Address already in use
解决:
使用其他端口：
sudo python3 network_monitor.py -t example.com -w 8081
或终止占用进程：
sudo lsof -ti:8080 | xargs kill -9

10.5 无数据捕获
问题: 工具运行但无数据显示
解决:
- 检查目标是否可达
- 验证网络接口选择
- 检查防火墙设置
- 尝试简化过滤条件

调试模式：

启用详细日志：
import logging
logging.basicConfig(level=logging.DEBUG)

测试网络接口：
sudo tcpdump -i eth0 -c 10 host example.com
测试DNS解析：
nslookup example.com

11. 注意事项

法律和道德考虑：
1. 合法使用: 仅在您拥有或获得授权的网络上使用
2. 隐私保护: 不要监控他人的私人通信
3. 公司政策: 遵守所在组织的网络安全政策
4. 法律法规: 了解并遵守当地网络安全法律法规

性能考虑：
1. 资源占用: 长时间监控可能消耗大量磁盘空间
2. 网络影响: 在高流量网络上可能影响性能
3. 内存使用: 监控大量目标可能增加内存使用

技术限制：
1. 加密流量: 无法解密HTTPS等加密流量内容
2. 网络类型: 在某些网络配置下可能无法捕获所有流量
3. 协议支持: 主要支持常见协议（HTTP、DNS、TCP、UDP）

最佳实践：
1. 定期清理: 定期清理旧的捕获文件
2. 备份配置: 保存重要的目标列表和过滤规则
3. 监控日志: 关注工具运行日志和系统资源
4. 版本更新: 定期更新工具和依赖库

获取帮助

如果您遇到问题：
1. 查看本文档的故障排除部分
2. 检查工具输出的错误信息
3. 验证系统配置和权限
4. 查阅相关技术文档

重要提醒: 此工具仅供教育和授权测试使用。请负责任地使用网络监控工具，尊重他人隐私并遵守适用法律。

本文档由脚本自动生成 - 生成时间: {current_date}
"""

    return readme_content

def main():
    """主函数"""
    print("开始生成 README 文档...")
    
    # 生成文档内容
    readme_content = generate_readme()
    
    # 写入文件
    try:
        with open('README.txt', 'w', encoding='utf-8') as f:
            f.write(readme_content)
        print("README 文档生成成功！")
        print(f"文件位置: {Path('README.txt').absolute()}")
        print(f"文件大小: {len(readme_content)} 字符")
    except Exception as e:
        print(f"生成文档时出错: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())