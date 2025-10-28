#!/usr/bin/env python3
"""
网络数据捕获和分析程序 - 优化版
支持按源地址/目标地址过滤，按出端/入端区分流量
"""

import argparse
import threading
import time
import os
import json
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict, deque
from urllib.parse import urlparse
import re

from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP

class NetworkMonitor:
    def __init__(self, output_dir="captured_data", web_port=8080, max_files=1000):
        self.output_dir = output_dir
        self.web_port = web_port
        self.max_files = max_files
        
        # 创建输出目录结构
        self._create_directory_structure()
        
        # 数据存储
        self.captured_data = deque(maxlen=1000)
        self.domain_stats = defaultdict(lambda: {'outbound': 0, 'inbound': 0})
        self.url_stats = defaultdict(lambda: {'outbound': 0, 'inbound': 0})
        self.ip_stats = defaultdict(lambda: {'outbound': 0, 'inbound': 0})
        
        # 文件计数器
        self.file_counter = 0
        self.running = False
        
        # 过滤条件
        self.target_hosts = set()
        self.target_ips = set()
        
    def _create_directory_structure(self):
        """创建目录结构"""
        base_dirs = ['outbound', 'inbound']
        for direction in base_dirs:
            os.makedirs(f"{self.output_dir}/{direction}/domains", exist_ok=True)
            os.makedirs(f"{self.output_dir}/{direction}/urls", exist_ok=True)
            os.makedirs(f"{self.output_dir}/{direction}/ips", exist_ok=True)
            os.makedirs(f"{self.output_dir}/{direction}/raw", exist_ok=True)
    
    def set_targets(self, targets):
        """设置监控目标"""
        for target in targets:
            # 检查是否是IP地址
            try:
                ip = ipaddress.ip_address(target)
                self.target_ips.add(str(ip))
                print(f"添加IP目标: {target}")
            except ValueError:
                # 如果不是IP，则当作域名处理
                self.target_hosts.add(target.lower())
                print(f"添加域名目标: {target}")
    
    def _get_packet_direction(self, packet):
        """判断数据包方向：outbound(出端) 或 inbound(入端)"""
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # 检查是否是目标流量
        is_target_traffic = False
        target_info = {}
        
        # 检查目标IP
        if dst_ip in self.target_ips or src_ip in self.target_ips:
            is_target_traffic = True
            if dst_ip in self.target_ips:
                target_info = {'ip': dst_ip, 'type': 'ip'}
            else:
                target_info = {'ip': src_ip, 'type': 'ip'}
        
        # 检查HTTP Host
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            if http_layer.Host:
                host = http_layer.Host.decode('utf-8').lower()
                if host in self.target_hosts:
                    is_target_traffic = True
                    target_info = {'host': host, 'type': 'domain'}
        
        # 检查DNS查询
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # DNS查询
                query = dns_layer[DNSQR].qname.decode('utf-8').rstrip('.').lower()
                if query in self.target_hosts:
                    is_target_traffic = True
                    target_info = {'host': query, 'type': 'domain'}
        
        if not is_target_traffic:
            return None
        
        # 判断方向
        # 出端: 本地 -> 目标
        # 入端: 目标 -> 本地
        if target_info['type'] == 'ip':
            if dst_ip in self.target_ips:
                return 'outbound', target_info
            else:
                return 'inbound', target_info
        else:
            # 对于域名，我们假设发送到目标的包是出端，从目标返回的包是入端
            # 这在实际中可能需要更复杂的逻辑，这里简化处理
            if packet.haslayer(TCP) and packet[TCP].dport in [80, 443, 8080]:
                return 'outbound', target_info
            elif packet.haslayer(TCP) and packet[TCP].sport in [80, 443, 8080]:
                return 'inbound', target_info
            else:
                # 默认基于端口判断
                if packet.haslayer(TCP):
                    if packet[TCP].dport > packet[TCP].sport:
                        return 'outbound', target_info
                    else:
                        return 'inbound', target_info
                else:
                    return 'outbound', target_info  # 默认作为出端
    
    def start_capture(self, interface=None, port=None, filter_expr=""):
        """开始捕获网络数据"""
        self.running = True
        
        # 如果没有设置目标，使用空过滤捕获所有流量
        if not self.target_hosts and not self.target_ips:
            print("警告: 未指定监控目标，将捕获所有流量")
            filter_str = filter_expr
        else:
            # 构建针对目标的过滤表达式
            target_filters = []
            
            # IP目标过滤
            for ip in self.target_ips:
                target_filters.append(f"host {ip}")
            
            # 构建组合过滤条件
            if target_filters:
                target_filter = " or ".join(target_filters)
                if filter_expr:
                    filter_str = f"({target_filter}) and ({filter_expr})"
                else:
                    filter_str = target_filter
            else:
                filter_str = filter_expr
        
        print(f"开始捕获网络数据...")
        print(f"接口: {interface or '默认'}")
        print(f"端口: {port or '所有'}")
        print(f"过滤: {filter_str or '无'}")
        print(f"监控目标: {list(self.target_hosts) + list(self.target_ips)}")
        
        # 添加端口过滤
        if port:
            if filter_str:
                filter_str = f"{filter_str} and port {port}"
            else:
                filter_str = f"port {port}"
        
        try:
            if interface:
                sniff(iface=interface, filter=filter_str, prn=self.process_packet, store=False)
            else:
                sniff(filter=filter_str, prn=self.process_packet, store=False)
        except Exception as e:
            print(f"捕获错误: {e}")
            self.running = False
    
    def process_packet(self, packet):
        """处理捕获的数据包"""
        if not self.running:
            return
            
        try:
            # 获取数据包方向
            direction_info = self._get_packet_direction(packet)
            if not direction_info:
                return  # 不是目标流量，跳过
                
            direction, target_info = direction_info
            
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'direction': direction,
                'summary': packet.summary(),
                'raw_data': bytes(packet).hex(),
                'target_info': target_info
            }
            
            # 解析IP层
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst
                packet_info['protocol'] = ip_layer.proto
                
                # 统计IP（按方向）
                if direction == 'outbound':
                    self.ip_stats[ip_layer.dst]['outbound'] += 1
                else:
                    self.ip_stats[ip_layer.src]['inbound'] += 1
            
            # 解析传输层
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = str(tcp_layer.flags)
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
            
            # 解析DNS
            if packet.haslayer(DNS):
                self._process_dns(packet, packet_info, direction)
            
            # 解析HTTP
            if packet.haslayer(HTTPRequest):
                self._process_http_request(packet, packet_info, direction)
            elif packet.haslayer(HTTPResponse):
                self._process_http_response(packet, packet_info, direction)
            
            # 添加到捕获数据列表
            self.captured_data.append(packet_info)
            
            # 保存数据
            self.save_packet_data(packet_info, direction)
            
        except Exception as e:
            print(f"处理数据包错误: {e}")
    
    def _process_dns(self, packet, packet_info, direction):
        """处理DNS数据包"""
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:  # DNS查询
            query = dns_layer[DNSQR].qname.decode('utf-8').rstrip('.')
            packet_info['dns_query'] = query
            packet_info['dns_type'] = 'query'
            
            if direction == 'outbound':
                self.domain_stats[query]['outbound'] += 1
        else:  # DNS响应
            packet_info['dns_type'] = 'response'
            if dns_layer.an and dns_layer.an[0].type == 1:  # A记录
                for answer in dns_layer.an:
                    if answer.type == 1:  # A记录
                        packet_info['dns_answer'] = answer.rdata
                        break
    
    def _process_http_request(self, packet, packet_info, direction):
        """处理HTTP请求"""
        if direction != 'outbound':
            return
            
        http_layer = packet[HTTPRequest]
        host = http_layer.Host.decode('utf-8') if http_layer.Host else "Unknown"
        path = http_layer.Path.decode('utf-8') if http_layer.Path else "/"
        method = http_layer.Method.decode('utf-8') if http_layer.Method else "GET"
        
        url = f"http://{host}{path}"
        if http_layer.Host and b':443' in http_layer.Host or packet_info.get('dst_port') == 443:
            url = f"https://{host}{path}"
        
        packet_info['http_method'] = method
        packet_info['http_host'] = host
        packet_info['http_path'] = path
        packet_info['http_url'] = url
        
        self.url_stats[url]['outbound'] += 1
    
    def _process_http_response(self, packet, packet_info, direction):
        """处理HTTP响应"""
        if direction != 'inbound':
            return
            
        http_layer = packet[HTTPResponse]
        status_code = http_layer.Status_Code.decode('utf-8') if http_layer.Status_Code else "200"
        packet_info['http_status'] = status_code
        
        # 尝试从之前的请求中获取URL信息
        for prev_pkt in reversed(self.captured_data):
            if (prev_pkt.get('src_ip') == packet_info.get('dst_ip') and 
                prev_pkt.get('src_port') == packet_info.get('dst_port') and
                prev_pkt.get('direction') == 'outbound' and
                'http_url' in prev_pkt):
                packet_info['http_url'] = prev_pkt['http_url']
                self.url_stats[prev_pkt['http_url']]['inbound'] += 1
                break
    
    def save_packet_data(self, packet_info, direction):
        """保存数据包数据"""
        # 保存原始数据包
        self.file_counter = (self.file_counter % self.max_files) + 1
        raw_filename = f"{self.output_dir}/{direction}/raw/packet_{self.file_counter:06d}.json"
        
        with open(raw_filename, 'w', encoding='utf-8') as f:
            json.dump(packet_info, f, indent=2, ensure_ascii=False)
        
        # 按分类保存
        self._save_by_domain(packet_info, direction)
        self._save_by_url(packet_info, direction)
        self._save_by_ip(packet_info, direction)
    
    def _save_by_domain(self, packet_info, direction):
        """按域名保存数据"""
        domain = None
        if 'http_host' in packet_info:
            domain = packet_info['http_host']
        elif 'dns_query' in packet_info:
            domain = packet_info['dns_query']
        
        if domain:
            safe_domain = re.sub(r'[^\w\.-]', '_', domain)
            filename = f"{self.output_dir}/{direction}/domains/{safe_domain}.json"
            self._append_to_file(filename, packet_info)
    
    def _save_by_url(self, packet_info, direction):
        """按URL保存数据"""
        if 'http_url' in packet_info:
            url = packet_info['http_url']
            safe_url = str(hash(url))  # 使用哈希避免文件名过长
            filename = f"{self.output_dir}/{direction}/urls/{safe_url}.json"
            self._append_to_file(filename, packet_info)
    
    def _save_by_ip(self, packet_info, direction):
        """按IP保存数据"""
        if direction == 'outbound' and 'dst_ip' in packet_info:
            ip = packet_info['dst_ip']
        elif direction == 'inbound' and 'src_ip' in packet_info:
            ip = packet_info['src_ip']
        else:
            return
            
        safe_ip = ip.replace('.', '_')
        filename = f"{self.output_dir}/{direction}/ips/{safe_ip}.json"
        self._append_to_file(filename, packet_info)
    
    def _append_to_file(self, filename, data):
        """追加数据到文件"""
        try:
            existing_data = []
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            
            existing_data.append(data)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存文件错误 {filename}: {e}")
    
    def start_web_server(self):
        """启动Web服务器"""
        from flask import Flask, render_template_string, jsonify
        
        app = Flask(__name__)
        
        HTML_TEMPLATE = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>定向网络监控 - 出端/入端流量分析</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1400px; margin: 0 auto; }
                .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                .stats-container { display: flex; gap: 20px; margin-bottom: 20px; }
                .stat-section { flex: 1; background: white; padding: 15px; border-radius: 8px; }
                .direction-outbound { border-left: 4px solid #4CAF50; }
                .direction-inbound { border-left: 4px solid #2196F3; }
                .packet-list { background: white; padding: 15px; border-radius: 8px; }
                .packet-item { margin: 10px 0; padding: 10px; border-radius: 4px; }
                .outbound { background: #e8f5e8; border-left: 3px solid #4CAF50; }
                .inbound { background: #e3f2fd; border-left: 3px solid #2196F3; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .badge { padding: 2px 8px; border-radius: 12px; font-size: 12px; color: white; }
                .badge-outbound { background: #4CAF50; }
                .badge-inbound { background: #2196F3; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 定向网络流量监控</h1>
                    <p>监控目标: <strong id="targets"></strong></p>
                    <p>仅显示与目标相关的出端(→)和入端(←)流量</p>
                </div>
                
                <div class="stats-container">
                    <div class="stat-section direction-outbound">
                        <h3>📤 出端流量统计</h3>
                        <div id="outbound-stats">
                            <div id="outbound-domains"></div>
                            <div id="outbound-urls"></div>
                            <div id="outbound-ips"></div>
                        </div>
                    </div>
                    
                    <div class="stat-section direction-inbound">
                        <h3>📥 入端流量统计</h3>
                        <div id="inbound-stats">
                            <div id="inbound-domains"></div>
                            <div id="inbound-urls"></div>
                            <div id="inbound-ips"></div>
                        </div>
                    </div>
                </div>
                
                <div class="packet-list">
                    <h3>📊 实时数据流</h3>
                    <div id="packets" style="height: 500px; overflow-y: auto;"></div>
                </div>
            </div>
            
            <script>
                function updateData() {
                    fetch('/data')
                        .then(response => response.json())
                        .then(data => {
                            // 更新目标显示
                            document.getElementById('targets').textContent = data.targets.join(', ');
                            
                            // 更新出端统计
                            updateStats('outbound', data.stats.outbound);
                            updateStats('inbound', data.stats.inbound);
                            
                            // 更新数据包列表
                            updatePacketList(data.packets);
                        });
                }
                
                function updateStats(direction, stats) {
                    // 更新域名统计
                    let domainsHtml = '<h4>域名</h4>';
                    Object.entries(stats.domains).slice(0,5).forEach(([domain, count]) => {
                        domainsHtml += `<div>${domain}: ${count}</div>`;
                    });
                    document.getElementById(`${direction}-domains`).innerHTML = domainsHtml;
                    
                    // 更新URL统计
                    let urlsHtml = '<h4>URL</h4>';
                    Object.entries(stats.urls).slice(0,5).forEach(([url, count]) => {
                        urlsHtml += `<div title="${url}">${url.substring(0,50)}...: ${count}</div>`;
                    });
                    document.getElementById(`${direction}-urls`).innerHTML = urlsHtml;
                    
                    // 更新IP统计
                    let ipsHtml = '<h4>IP地址</h4>';
                    Object.entries(stats.ips).slice(0,5).forEach(([ip, count]) => {
                        ipsHtml += `<div>${ip}: ${count}</div>`;
                    });
                    document.getElementById(`${direction}-ips`).innerHTML = ipsHtml;
                }
                
                function updatePacketList(packets) {
                    let packetsHtml = '<table><tr><th>时间</th><th>方向</th><th>源IP:端口</th><th>目标IP:端口</th><th>协议</th><th>详细信息</th></tr>';
                    packets.forEach(pkt => {
                        const directionClass = pkt.direction === 'outbound' ? 'outbound' : 'inbound';
                        const directionBadge = pkt.direction === 'outbound' ? 
                            '<span class="badge badge-outbound">→ 出端</span>' : 
                            '<span class="badge badge-inbound">← 入端</span>';
                        
                        const src = pkt.src_ip ? `${pkt.src_ip}:${pkt.src_port || ''}` : 'N/A';
                        const dst = pkt.dst_ip ? `${pkt.dst_ip}:${pkt.dst_port || ''}` : 'N/A';
                        
                        let details = pkt.summary;
                        if (pkt.http_url) {
                            details = `${pkt.http_method || 'GET'} ${pkt.http_url}`;
                        } else if (pkt.dns_query) {
                            details = `DNS查询: ${pkt.dns_query}`;
                        }
                        
                        packetsHtml += `<tr class="packet-item ${directionClass}">
                            <td>${new Date(pkt.timestamp).toLocaleTimeString()}</td>
                            <td>${directionBadge}</td>
                            <td>${src}</td>
                            <td>${dst}</td>
                            <td>${pkt.protocol || ''}</td>
                            <td>${details}</td>
                        </tr>`;
                    });
                    packetsHtml += '</table>';
                    document.getElementById('packets').innerHTML = packetsHtml;
                }
                
                setInterval(updateData, 2000);
                updateData();
            </script>
        </body>
        </html>
        """
        
        @app.route('/')
        def index():
            return render_template_string(HTML_TEMPLATE)
        
        @app.route('/data')
        def get_data():
            # 准备统计数据
            outbound_stats = {
                'domains': {k: v['outbound'] for k, v in self.domain_stats.items() if v['outbound'] > 0},
                'urls': {k: v['outbound'] for k, v in self.url_stats.items() if v['outbound'] > 0},
                'ips': {k: v['outbound'] for k, v in self.ip_stats.items() if v['outbound'] > 0}
            }
            
            inbound_stats = {
                'domains': {k: v['inbound'] for k, v in self.domain_stats.items() if v['inbound'] > 0},
                'urls': {k: v['inbound'] for k, v in self.url_stats.items() if v['inbound'] > 0},
                'ips': {k: v['inbound'] for k, v in self.ip_stats.items() if v['inbound'] > 0}
            }
            
            return jsonify({
                'packets': list(self.captured_data),
                'stats': {
                    'outbound': outbound_stats,
                    'inbound': inbound_stats
                },
                'targets': list(self.target_hosts) + list(self.target_ips)
            })
        
        print(f"Web服务器启动在 http://0.0.0.0:{self.web_port}")
        app.run(host='0.0.0.0', port=self.web_port, debug=False, use_reloader=False)
    
    def stop(self):
        """停止监控"""
        self.running = False

def main():
    parser = argparse.ArgumentParser(description='定向网络数据监控工具')
    parser.add_argument('-i', '--interface', help='网络接口')
    parser.add_argument('-p', '--port', type=int, help='监听端口')
    parser.add_argument('-f', '--filter', default='', help='BPF过滤表达式')
    parser.add_argument('-o', '--output', default='captured_data', help='输出目录')
    parser.add_argument('-w', '--webport', type=int, default=8080, help='Web服务器端口')
    parser.add_argument('--max-files', type=int, default=1000, help='最大文件数')
    
    # 新增目标指定参数
    parser.add_argument('-t', '--target', action='append', help='监控目标(域名或IP)，可多次使用', default=[])
    parser.add_argument('--target-file', help='从文件读取监控目标(每行一个)')
    
    args = parser.parse_args()
    
    # 检查权限
    if os.geteuid() != 0:
        print("需要root权限来捕获网络数据包")
        print("请使用: sudo python3 network_monitor.py [参数]")
        return
    
    # 创建监控器
    monitor = NetworkMonitor(args.output, args.webport, args.max_files)
    
    # 设置监控目标
    targets = args.target
    
    # 从文件读取目标
    if args.target_file and os.path.exists(args.target_file):
        with open(args.target_file, 'r') as f:
            file_targets = [line.strip() for line in f if line.strip()]
            targets.extend(file_targets)
    
    if not targets:
        print("错误: 必须指定至少一个监控目标")
        print("使用 -t 参数指定目标，或使用 --target-file 从文件读取")
        return
    
    monitor.set_targets(targets)
    
    try:
        # 启动Web服务器线程
        web_thread = threading.Thread(target=monitor.start_web_server, daemon=True)
        web_thread.start()
        
        # 启动数据捕获
        monitor.start_capture(args.interface, args.port, args.filter)
        
    except KeyboardInterrupt:
        print("\n停止监控...")
        monitor.stop()
    except Exception as e:
        print(f"错误: {e}")
        monitor.stop()

if __name__ == "__main__":
    main()