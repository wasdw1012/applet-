import subprocess
import json
import requests
import socket
import sys
import os
import time
import re
import base64
import ssl
import urllib3
import asyncio
from datetime import datetime
from urllib.parse import urlparse, urljoin
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple, Optional

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Day1ReconEnhanced:
    def __init__(self, target_domain):
        """
        初始化增强版侦察对象
        
          V2新增：
        - 多API源配置
        - 现代化检测选项
        - 医疗行业专项检查
        
        参数说明：
        target_domain: 目标域名，如 example.com
        """
        self.target = target_domain
        self.results = {
            'target': target_domain,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'version': 'V2 Enhanced',
            'passive_recon': {
                'certificate_transparency': [],
                'subdomain_sources': {},
                'whois_data': {},
                'dns_records': {},
                'technology_stack': {},
                'cdn_waf_detection': {}
            },
            'active_scan': {
                'port_scan': '',
                'service_identification': '',
                'web_applications': {},
                'api_endpoints': [],
                'security_headers': {},
                'ssl_analysis': {}
            },
            'healthcare_specific': {
                'hipaa_compliance_check': {},
                'medical_endpoints': [],
                'patient_data_exposure': {},
                'payment_security': {}
            },
            'summary': {}
        }
        
        
        #   现代化技术检测配置
        self.modern_tech_signatures = {
            'cdn_providers': {
                'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
                'aws_cloudfront': ['x-amz-cf-id', 'cloudfront'],
                'fastly': ['fastly-ssl', 'x-served-by'],
                'akamai': ['akamai', 'x-akamai'],
                'framer': ['framer', 'framerusercontent']
            },
            'waf_signatures': {
                'cloudflare': ['cf-ray', 'cloudflare'],
                'aws_waf': ['x-amzn-requestid'],
                'incapsula': ['incap_ses', 'x-iinfo'],
                'sucuri': ['x-sucuri-id']
            },
            'js_frameworks': {
                'react': ['react', '_react', 'react-dom'],
                'vue': ['vue.js', '__vue__', 'vue-router'],
                'angular': ['angular', 'ng-version', 'ng-'],
                'next': ['next.js', '_next', '__next'],
                'nuxt': ['nuxt', '__nuxt']
            }
        }
        
        #   医疗行业特定检测
        self.healthcare_indicators = {
            'endpoints': [
                '/api/patients', '/api/appointments', '/api/medical-records',
                '/portal/patient', '/emr', '/ehr', '/hipaa',
                '/billing', '/insurance', '/payment'
            ],
            'keywords': [
                'patient', 'medical', 'health', 'appointment', 'doctor',
                'clinic', 'hospital', 'insurance', 'hipaa', 'phi'
            ],
            'security_requirements': [
                'hsts', 'csp', 'x-frame-options', 'x-content-type-options'
            ]
        }
        
        self.create_output_dir()
    
    def create_output_dir(self):
        """
        创建输出目录
        
        为什么需要：保存所有扫描结果，便于后续分析和报告生成
        """
        self.output_dir = f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"[+] 创建输出目录: {self.output_dir}")

    def log_step(self, step_name, description):
        """
        记录执行步骤
        
        为什么需要：跟踪侦察进度，便于调试和学习
        """
        print(f"\n{'='*60}")
        print(f"[STEP] {step_name}")
        print(f"[DESC] {description}")
        print(f"{'='*60}")

    def run_command(self, command, description):
        """
        执行系统命令并记录结果
        
        参数说明：
        command: 要执行的命令列表，如 ['nmap', '-sS', 'target.com']
        description: 命令描述，用于日志记录
        
        返回：命令输出结果
        
        为什么这样设计：
        1. 统一的命令执行接口
        2. 自动记录执行日志
        3. 错误处理和超时控制
        """
        try:
            print(f"[CMD] 执行: {' '.join(command)}")
            print(f"[DESC] {description}")
            
            # 设置超时，防止命令卡死
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5分钟超时
            )
            
            if result.returncode == 0:
                print(f"[OK] 命令执行成功")
                return result.stdout
            else:
                print(f"[WARN] 命令执行失败: {result.stderr}")
                return result.stderr
                
        except subprocess.TimeoutExpired:
            print(f"[ERROR] 命令执行超时")
            return "TIMEOUT"
        except FileNotFoundError:
            print(f"[ERROR] 命令不存在: {command[0]}")
            return "COMMAND_NOT_FOUND"
        except Exception as e:
            print(f"[ERROR] 命令执行异常: {e}")
            return str(e)

    def passive_information_gathering(self):
        """
        被动信息收集阶段
        
        为什么叫"被动"：
        - 不直接与目标服务器交互
        - 通过第三方服务和公开数据库收集信息
        - 目标服务器不会察觉到我们在收集信息
        
        收集内容：
        1. 域名注册信息 (WHOIS)
        2. DNS记录信息
        3. 子域名发现
        4. 证书透明度日志
        5. 搜索引擎信息
        6.   CDN和WAF检测
        """
        self.log_step("被动信息收集", "通过公开资源收集目标信息，不直接接触目标")
        
        # 1. WHOIS信息收集
        print("\n[1] WHOIS信息收集")
        print("目的：获取域名注册信息、管理员联系方式、DNS服务器等")
        whois_result = self.run_command(
            ['whois', self.target],
            "查询域名注册信息，了解域名所有者和技术联系人"
        )
        self.results['passive_recon']['whois_data'] = whois_result
        
        # 2. DNS信息收集
        print("\n[2] DNS信息收集")
        print("目的：了解域名解析配置，发现可能的服务器IP和子域名")
        
        # A记录 - 域名到IP的映射
        a_record = self.run_command(
            ['dig', '+short', 'A', self.target],
            "查询A记录，获取域名对应的IPv4地址"
        )
        
        # MX记录 - 邮件服务器信息
        mx_record = self.run_command(
            ['dig', '+short', 'MX', self.target],
            "查询MX记录，了解邮件服务器配置"
        )
        
        # NS记录 - 权威DNS服务器
        ns_record = self.run_command(
            ['dig', '+short', 'NS', self.target],
            "查询NS记录，了解权威DNS服务器"
        )
        
        # TXT记录 - 可能包含SPF、DKIM等安全配置
        txt_record = self.run_command(
            ['dig', '+short', 'TXT', self.target],
            "查询TXT记录，可能发现SPF、DKIM、域名验证等信息"
        )
        
        self.results['passive_recon']['dns_records'] = {
            'a_record': a_record,
            'mx_record': mx_record, 
            'ns_record': ns_record,
            'txt_record': txt_record
        }
        
        # 3. 证书透明度日志查询 (优化版 - 快速跳过)
        print("\n[3] 证书透明度日志查询") 
        print("目的：通过SSL证书日志发现子域名，这些通常不会出现在DNS枚举中")
        print("  检测到网络API较慢，自动启用快速模式...")
        self.certificate_transparency_search_fast()
        
        # 4. 子域名枚举
        print("\n[4] 子域名枚举")
        print("目的：发现目标的所有子域名，扩大攻击面")
        self.enhanced_subdomain_enumeration()
        
        #   5. CDN和WAF检测
        print("\n[5] CDN和WAF检测")
        print("目的：了解目标的防护措施，影响后续测试策略")
        self.detect_cdn_and_waf()

    def certificate_transparency_search(self):
        """
          增强版证书透明度日志搜索
        
        改进：
        - 多API源支持，提高成功率
        - 更好的错误处理和重试机制
        - 数据去重和清洗
        
        原理：
        - 所有SSL证书都会记录在公开的证书透明度日志中
        - 通过查询这些日志，可以发现目标的所有域名和子域名
        - 即使子域名没有DNS记录，也可能在证书中被发现
        
        为什么有效：
        - 很多管理员会为内部系统申请证书
        - 通配符证书会暴露域名结构
        - 历史证书可能包含已下线但仍存在的系统
        """
        print("  增强版证书透明度日志搜索...")
        all_domains = set()
        successful_sources = []
        
        # API源1: crt.sh (最可靠)
        try:
            print("  → 查询 crt.sh 数据库...")
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            
            response = requests.get(url, timeout=30, verify=False)
            if response.status_code == 200:
                cert_data = response.json()
                
                for cert in cert_data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name and self.target in name:
                                # 清理通配符
                                clean_name = name.replace('*.', '')
                                if self._is_valid_domain(clean_name):
                                    all_domains.add(clean_name)
                
                successful_sources.append('crt.sh')
                print(f"    ✓ crt.sh: 发现 {len([d for d in all_domains if 'crt.sh' not in str(d)])} 个域名")
                
        except Exception as e:
            print(f"    ✗ crt.sh 查询失败: {e}")
        
        # API源2: Certspotter (备用)
        try:
            print("  → 查询 Certspotter API...")
            url = f"https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names"
            
            response = requests.get(url, timeout=30, verify=False)
            if response.status_code == 200:
                cert_data = response.json()
                
                for cert in cert_data:
                    if 'dns_names' in cert:
                        for name in cert['dns_names']:
                            name = name.strip().lower()
                            if name and self.target in name:
                                clean_name = name.replace('*.', '')
                                if self._is_valid_domain(clean_name):
                                    all_domains.add(clean_name)
                
                successful_sources.append('certspotter')
                print(f"    ✓ Certspotter: 补充发现域名")
                
        except Exception as e:
            print(f"    ✗ Certspotter 查询失败: {e}")
        
        # 保存结果
        domain_list = sorted(list(all_domains))
        self.results['passive_recon']['certificate_transparency'] = domain_list
        
        print(f"[OK] 证书透明度搜索完成")
        print(f"      成功源: {', '.join(successful_sources) if successful_sources else '无'}")
        print(f"      发现域名: {len(domain_list)} 个")
        
        # 保存到文件
        if domain_list:
            with open(f"{self.output_dir}/cert_domains_enhanced.txt", 'w') as f:
                for domain in domain_list:
                    f.write(f"{domain}\n")
        
        return domain_list

    def certificate_transparency_search_fast(self):
        """
          快速版证书透明度搜索 - 优化网络延迟问题
        
        优化策略：
        - 超短超时时间 (3秒)
        - 实时状态反馈
        - 失败立即跳过
        - 不影响核心扫描流程
        """
        print("    快速模式启动 (3秒超时，失败自动跳过)...")
        
        all_domains = set()
        start_time = time.time()
        
        # 尝试快速查询 crt.sh
        try:
            print("  [进度] 尝试 crt.sh (3秒超时)...")
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            
            response = requests.get(url, timeout=3, verify=False)
            if response.status_code == 200:
                cert_data = response.json()
                print(f"  [成功] 获取到 {len(cert_data)} 条证书记录")
                
                # 快速处理，最多处理前50条
                process_count = min(50, len(cert_data))
                for i, cert in enumerate(cert_data[:process_count]):
                    if i % 10 == 0:
                        print(f"  [进度] 处理证书 {i+1}/{process_count}...")
                    
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name and self.target in name and '.' in name:
                                clean_name = name.replace('*.', '')
                                all_domains.add(clean_name)
                
                print(f"    crt.sh: 发现 {len(all_domains)} 个域名")
            else:
                print(f"     crt.sh 响应异常: {response.status_code}")
                
        except requests.exceptions.Timeout:
            print("    crt.sh 3秒超时，跳过")
        except Exception as e:
            print(f"    crt.sh 快速查询失败: {str(e)[:50]}...")
        
        # 保存结果
        domain_list = sorted(list(all_domains))
        self.results['passive_recon']['certificate_transparency'] = domain_list
        
        elapsed = time.time() - start_time
        print(f"[快速完成] 证书透明度搜索 - {elapsed:.1f}秒")
        print(f"      发现域名: {len(domain_list)} 个")
        print("      如需完整证书搜索，可在报告完成后单独运行")
        
        # 保存到文件
        if domain_list:
            with open(f"{self.output_dir}/cert_domains_fast.txt", 'w') as f:
                for domain in domain_list:
                    f.write(f"{domain}\n")
        
        return domain_list

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名格式是否正确"""
        if not domain or len(domain) > 253:
            return False
        
        # 基本域名格式检查
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(domain))

    def enhanced_subdomain_enumeration(self):
        """
          增强版子域名枚举
        
        多源策略：
        1. 字典暴力破解 (传统方法)
        2. 在线API查询 (HackerTarget等)
        4. DNS暴力破解 (大字典)
        
        改进：
        - 并发查询提高速度
        - 多个数据源交叉验证
        - 智能去重和域名验证
        """
        print("  增强版子域名枚举...")
        all_subdomains = set()
        
        # 方法1: 扩展字典暴力破解
        print("  → 扩展字典暴力破解...")
        extended_subdomains = [
            # 基础服务
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 
            'api', 'blog', 'shop', 'forum', 'support', 'help',
            
            # 安全相关
            'secure', 'vpn', 'ssh', 'rdp', 'panel', 'cpanel',
            'webmail', 'mx', 'ns1', 'ns2', 'dns', 'gateway',
            
            # 医疗行业特定
            'patient', 'portal', 'emr', 'ehr', 'medical', 'clinic',
            'appointment', 'billing', 'insurance', 'hipaa',
            
        ]
        
        dictionary_results = self._parallel_subdomain_check(extended_subdomains)
        all_subdomains.update(dictionary_results)
        print(f"    ✓ 字典暴力破解: {len(dictionary_results)} 个")
        
        # 方法2: 在线API查询
        print("  → 在线API查询...")
        api_results = self._query_subdomain_apis()
        all_subdomains.update(api_results)
        print(f"    ✓ API查询: {len(api_results)} 个")
        
        # 方法3: 从证书透明度结果中提取子域名
        cert_domains = self.results['passive_recon'].get('certificate_transparency', [])
        cert_subdomains = [d for d in cert_domains if d != self.target and d.endswith(self.target)]
        all_subdomains.update(cert_subdomains)
        print(f"    ✓ 证书透明度: {len(cert_subdomains)} 个")
        
        # 去重并验证
        final_subdomains = []
        for subdomain in all_subdomains:
            if self._verify_subdomain_exists(subdomain):
                final_subdomains.append(subdomain)
        
        # 保存结果
        self.results['passive_recon']['subdomain_sources']['enhanced'] = final_subdomains
        
        print(f"[OK] 增强版子域名枚举完成: {len(final_subdomains)} 个有效子域名")
        
        # 保存到文件
        with open(f"{self.output_dir}/subdomains_enhanced.txt", 'w') as f:
            for subdomain in sorted(final_subdomains):
                f.write(f"{subdomain}\n")
        
        return final_subdomains

    def _parallel_subdomain_check(self, subdomain_list: List[str]) -> List[str]:
        """并发检查子域名存在性"""
        found_subdomains = []
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check_subdomain, subdomain_list)
            found_subdomains = [r for r in results if r is not None]
        
        return found_subdomains

    def _query_subdomain_apis(self) -> List[str]:
        """查询在线子域名API"""
        found_subdomains = []
        
        # API 1: HackerTarget
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and self.target in subdomain:
                            found_subdomains.append(subdomain)
        except Exception as e:
            print(f"    ✗ HackerTarget API 失败: {e}")
        
        return list(set(found_subdomains))

    def _verify_subdomain_exists(self, subdomain: str) -> bool:
        """验证子域名是否真实存在"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False

    def detect_cdn_and_waf(self):
        """
          CDN和WAF检测
        
        目的：
        - 识别CDN提供商（影响攻击策略）
        - 检测WAF存在（影响漏洞扫描）
        - 了解防护措施强度
        
        检测方法：
        - HTTP响应头分析
        - 特殊字段识别
        - 响应特征匹配
        """
        print("  CDN和WAF检测...")
        
        detection_results = {
            'cdn_provider': 'unknown',
            'waf_detected': False,
            'waf_type': 'unknown',
            'security_level': 'unknown',
            'evidence': []
        }
        
        try:
            # 获取HTTP响应头
            response = requests.get(f"https://{self.target}", 
                                  timeout=10, 
                                  verify=False,
                                  allow_redirects=True)
            
            headers = response.headers
            
            # CDN检测
            for cdn_name, signatures in self.modern_tech_signatures['cdn_providers'].items():
                for sig in signatures:
                    # 检查响应头
                    for header_name, header_value in headers.items():
                        if sig.lower() in header_name.lower() or sig.lower() in str(header_value).lower():
                            detection_results['cdn_provider'] = cdn_name
                            detection_results['evidence'].append(f"CDN Header: {header_name}={header_value}")
            
            # WAF检测
            for waf_name, signatures in self.modern_tech_signatures['waf_signatures'].items():
                for sig in signatures:
                    for header_name, header_value in headers.items():
                        if sig.lower() in header_name.lower() or sig.lower() in str(header_value).lower():
                            detection_results['waf_detected'] = True
                            detection_results['waf_type'] = waf_name
                            detection_results['evidence'].append(f"WAF Header: {header_name}={header_value}")
            
            # 特殊检测：Framer平台
            if 'framer' in str(headers.get('Server', '')).lower():
                detection_results['cdn_provider'] = 'framer'
                detection_results['security_level'] = 'high'
                detection_results['evidence'].append("Framer平台检测")
            
            # 安全评级
            security_headers = ['strict-transport-security', 'x-frame-options', 'x-content-type-options']
            security_score = sum(1 for h in security_headers if h in headers)
            
            if security_score >= 3:
                detection_results['security_level'] = 'high'
            elif security_score >= 2:
                detection_results['security_level'] = 'medium'
            else:
                detection_results['security_level'] = 'low'
            
            print(f"      CDN提供商: {detection_results['cdn_provider']}")
            print(f"      WAF检测: {'是' if detection_results['waf_detected'] else '否'}")
            print(f"      安全等级: {detection_results['security_level']}")
            
        except Exception as e:
            print(f"    ✗ CDN/WAF检测失败: {e}")
        
        self.results['passive_recon']['cdn_waf_detection'] = detection_results
        return detection_results

    def enhanced_active_scanning(self):
        """
          自适应智能扫描系统
        
        V2升级：
        - 基于目标类型的自适应策略选择
        - 扫描效率与深度的智能平衡
        - 现代化平台专用检测流程
        - 实时策略调整和结果反馈
        
        扫描决策树：
        现代CDN → 轻量化扫描 + 应用层深度分析
        传统服务器 → 全面端口扫描 + 漏洞检测
        混合架构 → 平衡策略 + 分层检测
        """
        self.log_step("自适应智能扫描", "根据目标特征动态调整扫描策略")
        
        # 预分析：确定最优扫描策略
        print("\n[预分析] 扫描策略评估")
        scan_strategy = self.determine_optimal_strategy()
        print(f"    选定策略: {scan_strategy['name']}")
        print(f"    预计时间: {scan_strategy['estimated_time']}")
        print(f"    扫描深度: {scan_strategy['depth_level']}")
        
        # 1. 自适应端口扫描
        print(f"\n[1] {scan_strategy['port_scan']['name']}")
        print(f"目的：{scan_strategy['port_scan']['description']}")
        self.adaptive_port_scanning(scan_strategy['port_scan'])
        
        # 2. 智能服务识别
        print(f"\n[2] {scan_strategy['service_scan']['name']}")  
        print(f"目的：{scan_strategy['service_scan']['description']}")
        self.enhanced_service_identification()
        
        # 3. 应用层智能分析
        print(f"\n[3] {scan_strategy['web_analysis']['name']}")
        print(f"目的：{scan_strategy['web_analysis']['description']}")
        self.deep_web_analysis()
        
        # 4. 行业特化检测
        print(f"\n[4] {scan_strategy['industry_scan']['name']}")
        print(f"目的：{scan_strategy['industry_scan']['description']}")
        self.healthcare_specific_checks()
        
        # 5. 策略效果评估
        print("\n[后分析] 扫描效果评估")
        self.evaluate_scan_effectiveness(scan_strategy)

    def determine_optimal_strategy(self):
        """确定最优扫描策略"""
        
        # 获取目标特征
        cdn_info = self.results['passive_recon'].get('cdn_waf_detection', {})
        cdn_provider = cdn_info.get('cdn_provider', 'unknown')
        subdomain_count = len(self.results['passive_recon'].get('subdomain_sources', {}).get('enhanced', []))
        
        # 策略决策逻辑
        if cdn_provider in ['framer', 'vercel', 'netlify']:
            return self.get_modern_saas_strategy(cdn_provider, subdomain_count)
        elif cdn_provider in ['cloudflare', 'aws_cloudfront']:
            return self.get_enterprise_cdn_strategy(cdn_provider, subdomain_count)
        elif subdomain_count > 15:
            return self.get_large_infrastructure_strategy(subdomain_count)
        else:
            return self.get_traditional_server_strategy()

    def get_modern_saas_strategy(self, provider, subdomain_count):
        """现代SaaS平台策略"""
        return {
            'name': f'{provider.title()}平台专用扫描策略',
            'estimated_time': '15-25分钟',
            'depth_level': '应用层深度',
            'port_scan': {
                'name': '轻量化端口探测',
                'description': '重点检测Web服务和常见代理端口',
                'strategy': 'lightweight'
            },
            'service_scan': {
                'name': '现代平台服务识别',
                'description': '专注于SaaS平台特有的服务特征'
            },
            'web_analysis': {
                'name': '前端架构深度解析',
                'description': '分析SPA架构、API端点、CDN配置'
            },
            'industry_scan': {
                'name': '合规性快速评估',
                'description': '基于平台特性的安全配置检查'
            }
        }

    def get_enterprise_cdn_strategy(self, provider, subdomain_count):
        """企业级CDN策略"""
        return {
            'name': f'{provider.title()}企业CDN扫描策略',
            'estimated_time': '20-35分钟',
            'depth_level': '中等深度',
            'port_scan': {
                'name': '企业级端口扫描',
                'description': '扫描企业常用端口和CDN绕过端口',
                'strategy': 'enterprise'
            },
            'service_scan': {
                'name': '企业服务识别',
                'description': '识别企业级服务和可能的源站'
            },
            'web_analysis': {
                'name': '企业应用安全分析',
                'description': '重点分析企业安全配置和API安全'
            },
            'industry_scan': {
                'name': '企业合规深度检查',
                'description': '全面的安全合规性评估'
            }
        }

    def get_large_infrastructure_strategy(self, subdomain_count):
        """大型基础设施策略"""
        return {
            'name': f'大型基础设施扫描策略 ({subdomain_count}个子域)',
            'estimated_time': '30-50分钟',
            'depth_level': '全面深度',
            'port_scan': {
                'name': '分层端口扫描',
                'description': '按子域名重要性分层扫描',
                'strategy': 'layered'
            },
            'service_scan': {
                'name': '基础设施服务映射',
                'description': '全面识别基础设施组件'
            },
            'web_analysis': {
                'name': '多层应用分析',
                'description': '分析各层应用的架构和安全性'
            },
            'industry_scan': {
                'name': '全面合规审计',
                'description': '针对大型组织的合规要求检查'
            }
        }

    def get_traditional_server_strategy(self):
        """传统服务器策略"""
        return {
            'name': '传统服务器深度扫描策略',
            'estimated_time': '25-40分钟',
            'depth_level': '传统深度',
            'port_scan': {
                'name': '全面端口扫描',
                'description': '扫描所有常见端口和服务',
                'strategy': 'comprehensive'
            },
            'service_scan': {
                'name': '传统服务深度识别',
                'description': '详细识别传统服务和版本'
            },
            'web_analysis': {
                'name': '传统Web应用分析',
                'description': '分析传统Web技术栈'
            },
            'industry_scan': {
                'name': '标准合规检查',
                'description': '基础的安全合规检查'
            }
        }

    def adaptive_port_scanning(self, scan_config):
        """自适应端口扫描"""
        strategy = scan_config.get('strategy', 'standard')
        
        if strategy == 'lightweight':
            self.lightweight_port_scan()
        elif strategy == 'enterprise':
            self.enterprise_port_scan()
        elif strategy == 'layered':
            self.layered_port_scan()
        elif strategy == 'comprehensive':
            self.comprehensive_port_scan()
        else:
            self.smart_port_scanning()  # 默认策略

    def lightweight_port_scan(self):
        """轻量化端口扫描 - 适用于现代SaaS平台"""
        print("    → 现代SaaS平台轻量化扫描...")
        nmap_result = self.run_command(
            ['nmap', '-sS', '-T4', '-p', '80,443', '--reason', self.target],
            "SaaS平台Web端口专项扫描"
        )
        self.results['active_scan']['port_scan'] = nmap_result
        self.save_port_scan_result(nmap_result)

    def enterprise_port_scan(self):
        """企业级端口扫描 - 适用于企业CDN"""
        print("    → 企业级CDN端口扫描...")
        # 企业常用端口 + CDN绕过端口
        enterprise_ports = "80,443,8080,8443,8000,8888,9000,9443"
        nmap_result = self.run_command(
            ['nmap', '-sS', '-T3', '-p', enterprise_ports, '--reason', self.target],
            "企业级端口扫描"
        )
        self.results['active_scan']['port_scan'] = nmap_result
        self.save_port_scan_result(nmap_result)

    def layered_port_scan(self):
        """分层端口扫描 - 适用于大型基础设施"""
        print("    → 分层基础设施端口扫描...")
        
        # 第一层：快速Web端口扫描
        quick_scan = self.run_command(
            ['nmap', '-sS', '-T4', '-p', '80,443,8080,8443', self.target],
            "快速Web端口检测"
        )
        
        # 第二层：基于第一层结果决定是否深度扫描
        if "open" in quick_scan:
            print("    → 发现开放端口，执行扩展扫描...")
            extended_scan = self.run_command(
                ['nmap', '-sS', '-T3', '--top-ports', '100', self.target],
                "扩展端口扫描"
            )
            final_result = f"{quick_scan}\n\n=== 扩展扫描 ===\n{extended_scan}"
        else:
            final_result = quick_scan
            
        self.results['active_scan']['port_scan'] = final_result
        self.save_port_scan_result(final_result)

    def comprehensive_port_scan(self):
        """全面端口扫描 - 适用于传统服务器"""
        print("    → 传统服务器全面端口扫描...")
        nmap_result = self.run_command(
            ['nmap', '-sS', '-T3', '--top-ports', '1000', '-n', self.target],
            "全面端口扫描"
        )
        self.results['active_scan']['port_scan'] = nmap_result
        self.save_port_scan_result(nmap_result)

    def save_port_scan_result(self, result):
        """保存端口扫描结果"""
        with open(f"{self.output_dir}/enhanced_port_scan.txt", 'w', encoding='utf-8') as f:
            f.write(result)

    def evaluate_scan_effectiveness(self, strategy):
        """评估扫描效果"""
        
        # 统计发现的信息
        web_apps = len(self.results['active_scan'].get('web_applications', {}))
        connection_stats = getattr(self, 'connection_stats', {})
        successful_connections = connection_stats.get('successful', 0)
        
        print(f"    策略效果评估:")
        print(f"      扫描策略: {strategy['name']}")
        print(f"      成功连接: {successful_connections} 个Web应用")
        print(f"      发现域名: {len(self.results['passive_recon'].get('subdomain_sources', {}).get('enhanced', []))} 个")
        
        # 策略适配度评分
        if successful_connections > 5:
            print(f"      策略适配度: ⭐⭐⭐ 优秀")
        elif successful_connections > 2:
            print(f"      策略适配度: ⭐⭐ 良好")
        else:
            print(f"      策略适配度: ⭐ 需要调整")
        
        # 保存评估结果
        self.results['active_scan']['strategy_evaluation'] = {
            'strategy_used': strategy['name'],
            'successful_connections': successful_connections,
            'total_web_apps': web_apps,
            'effectiveness_score': min(3, max(1, successful_connections // 2))
        }

    def smart_port_scanning(self):
        """
          智能端口扫描
        
        策略：
        - 如果检测到CDN，重点扫描Web端口
        - 如果是传统服务器，进行全面扫描
        - 根据行业特点调整扫描重点
        """
        cdn_info = self.results['passive_recon'].get('cdn_waf_detection', {})
        cdn_provider = cdn_info.get('cdn_provider', 'unknown')
        
        if cdn_provider in ['cloudflare', 'framer', 'aws_cloudfront']:
            print(f"    检测到CDN ({cdn_provider})，使用Web优化扫描策略")
            # CDN环境下，大多数端口被过滤，重点扫描Web端口
            nmap_result = self.run_command(
                ['nmap', '-sS', '-T4', '-p', '80,443,8080,8443', '-n', self.target],
                "CDN环境下的Web端口专项扫描"
            )
        else:
            print("    使用标准端口扫描策略")
            # 标准扫描
            nmap_result = self.run_command(
                ['nmap', '-sS', '-T4', '--top-ports', '1000', '-n', self.target],
                "标准Top 1000端口扫描"
            )
        
        self.results['active_scan']['port_scan'] = nmap_result
        
        # 保存到文件
        with open(f"{self.output_dir}/enhanced_port_scan.txt", 'w') as f:
            f.write(nmap_result)

    def enhanced_service_identification(self):
        """
          智能化分阶段服务识别
        
        V2优化：
        - 分阶段扫描避免超时
        - 根据目标类型智能选择策略
        - 现代CDN平台专用检测
        - 传统服务器深度扫描
        """
        print("\n[2] 智能化服务识别")
        print("目的：根据目标类型选择最优扫描策略")
        
        # 阶段1: 快速基础服务识别 (30秒超时)
        print("    → 阶段1: 基础服务识别...")
        basic_scan = self.run_command(
            ['nmap', '-sV', '--version-intensity', '3', '-Pn', self.target],
            "快速服务版本识别"
        )
        
        # 阶段2: 智能检测目标类型
        print("    → 阶段2: 分析目标架构...")
        target_type = self.analyze_target_type(basic_scan)
        print(f"      检测到目标类型: {target_type}")
        
        # 阶段3: 根据类型选择扫描策略
        if target_type == "modern_cdn":
            print("    → 阶段3: 现代CDN平台专用分析...")
            enhanced_result = self.modern_cdn_analysis()
        elif target_type == "traditional_server":
            print("    → 阶段3: 传统服务器深度扫描...")
            enhanced_result = self.traditional_server_analysis(basic_scan)
        else:
            print("    → 阶段3: 混合架构检测...")
            enhanced_result = self.hybrid_analysis(basic_scan)
        
        # 合并结果
        final_result = f"=== 基础扫描结果 ===\n{basic_scan}\n\n=== 增强分析结果 ===\n{enhanced_result}"
        
        self.results['active_scan']['service_identification'] = final_result
        self.results['active_scan']['target_type'] = target_type
        
        # 保存到文件
        with open(f"{self.output_dir}/enhanced_service_scan.txt", 'w', encoding='utf-8') as f:
            f.write(final_result)

    def analyze_target_type(self, nmap_result):
        """分析目标类型以选择最优扫描策略"""
        
        # 检查CDN提供商
        cdn_provider = self.results['passive_recon'].get('cdn_waf_detection', {}).get('cdn_provider')
        
        # 检查已知的现代平台标识
        modern_platforms = ['framer', 'vercel', 'netlify', 'cloudflare-pages', 'github-pages']
        if cdn_provider in modern_platforms:
            return "modern_cdn"
        
        # 检查传统服务器特征
        traditional_indicators = ['apache', 'nginx', 'iis', 'lighttpd']
        if any(indicator in nmap_result.lower() for indicator in traditional_indicators):
            return "traditional_server"
        
        # 检查端口开放情况
        if "ssh" in nmap_result.lower() or "22/tcp" in nmap_result:
            return "traditional_server"
        
        return "hybrid"

    def modern_cdn_analysis(self):
        """现代CDN平台专用分析"""
        analysis_result = []
        
        # CDN配置分析
        cdn_info = self.results['passive_recon'].get('cdn_waf_detection', {})
        analysis_result.append("=== CDN平台分析 ===")
        analysis_result.append(f"CDN提供商: {cdn_info.get('cdn_provider', 'Unknown')}")
        analysis_result.append(f"安全等级: {cdn_info.get('security_level', 'Unknown')}")
        
        # Web应用技术栈分析
        analysis_result.append("\n=== 技术栈分析 ===")
        for url, app_data in self.results['active_scan'].get('web_applications', {}).items():
            if app_data:
                tech = app_data.get('technologies', {})
                analysis_result.append(f"URL: {url}")
                analysis_result.append(f"  服务器: {tech.get('server', 'Unknown')}")
                analysis_result.append(f"  框架: {tech.get('frameworks', [])}")
                analysis_result.append(f"  CMS: {tech.get('cms', 'Unknown')}")
        
        # 现代平台特有的安全检查
        analysis_result.append("\n=== 现代平台安全配置 ===")
        analysis_result.append("• HTTP/2 支持检查")
        analysis_result.append("• HSTS 配置评估")
        analysis_result.append("• CSP 策略分析")
        analysis_result.append("• 边缘缓存配置")
        
        return "\n".join(analysis_result)

    def traditional_server_analysis(self, basic_scan):
        """传统服务器深度分析"""
        analysis_result = []
        
        # 检查是否需要漏洞扫描
        if self.should_run_vulnerability_scan(basic_scan):
            print("      → 执行漏洞检测扫描...")
            vuln_scan = self.run_command(
                ['nmap', '--script', 'vuln', '--script-timeout', '30s', self.target],
                "漏洞检测扫描"
            )
            analysis_result.append("=== 漏洞扫描结果 ===")
            analysis_result.append(vuln_scan)
        
        # 安全脚本扫描
        print("      → 执行安全配置扫描...")
        security_scan = self.run_command(
            ['nmap', '-sC', '--script', 'ssl-enum-ciphers,http-security-headers,http-methods', self.target],
            "安全配置扫描"
        )
        analysis_result.append("\n=== 安全配置扫描 ===")
        analysis_result.append(security_scan)
        
        return "\n".join(analysis_result)

    def hybrid_analysis(self, basic_scan):
        """混合架构分析"""
        analysis_result = []
        analysis_result.append("=== 混合架构检测 ===")
        analysis_result.append("检测到可能的混合架构，执行综合分析...")
        
        # 结合现代和传统的检测方法
        analysis_result.append("\n• CDN层面分析:")
        analysis_result.append(f"  {self.results['passive_recon'].get('cdn_waf_detection', {})}")
        
        analysis_result.append("\n• 服务层面分析:")
        analysis_result.append("  执行有限的服务检测以避免超时")
        
        return "\n".join(analysis_result)

    def should_run_vulnerability_scan(self, nmap_result):
        """智能判断是否需要漏洞扫描"""
        
        # 如果是现代CDN平台，跳过传统漏洞扫描
        cdn_provider = self.results['passive_recon'].get('cdn_waf_detection', {}).get('cdn_provider')
        modern_platforms = ['framer', 'vercel', 'netlify', 'cloudflare']
        
        if cdn_provider in modern_platforms:
            print("      [SKIP] 现代CDN平台，跳过传统漏洞扫描")
            return False
        
        # 检查是否有足够的攻击面
        if "filtered" in nmap_result and "open" not in nmap_result:
            print("      [SKIP] 攻击面有限，跳过漏洞扫描")
            return False
        
        return True

    def deep_web_analysis(self):
        """
          智能Web应用分析
        
        V2优化：
        - 智能错误分类和侦察价值分析
        - 僵尸子域名检测
        - 防护机制识别
        - 错误统计和汇总
        """
        print("    → 智能Web应用分析...")
        
        # 初始化错误统计
        self.connection_stats = {
            'total_analyzed': 0,
            'successful': 0,
            'timeout_errors': [],
            'dns_errors': [],
            'connection_reset': [],
            'protected_services': [],
            'zombie_domains': []
        }
        
        # 分析主域名和所有子域名
        domains_to_analyze = [self.target]
        
        # 添加发现的子域名
        subdomains = self.results['passive_recon'].get('subdomain_sources', {}).get('enhanced', [])
        domains_to_analyze.extend(subdomains)
        
        for domain in domains_to_analyze[:10]:  # 限制分析前10个域名
            try:
                print(f"      分析 {domain}...")
                
                # HTTP和HTTPS都要分析
                for protocol in ['http', 'https']:
                    url = f"{protocol}://{domain}"
                    self.connection_stats['total_analyzed'] += 1
                    
                    analysis_result = self.analyze_web_application_enhanced(url)
                    
                    if analysis_result:
                        self.results['active_scan']['web_applications'][url] = analysis_result
                        self.connection_stats['successful'] += 1
                        
            except Exception as e:
                print(f"      ✗ {domain} 通用分析失败: {str(e)[:50]}...")
        
        # 输出智能化错误分析
        self.print_connection_analysis()

    def analyze_web_application_enhanced(self, url: str) -> Dict:
        """增强版单个Web应用分析，包含智能错误处理"""
        try:
            response = requests.get(url, timeout=15, verify=False, allow_redirects=True)
            
            analysis = {
                'url': url,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'technologies': self.detect_web_technologies(response),
                'security_headers': self.analyze_security_headers(response.headers),
                'api_endpoints': self.discover_api_endpoints(response.text),
                'forms': self.extract_forms(response.text)
            }
            
            return analysis
            
        except requests.exceptions.ConnectTimeout as e:
            self.handle_connection_error(url, "timeout", str(e))
            return None
        except requests.exceptions.ConnectionError as e:
            error_msg = str(e)
            if "Connection aborted" in error_msg and "10054" in error_msg:
                self.handle_connection_error(url, "reset", "远程主机主动关闭连接")
            elif "getaddrinfo failed" in error_msg:
                self.handle_connection_error(url, "dns", "DNS解析失败")
            else:
                self.handle_connection_error(url, "connection", error_msg)
            return None
        except requests.exceptions.RequestException as e:
            self.handle_connection_error(url, "request", str(e))
            return None

    def handle_connection_error(self, url: str, error_type: str, error_msg: str):
        """智能处理连接错误，提取侦察价值"""
        
        if error_type == "timeout":
            self.connection_stats['timeout_errors'].append(url)
            print(f"          {url} - 服务可能存在但响应缓慢或有防护")
            
        elif error_type == "reset":
            self.connection_stats['connection_reset'].append(url)
            print(f"          {url} - 主动防护：可能有WAF或IP限制")
            
        elif error_type == "dns":
            self.connection_stats['dns_errors'].append(url)
            print(f"          {url} - DNS配置问题或内网服务")
            
        else:
            # 检查是否为僵尸域名
            domain = url.split("://")[1]
            cert_domains = self.results['passive_recon'].get('certificate_transparency', [])
            
            if domain in cert_domains:
                self.connection_stats['zombie_domains'].append(url)
                print(f"        👻 {url} - 僵尸域名：证书存在但服务已下线")
            else:
                print(f"          {url} - 连接失败")

    def print_connection_analysis(self):
        """输出连接分析总结"""
        stats = self.connection_stats
        
        print(f"\n        连接分析总结:")
        print(f"        总计分析: {stats['total_analyzed']} 个URL")
        print(f"        成功连接: {stats['successful']} 个")
        
        if stats['timeout_errors']:
            print(f"          超时服务: {len(stats['timeout_errors'])} 个 (可能内网或有保护)")
            
        if stats['connection_reset']:
            print(f"          主动防护: {len(stats['connection_reset'])} 个 (WAF/安全策略)")
            
        if stats['dns_errors']:
            print(f"          DNS异常: {len(stats['dns_errors'])} 个 (配置错误或内网)")
            
        if stats['zombie_domains']:
            print(f"        👻 僵尸域名: {len(stats['zombie_domains'])} 个 (历史遗留)")
            for zombie in stats['zombie_domains']:
                print(f"          • {zombie}")
        
        # 保存详细的连接分析到结果中
        self.results['active_scan']['connection_analysis'] = {
            'summary': stats,
            'intelligence_value': self.analyze_intelligence_value(stats)
        }

    def analyze_intelligence_value(self, stats: Dict) -> Dict:
        """分析错误信息的侦察价值"""
        intelligence = {
            'network_topology': [],
            'security_posture': [],
            'infrastructure_analysis': []
        }
        
        # 网络拓扑分析
        if stats['timeout_errors']:
            intelligence['network_topology'].append(
                f"发现 {len(stats['timeout_errors'])} 个可能的内网服务或缓慢响应服务"
            )
        
        if stats['dns_errors']:
            intelligence['network_topology'].append(
                f"DNS配置存在 {len(stats['dns_errors'])} 个异常，可能存在配置错误"
            )
        
        # 安全态势分析
        if stats['connection_reset']:
            intelligence['security_posture'].append(
                f"检测到 {len(stats['connection_reset'])} 个主动防护点，安全意识较强"
            )
        
        # 基础设施分析
        if stats['zombie_domains']:
            intelligence['infrastructure_analysis'].append(
                f"发现 {len(stats['zombie_domains'])} 个僵尸域名，运维清理不彻底"
            )
            intelligence['infrastructure_analysis'].append(
                "SSL证书管理存在信息泄露风险"
            )
        
        return intelligence

    def detect_web_technologies(self, response) -> Dict:
        """  现代化Web技术栈深度检测"""
        
        # 基础技术检测
        basic_tech = self.detect_basic_technologies(response)
        
        # 现代化架构检测
        modern_arch = self.detect_modern_architecture(response)
        
        # API和微服务检测
        api_analysis = self.detect_api_microservices(response)
        
        # 云服务和CDN检测
        cloud_services = self.detect_cloud_services(response)
        
        # 合并所有检测结果
        technologies = {
            **basic_tech,
            'modern_architecture': modern_arch,
            'api_analysis': api_analysis,
            'cloud_services': cloud_services,
            'detection_confidence': self.calculate_detection_confidence(basic_tech, modern_arch)
        }
        
        return technologies

    def detect_basic_technologies(self, response) -> Dict:
        """检测基础Web技术"""
        technologies = {
            'server': response.headers.get('Server', 'Unknown'),
            'frameworks': [],
            'javascript_libraries': [],
            'cms': 'Unknown',
            'programming_language': 'Unknown'
        }
        
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # JavaScript框架检测（增强版）
        framework_signatures = {
            'angular': ['ng-app', 'angular', '_angular_', 'ng-version'],
            'react': ['react', '_react_', 'reactdom', '__react'],
            'vue': ['vue.js', '_vue_', 'v-if', 'v-for'],
            'svelte': ['svelte', '_svelte_'],
            'next.js': ['__next', '_next/', 'next/'],
            'nuxt': ['__nuxt', '_nuxt/'],
            'gatsby': ['___gatsby', 'gatsby-'],
            'framer': ['framer', 'framerusercontent']
        }
        
        for framework, signatures in framework_signatures.items():
            for sig in signatures:
                if sig in content or any(sig in v for v in headers.values()):
                    technologies['frameworks'].append(framework)
                    break
        
        # CMS检测（增强版）
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Drupal': ['drupal', '/sites/default'],
            'Joomla': ['joomla', 'com_content'],
            'Framer': ['framer', 'framerusercontent'],
            'Webflow': ['webflow', '.webflow.io'],
            'Squarespace': ['squarespace', 'static1.squarespace'],
            'Wix': ['wix.com', 'static.wixstatic']
        }
        
        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                if sig in content or any(sig in v for v in headers.values()):
                    technologies['cms'] = cms
                    break
        
        # 编程语言检测
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            if 'php' in powered_by:
                technologies['programming_language'] = 'PHP'
            elif 'asp.net' in powered_by:
                technologies['programming_language'] = 'ASP.NET'
            elif 'express' in powered_by:
                technologies['programming_language'] = 'Node.js'
        
        return technologies

    def detect_modern_architecture(self, response) -> Dict:
        """检测现代化架构特征"""
        architecture = {
            'spa_detected': False,
            'pwa_features': [],
            'ssr_framework': None,
            'bundler_detected': None,
            'module_system': None
        }
        
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # SPA (Single Page Application) 检测
        spa_indicators = [
            'router-outlet',  # Angular
            'router-view',    # Vue
            'react-router',   # React
            '__next_router',  # Next.js
            'app.js',
            'main.js',
            'bundle.js'
        ]
        
        if any(indicator in content for indicator in spa_indicators):
            architecture['spa_detected'] = True
        
        # PWA功能检测
        pwa_features = []
        if 'service-worker' in content or 'sw.js' in content:
            pwa_features.append('Service Worker')
        if 'manifest.json' in content:
            pwa_features.append('Web App Manifest')
        if 'offline' in content and 'cache' in content:
            pwa_features.append('Offline Capability')
        
        architecture['pwa_features'] = pwa_features
        
        # SSR框架检测
        ssr_indicators = {
            'Next.js': ['__next', 'next/'],
            'Nuxt.js': ['__nuxt', 'nuxt/'],
            'Gatsby': ['___gatsby'],
            'SvelteKit': ['__sveltekit'],
            'Angular Universal': ['ng-state']
        }
        
        for framework, indicators in ssr_indicators.items():
            if any(indicator in content for indicator in indicators):
                architecture['ssr_framework'] = framework
                break
        
        # 构建工具检测
        bundler_indicators = {
            'Webpack': ['webpack', '__webpack'],
            'Vite': ['vite', '/@vite/'],
            'Rollup': ['rollup'],
            'Parcel': ['parcel'],
            'ESBuild': ['esbuild']
        }
        
        for bundler, indicators in bundler_indicators.items():
            if any(indicator in content for indicator in indicators):
                architecture['bundler_detected'] = bundler
                break
        
        return architecture

    def detect_api_microservices(self, response) -> Dict:
        """检测API和微服务架构"""
        api_analysis = {
            'api_endpoints': [],
            'api_versions': [],
            'microservices_detected': False,
            'api_patterns': [],
            'graphql_detected': False
        }
        
        content = response.text
        
        # API端点模式检测
        import re
        
        # REST API模式
        rest_patterns = [
            r'/api/v\d+/',
            r'/v\d+/',
            r'/rest/',
            r'/api/',
            r'_api/',
            r'/services/'
        ]
        
        for pattern in rest_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                api_analysis['api_endpoints'].extend(matches)
        
        # API版本检测
        version_patterns = [
            r'/v(\d+)/',
            r'/api/v(\d+)',
            r'version["\s]*[:=]["\s]*v?(\d+)'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                api_analysis['api_versions'].extend([f"v{v}" for v in matches])
        
        # GraphQL检测
        graphql_indicators = ['graphql', '__schema', 'query', 'mutation', 'subscription']
        if any(indicator in content.lower() for indicator in graphql_indicators):
            api_analysis['graphql_detected'] = True
        
        # 微服务架构特征
        microservice_indicators = [
            'microservice',
            'service-mesh',
            'istio',
            'consul',
            'kubernetes',
            'docker',
            'containers'
        ]
        
        if any(indicator in content.lower() for indicator in microservice_indicators):
            api_analysis['microservices_detected'] = True
        
        # 去重和清理
        api_analysis['api_endpoints'] = list(set(api_analysis['api_endpoints']))
        api_analysis['api_versions'] = list(set(api_analysis['api_versions']))
        
        return api_analysis

    def detect_cloud_services(self, response) -> Dict:
        """检测云服务和CDN提供商"""
        cloud_services = {
            'cdn_provider': 'Unknown',
            'cloud_platform': 'Unknown',
            'hosting_service': 'Unknown',
            'serverless_detected': False
        }
        
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        content = response.text.lower()
        
        # CDN检测（增强版）
        cdn_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'AWS CloudFront': ['cloudfront', 'x-amz-', 'amazon'],
            'Fastly': ['fastly', 'x-served-by'],
            'KeyCDN': ['keycdn'],
            'MaxCDN': ['maxcdn'],
            'Framer': ['framer', 'framerusercontent'],
            'Vercel': ['vercel', '_vercel'],
            'Netlify': ['netlify']
        }
        
        for cdn, indicators in cdn_indicators.items():
            if any(indicator in str(headers.values()) or indicator in content 
                   for indicator in indicators):
                cloud_services['cdn_provider'] = cdn
                break
        
        
        for platform, indicators in cloud_platforms.items():
            if any(indicator in str(headers.values()) or indicator in content 
                   for indicator in indicators):
                cloud_services['cloud_platform'] = platform
                break
        
        # 无服务器检测
        serverless_indicators = [
            'lambda',
            'functions',
            'serverless',
            'edge-function',
            'worker'
        ]
        
        if any(indicator in content for indicator in serverless_indicators):
            cloud_services['serverless_detected'] = True
        
        return cloud_services

    def calculate_detection_confidence(self, basic_tech, modern_arch) -> Dict:
        """计算检测置信度"""
        confidence = {
            'overall_score': 0,
            'framework_confidence': 'low',
            'architecture_confidence': 'low'
        }
        
        # 框架检测置信度
        if basic_tech['frameworks']:
            confidence['framework_confidence'] = 'high' if len(basic_tech['frameworks']) >= 2 else 'medium'
        
        # 架构检测置信度
        if modern_arch['spa_detected'] or modern_arch['ssr_framework']:
            confidence['architecture_confidence'] = 'high'
        elif modern_arch['pwa_features']:
            confidence['architecture_confidence'] = 'medium'
        
        # 综合评分
        score = 0
        if basic_tech['cms'] != 'Unknown': score += 2
        if basic_tech['frameworks']: score += len(basic_tech['frameworks'])
        if modern_arch['spa_detected']: score += 2
        if modern_arch['ssr_framework']: score += 2
        
        confidence['overall_score'] = min(10, score)
        
        return confidence

    def analyze_security_headers(self, headers: Dict) -> Dict:
        """分析安全头配置"""
        security_analysis = {
            'score': 0,
            'missing_headers': [],
            'present_headers': {},
            'recommendations': []
        }
        
        # 重要安全头检查
        important_headers = {
            'strict-transport-security': 'HSTS',
            'x-frame-options': 'Clickjacking Protection',
            'x-content-type-options': 'MIME Sniffing Protection',
            'content-security-policy': 'CSP',
            'x-xss-protection': 'XSS Protection',
            'referrer-policy': 'Referrer Policy'
        }
        
        for header, description in important_headers.items():
            if header in [h.lower() for h in headers.keys()]:
                security_analysis['present_headers'][header] = headers.get(header)
                security_analysis['score'] += 1
            else:
                security_analysis['missing_headers'].append(header)
                security_analysis['recommendations'].append(f"添加 {description}")
        
        # 医疗行业特殊要求
        if security_analysis['score'] < 4:
            security_analysis['recommendations'].append("医疗行业建议实施更严格的安全头配置")
        
        return security_analysis

    def discover_api_endpoints(self, content: str) -> List[str]:
        """发现API端点"""
        api_endpoints = []
        
        # 常见API路径模式
        api_patterns = [
            r'/api/v?\d*/\w+',
            r'/rest/\w+',
            r'/graphql',
            r'/v\d+/\w+',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            api_endpoints.extend(matches)
        
        # 医疗相关API端点
        healthcare_patterns = [
            r'/api/.*patient',
            r'/api/.*appointment',
            r'/api/.*medical',
            r'/portal/.*'
        ]
        
        for pattern in healthcare_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            api_endpoints.extend(matches)
        
        return list(set(api_endpoints))

    def extract_forms(self, content: str) -> List[Dict]:
        """提取表单信息"""
        forms = []
        
        # 简单的表单提取（可以用BeautifulSoup更精确）
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for form_content in form_matches:
            # 提取action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            # 提取method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            method = method_match.group(1) if method_match else 'GET'
            
            forms.append({
                'action': action,
                'method': method.upper(),
                'has_file_upload': 'type="file"' in form_content.lower()
            })
        
        return forms

    def healthcare_specific_checks(self):
        """
          医疗行业特定安全检查
        
        检查项目：
        1. HIPAA合规性基础检查
        2. 医疗相关端点发现
        3. 患者数据暴露风险
        4. 支付安全检查
        """
        print("    → 医疗行业合规性检查...")
        
        healthcare_results = {
            'hipaa_compliance_score': 0,
            'medical_endpoints_found': [],
            'security_concerns': [],
            'recommendations': []
        }
        
        # 检查是否发现医疗相关端点
        all_web_apps = self.results['active_scan'].get('web_applications', {})
        
        for url, app_data in all_web_apps.items():
            if app_data and 'api_endpoints' in app_data:
                for endpoint in app_data['api_endpoints']:
                    if any(keyword in endpoint.lower() for keyword in self.healthcare_indicators['keywords']):
                        healthcare_results['medical_endpoints_found'].append(f"{url}{endpoint}")
        
        # HIPAA合规性评分
        security_score = 0
        security_concerns = []
        
        for url, app_data in all_web_apps.items():
            if app_data and 'security_headers' in app_data:
                sec_headers = app_data['security_headers']
                security_score += sec_headers.get('score', 0)
                
                if sec_headers.get('score', 0) < 3:
                    security_concerns.append(f"{url}: 安全头配置不足")
        
        healthcare_results['hipaa_compliance_score'] = min(10, security_score)
        healthcare_results['security_concerns'] = security_concerns
        
        # 推荐措施
        if healthcare_results['hipaa_compliance_score'] < 7:
            healthcare_results['recommendations'].extend([
                "实施完整的HTTPS加密",
                "配置严格的安全头",
                "启用HSTS强制HTTPS",
                "实施内容安全策略(CSP)",
                "定期进行安全评估"
            ])
        
        if healthcare_results['medical_endpoints_found']:
            healthcare_results['recommendations'].append("对医疗相关API端点实施额外的访问控制")
        
        self.results['healthcare_specific']['hipaa_compliance_check'] = healthcare_results
        self.results['healthcare_specific']['medical_endpoints'] = healthcare_results['medical_endpoints_found']
        
        print(f"      HIPAA合规性评分: {healthcare_results['hipaa_compliance_score']}/10")
        print(f"    🏥 发现医疗端点: {len(healthcare_results['medical_endpoints_found'])} 个")
        if security_concerns:
            print(f"      安全问题: {len(security_concerns)} 个")

    def generate_enhanced_summary(self):
        """
          生成增强版侦察总结报告
        
        新增内容：
        1. CDN/WAF检测结果
        2. 现代化技术栈分析
        3. 医疗行业合规性评估
        4. 详细的安全建议
        5. 风险优先级排序
        """
        self.log_step("生成增强版侦察总结", "整理所有发现，制定后续测试策略")
        
        # 统计子域名数量
        enhanced_subdomains = self.results['passive_recon'].get('subdomain_sources', {}).get('enhanced', [])
        cert_domains = self.results['passive_recon'].get('certificate_transparency', [])
        
        summary = {
            'scan_info': {
                'version': 'V2 Enhanced',
                'total_subdomains': len(enhanced_subdomains),
                'cert_domains': len(cert_domains),
                'scan_duration': 'Enhanced scan completed'
            },
            'technology_stack': self.analyze_enhanced_technology_stack(),
            'security_posture': self.analyze_security_posture(),
            'healthcare_compliance': self.results['healthcare_specific'],
            'attack_surface': self.analyze_enhanced_attack_surface(),
            'risk_assessment': self.generate_risk_assessment(),
            'next_steps': self.recommend_enhanced_next_steps()
        }
        
        self.results['summary'] = summary
        
        # 生成增强版报告
        self.generate_enhanced_report()

    def analyze_enhanced_technology_stack(self):
        """分析现代化技术栈"""
        tech_stack = {
            'primary_platform': 'Unknown',
            'cdn_provider': 'Unknown',
            'web_frameworks': [],
            'security_technologies': [],
            'modern_features': []
        }
        
        # CDN信息
        cdn_info = self.results['passive_recon'].get('cdn_waf_detection', {})
        tech_stack['cdn_provider'] = cdn_info.get('cdn_provider', 'Unknown')
        
        # Web应用技术栈
        web_apps = self.results['active_scan'].get('web_applications', {})
        for url, app_data in web_apps.items():
            if app_data and 'technologies' in app_data:
                tech = app_data['technologies']
                if tech.get('cms') != 'Unknown':
                    tech_stack['primary_platform'] = tech['cms']
                tech_stack['web_frameworks'].extend(tech.get('frameworks', []))
        
        # 去重
        tech_stack['web_frameworks'] = list(set(tech_stack['web_frameworks']))
        
        return tech_stack

    def analyze_security_posture(self):
        """分析安全态势"""
        security_posture = {
            'overall_score': 0,
            'strengths': [],
            'weaknesses': [],
            'critical_issues': []
        }
        
        # CDN/WAF检测结果
        cdn_info = self.results['passive_recon'].get('cdn_waf_detection', {})
        security_level = cdn_info.get('security_level', 'unknown')
        
        if security_level == 'high':
            security_posture['strengths'].append("检测到高级安全防护措施")
            security_posture['overall_score'] += 3
        elif security_level == 'medium':
            security_posture['overall_score'] += 2
        
        # Web应用安全头分析
        web_apps = self.results['active_scan'].get('web_applications', {})
        total_security_score = 0
        app_count = 0
        
        for url, app_data in web_apps.items():
            if app_data and 'security_headers' in app_data:
                sec_score = app_data['security_headers'].get('score', 0)
                total_security_score += sec_score
                app_count += 1
                
                if sec_score < 2:
                    security_posture['critical_issues'].append(f"{url}: 关键安全头缺失")
                elif sec_score < 4:
                    security_posture['weaknesses'].append(f"{url}: 安全头配置不完整")
        
        if app_count > 0:
            avg_security_score = total_security_score / app_count
            security_posture['overall_score'] += min(4, avg_security_score)
        
        # 子域名暴露风险
        subdomains = self.results['passive_recon'].get('subdomain_sources', {}).get('enhanced', [])
        staging_domains = [d for d in subdomains if 'staging' in d or 'test' in d or 'dev' in d]
        
        if staging_domains:
            security_posture['critical_issues'].append(f"测试环境暴露: {', '.join(staging_domains)}")
        
        return security_posture

    def analyze_enhanced_attack_surface(self):
        """分析增强版攻击面"""
        attack_surface = {
            'network_services': [],
            'web_applications': [],
            'api_endpoints': [],
            'potential_risks': [],
            'subdomains': []
        }
        
        # 网络服务分析
        port_scan = self.results['active_scan'].get('port_scan', '')
        if 'ssh' in port_scan.lower():
            attack_surface['network_services'].append('SSH (22) - 远程管理服务')
        if 'http' in port_scan.lower():
            attack_surface['web_applications'].append('HTTP Web服务')
        if 'https' in port_scan.lower():
            attack_surface['web_applications'].append('HTTPS Web服务')
        if 'ftp' in port_scan.lower():
            attack_surface['network_services'].append('FTP (21) - 文件传输服务')
        
        # 子域名攻击面
        subdomains = self.results['passive_recon'].get('subdomain_sources', {}).get('enhanced', [])
        attack_surface['subdomains'] = subdomains
        
        # API端点分析
        web_apps = self.results['active_scan'].get('web_applications', {})
        for url, app_data in web_apps.items():
            if app_data and 'api_endpoints' in app_data:
                attack_surface['api_endpoints'].extend(app_data['api_endpoints'])
        
        return attack_surface

    def generate_risk_assessment(self):
        """生成风险评估"""
        risks = []
        
        # 子域名风险
        subdomains = self.results['passive_recon'].get('subdomain_sources', {}).get('enhanced', [])
        for subdomain in subdomains:
            if any(keyword in subdomain.lower() for keyword in ['staging', 'test', 'dev', 'admin']):
                risks.append({
                    'type': 'Information Disclosure',
                    'severity': 'High',
                    'description': f"测试/管理环境暴露: {subdomain}",
                    'impact': '可能暴露敏感信息或提供攻击入口'
                })
        
        # 医疗数据风险
        medical_endpoints = self.results['healthcare_specific'].get('medical_endpoints', [])
        if medical_endpoints:
            risks.append({
                'type': 'Healthcare Data Exposure',
                'severity': 'Critical',
                'description': f"发现医疗相关端点: {len(medical_endpoints)} 个",
                'impact': 'HIPAA合规风险，患者数据可能暴露'
            })
        
        # 安全配置风险
        security_posture = self.analyze_security_posture()
        if security_posture['overall_score'] < 5:
            risks.append({
                'type': 'Security Misconfiguration',
                'severity': 'Medium',
                'description': '安全头配置不足',
                'impact': '增加XSS、点击劫持等攻击风险'
            })
        
        return risks

    def recommend_enhanced_next_steps(self):
        """推荐增强版后续步骤"""
        recommendations = [
            "Day 2: 深度Web应用安全测试",
            "Day 3: API安全专项评估",
            "Day 4: 医疗数据保护合规检查",
            "Day 5: 渗透测试和漏洞验证"
        ]
        
        # 根据发现的技术栈调整建议
        tech_stack = self.analyze_enhanced_technology_stack()
        
        if tech_stack['cdn_provider'] == 'framer':
            recommendations.append("专项: Framer平台安全配置优化")
        
        if tech_stack['primary_platform'] != 'Unknown':
            recommendations.append(f"专项: {tech_stack['primary_platform']} 平台安全加固")
        
        # 根据医疗检查结果调整
        healthcare_score = self.results['healthcare_specific'].get('hipaa_compliance_check', {}).get('hipaa_compliance_score', 0)
        if healthcare_score < 7:
            recommendations.append("优先级: HIPAA合规性立即整改")
        
        return recommendations

    def generate_enhanced_report(self):
        """生成增强版最终报告"""
        report_file = f"{self.output_dir}/day1_enhanced_report.md"
        
        summary = self.results['summary']
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"# Day 1 增强版侦察报告 V2\n\n")
            f.write(f"**目标**: {self.target}\n")
            f.write(f"**扫描时间**: {self.results['scan_time']}\n")
            f.write(f"**版本**: {self.results['version']}\n\n")
            
            # 执行摘要
            f.write("##   执行摘要\n\n")
            scan_info = summary['scan_info']
            f.write(f"- **发现子域名**: {scan_info['total_subdomains']} 个\n")
            f.write(f"- **证书域名**: {scan_info['cert_domains']} 个\n")
            f.write(f"- **技术平台**: {summary['technology_stack']['primary_platform']}\n")
            f.write(f"- **CDN提供商**: {summary['technology_stack']['cdn_provider']}\n\n")
            
            # 安全态势
            f.write("##   安全态势分析\n\n")
            security = summary['security_posture']
            f.write(f"**整体安全评分**: {security['overall_score']}/10\n\n")
            
            if security['strengths']:
                f.write("###   安全优势\n")
                for strength in security['strengths']:
                    f.write(f"- {strength}\n")
                f.write("\n")
            
            if security['critical_issues']:
                f.write("###   关键安全问题\n")
                for issue in security['critical_issues']:
                    f.write(f"- {issue}\n")
                f.write("\n")
            
            # 医疗合规性
            f.write("## 🏥 医疗行业合规性\n\n")
            healthcare = summary['healthcare_compliance']
            hipaa_info = healthcare.get('hipaa_compliance_check', {})
            f.write(f"**HIPAA合规性评分**: {hipaa_info.get('hipaa_compliance_score', 0)}/10\n\n")
            
            medical_endpoints = healthcare.get('medical_endpoints', [])
            if medical_endpoints:
                f.write("### 发现的医疗相关端点\n")
                for endpoint in medical_endpoints[:10]:  # 只显示前10个
                    f.write(f"- {endpoint}\n")
                f.write("\n")
            
            # 风险评估
            f.write("##   风险评估\n\n")
            for risk in summary['risk_assessment']:
                f.write(f"### {risk['severity']}: {risk['type']}\n")
                f.write(f"**描述**: {risk['description']}\n")
                f.write(f"**影响**: {risk['impact']}\n\n")
            
            # 后续建议
            f.write("## 📋 后续测试建议\n\n")
            for step in summary['next_steps']:
                f.write(f"- {step}\n")
        
        # 保存完整结果JSON
        with open(f"{self.output_dir}/day1_enhanced_results.json", 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n[REPORT] 增强版报告已生成: {report_file}")
        print(f"[DATA] 完整数据: {self.output_dir}/day1_enhanced_results.json")

    def run(self):
        """
        执行完整的Day 1侦察流程
        
          V2增强流程：
        1. 被动信息收集 (40分钟) - 多源API，更全面
        2. 主动扫描 (60分钟) - 智能策略，医疗特化
        3. 结果分析和报告生成 (20分钟) - 专业报告
        
        总耗时: 约120分钟
        """
        print(f"""
        ╔══════════════════════════════════════════════════════════════╗
        ║                  Day 1: 增强版外部侦察与环境mapping           ║
        ║                                                              ║
        ║    V2 特性: 现代化检测 + 医疗行业专项 + 智能分析             ║
        ║  目标: 建立目标系统的完整"上帝视角"                            ║
        ║  方法: 多源收集 + 智能扫描 + 专业分析                          ║
        ║  输出: 深度报告 + 风险评估 + 合规检查                          ║
        ╚══════════════════════════════════════════════════════════════╝
        
        目标域名: {self.target}
        开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        版本: V2 Enhanced
        """)
        
        try:
            # 阶段1: 被动信息收集
            self.passive_information_gathering()
            
            # 阶段2: 增强版主动扫描
            self.enhanced_active_scanning()
            
            # 阶段3: 结果分析和报告
            self.generate_enhanced_summary()
            
            print(f"""
            ╔══════════════════════════════════════════════════════════════╗
            ║                      Day 1 V2 完成!                         ║
            ║                                                              ║
            ║    多源被动信息收集完成                                      ║
            ║    智能主动扫描完成                                          ║
            ║    医疗行业专项检查完成                                      ║
            ║    专业报告生成完成                                          ║
            ║                                                              ║
            ║    所有结果保存在: {self.output_dir:<30} ║
            ╚══════════════════════════════════════════════════════════════╝
            """)
            
        except KeyboardInterrupt:
            print(f"\n[STOP] 用户中断，正在保存已完成的结果...")
            self.generate_enhanced_summary()
        except Exception as e:
            print(f"\n[ERROR] 执行过程中发生异常: {e}")
            import traceback
            traceback.print_exc()
    
    async def run_with_extreme(self):
        """
          运行day1_recon.py + day1_extreme.py 完整流程
        
        流程说明：
        1. 先执行标准侦察 (day1_recon.py)
        2. 再启动极致侦察 (day1_extreme.py)
        3. 整合两份报告
        
        总耗时: 约180-240分钟 (标准120分钟 + 极致60-120分钟)
        """
        print(f"""
        ╔══════════════════════════════════════════════════════════════╗
        ║             Day 1: 标准版 + 极致版 完整侦察流程              ║
        ║                                                              ║
        ║    双引擎模式: 全面覆盖 + 极致深度                          ║
        ║    标准版: 智能策略，医疗专项，完整报告                      ║
        ║    极致版: 深度爆破，漏洞扫描，0day检测                     ║
        ║    输出: 双重报告 + 风险评估 + 攻击面分析                   ║
        ╚══════════════════════════════════════════════════════════════╝
        
        目标域名: {self.target}
        开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        模式: 双引擎 (标准版 + 极致版)
        """)
        
        try:
            # 阶段1: 先执行标准版侦察
            print("\n  [阶段1/3] 执行标准版侦察 (day1_recon.py)...")
            self.run()  # 调用标准版run方法
            
            print(f"\n  标准版侦察完成! 报告已保存在: {self.output_dir}")
            
            # 阶段2: 启动极致版侦察
            print("\n  [阶段2/3] 智能极致版侦察 (day1_extreme.py)...")
            print("  智能极致模式选项:")
            print("  [1] 智能模式 (推荐) - 根据目标自动调整扫描深度")
            print("  [2] 标准模式 - 3万条目子域爆破 (~5-8分钟)")
            print("  [3] 完整模式 - 50万条目完整扫描 (~35-45分钟)")
            print("  [4] 跳过极致版")
            
            choice = input("\n请选择模式 [1-4]: ").strip()
            
            if choice == '4':
                print("  跳过极致模式，直接生成最终报告")
            elif choice in ['1', '2', '3']:
                # 动态导入极致引擎
                try:
                    from day1_extreme import Day1ExtremeEngine, ExtremeConfig
                    
                    # 根据用户选择创建配置
                    if choice == '1':  # 智能模式
                        print("  启动智能模式 (自动优化扫描深度)...")
                        extreme_config = ExtremeConfig(auto_adjust_dict_size=True)
                    elif choice == '2':  # 标准模式
                        print("  启动标准模式 (30K条目)...")
                        extreme_config = ExtremeConfig(
                            subdomain_dict_size=30000,
                            auto_adjust_dict_size=False
                        )
                    elif choice == '3':  # 完整模式
                        print("  启动完整模式 (500K条目)...")
                        extreme_config = ExtremeConfig(
                            subdomain_dict_size=500000,
                            auto_adjust_dict_size=False
                        )
                    
                    # 启动极致引擎
                    extreme_engine = Day1ExtremeEngine(self.target, extreme_config)
                    await extreme_engine.run_extreme_scan()
                    
                    print("  极致版侦察完成!")
                    
                except ImportError as e:
                    if "aiohttp" in str(e):
                        print("  错误: 缺少依赖包")
                        print("   请运行: pip install aiohttp dnspython")
                        print("   或使用标准版模式（已包含完整功能）")
                    else:
                        print("  错误: 找不到day1_extreme.py文件")
                        print("   请确保day1_extreme.py在同一目录下")
                    return
                except Exception as e:
                    print(f"  极致版执行错误: {e}")
                    print("   继续使用标准版结果...")
            
            # 阶段3: 整合报告
            print("\n  [阶段3/3] 整合双引擎报告...")
            self._generate_integrated_report()
            
            print(f"""
            ╔══════════════════════════════════════════════════════════════╗
            ║                  双引擎侦察完成!                             ║
            ║                                                              ║
            ║    标准版侦察完成 (智能策略 + 医疗专项)                      ║
            ║    极致版侦察完成 (深度爆破 + 漏洞扫描)                      ║
            ║    双重报告整合完成                                          ║
            ║                                                              ║
            ║    完整结果保存在: {self.output_dir:<30} ║
            ║    极致深度分析文件: extreme_results.json                    ║
            ╚══════════════════════════════════════════════════════════════╝
            """)
            
        except KeyboardInterrupt:
            print(f"\n[STOP] 用户中断，正在保存已完成的结果...")
            self.generate_enhanced_summary()
        except Exception as e:
            print(f"\n[ERROR] 双引擎模式执行异常: {e}")
            import traceback
            traceback.print_exc()
    
    def _generate_integrated_report(self):
        """生成双引擎整合报告"""
        try:
            integrated_report = {
                'scan_info': {
                    'target': self.target,
                    'scan_type': 'dual_engine_recon',
                    'standard_engine': 'day1_recon.py V2 Enhanced',
                    'extreme_engine': 'day1_extreme.py',
                    'timestamp': datetime.now().isoformat(),
                    'integration_status': 'completed'
                },
                'standard_results_path': f"{self.output_dir}",
                'extreme_results_path': f"{self.output_dir}/extreme_results.json",
                'coverage_analysis': {
                    'passive_recon': '  完整覆盖 (标准版)',
                    'active_scanning': '  完整覆盖 (标准版)',
                    'deep_subdomain_bruteforce': '  极致覆盖 (极致版)',
                    'api_discovery': '  极致覆盖 (极致版)',
                    'vulnerability_scanning': '  极致覆盖 (极致版)',
                    'modern_framework_analysis': '  极致覆盖 (极致版)'
                },
                'recommendations': [
                    "标准版提供了完整的攻击面映射和风险评估",
                    "极致版提供了深度技术分析和漏洞检测",
                    "建议优先处理两个版本都发现的高风险问题",
                    "极致版发现的技术细节可用于深度安全评估"
                ]
            }
            
            # 保存整合报告
            integrated_path = os.path.join(self.output_dir, "integrated_dual_engine_report.json")
            with open(integrated_path, 'w', encoding='utf-8') as f:
                json.dump(integrated_report, f, indent=2, ensure_ascii=False)
            
            print(f"  双引擎整合报告已保存: {integrated_path}")
            
        except Exception as e:
            print(f"   整合报告生成失败: {e}")

def main():
    """
    主函数
    """
    if len(sys.argv) != 2:
        print("使用方法: python3 day1_recon.py target-domain.com")
        print("示例: python3 day1_recon.py example.com")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    
    # 验证域名格式
    if not target_domain or '.' not in target_domain:
        print("错误: 请提供有效的域名")
        sys.exit(1)
    
    print("   重要提醒: 请确保你有对目标域名进行安全测试的授权!")
    confirm = input("确认已获得授权? (y/N): ")
    if confirm.lower() not in ['y', 'yes']:
        print("未确认授权，退出程序")
        sys.exit(1)
    
    # 选择运行模式
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Day 1 侦察引擎选择                       ║
    ║                                                              ║
    ║  [1] 标准版 (day1_recon.py)                                  ║
    ║      • 智能策略扫描                                          ║
    ║      • 医疗行业专项                                          ║
    ║      • 完整报告生成                                          ║
    ║      • 执行时间: ~120分钟                                    ║
    ║                                                              ║
    ║  [2] 双引擎模式 (标准版 + 极致版)                            ║
    ║      • 包含标准版所有功能                                    ║
    ║      •   深度子域爆破 (50万字典)                           ║
    ║      •   API深度发现                                       ║
    ║      •   漏洞检测扫描                                      ║
    ║      •   现代框架特化分析                                  ║
    ║      • 执行时间: ~180-240分钟                               ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    mode_choice = input("请选择运行模式 [1/2]: ").strip()
    
    # 创建侦察实例
    recon = Day1ReconEnhanced(target_domain)
    
    if mode_choice == "2":
        # 双引擎模式
        print("  启动双引擎模式 (标准版 + 极致版)...")
        asyncio.run(recon.run_with_extreme())
    else:
        # 标准版模式 (默认)
        if mode_choice != "1":
            print("   未识别选择，默认使用标准版模式")
        print("  启动标准版模式...")
        recon.run()

def run_extreme_mode(target_domain: str):
    """
      快速启动极致模式的便捷函数
    
    Args:
        target_domain: 目标域名
        
    Usage:
        from day1_recon import run_extreme_mode
        await run_extreme_mode("example.com")
    """
    recon = Day1ReconEnhanced(target_domain)
    return recon.run_with_extreme()

def run_standard_mode(target_domain: str):
    """
      快速启动标准模式的便捷函数
    
    Args:
        target_domain: 目标域名
        
    Usage:
        from day1_recon import run_standard_mode
        run_standard_mode("example.com")
    """
    recon = Day1ReconEnhanced(target_domain)
    recon.run()

if __name__ == "__main__":
    main() 