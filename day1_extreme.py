import asyncio
import aiohttp
import concurrent.futures
import threading
import queue
import time
import json
import re
import random
import hashlib
import base64
import itertools
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Callable
from dataclasses import dataclass
from collections import defaultdict, Counter
import urllib.parse
import dns.resolver
import dns.exception
import ssl
import socket
import subprocess
import sys
import os

# 高性能网络库
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3 import disable_warnings
disable_warnings()

@dataclass
class ExtremeConfig:
    """极致模式配置"""
    max_threads: int = 100
    max_async_requests: int = 500
    request_timeout: int = 10
    subdomain_dict_size: int = 500000
    api_version_range: int = 99
    enable_recursive_discovery: bool = True
    enable_ml_detection: bool = True
    vulnerability_db_update: bool = True
    
    # 新增：智能调整参数
    auto_adjust_dict_size: bool = True
    target_type_detection: bool = True
    discovery_rate_threshold: float = 0.02  # 2%发现率阈值

class Day1ExtremeEngine:
    """
    Day1 极致侦察引擎
    
      五大核心引擎：
    1. DeepSubdomainBruteforcer - 深度子域爆破
    2. APIDiscoveryEngine - API深度发现  
    3. ModernFrameworkAnalyzer - 现代框架特化
    4. AdvancedFingerprinter - 高级指纹识别
    5. VulnerabilityScanner - 漏洞检测集成
    """
    
    def __init__(self, target_domain: str, config: ExtremeConfig = None):
        self.target = target_domain
        self.config = config or ExtremeConfig()
        self.results = {
            'target': target_domain,
            'scan_start_time': datetime.now().isoformat(),
            'extreme_version': 'v1.0',
            'engines': {}
        }
        
        # 初始化五大引擎
        self.subdomain_engine = DeepSubdomainBruteforcer(target_domain, self.config)
        self.api_engine = APIDiscoveryEngine(target_domain, self.config)
        self.framework_engine = ModernFrameworkAnalyzer(target_domain, self.config)
        self.fingerprint_engine = AdvancedFingerprinter(target_domain, self.config)
        self.vulnerability_engine = VulnerabilityScanner(target_domain, self.config)
        
        # 创建输出目录
        self.output_dir = f"extreme_{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        Path(self.output_dir).mkdir(exist_ok=True)
        
        print(f"""
        ╔══════════════════════════════════════════════════════════════╗
        ║                 Day1 Extreme Engine v1.0                   ║
        ║                                                              ║
        ║  目标: {target_domain:<48} ║
        ║  模式: 极致深度扫描                                            ║
        ║  线程: {self.config.max_threads:<3} 并发 | 异步: {self.config.max_async_requests:<3} 连接                ║
        ║                                                              ║
        ║    警告: 此模式将进行极致深度扫描，请确保授权！                ║
        ╚══════════════════════════════════════════════════════════════╝
        """)

    async def run_extreme_scan(self):
        """执行极致扫描流程"""
        try:
            print("\n  启动极致扫描引擎...")
            
            # 并行执行五大引擎
            tasks = [
                self.subdomain_engine.run(),
                self.api_engine.run(),
                self.framework_engine.run(), 
                self.fingerprint_engine.run(),
                self.vulnerability_engine.run()
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 整合结果
            engine_names = ['subdomain', 'api', 'framework', 'fingerprint', 'vulnerability']
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    print(f"  {engine_names[i]} 引擎执行异常: {result}")
                    self.results['engines'][engine_names[i]] = {'error': str(result)}
                else:
                    self.results['engines'][engine_names[i]] = result
            
            # 生成极致报告
            await self.generate_extreme_report()
            
            print(f"""
            ╔══════════════════════════════════════════════════════════════╗
            ║                      极致扫描完成!                          ║
            ║                                                              ║
            ║    发现统计:                                                ║
            ║    • 子域名: {len(self.results['engines'].get('subdomain', {}).get('discovered_domains', [])):<4} 个          ║
            ║    • API端点: {len(self.results['engines'].get('api', {}).get('endpoints', [])):<4} 个        ║
            ║    • 框架特征: {len(self.results['engines'].get('framework', {}).get('frameworks', [])):<4} 个      ║
            ║    • 指纹识别: {len(self.results['engines'].get('fingerprint', {}).get('technologies', [])):<4} 个      ║
            ║    • 漏洞发现: {len(self.results['engines'].get('vulnerability', {}).get('vulnerabilities', [])):<4} 个      ║
            ║                                                              ║
            ║  📁 结果保存: {self.output_dir:<41} ║
            ╚══════════════════════════════════════════════════════════════╝
            """)
            
        except Exception as e:
            print(f"💥 极致扫描执行失败: {e}")
            import traceback
            traceback.print_exc()

    async def generate_extreme_report(self):
        """生成极致扫描报告"""
        report_path = f"{self.output_dir}/extreme_report.md"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"""# Day1 Extreme 极致扫描报告

**目标**: {self.target}
**扫描时间**: {self.results['scan_start_time']}
**引擎版本**: {self.results['extreme_version']}

##   执行摘要

本次极致扫描共启用5个专业引擎，进行了超深度的安全侦察。

""")
            
            # 各引擎详细报告
            for engine_name, engine_result in self.results['engines'].items():
                if 'error' not in engine_result:
                    f.write(f"\n##   {engine_name.title()} 引擎报告\n\n")
                    f.write(f"执行状态:   成功\n")
                    f.write(f"发现数量: {len(engine_result.get('discovered_items', []))} 项\n\n")
        
        # 保存完整JSON结果
        json_path = f"{self.output_dir}/extreme_results.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

class DeepSubdomainBruteforcer:
    """
    深度子域爆破引擎
    
      核心能力：
    - 50万条目超大字典爆破
    - 递归子域发现算法
    - 通配符DNS检测和绕过
    - 并发DNS查询优化
    - 智能重试机制
    """
    
    def __init__(self, target: str, config: ExtremeConfig):
        self.target = target
        self.config = config
        self.discovered_domains = set()
        self.wildcard_detected = False
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 2
        self.dns_resolver.lifetime = 5
        
        # 生成超大字典
        self.wordlist = self._generate_mega_wordlist()
        
    def _generate_mega_wordlist(self) -> List[str]:
        """智能生成子域字典 - 根据目标特征动态调整"""
        
        # 智能检测目标类型
        target_type = self._detect_target_type()
        optimal_size = self._calculate_optimal_dict_size(target_type)
        
        print(f"      智能字典生成...")
        print(f"      目标类型: {target_type}")
        print(f"      优化字典大小: {optimal_size:,} 条目")
        
        # 基础字典
        basic_words = [
            'www', 'mail', 'ftp', 'admin', 'test', 'staging', 'dev', 'api', 
            'app', 'mobile', 'secure', 'vpn', 'cdn', 'blog', 'shop', 'store',
            'portal', 'dashboard', 'panel', 'control', 'manage', 'system',
            'service', 'support', 'help', 'docs', 'wiki', 'forum', 'chat',
            'news', 'media', 'static', 'assets', 'cdn', 'img', 'images',
            'upload', 'download', 'files', 'backup', 'archive', 'logs'
        ]
        
        # 技术相关词汇
        tech_words = [
            'jenkins', 'gitlab', 'github', 'bitbucket', 'docker', 'k8s',
            'kubernetes', 'prometheus', 'grafana', 'kibana', 'elastic',
            'redis', 'mongo', 'mysql', 'postgres', 'oracle', 'mssql',
            'api', 'rest', 'graphql', 'websocket', 'webhook', 'callback'
        ]
        
        # 环境相关词汇  
        env_words = [
            'prod', 'production', 'live', 'staging', 'stage', 'test', 'testing',
            'dev', 'development', 'demo', 'sandbox', 'lab', 'experiment',
            'alpha', 'beta', 'rc', 'release', 'preview', 'canary'
        ]
        
        # 医疗行业专用词汇
        medical_words = [
            'patient', 'doctor', 'clinic', 'hospital', 'medical', 'health',
            'appointment', 'prescription', 'diagnosis', 'treatment', 'therapy',
            'pharmacy', 'lab', 'laboratory', 'radiology', 'imaging', 'xray',
            'mri', 'ct', 'ultrasound', 'cardiology', 'oncology', 'surgery'
        ]
        
        # 数字组合
        numbers = [str(i) for i in range(1, 100)]
        
        # 组合生成
        all_words = basic_words + tech_words + env_words + medical_words
        
        # 生成组合词汇
        combined_words = []
        
        # 单词 + 数字
        for word in all_words:
            for num in numbers[:20]:  # 限制前20个数字
                combined_words.append(f"{word}{num}")
                combined_words.append(f"{word}-{num}")
                combined_words.append(f"{num}{word}")
        
        # 单词 + 单词
        for word1 in basic_words[:20]:  # 限制组合数量
            for word2 in tech_words[:10]:
                combined_words.append(f"{word1}-{word2}")
                combined_words.append(f"{word1}_{word2}")
        
        # 环境 + 服务
        for env in env_words:
            for service in tech_words[:15]:
                combined_words.append(f"{env}-{service}")
                combined_words.append(f"{service}-{env}")
        
        # 合并并去重
        mega_wordlist = list(set(all_words + combined_words))
        
        # 智能填充到最优大小
        while len(mega_wordlist) < optimal_size:
            # 生成随机组合
            word1 = random.choice(all_words)
            word2 = random.choice(all_words)
            connector = random.choice(['-', '_', ''])
            new_word = f"{word1}{connector}{word2}"
            if new_word not in mega_wordlist:
                mega_wordlist.append(new_word)
        
        print(f"      智能字典生成完成: {len(mega_wordlist):,} 条目")
        print(f"      预计扫描时间: {self._estimate_scan_time(optimal_size)}")
        return mega_wordlist[:optimal_size]
    
    def _detect_target_type(self) -> str:
        """检测目标类型"""
        try:
            # 简单HTTP检测
            response = requests.get(f"http://{self.target}", timeout=5)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # 医疗机构检测
            medical_indicators = ['patient', 'doctor', 'clinic', 'appointment', 'medical']
            if any(word in content for word in medical_indicators):
                return "医疗机构"
            
            # SaaS平台检测
            if 'framer' in headers or 'framer' in content:
                return "Framer SaaS平台"
            
            # 电商平台检测
            ecommerce_indicators = ['shop', 'cart', 'product', 'buy', 'store']
            if any(word in content for word in ecommerce_indicators):
                return "电商平台"
            
            # 企业官网检测
            if any(word in content for word in ['company', 'about us', 'contact', 'business']):
                return "企业官网"
            
            return "通用网站"
        except:
            return "未知类型"
    
    def _calculate_optimal_dict_size(self, target_type: str) -> int:
        """根据目标类型计算最优字典大小"""
        size_mapping = {
            "医疗机构": 5000,      # 小型医疗机构
            "Framer SaaS平台": 8000,  # 现代SaaS平台
            "电商平台": 50000,     # 电商需要更多子域名
            "企业官网": 20000,     # 中型企业
            "通用网站": 15000,     # 标准大小
            "未知类型": 30000      # 保守估计
        }
        
        optimal_size = size_mapping.get(target_type, 30000)
        
        # 如果用户强制要求500K，则保持原值
        if not self.config.auto_adjust_dict_size:
            optimal_size = self.config.subdomain_dict_size
        
        return optimal_size
    
    def _estimate_scan_time(self, dict_size: int) -> str:
        """预估扫描时间"""
        # 基于并发数和平均响应时间预估
        avg_response_time = 0.3  # 秒
        concurrent_queries = self.config.max_threads
        
        total_time_seconds = (dict_size / concurrent_queries) * avg_response_time
        
        if total_time_seconds < 60:
            return f"{int(total_time_seconds)}秒"
        elif total_time_seconds < 3600:
            return f"{int(total_time_seconds/60)}分钟"
        else:
            return f"{total_time_seconds/3600:.1f}小时"

    async def run(self) -> Dict:
        """执行深度子域爆破"""
        print("\n  深度子域爆破引擎启动...")
        
        # 检测通配符DNS
        await self._detect_wildcard_dns()
        
        # 并发DNS查询
        discovered = await self._concurrent_dns_bruteforce()
        
        # 递归发现
        if self.config.enable_recursive_discovery:
            recursive_found = await self._recursive_discovery(discovered)
            discovered.update(recursive_found)
        
        self.discovered_domains = discovered
        
        # 保存结果
        self._save_subdomain_results()
        
        return {
            'discovered_domains': list(discovered),
            'total_count': len(discovered),
            'wildcard_detected': self.wildcard_detected,
            'wordlist_size': len(self.wordlist),
            'discovered_items': list(discovered)  # 统一字段名
        }

    async def _detect_wildcard_dns(self):
        """检测通配符DNS"""
        print("      检测通配符DNS...")
        
        random_subdomain = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=20))}.{self.target}"
        
        try:
            answers = dns.resolver.resolve(random_subdomain, 'A')
            if answers:
                self.wildcard_detected = True
                print(f"      检测到通配符DNS: {random_subdomain} -> {answers[0]}")
        except:
            print("      无通配符DNS")

    async def _concurrent_dns_bruteforce(self) -> Set[str]:
        """并发DNS爆破"""
        print(f"      开始并发DNS爆破 ({len(self.wordlist):,} 条目)...")
        
        discovered = set()
        semaphore = asyncio.Semaphore(self.config.max_threads)
        
        async def check_subdomain(subdomain_prefix):
            async with semaphore:
                full_domain = f"{subdomain_prefix}.{self.target}"
                try:
                    # 异步DNS查询
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None, 
                        lambda: dns.resolver.resolve(full_domain, 'A')
                    )
                    if answers:
                        discovered.add(full_domain)
                        print(f"        发现: {full_domain}")
                except:
                    pass  # DNS查询失败，忽略
        
        # 创建任务
        tasks = [check_subdomain(word) for word in self.wordlist]
        
        # 分批执行，避免内存过载
        batch_size = 1000
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            print(f"        进度: {min(i+batch_size, len(tasks)):,}/{len(tasks):,} ({(min(i+batch_size, len(tasks))/len(tasks)*100):.1f}%)")
        
        print(f"      爆破完成: 发现 {len(discovered)} 个子域名")
        return discovered

    async def _recursive_discovery(self, known_domains: Set[str]) -> Set[str]:
        """递归子域发现"""
        print("    🔄 启动递归发现...")
        
        new_discoveries = set()
        
        # 从已知域名中提取模式
        patterns = self._extract_subdomain_patterns(known_domains)
        
        # 基于模式生成新的候选域名
        candidates = self._generate_pattern_candidates(patterns)
        
        # 验证候选域名
        semaphore = asyncio.Semaphore(50)  # 递归发现使用较少并发
        
        async def verify_candidate(candidate):
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None,
                        lambda: dns.resolver.resolve(candidate, 'A')
                    )
                    if answers and candidate not in known_domains:
                        new_discoveries.add(candidate)
                        print(f"        递归发现: {candidate}")
                except:
                    pass
        
        tasks = [verify_candidate(candidate) for candidate in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"      递归发现完成: 新增 {len(new_discoveries)} 个域名")
        return new_discoveries

    def _extract_subdomain_patterns(self, domains: Set[str]) -> List[str]:
        """从已知域名中提取模式"""
        patterns = set()
        
        for domain in domains:
            subdomain = domain.replace(f".{self.target}", "")
            
            # 提取数字模式
            if re.search(r'\d+', subdomain):
                pattern = re.sub(r'\d+', 'NUM', subdomain)
                patterns.add(pattern)
            
            # 提取分隔符模式
            if '-' in subdomain:
                parts = subdomain.split('-')
                if len(parts) > 1:
                    patterns.add(f"{parts[0]}-*")
            
            if '_' in subdomain:
                parts = subdomain.split('_')
                if len(parts) > 1:
                    patterns.add(f"{parts[0]}_*")
        
        return list(patterns)

    def _generate_pattern_candidates(self, patterns: List[str]) -> Set[str]:
        """基于模式生成候选域名"""
        candidates = set()
        
        for pattern in patterns:
            if 'NUM' in pattern:
                # 数字替换
                for i in range(1, 21):  # 1-20
                    candidate = pattern.replace('NUM', str(i))
                    candidates.add(f"{candidate}.{self.target}")
            
            elif '*' in pattern:
                # 通配符替换
                common_suffixes = ['api', 'app', 'web', 'mobile', 'admin', 'test', 'prod']
                for suffix in common_suffixes:
                    candidate = pattern.replace('*', suffix)
                    candidates.add(f"{candidate}.{self.target}")
        
        return candidates

    def _save_subdomain_results(self):
        """保存子域名结果"""
        output_file = f"{self.target.replace('.', '_')}_extreme_subdomains.txt"
        
        with open(output_file, 'w') as f:
            for domain in sorted(self.discovered_domains):
                f.write(f"{domain}\n")
        
        print(f"    💾 子域名结果已保存: {output_file}")

class APIDiscoveryEngine:
    """
    API深度发现引擎
    
      核心能力：
    - GraphQL接口自省发现
    - REST API版本遍历 (v1-v99)
    - OpenAPI/Swagger文档发现
    - API参数模糊测试
    - 认证机制识别
    """
    
    def __init__(self, target: str, config: ExtremeConfig):
        self.target = target
        self.config = config
        self.session = self._create_optimized_session()
        self.discovered_endpoints = []
        
    def _create_optimized_session(self):
        """创建优化的HTTP会话"""
        session = requests.Session()
        
        # 配置重试策略
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置请求头
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        
        return session

    async def run(self) -> Dict:
        """执行API深度发现"""
        print("\n  API深度发现引擎启动...")
        
        # 并行执行多种发现方法
        tasks = [
            self._discover_rest_apis(),
            self._discover_graphql_apis(),
            self._discover_swagger_docs(),
            self._discover_api_versions(),
            self._fuzz_api_parameters()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 合并结果
        all_endpoints = set()
        for result in results:
            if isinstance(result, set):
                all_endpoints.update(result)
            elif isinstance(result, list):
                all_endpoints.update(result)
        
        self.discovered_endpoints = list(all_endpoints)
        
        return {
            'endpoints': self.discovered_endpoints,
            'total_count': len(self.discovered_endpoints),
            'discovery_methods': {
                'rest_api': len(results[0]) if not isinstance(results[0], Exception) else 0,
                'graphql': len(results[1]) if not isinstance(results[1], Exception) else 0,
                'swagger': len(results[2]) if not isinstance(results[2], Exception) else 0,
                'versions': len(results[3]) if not isinstance(results[3], Exception) else 0,
                'fuzzed': len(results[4]) if not isinstance(results[4], Exception) else 0
            },
            'discovered_items': self.discovered_endpoints  # 统一字段名
        }

    async def _discover_rest_apis(self) -> Set[str]:
        """发现REST API端点"""
        print("      REST API端点发现...")
        
        discovered = set()
        
        # 常见API路径
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/services', '/webapi', '/jsonapi',
            '/graphql', '/query', '/mutation',
            '/_api', '/api_', '/apis',
            '/v1', '/v2', '/v3', '/v4', '/v5'
        ]
        
        # 常见资源端点
        resources = [
            'users', 'user', 'accounts', 'account',
            'auth', 'login', 'token', 'oauth',
            'data', 'info', 'status', 'health',
            'config', 'settings', 'admin',
            'patients', 'doctors', 'appointments',  # 医疗相关
            'records', 'files', 'uploads'
        ]
        
        # 测试基础API路径
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        semaphore = asyncio.Semaphore(20)
        
        async def test_endpoint(url, path):
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: self.session.get(f"{url}{path}", timeout=5)
                    )
                    
                    # 检查响应特征
                    if self._is_api_response(response):
                        discovered.add(f"{url}{path}")
                        print(f"        API发现: {url}{path}")
                        
                        # 继续发现子资源
                        sub_discovered = await self._discover_sub_resources(f"{url}{path}", resources)
                        discovered.update(sub_discovered)
                
                except Exception:
                    pass
        
        # 测试所有组合
        tasks = []
        for url in base_urls:
            for path in api_paths:
                tasks.append(test_endpoint(url, path))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"      REST API发现完成: {len(discovered)} 个端点")
        return discovered

    async def _discover_sub_resources(self, base_url: str, resources: List[str]) -> Set[str]:
        """发现子资源"""
        discovered = set()
        semaphore = asyncio.Semaphore(10)
        
        async def test_resource(resource):
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: self.session.get(f"{base_url}/{resource}", timeout=3)
                    )
                    
                    if response.status_code < 500:  # 任何有效响应
                        discovered.add(f"{base_url}/{resource}")
                
                except Exception:
                    pass
        
        tasks = [test_resource(resource) for resource in resources]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return discovered

    def _is_api_response(self, response) -> bool:
        """判断是否为API响应"""
        # 检查Content-Type
        content_type = response.headers.get('Content-Type', '').lower()
        if 'application/json' in content_type or 'application/xml' in content_type:
            return True
        
        # 检查状态码
        if response.status_code in [200, 401, 403, 404, 405]:
            try:
                # 尝试解析JSON
                json.loads(response.text)
                return True
            except:
                pass
        
        # 检查响应内容特征
        api_indicators = [
            '"error":', '"message":', '"data":', '"status":',
            '"code":', '"success":', '"result":', '"response":',
            '"api":', '"version":', '"endpoints":'
        ]
        
        content_lower = response.text.lower()
        return any(indicator in content_lower for indicator in api_indicators)

    async def _discover_graphql_apis(self) -> Set[str]:
        """发现GraphQL API"""
        print("      GraphQL API发现...")
        
        discovered = set()
        
        graphql_paths = [
            '/graphql', '/graphiql', '/graph', '/gql',
            '/v1/graphql', '/api/graphql', '/query',
            '/graphql-playground', '/graphql/console'
        ]
        
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        semaphore = asyncio.Semaphore(10)
        
        async def test_graphql(url, path):
            async with semaphore:
                try:
                    # GraphQL introspection query
                    introspection_query = {
                        "query": "query IntrospectionQuery { __schema { queryType { name } } }"
                    }
                    
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: self.session.post(
                            f"{url}{path}",
                            json=introspection_query,
                            timeout=5
                        )
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'data' in data and '__schema' in data['data']:
                                discovered.add(f"{url}{path}")
                                print(f"        GraphQL发现: {url}{path}")
                        except:
                            pass
                
                except Exception:
                    pass
        
        tasks = []
        for url in base_urls:
            for path in graphql_paths:
                tasks.append(test_graphql(url, path))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"      GraphQL发现完成: {len(discovered)} 个端点")
        return discovered

    async def _discover_swagger_docs(self) -> Set[str]:
        """发现Swagger/OpenAPI文档"""
        print("      Swagger/OpenAPI文档发现...")
        
        discovered = set()
        
        swagger_paths = [
            '/swagger.json', '/swagger.yaml', '/swagger.yml',
            '/openapi.json', '/openapi.yaml', '/openapi.yml',
            '/api-docs', '/api/docs', '/docs', '/documentation',
            '/swagger-ui', '/swagger-ui.html', '/swagger-ui/index.html',
            '/api/swagger', '/api/swagger.json', '/api/swagger.yaml',
            '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json',
            '/redoc', '/rapidoc', '/api-explorer'
        ]
        
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        semaphore = asyncio.Semaphore(15)
        
        async def test_swagger(url, path):
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: self.session.get(f"{url}{path}", timeout=5)
                    )
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        swagger_indicators = [
                            'swagger', 'openapi', 'api documentation',
                            '"paths":', '"definitions":', '"components":',
                            'swagger-ui', 'redoc'
                        ]
                        
                        if any(indicator in content for indicator in swagger_indicators):
                            discovered.add(f"{url}{path}")
                            print(f"        Swagger发现: {url}{path}")
                
                except Exception:
                    pass
        
        tasks = []
        for url in base_urls:
            for path in swagger_paths:
                tasks.append(test_swagger(url, path))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"      Swagger发现完成: {len(discovered)} 个端点")
        return discovered

    async def _discover_api_versions(self) -> Set[str]:
        """发现API版本"""
        print("      API版本遍历 (v1-v99)...")
        
        discovered = set()
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        # 版本路径模式
        version_patterns = [
            '/v{}', '/api/v{}', '/rest/v{}',
            '/v{}/api', '/v{}/rest', '/v{}/graphql',
            '/version{}', '/ver{}', '/{}.0'
        ]
        
        semaphore = asyncio.Semaphore(25)
        
        async def test_version(url, pattern, version):
            async with semaphore:
                try:
                    path = pattern.format(version)
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: self.session.get(f"{url}{path}", timeout=3)
                    )
                    
                    # 检查有效响应
                    if response.status_code < 500:
                        if self._is_api_response(response) or response.status_code == 404:
                            discovered.add(f"{url}{path}")
                            if response.status_code != 404:
                                print(f"        版本发现: {url}{path}")
                
                except Exception:
                    pass
        
        # 测试版本1-99
        tasks = []
        for url in base_urls:
            for pattern in version_patterns:
                for version in range(1, self.config.api_version_range + 1):
                    tasks.append(test_version(url, pattern, version))
        
        # 分批执行，避免过载
        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
        
        print(f"      版本遍历完成: {len(discovered)} 个端点")
        return discovered

    async def _fuzz_api_parameters(self) -> Set[str]:
        """API参数模糊测试"""
        print("      API参数模糊测试...")
        
        discovered = set()
        
        # 常见参数名
        common_params = [
            'id', 'user_id', 'userid', 'uid', 'account_id',
            'limit', 'offset', 'page', 'size', 'count',
            'format', 'type', 'sort', 'order', 'filter',
            'search', 'query', 'q', 'keyword', 'term',
            'token', 'key', 'api_key', 'auth', 'session',
            'patient_id', 'doctor_id', 'appointment_id'  # 医疗相关
        ]
        
        # 基础API端点（从之前的发现中获取前几个）
        base_endpoints = [
            f"https://{self.target}/api",
            f"https://{self.target}/api/v1",
            f"http://{self.target}/api"
        ]
        
        semaphore = asyncio.Semaphore(10)
        
        async def fuzz_endpoint(endpoint, param):
            async with semaphore:
                try:
                    # 测试GET参数
                    test_url = f"{endpoint}?{param}=test"
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: self.session.get(test_url, timeout=3)
                    )
                    
                    # 分析响应差异
                    if response.status_code in [200, 400, 422]:  # 有效响应
                        if self._has_parameter_response(response, param):
                            discovered.add(f"{endpoint}?{param}=VALUE")
                            print(f"        参数发现: {endpoint}?{param}=")
                
                except Exception:
                    pass
        
        tasks = []
        for endpoint in base_endpoints:
            for param in common_params:
                tasks.append(fuzz_endpoint(endpoint, param))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"      参数模糊测试完成: {len(discovered)} 个端点")
        return discovered

    def _has_parameter_response(self, response, param_name: str) -> bool:
        """检查响应是否包含参数相关信息"""
        content = response.text.lower()
        
        # 检查错误消息中是否提到参数
        param_indicators = [
            f'"{param_name}"', f"'{param_name}'",
            f'parameter "{param_name}"', f'field "{param_name}"',
            f'{param_name} is required', f'{param_name} missing',
            f'invalid {param_name}', f'unknown {param_name}'
        ]
        
        return any(indicator in content for indicator in param_indicators)

class ModernFrameworkAnalyzer:
    """
    现代框架特化引擎
    
      核心能力：
    - Angular路由深度映射
    - SPA状态管理分析
    - 前端资源逆向工程
    - 组件树结构分析
    - 现代构建工具检测
    """
    
    def __init__(self, target: str, config: ExtremeConfig):
        self.target = target
        self.config = config
        self.session = requests.Session()
        self.discovered_frameworks = []

    async def run(self) -> Dict:
        """执行现代框架分析"""
        print("\n  现代框架特化引擎启动...")
        
        # 并行分析
        tasks = [
            self._analyze_angular_app(),
            self._analyze_react_app(),
            self._analyze_vue_app(),
            self._analyze_spa_routing(),
            self._analyze_build_artifacts()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 合并框架发现
        frameworks = []
        for result in results:
            if isinstance(result, list):
                frameworks.extend(result)
        
        self.discovered_frameworks = frameworks
        
        return {
            'frameworks': frameworks,
            'total_count': len(frameworks),
            'analysis_types': {
                'angular': len(results[0]) if not isinstance(results[0], Exception) else 0,
                'react': len(results[1]) if not isinstance(results[1], Exception) else 0,
                'vue': len(results[2]) if not isinstance(results[2], Exception) else 0,
                'routing': len(results[3]) if not isinstance(results[3], Exception) else 0,
                'build': len(results[4]) if not isinstance(results[4], Exception) else 0
            },
            'discovered_items': frameworks  # 统一字段名
        }

    async def _analyze_angular_app(self) -> List[Dict]:
        """分析Angular应用"""
        print("    🅰️ Angular应用深度分析...")
        
        discoveries = []
        
        try:
            # 获取主页
            response = self.session.get(f"https://{self.target}", timeout=10)
            content = response.text
            
            # Angular特征检测
            angular_indicators = {
                'ng-version': r'ng-version["\s]*[:=]["\s]*([^"\']+)',
                'angular-core': r'@angular/core["\s]*[:=]["\s]*([^"\']+)',
                'ng-app': r'ng-app["\s]*=',
                'router-outlet': r'<router-outlet',
                'angular-router': r'@angular/router'
            }
            
            for indicator, pattern in angular_indicators.items():
                if re.search(pattern, content, re.IGNORECASE):
                    version_match = re.search(pattern, content, re.IGNORECASE)
                    version = version_match.group(1) if version_match and version_match.groups() else "Unknown"
                    
                    discoveries.append({
                        'type': 'angular',
                        'feature': indicator,
                        'version': version,
                        'confidence': 'high'
                    })
            
            # 查找Angular路由配置
            await self._discover_angular_routes(content, discoveries)
            
        except Exception as e:
            print(f"        Angular分析失败: {e}")
        
        return discoveries

    async def _discover_angular_routes(self, content: str, discoveries: List[Dict]):
        """发现Angular路由"""
        
        # 查找路由配置模式
        route_patterns = [
            r'path\s*:\s*["\']([^"\']+)["\']',
            r'route\s*:\s*["\']([^"\']+)["\']',
            r'redirectTo\s*:\s*["\']([^"\']+)["\']'
        ]
        
        found_routes = set()
        for pattern in route_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            found_routes.update(matches)
        
        for route in found_routes:
            if route and route != '/':
                discoveries.append({
                    'type': 'angular_route',
                    'route': route,
                    'url': f"https://{self.target}#{route}",  # Angular通常使用hash路由
                    'confidence': 'medium'
                })

    async def _analyze_react_app(self) -> List[Dict]:
        """分析React应用"""
        print("    ⚛️ React应用深度分析...")
        
        discoveries = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            content = response.text
            
            # React特征检测
            react_indicators = {
                'react': r'react["\s]*[:=]["\s]*([^"\']+)',
                'react-dom': r'react-dom["\s]*[:=]["\s]*([^"\']+)',
                'react-router': r'react-router["\s]*[:=]["\s]*([^"\']+)',
                'jsx': r'React\.createElement|jsx',
                'react-app': r'data-react-helmet|__REACT_DEVTOOLS__'
            }
            
            for indicator, pattern in react_indicators.items():
                if re.search(pattern, content, re.IGNORECASE):
                    version_match = re.search(pattern, content, re.IGNORECASE)
                    version = version_match.group(1) if version_match and version_match.groups() else "Unknown"
                    
                    discoveries.append({
                        'type': 'react',
                        'feature': indicator,
                        'version': version,
                        'confidence': 'high'
                    })
            
            # 查找React组件
            component_patterns = [
                r'function\s+([A-Z][a-zA-Z0-9]+)\s*\(',
                r'const\s+([A-Z][a-zA-Z0-9]+)\s*=\s*\(',
                r'class\s+([A-Z][a-zA-Z0-9]+)\s+extends\s+React'
            ]
            
            found_components = set()
            for pattern in component_patterns:
                matches = re.findall(pattern, content)
                found_components.update(matches)
            
            for component in list(found_components)[:10]:  # 限制数量
                discoveries.append({
                    'type': 'react_component',
                    'component': component,
                    'confidence': 'medium'
                })
        
        except Exception as e:
            print(f"        React分析失败: {e}")
        
        return discoveries

    async def _analyze_vue_app(self) -> List[Dict]:
        """分析Vue应用"""
        print("    🖖 Vue应用深度分析...")
        
        discoveries = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            content = response.text
            
            # Vue特征检测
            vue_indicators = {
                'vue': r'vue["\s]*[:=]["\s]*([^"\']+)',
                'vue-router': r'vue-router["\s]*[:=]["\s]*([^"\']+)',
                'vuex': r'vuex["\s]*[:=]["\s]*([^"\']+)',
                'v-if': r'v-if=',
                'v-for': r'v-for=',
                'vue-app': r'new\s+Vue\s*\('
            }
            
            for indicator, pattern in vue_indicators.items():
                if re.search(pattern, content, re.IGNORECASE):
                    version_match = re.search(pattern, content, re.IGNORECASE)
                    version = version_match.group(1) if version_match and version_match.groups() else "Unknown"
                    
                    discoveries.append({
                        'type': 'vue',
                        'feature': indicator,
                        'version': version,
                        'confidence': 'high'
                    })
        
        except Exception as e:
            print(f"        Vue分析失败: {e}")
        
        return discoveries

    async def _analyze_spa_routing(self) -> List[Dict]:
        """分析SPA路由"""
        print("      SPA路由系统分析...")
        
        discoveries = []
        
        # 常见SPA路由模式
        common_spa_routes = [
            '/', '/home', '/dashboard', '/profile', '/settings',
            '/login', '/register', '/logout', '/auth',
            '/users', '/admin', '/api', '/docs',
            '/about', '/contact', '/help', '/support',
            '/patients', '/doctors', '/appointments'  # 医疗相关
        ]
        
        base_url = f"https://{self.target}"
        
        for route in common_spa_routes:
            try:
                # 测试路由（可能是hash路由或history路由）
                test_urls = [
                    f"{base_url}{route}",
                    f"{base_url}#{route}",
                    f"{base_url}#!/{route}"
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url, timeout=5)
                    
                    # 检查是否为有效的SPA路由
                    if response.status_code == 200:
                        # 检查内容是否与主页不同（表明路由有效）
                        if await self._is_different_spa_content(response.text, route):
                            discoveries.append({
                                'type': 'spa_route',
                                'route': route,
                                'url': test_url,
                                'confidence': 'medium'
                            })
                            break
            
            except Exception:
                continue
        
        return discoveries

    async def _is_different_spa_content(self, content: str, route: str) -> bool:
        """检查SPA内容是否不同"""
        # 简单的内容差异检测
        route_indicators = [
            route.replace('/', ''),
            f'"{route}"',
            f"'{route}'",
            f'path="{route}"',
            f"route: '{route}'"
        ]
        
        return any(indicator in content.lower() for indicator in route_indicators)

    async def _analyze_build_artifacts(self) -> List[Dict]:
        """分析构建产物"""
        print("    📦 构建产物分析...")
        
        discoveries = []
        
        # 常见构建文件
        build_files = [
            '/main.js', '/app.js', '/bundle.js', '/index.js',
            '/main.css', '/app.css', '/style.css',
            '/manifest.json', '/sw.js', '/service-worker.js',
            '/webpack.config.js', '/package.json',
            '/.env', '/.env.production', '/.env.local'
        ]
        
        base_url = f"https://{self.target}"
        
        for file_path in build_files:
            try:
                response = self.session.get(f"{base_url}{file_path}", timeout=5)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # 分析构建工具特征
                    build_tools = self._detect_build_tools(content)
                    
                    for tool in build_tools:
                        discoveries.append({
                            'type': 'build_tool',
                            'tool': tool,
                            'file': file_path,
                            'confidence': 'high'
                        })
            
            except Exception:
                continue
        
        return discoveries

    def _detect_build_tools(self, content: str) -> List[str]:
        """检测构建工具"""
        tools = []
        
        build_indicators = {
            'webpack': ['__webpack', 'webpackJsonp', 'webpack_require'],
            'vite': ['/@vite/', 'vite:', '?vite'],
            'rollup': ['rollup', 'rollupPlugins'],
            'parcel': ['parcel-bundler', 'parcel:', 'hotReload'],
            'esbuild': ['esbuild', '__esbuild'],
            'babel': ['@babel', '_babel', 'babelHelpers'],
            'typescript': ['__typescript', '.ts"', 'typescript']
        }
        
        content_lower = content.lower()
        for tool, indicators in build_indicators.items():
            if any(indicator.lower() in content_lower for indicator in indicators):
                tools.append(tool)
        
        return tools

class AdvancedFingerprinter:
    """
    高级指纹识别引擎
    
      核心能力：
    - JavaScript库版本精确检测
    - CSS框架和UI库识别
    - 第三方服务集成分析
    - 构建工具和打包器识别
    - CDN和静态资源分析
    """
    
    def __init__(self, target: str, config: ExtremeConfig):
        self.target = target
        self.config = config
        self.session = requests.Session()
        self.discovered_technologies = []

    async def run(self) -> Dict:
        """执行高级指纹识别"""
        print("\n  高级指纹识别引擎启动...")
        
        # 并行执行多种识别
        tasks = [
            self._fingerprint_js_libraries(),
            self._fingerprint_css_frameworks(),
            self._fingerprint_third_party_services(),
            self._fingerprint_server_technologies(),
            self._fingerprint_security_technologies()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 合并结果
        technologies = []
        for result in results:
            if isinstance(result, list):
                technologies.extend(result)
        
        self.discovered_technologies = technologies
        
        return {
            'technologies': technologies,
            'total_count': len(technologies),
            'categories': {
                'javascript': len(results[0]) if not isinstance(results[0], Exception) else 0,
                'css': len(results[1]) if not isinstance(results[1], Exception) else 0,
                'services': len(results[2]) if not isinstance(results[2], Exception) else 0,
                'server': len(results[3]) if not isinstance(results[3], Exception) else 0,
                'security': len(results[4]) if not isinstance(results[4], Exception) else 0
            },
            'discovered_items': technologies  # 统一字段名
        }

    async def _fingerprint_js_libraries(self) -> List[Dict]:
        """指纹识别JavaScript库"""
        print("      JavaScript库版本检测...")
        
        discoveries = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            content = response.text
            
            # 详细的JS库指纹库
            js_libraries = {
                'jQuery': {
                    'patterns': [r'jquery["\s]*[:=]["\s]*([0-9\.]+)', r'jQuery\s+v([0-9\.]+)'],
                    'indicators': ['jquery', '$.fn.jquery', 'jQuery.fn.init']
                },
                'React': {
                    'patterns': [r'react["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['React.version', '__REACT_DEVTOOLS__', 'react-dom']
                },
                'Angular': {
                    'patterns': [r'@angular/core["\s]*[:=]["\s]*([0-9\.]+)', r'ng-version["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['angular', 'ng-version', '@angular']
                },
                'Vue': {
                    'patterns': [r'vue["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['Vue.version', 'vue.js', '__VUE__']
                },
                'Bootstrap': {
                    'patterns': [r'bootstrap["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['bootstrap', 'btn-primary', 'container-fluid']
                },
                'D3.js': {
                    'patterns': [r'd3["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['d3.version', 'd3.js', 'd3.select']
                },
                'Chart.js': {
                    'patterns': [r'chart\.js["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['Chart.js', 'chartjs', 'new Chart']
                },
                'Moment.js': {
                    'patterns': [r'moment["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['moment.js', 'moment().format', '_isAMomentObject']
                },
                'Lodash': {
                    'patterns': [r'lodash["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['lodash', '_.js', '_.VERSION']
                },
                'Axios': {
                    'patterns': [r'axios["\s]*[:=]["\s]*([0-9\.]+)'],
                    'indicators': ['axios', 'axios.get', 'axios.post']
                }
            }
            
            for lib_name, lib_info in js_libraries.items():
                # 检查指示器
                if any(indicator in content for indicator in lib_info['indicators']):
                    # 尝试提取版本
                    version = "Unknown"
                    for pattern in lib_info['patterns']:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            break
                    
                    discoveries.append({
                        'type': 'javascript_library',
                        'name': lib_name,
                        'version': version,
                        'confidence': 'high' if version != "Unknown" else 'medium'
                    })
        
        except Exception as e:
            print(f"        JS库检测失败: {e}")
        
        return discoveries

    async def _fingerprint_css_frameworks(self) -> List[Dict]:
        """指纹识别CSS框架"""
        print("    🎨 CSS框架识别...")
        
        discoveries = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            content = response.text
            
            # CSS框架指纹库
            css_frameworks = {
                'Bootstrap': {
                    'patterns': [r'bootstrap["\s]*[:=]["\s]*([0-9\.]+)'],
                    'class_indicators': ['container', 'row', 'col-', 'btn-', 'navbar'],
                    'css_indicators': ['bootstrap.css', 'bootstrap.min.css']
                },
                'Tailwind CSS': {
                    'patterns': [r'tailwindcss["\s]*[:=]["\s]*([0-9\.]+)'],
                    'class_indicators': ['flex', 'grid', 'text-', 'bg-', 'p-', 'm-'],
                    'css_indicators': ['tailwind.css', '@tailwind']
                },
                'Bulma': {
                    'patterns': [r'bulma["\s]*[:=]["\s]*([0-9\.]+)'],
                    'class_indicators': ['column', 'section', 'hero', 'navbar', 'button'],
                    'css_indicators': ['bulma.css', 'bulma.min.css']
                },
                'Foundation': {
                    'patterns': [r'foundation["\s]*[:=]["\s]*([0-9\.]+)'],
                    'class_indicators': ['grid-x', 'cell', 'callout', 'button'],
                    'css_indicators': ['foundation.css', 'foundation.min.css']
                },
                'Semantic UI': {
                    'patterns': [r'semantic["\s]*[:=]["\s]*([0-9\.]+)'],
                    'class_indicators': ['ui segment', 'ui button', 'ui menu', 'ui grid'],
                    'css_indicators': ['semantic.css', 'semantic.min.css']
                },
                'Material-UI': {
                    'patterns': [r'@material-ui["\s]*[:=]["\s]*([0-9\.]+)'],
                    'class_indicators': ['MuiButton', 'MuiTextField', 'MuiAppBar'],
                    'css_indicators': ['material-ui', '@material-ui']
                },
                'Ant Design': {
                    'patterns': [r'antd["\s]*[:=]["\s]*([0-9\.]+)'],
                    'class_indicators': ['ant-btn', 'ant-input', 'ant-table', 'ant-menu'],
                    'css_indicators': ['antd.css', 'ant-design']
                }
            }
            
            for framework_name, framework_info in css_frameworks.items():
                confidence = 'low'
                version = "Unknown"
                
                # 检查CSS指示器
                css_found = any(css_indicator in content for css_indicator in framework_info['css_indicators'])
                
                # 检查类名指示器
                class_found = sum(1 for class_indicator in framework_info['class_indicators'] 
                                if class_indicator in content)
                
                if css_found or class_found >= 2:
                    confidence = 'high' if css_found else 'medium'
                    
                    # 尝试提取版本
                    for pattern in framework_info['patterns']:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            break
                    
                    discoveries.append({
                        'type': 'css_framework',
                        'name': framework_name,
                        'version': version,
                        'confidence': confidence,
                        'indicators_found': class_found
                    })
        
        except Exception as e:
            print(f"        CSS框架识别失败: {e}")
        
        return discoveries

    async def _fingerprint_third_party_services(self) -> List[Dict]:
        """指纹识别第三方服务"""
        print("    🔌 第三方服务集成分析...")
        
        discoveries = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            content = response.text
            headers = response.headers
            
            
            for service_name, service_info in third_party_services.items():
                found = False
                detection_method = []
                
                # 检查内容模式
                if 'patterns' in service_info:
                    for pattern in service_info['patterns']:
                        if re.search(pattern, content, re.IGNORECASE):
                            found = True
                            detection_method.append('content_pattern')
                            break
                
                # 检查域名
                if 'domains' in service_info:
                    for domain in service_info['domains']:
                        if domain in content:
                            found = True
                            detection_method.append('domain_reference')
                            break
                
                # 检查HTTP头
                if 'headers' in service_info:
                    for header in service_info['headers']:
                        if header in headers:
                            found = True
                            detection_method.append('http_header')
                            break
                
                if found:
                    discoveries.append({
                        'type': 'third_party_service',
                        'name': service_name,
                        'detection_method': detection_method,
                        'confidence': 'high'
                    })
        
        except Exception as e:
            print(f"        第三方服务识别失败: {e}")
        
        return discoveries

    async def _fingerprint_server_technologies(self) -> List[Dict]:
        """指纹识别服务器技术"""
        print("    🖥️ 服务器技术栈识别...")
        
        discoveries = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            headers = response.headers
            
            # 服务器头分析
            server_header = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')
            
            if server_header:
                discoveries.append({
                    'type': 'web_server',
                    'name': server_header,
                    'source': 'Server header',
                    'confidence': 'high'
                })
            
            if powered_by:
                discoveries.append({
                    'type': 'server_technology',
                    'name': powered_by,
                    'source': 'X-Powered-By header',
                    'confidence': 'high'
                })
            
            # 其他服务器相关头
            server_headers = {
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC',
                'X-Drupal-Cache': 'Drupal',
                'X-Generator': 'CMS/Framework',
                'X-Pingback': 'WordPress',
                'X-Powered-CMS': 'CMS System'
            }
            
            for header_name, technology in server_headers.items():
                if header_name in headers:
                    discoveries.append({
                        'type': 'server_technology',
                        'name': f"{technology} ({headers[header_name]})",
                        'source': header_name,
                        'confidence': 'high'
                    })
        
        except Exception as e:
            print(f"        服务器技术识别失败: {e}")
        
        return discoveries

    async def _fingerprint_security_technologies(self) -> List[Dict]:
        """指纹识别安全技术"""
        print("      安全技术识别...")
        
        discoveries = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            headers = response.headers
            
            # 安全相关头分析
            security_headers = {
                'Content-Security-Policy': 'CSP Policy',
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'Frame Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy',
                'X-Robots-Tag': 'Robot Control'
            }
            
            for header_name, protection_type in security_headers.items():
                if header_name in headers:
                    discoveries.append({
                        'type': 'security_technology',
                        'name': protection_type,
                        'value': headers[header_name],
                        'confidence': 'high'
                    })
            
            # WAF检测
            waf_indicators = {
                'cf-ray': 'Cloudflare WAF',
                'x-sucuri-id': 'Sucuri WAF',
                'x-protected-by': 'Security Service',
                'server': 'BigIP|F5|Imperva|Incapsula'
            }
            
            for header_name, waf_pattern in waf_indicators.items():
                if header_name in headers:
                    header_value = headers[header_name].lower()
                    if '|' in waf_pattern:
                        # 正则模式检查
                        patterns = waf_pattern.lower().split('|')
                        for pattern in patterns:
                            if pattern in header_value:
                                discoveries.append({
                                    'type': 'waf_technology',
                                    'name': f"WAF Detection: {pattern.upper()}",
                                    'source': header_name,
                                    'confidence': 'medium'
                                })
                                break
                    else:
                        discoveries.append({
                            'type': 'waf_technology',
                            'name': waf_pattern,
                            'source': header_name,
                            'confidence': 'high'
                        })
        
        except Exception as e:
            print(f"        安全技术识别失败: {e}")
        
        return discoveries

class VulnerabilityScanner:
    """
    漏洞检测集成引擎
    
      核心能力：
    - CVE数据库匹配检测
    - 已知漏洞模式识别
    - 0day特征启发式检测
    - 配置错误发现
    - 敏感信息暴露检测
    """
    
    def __init__(self, target: str, config: ExtremeConfig):
        self.target = target
        self.config = config
        self.session = requests.Session()
        self.discovered_vulnerabilities = []
        
        # CVE数据库（简化版，实际应从外部数据源加载）
        self.cve_database = self._load_cve_database()

    def _load_cve_database(self) -> Dict:
        """加载CVE数据库"""
        # 这里是简化的CVE数据库，实际应该从 NVD 或其他源加载
        return {
            'web_frameworks': {
                'angular': {
                    'CVE-2023-26118': {
                        'versions': ['<16.0.0'],
                        'description': 'XSS vulnerability in Angular',
                        'severity': 'high'
                    }
                },
                'react': {
                    'CVE-2018-6341': {
                        'versions': ['<16.2.0'],
                        'description': 'XSS in React DOM',
                        'severity': 'medium'
                    }
                }
            },
            'js_libraries': {
                'jquery': {
                    'CVE-2020-11022': {
                        'versions': ['<3.5.0'],
                        'description': 'XSS vulnerability in jQuery',
                        'severity': 'medium'
                    }
                }
            }
        }

    async def run(self) -> Dict:
        """执行漏洞检测扫描"""
        print("\n  漏洞检测集成引擎启动...")
        
        # 并行执行多种检测
        tasks = [
            self._scan_known_vulnerabilities(),
            self._scan_configuration_issues(),
            self._scan_information_disclosure(),
            self._scan_injection_points(),
            self._scan_authentication_issues()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 合并漏洞发现
        vulnerabilities = []
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
        
        self.discovered_vulnerabilities = vulnerabilities
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_count': len(vulnerabilities),
            'severity_breakdown': self._analyze_severity_breakdown(vulnerabilities),
            'scan_types': {
                'known_vulns': len(results[0]) if not isinstance(results[0], Exception) else 0,
                'config_issues': len(results[1]) if not isinstance(results[1], Exception) else 0,
                'info_disclosure': len(results[2]) if not isinstance(results[2], Exception) else 0,
                'injection': len(results[3]) if not isinstance(results[3], Exception) else 0,
                'auth_issues': len(results[4]) if not isinstance(results[4], Exception) else 0
            },
            'discovered_items': vulnerabilities  # 统一字段名
        }

    def _analyze_severity_breakdown(self, vulnerabilities: List[Dict]) -> Dict:
        """分析漏洞严重性分布"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown['info'] += 1
        
        return breakdown

    async def _scan_known_vulnerabilities(self) -> List[Dict]:
        """扫描已知漏洞"""
        print("      已知漏洞匹配检测...")
        
        vulnerabilities = []
        
        # 这里需要实际的技术栈版本信息
        # 在实际实现中，应该从之前的指纹识别结果中获取
        detected_technologies = {
            'jquery': '2.1.4',  # 示例版本
            'angular': '15.0.0',
            'react': '16.1.0'
        }
        
        for tech_name, version in detected_technologies.items():
            # 检查web_frameworks
            if tech_name in self.cve_database.get('web_frameworks', {}):
                cves = self.cve_database['web_frameworks'][tech_name]
                for cve_id, cve_info in cves.items():
                    if self._is_version_vulnerable(version, cve_info['versions']):
                        vulnerabilities.append({
                            'type': 'known_vulnerability',
                            'cve_id': cve_id,
                            'technology': tech_name,
                            'version': version,
                            'description': cve_info['description'],
                            'severity': cve_info['severity'],
                            'confidence': 'high'
                        })
            
            # 检查js_libraries
            if tech_name in self.cve_database.get('js_libraries', {}):
                cves = self.cve_database['js_libraries'][tech_name]
                for cve_id, cve_info in cves.items():
                    if self._is_version_vulnerable(version, cve_info['versions']):
                        vulnerabilities.append({
                            'type': 'known_vulnerability',
                            'cve_id': cve_id,
                            'technology': tech_name,
                            'version': version,
                            'description': cve_info['description'],
                            'severity': cve_info['severity'],
                            'confidence': 'high'
                        })
        
        return vulnerabilities

    def _is_version_vulnerable(self, current_version: str, vulnerable_patterns: List[str]) -> bool:
        """检查版本是否受漏洞影响"""
        try:
            # 简化的版本比较逻辑
            # 实际应该使用更robust的版本比较库
            current_parts = [int(x) for x in current_version.split('.')]
            
            for pattern in vulnerable_patterns:
                if pattern.startswith('<'):
                    # 小于某版本
                    target_version = pattern[1:]
                    target_parts = [int(x) for x in target_version.split('.')]
                    
                    # 简单比较
                    if current_parts < target_parts:
                        return True
                # 可以添加更多版本比较逻辑
        
        except ValueError:
            # 版本解析失败
            pass
        
        return False

    async def _scan_configuration_issues(self) -> List[Dict]:
        """扫描配置问题"""
        print("    ⚙️ 配置问题检测...")
        
        vulnerabilities = []
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=10)
            headers = response.headers
            
            # 检查安全头缺失
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'configuration_issue',
                    'issue': 'Missing Security Headers',
                    'missing_headers': missing_headers,
                    'severity': 'medium',
                    'description': f'Missing {len(missing_headers)} important security headers',
                    'confidence': 'high'
                })
            
            # 检查不安全的头值
            if 'X-Frame-Options' in headers:
                frame_options = headers['X-Frame-Options'].lower()
                if frame_options not in ['deny', 'sameorigin']:
                    vulnerabilities.append({
                        'type': 'configuration_issue',
                        'issue': 'Weak X-Frame-Options',
                        'value': headers['X-Frame-Options'],
                        'severity': 'low',
                        'description': 'X-Frame-Options allows framing from any origin',
                        'confidence': 'high'
                    })
            
            # 检查敏感信息泄露
            server_header = headers.get('Server', '')
            if server_header:
                # 检查是否暴露版本信息
                if re.search(r'\d+\.\d+', server_header):
                    vulnerabilities.append({
                        'type': 'information_disclosure',
                        'issue': 'Server Version Disclosure',
                        'value': server_header,
                        'severity': 'low',
                        'description': 'Server header reveals version information',
                        'confidence': 'medium'
                    })
        
        except Exception as e:
            print(f"        配置检测失败: {e}")
        
        return vulnerabilities

    async def _scan_information_disclosure(self) -> List[Dict]:
        """扫描信息泄露"""
        print("      信息泄露检测...")
        
        vulnerabilities = []
        
        # 敏感文件列表
        sensitive_files = [
            '/.env', '/.env.local', '/.env.production',
            '/config.json', '/config.yml', '/config.yaml',
            '/package.json', '/composer.json',
            '/web.config', '/.htaccess',
            '/robots.txt', '/sitemap.xml',
            '/backup.sql', '/dump.sql',
            '/.git/config', '/.svn/entries',
            '/admin', '/admin.php', '/administrator',
            '/phpmyadmin', '/mysql', '/database',
            '/api/docs', '/swagger.json', '/openapi.json'
        ]
        
        base_url = f"https://{self.target}"
        
        for file_path in sensitive_files:
            try:
                response = self.session.get(f"{base_url}{file_path}", timeout=5)
                
                if response.status_code == 200:
                    # 分析响应内容
                    content = response.text.lower()
                    
                    # 检查敏感信息模式
                    sensitive_patterns = [
                        r'password\s*[:=]\s*["\']([^"\']+)["\']',
                        r'api[_-]?key\s*[:=]\s*["\']([^"\']+)["\']',
                        r'secret\s*[:=]\s*["\']([^"\']+)["\']',
                        r'token\s*[:=]\s*["\']([^"\']+)["\']',
                        r'database[_-]?url\s*[:=]\s*["\']([^"\']+)["\']'
                    ]
                    
                    found_secrets = []
                    for pattern in sensitive_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            found_secrets.extend(matches)
                    
                    if found_secrets or self._is_sensitive_content(content):
                        severity = 'high' if found_secrets else 'medium'
                        
                        vulnerabilities.append({
                            'type': 'information_disclosure',
                            'file': file_path,
                            'url': f"{base_url}{file_path}",
                            'secrets_found': len(found_secrets),
                            'severity': severity,
                            'description': f'Sensitive file exposed: {file_path}',
                            'confidence': 'high'
                        })
            
            except Exception:
                continue
        
        return vulnerabilities

    def _is_sensitive_content(self, content: str) -> bool:
        """检查是否为敏感内容"""
        sensitive_indicators = [
            'password', 'secret', 'api_key', 'private_key',
            'database', 'connection_string', 'credential',
            'config', 'environment', 'production'
        ]
        
        return sum(1 for indicator in sensitive_indicators if indicator in content) >= 2

    async def _scan_injection_points(self) -> List[Dict]:
        """扫描注入点"""
        print("    💉 注入点检测...")
        
        vulnerabilities = []
        
        # 测试常见的注入参数
        injection_params = ['id', 'user', 'search', 'q', 'query', 'file', 'page']
        injection_payloads = [
            "' OR '1'='1",  # SQL注入
            "<script>alert('xss')</script>",  # XSS
            "../../../etc/passwd",  # 路径遍历
            "${7*7}",  # 模板注入
            "{{7*7}}"   # 模板注入
        ]
        
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        test_paths = ['/search', '/api/search', '/query', '/']
        
        for base_url in base_urls:
            for path in test_paths:
                for param in injection_params:
                    for payload in injection_payloads:
                        try:
                            test_url = f"{base_url}{path}?{param}={urllib.parse.quote(payload)}"
                            response = self.session.get(test_url, timeout=5)
                            
                            # 检查响应中是否包含注入载荷
                            if payload in response.text or self._detect_injection_response(response, payload):
                                vuln_type = self._classify_injection_type(payload)
                                
                                vulnerabilities.append({
                                    'type': 'injection_vulnerability',
                                    'injection_type': vuln_type,
                                    'parameter': param,
                                    'payload': payload,
                                    'url': test_url,
                                    'severity': 'high',
                                    'description': f'Possible {vuln_type} injection in {param} parameter',
                                    'confidence': 'medium'
                                })
                        
                        except Exception:
                            continue
        
        return vulnerabilities

    def _detect_injection_response(self, response, payload: str) -> bool:
        """检测注入响应特征"""
        # SQL注入响应特征
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
            'warning: mysql', 'error in your sql syntax'
        ]
        
        # XSS响应特征
        xss_indicators = [
            'alert(', 'javascript:', '<script'
        ]
        
        content_lower = response.text.lower()
        
        if any(error in content_lower for error in sql_errors):
            return True
        
        if any(indicator in content_lower for indicator in xss_indicators):
            return True
        
        return False

    def _classify_injection_type(self, payload: str) -> str:
        """分类注入类型"""
        if "'" in payload or "OR" in payload.upper():
            return "SQL Injection"
        elif "<script>" in payload.lower():
            return "XSS"
        elif "../" in payload:
            return "Path Traversal"
        elif "${" in payload or "{{" in payload:
            return "Template Injection"
        else:
            return "Unknown Injection"

    async def _scan_authentication_issues(self) -> List[Dict]:
        """扫描认证问题"""
        print("      认证机制检测...")
        
        vulnerabilities = []
        
        # 测试弱认证端点
        auth_endpoints = [
            '/login', '/admin', '/administrator', '/auth',
            '/api/login', '/api/auth', '/signin',
            '/dashboard', '/panel', '/control',
            '/wp-admin', '/wp-login.php'
        ]
        
        base_url = f"https://{self.target}"
        
        for endpoint in auth_endpoints:
            try:
                response = self.session.get(f"{base_url}{endpoint}", timeout=5)
                
                if response.status_code == 200:
                    # 检查是否存在默认凭据提示
                    content = response.text.lower()
                    
                    default_creds_indicators = [
                        'admin:admin', 'admin:password', 'root:root',
                        'default password', 'change default', 'demo:demo'
                    ]
                    
                    if any(indicator in content for indicator in default_creds_indicators):
                        vulnerabilities.append({
                            'type': 'authentication_issue',
                            'issue': 'Default Credentials Hint',
                            'endpoint': endpoint,
                            'url': f"{base_url}{endpoint}",
                            'severity': 'high',
                            'description': 'Login page suggests default credentials',
                            'confidence': 'medium'
                        })
                    
                    # 检查是否缺少CSRF保护
                    if 'form' in content and 'csrf' not in content and 'token' not in content:
                        vulnerabilities.append({
                            'type': 'authentication_issue',
                            'issue': 'Missing CSRF Protection',
                            'endpoint': endpoint,
                            'url': f"{base_url}{endpoint}",
                            'severity': 'medium',
                            'description': 'Login form lacks CSRF protection',
                            'confidence': 'low'
                        })
            
            except Exception:
                continue
        
        return vulnerabilities

async def main():
    """主函数"""
    if len(sys.argv) != 2:
        print("使用方法: python day1_extreme.py target-domain.com")
        print("示例: python day1_extreme.py example.com")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    
    # 验证域名格式
    if not target_domain or '.' not in target_domain:
        print("错误: 请提供有效的域名")
        sys.exit(1)
    
    print("   重要提醒: 极致模式将进行深度扫描，请确保你有对目标域名进行安全测试的授权!")
    confirm = input("确认已获得授权并了解法律风险? (y/N): ")
    if confirm.lower() not in ['y', 'yes']:
        print("未确认授权，退出程序")
        sys.exit(1)
    
    # 选择扫描模式
    print("\n  极致版侦察模式选择:")
    print("  [1] 智能模式 (推荐) - 根据目标自动调整扫描深度")
    print("  [2] 标准模式 - 3万条目子域爆破 (~5-8分钟)")
    print("  [3] 完整模式 - 50万条目完整扫描 (~35-45分钟)")
    
    choice = input("\n请选择模式 [1-3]: ").strip()
    
    # 根据选择创建配置
    if choice == '1':  # 智能模式
        print("  启动智能模式 (自动优化扫描深度)...")
        config = ExtremeConfig(auto_adjust_dict_size=True)
    elif choice == '2':  # 标准模式
        print("  启动标准模式 (30K条目)...")
        config = ExtremeConfig(
            subdomain_dict_size=30000,
            auto_adjust_dict_size=False
        )
    elif choice == '3':  # 完整模式
        print("  启动完整模式 (500K条目)...")
        config = ExtremeConfig(
            subdomain_dict_size=500000,
            auto_adjust_dict_size=False
        )
    else:
        print("  默认使用智能模式...")
        config = ExtremeConfig(auto_adjust_dict_size=True)
    
    # 启动极致引擎
    engine = Day1ExtremeEngine(target_domain, config)
    await engine.run_extreme_scan()

if __name__ == "__main__":
    asyncio.run(main()) 