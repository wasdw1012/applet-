
#资产定位全面侦察


import asyncio
import aiohttp
import json
import logging
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set, Optional, Any
import re
import ssl
import certifi
from dataclasses import dataclass, field
from collections import deque
import ipaddress

@dataclass
class DomainDiscoveryResult:
    """域名发现结果"""
    domain: str
    source_domain: str = ""  # 从哪个域名发现的
    discovery_method: str = ""  # 发现方式
    discovery_depth: int = 0  # 发现深度
    timestamp: datetime = field(default_factory=datetime.now)
    is_internal: bool = False  # 是否内部域名
    risk_score: int = 0  # 风险评分

@dataclass 
class ChainTrackingConfig:
    """链式追踪配置"""
    max_scan_depth: int = 3  # 最大扫描深度
    max_domain_count: int = 10  # 最大域名数量
    scan_interval: float = 2.0  # 扫描间隔（秒）
    enable_internal_scan: bool = True  # 是否扫描内网域名
    enable_ip_scan: bool = False  # 是否扫描IP地址
    scope_domains: List[str] = field(default_factory=list)  # 扫描范围域名

class ChainTrackingManager:
    """史诗级链式追踪管理器 - 自动发现整个资产网络"""
    
    def __init__(self, initial_domain: str, config: ChainTrackingConfig = None):
        self.initial_domain = initial_domain
        self.config = config or ChainTrackingConfig()
        
        # 核心数据结构
        self.scanned_domains: Set[str] = set()  # 已扫描集合
        self.scan_queue: deque = deque()  # 待扫描队列
        self.global_results: Dict[str, 'ScanResult'] = {}  # 全局结果字典
        self.discovery_chain: Dict[str, DomainDiscoveryResult] = {}  # 发现链路
        
        # 统计信息
        self.chain_stats = {
            'total_discovered': 0,
            'total_scanned': 0,
            'depth_distribution': {},
            'discovery_methods': {},
            'high_risk_domains': [],
            'scan_duration': 0,
            'circular_references_blocked': 0,  # 循环引用阻止次数
            'concurrent_batches': 0,           # 并发批次数
            'total_concurrent_scans': 0       # 总并发扫描数
        }
        
        # 初始化：将初始域名加入队列
        initial_discovery = DomainDiscoveryResult(
            domain=initial_domain,
            source_domain="manual_input",
            discovery_method="initial_target",
            discovery_depth=0
        )
        self.scan_queue.append(initial_discovery)
        self.discovery_chain[initial_domain] = initial_discovery
        
        print(f"[+] 链式追踪管理器已初始化")
        print(f"    初始目标: {initial_domain}")
        print(f"    最大深度: {self.config.max_scan_depth}")
        print(f"    最大域名数: {self.config.max_domain_count}")
    
    def add_discovered_domain(self, domain: str, source_domain: str = "", 
                            discovery_method: str = "", depth: int = 0) -> bool:
        """添加新发现的域名"""
        # 标准化域名
        domain = self._normalize_domain(domain)
        if not domain:
            return False
        
        # 🔄 循环引用检测 - 避免A→B→A的情况
        if domain == source_domain:
            self.chain_stats['circular_references_blocked'] += 1
            print(f"[🔄] 阻止循环引用: {domain} ← {source_domain}")
            return False  # 跳过循环引用
        
        # 检查是否已存在
        if domain in self.scanned_domains or domain in [d.domain for d in self.scan_queue]:
            return False
        
        # 智能过滤
        if not self._should_scan_domain(domain, depth):
            return False
        
        # 创建发现结果
        discovery_result = DomainDiscoveryResult(
            domain=domain,
            source_domain=source_domain,
            discovery_method=discovery_method,
            discovery_depth=depth,
            is_internal=self._is_internal_domain(domain),
            risk_score=self._calculate_risk_score(domain)
        )
        
        # 加入队列和追踪链
        self.scan_queue.append(discovery_result)
        self.discovery_chain[domain] = discovery_result
        self.chain_stats['total_discovered'] += 1
        
        # 更新统计
        self.chain_stats['depth_distribution'][depth] = self.chain_stats['depth_distribution'].get(depth, 0) + 1
        self.chain_stats['discovery_methods'][discovery_method] = self.chain_stats['discovery_methods'].get(discovery_method, 0) + 1
        
        print(f"[+] 发现新域名: {domain} (来源: {source_domain}, 方式: {discovery_method}, 深度: {depth})")
        return True
    
    def get_next_scan_target(self) -> Optional[DomainDiscoveryResult]:
        """获取下一个扫描目标"""
        if not self.scan_queue:
            return None
        
        # 检查数量限制
        if len(self.scanned_domains) >= self.config.max_domain_count:
            print(f"[!] 达到最大扫描域名数限制: {self.config.max_domain_count}")
            return None
        
        return self.scan_queue.popleft()
    
    def mark_domain_scanned(self, domain: str, scan_result: 'ScanResult'):
        """标记域名已扫描"""
        self.scanned_domains.add(domain)
        self.global_results[domain] = scan_result
        self.chain_stats['total_scanned'] += 1
        
        # 评估风险等级
        risk_score = self._evaluate_scan_risk(scan_result)
        if risk_score > 70:
            self.chain_stats['high_risk_domains'].append(domain)
        
        print(f"[✓] 域名扫描完成: {domain} (风险评分: {risk_score})")
    
    def _normalize_domain(self, domain: str) -> str:
        """标准化域名"""
        if not domain:
            return ""
        
        # 移除协议前缀
        domain = re.sub(r'^https?://', '', domain)
        # 移除路径
        domain = domain.split('/')[0]
        # 移除端口
        domain = domain.split(':')[0]
        # 转换为小写
        domain = domain.lower().strip()
        
        # 基本验证
        if not domain or '.' not in domain:
            return ""
        
        return domain
    
    def _should_scan_domain(self, domain: str, depth: int) -> bool:
        """智能过滤：判断是否应该扫描该域名"""
        # 深度限制
        if depth > self.config.max_scan_depth:
            return False
        
        # 检查是否在扫描范围内
        if self.config.scope_domains:
            if not any(self._is_subdomain_of(domain, scope) for scope in self.config.scope_domains):
                return False
        else:
            # 默认只扫描主域名的子域名
            main_domain = self._extract_main_domain(self.initial_domain)
            if not self._is_subdomain_of(domain, main_domain):
                return False
        
        # 跳过明显的第三方域名
        if self._is_obvious_third_party(domain):
            return False
        
        # 内网域名检查
        if self._is_internal_domain(domain) and not self.config.enable_internal_scan:
            return False
        
        # IP地址检查
        if self._is_ip_address(domain) and not self.config.enable_ip_scan:
            return False
        
        return True
    
    def _is_subdomain_of(self, subdomain: str, main_domain: str) -> bool:
        """检查是否为子域名"""
        return subdomain == main_domain or subdomain.endswith('.' + main_domain)
    
    def _extract_main_domain(self, domain: str) -> str:
        """提取主域名"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    def _is_obvious_third_party(self, domain: str) -> bool:
        """检查是否为明显的第三方域名"""
        third_party_patterns = [
            'googleapis.com', 'cloudflare.com', 'amazon.com', 'microsoft.com',
            'google.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'bootstrap', 'jquery', 'cdnjs', 'jsdelivr', 'unpkg.com'
        ]
        return any(pattern in domain for pattern in third_party_patterns)
    
    def _is_internal_domain(self, domain: str) -> bool:
        """检查是否为内部域名"""
        internal_patterns = [
            '.local', '.internal', '.intranet', '.corp', '.lan',
            'localhost', '127.0.0.1', '10.', '172.', '192.168.'
        ]
        return any(pattern in domain for pattern in internal_patterns)
    
    def _is_ip_address(self, domain: str) -> bool:
        """检查是否为IP地址"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    def _calculate_risk_score(self, domain: str) -> int:
        """计算域名风险评分"""
        score = 50  # 基础分
        
        # 内部域名加分
        if self._is_internal_domain(domain):
            score += 30
        
        # 管理相关域名加分
        admin_keywords = ['admin', 'manage', 'console', 'panel', 'backend']
        if any(keyword in domain for keyword in admin_keywords):
            score += 20
        
        # 开发测试环境加分
        dev_keywords = ['dev', 'test', 'staging', 'beta', 'debug']
        if any(keyword in domain for keyword in dev_keywords):
            score += 15
        
        return min(score, 100)
    
    def _evaluate_scan_risk(self, scan_result: 'ScanResult') -> int:
        """评估扫描结果的风险等级"""
        score = 0
        
        # 敏感文件发现
        score += len(scan_result.files) * 10
        
        # 管理面板发现
        score += len(scan_result.admin_panels) * 15
        
        # API端点发现
        score += len(scan_result.api_routes) * 5
        
        # 表单发现
        score += len(scan_result.forms) * 8
        
        return min(score, 100)
    
    def has_more_targets(self) -> bool:
        """检查是否还有待扫描目标"""
        return len(self.scan_queue) > 0 and len(self.scanned_domains) < self.config.max_domain_count
    
    def get_chain_summary(self) -> Dict:
        """获取链式追踪摘要"""
        return {
            'initial_domain': self.initial_domain,
            'total_discovered': self.chain_stats['total_discovered'],
            'total_scanned': self.chain_stats['total_scanned'],
            'pending_scan': len(self.scan_queue),
            'depth_distribution': self.chain_stats['depth_distribution'],
            'discovery_methods': self.chain_stats['discovery_methods'],
            'high_risk_domains': self.chain_stats['high_risk_domains'],
            'circular_references_blocked': self.chain_stats['circular_references_blocked'],
            'concurrent_batches': self.chain_stats['concurrent_batches'],
            'total_concurrent_scans': self.chain_stats['total_concurrent_scans'],
            'discovery_chain': {domain: {
                'source': result.source_domain,
                'method': result.discovery_method,
                'depth': result.discovery_depth,
                'risk_score': result.risk_score
            } for domain, result in self.discovery_chain.items()}
        }

# 导入噪音过滤器 - 防止"傻逼兴奋"
NOISE_FILTER_AVAILABLE = False
try:
    # 尝试相对导入（作为模块运行时）
    from .third_party_blacklist import (
        smart_filter, 
        filter_third_party_urls,
        analyze_noise_level,
        is_third_party,
        has_security_value
    )
    NOISE_FILTER_AVAILABLE = True
except ImportError:
    try:
        # 尝试绝对导入（直接执行脚本时）
        from third_party_blacklist import (
            smart_filter,
            filter_third_party_urls,
            analyze_noise_level,
            is_third_party,
            has_security_value
        )
        NOISE_FILTER_AVAILABLE = True
    except ImportError:
        try:
            # 尝试从当前目录导入
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from third_party_blacklist import (
                smart_filter,
                filter_third_party_urls,
                analyze_noise_level,
                is_third_party,
                has_security_value
            )
            NOISE_FILTER_AVAILABLE = True
        except ImportError:
            print("  警告: 噪音过滤器不可用，可能会有大量第三方服务噪音")

# 导入 WAF Defender - 防止WAF欺骗响应
WAF_DEFENDER_AVAILABLE = False
try:
    # 尝试相对导入（作为模块运行时）
    from .waf_defender import create_waf_defender, WAFDefender
    WAF_DEFENDER_AVAILABLE = True
except ImportError:
    try:
        # 尝试绝对导入（直接执行脚本时）
        from waf_defender import create_waf_defender, WAFDefender
        WAF_DEFENDER_AVAILABLE = True
    except ImportError:
        try:
            # 尝试从当前目录导入
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from waf_defender import create_waf_defender, WAFDefender
            WAF_DEFENDER_AVAILABLE = True
        except ImportError:
            print("  警告: WAF Defender不可用，可能会受到WAF欺骗")

# 导入动态IP池 - 500个IP轮换
DYNAMIC_IP_AVAILABLE = False
try:
    from .dynamic_ip_pool import init_ip_pool, get_proxy_session, get_ip_stats, force_switch_ip, _global_ip_pool
    DYNAMIC_IP_AVAILABLE = True
except ImportError:
    try:
        from dynamic_ip_pool import init_ip_pool, get_proxy_session, get_ip_stats, force_switch_ip, _global_ip_pool
        DYNAMIC_IP_AVAILABLE = True
    except ImportError:
        try:
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from dynamic_ip_pool import init_ip_pool, get_proxy_session, get_ip_stats, force_switch_ip, _global_ip_pool
            DYNAMIC_IP_AVAILABLE = True
        except ImportError:
            print("  警告: 动态IP池不可用，将使用常规请求")

# 导入User-Agent管理器
USER_AGENT_AVAILABLE = False
try:
    from .user_agent_manager import UserAgentManager, get_user_agent_manager
    USER_AGENT_AVAILABLE = True
except ImportError:
    try:
        from user_agent_manager import UserAgentManager, get_user_agent_manager
        USER_AGENT_AVAILABLE = True
    except ImportError:
        try:
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from user_agent_manager import UserAgentManager, get_user_agent_manager
            USER_AGENT_AVAILABLE = True
        except ImportError:
            print("  警告: User-Agent管理器不可用，将使用基础请求头")

# 导入认证管理器 - 访问认证后的内部资产
try:
    from .auth_manager import AuthenticationManager, AuthConfig, create_auth_manager
    AUTH_MANAGER_AVAILABLE = True
    print("认证 认证管理器已加载 - 可访问认证后内部资产")
except ImportError:
    AUTH_MANAGER_AVAILABLE = False
    print("   警告: 认证管理器不可用 - 无法访问认证后资产")

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class RequestBypassEnhancer:
    """请求绕过增强器 - 专门用于绕过WAF和检测系统"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.current_ua = None
        self.current_headers = {}
        self.request_count = 0
        self.bypass_stats = {
            'ua_rotations': 0,
            'header_variations': 0,
            'requests_made': 0,
            'detected_blocks': 0
        }
        
        # 初始化User-Agent管理器
        if USER_AGENT_AVAILABLE:
            self.ua_manager = get_user_agent_manager()
        else:
            self.ua_manager = None
    
    def rotate_user_agent(self):
        """轮换User-Agent"""
        if self.ua_manager:
            self.current_ua = self.ua_manager.rotate_user_agent()
        else:
            self.current_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
        self.bypass_stats['ua_rotations'] += 1
        return self.current_ua
    
    def generate_realistic_headers(self):
        """生成逼真的HTTP请求头"""
        if self.ua_manager:
            headers = self.ua_manager.generate_realistic_headers(self.target_url, force_rotate=True)
            self.current_ua = headers.get('User-Agent')
        else:
            # 基础回退头
            headers = {
                'User-Agent': self.current_ua or self.rotate_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'no-cache',
            }
        
        self.current_headers = headers
        self.bypass_stats['header_variations'] += 1
        return headers
    
    async def create_enhanced_session(self):
        """创建增强会话（基础User-Agent模式）"""
        headers = self.generate_realistic_headers()
        
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=100,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )

@dataclass
class ScanResult:
    """树状关联模型的扫描结果数据结构"""
    # 核心：以资产为中心的树状字典
    assets: Dict[str, Dict] = field(default_factory=dict)
    
    # 保留少量无法归属到特定资产的发现
    orphaned_findings: Dict = field(default_factory=lambda: {
        "global_technologies": [],  # 全局技术栈信息
        "cdn_services": [],         # CDN 服务
        "external_apis": []         # 外部API调用
    })
    
    def add_asset(self, domain: str, asset_type: str = "subdomain", 
                  protocol: str = "", status: int = 0, title: str = "") -> None:
        """添加新资产或更新现有资产"""
        if domain not in self.assets:
            self.assets[domain] = {
                "type": asset_type,
                "protocol": protocol,
                "status": status,
                "title": title,
                "discovery_timestamp": datetime.now().isoformat(),
                "technologies": [],
                "endpoints": {},
                "forms": [],
                "files": [],
                "risk_score": 0,
                "waf_detected": False,
                "cms_info": {},
                "database_info": {},
                "server_info": {}
            }
        else:
            # 更新已存在的资产信息
            if protocol: self.assets[domain]["protocol"] = protocol
            if status: self.assets[domain]["status"] = status  
            if title: self.assets[domain]["title"] = title
    
    def add_endpoint(self, domain: str, path: str, endpoint_data: Dict) -> None:
        """为指定资产添加端点"""
        self.add_asset(domain)  # 确保资产存在
        self.assets[domain]["endpoints"][path] = endpoint_data
    
    def add_technology(self, domain: str, tech_data: Dict) -> None:
        """为指定资产添加技术栈信息"""
        self.add_asset(domain)  # 确保资产存在
        self.assets[domain]["technologies"].append(tech_data)
    
    def add_form(self, domain: str, form_data: Dict) -> None:
        """为指定资产添加表单"""
        self.add_asset(domain)  # 确保资产存在
        self.assets[domain]["forms"].append(form_data)
    
    def add_file(self, domain: str, file_data: Dict) -> None:
        """为指定资产添加敏感文件"""
        self.add_asset(domain)  # 确保资产存在
        self.assets[domain]["files"].append(file_data)
    
    def calculate_risk_scores(self) -> None:
        """计算每个资产的风险评分"""
        for domain, asset in self.assets.items():
            score = 0
            
            # 基础分数
            if asset["type"] == "main_domain":
                score += 20
            elif asset["type"] == "subdomain":
                score += 10
                
            # 端点数量影响
            endpoint_count = len(asset["endpoints"])
            score += min(endpoint_count * 5, 30)  # 最多30分
            
            # 高风险端点加分
            for path, endpoint in asset["endpoints"].items():
                if any(keyword in path.lower() for keyword in ['admin', 'login', 'api', 'graphql', 'upload']):
                    score += 15
                if endpoint.get("risk_level") == "high":
                    score += 20
                elif endpoint.get("risk_level") == "medium":
                    score += 10
            
            # 技术栈风险
            for tech in asset["technologies"]:
                if tech.get("category") == "framework":
                    score += 5
                if tech.get("has_vulnerabilities"):
                    score += 25
            
            # 表单数量
            score += len(asset["forms"]) * 3
            
            # 敏感文件
            score += len(asset["files"]) * 8
            
            # WAF检测影响（被保护的资产风险相对较低）
            if asset["waf_detected"]:
                score = int(score * 0.8)
            
            asset["risk_score"] = min(score, 100)  # 最高100分
    
    def get_attack_surface_map(self) -> Dict:
        """生成攻击面地图"""
        attack_map = {}
        
        for domain, asset in self.assets.items():
            # 识别攻击路径
            attack_paths = []
            
            # 管理后台路径
            admin_endpoints = [path for path in asset["endpoints"].keys() 
                             if any(keyword in path.lower() for keyword in ['admin', 'login', 'dashboard'])]
            if admin_endpoints:
                attack_paths.append({
                    "type": "admin_access",
                    "endpoints": admin_endpoints,
                    "risk": "high"
                })
            
            # API端点
            api_endpoints = [path for path in asset["endpoints"].keys()
                           if any(keyword in path.lower() for keyword in ['api', 'graphql', 'rest'])]
            if api_endpoints:
                attack_paths.append({
                    "type": "api_access", 
                    "endpoints": api_endpoints,
                    "risk": "medium"
                })
            
            # 上传功能
            upload_endpoints = [path for path in asset["endpoints"].keys()
                              if 'upload' in path.lower()]
            if upload_endpoints:
                attack_paths.append({
                    "type": "file_upload",
                    "endpoints": upload_endpoints, 
                    "risk": "high"
                })
            
            if attack_paths:
                attack_map[domain] = {
                    "asset_info": {
                        "risk_score": asset["risk_score"],
                        "technologies": [t.get("name", "") for t in asset["technologies"]],
                        "waf_protected": asset["waf_detected"]
                    },
                    "attack_paths": attack_paths
                }
        
        return attack_map
    
    def to_dict(self) -> Dict:
        """转换为字典格式 - 新的树状结构"""
        return {
            "assets": self.assets,
            "orphaned_findings": self.orphaned_findings,
            "asset_count": len(self.assets),
            "total_endpoints": sum(len(asset["endpoints"]) for asset in self.assets.values()),
            "attack_surface_map": self.get_attack_surface_map()
        }
    
    # 兼容性方法：为了不破坏现有代码，暂时保留旧的属性访问方式
    @property
    def subdomains(self) -> List[Dict]:
        """兼容性：返回子域名列表"""
        return [{"domain": domain, **asset} for domain, asset in self.assets.items() 
                if asset["type"] in ["subdomain", "main_domain"]]
    
    @property  
    def admin_panels(self) -> List[Dict]:
        """兼容性：返回管理面板列表"""
        panels = []
        for domain, asset in self.assets.items():
            for path, endpoint in asset["endpoints"].items():
                if any(keyword in path.lower() for keyword in ['admin', 'login', 'dashboard']):
                    panels.append({
                        "domain": domain,
                        "url": f"{asset['protocol']}://{domain}{path}",
                        "path": path,
                        **endpoint
                    })
        return panels
    
    @property
    def technologies(self) -> List[Dict]:
        """兼容性：返回技术栈列表"""  
        techs = []
        for domain, asset in self.assets.items():
            for tech in asset["technologies"]:
                techs.append({"domain": domain, **tech})
        return techs + self.orphaned_findings["global_technologies"]

class SimpleProxyPool:
    """轻量级代理池 - 直接读取500个IP并轮换"""
    
    def __init__(self, proxy_file: str = "新建文本文档.txt"):
        self.proxies = []
        self.index = 0
        self.proxy_file = proxy_file
        
        try:
            # 读取代理文件
            with open(proxy_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if ':' in line:
                        proxy_url = f"socks5://{line}"
                        self.proxies.append(proxy_url)
                    elif line:  # 非空行但格式错误
                        logger.warning(f"PROXY_POOL_ERROR: Line {line_num} invalid format: {line}")
            
            if not self.proxies:
                raise ValueError(f"PROXY_POOL_ERROR: No valid proxies found in {proxy_file}")
            
            logger.info(f"PROXY_POOL_SUCCESS: Loaded {len(self.proxies)} proxies from {proxy_file}")
            
        except FileNotFoundError:
            logger.error(f"PROXY_POOL_ERROR: File not found: {proxy_file}")
            raise
        except Exception as e:
            logger.error(f"PROXY_POOL_ERROR: Failed to load proxies: {e}")
            raise
    
    async def get_proxy(self) -> str:
        """获取下一个代理地址"""
        if not self.proxies:
            raise RuntimeError("PROXY_POOL_ERROR: No proxies available")
        
        proxy = self.proxies[self.index % len(self.proxies)]
        self.index += 1
        return proxy
    
    def get_stats(self) -> dict:
        """获取代理池统计信息"""
        return {
            'total_proxies': len(self.proxies),
            'current_index': self.index,
            'proxy_file': self.proxy_file
        }

@dataclass 
class AssetMapperConfig:
    """扫描配置"""
    max_crawl_pages: int = 100
    max_js_files: int = 50
    request_timeout: int = 10
    subdomain_timeout: int = 5
    concurrent_limit: int = 20
    enable_zone_transfer: bool = True
    enable_crt_check: bool = True
    max_retries: int = 3
    retry_delay: float = 0.5
    
    # 绕过增强配置
    use_dynamic_ip: bool = True  # 启用动态IP池
    use_user_agent: bool = True  # 启用User-Agent轮换
    
    # 认证配置
    enable_authentication: bool = False
    auth_config: Dict[str, Any] = field(default_factory=dict)

class AssetMapper:
    def __init__(self, target_domain: str, config: AssetMapperConfig = None, auth_config=None,
                 enable_chain_tracking: bool = True, chain_config: ChainTrackingConfig = None):
        self.target = target_domain
        self.config = config or AssetMapperConfig()
        self.results = ScanResult()
        self.session: Optional[aiohttp.ClientSession] = None
        self.domain_protocols: Dict[str, str] = {}  # 缓存域名协议信息
        self.start_time = time.time()
        
        # 🚀 史诗级链式追踪管理器
        self.enable_chain_tracking = enable_chain_tracking
        self.chain_tracking_manager = None
        if enable_chain_tracking:
            self.chain_tracking_manager = ChainTrackingManager(target_domain, chain_config)
            print(f"[+] 史诗级链式追踪已启用！")
        
        # 绕过增强器配置
        target_url = f"https://{target_domain}"  # 默认使用HTTPS
        self.bypass_enhancer = RequestBypassEnhancer(target_url)
        self.use_dynamic_ip = self.config.use_dynamic_ip and DYNAMIC_IP_AVAILABLE
        self.use_user_agent = self.config.use_user_agent and USER_AGENT_AVAILABLE
        self.dynamic_ip_initialized = False
        
        # 认证管理器配置
        self.auth_manager = None
        self.auth_config = auth_config or self.config.auth_config if self.config.enable_authentication else None
        if AUTH_MANAGER_AVAILABLE and self.auth_config:
            try:
                if isinstance(self.auth_config, dict):
                    auth_config_obj = AuthConfig(**self.auth_config)
                else:
                    auth_config_obj = self.auth_config
                self.auth_manager = AuthenticationManager(auth_config_obj)
                print("认证 认证管理器初始化成功 - 准备访问认证后内部资产")
            except Exception as e:
                print(f"   认证管理器初始化失败: {e}")
        
        # 智能决策状态
        self.is_wordpress: bool = False
        self.is_medical: bool = False
        self.detected_cloud_services: List[str] = []
        self.detected_waf: List[str] = []
        
        # 缓存机制
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl: int = 300  # 5分钟缓存
        
        # 并发控制信号量
        self.path_semaphore = asyncio.Semaphore(20)
        self.js_semaphore = asyncio.Semaphore(10)
        
        # 常见路径
        self.jp_paths = [
            "/admin", "/wp-admin", "/login", "/member", "/mypage",
            "/reserve", "/reservation", "/yoyaku", "/contact",
            "/patient", "/kanja", "/user",
            "/api", "/ajax", "/json",
            "/export", "/download", "/csv",
            "/backup", "/bak", "/old",
            "/.git", "/.env", "/config",
            "/phpmyadmin", "/pma", "/mysql"
        ]
        
        # 现代API路径
        self.api_paths = [
            "/graphql", "/graphiql", "/playground",
            "/__graphql", "/query", "/gql",
            "/api/v1", "/api/v2", "/api/v3",
            "/v1", "/v2", "/v3",
            "/swagger", "/swagger-ui", "/api-docs",
            "/openapi.json", "/swagger.json"
        ]
        
        # 第三方集成路径
        self.integration_paths = [
            "/oauth", "/auth", "/callback",
            "/login/line", "/login/google", 
            "/saml", "/sso",
            "/payment", "/stripe", "/paypal",
            "/callback/payment",
            "/line-notify", "/linepay"
        ]
        
        # 医疗相关路径
        self.medical_paths = [
            "/patient", "/kanja", "/患者",
            "/doctor", "/医師", "/ishi", 
            "/appointment", "/予約", "/yoyaku",
            "/medical", "/診療", "/shinryo",
            "/pharmacy", "/薬局", "/yakkyoku",
            "/insurance", "/保険", "/hoken",
            "/dicom", "/pacs", "/ris",
            "/hl7", "/fhir"
        ]
        
        # 合并所有路径
        self.jp_paths.extend(self.api_paths)
        self.jp_paths.extend(self.integration_paths)
        self.jp_paths.extend(self.medical_paths)
        
        # 关键文件定义
        self.key_files = [
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            ".htaccess", "web.config", 
            "package.json", "package-lock.json",  # npm依赖
            "composer.json", "composer.lock",      # PHP依赖
            "wp-config.php.bak", "wp-config.php~",
            ".env", ".env.production", ".env.local",  # 环境变量
            ".git/config", ".git/HEAD",               # Git信息
            ".DS_Store", "Thumbs.db",                 # 系统文件
            "webpack.config.js", "webpack.mix.js",    # Webpack配置
            ".map", "app.js.map", "main.js.map"      # Source Maps
        ]
        
        # 内部子域名前缀
        self.internal_prefixes = [
            "internal", "staff", "admin", "dev", "test", "staging",
            "api", "backend", "dashboard", "manage", "console",
            "vpn", "mail", "ftp", "db", "mysql", "postgres",
            "jenkins", "gitlab", "jira", "wiki", "doc"
        ]
        
        # 性能监控统计
        self.stats = {
            'requests_made': 0,
            'requests_failed': 0,
            'bytes_downloaded': 0,
            'cache_hits': 0,
            'proxy_switches': 0,
            'noise_filtered': 0,        # 过滤的噪音数量
            'valuable_findings': 0      # 有价值的发现
        }
        
        # 初始化噪音过滤统计（与git工具一致）
        self.noise_stats = {
            'total_checked': 0,
            'noise_filtered': 0,
            'valuable_kept': 0,
            'filter_enabled': NOISE_FILTER_AVAILABLE
        }
        
        # 代理池支持 - 自动初始化500个IP
        try:
            self.proxy_pool = SimpleProxyPool()
            logger.info(f"PROXY_POOL_INIT: Successfully initialized with {self.proxy_pool.get_stats()['total_proxies']} proxies")
        except Exception as e:
            logger.error(f"PROXY_POOL_INIT_FAILED: {e}")
            self.proxy_pool = None
        
        self.current_proxy = None
        
        # WAF Defender 状态
        self.waf_defender = None
        self.waf_defender_initialized = False
        
        # 初始化会话（如果有代理池则使用第一个代理）
        self._init_session()
    
    def _init_session(self):
        """初始化HTTP会话（使用系统代理）"""
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
        )
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        if self.session:
            await self.session.close()
    
    async def check_protocol(self, domain: str) -> Optional[str]:
        """智能检测域名支持的协议 - 支持认证"""
        if domain in self.domain_protocols:
            return self.domain_protocols[domain]
        
        # 确保session已创建
        if not self.session:
            await self._create_session()
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                resp = await self.safe_request(url, 'GET', timeout=3, allow_redirects=True)
                if resp and resp.status < 500:
                    self.domain_protocols[domain] = protocol
                    logger.debug(f"域名 {domain} 支持协议: {protocol}")
                    await resp.release()  # 释放连接
                    return protocol
                if resp:
                    await resp.release()
            except Exception as e:
                logger.debug(f"协议检测失败 {protocol}://{domain}: {type(e).__name__}")
                continue
        
        logger.warning(f"无法连接到域名: {domain}")
        return None
    
    async def _initialize_waf_defender(self, protocol: str):
        """初始化 WAF Defender"""
        if not WAF_DEFENDER_AVAILABLE or self.waf_defender_initialized:
            return
        
        try:
            target_url = f"{protocol}://{self.target}"
            logger.info("[+] 初始化WAF Defender...")
            
            # 确保session已创建
            if not self.session:
                await self._create_session()
            
            self.waf_defender = await create_waf_defender(target_url, self.session)
            self.waf_defender_initialized = True
            
            logger.info(f"[+] WAF Defender初始化成功 (目标: {target_url})")
            
            # 显示WAF Defender基线信息
            if hasattr(self.waf_defender, 'get_stats'):
                stats = self.waf_defender.get_stats()
                logger.info(f"[+] WAF Defender 基线数量: {stats.get('baseline_count', 'unknown')}")
                logger.info(f"[+] WAF Defender 检测能力: {', '.join(stats.get('detection_capabilities', []))}")
            
        except Exception as e:
            logger.warning(f"[-] WAF Defender初始化失败: {e}")
            self.waf_defender = None
            self.waf_defender_initialized = False
    
    async def safe_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """安全的HTTP请求（支持绕过增强 + 认证管理器 + 重试机制 + 性能监控）"""
        start_time = time.time()
        
        for attempt in range(self.config.max_retries):
            try:
                # 认证管理器：为请求添加认证信息
                if self.auth_manager:
                    try:
                        kwargs = await self.auth_manager.prepare_request(url, **kwargs)
                    except Exception as e:
                        logger.debug(f"认证准备失败: {e}")
                
                # 使用增强会话（动态IP + User-Agent）
                if self.use_dynamic_ip or self.use_user_agent:
                    async with await self.get_enhanced_session() as enhanced_session:
                        if method.upper() == 'GET':
                            response = await enhanced_session.get(url, **kwargs)
                        elif method.upper() == 'POST':
                            response = await enhanced_session.post(url, **kwargs)
                        else:
                            response = await enhanced_session.request(method, url, **kwargs)
                        
                        # 更新绕过统计
                        self.bypass_enhancer.bypass_stats['requests_made'] += 1
                else:
                    # 使用标准session
                    if method.upper() == 'GET':
                        response = await self.session.get(url, **kwargs)
                    elif method.upper() == 'POST':
                        response = await self.session.post(url, **kwargs)
                    else:
                        response = await self.session.request(method, url, **kwargs)
                
                # 认证管理器：检查响应认证状态
                auth_ok = True
                if self.auth_manager:
                    auth_ok = await self.auth_manager.handle_response(response, url)
                    if not auth_ok and self.auth_manager.should_retry(response):
                        # 认证失效，尝试恢复
                        logger.debug("检测到认证失效，尝试恢复...")
                        await response.release()  # 释放当前连接
                        
                        recovery_success = await self.auth_manager._recover_authentication()
                        if recovery_success:
                            # 重新准备请求并重试
                            kwargs = await self.auth_manager.prepare_request(url, **kwargs)
                            if method.upper() == 'GET':
                                response = await self.session.get(url, **kwargs)
                            elif method.upper() == 'POST':
                                response = await self.session.post(url, **kwargs)
                            else:
                                response = await self.session.request(method, url, **kwargs)
                
                # 更新成功统计
                self.stats['requests_made'] += 1
                request_time = time.time() - start_time
                
                if hasattr(self, '_request_times'):
                    self._request_times.append(request_time)
                else:
                    self._request_times = [request_time]
                
                # 限制请求时间列表大小（内存优化）
                if len(self._request_times) > 1000:
                    self._request_times = self._request_times[-500:]
                
                # WAF欺骗检测
                if (self.waf_defender and self.waf_defender_initialized and 
                    response.status == 200):
                    try:
                        # 根据响应内容猜测预期类型
                        content_type = response.headers.get('Content-Type', '')
                        if 'json' in content_type:
                            expected_type = 'json'
                        elif 'html' in content_type:
                            expected_type = 'html'
                        else:
                            expected_type = 'unknown'
                        
                        is_real = await self.waf_defender.validate(url, response, expected_type=expected_type)
                        if not is_real:
                            logger.warning(f"WAF欺骗检测: {url} - 跳过伪造响应")
                            await response.release()  # 释放连接
                            continue  # 重试或返回None
                    except Exception as e:
                        logger.debug(f"WAF检测异常: {e}")
                        # WAF检测失败时不影响正常流程
                
                return response
            
            except asyncio.TimeoutError:
                logger.debug(f"请求超时 {url} (尝试 {attempt + 1}/{self.config.max_retries})")
                self.stats['requests_failed'] += 1
            except aiohttp.ClientError as e:
                logger.debug(f"客户端错误 {url}: {type(e).__name__} (尝试 {attempt + 1}/{self.config.max_retries})")
                self.stats['requests_failed'] += 1
            except Exception as e:
                logger.debug(f"请求异常 {url}: {type(e).__name__} (尝试 {attempt + 1}/{self.config.max_retries})")
                self.stats['requests_failed'] += 1
            
            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))
        
        logger.warning(f"请求最终失败: {url}")
        self.stats['requests_failed'] += 1
        return None
    
    async def _maybe_switch_proxy(self):
        """根据需要切换代理（代理池集成支持）"""
        if self.proxy_pool:
            try:
                new_proxy = await self.proxy_pool.get_proxy()
                if new_proxy != self.current_proxy:
                    await self.setup_proxy_session(new_proxy)
                    self.stats['proxy_switches'] += 1
                    logger.debug(f"PROXY_SWITCH_SUCCESS: Changed to {new_proxy}")
            except Exception as e:
                logger.warning(f"PROXY_SWITCH_FAILED: {e}")
    
    def _optimize_memory(self):
        """内存优化 - 智能清理和噪音过滤"""
        original_count = len(self.results.api_routes)
        
        # 第一步：噪音清理（如果可用）
        if NOISE_FILTER_AVAILABLE and original_count > 0:
            logger.info("执行智能噪音清理...")
            
            # 分析当前噪音水平
            noise_analysis = analyze_noise_level([route.get('route', '') for route in self.results.api_routes])
            
            if noise_analysis['noise_ratio'] > 0.3:  # 超过30%是噪音
                logger.warning(f"检测到高噪音环境: {noise_analysis['noise_ratio']:.1%} 的发现是第三方噪音")
                
                # 执行深度清理
                cleaned_routes = []
                for route in self.results.api_routes:
                    route_url = route.get('route', '')
                    route_type = route.get('type', 'unknown')
                    
                    # 高价值类型总是保留
                    if route_type in ['credential', 'internal_host']:
                        cleaned_routes.append(route)
                        continue
                    
                    # 其他类型使用智能过滤
                    if smart_filter(route_url, 'api_endpoint'):
                        cleaned_routes.append(route)
                    else:
                        self.stats['noise_filtered'] += 1
                
                noise_removed = len(self.results.api_routes) - len(cleaned_routes)
                self.results.api_routes = cleaned_routes
                logger.info(f"噪音清理完成: 移除 {noise_removed} 个噪音，保留 {len(cleaned_routes)} 个有价值发现")
        
        # 第二步：去重和数量限制
        if len(self.results.api_routes) > 1000:
            logger.warning(f"API路由仍然过多 ({len(self.results.api_routes)}), 执行去重...")
            
            # 智能去重：按价值优先级排序
            prioritized_routes = sorted(
                self.results.api_routes,
                key=lambda x: self._get_route_priority(x),
                reverse=True
            )
            
            # 去重逻辑
            seen_routes = set()
            deduplicated_routes = []
            
            for route in prioritized_routes:
                route_key = route.get('route', '')
                if route_key not in seen_routes:
                    seen_routes.add(route_key)
                    deduplicated_routes.append(route)
                    
                    # 限制最大数量
                    if len(deduplicated_routes) >= 500:
                        break
            
            self.results.api_routes = deduplicated_routes
            logger.info(f"智能去重完成，保留 {len(deduplicated_routes)} 个最有价值的发现")
        
        # 第三步：清理过大的缓存
        if len(self.cache) > 500:
            # 保留最近的250个缓存项
            cache_items = list(self.cache.items())
            cache_items.sort(key=lambda x: x[1].get('time', 0), reverse=True)
            self.cache = dict(cache_items[:250])
            logger.debug("缓存优化完成")
        
        # 优化统计
        final_count = len(self.results.api_routes)
        if original_count != final_count:
            reduction = (original_count - final_count) / original_count
            logger.info(f"内存优化完成: {original_count} → {final_count} (-{reduction:.1%})")
    
    def _get_route_priority(self, route: dict) -> int:
        """计算路由优先级分数（用于排序）"""
        score = 0
        route_type = route.get('type', '')
        route_content = route.get('route', '').lower()
        risk_level = route.get('risk_level', 'low')
        
        # 类型优先级
        type_scores = {
            'credential': 100,      # 凭据最高优先级
            'internal_host': 90,    # 内部主机
            'graphql': 80,          # GraphQL
            'api_endpoint': 70,     # API端点
            'unknown': 10
        }
        score += type_scores.get(route_type, 10)
        
        # 风险等级加分
        risk_scores = {
            'critical': 50,
            'high': 30,
            'medium': 20,
            'low': 10
        }
        score += risk_scores.get(risk_level, 10)
        
        # 内容价值加分
        if any(keyword in route_content for keyword in ['admin', 'api', 'secret', 'token', 'internal']):
            score += 20
        
        return score
    
    def get_performance_stats(self) -> Dict:
        """获取性能统计信息"""
        stats = self.stats.copy()
        
        if hasattr(self, '_request_times') and self._request_times:
            stats['avg_request_time'] = sum(self._request_times) / len(self._request_times)
            stats['max_request_time'] = max(self._request_times)
            stats['min_request_time'] = min(self._request_times)
        
        # 成功率
        total_requests = stats['requests_made'] + stats['requests_failed']
        if total_requests > 0:
            stats['success_rate'] = stats['requests_made'] / total_requests
        else:
            stats['success_rate'] = 0.0
        
        # 缓存命中率
        total_cache_requests = stats.get('cache_hits', 0) + stats['requests_made']
        if total_cache_requests > 0:
            stats['cache_hit_rate'] = stats.get('cache_hits', 0) / total_cache_requests
        else:
            stats['cache_hit_rate'] = 0.0
        
        return stats
    
    async def _create_session(self):
        """创建统一的HTTP session - 支持认证和代理"""
        if self.session and not self.session.closed:
            return self.session
        
        # 如果有代理池且没有设置当前代理，使用第一个代理
        if self.proxy_pool and not self.current_proxy:
            try:
                first_proxy = await self.proxy_pool.get_proxy()
                await self.setup_proxy_session(first_proxy)
                logger.info(f"PROXY_INIT_SUCCESS: Using first proxy {first_proxy}")
                return self.session
            except Exception as e:
                logger.error(f"PROXY_INIT_FAILED: {e}, falling back to no proxy")
        
        # 如果已有代理会话，直接返回
        if self.current_proxy:
            return self.session
        
        # 创建session（使用系统代理设置）
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers=headers
        )
        
        logger.info("SESSION_INIT: Created session without proxy")
        return self.session



    async def get_enhanced_session(self):
        """获取终极增强会话 - 动态IP + User-Agent 组合拳"""
        if self.use_dynamic_ip and self.dynamic_ip_initialized:
            # === 终极组合模式：动态IP + User-Agent ===
            ip = self.get_current_ip()
            if ip:
                # 创建带代理的增强会话
                headers = self.bypass_enhancer.generate_realistic_headers()
                
                connector = aiohttp.TCPConnector(
                    ssl=False,
                    limit=100,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                )
                
                timeout = aiohttp.ClientTimeout(total=30, connect=10)
                proxy_url = f'http://{ip}'
                
                session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers=headers
                )
                
                # 设置代理
                session._proxy = proxy_url
                return session
            else:
                logger.warning("[!] 动态IP获取失败，回退到User-Agent绕过模式")
                if DYNAMIC_IP_AVAILABLE:
                    force_switch_ip()  # 强制切换IP
        
        # 使用User-Agent绕过模式
        if self.use_user_agent:
            return await self.bypass_enhancer.create_enhanced_session()
        else:
            # 基础会话
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            return aiohttp.ClientSession(timeout=timeout)
    
    def get_current_ip(self):
        """获取当前动态IP"""
        try:
            # 直接调用全局IP池
            if DYNAMIC_IP_AVAILABLE and _global_ip_pool:
                if hasattr(_global_ip_pool, 'working_ips') and _global_ip_pool.working_ips:
                    return _global_ip_pool.get_random_ip()
        except:
            pass
        return None
    
    def _print_bypass_stats(self):
        """输出绕过增强统计"""
        logger.info("=== 绕过增强统计 ===")
        
        if self.use_dynamic_ip and self.dynamic_ip_initialized:
            try:
                if DYNAMIC_IP_AVAILABLE:
                    ip_stats = get_ip_stats()
                    logger.info(f"动态IP池: {ip_stats.get('working_count', 0)} 个有效IP")
                    logger.info(f"IP切换次数: {ip_stats.get('switch_count', 0)}")
            except:
                logger.info("动态IP池: 统计获取失败")
        elif self.use_dynamic_ip:
            logger.info("动态IP池: 初始化失败，已禁用")
        
        if self.use_user_agent:
            stats = self.bypass_enhancer.bypass_stats
            logger.info(f"User-Agent轮换: {stats['ua_rotations']} 次")
            logger.info(f"请求头变体: {stats['header_variations']} 次")
            
            # 显示当前User-Agent信息
            if self.bypass_enhancer.ua_manager:
                try:
                    ua_info = self.bypass_enhancer.ua_manager.get_user_agent_info()
                    if ua_info:
                        logger.info(f"当前UA: {ua_info.get('browser', 'Unknown')} {ua_info.get('version', '')} "
                                   f"({ua_info.get('os', 'Unknown')} {ua_info.get('device', 'Desktop')})")
                except:
                    logger.info("当前UA: 信息获取失败")
        else:
            logger.info("User-Agent轮换: 未启用")

    async def _cleanup_session(self):
        """清理session资源"""
        if self.session and not self.session.closed:
            await self.session.close()
        
        if self.auth_manager:
            try:
                await self.auth_manager.cleanup()
            except Exception as e:
                logger.debug(f"认证管理器清理异常: {e}")
           
    async def run(self) -> ScanResult:
        """🚀 史诗级主执行函数 - 链式追踪资产映射 + 认证支持"""
        
        # 如果启用链式追踪，使用史诗级循环模式
        if self.enable_chain_tracking and self.chain_tracking_manager:
            return await self._run_chain_tracking_mode()
        else:
            # 传统单点扫描模式
            return await self._run_single_target_mode()
    
    async def _run_chain_tracking_mode(self) -> ScanResult:
        """🚀 史诗级链式追踪扫描模式"""
        logger.info("="*80)
        logger.info("🚀 史诗级链式追踪资产映射启动！")
        logger.info("📡 自动发现和扫描整个资产网络")
        logger.info("="*80)
        
        chain_start_time = time.time()
        
        # 显示组件状态
        self._display_component_status()
        
        # 链式扫描主循环 - 批量并发优化
        scan_round = 0
        total_scan_result = ScanResult()
        concurrent_limit = 3  # 最大并发扫描数
        
        try:
            while self.chain_tracking_manager.has_more_targets():
                scan_round += 1
                
                # 🚀 批量获取扫描目标（2-3个并发）
                batch_targets = []
                for _ in range(concurrent_limit):
                    next_target = self.chain_tracking_manager.get_next_scan_target()
                    if next_target:
                        batch_targets.append(next_target)
                    else:
                        break
                
                if not batch_targets:
                    break
                
                # 统计并发批次
                if len(batch_targets) > 1:
                    self.chain_tracking_manager.chain_stats['concurrent_batches'] += 1
                    self.chain_tracking_manager.chain_stats['total_concurrent_scans'] += len(batch_targets)
                
                # 显示批次信息
                if len(batch_targets) == 1:
                    logger.info(f"\n🎯 [第{scan_round}轮] 单目标扫描: {batch_targets[0].domain}")
                else:
                    logger.info(f"\n🚀 [第{scan_round}轮] 并发扫描 {len(batch_targets)} 个目标:")
                    for target in batch_targets:
                        logger.info(f"   🎯 {target.domain} (来源: {target.source_domain}, 方式: {target.discovery_method}, 深度: {target.discovery_depth})")
                
                # 🚀 并发执行扫描任务
                scan_tasks = []
                for target in batch_targets:
                    async def scan_single_target(target_info):
                        # 临时设置目标域名
                        original_target = self.target
                        self.target = target_info.domain
                        try:
                            result = await self._run_single_target_mode(suppress_logs=True)
                            return target_info, result
                        finally:
                            self.target = original_target
                    
                    scan_tasks.append(scan_single_target(target))
                
                # 等待所有并发扫描完成
                batch_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                
                # 处理批次扫描结果
                for i, result in enumerate(batch_results):
                    if isinstance(result, Exception):
                        logger.error(f"   ❌ {batch_targets[i].domain} 扫描失败: {result}")
                        continue
                    
                    target_info, scan_result = result
                    
                    # 🔍 从扫描结果中提取新发现的域名
                    await self._extract_domains_from_scan_result(scan_result, target_info)
                    
                    # 标记当前域名已扫描
                    self.chain_tracking_manager.mark_domain_scanned(target_info.domain, scan_result)
                    
                    # 合并结果到总结果
                    self._merge_scan_results(total_scan_result, scan_result)
                    
                    logger.info(f"   ✅ {target_info.domain} 扫描完成")
                
                # 批次扫描间隔控制
                if self.chain_tracking_manager.config.scan_interval > 0:
                    await asyncio.sleep(self.chain_tracking_manager.config.scan_interval)
            
            # 链式追踪完成，生成史诗级总报告
            await self._generate_chain_tracking_report(total_scan_result, chain_start_time)
            
            return total_scan_result
            
        except Exception as e:
            logger.error(f"链式追踪扫描异常: {e}")
            return total_scan_result
        finally:
            await self._cleanup_session()
    
    async def _run_single_target_mode(self, suppress_logs: bool = False) -> ScanResult:
        """传统单目标扫描模式"""
        if not suppress_logs:
            logger.info(f"开始扫描目标: {self.target}")
            logger.info(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self._display_component_status()
        
        try:
            # 初始化动态IP池
            if self.use_dynamic_ip:
                logger.info("[+] 初始化动态IP池...")
                try:
                    if await init_ip_pool():
                        self.dynamic_ip_initialized = True
                        logger.info("[+] 动态IP池初始化成功!")
                    else:
                        logger.warning("[!] 动态IP池初始化失败，回退到User-Agent模式")
                        self.use_dynamic_ip = False
                except Exception as e:
                    logger.warning(f"[!] 动态IP池初始化异常: {e}")
                    self.use_dynamic_ip = False
            
            # 初始化组件
            await self._create_session()
            
            # 初始化认证管理器
            if self.auth_manager:
                await self.auth_manager.initialize()
                logger.info("认证 认证管理器初始化完成 - 准备访问认证后内部资产")
                
                # 显示认证统计
                auth_stats = self.auth_manager.get_auth_stats()
                auth_type = auth_stats.get('current_auth_type', 'unknown')
                logger.info(f"认证 认证类型: {auth_type}")
            
            # 首先检测主域名协议
            main_protocol = await self.check_protocol(self.target)
            if not main_protocol:
                logger.error(f"无法连接到主域名: {self.target}")
                return self.results
            
            logger.info(f"主域名协议: {main_protocol}://{self.target}")
            
            # 初始化 WAF Defender
            await self._initialize_waf_defender(main_protocol)
            
            # 并行执行所有扫描任务
            logger.info("启动并行扫描任务...")
            
            # 第一阶段：基础扫描
            basic_tasks = [
                self.subdomain_enum(),
                self.crawl_site(),
                self.tech_fingerprint()
            ]
            
            basic_results = await asyncio.gather(*basic_tasks, return_exceptions=True)
            
            # 智能路径发现（基于已发现的技术栈）
            await self.smart_path_discovery()
            
            # 第二阶段：深度扫描
            deep_tasks = [
                self.find_admin_panels(),
                self.scan_key_files(),
                self.extract_js_data_enhanced(),
                self.deep_tech_fingerprint(),
                self.medical_system_detection()
            ]
            
            tasks = basic_tasks + deep_tasks
            
            # 使用 gather 并处理异常
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 检查任务执行结果
            for i, result in enumerate(results):
                task_names = ['子域名枚举', '网站爬取', '后台扫描', '文件扫描', 'JS分析', '技术识别']
                if isinstance(result, Exception):
                    logger.error(f"{task_names[i]}任务失败: {type(result).__name__}: {result}")
                else:
                    logger.info(f"{task_names[i]}任务完成")
            
            # 内存优化
            logger.info("执行内存优化...")
            self._optimize_memory()
            
            # 生成报告和攻击面分析
            attack_surface = self.analyze_attack_surface()
            self.generate_report()
            
            scan_time = time.time() - self.start_time
            
            # 输出性能统计
            perf_stats = self.get_performance_stats()
            logger.info(f"扫描完成，耗时: {scan_time:.2f}秒")
            logger.info(f"性能统计: 请求 {perf_stats['requests_made']}, 成功率 {perf_stats['success_rate']:.2%}")
            
            # 噪音过滤统计（与git工具一致）
            if NOISE_FILTER_AVAILABLE and self.noise_stats['total_checked'] > 0:
                noise_ratio = self.noise_stats['noise_filtered'] / max(self.noise_stats['total_checked'], 1)
                logger.info(f"噪音过滤统计:")
                logger.info(f"    - 总检查: {self.noise_stats['total_checked']}")
                logger.info(f"    - 噪音过滤: {self.noise_stats['noise_filtered']}")
                logger.info(f"    - 有价值保留: {self.noise_stats['valuable_kept']}")
                logger.info(f"    - 噪音率: {noise_ratio:.1%}")
                
                if noise_ratio > 0.5:
                    logger.info("    - 效果: 成功避免了严重的'傻逼兴奋' - 大量第三方噪音被过滤")
                elif self.noise_stats['noise_filtered'] > 0:
                    logger.info("    - 效果: 智能过滤生效，保持高质量结果")
                else:
                    logger.info("    - 效果: 目标质量良好，无需过滤")
            elif NOISE_FILTER_AVAILABLE:
                logger.info("噪音过滤: 已启用，但未检测到需要过滤的内容")
            else:
                logger.info("噪音过滤: 未启用 - 建议启用以提高扫描质量")
            
            if perf_stats.get('avg_request_time'):
                logger.info(f"平均请求时间: {perf_stats['avg_request_time']:.3f}秒")
            if perf_stats.get('proxy_switches', 0) > 0:
                logger.info(f"代理切换: {perf_stats['proxy_switches']} 次")
            
            # 输出绕过增强统计
            if self.use_dynamic_ip or self.use_user_agent:
                self._print_bypass_stats()
            
            # 输出攻击面分析建议
            self._print_attack_recommendations(attack_surface)
            
            return self.results
            
        except Exception as e:
            logger.error(f"扫描过程中发生致命错误: {type(e).__name__}: {e}")
            return self.results
        finally:
            # 清理资源
            await self._cleanup_session()
    
    def _display_component_status(self):
        """显示组件状态"""
        waf_status = "OK" if WAF_DEFENDER_AVAILABLE else "错误"
        noise_status = "OK" if NOISE_FILTER_AVAILABLE else "错误"
        auth_status = "认证OK" if self.auth_manager else "  "
        
        logger.info(f"[*] WAF防护: {waf_status}")
        logger.info(f"[*] 噪音过滤: {noise_status}")
        logger.info(f"[*] 认证管理: {auth_status}")
        
        # 显示绕过模式
        if self.use_dynamic_ip:
            logger.info(f"[*] 绕过模式: 终极组合拳 (动态IP + User-Agent + 智能请求头)")
        elif self.use_user_agent:
            logger.info(f"[*] 绕过模式: User-Agent轮换 + 智能请求头")
        else:
            logger.info(f"[*] 绕过模式: 基础模式")
    
    async def _extract_domains_from_scan_result(self, scan_result: ScanResult, current_target: DomainDiscoveryResult):
        """🔍 从扫描结果中提取新发现的域名"""
        discovered_count = 0
        
        # 1. 从子域名枚举结果中提取
        for subdomain in scan_result.subdomains:
            domain = subdomain.get('subdomain', '')
            if self.chain_tracking_manager.add_discovered_domain(
                domain=domain,
                source_domain=current_target.domain,
                discovery_method="subdomain_enum",
                depth=current_target.discovery_depth + 1
            ):
                discovered_count += 1
        
        # 2. 从JS文件中提取域名
        for endpoint in scan_result.endpoints:
            if endpoint.get('source') == 'js_analysis':
                # 提取URL中的域名
                url = endpoint.get('url', '')
                if url:
                    domain = self._extract_domain_from_url(url)
                    if domain and self.chain_tracking_manager.add_discovered_domain(
                        domain=domain,
                        source_domain=current_target.domain,
                        discovery_method="js_analysis",
                        depth=current_target.discovery_depth + 1
                    ):
                        discovered_count += 1
        
        # 3. 从API响应中提取内部域名
        for api_route in scan_result.api_routes:
            # 解析API响应中可能包含的内部域名
            description = api_route.get('description', '')
            potential_domains = self._extract_domains_from_text(description)
            for domain in potential_domains:
                if self.chain_tracking_manager.add_discovered_domain(
                    domain=domain,
                    source_domain=current_target.domain,
                    discovery_method="api_response",
                    depth=current_target.discovery_depth + 1
                ):
                    discovered_count += 1
        
        # 4. 从SSL证书中提取域名（如果有WAF Defender信息）
        if hasattr(self, 'waf_defender') and self.waf_defender:
            # 这里可以添加SSL证书域名提取逻辑
            pass
        
        # 5. 从技术栈信息中提取相关域名
        for tech in scan_result.technologies:
            tech_info = tech.get('details', '')
            potential_domains = self._extract_domains_from_text(tech_info)
            for domain in potential_domains:
                if self.chain_tracking_manager.add_discovered_domain(
                    domain=domain,
                    source_domain=current_target.domain,
                    discovery_method="tech_fingerprint",
                    depth=current_target.discovery_depth + 1
                ):
                    discovered_count += 1
        
        if discovered_count > 0:
            logger.info(f"    🔍 新发现 {discovered_count} 个域名加入扫描队列")
        else:
            logger.info(f"    🔍 未发现新的目标域名")
    
    def _extract_domain_from_url(self, url: str) -> str:
        """从URL中提取域名"""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            domain = parsed.netloc
            # 移除端口号
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain.lower()
        except:
            return ""
    
    def _extract_domains_from_text(self, text: str) -> List[str]:
        """从文本中提取潜在的域名"""
        if not text:
            return []
        
        # 域名正则表达式
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        potential_domains = re.findall(domain_pattern, text)
        
        # 过滤明显的垃圾域名
        valid_domains = []
        for domain in potential_domains:
            domain = domain.lower()
            # 排除明显的文件扩展名等
            if not domain.endswith(('.jpg', '.png', '.gif', '.css', '.js', '.pdf', '.zip')):
                valid_domains.append(domain)
        
        return valid_domains
    
    def _merge_scan_results(self, total_result: ScanResult, current_result: ScanResult):
        """合并扫描结果到总结果"""
        total_result.endpoints.extend(current_result.endpoints)
        total_result.forms.extend(current_result.forms)
        total_result.api_routes.extend(current_result.api_routes)
        total_result.admin_panels.extend(current_result.admin_panels)
        total_result.files.extend(current_result.files)
        total_result.subdomains.extend(current_result.subdomains)
        total_result.technologies.extend(current_result.technologies)
    
    async def _generate_chain_tracking_report(self, total_result: ScanResult, chain_start_time: float):
        """🚀 生成史诗级链式追踪总报告"""
        chain_duration = time.time() - chain_start_time
        chain_summary = self.chain_tracking_manager.get_chain_summary()
        
        logger.info("\n" + "="*100)
        logger.info("🚀 史诗级链式追踪完成！资产网络全景报告")
        logger.info("="*100)
        
        # 基础统计
        logger.info(f"📊 总体统计:")
        logger.info(f"   🎯 初始目标: {chain_summary['initial_domain']}")
        logger.info(f"   🔍 发现域名: {chain_summary['total_discovered']} 个")
        logger.info(f"   ✅ 扫描完成: {chain_summary['total_scanned']} 个")
        logger.info(f"   ⏱️  总耗时: {chain_duration:.2f} 秒")
        logger.info(f"   ⚡ 平均扫描时间: {chain_duration/max(chain_summary['total_scanned'], 1):.2f} 秒/域名")
        
        # 深度分布
        if chain_summary['depth_distribution']:
            logger.info(f"\n📊 发现深度分布:")
            for depth, count in sorted(chain_summary['depth_distribution'].items()):
                logger.info(f"   📊 深度 {depth}: {count} 个域名")
        
        # 发现方式统计
        if chain_summary['discovery_methods']:
            logger.info(f"\n🔍 发现方式统计:")
            for method, count in sorted(chain_summary['discovery_methods'].items(), key=lambda x: x[1], reverse=True):
                logger.info(f"   🔍 {method}: {count} 个域名")
        
        # 🚀 优化效果统计
        logger.info(f"\n🚀 优化效果统计:")
        logger.info(f"   🔄 循环引用阻止: {chain_summary.get('circular_references_blocked', 0)} 次")
        logger.info(f"   ⚡ 并发批次: {chain_summary.get('concurrent_batches', 0)} 次")
        logger.info(f"   🚀 并发扫描总数: {chain_summary.get('total_concurrent_scans', 0)} 个")
        if chain_summary.get('concurrent_batches', 0) > 0:
            avg_concurrent = chain_summary.get('total_concurrent_scans', 0) / chain_summary.get('concurrent_batches', 1)
            logger.info(f"   📊 平均并发数: {avg_concurrent:.1f} 个/批次")
            efficiency_gain = (chain_summary.get('total_concurrent_scans', 0) - chain_summary.get('concurrent_batches', 0)) / max(chain_summary['total_scanned'], 1) * 100
            logger.info(f"   ⚡ 效率提升: 约 {efficiency_gain:.1f}%")
        
        # 高风险域名
        if chain_summary['high_risk_domains']:
            logger.info(f"\n⚠️  高风险域名 ({len(chain_summary['high_risk_domains'])} 个):")
            for domain in chain_summary['high_risk_domains'][:10]:  # 只显示前10个
                logger.info(f"   ⚠️  {domain}")
        
        # 发现链路图
        logger.info(f"\n🔗 发现链路图:")
        discovery_chain = chain_summary['discovery_chain']
        for domain, info in list(discovery_chain.items())[:15]:  # 显示前15个
            if info['source'] == 'manual_input':
                logger.info(f"   🎯 {domain} (初始目标)")
            else:
                logger.info(f"   🔗 {domain} ← {info['source']} (通过{info['method']}, 深度{info['depth']}, 风险{info['risk_score']})")
        
        if len(discovery_chain) > 15:
            logger.info(f"   ... 还有 {len(discovery_chain) - 15} 个域名")
        
        # 汇总高危发现
        logger.info(f"\n🎯 全网络高危发现汇总:")
        logger.info(f"   🎯 API端点: {len(total_result.api_routes)} 个")
        logger.info(f"   🎯 管理面板: {len(total_result.admin_panels)} 个")
        logger.info(f"   🎯 敏感文件: {len(total_result.files)} 个")
        logger.info(f"   🎯 表单接口: {len(total_result.forms)} 个")
        logger.info(f"   🎯 子域名: {len(total_result.subdomains)} 个")
        logger.info(f"   🎯 技术栈: {len(total_result.technologies)} 个")
        
        # 绕过增强统计
        if self.use_dynamic_ip or self.use_user_agent:
            self._print_bypass_stats()
        
        logger.info("="*100)
        logger.info("🎉 史诗级链式追踪任务完成！完整的资产网络情报已获取！")
        logger.info("="*100)

    async def subdomain_enum(self):
        """子域名枚举 - 增强版"""
        logger.info("开始子域名枚举...")
        
        subdomains = set()
        
        # 1. 使用外部工具
        tools = [
            ("subfinder", f"subfinder -d {self.target} -silent"),
            ("amass", f"amass enum -passive -d {self.target} -silent")
        ]
        
        for tool_name, cmd in tools:
            try:
                logger.debug(f"运行工具: {tool_name}")
                result = subprocess.run(
                    cmd.split(), 
                    capture_output=True, 
                    text=True, 
                    timeout=60
                )
                if result.returncode == 0:
                    found_domains = [d.strip() for d in result.stdout.strip().split('\n') if d.strip()]
                    subdomains.update(found_domains)
                    logger.info(f"{tool_name} 发现 {len(found_domains)} 个子域名")
                else:
                    logger.warning(f"{tool_name} 执行失败: {result.stderr}")
            except subprocess.TimeoutExpired:
                logger.warning(f"{tool_name} 执行超时")
            except FileNotFoundError:
                logger.debug(f"{tool_name} 工具未安装")
            except Exception as e:
                logger.debug(f"{tool_name} 执行异常: {type(e).__name__}: {e}")
        
        # 2. 证书透明度日志查询
        if self.config.enable_crt_check:
            await self.query_crtsh(subdomains)
        
        # 3. DNS Zone Transfer尝试
        if self.config.enable_zone_transfer:
            await self.try_zone_transfer(subdomains)
        
        # 4. 内部域名猜测
        logger.debug("添加猜测的内部域名...")
        for prefix in self.internal_prefixes:
            subdomains.add(f"{prefix}.{self.target}")
        
        # 5. 验证存活的子域名
        await self._verify_subdomains(subdomains)
        
        logger.info(f"子域名枚举完成，发现 {len(self.results.subdomains)} 个存活域名")
    
    async def _verify_subdomains(self, subdomains: Set[str]):
        """验证子域名存活状态"""
        logger.info(f"验证 {len(subdomains)} 个子域名...")
        
        # 创建验证任务
        tasks = []
        semaphore = asyncio.Semaphore(10)  # 限制并发数
        
        async def verify_single_subdomain(subdomain: str):
            async with semaphore:
                if not subdomain or subdomain == self.target:
                    return
                
                protocol = await self.check_protocol(subdomain)
                if protocol:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = await self.safe_request(url, timeout=self.config.subdomain_timeout)
                        if response and response.status < 500:
                            # 🌟 新的树状存储方式
                            self.results.add_asset(
                                domain=subdomain,
                                asset_type="subdomain",
                                protocol=protocol,
                                status=response.status,
                                title=await self._extract_title(response)
                            )
                            logger.debug(f"存活子域名: {protocol}://{subdomain} ({response.status})")
                    except Exception as e:
                        logger.debug(f"子域名验证失败 {subdomain}: {type(e).__name__}")
        
        # 启动所有验证任务
        for subdomain in subdomains:
            tasks.append(verify_single_subdomain(subdomain.strip()))
        
        # 等待所有任务完成
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _extract_title(self, response: aiohttp.ClientResponse) -> str:
        """提取页面标题"""
        try:
            content = await response.text()
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.I)
            if title_match:
                return title_match.group(1).strip()[:100]  # 限制长度
        except Exception:
            pass
        return ""
    
    async def smart_path_discovery(self):
        """智能路径探测 - 根据已发现内容动态生成路径"""
        logger.info("智能路径发现...")
        
        additional_paths = []
        
        # WordPress相关路径
        if self.is_wordpress:
            logger.info("检测到WordPress，添加专项路径")
            wp_paths = [
                '/wp-json/wp/v2/users',
                '/wp-json/wp/v2/posts', 
                '/?rest_route=/wp/v2/users',
                '/wp-content/debug.log',
                '/wp-config.php.bak',
                '/wp-admin/admin-ajax.php',
                '/xmlrpc.php'
            ]
            additional_paths.extend(wp_paths)
        
        # 医疗系统相关路径
        if self.is_medical:
            logger.info("检测到医疗系统，添加专项路径")
            medical_paths = [
                '/api/patients/export',
                '/api/appointments/list',
                '/medical/records/download',
                '/ris/studies',
                '/pacs/wado',
                '/hie/patient/search'
            ]
            additional_paths.extend(medical_paths)
        
        # 根据检测到的技术栈添加路径
        for tech in self.results.technologies:
            tech_name = tech.get('name', '').lower()
            if 'react' in tech_name:
                additional_paths.extend(['/static/js/main.*.js.map', '/manifest.json'])
            elif 'vue' in tech_name:
                additional_paths.extend(['/js/app.*.js.map', '/js/chunk-vendors.*.js.map'])
            elif 'laravel' in tech_name:
                additional_paths.extend(['/api/user', '/telescope', '/horizon'])
        
        if additional_paths:
            self.jp_paths.extend(additional_paths)
            logger.info(f"添加了 {len(additional_paths)} 个智能路径")
    
    async def check_path_cached(self, url: str) -> Optional[Dict]:
        """带缓存的路径检查（增强版）"""
        # 检查缓存
        if url in self.cache:
            cache_entry = self.cache[url]
            if time.time() - cache_entry['time'] < self.cache_ttl:
                self.stats['cache_hits'] += 1
                logger.debug(f"使用缓存: {url}")
                return cache_entry['data']
        
        # 使用并发控制
        async with self.path_semaphore:
            result = await self._check_admin_path(url)
            
            # 存入缓存
            self.cache[url] = {
                'data': result,
                'time': time.time()
            }
            
            return result
    
    def set_proxy_pool(self, proxy_pool):
        """设置代理池（供外部调用）"""
        self.proxy_pool = proxy_pool
        logger.info("代理池已设置，支持自动切换代理")
    
    async def setup_proxy_session(self, proxy_endpoint: str):
        """使用指定代理设置会话 - 支持SOCKS5"""
        if self.session:
            await self.session.close()
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        try:
            if proxy_endpoint.startswith('socks5://'):
                # 使用SOCKS5代理
                import aiohttp_socks
                connector = aiohttp_socks.ProxyConnector.from_url(proxy_endpoint, ssl=ssl_context)
                logger.debug(f"PROXY_SESSION: Using SOCKS5 connector for {proxy_endpoint}")
            else:
                # 使用HTTP代理
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context,
                    limit=self.config.concurrent_limit,
                    limit_per_host=10,
                    ttl_dns_cache=300,
                    use_dns_cache=True
                )
                logger.debug(f"PROXY_SESSION: Using HTTP connector for {proxy_endpoint}")
            
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            
            session_kwargs = {
                'connector': connector,
                'timeout': timeout,
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                }
            }
            
            # 只有HTTP代理才需要proxy参数
            if not proxy_endpoint.startswith('socks5://'):
                session_kwargs['proxy'] = proxy_endpoint
            
            self.session = aiohttp.ClientSession(**session_kwargs)
            self.current_proxy = proxy_endpoint
            logger.info(f"PROXY_SESSION_SUCCESS: Set proxy {proxy_endpoint}")
            
        except ImportError:
            logger.error("PROXY_SESSION_ERROR: aiohttp_socks not available for SOCKS5 proxy")
            raise
        except Exception as e:
            logger.error(f"PROXY_SESSION_ERROR: Failed to setup proxy session: {e}")
            raise
    
    async def extract_js_data_enhanced(self):
        """增强的JS分析 - 提取更多敏感信息"""
        logger.info("开始增强JS分析...")
        
        main_protocol = await self.check_protocol(self.target)
        if not main_protocol:
            return
        
        base_url = f"{main_protocol}://{self.target}"
        
        try:
            response = await self.safe_request(base_url)
            if not response:
                return
            
            html = await response.text()
            
            # 找出所有JS文件
            js_files = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)', html)
            
            # 限制分析文件数量
            js_files = js_files[:self.config.max_js_files]
            
            # 并发分析JS文件
            tasks = []
            for js_file in js_files:
                task = self._analyze_single_js_file(urljoin(base_url, js_file))
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info(f"JS分析完成，分析了 {len(js_files)} 个文件")
            
        except Exception as e:
            logger.debug(f"JS分析失败: {type(e).__name__}: {e}")
    
    async def _analyze_single_js_file(self, js_url: str):
        """分析单个JS文件"""
        async with self.js_semaphore:
            try:
                response = await self.safe_request(js_url, timeout=5)
                if not response:
                    return
                
                js_content = await response.text()
                
                # 1. 提取硬编码凭据
                await self._extract_credentials(js_content, js_url)
                
                # 2. 提取内部域名/IP
                await self._extract_internal_hosts(js_content, js_url)
                
                # 3. 提取API端点
                await self._extract_api_endpoints(js_content, js_url)
                
                # 4. GraphQL schema提取
                await self._extract_graphql_info(js_content, js_url)
                
                # 5. 检查Source Map
                await self._check_source_map(js_content, js_url)
                
            except Exception as e:
                logger.debug(f"JS文件分析失败 {js_url}: {type(e).__name__}")
    
    async def _extract_credentials(self, js_content: str, source: str):
        """提取硬编码凭据"""
        credential_patterns = [
            (r'["\'](?:api[_-]?key|apikey)["\']:\s*["\']([a-zA-Z0-9\-_]{20,})["\']', 'API Key'),
            (r'["\'](?:secret|token)["\']:\s*["\']([a-zA-Z0-9\-_]{20,})["\']', 'Secret/Token'),
            (r'(?:Bearer|Token)\s+([a-zA-Z0-9\-_\.]{20,})', 'Bearer Token'),
            (r'["\'](?:password|pwd)["\']:\s*["\']([^"\']{8,})["\']', 'Password'),
            (r'(?:access_token|accessToken)["\']:\s*["\']([^"\']{20,})["\']', 'Access Token')
        ]
        
        for pattern, cred_type in credential_patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                if len(match) >= 20:  # 过滤短值
                    # 🌟 新的树状存储方式：从源URL提取域名
                    domain = self._extract_domain_from_url(source)
                    if domain:
                        self.results.add_endpoint(
                            domain=domain,
                            path=f"/js_analysis/credential/{cred_type.lower().replace(' ', '_')}",
                            endpoint_data={
                                "credential_type": cred_type,
                                "credential_preview": f"{match[:30]}...",
                        "source": source,
                                "endpoint_type": "credential_leak",
                                "risk_level": "critical",
                                "discovery_method": "js_analysis"
                            }
                        )
    
    async def _extract_internal_hosts(self, js_content: str, source: str):
        """提取内部域名和IP"""
        internal_patterns = [
            (r'https?://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', 'Internal IP'),
            (r'https?://([a-zA-Z0-9\-]+\.internal)', 'Internal Domain'),
            (r'https?://([a-zA-Z0-9\-]+\.local)', 'Local Domain'),
            (r'https?://([a-zA-Z0-9\-]+\.intranet)', 'Intranet Domain'),
            (r'https?://([a-zA-Z0-9\-]+\.corp)', 'Corp Domain')
        ]
        
        for pattern, host_type in internal_patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                # 🌟 新的树状存储方式：从源URL提取域名
                domain = self._extract_domain_from_url(source)
                if domain:
                    self.results.add_endpoint(
                        domain=domain,
                        path=f"/js_analysis/internal_host/{match}",
                        endpoint_data={
                            "host_type": host_type,
                            "internal_host": match,
                    "source": source,
                            "endpoint_type": "internal_host_leak",
                            "risk_level": "high",
                            "discovery_method": "js_analysis"
                        }
                    )
    
    async def _extract_api_endpoints(self, js_content: str, source: str):
        """提取API端点 - 智能噪音过滤版"""
        api_patterns = [
            r'["\']/(api/[^"\']+)',
            r'["\']/(graphql[^"\']*)',
            r'["\']/(rest/[^"\']+)',
            r'endpoint["\']:\s*["\']([^"\']+)',
            r'baseURL["\']:\s*["\']([^"\']+)',
            r'apiUrl["\']:\s*["\']([^"\']+)'
        ]
        
        total_found = 0
        noise_filtered = 0
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                total_found += 1
                self.noise_stats['total_checked'] += 1
                
                if len(match) <= 3:  # 过滤太短的匹配
                    continue
                
                # 智能噪音过滤 - 防止"傻逼兴奋"
                if NOISE_FILTER_AVAILABLE:
                    # 检查是否是第三方噪音
                    if is_third_party(match):
                        # 但如果有安全价值，仍然保留
                        if not has_security_value(match):
                            noise_filtered += 1
                            self.stats['noise_filtered'] += 1
                            self.noise_stats['noise_filtered'] += 1
                            logger.debug(f"过滤第三方噪音: {match}")
                            continue
                
                # 这是有价值的发现
                self.stats['valuable_findings'] += 1
                self.noise_stats['valuable_kept'] += 1
                
                # 🌟 新的树状存储方式：从源URL提取域名
                domain = self._extract_domain_from_url(source)
                if domain:
                    self.results.add_endpoint(
                        domain=domain,
                        path=match,
                        endpoint_data={
                    "source": source,
                            "endpoint_type": "api_endpoint",
                            "risk_level": "medium",
                            "filtered": False,
                            "discovery_method": "js_analysis"
                        }
                    )
        
        # 日志统计
        if total_found > 0:
            noise_ratio = noise_filtered / total_found
            if noise_ratio > 0.5:
                logger.info(f"API端点噪音过滤: {noise_filtered}/{total_found} ({noise_ratio:.1%}) - 避免了傻逼兴奋")
            elif noise_filtered > 0:
                logger.debug(f"过滤了 {noise_filtered} 个第三方API端点")
    
    async def _extract_graphql_info(self, js_content: str, source: str):
        """提取GraphQL信息 - 智能过滤版"""
        graphql_patterns = [
            (r'type\s+(\w+)\s*{[^}]+}', 'GraphQL Type'),
            (r'__schema', 'GraphQL Introspection'),
            (r'IntrospectionQuery', 'GraphQL Introspection Query'),
            (r'query\s+(\w+)\s*{', 'GraphQL Query'),
            (r'mutation\s+(\w+)\s*{', 'GraphQL Mutation')
        ]
        
        for pattern, gql_type in graphql_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                route_content = f"[GRAPHQL: {gql_type}] {match if isinstance(match, str) else 'found'}"
                
                # GraphQL发现通常很有价值，但也要检查是否来自第三方
                self.noise_stats['total_checked'] += 1
                
                if NOISE_FILTER_AVAILABLE and is_third_party(source):
                    # 如果来源是第三方JS，但GraphQL schema泄露仍有价值
                    if gql_type not in ['GraphQL Introspection', 'IntrospectionQuery']:
                        self.stats['noise_filtered'] += 1
                        self.noise_stats['noise_filtered'] += 1
                        logger.debug(f"过滤第三方GraphQL噪音: {route_content}")
                        continue
                
                self.stats['valuable_findings'] += 1
                self.noise_stats['valuable_kept'] += 1
                
                # 🌟 新的树状存储方式：从源URL提取域名
                domain = self._extract_domain_from_url(source)
                if domain:
                    self.results.add_endpoint(
                        domain=domain,
                        path=f"/graphql/{gql_type.lower().replace(' ', '_')}",
                        endpoint_data={
                            "graphql_type": gql_type,
                            "content": route_content,
                    "source": source,
                            "endpoint_type": "graphql",
                            "risk_level": "high" if gql_type in ['GraphQL Introspection', 'IntrospectionQuery'] else "medium",
                            "discovery_method": "js_analysis"
                        }
                    )
    
    async def _check_source_map(self, js_content: str, js_url: str):
        """检查并下载Source Map"""
        if '//# sourceMappingURL=' in js_content:
            map_match = re.search(r'//# sourceMappingURL=([^\s]+)', js_content)
            if map_match:
                map_url = urljoin(js_url, map_match.group(1))
                map_response = await self.safe_request(map_url, timeout=3)
                if map_response and map_response.status == 200:
                    map_content = await map_response.read()
                    self.results.files.append({
                        "file": "source_map",
                        "url": map_url,
                        "size": len(map_content),
                        "preview": "Source map - 包含原始源代码!",
                        "risk_level": "high"
                    })
    
    async def deep_tech_fingerprint(self):
        """深度技术栈识别"""
        logger.info("深度技术栈识别...")
        
        main_protocol = await self.check_protocol(self.target)
        if not main_protocol:
            return
        
        response = await self.safe_request(f"{main_protocol}://{self.target}")
        if not response:
            return
        
        headers = dict(response.headers)
        html = await response.text()
        
        # 1. 检测具体框架版本
        await self._detect_framework_versions(html)
        
        # 2. 检测云服务
        await self._detect_cloud_services(headers, html)
        
        # 3. 检测安全设备/WAF
        await self._detect_waf_signatures(headers, html)
        
        logger.info(f"技术栈识别完成: {len(self.results.technologies)} 项技术")
    
    async def _detect_framework_versions(self, html: str):
        """检测框架版本"""
        version_patterns = {
            'wordpress': r'wp-includes/js/wp-embed\.min\.js\?ver=([\d\.]+)',
            'jquery': r'jquery[/-]([\d\.]+)',
            'react': r'react@([\d\.]+)',
            'vue': r'vue@([\d\.]+)',
            'bootstrap': r'bootstrap[/-]([\d\.]+)'
        }
        
        for framework, pattern in version_patterns.items():
            matches = re.findall(pattern, html, re.I)
            for version in matches:
                # 🌟 新的树状存储方式：技术栈关联到主域名
                self.results.add_technology(
                    domain=self.target,
                    tech_data={
                        "category": "framework_version",
                    "name": f"{framework.title()} v{version}",
                        "version": version,
                        "framework": framework.title(),
                        "has_vulnerabilities": self._check_framework_vulnerabilities(framework, version),
                        "discovery_method": "html_analysis"
                    }
                )
                
                # 设置WordPress标志
                if framework == 'wordpress':
                    self.is_wordpress = True
    
    def _check_framework_vulnerabilities(self, framework: str, version: str) -> bool:
        """检查框架版本是否存在已知漏洞（简化版）"""
        # 这里可以集成CVE数据库，目前使用简单的版本判断
        vulnerable_versions = {
            'wordpress': ['5.7', '5.6', '5.5'],  # 示例
            'drupal': ['8.9', '9.0', '9.1'],
            'joomla': ['3.9', '4.0']
        }
        
        if framework.lower() in vulnerable_versions:
            return version in vulnerable_versions[framework.lower()]
        return False
    
    async def _detect_cloud_services(self, headers: Dict, html: str):
        """检测云服务"""
        cloud_indicators = {
            'aws': {
                'headers': ['x-amz-cf-id', 'x-amz-request-id'],
                'content': ['amazonaws.com', 'cloudfront.net', 's3.amazonaws.com']
            },
            'gcp': {
                'headers': ['x-goog-trace'],
                'content': ['googleapis.com', 'googleusercontent.com', 'storage.googleapis.com']
            },
            'azure': {
                'headers': ['x-azure-ref'],
                'content': ['azurewebsites.net', 'blob.core.windows.net', 'azureedge.net']
            },
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status'],
                'content': ['cloudflare.com', 'cdnjs.cloudflare.com']
            }
        }
        
        for cloud, indicators in cloud_indicators.items():
            detected = False
            
            # 检查headers
            for header in indicators['headers']:
                if header in headers:
                    detected = True
                    break
            
            # 检查内容
            if not detected:
                html_lower = html.lower()
                for content_indicator in indicators['content']:
                    if content_indicator in html_lower:
                        detected = True
                        break
            
            if detected:
                self.detected_cloud_services.append(cloud)
                # 🌟 新的树状存储方式：云服务技术栈关联到主域名
                self.results.add_technology(
                    domain=self.target,
                    tech_data={
                        "category": "cloud_service",
                    "name": cloud.upper(),
                        "detail": f"检测到{cloud}云服务特征",
                        "service_type": "cloud_infrastructure",
                        "discovery_method": "header_content_analysis"
                    }
                )
    
    async def _detect_waf_signatures(self, headers: Dict, html: str):
        """检测WAF/安全设备"""
        waf_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', '__cfduid', 'cf-cache-status'],
                'content': ['cloudflare', 'attention required']
            },
            'akamai': {
                'headers': ['akamai-cache-status'],
                'content': ['akamai', 'akamaihd.net']
            },
            'incapsula': {
                'headers': ['x-iinfo'],
                'content': ['incap_ses', 'visid_incap']
            },
            'sucuri': {
                'headers': ['x-sucuri-cache'],
                'content': ['sucuri', 'cloudproxy']
            }
        }
        
        for waf, signatures in waf_signatures.items():
            detected = False
            
            # 检查headers
            for header in signatures['headers']:
                if header in headers:
                    detected = True
                    break
            
            # 检查内容
            if not detected:
                html_lower = html.lower()
                for content_sig in signatures['content']:
                    if content_sig in html_lower:
                        detected = True
                        break
            
            if detected:
                self.detected_waf.append(waf)
                # 🌟 新的树状存储方式：WAF技术栈关联到主域名
                self.results.add_technology(
                    domain=self.target,
                    tech_data={
                        "category": "security_device",
                    "name": f"{waf.upper()} WAF",
                        "detail": f"检测到{waf} Web应用防火墙",
                        "security_type": "web_application_firewall",
                        "discovery_method": "waf_signature_analysis"
                    }
                )
                # 标记资产受WAF保护
                self.results.add_asset(self.target)
                self.results.assets[self.target]["waf_detected"] = True
    
    async def medical_system_detection(self):
        """医疗系统专项检测"""
        logger.info("医疗系统专项检测...")
        
        main_protocol = await self.check_protocol(self.target)
        if not main_protocol:
            return
        
        base_url = f"{main_protocol}://{self.target}"
        
        # FHIR API端点检测
        fhir_endpoints = [
            '/fhir/Patient',
            '/fhir/Appointment', 
            '/fhir/Medication',
            '/fhir/metadata',
            '/fhir/Observation'
        ]
        
        # DICOM/PACS端点检测
        dicom_endpoints = [
            '/dicom-web/studies',
            '/pacs/studies',
            '/wado',
            '/dcm4chee',
            '/orthanc'
        ]
        
        # HL7/医疗集成端点
        hl7_endpoints = [
            '/hl7/messages',
            '/hie/patient/search',
            '/emr/api',
            '/his/api'
        ]
        
        all_medical_endpoints = fhir_endpoints + dicom_endpoints + hl7_endpoints
        
        medical_found = 0
        for endpoint in all_medical_endpoints:
            url = urljoin(base_url, endpoint)
            response = await self.safe_request(url, timeout=5)
            
            if response and response.status in [200, 401, 403]:
                medical_found += 1
                # 🌟 新的树状存储方式：医疗端点关联到主域名
                path = f"/medical/{endpoint.split('/')[-1]}"
                self.results.add_endpoint(
                    domain=self.target,
                    path=path,
                    endpoint_data={
                    "url": url,
                    "status": response.status,
                    "risk_level": "critical" if response.status == 200 else "high",
                        "endpoint_type": "medical_system",
                        "description": "医疗系统API端点",
                        "discovery_method": "medical_system_scan"
                    }
                )
        
        if medical_found > 0:
            self.is_medical = True
            logger.info(f"检测到医疗系统，发现 {medical_found} 个医疗相关端点")
            
            # 🌟 新的树状存储方式：医疗系统技术栈关联到主域名  
            self.results.add_technology(
                domain=self.target,
                tech_data={
                    "category": "medical_system",
                "name": "医疗信息系统",
                    "detail": f"发现 {medical_found} 个医疗相关端点",
                    "endpoint_count": medical_found,
                    "compliance_required": True,
                    "data_sensitivity": "high",
                    "discovery_method": "medical_system_scan"
                }
            )
    
    def prioritize_findings(self):
        """对发现进行优先级排序"""
        priority_keywords = {
            'critical': ['admin', 'config', 'backup', 'sql', 'database', 'patient', 'medical'],
            'high': ['api', 'auth', 'login', 'payment', 'fhir', 'dicom'],
            'medium': ['user', 'profile', 'search', 'appointment'],
            'low': ['static', 'assets', 'images', 'css', 'js']
        }
        
        # 为管理面板设置优先级
        for finding in self.results.admin_panels:
            if 'priority' not in finding:  # 避免重复设置
                url_lower = finding['url'].lower()
                for level, keywords in priority_keywords.items():
                    if any(kw in url_lower for kw in keywords):
                        finding['priority'] = level
                        break
                else:
                    finding['priority'] = 'low'
        
        # 为API路由设置优先级
        for api in self.results.api_routes:
            if 'priority' not in api:
                route_lower = api.get('route', '').lower()
                api_type = api.get('type', '')
                
                if api_type in ['credential', 'internal_host']:
                    api['priority'] = 'critical'
                elif api_type == 'graphql':
                    api['priority'] = 'high'
                else:
                    for level, keywords in priority_keywords.items():
                        if any(kw in route_lower for kw in keywords):
                            api['priority'] = level
                            break
                    else:
                        api['priority'] = 'medium'
    
    def analyze_attack_surface(self) -> Dict:
        """分析攻击面，为后续工具提供建议"""
        logger.info("分析攻击面...")
        
        # 首先对发现进行优先级排序
        self.prioritize_findings()
        
        recommendations = {
            'next_tools': [],
            'priority_targets': [],
            'techniques': [],
            'risk_assessment': 'low'
        }
        
        # 根据发现推荐下一步工具
        if self.results.files:
            sensitive_files = [f for f in self.results.files if 'map' in f.get('file', '') or '.env' in f.get('file', '')]
            if sensitive_files:
                recommendations['next_tools'].extend(['git_leak_extractor', 'backup_miner'])
        
        # GraphQL检测
        graphql_apis = [api for api in self.results.api_routes if 'graphql' in api.get('route', '').lower()]
        if graphql_apis:
            recommendations['next_tools'].append('graphql_bomber')
            recommendations['techniques'].append('GraphQL introspection attack')
        
        # 医疗系统检测
        if self.is_medical:
            recommendations['next_tools'].extend(['data_hunter', 'incremental_id_hunter'])
            recommendations['techniques'].extend(['FHIR API enumeration', 'Patient data mining'])
            recommendations['risk_assessment'] = 'critical'  # 医疗数据最高优先级
        
        # WordPress检测
        if self.is_wordpress:
            recommendations['next_tools'].extend(['backup_miner', 'data_hunter'])
            recommendations['techniques'].append('WordPress REST API exploitation')
        
        # 缓存系统检测
        if any('redis' in tech.get('name', '').lower() for tech in self.results.technologies):
            recommendations['next_tools'].append('cache_layer_extractor')
        
        # 云服务检测
        if self.detected_cloud_services:
            recommendations['next_tools'].append('cloud_native_attacker')
            recommendations['techniques'].append('Cloud metadata service attack')
        
        # WAF检测
        if self.detected_waf:
            recommendations['techniques'].extend(['WAF bypass techniques', 'Rate limiting evasion'])
        
        # 高优先级目标识别
        critical_findings = [
            f for f in self.results.admin_panels 
            if f.get('priority') == 'critical' or f.get('risk_level') == 'critical'
        ]
        
        high_priority_apis = [
            api for api in self.results.api_routes 
            if api.get('priority') in ['critical', 'high']
        ]
        
        recommendations['priority_targets'] = critical_findings + high_priority_apis
        
        # 风险评估
        if len(critical_findings) > 3 or self.is_medical:
            recommendations['risk_assessment'] = 'critical'
        elif len(critical_findings) > 1 or len(high_priority_apis) > 5:
            recommendations['risk_assessment'] = 'high'
        elif len(self.results.admin_panels) > 5:
            recommendations['risk_assessment'] = 'medium'
        
        return recommendations
    
    def _print_attack_recommendations(self, attack_surface: Dict):
        """打印攻击面分析建议"""
        logger.info("=== 攻击面分析建议 ===")
        
        risk = attack_surface['risk_assessment']
        risk_icons = {
            'critical': '🚨',
            'high': ' ',
            'medium': ' ',
            'low': 'OK'
        }
        
        logger.info(f"{risk_icons.get(risk, ' ')} 风险评估: {risk.upper()}")
        
        if attack_surface['next_tools']:
            logger.info(f"  推荐工具 ({len(attack_surface['next_tools'])}个):")
            for tool in attack_surface['next_tools'][:5]:  # 只显示前5个
                logger.info(f"   - {tool}")
        
        if attack_surface['techniques']:
            logger.info(f"目标 推荐技术 ({len(attack_surface['techniques'])}个):")
            for technique in attack_surface['techniques'][:5]:
                logger.info(f"   - {technique}")
        
        if attack_surface['priority_targets']:
            logger.info(f"  优先目标 ({len(attack_surface['priority_targets'])}个):")
            for target in attack_surface['priority_targets'][:3]:
                if 'url' in target:
                    logger.info(f"   - {target['url']} [{target.get('priority', 'unknown')}]")
                else:
                    logger.info(f"   - {target.get('route', 'Unknown')} [{target.get('priority', 'unknown')}]")
        
        if self.detected_waf:
            logger.info(f"  检测到WAF: {', '.join(self.detected_waf)} - 建议使用绕过技术")
    async def crawl_site(self):
        """网站内容爬取 - 优化版"""
        logger.info("开始网站结构爬取...")
        
        visited = set()
        main_protocol = await self.check_protocol(self.target) 
        if not main_protocol:
            logger.warning("无法确定主域名协议，跳过爬取")
            return
            
        base_url = f"{main_protocol}://{self.target}"
        to_visit = [base_url]
        
        crawl_count = 0
        max_pages = self.config.max_crawl_pages
        
        while to_visit and crawl_count < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            
            visited.add(url)
            crawl_count += 1
            
            response = await self.safe_request(url)
            if response and response.status == 200:
                try:
                    text = await response.text()
                    logger.debug(f"爬取页面 {crawl_count}/{max_pages}: {url}")
                    
                    # 提取表单信息
                    await self._extract_forms(url, text)
                    
                    # 提取新链接
                    new_links = self._extract_links(url, text)
                    for link in new_links:
                        if link not in visited and len(to_visit) < 50:  # 限制待访问队列
                            to_visit.append(link)
                    
                    # 检测特殊功能页面
                    await self._detect_special_pages(url, text)
                    
                except Exception as e:
                    logger.debug(f"页面内容解析失败 {url}: {type(e).__name__}: {e}")
            
            # 避免过快请求
            await asyncio.sleep(0.1)
        
        logger.info(f"网站爬取完成，访问了 {crawl_count} 个页面")
    
    async def _extract_forms(self, url: str, html: str):
        """提取表单信息"""
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        for form_content in forms:
            action_match = re.search(r'action=["\']([^"\']+)', form_content, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']+)', form_content, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else url
            method = method_match.group(1).upper() if method_match else "GET"
            form_url = urljoin(url, action)
            
            # 分析表单输入
            inputs = re.findall(r'<input[^>]*>', form_content, re.IGNORECASE)
            textareas = re.findall(r'<textarea[^>]*>', form_content, re.IGNORECASE)
            selects = re.findall(r'<select[^>]*>', form_content, re.IGNORECASE)
            
            # 检测表单类型
            form_type = self._detect_form_type(form_content.lower())
            
            # 🌟 新的树状存储方式：从页面URL提取域名
            domain = self._extract_domain_from_url(url)
            if domain:
                self.results.add_form(
                    domain=domain,
                    form_data={
                "url": url,
                "action": form_url,
                "method": method,
                "inputs": len(inputs),
                "textareas": len(textareas),
                "selects": len(selects),
                "form_type": form_type,
                        "has_file_upload": 'type="file"' in form_content.lower(),
                        "risk_level": "high" if form_type in ["login", "admin", "upload"] else "medium",
                        "discovery_method": "form_analysis"
                    }
                )
    
    def _detect_form_type(self, form_content: str) -> str:
        """检测表单类型"""
        type_keywords = {
            "login": ["login", "signin", "ログイン", "password", "username"],
            "contact": ["contact", "お問い合わせ", "message", "inquiry"],
            "reservation": ["reserve", "yoyaku", "予約", "appointment", "booking"],
            "registration": ["register", "signup", "会員登録", "registration"],
            "search": ["search", "検索", "query"],
            "payment": ["payment", "pay", "credit", "支払い", "決済"]
        }
        
        for form_type, keywords in type_keywords.items():
            if any(keyword in form_content for keyword in keywords):
                return form_type
        
        return "unknown"
    
    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """提取页面链接"""
        links = set()
        link_patterns = [
            r'href=["\']([^"\']+)',
            r'src=["\']([^"\']+\.(?:js|css))',
        ]
        
        for pattern in link_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for link in matches:
                if link.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    continue
                
                full_url = urljoin(base_url, link)
                # 只收集同域名链接
                if self.target in full_url and not full_url.endswith(('.jpg', '.png', '.gif', '.pdf')):
                    links.add(full_url)
        
        return list(links)
    
    async def _detect_special_pages(self, url: str, html: str):
        """检测特殊功能页面"""
        content_lower = html.lower()
        
        # 🌟 新的树状存储方式：从页面URL提取域名
        domain = self._extract_domain_from_url(url)
        if not domain:
            return
        
        # 预约相关页面
        reservation_keywords = ['予約', 'yoyaku', 'reserve', 'booking', 'appointment']
        if any(keyword in content_lower for keyword in reservation_keywords):
            path = urlparse(url).path or "/"
            self.results.add_endpoint(
                domain=domain,
                path=path,
                endpoint_data={
                "url": url,
                    "endpoint_type": "reservation_related",
                    "keywords_found": [kw for kw in reservation_keywords if kw in content_lower],
                    "risk_level": "low",
                    "discovery_method": "content_analysis"
                }
            )
        
        # 管理后台相关
        admin_keywords = ['admin', 'dashboard', 'management', '管理', 'control']
        if any(keyword in content_lower for keyword in admin_keywords):
            path = urlparse(url).path or "/"
            self.results.add_endpoint(
                domain=domain,
                path=path,
                endpoint_data={
                "url": url,
                    "endpoint_type": "admin_related",
                    "keywords_found": [kw for kw in admin_keywords if kw in content_lower],
                    "risk_level": "high",
                    "discovery_method": "content_analysis"
                }
            )
        
        # API相关页面
        api_keywords = ['api', 'graphql', 'swagger', 'openapi']
        if any(keyword in content_lower for keyword in api_keywords):
            path = urlparse(url).path or "/"
            self.results.add_endpoint(
                domain=domain,
                path=path,
                endpoint_data={
                "url": url,
                    "endpoint_type": "api_related",
                    "keywords_found": [kw for kw in api_keywords if kw in content_lower],
                    "risk_level": "medium",
                    "discovery_method": "content_analysis"
                }
            )

    async def find_admin_panels(self):
        """查找管理后台 - 优化版"""
        logger.info("开始后台路径扫描...")
        
        main_protocol = await self.check_protocol(self.target)
        if not main_protocol:
            logger.warning("无法确定协议，跳过后台扫描")
            return
        
        base_url = f"{main_protocol}://{self.target}"
        
        # 创建扫描任务
        tasks = []
        semaphore = asyncio.Semaphore(15)  # 限制并发数
        
        async def check_single_path(path: str):
            url = urljoin(base_url, path)
            result = await self.check_path_cached(url)
            if result:
                # 🌟 新的树状存储方式：将管理面板关联到特定域名
                self.results.add_endpoint(
                    domain=self.target,
                    path=path,
                    endpoint_data={
                        **result,
                        "endpoint_type": "admin_panel",
                        "discovery_method": "path_scan"
                    }
                )
        
        # 启动所有扫描任务
        for path in self.jp_paths:
            tasks.append(check_single_path(path))
        
        # 执行扫描
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 统计结果
        successful_scans = sum(1 for r in results if not isinstance(r, Exception))
        logger.info(f"后台扫描完成: 发现 {len(self.results.admin_panels)} 个有效路径 (扫描了 {successful_scans} 个路径)")

    async def _check_admin_path(self, url: str) -> Optional[Dict]:
        """检查单个管理路径"""
        response = await self.safe_request(url, allow_redirects=False, timeout=5)
        if not response:
            return None
        
        # 有价值的状态码
        if response.status in [200, 301, 302, 401, 403, 405]:
            try:
                content = await response.read()
                headers = dict(response.headers)
                
                # 分析响应特征
                risk_level = self._assess_path_risk(response.status, headers, len(content))
                
                return {
                    "url": url,
                    "status": response.status,
                    "size": len(content),
                    "risk_level": risk_level,
                    "server": headers.get('Server', ''),
                    "content_type": headers.get('Content-Type', ''),
                    "location": headers.get('Location', '') if response.status in [301, 302] else ''
                }
            except Exception as e:
                logger.debug(f"路径检查失败 {url}: {type(e).__name__}")
        
        return None
    
    def _assess_path_risk(self, status: int, headers: Dict, content_size: int) -> str:
        """评估路径风险等级"""
        # 200 状态的大响应通常是真实页面
        if status == 200 and content_size > 1000:
            return "high"
        
        # 401/403 表示存在但需要认证
        if status in [401, 403]:
            return "medium"
        
        # 重定向也值得关注
        if status in [301, 302]:
            return "medium"
        
        # 405 Method Not Allowed 表示端点存在
        if status == 405:
            return "low"
        
        return "low"

    async def scan_key_files(self):
        """扫描关键文件 - 优化版"""
        logger.info("开始敏感文件扫描...")
        
        main_protocol = await self.check_protocol(self.target)
        if not main_protocol:
            logger.warning("无法确定协议，跳过文件扫描")
            return
        
        base_url = f"{main_protocol}://{self.target}"
        
        # 并发扫描文件
        tasks = []
        semaphore = asyncio.Semaphore(10)  # 限制并发数
        
        async def scan_single_file(file_name: str):
            async with semaphore:
                url = urljoin(base_url, file_name)
                response = await self.safe_request(url, timeout=5)
                
                # 更新统计
                self.stats['requests_made'] += 1
                
                if response and response.status == 200:
                    try:
                        content = await response.text()
                        file_size = len(content)
                        
                        # 更新下载统计
                        self.stats['bytes_downloaded'] += file_size
                        
                        # 评估文件风险等级
                        risk_level = self._assess_file_risk(file_name, file_size, content)
                        
                        self.results.files.append({
                            "file": file_name,
                            "url": url,
                            "size": file_size,
                            "preview": content[:100],
                            "risk_level": risk_level,
                            "content_type": response.headers.get('Content-Type', ''),
                            "last_modified": response.headers.get('Last-Modified', '')
                        })
                        
                        logger.debug(f"发现敏感文件: {file_name} ({file_size} bytes, {risk_level})")
                        
                    except Exception as e:
                        logger.debug(f"文件内容读取失败 {url}: {type(e).__name__}")
                        self.stats['requests_failed'] += 1
                elif response:
                    # 记录其他状态码的响应
                    if response.status in [403, 401]:
                        self.results.files.append({
                            "file": file_name,
                            "url": url,
                            "size": 0,
                            "preview": f"Access denied (HTTP {response.status})",
                            "risk_level": "medium",
                            "status": response.status
                        })
                else:
                    self.stats['requests_failed'] += 1
        
        # 启动所有任务
        for file_name in self.key_files:
            tasks.append(scan_single_file(file_name))
        
        # 等待所有任务完成
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"敏感文件扫描完成，发现 {len(self.results.files)} 个文件")
    
    def _assess_file_risk(self, file_name: str, file_size: int, content: str) -> str:
        """评估文件风险等级"""
        file_lower = file_name.lower()
        content_lower = content.lower()
        
        # 高风险文件
        high_risk_files = ['.env', 'wp-config', '.git', 'backup', 'database', 'config.php']
        if any(risk_file in file_lower for risk_file in high_risk_files):
            return "critical"
        
        # 检查内容中的敏感信息
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'database', 'mysql', 'postgres']
        if any(pattern in content_lower for pattern in sensitive_patterns):
            return "high"
        
        # Source maps
        if '.map' in file_lower:
            return "high"
        
        # 配置文件
        if any(ext in file_lower for ext in ['.json', '.xml', '.config']):
            return "medium"
        
        return "low"
    async def extract_js_data(self):
        #提取JS中的API端点 增强版
        print("[+] 分析JavaScript文件...")
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.base_url, timeout=10) as resp:
                    html = await resp.text()
                    
                    # 找出所有JS文件
                    js_files = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)', html)
                    
                    # 检查React DevTools Hook
                    if '__REACT_DEVTOOLS_GLOBAL_HOOK__' in html:
                        self.results["technologies"].append({
                            "type": "frontend",
                            "name": "React (DevTools Exposed)",
                            "detail": "React DevTools Hook detected"
                        })
                    
                    # 检查webpack
                    if 'webpackJsonp' in html or 'webpackChunk' in html:
                        self.results["technologies"].append({
                            "type": "bundler",
                            "name": "Webpack",
                            "detail": "Webpack chunks detected"
                        })
                    
                    for js_file in js_files[:50]:  # 直接你妈50！
                        js_url = urljoin(self.base_url, js_file)
                        
                        # 检查是否有对应的source map
                        map_url = js_url + '.map'
                        
                        try:
                            # 下载JS文件
                            async with session.get(js_url, timeout=5) as js_resp:
                                js_content = await js_resp.text()
                                
                                # 检查source map注释
                                if '//# sourceMappingURL=' in js_content:
                                    map_ref = re.search(r'//# sourceMappingURL=([^\s]+)', js_content)
                                    if map_ref:
                                        actual_map_url = urljoin(js_url, map_ref.group(1))
                                        # 尝试下载source map
                                        try:
                                            async with session.get(actual_map_url, timeout=5) as map_resp:
                                                if map_resp.status == 200:
                                                    self.results["files"].append({
                                                        "file": "source_map",
                                                        "url": actual_map_url,
                                                        "size": len(await map_resp.read()),
                                                        "preview": "Source map found - contains original source code!"
                                                    })
                                        except Exception as e:  # 注意：需要 import logging
                                            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
                                # 增强的API提取
                                api_patterns = [
                                    r'["\']/(api/[^"\']+)',
                                    r'["\']/(ajax/[^"\']+)',
                                    r'["\']/(graphql[^"\']*)',
                                    r'["\']/(rest/[^"\']+)',
                                    r'endpoint["\']:\s*["\']([^"\']+)',
                                    r'url["\']:\s*["\']([^"\']+)',
                                    r'baseURL["\']:\s*["\']([^"\']+)',
                                    r'apiUrl["\']:\s*["\']([^"\']+)',
                                    # GraphQL特征
                                    r'query\s+\w+\s*{[^}]+}',
                                    r'mutation\s+\w+\s*{[^}]+}',
                                    r'subscription\s+\w+\s*\{[^}]+\}',  #新增
                                    r'["\']swagger["\']:\s*["\']([^"\']+)', #新增
                                    r'["\']openapi["\']:\s*["\']([^"\']+)'  #新增
                                ]
                                
                                for pattern in api_patterns:
                                    matches = re.findall(pattern, js_content)
                                    for match in matches:
                                        self.results["api_routes"].append({
                                            "route": match[:100],  # 限制长度
                                            "source": js_file
                                        })
                                
                                # 提取可能的密钥令牌
                                secret_patterns = [
                                    r'["\'](?:api[_-]?key|apikey)["\']:\s*["\']([^"\']+)',
                                    r'["\'](?:secret|token)["\']:\s*["\']([^"\']+)',
                                    r'["\'](?:auth|authorization)["\']:\s*["\']([^"\']+)',
                                    r'["\'](?:firebase|aws|azure)[^"\']*["\']:\s*["\']([^"\']+)'
                                ]
                                
                                for pattern in secret_patterns:
                                    matches = re.findall(pattern, js_content, re.I)
                                    for match in matches:
                                        if len(match) > 10:  # 过滤明显的占位符
                                            self.results["api_routes"].append({
                                                "route": f"[POTENTIAL SECRET: {match[:20]}...]",
                                                "source": js_file
                                            })
                                            
                        except Exception as e:  # 注意：需要 import logging
                                            
                            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
                        # 尝试直接访问.map
                        try:
                            async with session.get(map_url, timeout=3) as map_resp:
                                if map_resp.status == 200:
                                    self.results["files"].append({
                                        "file": "source_map",
                                        "url": map_url,
                                        "size": len(await map_resp.read()),
                                        "preview": "Direct source map access!"
                                    })
                        except Exception as e:  # 注意：需要 import logging
                            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
            except Exception as e:  # 注意：需要 import logging
                logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    async def tech_fingerprint(self):
        #技术栈识别
        print("[+] 识别技术栈...")
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.base_url, timeout=10) as resp:
                    headers = dict(resp.headers)
                    html = await resp.text()
                    
                    # 修正：添加安全配置检测
                    # 安全头检测
                    security_headers = {
                        'X-Frame-Options': '防点击劫持',
                        'Content-Security-Policy': 'CSP策略',
                        'Strict-Transport-Security': 'HSTS',
                        'X-Content-Type-Options': 'MIME类型',
                        'X-XSS-Protection': 'XSS防护'
                    }
                    
                    missing_headers = []
                    for header, desc in security_headers.items():
                        if header not in headers:
                            missing_headers.append(f"{header} ({desc})")
                    
                    if missing_headers:
                        self.results["technologies"].append({
                            "type": "security_config", 
                            "name": "Missing Security Headers",
                            "detail": missing_headers
                        })
                    
                    # CORS配置检测
                    if 'Access-Control-Allow-Origin' in headers:
                        cors_value = headers['Access-Control-Allow-Origin']
                        if cors_value == '*':
                            self.results["technologies"].append({
                                "type": "security_config",
                                "name": "CORS Misconfiguration", 
                                "detail": f"Wildcard CORS: {cors_value}"
                            })
                    
                    # CDN检测
                    cdn_headers = {
                        'cf-ray': 'Cloudflare',
                        'x-amz-cf-id': 'AWS CloudFront', 
                        'x-azure-ref': 'Azure CDN',
                        'ali-swift-global-savetime': 'Alibaba CDN'
                    }
                    
                    for header, cdn_name in cdn_headers.items():
                        if header in headers:
                            self.results["technologies"].append({
                                "type": "cdn",
                                "name": cdn_name,
                                "detail": f"{header}: {headers[header]}"
                            })
                    
                    
                    # 服务器识别
                    if 'Server' in headers:
                        self.results["technologies"].append({
                            "type": "server",
                            "name": headers['Server']
                        })
                    
                    # CMS识别
                    cms_signatures = {
                        "WordPress": ["wp-content", "wp-includes", "wp-json"],
                        "Drupal": ["sites/default", "drupal.js"],
                        "Joomla": ["option=com_", "joomla"],
                        "Laravel": ["laravel_session"],
                        "Django": ["csrfmiddlewaretoken"]
                    }
                    
                    for cms, signatures in cms_signatures.items():
                        if any(sig in html for sig in signatures):
                            self.results["technologies"].append({
                                "type": "cms",
                                "name": cms
                            })
                    
                    # 框架识别
                    if "react" in html.lower():
                        self.results["technologies"].append({"type": "frontend", "name": "React"})
                    if "vue" in html.lower():
                        self.results["technologies"].append({"type": "frontend", "name": "Vue"})
                    if "angular" in html.lower():
                        self.results["technologies"].append({"type": "frontend", "name": "Angular"})
                        
            except Exception as e:  # 注意：需要 import logging
                        
                logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    def generate_report(self):
        """生成扫描报告 - 树状关联模型版"""
        # 🌟 首先计算所有资产的风险评分
        self.results.calculate_risk_scores()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"asset_report_{self.target}_{timestamp}.json"
        
        # 准备报告数据
        report_data = {
            "scan_info": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "scan_duration": f"{time.time() - self.start_time:.2f}s",
                "config": {
                    "max_crawl_pages": self.config.max_crawl_pages,
                    "max_js_files": self.config.max_js_files,
                    "concurrent_limit": self.config.concurrent_limit
                }
            },
            "results": self.results.to_dict(),
            "summary": self._generate_summary(),
            "high_priority_targets": self._identify_high_priority_targets(),
            "waf_protection_stats": self._get_waf_stats()
        }
        
        # 保存JSON报告
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"报告已保存: {report_file}")
            
            # 输出高优先级发现
            self._print_priority_findings()
            
        except Exception as e:
            logger.error(f"报告生成失败: {type(e).__name__}: {e}")
    
    def _generate_summary(self) -> Dict:
        """生成扫描摘要 - 树状关联模型版"""
        total_endpoints = sum(len(asset["endpoints"]) for asset in self.results.assets.values())
        total_forms = sum(len(asset["forms"]) for asset in self.results.assets.values())
        total_technologies = sum(len(asset["technologies"]) for asset in self.results.assets.values())
        
        # 统计高风险资产
        high_risk_assets = [domain for domain, asset in self.results.assets.items() 
                          if asset["risk_score"] >= 70]
        
        # 统计端点类型
        endpoint_types = {}
        admin_endpoints = 0
        api_endpoints = 0
        
        for asset in self.results.assets.values():
            for endpoint in asset["endpoints"].values():
                endpoint_type = endpoint.get("endpoint_type", "unknown")
                endpoint_types[endpoint_type] = endpoint_types.get(endpoint_type, 0) + 1
                
                if endpoint_type == "admin_panel":
                    admin_endpoints += 1
                elif endpoint_type in ["api_endpoint", "graphql"]:
                    api_endpoints += 1
        
        return {
            "total_assets": len(self.results.assets),
            "total_subdomains": len([a for a in self.results.assets.values() if a["type"] == "subdomain"]),
            "total_endpoints": total_endpoints,
            "total_forms": total_forms,
            "total_technologies": total_technologies,
            "admin_endpoints": admin_endpoints,
            "api_endpoints": api_endpoints,
            "endpoint_types": endpoint_types,
            "form_types": self._count_form_types(),
            "high_risk_assets": len(high_risk_assets),
            "high_risk_asset_list": high_risk_assets[:5],  # 显示前5个
            "avg_risk_score": round(sum(asset["risk_score"] for asset in self.results.assets.values()) / max(len(self.results.assets), 1), 2)
        }
    
    def _count_form_types(self) -> Dict[str, int]:
        """统计表单类型 - 树状关联模型版"""
        form_types = {}
        for asset in self.results.assets.values():
            for form in asset["forms"]:
                form_type = form.get('form_type', 'unknown')
                form_types[form_type] = form_types.get(form_type, 0) + 1
        return form_types
    
    def _identify_high_priority_targets(self) -> Dict:
        """识别高优先级目标"""
        high_priority = {
            "reservation_forms": [],
            "login_forms": [],
            "admin_panels": [],
            "sensitive_files": [],
            "api_endpoints": []
        }
        
        # 预约表单（最高优先级）
        for form in self.results.forms:
            if form.get('form_type') == 'reservation':
                high_priority["reservation_forms"].append({
                    "url": form["url"],
                    "action": form["action"],
                    "method": form["method"]
                })
        
        # 登录表单
        for form in self.results.forms:
            if form.get('form_type') == 'login':
                high_priority["login_forms"].append({
                    "url": form["url"],
                    "action": form["action"]
                })
        
        # 高风险管理面板
        for panel in self.results.admin_panels:
            if panel.get('risk_level') in ['high', 'medium']:
                high_priority["admin_panels"].append({
                    "url": panel["url"],
                    "status": panel["status"],
                    "risk_level": panel["risk_level"]
                })
        
        # 敏感文件
        sensitive_extensions = ['.env', '.git', '.config', '.bak', '.map']
        for file_info in self.results.files:
            file_name = file_info.get('file', '')
            if any(ext in file_name for ext in sensitive_extensions):
                high_priority["sensitive_files"].append({
                    "file": file_name,
                    "url": file_info["url"],
                    "size": file_info["size"]
                })
        
        # API端点
        for api in self.results.api_routes:
            route = api.get('route', '')
            if any(keyword in route.lower() for keyword in ['graphql', 'api', 'rest']):
                high_priority["api_endpoints"].append({
                    "route": route,
                    "source": api.get("source", "")
                })
        
        return high_priority
    
    def _get_waf_stats(self) -> Dict:
        """获取WAF防护统计信息"""
        waf_stats = {
            'waf_defender_enabled': WAF_DEFENDER_AVAILABLE,
            'waf_defender_initialized': self.waf_defender_initialized,
            'target_url': f"https://{self.target}" if hasattr(self, 'target') else 'unknown',
            'protection_status': '已启用WAF欺骗检测' if self.waf_defender_initialized else 
                               ('WAF Defender不可用' if not WAF_DEFENDER_AVAILABLE else '未初始化'),
            'baseline_info': self.waf_defender.get_stats() if self.waf_defender else None
        }
        
        # 添加噪音过滤统计（与git工具一致）
        waf_stats['noise_filtering_stats'] = {
            'filter_enabled': NOISE_FILTER_AVAILABLE,
            'total_checked': self.noise_stats['total_checked'],
            'noise_filtered': self.noise_stats['noise_filtered'],
            'valuable_kept': self.noise_stats['valuable_kept'],
            'noise_ratio': (self.noise_stats['noise_filtered'] / 
                           max(self.noise_stats['total_checked'], 1)) if self.noise_stats['total_checked'] > 0 else 0,
            'effectiveness': '有效过滤噪音' if self.noise_stats['noise_filtered'] > 0 else '无噪音发现'
        }
        
        return waf_stats
    
    def _print_priority_findings(self):
        """打印高优先级发现"""
        priority = self._identify_high_priority_targets()
        
        logger.info("=== 高优先级目标 ===")
        
        if priority["reservation_forms"]:
            logger.info(f" 预约表单 ({len(priority['reservation_forms'])}个):")
            for form in priority["reservation_forms"][:10]:  
                logger.info(f"   - {form['action']} ({form['method']})")
        
        if priority["admin_panels"]:
            logger.info(f" 管理面板 ({len(priority['admin_panels'])}个):")
            for panel in priority["admin_panels"][:10]:
                logger.info(f"   - {panel['url']} [{panel['status']}] ({panel['risk_level']})")
        
        if priority["sensitive_files"]:
            logger.info(f" 敏感文件 ({len(priority['sensitive_files'])}个):")
            for file_info in priority["sensitive_files"][:50]:
                logger.info(f"   - {file_info['file']} ({file_info['size']} bytes)")
        
        if priority["api_endpoints"]:
            logger.info(f" API端点 ({len(priority['api_endpoints'])}个):")
            for api in priority["api_endpoints"][:20]:
                logger.info(f"   - {api['route']}")
        
        # 总体风险评估
        total_high_risk = (len(priority["reservation_forms"]) + 
                          len(priority["admin_panels"]) + 
                          len(priority["sensitive_files"]))
        
        if total_high_risk > 5:
            logger.info("  风险评估: 高风险 - 发现多个敏感目标")
        elif total_high_risk > 2:
            logger.info("  风险评估: 中等风险 - 存在部分敏感目标")
        else:
            logger.info(" 风险评估: 低风险 - 暴露面较小")

    async def query_crtsh(self, subdomains):
        #查询证书透明度日志
        print("[+] 查询证书透明度 (crt.sh)...")
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            try:
                # crt.sh API
                url = f"https://crt.sh/?q=%.{self.target}&output=json"  #修正
                async with session.get(url, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            # 提取所有域名
                            domains = name_value.replace('*.', '').split('\n')
                            for domain in domains:
                                if domain and self.target in domain:
                                    subdomains.add(domain.strip())
                        print(f"    发现 {len(data)} 个证书")
            except Exception as e:
                print(f"[-] crt.sh查询失败: {e}")

    async def try_zone_transfer(self, subdomains):
        #尝试DNS区域传输
        print("[+] 尝试DNS区域传输...")
        
        try:
            # 获取NS记录
            import dns.resolver
            import dns.zone
            import dns.query
            
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(self.target, 'NS')
            
            for ns in answers:
                ns_str = str(ns).rstrip('.')
                print(f"    测试NS服务器: {ns_str}")
                
                try:
                    # 尝试区域传输
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_str, self.target))
                    print(f"[!] 区域传输成功! NS: {ns_str}")
                    
                    # 提取所有记录
                    for name, node in zone.nodes.items():
                        subdomain = str(name) + '.' + self.target
                        if subdomain != f"@.{self.target}":
                            subdomains.add(subdomain)
                except Exception as e:  # 注意：需要 import logging
                    logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
        except ImportError:
            print("[-] 需要安装dnspython: pip install dnspython")
        except Exception as e:
            pass

async def main():
    """主函数 - 智能资产映射 + 认证支持"""
    import sys
    
    if len(sys.argv) > 1:
        target_domain = sys.argv[1]
    else:
        target_domain = input("请输入目标域名 [默认: asanoha-clinic.com]: ").strip()
        if not target_domain:
            target_domain = "asanoha-clinic.com"
    
    # 认证配置示例（可根据需要修改）
    auth_config = None
    
    # 示例1: 管理员后台登录
    # auth_config = {
    #     'login_url': f'https://{target_domain}/admin/login',
    #     'username': 'admin',
    #     'password': 'password123',
    #     'heartbeat_endpoint': '/admin/api/status'
    # }
    
    # 示例2: 用户登录（访问内部资产）
    # auth_config = {
    #     'login_url': f'https://{target_domain}/login',
    #     'username': 'user',
    #     'password': 'userpass',
    #     'heartbeat_endpoint': '/api/profile'
    # }
    
    # 示例3: JWT Token方式
    # auth_config = {
    #     'jwt_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    # }
    
    # 🚀 史诗级链式追踪配置
    enable_epic_mode = True  # 启用史诗级模式
    chain_config = ChainTrackingConfig(
        max_scan_depth=3,      # 最大扫描深度：3层
        max_domain_count=10,   # 最大域名数量：10个（防止爆炸式增长）
        scan_interval=2.0,     # 扫描间隔：2秒（避免触发告警）
        enable_internal_scan=True,   # 启用内网域名扫描
        enable_ip_scan=False,        # 禁用IP地址扫描
        scope_domains=[]  # 空列表表示只扫描主域名的子域名
    )
    
    config = AssetMapperConfig(
        max_crawl_pages=50,  # 限制爬取页面数
        max_js_files=30,     # 限制JS文件分析数
        concurrent_limit=15,  # 适中的并发数
        use_dynamic_ip=True,  # 启用动态IP池（终极组合拳）
        use_user_agent=True,  # 启用User-Agent轮换
        enable_authentication=bool(auth_config),
        auth_config=auth_config or {}
    )
    
    print("="*80)
    if enable_epic_mode:
        print("🚀 史诗级链式追踪资产映射器")
        print("📡 自动发现和扫描整个资产网络")
    else:
        print("目标 启动资产映射器")
    print("="*80)
    print(f"🎯 初始目标: {target_domain}")
    print(f"认证 认证模式: {'启用' if auth_config else '禁用'}")
    
    if enable_epic_mode:
        print(f"🚀 链式追踪配置:")
        print(f"   📊 最大扫描深度: {chain_config.max_scan_depth} 层")
        print(f"   📊 最大域名数量: {chain_config.max_domain_count} 个")
        print(f"   ⏱️  扫描间隔: {chain_config.scan_interval} 秒")
        print(f"   🔍 内网扫描: {'启用' if chain_config.enable_internal_scan else '禁用'}")
        print(f"   🌐 IP扫描: {'启用' if chain_config.enable_ip_scan else '禁用'}")
    
    # 显示绕过模式配置
    if config.use_dynamic_ip and DYNAMIC_IP_AVAILABLE:
        print(f"绕过模式: 终极组合拳 (动态IP池 + User-Agent轮换)")
    elif config.use_user_agent and USER_AGENT_AVAILABLE:
        print(f"绕过模式: User-Agent轮换模式")
    else:
        print(f"绕过模式: 基础模式")
    
    if auth_config:
        print("  启用认证模式 - 可访问认证后内部资产！")
        print("   预期发现: 内部API、管理端点、隐藏功能")
    else:
        print("  无认证模式 - 仅访问公开资产")
        print("   提示: 修改main函数中的auth_config来启用认证")
    
    if config.use_dynamic_ip or config.use_user_agent:
        print("  启用绕过增强 - 提高WAF绕过能力！")
        if config.use_dynamic_ip:
            print("   - 500个动态IP轮换")
        if config.use_user_agent:
            print("   - 智能User-Agent伪装")
    
    async with AssetMapper(target_domain, config, auth_config, 
                          enable_chain_tracking=enable_epic_mode, 
                          chain_config=chain_config) as mapper:
        results = await mapper.run()
        
        # 输出关键统计信息
        logger.info("=== 扫描结果摘要 ===")
        logger.info(f"子域名: {len(results.subdomains)}")
        logger.info(f"表单: {len(results.forms)}")
        logger.info(f"API路由: {len(results.api_routes)}")
        logger.info(f"后台路径: {len(results.admin_panels)}")
        logger.info(f"敏感文件: {len(results.files)}")
        logger.info(f"技术栈: {len(results.technologies)}")
        
        if auth_config and mapper.auth_manager:
            auth_stats = mapper.auth_manager.get_auth_stats()
            print(f"\n认证 认证统计:")
            print(f"    认证请求: {auth_stats.get('authenticated_requests', 0)}")
            print(f"    认证失败: {auth_stats.get('auth_failures', 0)}")
            print(f"    会话恢复: {auth_stats.get('session_recoveries', 0)}")
        
        return results

if __name__ == "__main__":
    # 设置日志级别
    logger.setLevel(logging.INFO)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("扫描被用户中断")
    except Exception as e:
        logger.error(f"程序异常退出: {type(e).__name__}: {e}")
