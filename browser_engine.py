import asyncio
import json
import re
import time
import traceback
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
import os
import sys

# 核心依赖检查
try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("  Playwright未安装，请运行: pip install playwright && playwright install")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("  BeautifulSoup4未安装，请运行: pip install beautifulsoup4")

@dataclass
class BrowserConfig:
    """浏览器引擎配置"""
    # 基础配置
    headless: bool = True
    timeout: int = 30000  # 30秒
    viewport_width: int = 1920
    viewport_height: int = 1080
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # 安全配置
    disable_security: bool = True  # 允许跨域请求
    ignore_https_errors: bool = True
    disable_web_security: bool = True
    
    # 性能配置
    max_pages: int = 5  # 最大并发页面数
    page_load_timeout: int = 15000  # 页面加载超时
    network_idle_timeout: int = 3000  # 网络空闲等待时间
    
    # 发现配置
    max_spa_routes: int = 50  # 最大SPA路由发现数
    max_api_endpoints: int = 200  # 最大API端点数
    javascript_execution_timeout: int = 10000  # JS执行超时
    
    # 目标特化配置
    medical_keywords: List[str] = field(default_factory=lambda: [
        'patient', 'doctor', 'appointment', 'medical', 'health', 
        'diagnosis', 'prescription', 'treatment', 'clinic'
    ])

class BrowserEngine:

    
    def __init__(self, target: str, config: BrowserConfig = None):
        self.target = target.strip()
        self.config = config or BrowserConfig()
        
        # 确保目标有协议
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"https://{self.target}"
        
        # 结果存储
        self.discovered_apis: Set[str] = set()
        self.spa_routes: Set[str] = set()
        self.javascript_errors: List[Dict] = []
        self.security_issues: List[Dict] = []
        self.network_requests: List[Dict] = []
        self.dom_analysis: Dict = {}
        self.performance_metrics: Dict = {}
        
        # 浏览器实例
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        
        print(f"  浏览器引擎初始化: {self.target}")
    
    async def run(self) -> Dict[str, Any]:
        """执行完整的浏览器安全分析"""
        if not PLAYWRIGHT_AVAILABLE:
            return self._create_error_result("Playwright未安装")
        
        start_time = time.time()
        
        try:
            print("\n  启动无头浏览器引擎...")
            
            # 启动浏览器
            await self._launch_browser()
            
            # 核心分析流程
            await self._perform_analysis()
            
            # 生成分析结果
            results = self._generate_results()
            
            execution_time = time.time() - start_time
            results['execution_time'] = f"{execution_time:.2f}秒"
            
            print(f"  浏览器引擎分析完成 ({execution_time:.2f}秒)")
            return results
            
        except Exception as e:
            error_msg = f"浏览器引擎执行错误: {e}"
            print(f"  {error_msg}")
            return self._create_error_result(error_msg)
        finally:
            await self._cleanup()
    
    async def _launch_browser(self):
        """启动浏览器实例"""
        print("      启动Chromium浏览器...")
        
        playwright = await async_playwright().start()
        
        # 浏览器启动参数
        browser_args = [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--disable-extensions',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage'
        ]
        
        if self.config.disable_security:
            browser_args.extend([
                '--disable-web-security',
                '--allow-running-insecure-content'
            ])
        
        self.browser = await playwright.chromium.launch(
            headless=self.config.headless,
            args=browser_args
        )
        
        # 创建浏览器上下文
        self.context = await self.browser.new_context(
            viewport={
                'width': self.config.viewport_width,
                'height': self.config.viewport_height
            },
            user_agent=self.config.user_agent,
            ignore_https_errors=self.config.ignore_https_errors
        )
        
        print("      浏览器启动成功")
    
    async def _perform_analysis(self):
        """执行核心分析流程"""
        page = await self.context.new_page()
        
        try:
            # 设置网络监听
            await self._setup_network_monitoring(page)
            
            # 设置错误监听
            await self._setup_error_monitoring(page)
            
            # 主页面分析
            print("      加载主页面...")
            await self._analyze_main_page(page)
            
            # 动态API发现
            print("      动态API发现...")
            await self._discover_dynamic_apis(page)
            
            # SPA路由分析
            print("      SPA路由分析...")
            await self._analyze_spa_routes(page)
            
            # JavaScript安全分析
            print("      JavaScript安全分析...")
            await self._analyze_javascript_security(page)
            
            # DOM安全检查
            print("      DOM安全检查...")
            await self._analyze_dom_security(page)
            
            # 性能分析
            print("      性能指标收集...")
            await self._collect_performance_metrics(page)
            
        finally:
            await page.close()
    
    async def _setup_network_monitoring(self, page: Page):
        """设置网络请求监听"""
        async def handle_request(request):
            try:
                url = request.url
                method = request.method
                headers = request.headers
                
                # 记录网络请求
                self.network_requests.append({
                    'url': url,
                    'method': method,
                    'headers': dict(headers),
                    'timestamp': datetime.now().isoformat()
                })
                
                # API端点识别
                if self._is_api_endpoint(url):
                    self.discovered_apis.add(url)
                    print(f"        发现API: {method} {url}")
                
            except Exception as e:
                print(f"        网络监听错误: {e}")
        
        page.on('request', handle_request)
    
    async def _setup_error_monitoring(self, page: Page):
        """设置JavaScript错误监听"""
        async def handle_console(msg):
            if msg.type in ['error', 'warning']:
                self.javascript_errors.append({
                    'type': msg.type,
                    'text': msg.text,
                    'timestamp': datetime.now().isoformat()
                })
        
        async def handle_page_error(error):
            self.javascript_errors.append({
                'type': 'page_error',
                'text': str(error),
                'timestamp': datetime.now().isoformat()
            })
        
        page.on('console', handle_console)
        page.on('pageerror', handle_page_error)
    
    async def _analyze_main_page(self, page: Page):
        """分析主页面"""
        try:
            # 导航到目标页面
            response = await page.goto(
                self.target,
                wait_until='networkidle',
                timeout=self.config.page_load_timeout
            )
            
            if not response:
                raise Exception("页面加载失败")
            
            # 等待JavaScript执行
            await page.wait_for_timeout(3000)
            
            # 基础页面信息
            title = await page.title()
            url = page.url
            
            print(f"        页面标题: {title}")
            print(f"        实际URL: {url}")
            
            # 检查是否是SPA
            is_spa = await self._detect_spa_application(page)
            if is_spa:
                print("        检测到单页应用(SPA)")
            
        except Exception as e:
            print(f"        主页面分析错误: {e}")
    
    async def _detect_spa_application(self, page: Page) -> bool:
        """检测是否为单页应用"""
        try:
            # 检查常见SPA框架标识
            spa_indicators = await page.evaluate("""
                () => {
                    const indicators = {
                        react: !!(window.React || document.querySelector('[data-reactroot]')),
                        vue: !!(window.Vue || document.querySelector('[data-v-]')),
                        angular: !!(window.angular || window.ng || document.querySelector('[ng-app]')),
                        ember: !!(window.Ember),
                        backbone: !!(window.Backbone)
                    };
                    return indicators;
                }
            """)
            
            return any(spa_indicators.values())
        except:
            return False
    
    async def _discover_dynamic_apis(self, page: Page):
        """发现动态加载的API端点"""
        try:
            # 触发可能的AJAX请求
            trigger_scripts = [
                "window.scrollTo(0, document.body.scrollHeight);",  # 滚动触发懒加载
                "document.querySelectorAll('button, a').forEach(el => el.click?.());",  # 点击交互元素
                "window.history.pushState({}, '', '#/dashboard');",  # 触发路由变化
                "window.history.pushState({}, '', '#/api');",
                "window.history.pushState({}, '', '#/admin');"
            ]
            
            for script in trigger_scripts:
                try:
                    await page.evaluate(script)
                    await page.wait_for_timeout(1000)  # 等待请求触发
                except:
                    continue
            
            print(f"        发现API端点: {len(self.discovered_apis)} 个")
            
        except Exception as e:
            print(f"        动态API发现错误: {e}")
    
    async def _analyze_spa_routes(self, page: Page):
        """分析SPA路由"""
        try:
            # 常见SPA路由模式
            common_routes = [
                '/', '/home', '/dashboard', '/profile', '/settings', '/login', '/logout',
                '/admin', '/api', '/docs', '/help', '/about', '/contact', '/users',
                '/patient', '/doctor', '/appointment', '/medical', '/health'  # 医疗相关
            ]
            
            for route in common_routes:
                try:
                    # 构造可能的SPA路由URL
                    spa_urls = [
                        f"{self.target}#{route}",
                        f"{self.target}#!{route}",
                        f"{self.target}{route}"
                    ]
                    
                    for spa_url in spa_urls:
                        try:
                            await page.goto(spa_url, timeout=5000, wait_until='domcontentloaded')
                            
                            # 检查页面是否真实存在（不是404）
                            content = await page.content()
                            if not any(error in content.lower() for error in ['404', 'not found', 'page not found']):
                                self.spa_routes.add(spa_url)
                                print(f"        发现路由: {spa_url}")
                            
                            await page.wait_for_timeout(500)
                            
                            if len(self.spa_routes) >= self.config.max_spa_routes:
                                break
                        except:
                            continue
                    
                    if len(self.spa_routes) >= self.config.max_spa_routes:
                        break
                        
                except:
                    continue
            
            print(f"        发现SPA路由: {len(self.spa_routes)} 个")
            
        except Exception as e:
            print(f"        SPA路由分析错误: {e}")
    
    async def _analyze_javascript_security(self, page: Page):
        """JavaScript安全分析"""
        try:
            # 检查客户端存储
            storage_analysis = await page.evaluate("""
                () => {
                    const analysis = {
                        localStorage: {},
                        sessionStorage: {},
                        cookies: document.cookie,
                        globalVariables: []
                    };
                    
                    // 检查localStorage
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        analysis.localStorage[key] = localStorage.getItem(key);
                    }
                    
                    // 检查sessionStorage  
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        analysis.sessionStorage[key] = sessionStorage.getItem(key);
                    }
                    
                    // 检查全局变量
                    const globalVars = Object.keys(window).filter(key => 
                        !key.startsWith('webkit') && 
                        typeof window[key] !== 'function' &&
                        key.length > 3
                    );
                    analysis.globalVariables = globalVars.slice(0, 20);
                    
                    return analysis;
                }
            """)
            
            # 检查敏感信息泄露
            sensitive_patterns = [
                r'token["\']?\s*[:=]\s*["\']([^"\']+)',
                r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)',
                r'password["\']?\s*[:=]\s*["\']([^"\']+)',
                r'secret["\']?\s*[:=]\s*["\']([^"\']+)'
            ]
            
            page_content = await page.content()
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                for match in matches:
                    self.security_issues.append({
                        'type': 'sensitive_data_exposure',
                        'pattern': pattern,
                        'value': match[:20] + '...' if len(match) > 20 else match,
                        'severity': 'high'
                    })
            
            # 存储分析结果
            self.dom_analysis['client_storage'] = storage_analysis
            
            print(f"        JS安全问题: {len(self.security_issues)} 个")
            
        except Exception as e:
            print(f"        JavaScript安全分析错误: {e}")
    
    async def _analyze_dom_security(self, page: Page):
        """DOM安全检查"""
        try:
            # 获取DOM结构信息
            dom_info = await page.evaluate("""
                () => {
                    const info = {
                        forms: [],
                        inputs: [],
                        links: [],
                        scripts: [],
                        iframes: []
                    };
                    
                    // 表单分析
                    document.querySelectorAll('form').forEach(form => {
                        info.forms.push({
                            action: form.action,
                            method: form.method,
                            hasFileUpload: !!form.querySelector('input[type="file"]')
                        });
                    });
                    
                    // 输入框分析
                    document.querySelectorAll('input').forEach(input => {
                        info.inputs.push({
                            type: input.type,
                            name: input.name,
                            id: input.id,
                            placeholder: input.placeholder
                        });
                    });
                    
                    // 外部脚本分析
                    document.querySelectorAll('script[src]').forEach(script => {
                        info.scripts.push(script.src);
                    });
                    
                    // iframe分析
                    document.querySelectorAll('iframe').forEach(iframe => {
                        info.iframes.push(iframe.src);
                    });
                    
                    return info;
                }
            """)
            
            self.dom_analysis['structure'] = dom_info
            
            # 检查安全问题
            if dom_info['iframes']:
                self.security_issues.append({
                    'type': 'iframe_usage',
                    'description': f"发现 {len(dom_info['iframes'])} 个iframe",
                    'severity': 'medium'
                })
            
            # 检查外部脚本
            external_scripts = [s for s in dom_info['scripts'] if not urlparse(s).netloc.endswith(urlparse(self.target).netloc)]
            if external_scripts:
                self.security_issues.append({
                    'type': 'external_scripts',
                    'description': f"发现 {len(external_scripts)} 个外部脚本",
                    'scripts': external_scripts[:5],  # 只显示前5个
                    'severity': 'low'
                })
            
            print(f"        DOM元素: 表单{len(dom_info['forms'])}个, 输入框{len(dom_info['inputs'])}个")
            
        except Exception as e:
            print(f"        DOM安全检查错误: {e}")
    
    async def _collect_performance_metrics(self, page: Page):
        """收集性能指标"""
        try:
            # 获取性能指标
            metrics = await page.evaluate("""
                () => {
                    const perf = performance.getEntriesByType('navigation')[0];
                    return {
                        domContentLoaded: perf.domContentLoadedEventEnd - perf.domContentLoadedEventStart,
                        loadComplete: perf.loadEventEnd - perf.loadEventStart,
                        firstPaint: performance.getEntriesByType('paint').find(p => p.name === 'first-paint')?.startTime || 0,
                        firstContentfulPaint: performance.getEntriesByType('paint').find(p => p.name === 'first-contentful-paint')?.startTime || 0
                    };
                }
            """)
            
            self.performance_metrics = metrics
            
        except Exception as e:
            print(f"        性能指标收集错误: {e}")
    
    def _is_api_endpoint(self, url: str) -> bool:
        """判断是否为API端点"""
        api_indicators = [
            '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/',
            '.json', '/endpoint/', '/service/', '/data/'
        ]
        
        return any(indicator in url.lower() for indicator in api_indicators)
    
    def _generate_results(self) -> Dict[str, Any]:
        """生成分析结果"""
        return {
            'target': self.target,
            'scan_timestamp': datetime.now().isoformat(),
            'browser_engine_version': 'v1.0',
            
            # 核心发现
            'discovered_apis': {
                'count': len(self.discovered_apis),
                'endpoints': list(self.discovered_apis)[:50]  # 限制输出数量
            },
            
            'spa_routes': {
                'count': len(self.spa_routes),
                'routes': list(self.spa_routes)
            },
            
            'security_issues': {
                'count': len(self.security_issues),
                'issues': self.security_issues
            },
            
            'javascript_errors': {
                'count': len(self.javascript_errors),
                'errors': self.javascript_errors[:10]  # 限制错误数量
            },
            
            'network_requests': {
                'count': len(self.network_requests),
                'unique_domains': len(set(urlparse(req['url']).netloc for req in self.network_requests)),
                'requests': self.network_requests[:20]  # 限制请求数量
            },
            
            'dom_analysis': self.dom_analysis,
            'performance_metrics': self.performance_metrics,
            
            # 统计信息
            'summary': {
                'total_apis_discovered': len(self.discovered_apis),
                'spa_routes_found': len(self.spa_routes),
                'security_issues_detected': len(self.security_issues),
                'javascript_errors': len(self.javascript_errors),
                'network_requests_captured': len(self.network_requests)
            }
        }
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        """创建错误结果"""
        return {
            'target': self.target,
            'scan_timestamp': datetime.now().isoformat(),
            'browser_engine_version': 'v1.0',
            'error': error_message,
            'success': False,
            'discovered_apis': {'count': 0, 'endpoints': []},
            'spa_routes': {'count': 0, 'routes': []},
            'security_issues': {'count': 0, 'issues': []},
            'summary': {
                'total_apis_discovered': 0,
                'spa_routes_found': 0,
                'security_issues_detected': 0
            }
        }
    
    async def _cleanup(self):
        """清理浏览器资源"""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
        except:
            pass

# 快速集成接口
async def run_browser_analysis(target: str, config: BrowserConfig = None) -> Dict[str, Any]:
    """
    快速浏览器分析接口
    
    Args:
        target: 目标域名或URL
        config: 浏览器配置，可选
    
    Returns:
        分析结果字典
    """
    engine = BrowserEngine(target, config)
    return await engine.run()

# 命令行接口
async def main():
    """命令行主函数"""
    if len(sys.argv) != 2:
        print("使用方法: python browser_engine.py target-domain.com")
        print("示例: python browser_engine.py biograph.com")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"  启动浏览器引擎分析: {target}")
    
    # 检查依赖
    if not PLAYWRIGHT_AVAILABLE:
        print("  Playwright未安装")
        print("请运行: pip install playwright")
        print("然后运行: playwright install")
        sys.exit(1)
    
    # 创建配置
    config = BrowserConfig(
        headless=True,
        timeout=30000
    )
    
    # 执行分析
    results = await run_browser_analysis(target, config)
    
    # 输出结果
    print("\n" + "="*60)
    print("  浏览器引擎分析结果")
    print("="*60)
    
    if results.get('error'):
        print(f"  分析失败: {results['error']}")
        return
    
    summary = results['summary']
    print(f"  API端点发现: {summary['total_apis_discovered']} 个")
    print(f"  SPA路由发现: {summary['spa_routes_found']} 个") 
    print(f"  安全问题: {summary['security_issues_detected']} 个")
    print(f"  JavaScript错误: {summary['javascript_errors']} 个")
    print(f"  网络请求: {summary['network_requests_captured']} 个")
    
    # 保存详细结果
    output_file = f"browser_analysis_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n  详细结果已保存: {output_file}")

if __name__ == "__main__":
    asyncio.run(main()) 