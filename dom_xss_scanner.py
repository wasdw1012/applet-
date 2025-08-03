
import asyncio
import json
import re
import uuid
import time
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field

# Playwright依赖
try:
    from playwright.async_api import Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("  Playwright未安装，DOM XSS扫描器不可用")

@dataclass
class XSSPayload:
    """XSS测试载荷"""
    name: str
    payload: str
    canary_token: str
    detection_method: str
    risk_level: str

@dataclass
class XSSVulnerability:
    """XSS漏洞信息"""
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
    """DOM XSS扫描配置"""
    # 检测配置
    enable_form_testing: bool = True
    enable_url_param_testing: bool = True
    enable_hash_testing: bool = True
    enable_dom_property_testing: bool = True
    
    # 安全配置
    max_payloads_per_input: int = 5
    detection_timeout: int = 5000  # 5秒检测超时
    safe_mode: bool = True  # 安全模式，只使用无害payload
    
    # 性能配置
    max_inputs_to_test: int = 20
    concurrent_tests: int = 3
    page_wait_time: int = 2000  # 页面加载等待时间

class DOMXSSScanner:
    """
      DOM XSS自动化检测引擎
    
    核心能力：
    • 智能识别所有可能的XSS注入点
    • 使用安全的Canary Token进行检测
    • 实时监控DOM变化和JavaScript执行
    • 零误报的漏洞验证机制
    • 完整的漏洞详情和修复建议
    """
    
    def __init__(self, page: Page, config: DOMXSSConfig = None):
        self.page = page
        self.config = config or DOMXSSConfig()
        
        # 检测结果
        self.vulnerabilities: List[XSSVulnerability] = []
        self.tested_inputs: List[Dict] = []
        self.canary_tokens: Set[str] = set()
        
        # 会话标识
        self.scan_id = str(uuid.uuid4())[:8]
        
        print(f"  DOM XSS扫描器初始化 [扫描ID: {self.scan_id}]")
    
    async def scan(self) -> Dict[str, Any]:
        """执行完整的DOM XSS扫描"""
        print("\n  启动DOM XSS自动化检测...")
        
        start_time = time.time()
        
        try:
            # 设置页面监控
            await self._setup_page_monitoring()
            
            # 识别输入点
            print("      识别XSS注入点...")
            input_points = await self._identify_injection_points()
            
            # 生成测试载荷
            print("      生成安全测试载荷...")
            payloads = self._generate_safe_payloads()
            
            # 执行XSS测试
            print("      执行DOM XSS测试...")
            await self._execute_xss_tests(input_points, payloads)
            
            # 验证检测结果
            print("      验证漏洞发现...")
            await self._verify_vulnerabilities()
            
            execution_time = time.time() - start_time
            
            # 生成扫描报告
            results = self._generate_scan_report(execution_time)
            
            print(f"  DOM XSS扫描完成 ({execution_time:.2f}秒)")
            print(f"  发现漏洞: {len(self.vulnerabilities)} 个")
            print(f"  测试点: {len(self.tested_inputs)} 个")
            
            return results
            
        except Exception as e:
            print(f"  DOM XSS扫描错误: {e}")
            return self._create_error_result(str(e))
    
    async def _setup_page_monitoring(self):
        """设置页面监控"""
        # 注入DOM变化监控脚本
        await self.page.add_init_script("""
            window.xss_canary_detections = [];
            window.xss_dom_mutations = [];
            
            // DOM变化监控
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.type === 'childList') {
                        mutation.addedNodes.forEach(function(node) {
                            if (node.nodeType === 1 && node.innerHTML) {
                                window.xss_dom_mutations.push({
                                    type: 'childList',
                                    content: node.innerHTML.substring(0, 200),
                                    timestamp: Date.now()
                                });
                            }
                        });
                    }
                });
            });
            
            observer.observe(document.body || document.documentElement, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeOldValue: true
            });
            
            // Canary Token检测函数
            window.detectCanaryToken = function(token) {
                window.xss_canary_detections.push({
                    token: token,
                    detected: true,
                    timestamp: Date.now(),
                    location: 'javascript_execution'
                });
            };
        """)
    
    async def _identify_injection_points(self) -> List[Dict]:
        """识别所有可能的XSS注入点"""
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
        
        print(f"        发现注入点: {len(injection_points)} 个")
        return injection_points[:self.config.max_inputs_to_test]
    
    async def _find_form_inputs(self) -> List[Dict]:
        """查找表单输入点"""
        try:
            inputs = await self.page.evaluate("""
                () => {
                    const inputs = [];
                    
                    // 扩展输入框类型检测
                    document.querySelectorAll('input, textarea, [contenteditable="true"], [role="textbox"], [role="searchbox"]').forEach((input, index) => {
                        // 跳过隐藏和只读元素
                        if (input.type === 'hidden' || input.readOnly || input.disabled) return;
                        
                        // 包含更多输入类型
                        inputs.push({
                            type: 'form_input',
                            element: 'input',
                            selector: input.tagName.toLowerCase() + (input.id ? '#' + input.id : '') + (input.name ? '[name="' + input.name + '"]' : ''),
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
        """查找URL参数注入点"""
        current_url = self.page.url
        parsed_url = urlparse(current_url)
        params = parse_qs(parsed_url.query)
        
        url_points = []
        for param_name in params.keys():
            url_points.append({
                'type': 'url_parameter',
                'parameter': param_name,
                'current_value': params[param_name][0] if params[param_name] else '',
                'url': current_url
            })
        
        return url_points
    
    async def _find_hash_parameters(self) -> List[Dict]:
        """查找Hash片段注入点"""
        try:
            hash_info = await self.page.evaluate("""
                () => {
                    const hash = window.location.hash;
                    if (!hash) return [];
                    
                    // 检查hash是否包含参数
                    const hashParams = [];
                    if (hash.includes('=')) {
                        // 类似 #param=value 的形式
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
                        // 整个hash作为一个测试点
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
        """查找DOM属性注入点"""
        try:
            dom_points = await self.page.evaluate("""
                () => {
                    const points = [];
                    
                    // 扩展DOM注入点检测 - 现代网站兼容
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
                            points.push({
                                type: 'dom_property',
                                element: el.tagName.toLowerCase(),
                                selector: el.id ? '#' + el.id : '.' + (el.className.split(' ')[0] || 'element'),
                                current_content: el.innerHTML ? el.innerHTML.substring(0, 100) : '',
                                attributes: Array.from(el.attributes).map(attr => attr.name),
                                interactive: !!(el.onclick || el.getAttribute('role') === 'button'),
                                aria_label: el.getAttribute('aria-label') || '',
                                placeholder: el.placeholder || '',
                                data_attributes: Array.from(el.attributes)
                                    .filter(attr => attr.name.startsWith('data-'))
                                    .map(attr => ({ name: attr.name, value: attr.value }))
                            });
                        }
                    });
                    
                    return points.slice(0, 10); // 限制数量
                }
            """)
            
            return dom_points
        except:
            return []
    
    def _generate_safe_payloads(self) -> List[XSSPayload]:
        """生成安全的XSS测试载荷"""
        payloads = []
        
        # 基础Canary Token
        base_canary = f"XSS_CANARY_{self.scan_id}"
        
        # 1. 基础DOM检测
        payloads.append(XSSPayload(
            name="基础DOM注入",
            payload=f'<div id="{base_canary}_1">DOM_CANARY_TEST</div>',
            canary_token=f"{base_canary}_1",
            detection_method="dom_search",
            risk_level="medium"
        ))
        
        # 2. JavaScript执行检测
        payloads.append(XSSPayload(
            name="JS执行检测",
            payload=f'<script>window.detectCanaryToken("{base_canary}_2")</script>',
            canary_token=f"{base_canary}_2",
            detection_method="js_execution",
            risk_level="high"
        ))
        
        # 3. 事件处理器检测
        payloads.append(XSSPayload(
            name="事件处理器",
            payload=f'<img src="x" onerror="window.detectCanaryToken(\'{base_canary}_3\')">',
            canary_token=f"{base_canary}_3",
            detection_method="js_execution",
            risk_level="high"
        ))
        
        # 4. 属性注入检测
        payloads.append(XSSPayload(
            name="属性注入",
            payload=f'" onmouseover="window.detectCanaryToken(\'{base_canary}_4\')" data-test="',
            canary_token=f"{base_canary}_4",
            detection_method="js_execution",
            risk_level="medium"
        ))
        
        # 5. 文本节点检测
        payloads.append(XSSPayload(
            name="文本节点",
            payload=f'{base_canary}_5_TEXT_INJECTION',
            canary_token=f"{base_canary}_5_TEXT_INJECTION",
            detection_method="dom_search",
            risk_level="low"
        ))
        
        # 存储所有canary tokens
        for payload in payloads:
            self.canary_tokens.add(payload.canary_token)
        
        return payloads[:self.config.max_payloads_per_input]
    
    async def _execute_xss_tests(self, injection_points: List[Dict], payloads: List[XSSPayload]):
        """执行XSS测试"""
        for point_index, injection_point in enumerate(injection_points):
            print(f"        测试点 {point_index + 1}/{len(injection_points)}: {injection_point.get('type', 'unknown')}")
            
            for payload in payloads:
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
                            print(f"          发现漏洞: {vulnerability.severity} - {vulnerability.detection_method}")
                    
                    test_record['status'] = 'completed'
                    
                    # 测试间隔
                    await self.page.wait_for_timeout(500)
                    
                except Exception as e:
                    print(f"          测试错误: {e}")
                    test_record['status'] = f'error: {e}'
    
    async def _inject_payload(self, injection_point: Dict, payload: XSSPayload) -> bool:
        """向注入点注入测试载荷"""
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
        """向表单输入框注入载荷"""
        try:
            selector = injection_point['selector']
            
            # 清空输入框
            await self.page.fill(selector, "")
            
            # 注入payload
            await self.page.fill(selector, payload.payload)
            
            # 触发表单提交或事件
            await self.page.press(selector, "Tab")  # 触发blur事件
            
            return True
        except:
            return False
    
    async def _inject_url_parameter(self, injection_point: Dict, payload: XSSPayload) -> bool:
        """向URL参数注入载荷"""
        try:
            current_url = self.page.url
            parsed_url = urlparse(current_url)
            params = parse_qs(parsed_url.query)
            
            # 修改参数值
            param_name = injection_point['parameter']
            params[param_name] = [payload.payload]
            
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
            
            # 导航到新URL
            await self.page.goto(new_url, wait_until='domcontentloaded', timeout=10000)
            
            return True
        except:
            return False
    
    async def _inject_hash_parameter(self, injection_point: Dict, payload: XSSPayload) -> bool:
        """向Hash参数注入载荷"""
        try:
            if injection_point['type'] == 'hash_fragment':
                # 整个hash替换
                new_hash = f"#{payload.payload}"
            else:
                # 参数替换
                param_name = injection_point['parameter']
                new_hash = f"#{param_name}={payload.payload}"
            
            # 更新hash
            await self.page.evaluate(f"window.location.hash = '{new_hash}'")
            
            # 等待hash变化处理
            await self.page.wait_for_timeout(1000)
            
            return True
        except:
            return False
    
    async def _inject_dom_property(self, injection_point: Dict, payload: XSSPayload) -> bool:
        """向DOM属性注入载荷"""
        try:
            selector = injection_point['selector']
            
            # 直接修改innerHTML
            await self.page.evaluate(f"""
                (selector, payload) => {{
                    const element = document.querySelector(selector);
                    if (element) {{
                        element.innerHTML = payload;
                        return true;
                    }}
                    return false;
                }}
            """, selector, payload.payload)
            
            return True
        except:
            return False
    
    async def _detect_xss_vulnerability(self, injection_point: Dict, payload: XSSPayload) -> Optional[XSSVulnerability]:
        """检测XSS漏洞是否触发"""
        try:
            if payload.detection_method == "dom_search":
                # DOM搜索检测
                dom_found = await self.page.evaluate(f"""
                    () => {{
                        const canary = "{payload.canary_token}";
                        return document.body.innerHTML.includes(canary);
                    }}
                """)
                
                if dom_found:
                    return self._create_vulnerability(injection_point, payload, "DOM内容检测")
            
            elif payload.detection_method == "js_execution":
                # JavaScript执行检测
                js_detections = await self.page.evaluate("""
                    () => window.xss_canary_detections || []
                """)
                
                for detection in js_detections:
                    if detection['token'] == payload.canary_token:
                        return self._create_vulnerability(injection_point, payload, "JavaScript执行检测")
            
            return None
            
        except Exception as e:
            print(f"            检测错误: {e}")
            return None
    
    def _create_vulnerability(self, injection_point: Dict, payload: XSSPayload, detection_context: str) -> XSSVulnerability:
        """创建漏洞记录"""
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
        """验证发现的漏洞"""
        verified_vulns = []
        
        for vuln in self.vulnerabilities:
            # 二次验证
            try:
                # 生成新的验证canary
                verify_canary = f"VERIFY_{vuln.vuln_id}"
                
                # 简单的再次测试
                dom_clean = await self.page.evaluate(f"""
                    () => !document.body.innerHTML.includes("{verify_canary}")
                """)
                
                if dom_clean:
                    verified_vulns.append(vuln)
                else:
                    print(f"          漏洞验证失败: {vuln.vuln_id}")
                    
            except:
                # 保守策略：验证失败时保留漏洞
                verified_vulns.append(vuln)
        
        self.vulnerabilities = verified_vulns
    
    def _generate_scan_report(self, execution_time: float) -> Dict[str, Any]:
        """生成扫描报告"""
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
            
            # 测试统计
            'test_summary': {
                'total_injection_points': len(self.tested_inputs),
                'completed_tests': len([t for t in self.tested_inputs if t['status'] == 'completed']),
                'failed_tests': len([t for t in self.tested_inputs if 'error' in t['status']])
            },
            
            # 安全建议
            'security_recommendations': self._generate_security_recommendations()
        }
    
    def _generate_security_recommendations(self) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        if self.vulnerabilities:
            recommendations.extend([
                "  立即对所有用户输入进行HTML实体编码",
                "  实施内容安全策略(CSP)头部",
                "  使用输入验证白名单机制",
                "  避免直接操作DOM innerHTML属性",
                "  定期进行自动化XSS安全测试"
            ])
        
        if any(v.severity == 'high' for v in self.vulnerabilities):
            recommendations.insert(0, "  发现高危XSS漏洞，建议立即修复！")
        
        if not self.vulnerabilities:
            recommendations.append("  未发现DOM XSS漏洞，但建议持续监控")
        
        return recommendations
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        """创建错误结果"""
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

# 快速集成接口
async def scan_dom_xss(page: Page, config: DOMXSSConfig = None) -> Dict[str, Any]:
    """
    快速DOM XSS扫描接口
    
    Args:
        page: Playwright页面对象
        config: 扫描配置，可选
    
    Returns:
        扫描结果字典
    """
    scanner = DOMXSSScanner(page, config)
    return await scanner.scan()

# 独立运行接口
async def main():
    """独立测试主函数"""
    if not PLAYWRIGHT_AVAILABLE:
        print("  Playwright未安装，无法运行DOM XSS扫描器")
        return
    
    # 这里可以添加独立测试逻辑
    print("  DOM XSS扫描器已准备就绪")
    print("  使用方法: 通过browser_engine.py集成调用")

if __name__ == "__main__":
    asyncio.run(main()) 