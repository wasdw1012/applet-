import asyncio
import json
import sys
from datetime import datetime
from typing import Dict, Any

# 导入依赖
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from dom_xss_scanner import DOMXSSScanner, DOMXSSConfig, scan_dom_xss
    DOM_XSS_AVAILABLE = True
except ImportError as e:
    DOM_XSS_AVAILABLE = False
    print(f"  DOM XSS扫描器导入失败: {e}")

try:
    from browser_engine import BrowserEngine, BrowserConfig
    BROWSER_ENGINE_AVAILABLE = True
except ImportError:
    BROWSER_ENGINE_AVAILABLE = False

async def test_dom_xss_scanner(target: str) -> Dict[str, Any]:
    """测试DOM XSS扫描器"""
    print(f"  测试DOM XSS扫描器: {target}")
    
    if not all([PLAYWRIGHT_AVAILABLE, DOM_XSS_AVAILABLE]):
        return {
            'error': 'DOM XSS扫描器依赖不完整',
            'success': False
        }
    
    try:
        # 启动浏览器
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        # 导航到目标页面
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # 优化页面加载策略
        await page.goto(target, wait_until='domcontentloaded', timeout=20000)
        # 额外等待JavaScript执行
        await page.wait_for_timeout(3000)
        
        # 创建DOM XSS配置
        xss_config = DOMXSSConfig(
            enable_form_testing=True,
            enable_url_param_testing=True,
            enable_hash_testing=True,
            safe_mode=True,  # 安全模式
            max_inputs_to_test=10,  # 限制测试点
            detection_timeout=3000  # 3秒检测超时
        )
        
        # 执行DOM XSS扫描
        results = await scan_dom_xss(page, xss_config)
        
        # 清理资源
        await browser.close()
        await playwright.stop()
        
        return results
        
    except Exception as e:
        print(f"  DOM XSS测试失败: {e}")
        return {
            'error': str(e),
            'success': False
        }

def show_integration_guide():
    """显示集成指导"""
    
    integration_code = '''
# 🔗 Browser Engine集成DOM XSS扫描器

## 步骤1: 修改browser_engine.py的导入部分

```python
# 在browser_engine.py顶部添加
try:
    from dom_xss_scanner import DOMXSSScanner, DOMXSSConfig, scan_dom_xss
    DOM_XSS_AVAILABLE = True
except ImportError:
    DOM_XSS_AVAILABLE = False
    print("  DOM XSS扫描器不可用")
```

## 步骤2: 修改BrowserConfig类

```python
@dataclass
class BrowserConfig:
    # ... 现有配置 ...
    
    # 新增: DOM XSS扫描配置
    enable_dom_xss_scan: bool = True
    xss_safe_mode: bool = True
    xss_max_inputs: int = 15
    xss_detection_timeout: int = 5000
```

## 步骤3: 修改BrowserEngine类的__init__方法

```python
class BrowserEngine:
    def __init__(self, target: str, config: BrowserConfig = None):
        # ... 现有代码 ...
        
        # 新增: DOM XSS结果存储
        self.xss_vulnerabilities: List[Dict] = []
        self.xss_scan_summary: Dict = {}
```

## 步骤4: 在_perform_analysis方法中添加DOM XSS扫描

```python
async def _perform_analysis(self):
    page = await self.context.new_page()
    
    try:
        # ... 现有分析代码 ...
        
        # 新增: DOM XSS安全扫描
        if self.config.enable_dom_xss_scan and DOM_XSS_AVAILABLE:
            print("      DOM XSS安全扫描...")
            await self._perform_dom_xss_scan(page)
        
    finally:
        await page.close()

async def _perform_dom_xss_scan(self, page: Page):
    \"\"\"执行DOM XSS安全扫描\"\"\"
    try:
        # 创建XSS扫描配置
        xss_config = DOMXSSConfig(
            enable_form_testing=True,
            enable_url_param_testing=True,
            enable_hash_testing=True,
            safe_mode=self.config.xss_safe_mode,
            max_inputs_to_test=self.config.xss_max_inputs,
            detection_timeout=self.config.xss_detection_timeout
        )
        
        # 执行XSS扫描
        xss_results = await scan_dom_xss(page, xss_config)
        
        # 存储结果
        self.xss_scan_summary = xss_results.get('vulnerability_summary', {})
        self.xss_vulnerabilities = xss_results.get('vulnerabilities', [])
        
        # 输出发现
        total_vulns = self.xss_scan_summary.get('total_vulnerabilities', 0)
        if total_vulns > 0:
            print(f"        发现XSS漏洞: {total_vulns} 个")
            high_vulns = self.xss_scan_summary.get('high_severity', 0)
            if high_vulns > 0:
                print(f"         高危漏洞: {high_vulns} 个")
        else:
            print(f"        未发现XSS漏洞")
            
    except Exception as e:
        print(f"        DOM XSS扫描错误: {e}")
        self.xss_scan_summary = {'error': str(e)}
        self.xss_vulnerabilities = []
```

## 步骤5: 修改_generate_results方法

```python
def _generate_results(self) -> Dict[str, Any]:
    return {
        # ... 现有结果 ...
        
        # 新增: XSS扫描结果
        'dom_xss_scan': {
            'summary': self.xss_scan_summary,
            'vulnerabilities': self.xss_vulnerabilities,
            'scan_enabled': self.config.enable_dom_xss_scan and DOM_XSS_AVAILABLE
        },
        
        # 更新summary
        'summary': {
            # ... 现有统计 ...
            'xss_vulnerabilities_found': len(self.xss_vulnerabilities),
            'xss_high_severity': self.xss_scan_summary.get('high_severity', 0)
        }
    }
```

## 使用示例：

```python
from browser_engine import BrowserEngine, BrowserConfig

# 创建配置（启用XSS扫描）
config = BrowserConfig(
    headless=True,
    enable_dom_xss_scan=True,
    xss_safe_mode=True,
    xss_max_inputs=20
)

# 执行扫描
engine = BrowserEngine("biograph.com", config)
results = await engine.run()

# 查看XSS结果
xss_results = results['dom_xss_scan']
print(f"发现XSS漏洞: {len(xss_results['vulnerabilities'])} 个")
```
'''
    
    print("🔗 DOM XSS扫描器集成指导")
    print("="*60)
    print(integration_code)
    print("="*60)

async def demo_dom_xss_capabilities(target: str):
    """演示DOM XSS扫描能力"""
    print(f"  DOM XSS扫描器能力演示: {target}")
    print("="*60)
    
    # 执行扫描
    results = await test_dom_xss_scanner(target)
    
    if results.get('error'):
        print(f"  演示失败: {results['error']}")
        return
    
    # 输出核心发现
    summary = results.get('vulnerability_summary', {})
    vulnerabilities = results.get('vulnerabilities', [])
    test_summary = results.get('test_summary', {})
    
    print(f"  扫描摘要:")
    print(f"    测试的注入点: {test_summary.get('total_injection_points', 0)} 个")
    print(f"    完成的测试: {test_summary.get('completed_tests', 0)} 个")
    print(f"    发现的漏洞: {summary.get('total_vulnerabilities', 0)} 个")
    
    if summary.get('total_vulnerabilities', 0) > 0:
        print(f"     高危漏洞: {summary.get('high_severity', 0)} 个")
        print(f"     中危漏洞: {summary.get('medium_severity', 0)} 个")
        print(f"     低危漏洞: {summary.get('low_severity', 0)} 个")
        
        print(f"\n  漏洞详情:")
        for i, vuln in enumerate(vulnerabilities[:3], 1):  # 显示前3个
            print(f"  [{i}] {vuln.get('severity', 'unknown').upper()}: {vuln.get('detection_method', 'unknown')}")
            print(f"      URL: {vuln.get('url', 'unknown')}")
            print(f"      载荷: {vuln.get('payload', 'unknown')[:50]}...")
    else:
        print(f"    未发现DOM XSS漏洞")
    
    # 安全建议
    recommendations = results.get('security_recommendations', [])
    if recommendations:
        print(f"\n  安全建议:")
        for rec in recommendations[:3]:
            print(f"  • {rec}")
    
    # 保存详细结果
    output_file = f"dom_xss_scan_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n  详细结果已保存: {output_file}")
    print(f"⏱️  扫描耗时: {results.get('execution_time', 'unknown')}")
    print("\n" + "="*60)

def check_dependencies():
    """检查DOM XSS扫描器依赖"""
    print("  检查DOM XSS扫描器依赖...")
    
    dependencies = {
        'playwright': PLAYWRIGHT_AVAILABLE,
        'dom_xss_scanner': DOM_XSS_AVAILABLE,
        'browser_engine': BROWSER_ENGINE_AVAILABLE
    }
    
    for dep, available in dependencies.items():
        if available:
            print(f"    {dep} - 可用")
        else:
            print(f"    {dep} - 不可用")
    
    if all(dependencies.values()):
        print("\n  所有依赖已就绪！可以开始DOM XSS安全测试。")
        return True
    else:
        print("\n  请安装缺少的依赖：")
        if not PLAYWRIGHT_AVAILABLE:
            print("   pip install playwright && playwright install")
        if not DOM_XSS_AVAILABLE:
            print("   确保dom_xss_scanner.py在同一目录下")
        if not BROWSER_ENGINE_AVAILABLE:
            print("   确保browser_engine.py在同一目录下")
        return False

async def integrated_security_scan(target: str):
    """集成安全扫描演示（浏览器引擎 + DOM XSS）"""
    print(f"  集成安全扫描演示: {target}")
    print("="*60)
    
    if not BROWSER_ENGINE_AVAILABLE:
        print("  浏览器引擎不可用，无法执行集成扫描")
        return
    
    try:
        # 浏览器引擎基础扫描
        print("  [1/2] 浏览器引擎扫描...")
        browser_config = BrowserConfig(
            headless=True, 
            timeout=20000,
            page_load_timeout=15000,
            network_idle_timeout=2000
        )
        browser_engine = BrowserEngine(target, browser_config)
        browser_results = await browser_engine.run()
        
        # DOM XSS安全扫描
        print("  [2/2] DOM XSS安全扫描...")
        xss_results = await test_dom_xss_scanner(target)
        
        # 整合结果
        integrated_results = {
            'target': target,
            'scan_timestamp': datetime.now().isoformat(),
            'browser_engine': browser_results,
            'dom_xss_scan': xss_results,
            'integrated_summary': {
                'apis_discovered': browser_results.get('summary', {}).get('total_apis_discovered', 0),
                'spa_routes_found': browser_results.get('summary', {}).get('spa_routes_found', 0),
                'xss_vulnerabilities': xss_results.get('vulnerability_summary', {}).get('total_vulnerabilities', 0),
                'security_issues': browser_results.get('summary', {}).get('security_issues_detected', 0)
            }
        }
        
        # 输出整合结果
        summary = integrated_results['integrated_summary']
        print(f"\n  集成扫描结果:")
        print(f"    API端点发现: {summary['apis_discovered']} 个")
        print(f"    SPA路由发现: {summary['spa_routes_found']} 个")
        print(f"    XSS漏洞发现: {summary['xss_vulnerabilities']} 个")
        print(f"    其他安全问题: {summary['security_issues']} 个")
        
        # 保存集成结果
        output_file = f"integrated_security_scan_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(integrated_results, f, indent=2, ensure_ascii=False)
        
        print(f"\n  集成报告已保存: {output_file}")
        
        return integrated_results
        
    except Exception as e:
        print(f"  集成扫描失败: {e}")
        return None

async def main():
    """主函数"""
    print("  DOM XSS扫描器集成工具")
    print("="*40)
    
    if len(sys.argv) < 2:
        print("使用方法:")
        print("  python dom_xss_integration.py check                    # 检查依赖")
        print("  python dom_xss_integration.py test <target>            # 测试DOM XSS扫描")
        print("  python dom_xss_integration.py demo <target>            # 演示扫描能力")
        print("  python dom_xss_integration.py integrated <target>      # 集成安全扫描")
        print("  python dom_xss_integration.py guide                    # 显示集成指导")
        print("\n示例:")
        print("  python dom_xss_integration.py test biograph.com")
        print("  python dom_xss_integration.py demo biograph.com")
        print("  python dom_xss_integration.py integrated biograph.com")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'check':
        check_dependencies()
    elif command == 'guide':
        show_integration_guide()
    elif command in ['test', 'demo', 'integrated'] and len(sys.argv) > 2:
        target = sys.argv[2]
        
        # 检查依赖
        if not check_dependencies():
            print("\n  依赖检查失败，请先安装必需的依赖。")
            sys.exit(1)
        
        if command == 'test':
            results = await test_dom_xss_scanner(target)
            print(f"  测试完成，发现漏洞: {results.get('vulnerability_summary', {}).get('total_vulnerabilities', 0)} 个")
        elif command == 'demo':
            await demo_dom_xss_capabilities(target)
        elif command == 'integrated':
            await integrated_security_scan(target)
    else:
        print("  无效的命令或缺少参数")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 