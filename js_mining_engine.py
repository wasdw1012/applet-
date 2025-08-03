#!/usr/bin/env python3
"""
JavaScript深度挖掘引擎 (Deep JavaScript Mining Engine)
专门从现代Web应用的JS文件中挖掘隐藏的API端点和路径
这是针对SPA和现代Web应用的核心武器！
"""

import asyncio
import aiohttp
import ssl
import re
import json
import time
from datetime import datetime
from typing import List, Dict, Set, Any
from urllib.parse import urljoin, urlparse
import jsbeautifier
from playwright.async_api import async_playwright

class JavaScriptMiningEngine:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.discovered_js_files: Set[str] = set()
        self.extracted_endpoints: Set[str] = set()
        self.extracted_paths: Set[str] = set()
        self.session = None
        self.results = []
        
        # API端点匹配正则表达式
        self.api_patterns = [
            # REST API模式
            r'["\'/](api|apis?)["\'/][a-zA-Z0-9/_-]+',
            r'["\'/]v\d+["\'/][a-zA-Z0-9/_-]+',
            r'["\'/](graphql|graph)["\'/]?',
            r'["\'/](rest|REST)["\'/][a-zA-Z0-9/_-]+',
            
            # 后台管理路径
            r'["\'/](admin|administrator|manage|manager|backend|dashboard)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](panel|control|console|cp)["\'/][a-zA-Z0-9/_-]*',
            
            # 医疗系统特定API
            r'["\'/](patient|patients|medical|doctor|doctors|appointment|appointments)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](record|records|diagnosis|prescription|treatment)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](staff|nurse|clinic|hospital)["\'/][a-zA-Z0-9/_-]*',
            
            # 常见功能路径
            r'["\'/](auth|login|logout|register|profile|user|users)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](upload|download|file|files|media|image|images)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](search|query|filter|export|import)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](config|settings|preference|option)["\'/][a-zA-Z0-9/_-]*',
            
            # 数据操作路径  
            r'["\'/](create|read|update|delete|get|post|put|patch)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](list|view|edit|add|remove|save)["\'/][a-zA-Z0-9/_-]*',
            
            # 通用路径模式
            r'["\']\/[a-zA-Z][a-zA-Z0-9/_-]{2,}["\']',
            
            # URL参数和查询
            r'["\'][a-zA-Z0-9/_-]+\?[a-zA-Z0-9&=_-]+["\']',
            
            # 域名相对路径
            r'["\']\.\/[a-zA-Z0-9/_.-]+["\']',
            r'["\']\.\.\/[a-zA-Z0-9/_.-]+["\']'
        ]
        
        # 敏感信息匹配正则
        self.sensitive_patterns = [
            # API密钥和令牌
            r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{10,}["\']',
            r'(access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_.-]{10,}["\']',
            r'(secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{10,}["\']',
            
            # 数据库连接
            r'(database[_-]?url|db[_-]?url)["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'(connection[_-]?string)["\']?\s*[:=]\s*["\'][^"\']+["\']',
            
            # 服务器信息
            r'(server[_-]?url|base[_-]?url)["\']?\s*[:=]\s*["\']https?://[^"\']+["\']',
            r'(endpoint|host)["\']?\s*[:=]\s*["\']https?://[^"\']+["\']',
            
            # 认证信息
            r'(username|user[_-]?name)["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'(password|passwd)["\']?\s*[:=]\s*["\'][^"\']+["\']',
            
            # 配置信息
            r'(config|configuration)["\']?\s*[:=]\s*\{[^}]+\}',
            r'(env|environment)["\']?\s*[:=]\s*["\'][^"\']+["\']'
        ]
        
    async def run_js_mining(self):
        """运行JavaScript挖掘"""
        print("🔍 JavaScript深度挖掘引擎启动")
        print("=" * 60)
        print(f"🎯 目标: {self.target}")
        print("🚀 策略: 发现现代Web应用的隐藏API和路径")
        print("=" * 60)
        
        start_time = time.time()
        
        # Phase 1: 使用浏览器引擎收集所有JS文件
        await self._phase1_collect_js_files()
        
        # Phase 2: 下载并分析JS文件内容
        await self._phase2_analyze_js_content()
        
        # Phase 3: 验证发现的端点
        await self._phase3_validate_endpoints()
        
        duration = time.time() - start_time
        self._generate_mining_report(duration)
        
    async def _phase1_collect_js_files(self):
        """Phase 1: 收集所有JS文件"""
        print("\n📂 Phase 1: 收集JavaScript文件")
        print("-" * 50)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # 监听网络请求，收集JS文件
            js_files = set()
            
            async def handle_response(response):
                url = response.url
                content_type = response.headers.get('content-type', '')
                
                # 识别JavaScript文件
                if (url.endswith('.js') or 
                    'javascript' in content_type or 
                    'application/javascript' in content_type or
                    'text/javascript' in content_type):
                    js_files.add(url)
                    print(f"   📄 发现JS文件: {url}")
                    
            page.on('response', handle_response)
            
            try:
                # 访问目标页面
                await page.goto(self.target, wait_until='networkidle', timeout=30000)
                await page.wait_for_timeout(5000)  # 等待动态加载
                
                # 尝试导航到可能的子页面
                potential_pages = [
                    f"{self.target}/about",
                    f"{self.target}/contact", 
                    f"{self.target}/services",
                    f"{self.target}/login",
                    f"{self.target}/admin"
                ]
                
                for page_url in potential_pages:
                    try:
                        await page.goto(page_url, wait_until='domcontentloaded', timeout=10000)
                        await page.wait_for_timeout(2000)
                    except:
                        continue
                        
            except Exception as e:
                print(f"   ⚠️ 浏览器访问错误: {e}")
                
            await browser.close()
            
        self.discovered_js_files.update(js_files)
        print(f"   ✅ 总共发现 {len(self.discovered_js_files)} 个JS文件")
        
    async def _phase2_analyze_js_content(self):
        """Phase 2: 分析JS文件内容"""
        print("\n🔍 Phase 2: 深度分析JavaScript内容")
        print("-" * 50)
        
        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context())
        timeout = aiohttp.ClientTimeout(total=30)
        
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        
        try:
            for js_url in self.discovered_js_files:
                await self._analyze_single_js_file(js_url)
        finally:
            await self.session.close()
            
    async def _analyze_single_js_file(self, js_url: str):
        """分析单个JS文件"""
        try:
            print(f"🔬 分析: {js_url}")
            
            async with self.session.get(js_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # 尝试美化压缩的JS代码
                    if len(content) > 1000 and '\n' not in content[:1000]:
                        try:
                            content = jsbeautifier.beautify(content)
                            print(f"   ✨ 代码美化成功")
                        except:
                            print(f"   ⚠️ 代码美化失败，使用原始内容")
                    
                    # 提取API端点和路径
                    endpoints = self._extract_endpoints(content, js_url)
                    paths = self._extract_paths(content, js_url)
                    sensitive_info = self._extract_sensitive_info(content, js_url)
                    
                    result = {
                        "js_file": js_url,
                        "size": len(content),
                        "endpoints_found": len(endpoints),
                        "paths_found": len(paths), 
                        "sensitive_info_found": len(sensitive_info),
                        "endpoints": list(endpoints)[:20],  # 只记录前20个
                        "paths": list(paths)[:20],
                        "sensitive_info": sensitive_info,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.results.append(result)
                    
                    if endpoints or paths or sensitive_info:
                        print(f"   🎯 端点: {len(endpoints)}, 路径: {len(paths)}, 敏感信息: {len(sensitive_info)}")
                    
                    self.extracted_endpoints.update(endpoints)
                    self.extracted_paths.update(paths)
                    
        except Exception as e:
            print(f"   ❌ 分析失败: {e}")
            
    def _extract_endpoints(self, content: str, js_url: str) -> Set[str]:
        """提取API端点"""
        endpoints = set()
        
        for pattern in self.api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # 清理匹配结果
                endpoint = match.strip('\'"/')
                if len(endpoint) > 2 and not endpoint.startswith('http'):
                    # 转换为完整URL
                    if endpoint.startswith('/'):
                        full_url = f"{self.target}{endpoint}"
                    else:
                        full_url = f"{self.target}/{endpoint}"
                    endpoints.add(full_url)
                    
        return endpoints
        
    def _extract_paths(self, content: str, js_url: str) -> Set[str]:
        """提取路径信息"""
        paths = set()
        
        # 更宽泛的路径匹配
        path_patterns = [
            r'["\']\/[a-zA-Z][a-zA-Z0-9\/._-]{3,}["\']',
            r'["\'][a-zA-Z][a-zA-Z0-9\/._-]{3,}\.html?["\']',
            r'["\'][a-zA-Z][a-zA-Z0-9\/._-]{3,}\.php["\']',
            r'["\'][a-zA-Z][a-zA-Z0-9\/._-]{3,}\.jsp["\']',
            r'["\'][a-zA-Z][a-zA-Z0-9\/._-]{3,}\.asp["\']'
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                path = match.strip('\'"')
                if len(path) > 3:
                    paths.add(path)
                    
        return paths
        
    def _extract_sensitive_info(self, content: str, js_url: str) -> List[Dict[str, str]]:
        """提取敏感信息"""
        sensitive_info = []
        
        for pattern in self.sensitive_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                info = {
                    "type": "sensitive_data",
                    "pattern": pattern,
                    "match": match.group(0)[:100],  # 只记录前100个字符
                    "position": match.start()
                }
                sensitive_info.append(info)
                
        return sensitive_info
        
    async def _phase3_validate_endpoints(self):
        """Phase 3: 验证发现的端点"""
        print("\n✅ Phase 3: 验证发现的端点")
        print("-" * 50)
        
        if not self.extracted_endpoints:
            print("   📋 没有发现端点需要验证")
            return
            
        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context())
        timeout = aiohttp.ClientTimeout(total=15)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for endpoint in list(self.extracted_endpoints)[:50]:  # 只验证前50个
                tasks.append(self._validate_endpoint(session, endpoint))
                
            await asyncio.gather(*tasks, return_exceptions=True)
            
    async def _validate_endpoint(self, session: aiohttp.ClientSession, endpoint: str):
        """验证单个端点"""
        try:
            async with session.get(endpoint, allow_redirects=False) as response:
                if response.status in [200, 201, 301, 302, 401, 403]:
                    result = {
                        "endpoint": endpoint,
                        "status": response.status,
                        "accessible": response.status in [200, 201],
                        "size": response.headers.get('content-length', 0),
                        "content_type": response.headers.get('content-type', ''),
                        "validated": True,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.results.append(result)
                    
                    if response.status in [200, 201]:
                        print(f"   ✅ 可访问: {endpoint} ({response.status})")
                    elif response.status in [401, 403]:
                        print(f"   🔐 受保护: {endpoint} ({response.status})")
                    else:
                        print(f"   🔄 重定向: {endpoint} ({response.status})")
                        
        except Exception as e:
            pass
            
    def _generate_mining_report(self, duration: float):
        """生成挖掘报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"js_mining_results_{timestamp}.json"
        
        # 统计信息
        total_js_files = len(self.discovered_js_files)
        total_endpoints = len(self.extracted_endpoints)
        total_paths = len(self.extracted_paths)
        
        # 验证结果统计
        validated_results = [r for r in self.results if r.get("validated")]
        accessible_count = len([r for r in validated_results if r.get("accessible")])
        protected_count = len([r for r in validated_results if r.get("status") in [401, 403]])
        
        report = {
            "scan_info": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "duration": duration,
                "js_files_analyzed": total_js_files,
                "endpoints_extracted": total_endpoints,
                "paths_extracted": total_paths,
                "endpoints_validated": len(validated_results),
                "accessible_endpoints": accessible_count,
                "protected_endpoints": protected_count
            },
            "discovered_js_files": list(self.discovered_js_files),
            "extracted_endpoints": list(self.extracted_endpoints),
            "extracted_paths": list(self.extracted_paths),
            "analysis_results": self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        print(f"\n🎯 JavaScript挖掘完成!")
        print(f"📂 JS文件分析: {total_js_files}")
        print(f"🔌 端点发现: {total_endpoints}")
        print(f"📄 路径发现: {total_paths}")
        print(f"✅ 可访问端点: {accessible_count}")
        print(f"🔐 受保护端点: {protected_count}")
        print(f"⏱️ 挖掘耗时: {duration:.2f}秒")
        print(f"📄 详细报告: {filename}")
        
        if accessible_count > 0:
            print(f"\n🔥 发现可访问的新端点!")
            for result in validated_results:
                if result.get("accessible"):
                    print(f"   ✅ {result['endpoint']}")

async def main():
    import sys
    
    if len(sys.argv) != 2:
        print("使用方法: python js_mining_engine.py <target>")
        print("示例: python js_mining_engine.py https://asanoha-clinic.com")
        return
        
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
        
    engine = JavaScriptMiningEngine(target)
    await engine.run_js_mining()

if __name__ == "__main__":
    asyncio.run(main()) 