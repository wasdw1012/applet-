#!/usr/bin/env python3
"""
JavaScript深度挖掘引擎 - 完整版 (Advanced JS Mining Engine)
新增：熵值检测、完整正则库、智能密钥识别
"""

import asyncio
import aiohttp
import ssl
import re
import json
import time
import math
from datetime import datetime
from typing import List, Dict, Set, Any
from urllib.parse import urljoin, urlparse
import jsbeautifier
from playwright.async_api import async_playwright
from anti_waf_engine import AntiWAFEngine, StealthHTTPClient

class AdvancedJSMiningEngine:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.discovered_js_files: Set[str] = set()
        self.extracted_endpoints: Set[str] = set()
        self.extracted_paths: Set[str] = set()
        self.high_entropy_strings: List[Dict] = []
        self.results = []
        
        # 反WAF引擎集成
        self.anti_waf = AntiWAFEngine()
        
        # 完整的敏感信息正则库
        self.sensitive_patterns = {
            # API密钥和令牌 (更全面)
            "firebase_url": r'https://[a-z0-9-]+\.firebaseio\.com',
            "mailgun_key": r'key-[a-z0-9]{32}',
            "twilio_sid": r'AC[a-f0-9]{32}',
            "sendgrid_key": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            
            # 通用API密钥模式
            "api_key_pattern": r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{10,}["\']',
            "secret_key_pattern": r'(secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{10,}["\']',
            "access_token_pattern": r'(access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_.-]{10,}["\']',
            
            # 数据库和服务器
            "database_url": r'(database[_-]?url|db[_-]?url)["\']?\s*[:=]\s*["\'][^"\']+["\']',
            "connection_string": r'(connection[_-]?string)["\']?\s*[:=]\s*["\'][^"\']+["\']',
            "server_url": r'(server[_-]?url|base[_-]?url)["\']?\s*[:=]\s*["\']https?://[^"\']+["\']',
            
            # JWT和认证
            "jwt_token": r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            "bearer_token": r'Bearer\s+[a-zA-Z0-9_-]{20,}',
            
            # 密码和凭据
            "password_pattern": r'(password|passwd)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
            "username_pattern": r'(username|user[_-]?name)["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
            
            # 云服务配置
            "s3_bucket": r's3://[a-z0-9.-]+',
            "azure_storage": r'https://[a-z0-9]+\.blob\.core\.windows\.net',
            "gcp_storage": r'gs://[a-z0-9.-]+',
        }
        
        # API端点匹配（与基础版本相同但优化）
        self.api_patterns = [
            r'["\'/](api|apis?)["\'/][a-zA-Z0-9/_-]+',
            r'["\'/]v\d+["\'/][a-zA-Z0-9/_-]+',
            r'["\'/](graphql|graph)["\'/]?',
            r'["\'/](admin|dashboard|panel)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](patient|medical|doctor)["\'/][a-zA-Z0-9/_-]*',
            r'["\'/](auth|login|user)["\'/][a-zA-Z0-9/_-]*',
            r'["\']\/[a-zA-Z][a-zA-Z0-9/_-]{2,}["\']',
        ]
        
    def calculate_entropy(self, string: str) -> float:
        """计算字符串的香农熵"""
        if len(string) == 0:
            return 0
        
        # 统计字符频率
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # 计算熵值
        entropy = 0
        length = len(string)
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
    
    def is_high_entropy_string(self, string: str, min_length: int = 20, min_entropy: float = 4.5) -> bool:
        """判断是否为高熵值字符串（可能是密钥）"""
        # 过滤条件
        if len(string) < min_length:
            return False
            
        # 排除明显的非密钥字符串
        excluded_patterns = [
            r'^https?://',  # URL
            r'^\d+$',       # 纯数字
            r'^[a-z\s]+$',  # 纯小写字母加空格
            r'console\.log', # 代码片段
            r'function\s',   # 函数定义
            r'var\s|let\s|const\s',  # 变量声明
        ]
        
        for pattern in excluded_patterns:
            if re.search(pattern, string, re.IGNORECASE):
                return False
        
        # 计算熵值
        entropy = self.calculate_entropy(string)
        return entropy >= min_entropy
    
    def extract_high_entropy_strings(self, content: str, js_url: str) -> List[Dict]:
        """提取高熵值字符串"""
        high_entropy_results = []
        
        # 寻找可能的密钥字符串（引号包围的长字符串）
        string_patterns = [
            r'"([a-zA-Z0-9+/=_-]{20,})"',   # 双引号
            r"'([a-zA-Z0-9+/=_-]{20,})'",   # 单引号
            r'`([a-zA-Z0-9+/=_-]{20,})`',   # 反引号
        ]
        
        for pattern in string_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                candidate_string = match.group(1)
                
                if self.is_high_entropy_string(candidate_string):
                    entropy = self.calculate_entropy(candidate_string)
                    
                    result = {
                        "type": "high_entropy_string",
                        "string": candidate_string,
                        "entropy": entropy,
                        "length": len(candidate_string),
                        "position": match.start(),
                        "js_file": js_url,
                        "context": content[max(0, match.start()-50):match.end()+50]
                    }
                    
                    high_entropy_results.append(result)
                    
        return high_entropy_results
    
    def extract_sensitive_info_advanced(self, content: str, js_url: str) -> List[Dict[str, str]]:
        """高级敏感信息提取"""
        sensitive_info = []
        
        for info_type, pattern in self.sensitive_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                info = {
                    "type": info_type,
                    "pattern": pattern,
                    "match": match.group(0)[:100],  # 限制长度
                    "position": match.start(),
                    "js_file": js_url
                }
                sensitive_info.append(info)
                
        return sensitive_info
    
    async def run_advanced_js_mining(self):
        """运行高级JavaScript挖掘"""
        print("🧠 高级JavaScript深度挖掘引擎启动")
        print("=" * 60)
        print(f"🎯 目标: {self.target}")
        print("🚀 新增功能: 熵值检测 + 完整正则库")
        
        # 显示反WAF配置
        self.anti_waf.print_stealth_stats()
        print("=" * 60)
        
        start_time = time.time()
        
        # Phase 1: 收集JS文件（使用反WAF技术）
        await self._phase1_stealth_js_collection()
        
        # Phase 2: 高级内容分析
        await self._phase2_advanced_analysis()
        
        # Phase 3: 端点验证
        await self._phase3_stealth_endpoint_validation()
        
        duration = time.time() - start_time
        self._generate_advanced_report(duration)
        
    async def _phase1_stealth_js_collection(self):
        """Phase 1: 隐蔽JS文件收集"""
        print("\n🕵️ Phase 1: 隐蔽JS文件收集")
        print("-" * 50)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # 设置随机User-Agent
            user_agent = self.anti_waf.get_random_user_agent()
            await page.set_extra_http_headers({"User-Agent": user_agent})
            
            js_files = set()
            
            async def handle_response(response):
                url = response.url
                content_type = response.headers.get('content-type', '')
                
                if (url.endswith('.js') or 
                    'javascript' in content_type):
                    js_files.add(url)
                    print(f"   📄 发现JS文件: {url}")
                    
            page.on('response', handle_response)
            
            try:
                await page.goto(self.target, wait_until='networkidle', timeout=30000)
                await page.wait_for_timeout(5000)
            except Exception as e:
                print(f"   ⚠️ 浏览器访问错误: {e}")
                
            await browser.close()
            
        self.discovered_js_files.update(js_files)
        print(f"   ✅ 总共发现 {len(self.discovered_js_files)} 个JS文件")
        
    async def _phase2_advanced_analysis(self):
        """Phase 2: 高级内容分析"""
        print("\n🧠 Phase 2: 高级内容分析 (熵值检测)")
        print("-" * 50)
        
        async with StealthHTTPClient() as client:
            for js_url in list(self.discovered_js_files)[:30]:  # 限制分析数量
                await self._analyze_js_file_advanced(client, js_url)
                
    async def _analyze_js_file_advanced(self, client: StealthHTTPClient, js_url: str):
        """高级JS文件分析"""
        try:
            print(f"🔬 高级分析: {js_url}")
            
            async with await client.get(js_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # 代码美化
                    if len(content) > 1000 and '\n' not in content[:1000]:
                        try:
                            content = jsbeautifier.beautify(content)
                        except:
                            pass
                    
                    # 1. 基础端点提取
                    endpoints = self._extract_endpoints(content, js_url)
                    
                    # 2. 高级敏感信息提取
                    sensitive_info = self.extract_sensitive_info_advanced(content, js_url)
                    
                    # 3. 熵值检测 (新功能!)
                    high_entropy_strings = self.extract_high_entropy_strings(content, js_url)
                    
                    result = {
                        "js_file": js_url,
                        "size": len(content),
                        "endpoints_found": len(endpoints),
                        "sensitive_info_found": len(sensitive_info),
                        "high_entropy_strings_found": len(high_entropy_strings),
                        "endpoints": list(endpoints)[:10],
                        "sensitive_info": sensitive_info,
                        "high_entropy_strings": high_entropy_strings,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.results.append(result)
                    self.extracted_endpoints.update(endpoints)
                    self.high_entropy_strings.extend(high_entropy_strings)
                    
                    if sensitive_info or high_entropy_strings:
                        print(f"   🎯 敏感信息: {len(sensitive_info)}, 高熵字符串: {len(high_entropy_strings)}")
                    
        except Exception as e:
            print(f"   ❌ 分析失败: {e}")
            
    def _extract_endpoints(self, content: str, js_url: str) -> Set[str]:
        """提取API端点（与基础版本相同）"""
        endpoints = set()
        
        for pattern in self.api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match.strip('\'"/')
                if len(endpoint) > 2 and not endpoint.startswith('http'):
                    if endpoint.startswith('/'):
                        full_url = f"{self.target}{endpoint}"
                    else:
                        full_url = f"{self.target}/{endpoint}"
                    endpoints.add(full_url)
                    
        return endpoints
        
    async def _phase3_stealth_endpoint_validation(self):
        """Phase 3: 隐蔽端点验证"""
        print("\n✅ Phase 3: 隐蔽端点验证")
        print("-" * 50)
        
        if not self.extracted_endpoints:
            print("   📋 没有发现端点需要验证")
            return
            
        async with StealthHTTPClient() as client:
            tasks = []
            for endpoint in list(self.extracted_endpoints)[:20]:  # 限制验证数量
                tasks.append(self._validate_endpoint_stealth(client, endpoint))
                
            await asyncio.gather(*tasks, return_exceptions=True)
            
    async def _validate_endpoint_stealth(self, client: StealthHTTPClient, endpoint: str):
        """隐蔽端点验证"""
        try:
            async with await client.get(endpoint, allow_redirects=False) as response:
                if response.status in [200, 201]:
                    print(f"   ✅ 可访问: {endpoint} ({response.status})")
                elif response.status in [401, 403]:
                    print(f"   🔐 受保护: {endpoint} ({response.status})")
                    
        except Exception as e:
            pass
            
    def _generate_advanced_report(self, duration: float):
        """生成高级挖掘报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"advanced_js_mining_{timestamp}.json"
        
        # 统计信息
        total_js_files = len(self.discovered_js_files)
        total_endpoints = len(self.extracted_endpoints)
        total_sensitive = sum(len(r.get("sensitive_info", [])) for r in self.results)
        total_high_entropy = len(self.high_entropy_strings)
        
        # 高熵字符串分析
        entropy_analysis = {
            "count": total_high_entropy,
            "avg_entropy": sum(s["entropy"] for s in self.high_entropy_strings) / max(1, total_high_entropy),
            "avg_length": sum(s["length"] for s in self.high_entropy_strings) / max(1, total_high_entropy)
        }
        
        report = {
            "scan_info": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "duration": duration,
                "engine_version": "Advanced v2.0",
                "anti_waf_enabled": True,
                "js_files_analyzed": total_js_files,
                "endpoints_extracted": total_endpoints,
                "sensitive_info_found": total_sensitive,
                "high_entropy_strings_found": total_high_entropy
            },
            "entropy_analysis": entropy_analysis,
            "discovered_js_files": list(self.discovered_js_files),
            "extracted_endpoints": list(self.extracted_endpoints),
            "high_entropy_strings": self.high_entropy_strings,
            "analysis_results": self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        print(f"\n🧠 高级JavaScript挖掘完成!")
        print(f"📂 JS文件分析: {total_js_files}")
        print(f"🔌 端点发现: {total_endpoints}")
        print(f"🔐 敏感信息: {total_sensitive}")
        print(f"🎯 高熵字符串: {total_high_entropy}")
        if total_high_entropy > 0:
            print(f"📊 平均熵值: {entropy_analysis['avg_entropy']:.2f}")
        print(f"⏱️ 挖掘耗时: {duration:.2f}秒")
        print(f"📄 详细报告: {filename}")
        
        if total_high_entropy > 0:
            print(f"\n🔥 发现高熵字符串（可能的密钥）:")
            for s in self.high_entropy_strings[:5]:  # 显示前5个
                print(f"   🎯 熵值: {s['entropy']:.2f}, 长度: {s['length']}, 文件: {s['js_file']}")

async def main():
    import sys
    
    if len(sys.argv) != 2:
        print("使用方法: python js_mining_engine_advanced.py <target>")
        print("示例: python js_mining_engine_advanced.py https://asanoha-clinic.com")
        return
        
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
        
    engine = AdvancedJSMiningEngine(target)
    await engine.run_advanced_js_mining()

if __name__ == "__main__":
    asyncio.run(main()) 