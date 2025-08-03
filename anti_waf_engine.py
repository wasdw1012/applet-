#!/usr/bin/env python3
"""
反WAF引擎 (Anti-WAF Engine) - 专业版
专门绕过WAF、CDN、IPS等安全设备的检测
集成代理池技术，实现分布式IP对抗
示例域名请替换实际部署域名
"""

import asyncio
import aiohttp
import ssl
import random
import time
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass
from aiohttp_socks import ProxyConnector

@dataclass
class ProxyStats:
    """代理统计信息"""
    proxy: str
    success_count: int = 0
    failure_count: int = 0
    total_requests: int = 0
    avg_response_time: float = 0.0
    last_success_time: float = 0.0
    last_failure_time: float = 0.0
    quality_score: float = 1.0  # 质量评分 0-1
    
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.success_count / self.total_requests
    
    def update_success(self, response_time: float):
        self.success_count += 1
        self.total_requests += 1
        self.last_success_time = time.time()
        # 更新平均响应时间
        if self.avg_response_time == 0:
            self.avg_response_time = response_time
        else:
            self.avg_response_time = (self.avg_response_time + response_time) / 2
        self._update_quality_score()
    
    def update_failure(self):
        self.failure_count += 1
        self.total_requests += 1
        self.last_failure_time = time.time()
        self._update_quality_score()
    
    def _update_quality_score(self):
        """更新质量评分"""
        if self.total_requests == 0:
            self.quality_score = 1.0
            return
            
        # 基础成功率权重60%
        success_rate = self.success_rate()
        base_score = success_rate * 0.6
        
        # 响应时间权重30% (响应时间越短得分越高)
        time_score = max(0, (3.0 - self.avg_response_time) / 3.0) * 0.3
        
        # 最近成功权重10%
        recent_success = 0.1 if time.time() - self.last_success_time < 300 else 0
        
        self.quality_score = min(1.0, base_score + time_score + recent_success)

class AntiWAFEngine:
    def __init__(self, proxy_file: str = "proxies.txt"):
        # 真实浏览器User-Agent池 (2024-2025最新版本)
        self.user_agents = [
            # Chrome 浏览器
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", 
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            
            # Firefox 浏览器
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
            
            # Safari 浏览器
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
            
            # Edge 浏览器
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
            
            # 移动端浏览器
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
        ]
        
        # 健壮性代理池管理
        self.proxy_file = proxy_file
        self.proxies = []
        self.proxy_pool = {}  # 代理质量池 {proxy: ProxyStats}
        self.active_proxies = []  # 当前可用代理
        self.frozen_proxies = {}  # 冷冻代理 {proxy: unfreeze_time}
        self.proxy_rotation_index = 0  # 轮换索引
        self.max_proxy_failures = 3  # 最大失败次数
        self.freeze_duration = 300  # 冷冻时长(秒)
        self.health_check_interval = 600  # 健康检查间隔(秒)
        
        # 加载代理列表
        self._load_proxies()
        
        # 常见的HTTP头池 (混淆用)
        self.common_headers = {
            "Accept": [
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "application/json,text/plain,*/*",
                "*/*"
            ],
            "Accept-Language": [
                "en-US,en;q=0.9",
                "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
                "zh-CN,zh;q=0.9,en;q=0.8",
                "en-GB,en-US;q=0.9,en;q=0.8",
                "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
            ],
            "Accept-Encoding": [
                "gzip, deflate, br, zstd",
                "gzip, deflate, br",
                "gzip, deflate",
                "identity"
            ],
            "Connection": [
                "keep-alive",
                "close"
            ],
            "Upgrade-Insecure-Requests": ["1"],
            "Sec-Fetch-Dest": ["document", "empty"],
            "Sec-Fetch-Mode": ["navigate", "cors"],
            "Sec-Fetch-Site": ["none", "same-origin", "cross-site"],
            "Cache-Control": ["no-cache", "max-age=0"],
            "Pragma": ["no-cache"]
        }
        
        # 可选的额外头部 (进一步混淆)
        self.optional_headers = {
            "X-Requested-With": ["XMLHttpRequest"],
            "X-Forwarded-Proto": ["https"],
            "DNT": ["1"],
            "Sec-GPC": ["1"]
        }
        
    def _load_proxies(self):
        """从文件加载代理列表"""
        if not os.path.exists(self.proxy_file):
            print(f"⚠️  代理文件 {self.proxy_file} 不存在，将使用直连模式")
            return
            
        try:
            with open(self.proxy_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 基础代理格式验证
                        if '://' in line:
                            self.proxies.append(line)
            
            print(f"📋 加载代理: {len(self.proxies)} 个")
            
        except Exception as e:
            print(f"❌ 代理文件加载失败: {e}")
    
    async def _robust_validate_proxy(self, proxy: str, timeout: int = 15) -> tuple[bool, float]:
        """修复版代理验证 - 正确处理HTTP和SOCKS代理"""
        start_time = time.time()
        
        # 优化测试URL，提高成功率
        test_urls = [
            "http://httpbin.org/ip",
            "http://ifconfig.me/ip", 
            "http://icanhazip.com",
            "http://ident.me"
        ]
        
        # === 修复：正确处理不同代理类型 ===
        is_socks_proxy = proxy.startswith(('socks5://', 'socks4://'))
        
        if is_socks_proxy:
            # SOCKS代理：使用ProxyConnector处理
            connector = ProxyConnector.from_url(proxy, ssl=False)
            use_proxy_param = False  # connector已处理代理
        else:
            # HTTP/HTTPS代理：使用普通connector + proxy参数
            connector = aiohttp.TCPConnector(ssl=False, limit=5)
            use_proxy_param = True   # 需要在请求中传入proxy参数
        # ==========================================
        
        last_error = None
        
        for i, test_url in enumerate(test_urls):
            try:
                timeout_config = aiohttp.ClientTimeout(
                    total=timeout,
                    connect=8,  # 放宽连接超时
                    sock_read=timeout
                )
                
                # 创建session
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout_config
                ) as session:
                    # 🔧 修复：根据代理类型决定是否传入proxy参数
                    if use_proxy_param:
                        # HTTP代理：需要传入proxy参数
                        response = await session.get(test_url, proxy=proxy)
                    else:
                        # SOCKS代理：connector已处理，不需要proxy参数  
                        response = await session.get(test_url)
                    
                    async with response:
                        response_time = time.time() - start_time
                        
                        # 更宽松验证条件
                        if response.status in [200, 201, 301, 302] and response_time < 25.0:
                                # 简单验证响应内容
                                try:
                                    content = await response.text()
                                    # 更宽松的内容验证
                                    if len(content) > 3 or response.status in [301, 302]:  
                                        proxy_type = "SOCKS" if is_socks_proxy else "HTTP"
                                        print(f"✅ {proxy} ({proxy_type}) | {test_url} | {response_time:.2f}s")
                                        # 确保关闭connector，避免资源泄露
                                        await connector.close()
                                        return True, response_time
                                except:
                                    # 状态码正确就算成功（更宽松）
                                    proxy_type = "SOCKS" if is_socks_proxy else "HTTP"
                                    print(f"✅ {proxy} ({proxy_type}) | {test_url} | {response_time:.2f}s (内容解析失败但状态正确)")
                                    await connector.close()
                                    return True, response_time
                            
            except Exception as e:
                last_error = str(e)
                # 打印详细错误信息用于诊断
                if i == 0:  # 只在第一个URL失败时打印，避免刷屏
                    proxy_type = "SOCKS" if is_socks_proxy else "HTTP"
                    print(f"❌ {proxy} ({proxy_type}) | {test_url} | 错误: {str(e)[:50]}...")
                continue
        
        # 确保关闭connector
        if connector:
            await connector.close()
            
        # 所有URL都失败，记录最后一个错误
        proxy_type = "SOCKS" if is_socks_proxy else "HTTP"
        print(f"❌ {proxy} ({proxy_type}) | 全部失败 | 最后错误: {last_error[:50] if last_error else 'Unknown'}...")
        return False, time.time() - start_time
    
    def _unfreeze_expired_proxies(self):
        """解冻过期的代理"""
        current_time = time.time()
        expired_proxies = []
        
        for proxy, unfreeze_time in self.frozen_proxies.items():
            if current_time >= unfreeze_time:
                expired_proxies.append(proxy)
        
        for proxy in expired_proxies:
            del self.frozen_proxies[proxy]
            if proxy in self.proxies and proxy not in self.active_proxies:
                self.active_proxies.append(proxy)
                print(f"🔄 代理解冻: {proxy}")
    
    def _freeze_proxy(self, proxy: str):
        """冷冻代理"""
        if proxy in self.active_proxies:
            self.active_proxies.remove(proxy)
        
        freeze_until = time.time() + self.freeze_duration
        self.frozen_proxies[proxy] = freeze_until
        print(f"❄️  代理冷冻: {proxy} (解冻时间: {self.freeze_duration}s后)")
    
    async def validate_proxies(self, max_concurrent: int = 15) -> int:
        """健壮性并发代理验证 - 降低并发减少网络拥堵"""
        if not self.proxies:
            print("⚠️  无代理可验证")
            return 0
            
        print(f"🔍 健壮性代理验证启动: {len(self.proxies)} 个代理")
        print(f"🚀 并发验证: {max_concurrent} 个同时检测 (优化网络稳定性)")
        print(f"⏱️  每个代理超时: 15秒，最多尝试6个测试URL")
        print("📊 详细验证日志:")
        
        # 清理冻结过期的代理
        self._unfreeze_expired_proxies()
        
        semaphore = asyncio.Semaphore(max_concurrent)
        validation_results = []
        
        async def validate_with_timing(proxy):
            async with semaphore:
                start_time = time.time()
                is_valid, response_time = await self._robust_validate_proxy(proxy)
                
                if proxy not in self.proxy_pool:
                    self.proxy_pool[proxy] = ProxyStats(proxy=proxy)
                
                if is_valid:
                    self.proxy_pool[proxy].update_success(response_time)
                    if proxy not in self.active_proxies:
                        self.active_proxies.append(proxy)
                    print(f"✅ {proxy} | {response_time:.2f}s | 质量:{self.proxy_pool[proxy].quality_score:.2f}")
                else:
                    self.proxy_pool[proxy].update_failure()
                    if proxy in self.active_proxies:
                        self.active_proxies.remove(proxy)
                
                return is_valid, response_time
        
        # 并发验证所有代理
        tasks = [validate_with_timing(proxy) for proxy in self.proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 统计结果
        valid_results = [r for r in results if isinstance(r, tuple) and r[0]]
        
        # 按质量评分排序
        self.active_proxies.sort(key=lambda p: self.proxy_pool[p].quality_score, reverse=True)
        
        print(f"\n📊 验证完成: {len(valid_results)}/{len(self.proxies)} 可用")
        
        # 详细统计分析
        if len(valid_results) > 0:
            avg_response_time = sum(r[1] for r in valid_results) / len(valid_results)
            best_proxy = self.active_proxies[0] if self.active_proxies else None
            print(f"📈 平均响应时间: {avg_response_time:.2f}s")
            if best_proxy:
                best_stats = self.proxy_pool[best_proxy]
                print(f"🏆 最佳代理: {best_proxy} (质量:{best_stats.quality_score:.2f})")
        else:
            print("⚠️  代理验证全部失败！可能原因:")
            print("   1. 网络环境限制 (防火墙/ISP阻断)")
            print("   2. 代理质量问题 (失效/过载)")
            print("   3. 目标测试URL被屏蔽")
            print("   4. 本地网络配置问题")
        
        return len(valid_results)
    
    async def initialize_proxy_pool(self):
        """初始化代理池 - 快速修复版本"""
        print("🚀 初始化代理池...")
        
        if not self.proxies:
            print("⚠️  没有代理配置，使用直连模式")
            return
        
        # 快速验证代理
        await self.validate_proxies()
        
        print(f"✅ 代理池初始化完成: {len(self.active_proxies)} 个可用代理")
    
    async def quick_diagnostic(self) -> Dict[str, Any]:
        """快速诊断网络和代理环境"""
        print("\n🔬 执行快速诊断...")
        diagnostic = {
            'direct_connection': False,
            'dns_resolution': False,
            'test_urls_accessible': [],
            'proxy_protocols': {'http': 0, 'socks5': 0},
            'geographic_distribution': {}
        }
        
        # 测试直连
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout_config = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout_config) as session:
                async with session.get("http://httpbin.org/ip") as response:
                    if response.status == 200:
                        diagnostic['direct_connection'] = True
                        print("✅ 直连测试: 成功")
        except Exception as e:
            print(f"❌ 直连测试: 失败 - {str(e)[:50]}...")
        
        # 统计代理类型
        for proxy in self.proxies:
            if proxy.startswith('http://'):
                diagnostic['proxy_protocols']['http'] += 1
            elif proxy.startswith('socks5://'):
                diagnostic['proxy_protocols']['socks5'] += 1
        
        print(f"📊 代理统计: HTTP {diagnostic['proxy_protocols']['http']} 个, SOCKS5 {diagnostic['proxy_protocols']['socks5']} 个")
        
        return diagnostic
    
    def get_smart_proxy(self) -> Optional[str]:
        """智能代理选择 - 基于质量评分的轮换"""
        self._unfreeze_expired_proxies()
        
        if not self.active_proxies:
            return None
        
        # 80%概率选择高质量代理，20%概率随机选择
        if random.random() < 0.8 and len(self.active_proxies) > 1:
            # 按质量评分权重选择
            top_proxies = self.active_proxies[:min(5, len(self.active_proxies))]
            weights = [self.proxy_pool[p].quality_score for p in top_proxies]
            return random.choices(top_proxies, weights=weights)[0]
        else:
            # 简单轮换选择
            proxy = self.active_proxies[self.proxy_rotation_index % len(self.active_proxies)]
            self.proxy_rotation_index += 1
            return proxy
    
    def get_random_proxy(self) -> Optional[str]:
        """获取代理 - 兼容性方法"""
        return self.get_smart_proxy()
    
    def mark_proxy_failed(self, proxy: str):
        """智能失败处理 - 记录失败并评估是否冷冻"""
        if not proxy or proxy not in self.proxy_pool:
            return
        
        self.proxy_pool[proxy].update_failure()
        stats = self.proxy_pool[proxy]
        
        # 失败条件判断
        should_freeze = False
        
        # 条件1: 连续失败次数过多
        if stats.failure_count >= self.max_proxy_failures:
            should_freeze = True
        
        # 条件2: 成功率过低且有足够样本
        elif stats.total_requests >= 10 and stats.success_rate() < 0.3:
            should_freeze = True
        
        # 条件3: 质量评分过低
        elif stats.quality_score < 0.2:
            should_freeze = True
        
        if should_freeze:
            self._freeze_proxy(proxy)
            print(f"📉 代理质量下降: {proxy} | 成功率:{stats.success_rate():.1%} | 质量:{stats.quality_score:.2f}")
        else:
            print(f"⚠️  代理失败: {proxy} | 失败次数:{stats.failure_count} | 成功率:{stats.success_rate():.1%}")
    
    def mark_proxy_success(self, proxy: str, response_time: float):
        """记录代理成功"""
        if proxy and proxy in self.proxy_pool:
            self.proxy_pool[proxy].update_success(response_time)
    
    def get_proxy_stats(self) -> Dict[str, int]:
        """获取健壮性代理统计信息"""
        high_quality_proxies = [p for p in self.active_proxies if self.proxy_pool.get(p, ProxyStats(p)).quality_score > 0.7]
        
        return {
            'total_proxies': len(self.proxies),
            'active_proxies': len(self.active_proxies),
            'frozen_proxies': len(self.frozen_proxies),
            'high_quality_proxies': len(high_quality_proxies),
            'total_requests': sum(stats.total_requests for stats in self.proxy_pool.values()),
            'total_successes': sum(stats.success_count for stats in self.proxy_pool.values())
        }
    
    def get_detailed_proxy_stats(self) -> List[Dict]:
        """获取详细代理统计"""
        stats_list = []
        for proxy in self.active_proxies:
            if proxy in self.proxy_pool:
                stats = self.proxy_pool[proxy]
                stats_list.append({
                    'proxy': proxy,
                    'success_rate': stats.success_rate(),
                    'quality_score': stats.quality_score,
                    'avg_response_time': stats.avg_response_time,
                    'total_requests': stats.total_requests
                })
        
        return sorted(stats_list, key=lambda x: x['quality_score'], reverse=True)

    def get_random_user_agent(self) -> str:
        """获取随机User-Agent"""
        return random.choice(self.user_agents)
        
    def get_random_headers(self, include_optional: bool = True) -> Dict[str, str]:
        """生成随机HTTP头部"""
        headers = {}
        
        # 必需的头部
        headers["User-Agent"] = self.get_random_user_agent()
        
        for header_name, values in self.common_headers.items():
            if random.random() > 0.1:  # 90%概率包含
                headers[header_name] = random.choice(values)
        
        # 可选的头部 (30%概率包含)
        if include_optional and random.random() > 0.7:
            for header_name, values in self.optional_headers.items():
                if random.random() > 0.5:  # 50%概率包含
                    headers[header_name] = random.choice(values)
                    
        return headers
        
    async def random_delay(self, min_delay: float = 0.3, max_delay: float = 1.2):
        """随机延迟 - 模拟人类访问行为 (猥琐部署：增大延迟范围)"""
        delay = random.uniform(min_delay, max_delay)
        await asyncio.sleep(delay)
        
    def create_stealth_session(self, timeout: int = 30) -> aiohttp.ClientSession:
        """创建隐蔽的HTTP会话"""
        connector = aiohttp.TCPConnector(
            ssl=ssl.create_default_context(),
            limit=10,  # 限制并发连接数
            limit_per_host=3,  # 限制每个主机的连接数
            ttl_dns_cache=300,  # DNS缓存TTL
            use_dns_cache=True
        )
        
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        
        # 随机选择一个基础头部作为默认
        default_headers = self.get_random_headers(include_optional=False)
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers=default_headers
        )
        
    async def stealth_request(self, 
                            session: aiohttp.ClientSession,
                            method: str,
                            url: str,
                            use_proxy: bool = True,
                            **kwargs) -> aiohttp.ClientResponse:
        """执行隐蔽的HTTP请求 - 集成代理轮换"""
        
        # 随机延迟
        await self.random_delay()
        
        # 为每个请求生成新的头部
        request_headers = self.get_random_headers()
        
        # 合并用户提供的头部
        if "headers" in kwargs:
            request_headers.update(kwargs["headers"])
            
        kwargs["headers"] = request_headers
        
        # 添加随机行为模式
        if random.random() > 0.8:  # 20%概率添加Referer
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"]["Referer"] = self._generate_fake_referer(url)
        
        # 健壮性代理轮换 - 智能选择
        proxy = None
        if use_proxy and self.active_proxies:
            proxy = self.get_smart_proxy()
            if proxy:
                kwargs["proxy"] = proxy
        
        # 执行请求，带健壮性失败处理
        max_retries = 3
        for attempt in range(max_retries):
            try:
                request_start_time = time.time()
                response = await session.request(method, url, **kwargs)
                response_time = time.time() - request_start_time
                
                # 记录成功
                if proxy:
                    self.mark_proxy_success(proxy, response_time)
                
                return response
                
            except Exception as e:
                # 如果使用了代理且请求失败，标记代理失败
                if proxy:
                    self.mark_proxy_failed(proxy)
                    
                    # 健壮性重试策略
                    if attempt < max_retries - 1:  # 不是最后一次尝试
                        # 尝试用新的高质量代理重试
                        new_proxy = self.get_smart_proxy()
                        if new_proxy and new_proxy != proxy:
                            kwargs["proxy"] = new_proxy
                            proxy = new_proxy
                            continue
                        
                        # 如果没有其他代理，尝试直连
                        if "proxy" in kwargs:
                            del kwargs["proxy"]
                            proxy = None
                            continue
                
                # 最后一次尝试失败，重新抛出异常
                if attempt == max_retries - 1:
                    raise e
        
    def print_stealth_stats(self):
        """打印健壮性反WAF引擎统计"""
        print("🕵️ 反WAF引擎 专业版 配置:")
        print(f"   📱 User-Agent池: {len(self.user_agents)} 个")
        print(f"   🔀 请求头变化: {len(self.common_headers)} 类")
        print(f"   ⏱️ 随机延迟: 0.1-0.5秒")
        print(f"   🎭 混淆技术: 启用")
        
        # 健壮性代理池统计
        proxy_stats = self.get_proxy_stats()
        if proxy_stats['total_proxies'] > 0:
            print(f"   🌐 健壮性代理池:")
            print(f"      总代理数: {proxy_stats['total_proxies']} 个")
            print(f"      活跃代理: {proxy_stats['active_proxies']} 个")
            print(f"      冷冻代理: {proxy_stats['frozen_proxies']} 个")
            print(f"      高质量代理: {proxy_stats['high_quality_proxies']} 个")
            
            if proxy_stats['total_requests'] > 0:
                success_rate = proxy_stats['total_successes'] / proxy_stats['total_requests']
                print(f"      总体成功率: {success_rate:.1%}")
                print(f"      总请求数: {proxy_stats['total_requests']}")
                
            # 显示前3个最佳代理
            top_proxies = self.get_detailed_proxy_stats()[:3]
            if top_proxies:
                print(f"      🏆 最佳代理:")
                for i, proxy_info in enumerate(top_proxies, 1):
                    print(f"         {i}. 质量:{proxy_info['quality_score']:.2f} | "
                          f"成功率:{proxy_info['success_rate']:.1%} | "
                          f"响应:{proxy_info['avg_response_time']:.1f}s")
        else:
            print(f"   🌐 代理模式: 直连 (未配置代理池)")

# 便捷包装类 - 直接替换现有HTTP请求
class StealthHTTPClient:
    def __init__(self, proxy_file: str = "proxies.txt", validate_proxies: bool = False):
        self.anti_waf = AntiWAFEngine(proxy_file)
        self.session = None
        self.validate_proxies = validate_proxies
        
    async def __aenter__(self):
        # 如果需要，验证代理池
        if self.validate_proxies and self.anti_waf.proxies:
            await self.anti_waf.validate_proxies()
            
        self.session = self.anti_waf.create_stealth_session()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """隐蔽GET请求"""
        return await self.anti_waf.stealth_request(self.session, "GET", url, **kwargs)
        
    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """隐蔽POST请求"""
        return await self.anti_waf.stealth_request(self.session, "POST", url, **kwargs)
        
    async def put(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """隐蔽PUT请求"""
        return await self.anti_waf.stealth_request(self.session, "PUT", url, **kwargs)
        
    async def delete(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """隐蔽DELETE请求"""
        return await self.anti_waf.stealth_request(self.session, "DELETE", url, **kwargs)
    
    def get_headers(self) -> Dict[str, str]:
        """获取随机头部（兼容现有代码）"""
        return self.anti_waf.get_random_headers()
    
    def get_proxy_stats(self) -> Dict[str, int]:
        """获取代理统计信息"""
        return self.anti_waf.get_proxy_stats()
    
    async def validate_proxies(self) -> int:
        """手动验证代理池"""
        return await self.anti_waf.validate_proxies()
    
    def print_stats(self):
        """打印引擎统计信息"""
        self.anti_waf.print_stealth_stats()

# 测试函数
async def test_anti_waf():
    """测试反WAF引擎 - 包含代理池测试"""
    print("🔍 反WAF引擎 专业版 测试")
    print("=" * 60)
    
    # 测试基础功能
    anti_waf = AntiWAFEngine()
    anti_waf.print_stealth_stats()
    
    print("\n🧪 测试User-Agent轮换:")
    for i in range(3):
        ua = anti_waf.get_random_user_agent()
        print(f"   {i+1}. {ua[:60]}...")
        
    print("\n🧪 测试随机头部生成:")
    for i in range(2):
        headers = anti_waf.get_random_headers()
        print(f"   {i+1}. 头部数量: {len(headers)}")
        print(f"      User-Agent: {headers.get('User-Agent', 'N/A')[:50]}...")
    
    # 测试代理池功能  
    if anti_waf.proxies:
        print("\n🌐 测试代理池功能:")
        print(f"   加载代理: {len(anti_waf.proxies)} 个")
        
        # 运行快速诊断
        await anti_waf.quick_diagnostic()
        
        # 验证代理（降低并发数以减少网络压力）
        if len(anti_waf.proxies) > 0:
            print("\n   开始验证代理...")
            valid_count = await anti_waf.validate_proxies(max_concurrent=10)
            
            if valid_count > 0:
                print(f"\n   ✅ 发现 {valid_count} 个可用代理")
                
                # 显示详细代理统计
                detailed_stats = anti_waf.get_detailed_proxy_stats()
                if detailed_stats:
                    print(f"   📋 代理质量报告:")
                    for i, stats in enumerate(detailed_stats[:5], 1):  # 显示前5个
                        print(f"      {i}. {stats['proxy']} | 质量:{stats['quality_score']:.2f} | 响应:{stats['avg_response_time']:.1f}s")
                
                # 测试代理轮换
                print("\n🔄 测试代理轮换:")
                for i in range(3):
                    proxy = anti_waf.get_smart_proxy()
                    if proxy:
                        print(f"   {i+1}. {proxy}")
                    else:
                        print(f"   {i+1}. 无可用代理")
            else:
                print("\n   ⚠️  没有发现可用代理")
                print("   💡 建议:")
                print("      1. 检查网络连接和防火墙设置")
                print("      2. 尝试更换代理源")
                print("      3. 降低并发数重试")
    else:
        print("\n🌐 代理池: 未配置，使用直连模式")
    
    print("\n✅ 反WAF引擎测试完成")

# 简化的代理池测试
async def test_proxy_pool():
    """专门测试代理池功能"""
    print("🌐 代理池专项测试")
    print("=" * 40)
    
    async with StealthHTTPClient(validate_proxies=True) as client:
        client.print_stats()
        
        # 尝试发起一个测试请求
        try:
            print("\n🔍 测试代理请求...")
            async with await client.get("http://httpbin.org/ip") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ 请求成功，IP: {data.get('origin', 'Unknown')}")
                else:
                    print(f"⚠️  请求返回状态码: {response.status}")
        except Exception as e:
            print(f"❌ 请求失败: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "proxy":
        asyncio.run(test_proxy_pool())
    else:
        asyncio.run(test_anti_waf()) 