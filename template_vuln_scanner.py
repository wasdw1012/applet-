import asyncio
import aiohttp
import yaml
import json
import re
import time
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor
import ssl
from anti_waf_engine import AntiWAFEngine, StealthHTTPClient

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TemplateInfo:
    """模板信息结构"""
    id: str
    name: str
    author: str
    severity: str
    description: str
    reference: List[str] = field(default_factory=list)
    classification: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class HTTPRequest:
    """HTTP请求配置"""
    method: str = 'GET'
    path: str = '/'
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ''
    follow_redirects: bool = False
    max_redirects: int = 3
    timeout: int = 10
    raw: Optional[str] = None

@dataclass
class Matcher:
    """匹配器配置"""
    # 响应状态码匹配
    status: Optional[List[int]] = None
    
    # 响应体内容匹配
    words: Optional[List[str]] = None
    regex: Optional[List[str]] = None
    
    # 响应头匹配
    headers: Optional[Dict[str, str]] = None
    
    # 二进制匹配
    binary: Optional[List[str]] = None
    
    # 响应大小匹配
    size: Optional[List[int]] = None
    
    # 响应时间匹配 (毫秒)
    duration: Optional[List[int]] = None
    
    # DSL表达式匹配
    dsl: Optional[List[str]] = None
    
    # 条件逻辑
    condition: str = 'and'  # and, or
    
    # 匹配类型
    type: str = 'word'  # word, regex, status, size, duration, dsl
    
    # 编码方式
    encoding: str = 'utf-8'
    
    # 大小写敏感
    case_insensitive: bool = True

@dataclass
class VulnerabilityTemplate:
    """完整的漏洞模板"""
    id: str
    info: TemplateInfo
    requests: List[HTTPRequest]
    matchers: List[Matcher]
    
    # 高级功能
    variables: Dict[str, str] = field(default_factory=dict)
    payloads: Dict[str, List[str]] = field(default_factory=dict)
    extractors: List[Dict] = field(default_factory=list)
    
    # 执行控制
    max_request_per_second: int = 100
    batch_size: int = 10
    stop_at_first_match: bool = True

@dataclass
class ScanResult:
    """扫描结果"""
    template_id: str
    template_name: str
    target_url: str
    vulnerability_found: bool
    severity: str
    matched_data: Dict[str, Any]
    request_data: Dict[str, Any]
    response_data: Dict[str, Any]
    execution_time: float
    timestamp: str

@dataclass
class ScannerConfig:
    """扫描器配置"""
    # 并发控制
    max_concurrent_requests: int = 500
    max_concurrent_templates: int = 100
    rate_limit: int = 1000  # 每秒请求数
    
    # 超时配置
    default_timeout: int = 10
    max_timeout: int = 30
    
    # 重试配置
    max_retries: int = 3
    retry_delay: float = 1.0
    
    # HTTP配置
    follow_redirects: bool = False
    max_redirects: int = 5
    verify_ssl: bool = False
    
    # 输出配置
    verbose: bool = True
    silent: bool = False
    
    # 过滤配置
    severity_filter: List[str] = field(default_factory=lambda: ['low', 'medium', 'high', 'critical'])
    exclude_tags: List[str] = field(default_factory=list)
    include_tags: List[str] = field(default_factory=list)

class TemplateParser:
    """
    模板解析器 - 负责解析YAML模板文件
    """
    
    def __init__(self):
        self.templates: Dict[str, VulnerabilityTemplate] = {}
        self.template_paths: List[Path] = []
    
    def load_template_from_file(self, file_path: Path) -> Optional[VulnerabilityTemplate]:
        """从文件加载单个模板"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                template_data = yaml.safe_load(f)
            
            return self._parse_template_data(template_data, str(file_path))
        except Exception as e:
            logger.error(f"加载模板文件失败 {file_path}: {e}")
            return None
    
    def load_templates_from_directory(self, directory: Path) -> int:
        """从目录加载所有模板"""
        loaded_count = 0
        
        for template_file in directory.glob('**/*.yaml'):
            template = self.load_template_from_file(template_file)
            if template:
                self.templates[template.id] = template
                loaded_count += 1
                logger.info(f"加载模板: {template.info.name}")
        
        for template_file in directory.glob('**/*.yml'):
            template = self.load_template_from_file(template_file)
            if template:
                self.templates[template.id] = template
                loaded_count += 1
                logger.info(f"加载模板: {template.info.name}")
        
        return loaded_count
    
    def _parse_template_data(self, data: Dict, source: str) -> VulnerabilityTemplate:
        """解析模板数据结构"""
        # 解析模板信息
        info_data = data.get('info', {})
        template_info = TemplateInfo(
            id=data.get('id', ''),
            name=info_data.get('name', ''),
            author=info_data.get('author', ''),
            severity=info_data.get('severity', 'medium'),
            description=info_data.get('description', ''),
            reference=info_data.get('reference', []),
            classification=info_data.get('classification', {}),
            metadata=info_data.get('metadata', {})
        )
        
        # 解析HTTP请求
        requests_data = data.get('requests', data.get('http', []))
        if isinstance(requests_data, dict):
            requests_data = [requests_data]
        
        http_requests = []
        for req_data in requests_data:
            http_request = HTTPRequest(
                method=req_data.get('method', 'GET').upper(),
                path=req_data.get('path', '/'),
                headers=req_data.get('headers', {}),
                body=req_data.get('body', ''),
                follow_redirects=req_data.get('follow_redirects', False),
                max_redirects=req_data.get('max_redirects', 3),
                timeout=req_data.get('timeout', 10),
                raw=req_data.get('raw')
            )
            http_requests.append(http_request)
        
        # 解析匹配器
        matchers_data = data.get('matchers', [])
        if isinstance(matchers_data, dict):
            matchers_data = [matchers_data]
        
        matchers = []
        for matcher_data in matchers_data:
            matcher = Matcher(
                status=matcher_data.get('status'),
                words=matcher_data.get('words'),
                regex=matcher_data.get('regex'),
                headers=matcher_data.get('headers'),
                binary=matcher_data.get('binary'),
                size=matcher_data.get('size'),
                duration=matcher_data.get('duration'),
                dsl=matcher_data.get('dsl'),
                condition=matcher_data.get('condition', 'and'),
                type=matcher_data.get('type', 'word'),
                encoding=matcher_data.get('encoding', 'utf-8'),
                case_insensitive=matcher_data.get('case_insensitive', True)
            )
            matchers.append(matcher)
        
        # 创建完整模板
        template = VulnerabilityTemplate(
            id=data.get('id', hashlib.md5(source.encode()).hexdigest()[:8]),
            info=template_info,
            requests=http_requests,
            matchers=matchers,
            variables=data.get('variables', {}),
            payloads=data.get('payloads', {}),
            extractors=data.get('extractors', []),
            max_request_per_second=data.get('max_request_per_second', 100),
            batch_size=data.get('batch_size', 10),
            stop_at_first_match=data.get('stop_at_first_match', True)
        )
        
        return template
    
    def get_templates_by_severity(self, severity: str) -> List[VulnerabilityTemplate]:
        """根据严重程度获取模板"""
        return [t for t in self.templates.values() if t.info.severity == severity]
    
    def get_templates_by_tag(self, tag: str) -> List[VulnerabilityTemplate]:
        """根据标签获取模板"""
        return [t for t in self.templates.values() 
                if tag in t.info.classification.get('tags', [])]

class HTTPExecutor:
    """
    高性能HTTP执行器 - 负责执行HTTP请求 (反WAF增强版)
    """
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        
        # 反WAF引擎初始化
        self.anti_waf = AntiWAFEngine()
        
        # SSL配置
        self.ssl_context = ssl.create_default_context()
        if not config.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def __aenter__(self):
        """异步上下文管理器入口 - 反WAF增强版"""
        # 使用反WAF引擎创建隐蔽会话
        self.session = self.anti_waf.create_stealth_session(timeout=self.config.default_timeout)
        
        # 如果需要自定义SSL设置，更新connector
        if not self.config.verify_ssl:
            await self.session.close()  # 关闭默认session
            
            connector = aiohttp.TCPConnector(
                limit=self.config.max_concurrent_requests,
                ssl=self.ssl_context,
                ttl_dns_cache=300,
                use_dns_cache=True,
            )
            
            # 重新创建session，但保持反WAF的随机头部
            default_headers = self.anti_waf.get_random_headers(include_optional=False)
            timeout = aiohttp.ClientTimeout(total=self.config.default_timeout)
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=default_headers
            )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出"""
        if self.session:
            await self.session.close()
    
    async def execute_request(self, 
                            target_url: str, 
                            http_request: HTTPRequest,
                            variables: Dict[str, str] = None) -> Dict[str, Any]:
        """执行单个HTTP请求"""
        async with self.semaphore:
            try:
                # 变量替换
                if variables:
                    http_request = self._replace_variables(http_request, variables)
                
                # 构建完整URL
                full_url = urljoin(target_url, http_request.path)
                
                # 准备请求参数
                kwargs = {
                    'method': http_request.method,
                    'url': full_url,
                    'headers': http_request.headers,
                    'timeout': aiohttp.ClientTimeout(total=http_request.timeout),
                    'allow_redirects': http_request.follow_redirects,
                    'max_redirects': http_request.max_redirects if http_request.follow_redirects else 0,
                    'ssl': self.ssl_context
                }
                
                # 添加请求体
                if http_request.body:
                    kwargs['data'] = http_request.body
                elif http_request.raw:
                    kwargs['data'] = http_request.raw
                
                # 执行隐蔽请求 - 反WAF增强
                start_time = time.time()
                
                # 使用反WAF引擎执行隐蔽请求
                response = await self.anti_waf.stealth_request(
                    self.session,
                    kwargs['method'],
                    kwargs['url'],
                    headers=kwargs.get('headers'),
                    data=kwargs.get('data'),
                    timeout=kwargs.get('timeout'),
                    ssl=kwargs.get('ssl'),
                    allow_redirects=kwargs.get('allow_redirects'),
                    max_redirects=kwargs.get('max_redirects', 0)
                )
                
                async with response:
                    response_body = await response.read()
                    execution_time = time.time() - start_time
                    
                    # 构建响应数据
                    response_data = {
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'body': response_body,
                        'text': response_body.decode('utf-8', errors='ignore'),
                        'url': str(response.url),
                        'execution_time': execution_time,
                        'size': len(response_body)
                    }
                    
                    return response_data
            
            except asyncio.TimeoutError:
                return {'error': 'timeout', 'execution_time': http_request.timeout}
            except Exception as e:
                return {'error': str(e), 'execution_time': 0}
    
    def _replace_variables(self, http_request: HTTPRequest, variables: Dict[str, str]) -> HTTPRequest:
        """替换请求中的变量"""
        # 简单的变量替换实现
        path = http_request.path
        body = http_request.body
        headers = http_request.headers.copy()
        
        for var_name, var_value in variables.items():
            placeholder = f"{{{{{var_name}}}}}"
            path = path.replace(placeholder, var_value)
            body = body.replace(placeholder, var_value)
            
            # 替换头部中的变量
            for header_name, header_value in headers.items():
                headers[header_name] = header_value.replace(placeholder, var_value)
        
        return HTTPRequest(
            method=http_request.method,
            path=path,
            headers=headers,
            body=body,
            follow_redirects=http_request.follow_redirects,
            max_redirects=http_request.max_redirects,
            timeout=http_request.timeout,
            raw=http_request.raw
        )

class ResponseMatcher:
    """
    智能响应匹配器 - 负责根据模板规则匹配响应
    """
    
    def __init__(self):
        self.compiled_regex_cache: Dict[str, re.Pattern] = {}
    
    def match_response(self, response_data: Dict[str, Any], matchers: List[Matcher]) -> Tuple[bool, Dict[str, Any]]:
        """匹配响应数据"""
        if not matchers:
            return False, {}
        
        match_results = []
        matched_data = {}
        
        for matcher in matchers:
            match_result = self._match_single_matcher(response_data, matcher)
            match_results.append(match_result['matched'])
            
            if match_result['matched']:
                matched_data.update(match_result['data'])
        
        # 根据条件逻辑判断最终结果
        if len(matchers) == 1:
            final_result = match_results[0]
        else:
            # 不同类型的matcher之间必须使用AND逻辑
            # 这确保了状态码、关键词、正则等条件必须同时满足
            final_result = all(match_results)
        
        return final_result, matched_data
    
    def _match_single_matcher(self, response_data: Dict[str, Any], matcher: Matcher) -> Dict[str, Any]:
        """匹配单个匹配器"""
        result = {'matched': False, 'data': {}}
        
        # 检查是否有错误
        if 'error' in response_data:
            return result
        
        # 重定向响应预过滤：除非明确允许，否则重定向响应不应被视为漏洞
        status_code = response_data.get('status_code', 0)
        if status_code in [301, 302, 303, 307, 308]:
            # 如果matcher没有明确包含重定向状态码，直接返回不匹配
            if matcher.status is None or status_code not in matcher.status:
                result['data']['redirect_filtered'] = True
                return result
        
        # 状态码匹配
        if matcher.status is not None:
            status_match = response_data.get('status_code', 0) in matcher.status
            result['data']['status_match'] = status_match
            if not status_match:
                return result
        
        # 响应体文本匹配
        response_text = response_data.get('text', '')
        if not matcher.case_insensitive:
            response_text = response_text.lower()
        
        # 关键词匹配
        if matcher.words:
            word_matches = []
            for word in matcher.words:
                if not matcher.case_insensitive:
                    word = word.lower()
                match_found = word in response_text
                word_matches.append(match_found)
                if match_found:
                    result['data'][f'word_match_{word}'] = True
            
            if matcher.condition == 'or':
                word_result = any(word_matches)
            else:
                word_result = all(word_matches)
            
            if not word_result:
                return result
        
        # 正则表达式匹配
        if matcher.regex:
            regex_matches = []
            for regex_pattern in matcher.regex:
                try:
                    if regex_pattern not in self.compiled_regex_cache:
                        flags = re.IGNORECASE if matcher.case_insensitive else 0
                        self.compiled_regex_cache[regex_pattern] = re.compile(regex_pattern, flags)
                    
                    regex_obj = self.compiled_regex_cache[regex_pattern]
                    regex_match = regex_obj.search(response_text)
                    regex_matches.append(regex_match is not None)
                    
                    if regex_match:
                        result['data'][f'regex_match_{regex_pattern}'] = regex_match.group(0)
                        if regex_match.groups():
                            result['data'][f'regex_groups_{regex_pattern}'] = regex_match.groups()
                
                except re.error as e:
                    logger.warning(f"正则表达式错误 {regex_pattern}: {e}")
                    regex_matches.append(False)
            
            if regex_matches:
                if matcher.condition == 'or':
                    regex_result = any(regex_matches)
                else:
                    regex_result = all(regex_matches)
                
                if not regex_result:
                    return result
        
        # 响应头匹配
        if matcher.headers:
            response_headers = response_data.get('headers', {})
            header_matches = []
            
            for header_name, header_value in matcher.headers.items():
                actual_value = response_headers.get(header_name, '')
                if not matcher.case_insensitive:
                    actual_value = actual_value.lower()
                    header_value = header_value.lower()
                
                header_match = header_value in actual_value
                header_matches.append(header_match)
                
                if header_match:
                    result['data'][f'header_match_{header_name}'] = actual_value
            
            if header_matches:
                if matcher.condition == 'or':
                    header_result = any(header_matches)
                else:
                    header_result = all(header_matches)
                
                if not header_result:
                    return result
        
        # 响应大小匹配
        if matcher.size:
            response_size = response_data.get('size', 0)
            size_match = response_size in matcher.size
            result['data']['size_match'] = size_match
            if not size_match:
                return result
        
        # 响应时间匹配
        if matcher.duration:
            execution_time_ms = int(response_data.get('execution_time', 0) * 1000)
            duration_match = any(
                duration_min <= execution_time_ms <= duration_max 
                for duration_min, duration_max in [
                    (d, d + 100) if isinstance(d, int) else d 
                    for d in matcher.duration
                ]
            )
            result['data']['duration_match'] = duration_match
            if not duration_match:
                return result
        
        # DSL表达式匹配 (简化实现)
        if matcher.dsl:
            # 这里可以实现更复杂的DSL表达式计算
            # 暂时作为简单字符串匹配处理
            dsl_matches = []
            for dsl_expr in matcher.dsl:
                # 简单的DSL实现：支持 contains(), len(), status_code 等
                try:
                    dsl_result = self._evaluate_dsl(dsl_expr, response_data)
                    dsl_matches.append(dsl_result)
                except Exception as e:
                    logger.warning(f"DSL表达式错误 {dsl_expr}: {e}")
                    dsl_matches.append(False)
            
            if dsl_matches:
                if matcher.condition == 'or':
                    dsl_result = any(dsl_matches)
                else:
                    dsl_result = all(dsl_matches)
                
                if not dsl_result:
                    return result
        
        # 如果所有匹配都通过，标记为匹配成功
        result['matched'] = True
        return result
    
    def _evaluate_dsl(self, dsl_expr: str, response_data: Dict[str, Any]) -> bool:
        """评估DSL表达式 (简化实现)"""
        # 简单的DSL实现，支持基本表达式
        text = response_data.get('text', '')
        status_code = response_data.get('status_code', 0)
        size = response_data.get('size', 0)
        
        # 替换DSL变量
        dsl_expr = dsl_expr.replace('len(body)', str(size))
        dsl_expr = dsl_expr.replace('status_code', str(status_code))
        dsl_expr = dsl_expr.replace('contains(body,', f'"{text}".find(')
        
        try:
            # 简单的表达式计算 (安全起见，限制可用函数)
            allowed_names = {"len": len, "str": str, "int": int}
            result = eval(dsl_expr, {"__builtins__": {}}, allowed_names)
            return bool(result)
        except:
            return False

class TemplateVulnScanner:
    """
    模板化漏洞扫描引擎主类
    """
    
    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.template_parser = TemplateParser()
        self.response_matcher = ResponseMatcher()
        self.results: List[ScanResult] = []
        
        # 统计信息
        self.stats = {
            'templates_loaded': 0,
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'scan_duration': 0,
            'start_time': None
        }
    
    async def load_templates(self, template_paths: List[str]) -> int:
        """加载漏洞模板"""
        total_loaded = 0
        
        for path_str in template_paths:
            path = Path(path_str)
            if path.is_file():
                template = self.template_parser.load_template_from_file(path)
                if template:
                    self.template_parser.templates[template.id] = template
                    total_loaded += 1
            elif path.is_dir():
                loaded = self.template_parser.load_templates_from_directory(path)
                total_loaded += loaded
        
        self.stats['templates_loaded'] = total_loaded
        
        if not self.config.silent:
            print(f"  加载模板: {total_loaded} 个")
        
        return total_loaded
    
    async def scan_target(self, target_url: str, template_filter: Dict[str, Any] = None) -> List[ScanResult]:
        """扫描单个目标"""
        self.stats['start_time'] = time.time()
        
        if not self.config.silent:
            print(f"  开始扫描目标: {target_url}")
        
        # 获取要执行的模板
        templates_to_run = self._filter_templates(template_filter)
        
        if not templates_to_run:
            print("  没有找到匹配的模板")
            return []
        
        # 执行扫描
        async with HTTPExecutor(self.config) as executor:
            tasks = []
            semaphore = asyncio.Semaphore(self.config.max_concurrent_templates)
            
            for template in templates_to_run:
                task = self._scan_with_template(target_url, template, executor, semaphore)
                tasks.append(task)
            
            # 并发执行所有模板
            template_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 处理结果
            for result in template_results:
                if isinstance(result, Exception):
                    logger.error(f"模板执行错误: {result}")
                elif result:
                    self.results.append(result)
                    if result.vulnerability_found:
                        self.stats['vulnerabilities_found'] += 1
        
        self.stats['scan_duration'] = time.time() - self.stats['start_time']
        
        if not self.config.silent:
            print(f"  扫描完成: 发现 {self.stats['vulnerabilities_found']} 个漏洞")
        
        return self.results
    
    async def _scan_with_template(self, 
                                target_url: str, 
                                template: VulnerabilityTemplate,
                                executor: HTTPExecutor,
                                semaphore: asyncio.Semaphore) -> Optional[ScanResult]:
        """使用单个模板扫描目标"""
        async with semaphore:
            try:
                start_time = time.time()
                
                # 执行模板中的所有HTTP请求
                for http_request in template.requests:
                    response_data = await executor.execute_request(
                        target_url, 
                        http_request, 
                        template.variables
                    )
                    
                    self.stats['requests_sent'] += 1
                    
                    # 检查响应是否匹配漏洞特征
                    is_vulnerable, matched_data = self.response_matcher.match_response(
                        response_data, template.matchers
                    )
                    
                    if is_vulnerable:
                        # 创建扫描结果
                        result = ScanResult(
                            template_id=template.id,
                            template_name=template.info.name,
                            target_url=target_url,
                            vulnerability_found=True,
                            severity=template.info.severity,
                            matched_data=matched_data,
                            request_data={
                                'method': http_request.method,
                                'path': http_request.path,
                                'headers': http_request.headers,
                                'body': http_request.body
                            },
                            response_data=response_data,
                            execution_time=time.time() - start_time,
                            timestamp=datetime.now().isoformat()
                        )
                        
                        if not self.config.silent:
                            print(f"  发现漏洞: {template.info.name} [{template.info.severity.upper()}]")
                        
                        return result
                    
                    # 如果配置为找到第一个匹配就停止
                    if template.stop_at_first_match and is_vulnerable:
                        break
                
                return None
            
            except Exception as e:
                logger.error(f"模板执行错误 {template.id}: {e}")
                return None
    
    def _filter_templates(self, template_filter: Dict[str, Any] = None) -> List[VulnerabilityTemplate]:
        """根据过滤条件获取模板"""
        templates = list(self.template_parser.templates.values())
        
        if not template_filter:
            return templates
        
        # 根据严重程度过滤
        if 'severity' in template_filter:
            severity_filter = template_filter['severity']
            if isinstance(severity_filter, str):
                severity_filter = [severity_filter]
            templates = [t for t in templates if t.info.severity in severity_filter]
        
        # 根据标签过滤
        if 'tags' in template_filter:
            tags_filter = template_filter['tags']
            if isinstance(tags_filter, str):
                tags_filter = [tags_filter]
            templates = [t for t in templates 
                        if any(tag in t.info.classification.get('tags', []) for tag in tags_filter)]
        
        # 根据模板ID过滤
        if 'template_ids' in template_filter:
            template_ids = template_filter['template_ids']
            if isinstance(template_ids, str):
                template_ids = [template_ids]
            templates = [t for t in templates if t.id in template_ids]
        
        return templates
    
    def generate_report(self, output_format: str = 'json') -> str:
        """生成扫描报告"""
        report_data = {
            'scan_info': {
                'scanner': 'TemplateVulnScanner',
                'version': '1.0',
                'timestamp': datetime.now().isoformat(),
                'duration': self.stats['scan_duration'],
                'templates_used': self.stats['templates_loaded'],
                'requests_sent': self.stats['requests_sent'],
                'vulnerabilities_found': self.stats['vulnerabilities_found']
            },
            'vulnerabilities': [
                {
                    'id': result.template_id,
                    'name': result.template_name,
                    'target': result.target_url,
                    'severity': result.severity,
                    'matched_data': result.matched_data,
                    'request': result.request_data,
                    'response': {
                        'status_code': result.response_data.get('status_code'),
                        'size': result.response_data.get('size'),
                        'execution_time': result.response_data.get('execution_time')
                    },
                    'timestamp': result.timestamp
                }
                for result in self.results if result.vulnerability_found
            ]
        }
        
        if output_format.lower() == 'json':
            return json.dumps(report_data, indent=2, ensure_ascii=False)
        else:
            return str(report_data)
    
    def save_report(self, filename: str, output_format: str = 'json'):
        """保存扫描报告到文件"""
        report = self.generate_report(output_format)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        if not self.config.silent:
            print(f"  报告已保存: {filename}")

# 命令行接口
async def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='模板化漏洞扫描引擎')
    parser.add_argument('target', help='目标URL')
    parser.add_argument('-t', '--templates', required=True, help='模板文件或目录路径')
    parser.add_argument('-o', '--output', help='输出报告文件名')
    parser.add_argument('-c', '--concurrency', type=int, default=100, help='并发数')
    parser.add_argument('-s', '--severity', choices=['low', 'medium', 'high', 'critical'], 
                       help='严重程度过滤')
    parser.add_argument('--silent', action='store_true', help='静默模式')
    
    args = parser.parse_args()
    
    # 创建配置
    config = ScannerConfig(
        max_concurrent_requests=args.concurrency,
        silent=args.silent
    )
    
    # 创建扫描器
    scanner = TemplateVulnScanner(config)
    
    # 加载模板
    await scanner.load_templates([args.templates])
    
    # 显示反WAF配置 (仅在非静默模式下)
    if not args.silent:
        anti_waf = AntiWAFEngine()
        print("\n🕵️ 反WAF引擎已启用:")
        print(f"   📱 User-Agent池: {len(anti_waf.user_agents)} 个")
        print(f"   🔀 请求头变化: {len(anti_waf.common_headers)} 类")
        print(f"   ⏱️ 随机延迟: 0.1-0.5秒")
        print(f"   🎭 混淆技术: 启用")
        print()
    
    # 执行扫描
    template_filter = {}
    if args.severity:
        template_filter['severity'] = args.severity
    
    await scanner.scan_target(args.target, template_filter)
    
    # 保存报告
    if args.output:
        scanner.save_report(args.output)
    else:
        print(scanner.generate_report())

if __name__ == "__main__":
    asyncio.run(main()) 