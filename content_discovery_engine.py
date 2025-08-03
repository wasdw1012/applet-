#!/usr/bin/env python3
"""
全疆域内容发现引擎 (Content Discovery Engine)
集成反WAF能力的并行内容发现系统
为第二阶段行动建立完整的攻击路径地图集
示例域名请替换实际部署域名
"""

import asyncio
import aiohttp
import ssl
import random
import time
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
import concurrent.futures
from pathlib import Path

# 导入反WAF引擎
from anti_waf_engine import AntiWAFEngine

class ContentDiscoveryEngine:
    def __init__(self, subdomains_file: str = None, target_domain: str = None):
        """
        初始化全疆域内容发现引擎
        
        参数:
        subdomains_file: 子域名列表文件路径
        target_domain: 目标域名（用于生成输出文件名）
        """
        self.target_domain = target_domain
        self.subdomains_file = subdomains_file
        self.subdomains = []
        self.discovered_paths = {}
        self.attack_surface_map = {}
        
        # 集成反WAF引擎
        self.anti_waf = AntiWAFEngine()
        
        # 输出目录
        self.output_dir = "content_discovery_results"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 扫描配置
        self.config = {
                'concurrent_domains': 5,    # 并发域名数量
    'concurrent_paths': 12,     # 每个域名的并发路径数量 (猥琐部署：降低并发)
            'request_timeout': 10,      # 请求超时时间
            'delay_range': (0.5, 2.0),  # 随机延迟范围
            'max_retries': 2,           # 最大重试次数
            'interesting_status_codes': [200, 201, 204, 301, 302, 403, 401, 500, 503],
            'skip_extensions': ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.woff', '.woff2']
        }
        
        # 核心路径字典 - 根据阶段1发现优化
        self.discovery_paths = [
            # 管理界面
            '/admin', '/admin/', '/administrator', '/admin.php', '/admin/login',
            '/admin/index.php', '/admin/admin.php', '/admin/dashboard',
            '/wp-admin/', '/wp-admin/admin.php', '/phpmyadmin/', '/adminer.php',
            '/manager/html', '/manager/', '/console/', '/control/', '/cp/',
            
            # API端点
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/', '/api/docs',
            '/api/swagger', '/api/openapi', '/api/graphql', '/graphql',
            '/rest/', '/rest/api/', '/v1/', '/v2/', '/v3/',
            '/api/health', '/api/status', '/api/version', '/api/config',
            
            # 医疗系统特定路径（基于biograph.com发现）
            '/patient/', '/patients/', '/medical/', '/health/', '/records/',
            '/hipaa/', '/phi/', '/emr/', '/ehr/', '/dicom/', '/hl7/',
            '/billing/', '/insurance/', '/claims/', '/appointments/',
            '/provider/', '/physician/', '/doctor/', '/nurse/',
            
            # 认证相关
            '/login', '/login.php', '/login.asp', '/signin', '/auth/',
            '/authentication/', '/oauth/', '/sso/', '/saml/', '/ldap/',
            '/forgot-password', '/reset-password', '/change-password',
            
            # 配置和敏感文件
            '/.env', '/.env.local', '/.env.production', '/config/',
            '/configuration/', '/settings/', '/setup/', '/install/',
            '/web.config', '/app.config', '/database.yml', '/secrets.yml',
            '/.git/', '/.svn/', '/.hg/', '/CVS/', '/.DS_Store',
            
            # 备份和临时文件
            '/backup/', '/backups/', '/bak/', '/old/', '/tmp/', '/temp/',
            '/cache/', '/log/', '/logs/', '/dump/', '/sql/', '/db/',
            '/backup.sql', '/backup.tar.gz', '/dump.sql', '/database.sql',
            
            # 开发和测试环境
            '/dev/', '/development/', '/test/', '/testing/', '/stage/', '/staging/',
            '/qa/', '/uat/', '/demo/', '/sandbox/', '/debug/', '/trace/',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            
            # 文档和帮助
            '/docs/', '/documentation/', '/help/', '/support/', '/manual/',
            '/readme', '/README', '/CHANGELOG', '/LICENSE', '/INSTALL',
            '/wiki/', '/knowledge/', '/faq/', '/about/',
            
            # 服务和健康检查
            '/health', '/healthcheck', '/status', '/ping', '/version',
            '/metrics', '/monitoring/', '/stats/', '/analytics/',
            '/prometheus/', '/grafana/', '/kibana/',
            
            # 文件上传和下载
            '/upload/', '/uploads/', '/files/', '/download/', '/downloads/',
            '/media/', '/images/', '/documents/', '/attachments/',
            '/export/', '/import/', '/transfer/',
            
            # 第三方集成
            '/webhook/', '/webhooks/', '/callback/', '/notify/',
            '/integration/', '/connector/', '/plugin/', '/addon/',
            '/oauth2/', '/openid/', '/cas/', '/radius/',
            
            # 移动应用API
            '/mobile/', '/app/', '/android/', '/ios/', '/flutter/',
            '/cordova/', '/phonegap/', '/ionic/', '/react-native/',
            
            # 云服务相关
            '/aws/', '/azure/', '/gcp/', '/s3/', '/ec2/', '/lambda/',
            '/docker/', '/kubernetes/', '/k8s/', '/helm/', '/terraform/',
            
            # 安全相关
            '/security/', '/audit/', '/compliance/', '/policy/',
            '/firewall/', '/waf/', '/ids/', '/ips/', '/siem/',
            '/vulnerability/', '/pentest/', '/security-headers/',
            
            # 常见CMS路径
            '/wp-content/', '/wp-includes/', '/wp-json/', '/xmlrpc.php',
            '/drupal/', '/joomla/', '/magento/', '/prestashop/',
            '/typo3/', '/concrete5/', '/modx/', '/craft/',
            
            # 框架特定路径
            '/laravel/', '/symfony/', '/codeigniter/', '/cakephp/',
            '/rails/', '/django/', '/flask/', '/spring/', '/struts/',
            '/express/', '/next/', '/nuxt/', '/angular/', '/react/', '/vue/',
        ]
        
        # 文件扩展名字典
        self.file_extensions = [
            '', '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
            '.cfm', '.cgi', '.pl', '.py', '.rb', '.sh', '.bat',
            '.html', '.htm', '.xml', '.json', '.txt', '.log',
            '.sql', '.bak', '.old', '.orig', '.tmp', '.swp',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.war', '.jar'
        ]

    def load_subdomains(self) -> List[str]:
        """从文件或直接输入加载子域名列表"""
        subdomains = []
        
        if self.subdomains_file and os.path.exists(self.subdomains_file):
            print(f"📂 从文件加载子域名: {self.subdomains_file}")
            with open(self.subdomains_file, 'r', encoding='utf-8') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and not subdomain.startswith('#'):
                        subdomains.append(subdomain)
        else:
            # 如果没有文件，尝试从day1_recon结果目录查找
            possible_files = [
                'subdomains_enhanced.txt',
                'output/subdomains_enhanced.txt',
                f'{self.target_domain}_subdomains.txt'
            ]
            
            for file_path in possible_files:
                if os.path.exists(file_path):
                    print(f"📂 自动发现子域名文件: {file_path}")
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain and not subdomain.startswith('#'):
                                subdomains.append(subdomain)
                    break
        
        if not subdomains and self.target_domain:
            print(f"⚠️  未找到子域名文件，使用主域名: {self.target_domain}")
            subdomains = [self.target_domain]
        
        self.subdomains = list(set(subdomains))  # 去重
        print(f"🎯 加载子域名: {len(self.subdomains)} 个")
        return self.subdomains

    async def check_path(self, session: aiohttp.ClientSession, domain: str, path: str) -> Optional[Dict]:
        """检查单个路径的可访问性"""
        for protocol in ['https', 'http']:
            url = f"{protocol}://{domain}{path}"
            
            try:
                # 使用反WAF引擎的StealthHTTPClient进行分布式扫描
                response = await self.anti_waf.stealth_request(
                    session, 
                    "GET", 
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config['request_timeout']),
                    ssl=False,
                    allow_redirects=False
                )
                
                async with response:
                    
                    if response.status in self.config['interesting_status_codes']:
                        content_length = response.headers.get('Content-Length', '0')
                        content_type = response.headers.get('Content-Type', '')
                        server = response.headers.get('Server', '')
                        location = response.headers.get('Location', '')
                        
                        result = {
                            'url': url,
                            'status': response.status,
                            'content_length': content_length,
                            'content_type': content_type,
                            'server': server,
                            'location': location,
                            'protocol': protocol,
                            'path': path,
                            'domain': domain,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # 检查是否为有趣的响应
                        if self.is_interesting_response(result):
                            print(f"✅ 发现: {url} [{response.status}] {content_length}字节")
                            return result
            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
        
        return None

    def is_interesting_response(self, result: Dict) -> bool:
        """判断响应是否值得关注"""
        status = result['status']
        content_length = int(result.get('content_length', '0'))
        content_type = result.get('content_type', '').lower()
        url = result['url']
        
        # 跳过静态资源
        if any(url.lower().endswith(ext) for ext in self.config['skip_extensions']):
            return False
        
        # 跳过太小的响应（可能是错误页面）
        if status == 200 and content_length < 100:
            return False
        
        # 重点关注的状态码
        interesting_statuses = [200, 201, 204, 401, 403, 500, 503]
        if status in interesting_statuses:
            return True
        
        # 重定向但包含敏感关键词
        if status in [301, 302] and any(keyword in url.lower() for keyword in 
                                      ['admin', 'login', 'api', 'config', 'dashboard']):
            return True
        
        return False

    async def scan_domain(self, domain: str) -> List[Dict]:
        """扫描单个域名的所有路径"""
        print(f"\n🔍 开始扫描域名: {domain}")
        discovered = []
        
        # 创建SSL上下文（忽略证书验证）
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # 创建连接器
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=50,
            limit_per_host=20
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # 创建任务列表
            tasks = []
            
            # 基础路径扫描
            for path in self.discovery_paths:
                task = asyncio.create_task(self.check_path(session, domain, path))
                tasks.append(task)
            
            # 带扩展名的路径扫描
            for base_path in ['/admin', '/config', '/backup', '/test', '/api']:
                for ext in self.file_extensions:
                    path = f"{base_path}{ext}"
                    task = asyncio.create_task(self.check_path(session, domain, path))
                    tasks.append(task)
            
            # 并发执行，控制并发数量
            semaphore = asyncio.Semaphore(self.config['concurrent_paths'])
            
            async def bounded_check(task):
                async with semaphore:
                    return await task
            
            bounded_tasks = [bounded_check(task) for task in tasks]
            results = await asyncio.gather(*bounded_tasks, return_exceptions=True)
            
            # 收集有效结果
            for result in results:
                if result and isinstance(result, dict):
                    discovered.append(result)
        
        print(f"📊 {domain} 发现路径: {len(discovered)} 个")
        return discovered

    async def run_parallel_discovery(self) -> Dict:
        """并行执行全疆域内容发现"""
        print("\n🚀 启动全疆域内容发现引擎")
        print("=" * 60)
        
        # 加载子域名
        self.load_subdomains()
        
        if not self.subdomains:
            print("❌ 未找到任何子域名，无法继续")
            return {}
        
        start_time = time.time()
        all_results = {}
        
        # 控制并发域名数量
        semaphore = asyncio.Semaphore(self.config['concurrent_domains'])
        
        async def scan_with_semaphore(domain):
            async with semaphore:
                return domain, await self.scan_domain(domain)
        
        # 创建扫描任务
        tasks = [scan_with_semaphore(domain) for domain in self.subdomains]
        
        # 执行并行扫描
        print(f"🎯 并行扫描 {len(self.subdomains)} 个子域名 (并发: {self.config['concurrent_domains']})")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 收集结果
        total_paths = 0
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                domain, paths = result
                if paths:
                    all_results[domain] = paths
                    total_paths += len(paths)
        
        elapsed_time = time.time() - start_time
        
        print("\n" + "=" * 60)
        print(f"✅ 全疆域内容发现完成!")
        print(f"📊 扫描域名: {len(self.subdomains)} 个")
        print(f"🎯 发现路径: {total_paths} 个")
        print(f"⏱️  耗时: {elapsed_time:.2f} 秒")
        
        # 保存结果
        self.save_results(all_results)
        self.generate_attack_surface_map(all_results)
        
        return all_results

    def save_results(self, results: Dict):
        """保存发现结果"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 详细结果JSON
        detailed_file = f"{self.output_dir}/content_discovery_{timestamp}.json"
        with open(detailed_file, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_info': {
                    'target_domain': self.target_domain,
                    'scan_time': datetime.now().isoformat(),
                    'total_domains': len(results),
                    'total_paths': sum(len(paths) for paths in results.values()),
                    'engine_version': 'ContentDiscoveryEngine v1.0'
                },
                'discovered_paths': results
            }, f, indent=2, ensure_ascii=False)
        
        # 简化路径列表
        simple_file = f"{self.output_dir}/discovered_paths_{timestamp}.txt"
        with open(simple_file, 'w', encoding='utf-8') as f:
            f.write(f"# 全疆域内容发现结果 - {datetime.now()}\n")
            f.write(f"# 目标: {self.target_domain}\n")
            f.write(f"# 发现域名: {len(results)} 个\n")
            f.write(f"# 发现路径: {sum(len(paths) for paths in results.values())} 个\n\n")
            
            for domain, paths in results.items():
                f.write(f"\n[{domain}] - {len(paths)} 个路径\n")
                f.write("-" * 50 + "\n")
                for path_info in paths:
                    status = path_info['status']
                    url = path_info['url']
                    length = path_info['content_length']
                    f.write(f"{status:3d} | {length:>8} | {url}\n")
        
        print(f"💾 结果已保存:")
        print(f"    详细结果: {detailed_file}")
        print(f"    路径列表: {simple_file}")

    def generate_attack_surface_map(self, results: Dict):
        """生成攻击面地图"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        map_file = f"{self.output_dir}/attack_surface_map_{timestamp}.json"
        
        attack_map = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'target_domain': self.target_domain,
                'total_domains': len(results),
                'total_attack_vectors': 0
            },
            'attack_vectors': {
                'admin_interfaces': [],
                'api_endpoints': [],
                'authentication_pages': [],
                'configuration_files': [],
                'backup_files': [],
                'development_environments': [],
                'sensitive_directories': [],
                'medical_specific': [],
                'high_value_targets': []
            }
        }
        
        # 分类攻击向量
        for domain, paths in results.items():
            for path_info in paths:
                url = path_info['url']
                path = path_info['path']
                status = path_info['status']
                
                # 管理界面
                if any(keyword in path.lower() for keyword in ['admin', 'manage', 'control', 'dashboard']):
                    attack_map['attack_vectors']['admin_interfaces'].append({
                        'url': url, 'status': status, 'priority': 'HIGH'
                    })
                
                # API端点
                elif any(keyword in path.lower() for keyword in ['api', 'rest', 'graphql', 'webhook']):
                    attack_map['attack_vectors']['api_endpoints'].append({
                        'url': url, 'status': status, 'priority': 'HIGH'
                    })
                
                # 认证页面
                elif any(keyword in path.lower() for keyword in ['login', 'auth', 'signin', 'sso']):
                    attack_map['attack_vectors']['authentication_pages'].append({
                        'url': url, 'status': status, 'priority': 'MEDIUM'
                    })
                
                # 配置文件
                elif any(keyword in path.lower() for keyword in ['config', 'settings', '.env', 'web.config']):
                    attack_map['attack_vectors']['configuration_files'].append({
                        'url': url, 'status': status, 'priority': 'HIGH'
                    })
                
                # 备份文件
                elif any(keyword in path.lower() for keyword in ['backup', 'bak', 'dump', 'sql']):
                    attack_map['attack_vectors']['backup_files'].append({
                        'url': url, 'status': status, 'priority': 'HIGH'
                    })
                
                # 开发环境
                elif any(keyword in path.lower() for keyword in ['dev', 'test', 'stage', 'debug']):
                    attack_map['attack_vectors']['development_environments'].append({
                        'url': url, 'status': status, 'priority': 'MEDIUM'
                    })
                
                # 医疗系统特定
                elif any(keyword in path.lower() for keyword in ['patient', 'medical', 'health', 'hipaa', 'phi']):
                    attack_map['attack_vectors']['medical_specific'].append({
                        'url': url, 'status': status, 'priority': 'CRITICAL'
                    })
                
                # 敏感目录
                else:
                    attack_map['attack_vectors']['sensitive_directories'].append({
                        'url': url, 'status': status, 'priority': 'LOW'
                    })
                
                # 高价值目标（基于状态码）
                if status in [200, 401, 403, 500]:
                    attack_map['attack_vectors']['high_value_targets'].append({
                        'url': url, 'status': status, 'reason': f'Status {status}',
                        'priority': 'HIGH' if status in [200, 500] else 'MEDIUM'
                    })
        
        # 计算总攻击向量数
        total_vectors = sum(len(vectors) for vectors in attack_map['attack_vectors'].values())
        attack_map['metadata']['total_attack_vectors'] = total_vectors
        
        # 保存攻击面地图
        with open(map_file, 'w', encoding='utf-8') as f:
            json.dump(attack_map, f, indent=2, ensure_ascii=False)
        
        print(f"🗺️  攻击面地图已生成: {map_file}")
        print(f"    总攻击向量: {total_vectors} 个")
        
        # 输出关键发现统计
        print("\n📈 关键攻击向量统计:")
        for category, vectors in attack_map['attack_vectors'].items():
            if vectors:
                count = len(vectors)
                high_priority = len([v for v in vectors if v.get('priority') == 'HIGH'])
                print(f"    {category}: {count} 个 (高优先级: {high_priority})")

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='全疆域内容发现引擎')
    parser.add_argument('--subdomains-file', '-f', help='子域名列表文件路径')
    parser.add_argument('--target-domain', '-t', help='目标域名')
    parser.add_argument('--concurrent-domains', '-cd', type=int, default=5, help='并发域名数量')
    parser.add_argument('--concurrent-paths', '-cp', type=int, default=12, help='每个域名的并发路径数量')
    
    args = parser.parse_args()
    
    # 创建引擎实例
    engine = ContentDiscoveryEngine(
        subdomains_file=args.subdomains_file,
        target_domain=args.target_domain
    )
    
    # 更新配置
    if args.concurrent_domains:
        engine.config['concurrent_domains'] = args.concurrent_domains
    if args.concurrent_paths:
        engine.config['concurrent_paths'] = args.concurrent_paths
    
    # 运行发现
    try:
        results = asyncio.run(engine.run_parallel_discovery())
        
        if results:
            print("\n🎯 全疆域内容发现完成！攻击路径地图已就绪！")
            print("💎 为第二阶段总攻做好了完整的情报支撑！")
        else:
            print("\n❌ 未发现任何有效路径，请检查目标配置")
            
    except KeyboardInterrupt:
        print("\n⏹️  扫描被用户中断")
    except Exception as e:
        print(f"\n❌ 扫描过程中出现错误: {e}")

if __name__ == "__main__":
    main() 