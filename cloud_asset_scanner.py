import asyncio
import aiohttp
import re
import time
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, field
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CloudAsset:
    """云资产结构"""
    name: str
    platform: str  # aws, azure, gcp
    asset_type: str  # s3, blob, storage
    url: str
    status: str  # public, private, not_found, error
    size_estimate: Optional[str] = None
    last_modified: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    discovered_files: List[str] = field(default_factory=list)

@dataclass
class CloudScanConfig:
    """云扫描配置"""
    max_concurrent_requests: int = 200
    request_timeout: int = 10
    max_retries: int = 2
    enable_aws_s3: bool = True
    enable_azure_blob: bool = True
    enable_gcp_storage: bool = True
    deep_enumeration: bool = False  # 是否深度枚举文件
    verify_ssl: bool = False

class S3BucketScanner:
    """
    AWS S3 存储桶扫描器
    """
    
    def __init__(self, config: CloudScanConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        
        # S3 区域列表
        self.s3_regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-southeast-1',
            'ap-northeast-1', 'ap-south-1', 'sa-east-1'
        ]
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent_requests,
            ssl=False,
            ttl_dns_cache=300,
        )
        
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'CloudAssetScanner/1.0'}
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出"""
        if self.session:
            await self.session.close()
    
    def generate_bucket_names(self, target_domain: str) -> List[str]:
        """根据目标域名生成潜在的S3存储桶名称"""
        # 提取域名基础信息
        domain_clean = target_domain.replace('https://', '').replace('http://', '')
        domain_parts = domain_clean.split('.')
        company_name = domain_parts[0]
        
        # 基础词汇
        base_words = [
            company_name,
            domain_clean.replace('.', '-'),
            domain_clean.replace('.', ''),
            company_name.replace('-', ''),
            company_name.replace('_', ''),
        ]
        
        # 常见后缀
        suffixes = [
            '', '-backup', '-backups', '-data', '-assets', '-files', '-docs',
            '-images', '-media', '-uploads', '-download', '-downloads',
            '-static', '-public', '-private', '-staging', '-prod', '-production',
            '-dev', '-development', '-test', '-testing', '-logs', '-log',
            '-config', '-configs', '-database', '-db', '-dump', '-export',
            '-archive', '-archives', '-temp', '-tmp', '-cache',
            '-www', '-web', '-site', '-website', '-cdn', '-content',
            '-bucket', '-storage', '-store', '-repo', '-repository'
        ]
        
        # 常见前缀
        prefixes = [
            '', 'www-', 'assets-', 'static-', 'media-', 'files-', 'data-',
            'backup-', 'prod-', 'dev-', 'test-', 'staging-', 'public-',
            'private-', 'internal-', 'external-', 'admin-', 'user-',
            'client-', 'customer-', 'api-', 'app-', 'mobile-'
        ]
        
        # 生成组合
        bucket_names = set()
        
        # 基础名称
        for base in base_words:
            bucket_names.add(base)
            
            # 添加后缀
            for suffix in suffixes:
                bucket_names.add(f"{base}{suffix}")
            
            # 添加前缀
            for prefix in prefixes:
                bucket_names.add(f"{prefix}{base}")
                
                # 前缀+后缀组合
                for suffix in suffixes[:10]:  # 限制组合数量
                    bucket_names.add(f"{prefix}{base}{suffix}")
        
        # 特殊组合
        special_combinations = [
            f"{company_name}-com",
            f"{company_name}-net",
            f"{company_name}-org",
            f"{company_name}com",
            f"{company_name}backup",
            f"{company_name}data",
            f"backup{company_name}",
            f"data{company_name}",
            f"{company_name}2021",
            f"{company_name}2022",
            f"{company_name}2023",
            f"{company_name}2024",
            f"{company_name}2025",
        ]
        
        bucket_names.update(special_combinations)
        
        # 过滤无效名称
        valid_buckets = []
        for name in bucket_names:
            if self._is_valid_bucket_name(name):
                valid_buckets.append(name.lower())
        
        return sorted(list(set(valid_buckets)))
    
    def _is_valid_bucket_name(self, name: str) -> bool:
        """验证S3存储桶名称是否有效"""
        if not name or len(name) < 3 or len(name) > 63:
            return False
        
        # S3命名规则
        if not re.match(r'^[a-z0-9.-]+$', name):
            return False
        
        if name.startswith('.') or name.endswith('.'):
            return False
        
        if '..' in name or '.-' in name or '-.' in name:
            return False
        
        return True
    
    async def check_bucket_exists(self, bucket_name: str) -> CloudAsset:
        """检查单个S3存储桶是否存在及其权限"""
        async with self.semaphore:
            # 尝试多个S3端点
            endpoints = [
                f"https://{bucket_name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket_name}",
                f"https://{bucket_name}.s3-us-west-2.amazonaws.com",
                f"https://{bucket_name}.s3-eu-west-1.amazonaws.com",
            ]
            
            for endpoint in endpoints:
                try:
                    # 发送HEAD请求检查存在性
                    async with self.session.head(endpoint) as response:
                        status = self._analyze_s3_response(response.status, response.headers)
                        
                        asset = CloudAsset(
                            name=bucket_name,
                            platform='aws',
                            asset_type='s3',
                            url=endpoint,
                            status=status
                        )
                        
                        # 如果存在且可访问，尝试获取更多信息
                        if status == 'public':
                            await self._enumerate_bucket_contents(asset)
                        
                        return asset
                
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    continue
            
            # 所有端点都失败
            return CloudAsset(
                name=bucket_name,
                platform='aws',
                asset_type='s3',
                url=f"https://{bucket_name}.s3.amazonaws.com",
                status='not_found'
            )
    
    def _analyze_s3_response(self, status_code: int, headers: dict) -> str:
        """分析S3响应状态"""
        if status_code == 200:
            return 'public'  # 公开可读
        elif status_code == 403:
            return 'private'  # 存在但私有
        elif status_code == 404:
            return 'not_found'  # 不存在
        elif status_code == 301 or status_code == 302:
            return 'redirect'  # 重定向
        else:
            return 'unknown'
    
    async def _enumerate_bucket_contents(self, asset: CloudAsset):
        """枚举存储桶内容（仅对公开可读的桶）"""
        if not self.config.deep_enumeration:
            return
        
        try:
            async with self.session.get(asset.url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # 解析XML响应，提取文件列表
                    files = self._parse_s3_listing(content)
                    asset.discovered_files = files[:50]  # 限制显示文件数量
                    
                    # 估算大小
                    if len(files) > 0:
                        asset.size_estimate = f"~{len(files)} files"
        
        except Exception as e:
            logger.debug(f"Failed to enumerate bucket {asset.name}: {e}")
    
    def _parse_s3_listing(self, xml_content: str) -> List[str]:
        """解析S3列表XML响应"""
        files = []
        
        # 简单的XML解析，提取Key标签
        import re
        key_pattern = r'<Key>(.*?)</Key>'
        matches = re.findall(key_pattern, xml_content)
        
        for match in matches:
            if match and not match.endswith('/'):  # 忽略目录
                files.append(match)
        
        return files

class CloudAssetScanner:
    """
    云资产发现引擎主类
    """
    
    def __init__(self, config: CloudScanConfig = None):
        self.config = config or CloudScanConfig()
        self.discovered_assets: List[CloudAsset] = []
        
        # 统计信息
        self.stats = {
            'total_checked': 0,
            'buckets_found': 0,
            'public_buckets': 0,
            'private_buckets': 0,
            'scan_duration': 0,
            'start_time': None
        }
    
    async def scan_target(self, target_domain: str) -> List[CloudAsset]:
        """扫描目标的云资产"""
        self.stats['start_time'] = time.time()
        
        print(f"🌩️ 开始云资产发现: {target_domain}")
        print(f"  目标范围: AWS S3 存储桶")
        
        results = []
        
        # AWS S3 扫描
        if self.config.enable_aws_s3:
            s3_results = await self._scan_aws_s3(target_domain)
            results.extend(s3_results)
        
        self.discovered_assets = results
        self.stats['scan_duration'] = time.time() - self.stats['start_time']
        
        self._print_summary()
        
        return results
    
    async def _scan_aws_s3(self, target_domain: str) -> List[CloudAsset]:
        """扫描AWS S3存储桶"""
        print(f"  生成S3存储桶字典...")
        
        async with S3BucketScanner(self.config) as scanner:
            bucket_names = scanner.generate_bucket_names(target_domain)
            
            print(f"📋 生成候选存储桶: {len(bucket_names)} 个")
            print(f"  开始并发检测...")
            
            # 并发检测所有存储桶
            tasks = []
            for bucket_name in bucket_names:
                task = scanner.check_bucket_exists(bucket_name)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 过滤有效结果
            valid_assets = []
            for result in results:
                if isinstance(result, CloudAsset) and result.status != 'not_found':
                    valid_assets.append(result)
                    
                    if result.status == 'public':
                        self.stats['public_buckets'] += 1
                        print(f"  发现公开存储桶: {result.name}")
                    elif result.status == 'private':
                        self.stats['private_buckets'] += 1
                        print(f"  发现私有存储桶: {result.name}")
            
            self.stats['total_checked'] = len(bucket_names)
            self.stats['buckets_found'] = len(valid_assets)
            
            return valid_assets
    
    def _print_summary(self):
        """打印扫描摘要"""
        print(f"\n{'='*60}")
        print(f"🌩️ 云资产发现完成")
        print(f"{'='*60}")
        print(f"  扫描统计:")
        print(f"    检测总数: {self.stats['total_checked']}")
        print(f"  📦 发现存储桶: {self.stats['buckets_found']}")
        print(f"    公开可读: {self.stats['public_buckets']}")
        print(f"    私有存储桶: {self.stats['private_buckets']}")
        print(f"     扫描耗时: {self.stats['scan_duration']:.2f}秒")
        
        if self.stats['public_buckets'] > 0:
            print(f"\n  风险提醒:")
            print(f"  发现 {self.stats['public_buckets']} 个公开可读的存储桶")
            print(f"  建议立即检查是否包含敏感数据")
        
        print(f"\n  详细结果:")
        for asset in self.discovered_assets:
            status_emoji = {
                'public': ' ',
                'private': ' ',
                'redirect': '🔄',
                'unknown': '❓'
            }.get(asset.status, '📦')
            
            print(f"  {status_emoji} {asset.name} - {asset.status.upper()}")
            print(f"     URL: {asset.url}")
            if asset.discovered_files:
                print(f"     文件: {len(asset.discovered_files)} 个")
            print()
    
    def save_report(self, filename: str):
        """保存扫描报告"""
        import json
        
        report_data = {
            'scan_info': {
                'scanner': 'CloudAssetScanner',
                'version': '1.0',
                'timestamp': datetime.now().isoformat(),
                'duration': self.stats['scan_duration'],
                'total_checked': self.stats['total_checked'],
                'buckets_found': self.stats['buckets_found'],
                'public_buckets': self.stats['public_buckets'],
                'private_buckets': self.stats['private_buckets']
            },
            'discovered_assets': [
                {
                    'name': asset.name,
                    'platform': asset.platform,
                    'type': asset.asset_type,
                    'url': asset.url,
                    'status': asset.status,
                    'size_estimate': asset.size_estimate,
                    'discovered_files': asset.discovered_files[:10]  # 只保存前10个文件
                }
                for asset in self.discovered_assets
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"  报告已保存: {filename}")

# 命令行接口
async def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='云资产发现引擎')
    parser.add_argument('target', help='目标域名')
    parser.add_argument('-o', '--output', help='输出报告文件名')
    parser.add_argument('-c', '--concurrency', type=int, default=200, help='并发数')
    parser.add_argument('--deep', action='store_true', help='深度枚举（枚举文件列表）')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间')
    
    args = parser.parse_args()
    
    # 创建配置
    config = CloudScanConfig(
        max_concurrent_requests=args.concurrency,
        request_timeout=args.timeout,
        deep_enumeration=args.deep
    )
    
    # 创建扫描器
    scanner = CloudAssetScanner(config)
    
    # 执行扫描
    results = await scanner.scan_target(args.target)
    
    # 保存报告
    if args.output:
        scanner.save_report(args.output)
    else:
        # 默认文件名
        domain_safe = args.target.replace('https://', '').replace('http://', '').replace('/', '_')
        filename = f"cloud_assets_{domain_safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        scanner.save_report(filename)

if __name__ == "__main__":
    asyncio.run(main()) 