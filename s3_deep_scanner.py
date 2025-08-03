import asyncio
import aiohttp
import json
import time
from typing import List, Dict, Any

class S3DeepScanner:
    """S3深度扫描器"""
    
    def __init__(self):
        self.session = None
        self.found_issues = []
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, ssl=False)
        timeout = aiohttp.ClientTimeout(total=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'S3DeepScanner/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def deep_scan_bucket(self, bucket_name: str):
        """深度扫描单个S3桶"""
        print(f"  开始深度扫描: {bucket_name}")
        
        # 1. 生成变种桶名
        variants = self._generate_bucket_variants(bucket_name)
        await self._scan_bucket_variants(bucket_name, variants)
        
        # 2. 测试不同的访问方式
        await self._test_access_methods(bucket_name)
        
        # 3. 尝试常见敏感文件路径
        await self._scan_sensitive_paths(bucket_name)
        
        # 4. 检测版本控制
        await self._check_versioning(bucket_name)
        
        # 5. 尝试错误配置
        await self._test_misconfigurations(bucket_name)
    
    def _generate_bucket_variants(self, base_name: str) -> List[str]:
        """生成桶的变种名称"""
        variants = []
        
        # 基于base_name生成更多可能的桶
        patterns = [
            f"{base_name}-backup",
            f"{base_name}-backups", 
            f"{base_name}-data",
            f"{base_name}-files",
            f"{base_name}-logs",
            f"{base_name}-uploads",
            f"{base_name}-temp",
            f"{base_name}-staging",
            f"{base_name}-prod",
            f"{base_name}-production",
            f"{base_name}-dev",
            f"{base_name}-development",
            f"backup-{base_name}",
            f"data-{base_name}",
            f"files-{base_name}",
            f"logs-{base_name}",
            f"{base_name}backup",
            f"{base_name}data",
            f"{base_name}files",
            f"{base_name}logs",
            f"{base_name}2021",
            f"{base_name}2022", 
            f"{base_name}2023",
            f"{base_name}2024",
            f"{base_name}2025",
            f"{base_name}-old",
            f"{base_name}-new",
            f"{base_name}-bak",
            f"{base_name}-copy",
        ]
        
        return patterns
    
    async def _scan_bucket_variants(self, original: str, variants: List[str]):
        """扫描桶的变种"""
        print(f"  扫描 {len(variants)} 个变种桶...")
        
        tasks = []
        for variant in variants:
            task = self._check_bucket_exists(variant)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        found_variants = []
        for i, result in enumerate(results):
            if isinstance(result, dict) and result.get('exists'):
                found_variants.append(variants[i])
                status = result.get('status', 'unknown')
                print(f"  发现变种桶: {variants[i]} - {status}")
                
                self.found_issues.append({
                    'type': 'variant_bucket_found',
                    'bucket': variants[i],
                    'original': original,
                    'status': status,
                    'severity': 'high' if status == 'public' else 'medium'
                })
        
        return found_variants
    
    async def _check_bucket_exists(self, bucket_name: str) -> Dict[str, Any]:
        """检查桶是否存在"""
        endpoints = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}"
        ]
        
        for endpoint in endpoints:
            try:
                async with self.session.head(endpoint) as response:
                    if response.status == 200:
                        return {'exists': True, 'status': 'public', 'url': endpoint}
                    elif response.status == 403:
                        return {'exists': True, 'status': 'private', 'url': endpoint}
                    elif response.status == 404:
                        return {'exists': False}
            except:
                continue
        
        return {'exists': False}
    
    async def _test_access_methods(self, bucket_name: str):
        """测试不同的访问方式"""
        print(f"🔓 测试访问方式: {bucket_name}")
        
        # 测试不同的端点格式
        endpoints = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
            f"https://{bucket_name}.s3-us-west-2.amazonaws.com",
            f"https://{bucket_name}.s3-eu-west-1.amazonaws.com",
            f"https://{bucket_name}.s3.ap-southeast-1.amazonaws.com",
            f"http://{bucket_name}.s3.amazonaws.com",  # HTTP而非HTTPS
        ]
        
        for endpoint in endpoints:
            try:
                async with self.session.get(endpoint) as response:
                    if response.status == 200:
                        content = await response.text()
                        print(f"  公开访问成功: {endpoint}")
                        
                        # 解析列表内容
                        files = self._parse_s3_listing(content)
                        
                        self.found_issues.append({
                            'type': 'public_access_found',
                            'bucket': bucket_name,
                            'endpoint': endpoint,
                            'files_count': len(files),
                            'sample_files': files[:5],
                            'severity': 'critical'
                        })
                        
                        return True
            except:
                continue
        
        return False
    
    async def _scan_sensitive_paths(self, bucket_name: str):
        """扫描敏感文件路径"""
        print(f"  扫描敏感路径: {bucket_name}")
        
        # 常见的敏感文件路径
        sensitive_paths = [
            'database.sql',
            'backup.sql', 
            'dump.sql',
            'config.json',
            'config.xml',
            'settings.json',
            'credentials.json',
            'secret.txt',
            'password.txt',
            'users.csv',
            'patients.csv',
            'medical_records.csv',
            'backup.zip',
            'data.zip',
            'export.zip',
            '.env',
            'wp-config.php',
            'database.php',
            'config.php',
            'admin.txt',
            'readme.txt',
            'test.txt',
            'index.html',
            'error.log',
            'access.log',
            'debug.log',
        ]
        
        base_url = f"https://{bucket_name}.s3.amazonaws.com"
        
        for path in sensitive_paths:
            try:
                url = f"{base_url}/{path}"
                async with self.session.head(url) as response:
                    if response.status == 200:
                        # 获取文件大小
                        size = response.headers.get('Content-Length', 'unknown')
                        print(f"  敏感文件可访问: {path} ({size} bytes)")
                        
                        self.found_issues.append({
                            'type': 'sensitive_file_accessible',
                            'bucket': bucket_name,
                            'file': path,
                            'url': url,
                            'size': size,
                            'severity': 'critical'
                        })
            except:
                continue
    
    async def _check_versioning(self, bucket_name: str):
        """检查版本控制泄露"""
        print(f"  检查版本控制: {bucket_name}")
        
        # 尝试访问版本控制端点
        versioning_urls = [
            f"https://{bucket_name}.s3.amazonaws.com/?versioning",
            f"https://{bucket_name}.s3.amazonaws.com/?versions",
            f"https://s3.amazonaws.com/{bucket_name}?versioning",
        ]
        
        for url in versioning_urls:
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if 'Version' in content or 'versioning' in content.lower():
                            print(f"  版本控制信息泄露: {url}")
                            
                            self.found_issues.append({
                                'type': 'versioning_exposed',
                                'bucket': bucket_name,
                                'url': url,
                                'severity': 'medium'
                            })
            except:
                continue
    
    async def _test_misconfigurations(self, bucket_name: str):
        """测试常见错误配置"""
        print(f"⚙️ 检测错误配置: {bucket_name}")
        
        # 测试CORS配置
        cors_url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }
            async with self.session.options(cors_url, headers=headers) as response:
                cors_headers = response.headers
                if 'Access-Control-Allow-Origin' in cors_headers:
                    origin = cors_headers['Access-Control-Allow-Origin']
                    if origin == '*' or 'evil.com' in origin:
                        print(f"  CORS错误配置: {origin}")
                        
                        self.found_issues.append({
                            'type': 'cors_misconfiguration',
                            'bucket': bucket_name,
                            'allowed_origin': origin,
                            'severity': 'high'
                        })
        except:
            pass
        
        # 测试其他HTTP方法
        methods = ['PUT', 'POST', 'DELETE']
        for method in methods:
            try:
                async with self.session.request(method, cors_url) as response:
                    if response.status not in [403, 405, 501]:
                        print(f"  HTTP方法 {method} 可用: {response.status}")
                        
                        self.found_issues.append({
                            'type': 'http_method_allowed',
                            'bucket': bucket_name,
                            'method': method,
                            'status': response.status,
                            'severity': 'high'
                        })
            except:
                continue
    
    def _parse_s3_listing(self, xml_content: str) -> List[str]:
        """解析S3列表XML"""
        import re
        files = []
        key_pattern = r'<Key>(.*?)</Key>'
        matches = re.findall(key_pattern, xml_content)
        return [match for match in matches if not match.endswith('/')]
    
    def print_summary(self):
        """打印扫描摘要"""
        print(f"\n{'='*60}")
        print(f"  S3深度扫描完成")
        print(f"{'='*60}")
        
        if not self.found_issues:
            print("  未发现明显的安全问题")
            return
        
        # 按严重程度分组
        critical = [i for i in self.found_issues if i['severity'] == 'critical']
        high = [i for i in self.found_issues if i['severity'] == 'high'] 
        medium = [i for i in self.found_issues if i['severity'] == 'medium']
        
        print(f"  发现 {len(self.found_issues)} 个安全问题:")
        print(f"  🔴 CRITICAL: {len(critical)}")
        print(f"  🟠 HIGH: {len(high)}")
        print(f"  🟡 MEDIUM: {len(medium)}")
        
        print(f"\n📋 详细问题:")
        for issue in self.found_issues:
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡'
            }.get(issue['severity'], '⚪')
            
            print(f"\n{severity_emoji} {issue['type'].upper()}")
            for key, value in issue.items():
                if key not in ['type', 'severity']:
                    print(f"    {key}: {value}")

async def main():
    """主函数"""
    # 扫描之前发现的桶
    buckets_to_scan = ['biograph', 'test-biograph']
    
    async with S3DeepScanner() as scanner:
        for bucket in buckets_to_scan:
            await scanner.deep_scan_bucket(bucket)
            print()
        
        scanner.print_summary()
        
        # 保存结果
        if scanner.found_issues:
            report_file = f"s3_deep_scan_results_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(scanner.found_issues, f, indent=2)
            print(f"\n  详细报告已保存: {report_file}")

if __name__ == "__main__":
    asyncio.run(main()) 