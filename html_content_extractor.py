
import asyncio
import re
import json
from datetime import datetime
from anti_waf_engine import StealthHTTPClient

class HTMLContentExtractor:
    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 测试所有返回相同HTML的端点
        self.test_urls = [
            "https://secure.biograph.com/backup.sql",
            "http://secure.biograph.com/api",
            "http://secure.biograph.com/config.txt",
            "http://secure.biograph.com/admin.php",
            "http://secure.biograph.com/wp-admin/"
        ]
        self.html_content = ""
        self.findings = {}
    
    async def download_html_content(self):
        """下载HTML内容进行分析"""
        print("🔻 下载HTML内容进行深度分析...")
        
        async with StealthHTTPClient() as client:
            try:
                # 使用第一个URL下载内容
                async with await client.get(self.test_urls[0], timeout=15) as response:
                    if response.status == 200:
                        content = await response.read()
                        self.html_content = content.decode('utf-8', errors='ignore')
                        print(f"✅ 成功获取HTML内容: {len(self.html_content)}字符")
                        return True
                    else:
                        print(f"❌ 下载失败: HTTP {response.status}")
                        return False
            except Exception as e:
                print(f"❌ 下载异常: {e}")
                return False
    
    def extract_application_info(self):
        """提取应用程序信息"""
        print("\n🔍 应用程序信息提取:")
        
        findings = {
            'title': '',
            'meta_tags': [],
            'script_sources': [],
            'css_sources': [],
            'api_endpoints': [],
            'version_info': [],
            'third_party_services': []
        }
        
        # 提取页面标题
        title_match = re.search(r'<title[^>]*>(.*?)</title>', self.html_content, re.IGNORECASE | re.DOTALL)
        if title_match:
            findings['title'] = title_match.group(1).strip()
            print(f"  📄 页面标题: {findings['title']}")
        
        # 提取meta标签
        meta_pattern = r'<meta\s+([^>]+)>'
        meta_matches = re.findall(meta_pattern, self.html_content, re.IGNORECASE)
        for meta in meta_matches:
            if 'name=' in meta or 'property=' in meta:
                findings['meta_tags'].append(meta)
                print(f"  🏷️ Meta标签: {meta[:60]}...")
        
        # 提取JavaScript文件
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        script_sources = re.findall(script_pattern, self.html_content, re.IGNORECASE)
        for src in script_sources:
            findings['script_sources'].append(src)
            print(f"  📜 JS文件: {src}")
            
            # 检查版本信息
            version_match = re.search(r'[\d.]+', src)
            if version_match and len(version_match.group()) > 3:
                findings['version_info'].append({
                    'type': 'javascript_version',
                    'value': version_match.group(),
                    'source': src
                })
        
        # 提取CSS文件
        css_pattern = r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']'
        css_sources = re.findall(css_pattern, self.html_content, re.IGNORECASE)
        for src in css_sources:
            findings['css_sources'].append(src)
            print(f"  🎨 CSS文件: {src}")
        
        self.findings.update(findings)
        return findings
    
    def extract_inline_javascript(self):
        """提取内联JavaScript代码"""
        print("\n💻 内联JavaScript分析:")
        
        # 提取所有script标签内容
        inline_script_pattern = r'<script[^>]*>(.*?)</script>'
        inline_scripts = re.findall(inline_script_pattern, self.html_content, re.DOTALL | re.IGNORECASE)
        
        js_findings = {
            'config_objects': [],
            'api_calls': [],
            'environment_vars': [],
            'debug_info': []
        }
        
        for script_content in inline_scripts:
            if len(script_content.strip()) < 10:
                continue
                
            print(f"  🔍 分析脚本段落: {len(script_content)}字符")
            
            # 搜索配置对象
            config_patterns = [
                r'window\.__CONFIG__\s*=\s*({[^}]+})',
                r'const\s+config\s*=\s*({[^}]+})',
                r'var\s+config\s*=\s*({[^}]+})',
                r'window\.APP_CONFIG\s*=\s*({[^}]+})'
            ]
            
            for pattern in config_patterns:
                matches = re.findall(pattern, script_content, re.DOTALL)
                for match in matches:
                    try:
                        config_data = json.loads(match)
                        js_findings['config_objects'].append(config_data)
                        print(f"    📋 配置对象: {len(str(config_data))}字符")
                    except:
                        # 即使JSON解析失败，也记录原始内容
                        js_findings['config_objects'].append({'raw': match})
                        print(f"    📋 配置对象(原始): {match[:50]}...")
            
            # 搜索API调用
            api_patterns = [
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
                r'\.ajax\s*\(\s*{[^}]*url\s*:\s*["\']([^"\']+)["\']',
                r'/api/[^"\')\s]+'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                for match in matches:
                    if match not in js_findings['api_calls']:
                        js_findings['api_calls'].append(match)
                        print(f"    🔗 API调用: {match}")
            
            # 搜索环境变量
            env_patterns = [
                r'process\.env\.(\w+)',
                r'NODE_ENV["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'REACT_APP_(\w+)',
                r'VUE_APP_(\w+)'
            ]
            
            for pattern in env_patterns:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                for match in matches:
                    js_findings['environment_vars'].append(match)
                    print(f"    🌍 环境变量: {match}")
        
        self.findings['javascript'] = js_findings
        return js_findings
    
    def extract_network_resources(self):
        """提取网络资源信息"""
        print("\n🌐 网络资源分析:")
        
        network_findings = {
            'external_domains': [],
            'cdn_resources': [],
            'websocket_endpoints': [],
            'iframe_sources': []
        }
        
        # 提取外部域名
        domain_pattern = r'https?://([^/"\'\s]+)'
        domains = re.findall(domain_pattern, self.html_content, re.IGNORECASE)
        
        for domain in set(domains):
            if domain not in ['secure.biograph.com', 'biograph.com']:
                network_findings['external_domains'].append(domain)
                print(f"  🌍 外部域名: {domain}")
                
                # 检查是否为CDN
                cdn_indicators = ['cdn', 'static', 'assets', 'cloudfront', 'fastly', 'cloudflare']
                if any(indicator in domain.lower() for indicator in cdn_indicators):
                    network_findings['cdn_resources'].append(domain)
                    print(f"    📦 CDN资源: {domain}")
        
        # 搜索WebSocket端点
        websocket_pattern = r'wss?://([^"\')\s]+)'
        websockets = re.findall(websocket_pattern, self.html_content, re.IGNORECASE)
        for ws in set(websockets):
            network_findings['websocket_endpoints'].append(ws)
            print(f"  🔌 WebSocket: {ws}")
        
        # 提取iframe源
        iframe_pattern = r'<iframe[^>]+src=["\']([^"\']+)["\']'
        iframes = re.findall(iframe_pattern, self.html_content, re.IGNORECASE)
        for iframe in iframes:
            network_findings['iframe_sources'].append(iframe)
            print(f"  🖼️ IFrame: {iframe}")
        
        self.findings['network'] = network_findings
        return network_findings
    
    def search_sensitive_patterns(self):
        """搜索敏感信息模式"""
        print("\n🚨 敏感信息搜索:")
        
        sensitive_findings = {
            'api_keys': [],
            'tokens': [],
            'internal_ips': [],
            'debug_info': [],
            'error_messages': []
        }
        
        # API密钥模式
        api_key_patterns = [
            r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']',  # Base64编码的密钥
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']'
        ]
        
        for pattern in api_key_patterns:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE)
            for match in matches:
                if len(match) >= 20:  # 过滤太短的匹配
                    sensitive_findings['api_keys'].append(match)
                    print(f"  🔑 潜在API密钥: {match[:8]}...{match[-4:]}")
        
        # 内网IP模式
        internal_ip_pattern = r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[\d.]+(?::\d+)?\b'
        internal_ips = re.findall(internal_ip_pattern, self.html_content)
        for ip in set(internal_ips):
            sensitive_findings['internal_ips'].append(ip)
            print(f"  🏠 内网IP: {ip}")
        
        # 调试信息
        debug_patterns = [
            r'console\.(?:log|error|warn|debug)\([^)]+\)',
            r'debugger;',
            r'DEBUG\s*=\s*true',
            r'development.*mode'
        ]
        
        for pattern in debug_patterns:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE)
            for match in matches:
                sensitive_findings['debug_info'].append(match)
                print(f"  🐛 调试信息: {match[:50]}...")
        
        self.findings['sensitive'] = sensitive_findings
        return sensitive_findings
    
    def generate_comprehensive_report(self):
        """生成综合分析报告"""
        report = {
            'session_id': self.session_id,
            'analysis_time': datetime.now().isoformat(),
            'html_content_length': len(self.html_content),
            'target_urls': self.test_urls,
            'findings': self.findings,
            'summary': {
                'total_js_files': len(self.findings.get('script_sources', [])),
                'total_css_files': len(self.findings.get('css_sources', [])),
                'external_domains': len(self.findings.get('network', {}).get('external_domains', [])),
                'api_endpoints_found': len(self.findings.get('javascript', {}).get('api_calls', [])),
                'sensitive_items': len(self.findings.get('sensitive', {}).get('api_keys', [])),
                'risk_assessment': self._assess_risk()
            }
        }
        
        report_file = f"html_content_analysis_{self.session_id}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report_file
    
    def _assess_risk(self):
        """评估风险等级"""
        sensitive_count = len(self.findings.get('sensitive', {}).get('api_keys', []))
        debug_count = len(self.findings.get('sensitive', {}).get('debug_info', []))
        api_count = len(self.findings.get('javascript', {}).get('api_calls', []))
        
        if sensitive_count > 0:
            return "HIGH"
        elif debug_count > 2 or api_count > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def print_summary(self):
        """打印分析摘要"""
        print(f"\n🦅 HTML内容分析完成摘要:")
        print(f"📄 HTML长度: {len(self.html_content)}字符")
        print(f"📜 JavaScript文件: {len(self.findings.get('script_sources', []))}个")
        print(f"🎨 CSS文件: {len(self.findings.get('css_sources', []))}个")
        print(f"🌐 外部域名: {len(self.findings.get('network', {}).get('external_domains', []))}个")
        print(f"🔗 API端点: {len(self.findings.get('javascript', {}).get('api_calls', []))}个")
        print(f"🔑 敏感信息: {len(self.findings.get('sensitive', {}).get('api_keys', []))}个")
        print(f"🚨 风险等级: {self._assess_risk()}")
    
    async def execute_full_analysis(self):
        """执行完整分析"""
        print("🔍 HTML内容深度分析启动!")
        
        if not await self.download_html_content():
            return None
        
        # 执行各种分析
        self.extract_application_info()
        self.extract_inline_javascript()
        self.extract_network_resources()
        self.search_sensitive_patterns()
        
        # 生成报告
        report_file = self.generate_comprehensive_report()
        self.print_summary()
        
        print(f"\n📄 详细报告: {report_file}")
        return report_file

async def main():
    extractor = HTMLContentExtractor()
    await extractor.execute_full_analysis()

if __name__ == "__main__":
    asyncio.run(main()) 