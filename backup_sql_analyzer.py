import asyncio
import re
import json
import hashlib
from datetime import datetime
from anti_waf_engine import StealthHTTPClient

class BackupSQLAnalyzer:
    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.target_url = " "
        self.findings = {
            'file_info': {},
            'sql_structure': {},
            'credentials': [],
            'sensitive_data': [],
            'table_analysis': {},
            'security_risks': []
        }
    
    async def download_backup_file(self):
        """下载backup.sql文件"""
        print(f"🔻 开始下载: {self.target_url}")
        
        async with StealthHTTPClient() as client:
            try:
                async with await client.get(self.target_url, timeout=30) as response:
                    if response.status == 200:
                        content = await response.read()
                        
                        self.findings['file_info'] = {
                            'url': self.target_url,
                            'status_code': response.status,
                            'content_length': len(content),
                            'content_type': response.headers.get('content-type', 'unknown'),
                            'server': response.headers.get('server', 'unknown'),
                            'last_modified': response.headers.get('last-modified', 'unknown'),
                            'etag': response.headers.get('etag', 'unknown'),
                            'content_hash': hashlib.md5(content).hexdigest()
                        }
                        
                        print(f"✅ 下载成功: {len(content)}字节")
                        print(f"📄 内容类型: {self.findings['file_info']['content_type']}")
                        print(f"🗂️ 内容哈希: {self.findings['file_info']['content_hash']}")
                        
                        return content
                    else:
                        print(f"❌ 下载失败: HTTP {response.status}")
                        return None
            except Exception as e:
                print(f"❌ 下载异常: {e}")
                return None
    
    def analyze_content_type(self, content):
        """分析内容类型"""
        try:
            # 尝试UTF-8解码
            text_content = content.decode('utf-8', errors='ignore')
            
            # 检查是否为HTML
            if text_content.strip().startswith('<!doctype html>') or '<html' in text_content.lower():
                print("📄 内容类型: HTML页面 (非真实SQL文件)")
                return 'html', text_content
            
            # 检查是否为SQL
            sql_indicators = [
                'CREATE TABLE', 'INSERT INTO', 'DROP TABLE', 'ALTER TABLE',
                'CREATE DATABASE', 'USE ', 'GRANT ', 'REVOKE ',
                '-- ', '/*', 'SELECT ', 'UPDATE ', 'DELETE '
            ]
            
            if any(indicator in text_content.upper() for indicator in sql_indicators):
                print("🗃️ 内容类型: SQL数据库文件")
                return 'sql', text_content
            
            print("❓ 内容类型: 未知格式")
            return 'unknown', text_content
            
        except Exception as e:
            print(f"❌ 内容分析失败: {e}")
            return 'binary', content
    
    def analyze_html_content(self, html_content):
        """深度分析HTML内容寻找敏感信息"""
        print("\n🔍 HTML内容深度分析:")
        
        # 提取所有脚本内容
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        # 提取配置对象
        config_patterns = [
            r'window\.__CONFIG__\s*=\s*({.*?});',
            r'var\s+config\s*=\s*({.*?});',
            r'const\s+config\s*=\s*({.*?});',
            r'window\.config\s*=\s*({.*?});'
        ]
        
        for pattern in config_patterns:
            matches = re.findall(pattern, html_content, re.DOTALL)
            for match in matches:
                try:
                    # 尝试解析JSON配置
                    config_obj = json.loads(match)
                    self.findings['sensitive_data'].append({
                        'type': 'javascript_config',
                        'content': config_obj,
                        'risk': 'MEDIUM'
                    })
                    print(f"  📋 发现JS配置对象: {len(str(config_obj))}字符")
                except:
                    pass
        
        # 搜索API密钥模式
        api_key_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
        ]
        
        for pattern in api_key_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                self.findings['credentials'].append({
                    'type': 'api_key',
                    'value': match,
                    'context': 'html_javascript',
                    'risk': 'HIGH'
                })
                print(f"  🔑 发现API密钥: {match[:8]}...{match[-4:]}")
        
        # 搜索数据库连接字符串
        db_patterns = [
            r'mysql://([^"\']+)',
            r'postgresql://([^"\']+)',
            r'mongodb://([^"\']+)',
            r'redis://([^"\']+)',
            r'Host["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'Database["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'Password["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in db_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                self.findings['credentials'].append({
                    'type': 'database_connection',
                    'value': match,
                    'context': 'html_source',
                    'risk': 'CRITICAL'
                })
                print(f"  🗄️ 发现数据库连接: {match}")
        
        # 搜索内网IP和端口
        internal_ip_pattern = r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[\d.]+(?::\d+)?\b'
        internal_ips = re.findall(internal_ip_pattern, html_content)
        for ip in set(internal_ips):
            self.findings['sensitive_data'].append({
                'type': 'internal_ip',
                'value': ip,
                'risk': 'MEDIUM'
            })
            print(f"  🌐 发现内网IP: {ip}")
        
        # 搜索邮箱地址
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, html_content)
        for email in set(emails):
            if not any(domain in email for domain in ['example.com', 'test.com', 'localhost']):
                self.findings['sensitive_data'].append({
                    'type': 'email_address',
                    'value': email,
                    'risk': 'LOW'
                })
                print(f"  📧 发现邮箱: {email}")
    
    def analyze_sql_content(self, sql_content):
        """深度分析SQL内容"""
        print("\n🗃️ SQL数据库深度分析:")
        
        # 提取CREATE TABLE语句
        table_pattern = r'CREATE TABLE\s+`?(\w+)`?\s*\((.*?)\);'
        tables = re.findall(table_pattern, sql_content, re.DOTALL | re.IGNORECASE)
        
        for table_name, columns in tables:
            self.findings['table_analysis'][table_name] = {
                'columns': self._parse_table_columns(columns),
                'sensitive_fields': []
            }
            print(f"  📊 表: {table_name} ({len(self.findings['table_analysis'][table_name]['columns'])}列)")
            
            # 检查敏感字段
            sensitive_field_patterns = ['password', 'pwd', 'pass', 'secret', 'token', 'key', 'hash', 'salt']
            for field in sensitive_field_patterns:
                if field in columns.lower():
                    self.findings['table_analysis'][table_name]['sensitive_fields'].append(field)
                    print(f"    🔒 敏感字段: {field}")
        
        # 提取INSERT语句中的数据
        insert_pattern = r'INSERT INTO\s+`?(\w+)`?.*?VALUES\s*\((.*?)\);'
        inserts = re.findall(insert_pattern, sql_content, re.DOTALL | re.IGNORECASE)
        
        for table_name, values in inserts[:10]:  # 只分析前10条
            if 'users' in table_name.lower() or 'admin' in table_name.lower():
                print(f"  👤 用户数据表: {table_name}")
                # 寻找潜在的用户凭据
                self._extract_user_credentials(table_name, values)
        
        # 搜索数据库配置
        config_patterns = [
            r'-- Host:\s*([^\r\n]+)',
            r'-- Database:\s*([^\r\n]+)',
            r'-- Server version:\s*([^\r\n]+)',
            r'-- PHP Version:\s*([^\r\n]+)'
        ]
        
        for pattern in config_patterns:
            matches = re.findall(pattern, sql_content)
            for match in matches:
                self.findings['sensitive_data'].append({
                    'type': 'database_info',
                    'value': match.strip(),
                    'risk': 'MEDIUM'
                })
                print(f"  ℹ️ 数据库信息: {match.strip()}")
    
    def _parse_table_columns(self, column_definition):
        """解析表列定义"""
        columns = []
        for line in column_definition.split('\n'):
            line = line.strip()
            if line and not line.startswith('--'):
                column_match = re.match(r'`?(\w+)`?\s+(\w+)', line)
                if column_match:
                    columns.append({
                        'name': column_match.group(1),
                        'type': column_match.group(2)
                    })
        return columns
    
    def _extract_user_credentials(self, table_name, values_str):
        """提取用户凭据信息"""
        # 简单的值提取 - 寻找可能的用户名和密码哈希
        values = re.findall(r"'([^']*)'", values_str)
        
        for value in values:
            # 检查是否为密码哈希
            if len(value) == 32 and re.match(r'^[a-f0-9]{32}$', value):
                self.findings['credentials'].append({
                    'type': 'password_hash_md5',
                    'value': value,
                    'table': table_name,
                    'risk': 'HIGH'
                })
            elif len(value) == 64 and re.match(r'^[a-f0-9]{64}$', value):
                self.findings['credentials'].append({
                    'type': 'password_hash_sha256',
                    'value': value,
                    'table': table_name,
                    'risk': 'HIGH'
                })
            elif '@' in value and '.' in value:
                self.findings['credentials'].append({
                    'type': 'email_credential',
                    'value': value,
                    'table': table_name,
                    'risk': 'MEDIUM'
                })
    
    def assess_security_risks(self):
        """评估安全风险"""
        print("\n🚨 安全风险评估:")
        
        # 计算风险等级
        critical_count = sum(1 for item in self.findings['credentials'] + self.findings['sensitive_data'] 
                           if item.get('risk') == 'CRITICAL')
        high_count = sum(1 for item in self.findings['credentials'] + self.findings['sensitive_data'] 
                        if item.get('risk') == 'HIGH')
        
        if critical_count > 0:
            risk_level = "🔴 CRITICAL"
            self.findings['security_risks'].append("数据库凭据或连接字符串泄露")
        elif high_count > 3:
            risk_level = "🟠 HIGH" 
            self.findings['security_risks'].append("多个高价值凭据泄露")
        elif high_count > 0:
            risk_level = "🟡 MEDIUM"
            self.findings['security_risks'].append("敏感信息泄露")
        else:
            risk_level = "🟢 LOW"
        
        print(f"总体风险等级: {risk_level}")
        print(f"关键发现: {critical_count}个")
        print(f"高风险发现: {high_count}个")
        
        return risk_level
    
    def generate_report(self):
        """生成分析报告"""
        report = {
            'session_id': self.session_id,
            'analysis_time': datetime.now().isoformat(),
            'target_url': self.target_url,
            'findings': self.findings,
            'summary': {
                'total_credentials': len(self.findings['credentials']),
                'total_sensitive_data': len(self.findings['sensitive_data']),
                'total_tables': len(self.findings['table_analysis']),
                'security_risks': self.findings['security_risks']
            }
        }
        
        report_file = f"backup_sql_analysis_{self.session_id}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report_file
    
    async def execute_analysis(self):
        """执行完整分析"""
        print("🚨 backup.sql 深度分析开始!")
        
        # 下载文件
        content = await self.download_backup_file()
        if not content:
            return None
        
        # 分析内容类型
        content_type, parsed_content = self.analyze_content_type(content)
        
        # 根据类型进行不同分析
        if content_type == 'html':
            self.analyze_html_content(parsed_content)
        elif content_type == 'sql':
            self.analyze_sql_content(parsed_content)
        
        # 安全风险评估
        risk_level = self.assess_security_risks()
        
        # 生成报告
        report_file = self.generate_report()
        
        print(f"\n📄 详细报告: {report_file}")
        return report_file

async def main():
    analyzer = BackupSQLAnalyzer()
    await analyzer.execute_analysis()

if __name__ == "__main__":
    asyncio.run(main()) 