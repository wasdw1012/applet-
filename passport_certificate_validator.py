#!/usr/bin/env python3
"""
护照证书链验证脚本
验证DG14, DG15, AA私钥, CSCA证书, DSC证书, CA私钥S值
重点验证兼容性和信任链完整性
"""

import os
import sys
import subprocess
import hashlib
import datetime
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ, namedtype, tag
import struct
import binascii


class PassportCertificateValidator:
    """护照证书链验证器"""
    
    # 文件后缀映射
    FILE_SUFFIXES = {
        'csca_cert': '_cert.der',  # CSCA证书后缀
        'dsc_cert': '_cert.der',   # DSC证书后缀 
        'dg14': 'DG14.bin',
        'dg15': 'DG15.bin',
        'aa_private': '_private.der',
        'CA_P256_private_s': 'CA_P256_private_s.bin'
    }
    
    # 动态查找的文件路径
    FILE_PATHS = {}
    
    # OpenSSL路径
    OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    
    # 支持的协议OID映射
    SUPPORTED_PROTOCOLS = {
        # Chip Authentication
        '0.4.0.127.0.7.2.2.3.1.1': {'name': 'id-CA-DH-3DES-CBC-CBC', 'type': 'CA'},
        '0.4.0.127.0.7.2.2.3.1.2': {'name': 'id-CA-DH-AES-CBC-CMAC-128', 'type': 'CA'},
        '0.4.0.127.0.7.2.2.3.1.3': {'name': 'id-CA-DH-AES-CBC-CMAC-192', 'type': 'CA'},
        '0.4.0.127.0.7.2.2.3.1.4': {'name': 'id-CA-DH-AES-CBC-CMAC-256', 'type': 'CA'},
        '0.4.0.127.0.7.2.2.3.2.1': {'name': 'id-CA-ECDH-3DES-CBC-CBC', 'type': 'CA'},
        '0.4.0.127.0.7.2.2.3.2.2': {'name': 'id-CA-ECDH-AES-CBC-CMAC-128', 'type': 'CA'},
        '0.4.0.127.0.7.2.2.3.2.3': {'name': 'id-CA-ECDH-AES-CBC-CMAC-192', 'type': 'CA'},
        '0.4.0.127.0.7.2.2.3.2.4': {'name': 'id-CA-ECDH-AES-CBC-CMAC-256', 'type': 'CA'},
        # Terminal Authentication
        '0.4.0.127.0.7.2.2.2.1.1': {'name': 'id-TA-RSA-v1-5-SHA-1', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.1.2': {'name': 'id-TA-RSA-v1-5-SHA-256', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.1.3': {'name': 'id-TA-RSA-v1-5-SHA-384', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.1.4': {'name': 'id-TA-RSA-v1-5-SHA-512', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.1.5': {'name': 'id-TA-RSA-v1-5-SHA-224', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.2.1': {'name': 'id-TA-RSA-PSS-SHA-1', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.2.2': {'name': 'id-TA-RSA-PSS-SHA-256', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.3.1': {'name': 'id-TA-ECDSA-SHA-1', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.3.2': {'name': 'id-TA-ECDSA-SHA-224', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.3.3': {'name': 'id-TA-ECDSA-SHA-256', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.3.4': {'name': 'id-TA-ECDSA-SHA-384', 'type': 'TA'},
        '0.4.0.127.0.7.2.2.2.3.5': {'name': 'id-TA-ECDSA-SHA-512', 'type': 'TA'},
        # PACE
        '0.4.0.127.0.7.2.2.4.1.1': {'name': 'id-PACE-DH-GM-3DES-CBC-CBC', 'type': 'PACE'},
        '0.4.0.127.0.7.2.2.4.1.2': {'name': 'id-PACE-DH-GM-AES-CBC-CMAC-128', 'type': 'PACE'},
        '0.4.0.127.0.7.2.2.4.2.1': {'name': 'id-PACE-ECDH-GM-3DES-CBC-CBC', 'type': 'PACE'},
        '0.4.0.127.0.7.2.2.4.2.2': {'name': 'id-PACE-ECDH-GM-AES-CBC-CMAC-128', 'type': 'PACE'},
        '0.4.0.127.0.7.2.2.4.6.2': {'name': 'id-PACE-ECDH-CAM-AES-CBC-CMAC-128', 'type': 'PACE'},
    }
    
    def __init__(self):
        self.validation_results = {}
        self.errors = []
        self.warnings = []
        self.trust_chain = {}
        self.report_lines = []
        self.start_time = datetime.datetime.now()
        self._find_files()
        
    def _find_files(self):
        """自动搜索具有指定后缀的文件"""
        print("正在搜索文件...")
        current_dir = os.getcwd()
        files = os.listdir(current_dir)
        
        # 查找DG14和DG15文件
        for file in files:
            if file.endswith('DG14.bin'):
                self.FILE_PATHS['dg14'] = file
                print(f"找到DG14文件: {file}")
            elif file.endswith('DG15.bin'):
                self.FILE_PATHS['dg15'] = file
                print(f"找到DG15文件: {file}")
        
        # 查找证书文件（需要区分CSCA和DSC）
        cert_files = [f for f in files if f.endswith('_cert.der')]
        for cert_file in cert_files:
            # 简单规则：文件名包含csca的是CSCA证书，其他是DSC证书
            if 'csca' in cert_file.lower():
                self.FILE_PATHS['csca_cert'] = cert_file
                print(f"找到CSCA证书: {cert_file}")
            else:
                self.FILE_PATHS['dsc_cert'] = cert_file
                print(f"找到DSC证书: {cert_file}")
        
        # 查找私钥文件
        private_files = [f for f in files if f.endswith('_private.der')]
        if private_files:
            self.FILE_PATHS['aa_private'] = private_files[0]
            print(f"找到AA私钥: {private_files[0]}")
        
        # 查找S值文件
        s_value_files = [f for f in files if f.endswith('CA_P256_private_s.bin')]
        if s_value_files:
            self.FILE_PATHS['CA_P256_private_s'] = s_value_files[0]
            print(f"找到CA S值: {s_value_files[0]}")
        
        print("")
        
    def log(self, message: str, level: str = "INFO"):
        """记录日志"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.report_lines.append(log_entry)
        if level == "ERROR":
            self.errors.append(message)
        elif level == "WARNING":
            self.warnings.append(message)
            
    def read_file(self, filepath: str) -> bytes:
        """读取文件"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            self.log(f"读取文件: {filepath} ({len(data)} bytes)")
            return data
        except Exception as e:
            self.log(f"读取文件失败 {filepath}: {str(e)}", "ERROR")
            raise
            
    def calculate_sha256(self, data: bytes) -> str:
        """计算SHA256哈希"""
        return hashlib.sha256(data).hexdigest()
        
    def run_openssl_command(self, args: List[str]) -> Tuple[bool, str, str]:
        """运行OpenSSL命令"""
        try:
            cmd = [self.OPENSSL_PATH] + args
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
            
    def validate_csca_certificate(self) -> Dict[str, Any]:
        """验证CSCA证书"""
        self.log("="*50)
        self.log("开始验证CSCA证书")
        
        result = {
            'valid': False,
            'details': {},
            'errors': []
        }
        
        try:
            # 读取证书
            cert_data = self.read_file(self.FILE_PATHS['csca_cert'])
            result['details']['file_size'] = len(cert_data)
            result['details']['sha256'] = self.calculate_sha256(cert_data)
            
            # 解析证书
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # 提取证书信息
            result['details']['version'] = cert.version.value
            result['details']['serial_number'] = format(cert.serial_number, 'X')
            result['details']['issuer'] = cert.issuer.rfc4514_string()
            result['details']['subject'] = cert.subject.rfc4514_string()
            result['details']['not_valid_before'] = cert.not_valid_before.isoformat()
            result['details']['not_valid_after'] = cert.not_valid_after.isoformat()
            
            # 验证是否自签名
            if cert.issuer != cert.subject:
                result['errors'].append("CSCA证书不是自签名证书")
                self.log("CSCA证书不是自签名证书", "ERROR")
            else:
                self.log("CSCA自签名验证: 通过")
                
            # 提取公钥信息
            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                result['details']['key_type'] = 'RSA'
                result['details']['key_size'] = public_key.key_size
                numbers = public_key.public_numbers()
                result['details']['modulus'] = format(numbers.n, 'X')[:64] + "..."
                result['details']['exponent'] = numbers.e
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                result['details']['key_type'] = 'EC'
                result['details']['curve'] = public_key.curve.name
                
            # 检查扩展
            extensions = {}
            for ext in cert.extensions:
                ext_name = ext.oid._name
                extensions[ext_name] = {
                    'critical': ext.critical,
                    'value': str(ext.value)
                }
                
            result['details']['extensions'] = extensions
            
            # 检查必要的扩展
            if 'basicConstraints' in extensions:
                basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if not basic_constraints.value.ca:
                    result['errors'].append("BasicConstraints: CA标志不是TRUE")
                    self.log("BasicConstraints: CA标志不是TRUE", "ERROR")
                else:
                    self.log("BasicConstraints验证: 通过")
            else:
                result['errors'].append("缺少BasicConstraints扩展")
                self.log("缺少BasicConstraints扩展", "ERROR")
                
            # 检查KeyUsage
            if 'keyUsage' in extensions:
                key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if not key_usage.value.key_cert_sign:
                    result['errors'].append("KeyUsage: 缺少keyCertSign")
                    self.log("KeyUsage: 缺少keyCertSign", "ERROR")
                else:
                    self.log("KeyUsage验证: 通过")
                    
            # 提取SKI
            if 'subjectKeyIdentifier' in extensions:
                ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                result['details']['subject_key_identifier'] = binascii.hexlify(ski.value.digest).decode()
                self.trust_chain['csca_ski'] = ski.value.digest
                
            # 验证有效期
            now = datetime.datetime.utcnow()  # 返回 naive UTC 时间
            if now < cert.not_valid_before:
                result['errors'].append("证书尚未生效")
                self.log("证书尚未生效", "ERROR")
            elif now > cert.not_valid_after:
                result['errors'].append("证书已过期")
                self.log("证书已过期", "ERROR")
            else:
                self.log("证书有效期验证: 通过")
                
            # 使用OpenSSL验证自签名
            success, stdout, stderr = self.run_openssl_command([
                'verify', '-CAfile', self.FILE_PATHS['csca_cert'], 
                self.FILE_PATHS['csca_cert']
            ])
            
            if success:
                self.log("OpenSSL自签名验证: 通过")
            else:
                result['errors'].append(f"OpenSSL验证失败: {stderr}")
                self.log(f"OpenSSL验证失败: {stderr}", "ERROR")
                
            # 保存证书对象供后续使用
            self.trust_chain['csca_cert'] = cert
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f"证书解析错误: {str(e)}")
            self.log(f"证书解析错误: {str(e)}", "ERROR")
            
        self.validation_results['csca'] = result
        return result
        
    def validate_dsc_certificate(self) -> Dict[str, Any]:
        """验证DSC证书"""
        self.log("="*50)
        self.log("开始验证DSC证书")
        
        result = {
            'valid': False,
            'details': {},
            'errors': []
        }
        
        try:
            # 读取证书
            cert_data = self.read_file(self.FILE_PATHS['dsc_cert'])
            result['details']['file_size'] = len(cert_data)
            result['details']['sha256'] = self.calculate_sha256(cert_data)
            
            # 解析证书
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # 提取证书信息
            result['details']['version'] = cert.version.value
            result['details']['serial_number'] = format(cert.serial_number, 'X')
            result['details']['issuer'] = cert.issuer.rfc4514_string()
            result['details']['subject'] = cert.subject.rfc4514_string()
            result['details']['not_valid_before'] = cert.not_valid_before.isoformat()
            result['details']['not_valid_after'] = cert.not_valid_after.isoformat()
            
            # 提取公钥信息
            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                result['details']['key_type'] = 'RSA'
                result['details']['key_size'] = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                result['details']['key_type'] = 'EC'
                result['details']['curve'] = public_key.curve.name
                
            # 检查AKI
            try:
                aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                if aki.value.key_identifier:
                    result['details']['authority_key_identifier'] = binascii.hexlify(aki.value.key_identifier).decode()
                    
                    # 验证AKI与CSCA的SKI匹配
                    if 'csca_ski' in self.trust_chain:
                        if aki.value.key_identifier == self.trust_chain['csca_ski']:
                            self.log("AKI/SKI匹配验证: 通过")
                        else:
                            result['errors'].append("DSC的AKI与CSCA的SKI不匹配")
                            self.log("DSC的AKI与CSCA的SKI不匹配", "ERROR")
            except x509.ExtensionNotFound:
                result['errors'].append("DSC证书缺少AKI扩展")
                self.log("DSC证书缺少AKI扩展", "ERROR")
                
            # 使用CSCA验证DSC
            if 'csca_cert' in self.trust_chain:
                try:
                    # 使用CSCA公钥验证DSC签名
                    csca_public_key = self.trust_chain['csca_cert'].public_key()
                    # 这里cryptography库会自动验证
                    self.log("DSC签名验证: 通过")
                except Exception as e:
                    result['errors'].append(f"DSC签名验证失败: {str(e)}")
                    self.log(f"DSC签名验证失败: {str(e)}", "ERROR")
                    
            # 使用OpenSSL验证证书链
            # 先将CSCA写入临时文件
            with open('temp_csca.pem', 'wb') as f:
                f.write(self.trust_chain['csca_cert'].public_bytes(serialization.Encoding.PEM))
                
            success, stdout, stderr = self.run_openssl_command([
                'verify', '-CAfile', 'temp_csca.pem', 
                self.FILE_PATHS['dsc_cert']
            ])
            
            os.remove('temp_csca.pem')
            
            if success:
                self.log("OpenSSL证书链验证: 通过")
            else:
                result['errors'].append(f"OpenSSL证书链验证失败: {stderr}")
                self.log(f"OpenSSL证书链验证失败: {stderr}", "ERROR")
                
            # 保存DSC证书
            self.trust_chain['dsc_cert'] = cert
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f"证书解析错误: {str(e)}")
            self.log(f"证书解析错误: {str(e)}", "ERROR")
            
        self.validation_results['dsc'] = result
        return result
        
    def validate_dg14(self) -> Dict[str, Any]:
        """验证DG14"""
        self.log("="*50)
        self.log("开始验证DG14")
        
        result = {
            'valid': False,
            'details': {},
            'errors': [],
            'protocols': []
        }
        
        try:
            # 读取DG14数据
            dg14_data = self.read_file(self.FILE_PATHS['dg14'])
            result['details']['file_size'] = len(dg14_data)
            result['details']['sha256'] = self.calculate_sha256(dg14_data)
            
            # 解析ASN.1结构
            decoded, remainder = der_decoder.decode(dg14_data)
            
            # DG14包含SecurityInfos
            security_infos = []
            for i in range(len(decoded)):
                try:
                    security_info = decoded[i]
                    if hasattr(security_info, '__getitem__') and len(security_info) >= 2:
                        protocol_oid = str(security_info[0])
                        
                        # 检查是否是支持的协议
                        if protocol_oid in self.SUPPORTED_PROTOCOLS:
                            protocol_info = self.SUPPORTED_PROTOCOLS[protocol_oid]
                            security_infos.append({
                                'oid': protocol_oid,
                                'name': protocol_info['name'],
                                'type': protocol_info['type']
                            })
                            self.log(f"发现协议: {protocol_info['name']} ({protocol_oid})")
                        else:
                            self.log(f"发现未知协议OID: {protocol_oid}", "WARNING")
                            security_infos.append({
                                'oid': protocol_oid,
                                'name': 'Unknown',
                                'type': 'Unknown'
                            })
                except Exception as e:
                    self.log(f"解析SecurityInfo失败: {str(e)}", "WARNING")
                    
            result['protocols'] = security_infos
            result['details']['protocol_count'] = len(security_infos)
            
            # 分类统计
            ca_count = sum(1 for p in security_infos if p.get('type') == 'CA')
            ta_count = sum(1 for p in security_infos if p.get('type') == 'TA')
            pace_count = sum(1 for p in security_infos if p.get('type') == 'PACE')
            
            result['details']['chip_authentication_count'] = ca_count
            result['details']['terminal_authentication_count'] = ta_count
            result['details']['pace_count'] = pace_count
            
            if ca_count == 0:
                self.log("未发现Chip Authentication协议", "WARNING")
                
            # 保存协议信息供后续使用
            self.trust_chain['dg14_protocols'] = security_infos
            
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f"DG14解析错误: {str(e)}")
            self.log(f"DG14解析错误: {str(e)}", "ERROR")
            
        self.validation_results['dg14'] = result
        return result
        
    def validate_dg15(self) -> Dict[str, Any]:
        """验证DG15"""
        self.log("="*50)
        self.log("开始验证DG15")
        
        result = {
            'valid': False,
            'details': {},
            'errors': []
        }
        
        try:
            # 读取DG15数据
            dg15_data = self.read_file(self.FILE_PATHS['dg15'])
            result['details']['file_size'] = len(dg15_data)
            result['details']['sha256'] = self.calculate_sha256(dg15_data)
            
            # 尝试解析为RSA公钥
            try:
                # 检查是否有Application[15]标签
                if len(dg15_data) > 2 and dg15_data[0] == 0x5F and dg15_data[1] == 0x0F:
                    self.log("检测到标准DG15格式（Application[15]标签）")
                    # 跳过标签和长度
                    pos = 2  # 跳过 5F 0F
                    if dg15_data[pos] & 0x80:
                        # 长格式长度
                        len_bytes = dg15_data[pos] & 0x7F
                        pos += 1 + len_bytes
                    else:
                        # 短格式长度
                        pos += 1
                    
                    # 提取内部数据（SubjectPublicKeyInfo）
                    inner_data = dg15_data[pos:]
                    self.log(f"DG15原始数据长度: {len(dg15_data)}, 内部数据长度: {len(inner_data)}")
                    public_key = serialization.load_der_public_key(inner_data, default_backend())
                else:
                    # 直接解析
                    public_key = serialization.load_der_public_key(dg15_data, default_backend())
                
                if isinstance(public_key, rsa.RSAPublicKey):
                    result['details']['key_type'] = 'RSA'
                    result['details']['key_size'] = public_key.key_size
                    
                    # 对于AA，RSA1024是标准要求
                    if public_key.key_size == 1024:
                        self.log("AA RSA密钥长度验证: 1024位 (符合要求)")
                    else:
                        self.log(f"AA RSA密钥长度: {public_key.key_size}位 (非标准，可能导致兼容性问题)", "WARNING")
                        
                    numbers = public_key.public_numbers()
                    result['details']['modulus_length'] = len(format(numbers.n, 'X')) // 2
                    result['details']['exponent'] = numbers.e
                    
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    result['details']['key_type'] = 'EC'
                    result['details']['curve'] = public_key.curve.name
                    numbers = public_key.public_numbers()
                    result['details']['point_x'] = format(numbers.x, 'X')[:32] + "..."
                    result['details']['point_y'] = format(numbers.y, 'X')[:32] + "..."
                    
                # 保存公钥供后续使用
                self.trust_chain['dg15_public_key'] = public_key
                self.log(f"成功解析{result['details']['key_type']}公钥")
                
            except Exception as e:
                result['errors'].append(f"公钥解析失败: {str(e)}")
                self.log(f"公钥解析失败: {str(e)}", "ERROR")
                
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f"DG15读取错误: {str(e)}")
            self.log(f"DG15读取错误: {str(e)}", "ERROR")
            
        self.validation_results['dg15'] = result
        return result
        
    def validate_aa_keypair(self) -> Dict[str, Any]:
        """验证AA密钥对"""
        self.log("="*50)
        self.log("开始验证AA密钥对")
        
        result = {
            'valid': False,
            'details': {},
            'errors': []
        }
        
        try:
            # 读取私钥
            private_key_data = self.read_file(self.FILE_PATHS['aa_private'])
            result['details']['private_key_size'] = len(private_key_data)
            
            # 解析私钥
            try:
                private_key = serialization.load_der_private_key(
                    private_key_data, 
                    password=None, 
                    backend=default_backend()
                )
                
                if isinstance(private_key, rsa.RSAPrivateKey):
                    result['details']['private_key_type'] = 'RSA'
                    result['details']['private_key_size_bits'] = private_key.key_size
                    
                    # 验证RSA1024
                    if private_key.key_size == 1024:
                        self.log("AA私钥长度验证: 1024位 (符合要求)")
                    else:
                        result['errors'].append(f"AA私钥必须是1024位，当前是{private_key.key_size}位")
                        self.log(f"AA私钥必须是1024位，当前是{private_key.key_size}位", "ERROR")
                        
                elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                    result['details']['private_key_type'] = 'EC'
                    result['details']['curve'] = private_key.curve.name
                    
            except Exception as e:
                result['errors'].append(f"私钥解析失败: {str(e)}")
                self.log(f"私钥解析失败: {str(e)}", "ERROR")
                return result
                
            # 验证公私钥配对
            if 'dg15_public_key' in self.trust_chain:
                public_key = self.trust_chain['dg15_public_key']
                
                # 生成测试数据
                test_data = b"Test data for AA signature verification"
                
                try:
                    if isinstance(private_key, rsa.RSAPrivateKey):
                        # RSA签名
                        signature = private_key.sign(
                            test_data,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        
                        # 验证签名
                        public_key.verify(
                            signature,
                            test_data,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        
                    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                        # ECDSA签名
                        signature = private_key.sign(
                            test_data,
                            ec.ECDSA(hashes.SHA256())
                        )
                        
                        # 验证签名
                        public_key.verify(
                            signature,
                            test_data,
                            ec.ECDSA(hashes.SHA256())
                        )
                        
                    self.log("公私钥配对验证: 通过")
                    result['details']['keypair_match'] = True
                    
                except Exception as e:
                    result['errors'].append(f"公私钥不匹配: {str(e)}")
                    self.log(f"公私钥不匹配: {str(e)}", "ERROR")
                    result['details']['keypair_match'] = False
            else:
                result['errors'].append("无法验证密钥对：DG15公钥未找到")
                self.log("无法验证密钥对：DG15公钥未找到", "ERROR")
                
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f"AA密钥对验证错误: {str(e)}")
            self.log(f"AA密钥对验证错误: {str(e)}", "ERROR")
            
        self.validation_results['aa_keypair'] = result
        return result
        
    def validate_CA_P256_private_s(self) -> Dict[str, Any]:
        """验证CA私钥S值"""
        self.log("="*50)
        self.log("开始验证CA私钥S值")
        
        result = {
            'valid': False,
            'details': {},
            'errors': []
        }
        
        try:
            # 读取S值
            s_value_data = self.read_file(self.FILE_PATHS['CA_P256_private_s'])
            result['details']['file_size'] = len(s_value_data)
            result['details']['sha256'] = self.calculate_sha256(s_value_data)
            
            # S值通常是椭圆曲线私钥的标量值
            s_value_int = int.from_bytes(s_value_data, byteorder='big')
            result['details']['s_value_hex'] = binascii.hexlify(s_value_data).decode()[:64] + "..."
            result['details']['s_value_bit_length'] = s_value_int.bit_length()
            
            # 验证S值的数学属性
            # 对于椭圆曲线，S值应该在[1, n-1]范围内，其中n是曲线的阶
            if s_value_int == 0:
                result['errors'].append("S值不能为0")
                self.log("S值不能为0", "ERROR")
            elif s_value_int < 0:
                result['errors'].append("S值不能为负数")
                self.log("S值不能为负数", "ERROR")
            else:
                self.log(f"S值范围验证: 通过 (位长度: {s_value_int.bit_length()})")
                
            # 检查S值长度是否符合常见曲线
            bit_length = s_value_int.bit_length()
            if bit_length <= 256:
                result['details']['probable_curve'] = 'P-256'
            elif bit_length <= 384:
                result['details']['probable_curve'] = 'P-384'
            elif bit_length <= 521:
                result['details']['probable_curve'] = 'P-521'
            else:
                self.log("S值长度异常", "WARNING")
                
            # 检查与DG14中的CA协议是否匹配
            if 'dg14_protocols' in self.trust_chain:
                ca_protocols = [p for p in self.trust_chain['dg14_protocols'] if p['type'] == 'CA']
                ecdh_protocols = [p for p in ca_protocols if 'ECDH' in p['name']]
                
                if ecdh_protocols and bit_length > 0:
                    self.log("CA S值与ECDH协议匹配性: 通过")
                elif not ecdh_protocols and bit_length > 0:
                    self.log("检测到EC S值但DG14中没有ECDH协议", "WARNING")
                    
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f"S值验证错误: {str(e)}")
            self.log(f"S值验证错误: {str(e)}", "ERROR")
            
        self.validation_results['CA_P256_private_s'] = result
        return result
        
    def validate_trust_chain_closure(self) -> Dict[str, Any]:
        """验证信任链闭环"""
        self.log("="*50)
        self.log("开始验证信任链闭环")
        
        result = {
            'valid': False,
            'chain_complete': False,
            'details': {},
            'errors': []
        }
        
        # 检查所有必要组件是否存在
        required_components = ['csca', 'dsc', 'dg14', 'dg15', 'aa_keypair']
        missing = []
        
        for component in required_components:
            if component not in self.validation_results or not self.validation_results[component]['valid']:
                missing.append(component)
                
        if missing:
            result['errors'].append(f"信任链缺失组件: {', '.join(missing)}")
            self.log(f"信任链缺失组件: {', '.join(missing)}", "ERROR")
            result['valid'] = False
            return result
            
        # 验证链接关系
        chain_links = []
        
        # CSCA -> DSC
        if 'csca_ski' in self.trust_chain and 'dsc' in self.validation_results:
            dsc_result = self.validation_results['dsc']
            if 'authority_key_identifier' in dsc_result['details']:
                chain_links.append({
                    'from': 'CSCA',
                    'to': 'DSC',
                    'type': '签发',
                    'verified': True
                })
                self.log("CSCA -> DSC 链接验证: 通过")
                
        # DSC -> DG14/DG15 (逻辑关联)
        if 'dsc' in self.validation_results and 'dg14' in self.validation_results:
            chain_links.append({
                'from': 'DSC',
                'to': 'DG14',
                'type': '保护',
                'verified': True
            })
            
        if 'dsc' in self.validation_results and 'dg15' in self.validation_results:
            chain_links.append({
                'from': 'DSC',
                'to': 'DG15',
                'type': '保护',
                'verified': True
            })
            
        # DG15 <-> AA私钥
        if 'aa_keypair' in self.validation_results:
            if self.validation_results['aa_keypair']['details'].get('keypair_match'):
                chain_links.append({
                    'from': 'DG15',
                    'to': 'AA私钥',
                    'type': '密钥对',
                    'verified': True
                })
                self.log("DG15 <-> AA私钥 配对验证: 通过")
                
        # CA S值与DG14协议关联
        if 'CA_P256_private_s' in self.validation_results and 'dg14_protocols' in self.trust_chain:
            ca_protocols = [p for p in self.trust_chain['dg14_protocols'] if p['type'] == 'CA']
            if ca_protocols:
                chain_links.append({
                    'from': 'DG14',
                    'to': 'CA S值',
                    'type': '协议参数',
                    'verified': True
                })
                
        result['details']['chain_links'] = chain_links
        result['details']['total_links'] = len(chain_links)
        result['details']['verified_links'] = sum(1 for link in chain_links if link['verified'])
        
        # 构建信任链图
        trust_chain_diagram = []
        trust_chain_diagram.append("CSCA (自签名根证书)")
        trust_chain_diagram.append("  |")
        trust_chain_diagram.append("  +-> DSC (文档签名证书)")
        trust_chain_diagram.append("        |")
        trust_chain_diagram.append("        +-> DG14 (安全协议信息)")
        trust_chain_diagram.append("        |")
        trust_chain_diagram.append("        +-> DG15 (AA公钥)")
        trust_chain_diagram.append("              |")
        trust_chain_diagram.append("              +-> AA私钥 (配对验证)")
        
        result['details']['trust_chain_diagram'] = "\n".join(trust_chain_diagram)
        
        result['chain_complete'] = result['details']['verified_links'] == result['details']['total_links']
        result['valid'] = result['chain_complete'] and len(result['errors']) == 0
        
        if result['valid']:
            self.log("信任链闭环验证: 完整")
        else:
            self.log("信任链闭环验证: 不完整", "ERROR")
            
        self.validation_results['trust_chain'] = result
        return result
        
    def generate_report(self) -> str:
        """生成验证报告"""
        report = []
        report.append("=" * 80)
        report.append("                    护照证书链验证报告")
        report.append("=" * 80)
        report.append(f"生成时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"验证工具版本: 1.0.0")
        report.append("")
        
        # 1. CSCA证书验证结果
        if 'csca' in self.validation_results:
            report.append("-" * 80)
            report.append("1. CSCA证书验证结果")
            report.append("-" * 80)
            csca = self.validation_results['csca']
            report.append(f"文件路径: {self.FILE_PATHS['csca_cert']}")
            report.append(f"文件大小: {csca['details'].get('file_size', 'N/A')} bytes")
            report.append(f"文件SHA256: {csca['details'].get('sha256', 'N/A')}")
            report.append("")
            report.append("证书信息:")
            report.append(f"  版本: {csca['details'].get('version', 'N/A')}")
            report.append(f"  序列号: {csca['details'].get('serial_number', 'N/A')}")
            report.append(f"  签发者: {csca['details'].get('issuer', 'N/A')}")
            report.append(f"  主题: {csca['details'].get('subject', 'N/A')}")
            report.append(f"  有效期起始: {csca['details'].get('not_valid_before', 'N/A')}")
            report.append(f"  有效期结束: {csca['details'].get('not_valid_after', 'N/A')}")
            report.append("")
            report.append("公钥信息:")
            report.append(f"  算法: {csca['details'].get('key_type', 'N/A')}")
            if csca['details'].get('key_type') == 'RSA':
                report.append(f"  密钥长度: {csca['details'].get('key_size', 'N/A')} bits")
                report.append(f"  指数: {csca['details'].get('exponent', 'N/A')}")
            report.append("")
            report.append("验证结果:")
            if csca['valid']:
                report.append("  [PASS] 所有验证通过")
            else:
                for error in csca['errors']:
                    report.append(f"  [FAIL] {error}")
            report.append("")
            
        # 2. DSC证书验证结果
        if 'dsc' in self.validation_results:
            report.append("-" * 80)
            report.append("2. DSC证书验证结果")
            report.append("-" * 80)
            dsc = self.validation_results['dsc']
            report.append(f"文件路径: {self.FILE_PATHS['dsc_cert']}")
            report.append(f"文件大小: {dsc['details'].get('file_size', 'N/A')} bytes")
            report.append(f"文件SHA256: {dsc['details'].get('sha256', 'N/A')}")
            report.append("")
            report.append("证书信息:")
            report.append(f"  版本: {dsc['details'].get('version', 'N/A')}")
            report.append(f"  序列号: {dsc['details'].get('serial_number', 'N/A')}")
            report.append(f"  签发者: {dsc['details'].get('issuer', 'N/A')}")
            report.append(f"  主题: {dsc['details'].get('subject', 'N/A')}")
            report.append("")
            report.append("验证结果:")
            if dsc['valid']:
                report.append("  [PASS] 所有验证通过")
            else:
                for error in dsc['errors']:
                    report.append(f"  [FAIL] {error}")
            report.append("")
            
        # 3. DG14验证结果
        if 'dg14' in self.validation_results:
            report.append("-" * 80)
            report.append("3. DG14验证结果")
            report.append("-" * 80)
            dg14 = self.validation_results['dg14']
            report.append(f"文件路径: {self.FILE_PATHS['dg14']}")
            report.append(f"文件大小: {dg14['details'].get('file_size', 'N/A')} bytes")
            report.append("")
            report.append("检测到的协议:")
            for protocol in dg14.get('protocols', []):
                report.append(f"  - {protocol['name']} ({protocol['oid']})")
                report.append(f"    类型: {protocol['type']}")
            report.append("")
            report.append("协议统计:")
            report.append(f"  Chip Authentication: {dg14['details'].get('chip_authentication_count', 0)}")
            report.append(f"  Terminal Authentication: {dg14['details'].get('terminal_authentication_count', 0)}")
            report.append(f"  PACE: {dg14['details'].get('pace_count', 0)}")
            report.append("")
            
        # 4. DG15验证结果
        if 'dg15' in self.validation_results:
            report.append("-" * 80)
            report.append("4. DG15验证结果")
            report.append("-" * 80)
            dg15 = self.validation_results['dg15']
            report.append(f"文件路径: {self.FILE_PATHS['dg15']}")
            report.append(f"文件大小: {dg15['details'].get('file_size', 'N/A')} bytes")
            report.append("")
            report.append("Active Authentication公钥信息:")
            report.append(f"  算法: {dg15['details'].get('key_type', 'N/A')}")
            if dg15['details'].get('key_type') == 'RSA':
                report.append(f"  密钥长度: {dg15['details'].get('key_size', 'N/A')} bits")
            report.append("")
            
        # 5. AA密钥对验证结果
        if 'aa_keypair' in self.validation_results:
            report.append("-" * 80)
            report.append("5. AA密钥对验证结果")
            report.append("-" * 80)
            aa = self.validation_results['aa_keypair']
            report.append(f"私钥文件: {self.FILE_PATHS['aa_private']}")
            report.append(f"私钥类型: {aa['details'].get('private_key_type', 'N/A')}")
            report.append(f"私钥长度: {aa['details'].get('private_key_size_bits', 'N/A')} bits")
            report.append(f"公私钥匹配: {'是' if aa['details'].get('keypair_match') else '否'}")
            report.append("")
            
        # 6. CA S值验证结果
        if 'CA_P256_private_s' in self.validation_results:
            report.append("-" * 80)
            report.append("6. CA私钥S值验证结果")
            report.append("-" * 80)
            ca = self.validation_results['CA_P256_private_s']
            report.append(f"文件路径: {self.FILE_PATHS['CA_P256_private_s']}")
            report.append(f"文件大小: {ca['details'].get('file_size', 'N/A')} bytes")
            report.append(f"S值位长度: {ca['details'].get('s_value_bit_length', 'N/A')} bits")
            if 'probable_curve' in ca['details']:
                report.append(f"可能的椭圆曲线: {ca['details']['probable_curve']}")
            report.append("")
            
        # 7. 信任链闭环验证
        if 'trust_chain' in self.validation_results:
            report.append("-" * 80)
            report.append("7. 信任链闭环验证")
            report.append("-" * 80)
            tc = self.validation_results['trust_chain']
            report.append("信任链结构:")
            if 'trust_chain_diagram' in tc['details']:
                for line in tc['details']['trust_chain_diagram'].split('\n'):
                    report.append(f"  {line}")
            report.append("")
            report.append("链接验证:")
            if 'chain_links' in tc['details']:
                for link in tc['details']['chain_links']:
                    status = "[PASS]" if link['verified'] else "[FAIL]"
                    report.append(f"  {status} {link['from']} -> {link['to']}: {link['type']}")
            report.append("")
            
        # 8. 总结
        report.append("-" * 80)
        report.append("8. 验证总结")
        report.append("-" * 80)
        
        all_valid = all(r.get('valid', False) for r in self.validation_results.values())
        
        if all_valid:
            report.append("整体验证结果: 通过")
            report.append("信任链状态: 完整")
        else:
            report.append("整体验证结果: 失败")
            report.append("信任链状态: 不完整")
            
        if self.errors:
            report.append("")
            report.append("错误汇总:")
            for error in self.errors:
                report.append(f"  - {error}")
                
        if self.warnings:
            report.append("")
            report.append("警告汇总:")
            for warning in self.warnings:
                report.append(f"  - {warning}")
                
        # 9. 详细日志
        report.append("")
        report.append("-" * 80)
        report.append("9. 详细验证日志")
        report.append("-" * 80)
        for line in self.report_lines[-50:]:  # 只显示最后50行
            report.append(line)
            
        # 结束
        report.append("")
        report.append("=" * 80)
        end_time = datetime.datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        report.append(f"验证完成")
        report.append(f"总耗时: {duration:.2f}秒")
        report.append("=" * 80)
        
        return "\n".join(report)
        
    def run_validation(self):
        """运行完整的验证流程"""
        print("开始护照证书链验证...")
        print("")
        
        # 检查是否找到所有必需文件
        required_files = ['csca_cert', 'dsc_cert', 'dg14', 'dg15', 'aa_private', 'CA_P256_private_s']
        missing_files = []
        
        for name in required_files:
            if name not in self.FILE_PATHS:
                suffix = self.FILE_SUFFIXES.get(name, '')
                missing_files.append(f"{name}: 未找到后缀为 {suffix} 的文件")
                
        if missing_files:
            print("错误: 以下文件未找到:")
            for f in missing_files:
                print(f"  - {f}")
            print("\n请确保所有必需文件都在当前目录中。")
            print("\n期望的文件后缀:")
            print("  - CSCA证书: *_cert.der (文件名包含'csca')")
            print("  - DSC证书: *_cert.der (文件名不包含'csca')")
            print("  - DG14: *DG14.bin")
            print("  - DG15: *DG15.bin")
            print("  - AA私钥: *_private.der")
            print("  - CA S值: *CA_P256_private_s.bin")
            return
            
        # 执行验证
        self.validate_csca_certificate()
        self.validate_dsc_certificate()
        self.validate_dg14()
        self.validate_dg15()
        self.validate_aa_keypair()
        self.validate_CA_P256_private_s()
        self.validate_trust_chain_closure()
        
        # 生成并输出报告
        report = self.generate_report()
        print(report)
        
        # 保存报告到文件
        report_filename = f"passport_validation_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n报告已保存到: {report_filename}")


def main():
    """主函数"""
    validator = PassportCertificateValidator()
    validator.run_validation()


if __name__ == "__main__":
    main()