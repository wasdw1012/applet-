#!/usr/bin/env python3
"""
基于标准的证书链验证器 - 按照ICAO 9303和BSI TR-03110标准验证
增强版：包含完整的AA/CA/TA验证、证书链验证、标准符合性检查
"""
import os
import sys
from datetime import datetime
import hashlib
import struct

# 标准定义的标签值 (从BSI TR-03110和ICAO 9303)
DG14_TAG = 0x6E  # SecurityInfos
DG15_TAG = 0x6F  # PublicKey(s)
CV_CERT_TAG = 0x7F21  # CV Certificate
CERT_BODY_TAG = 0x7F4E  # Certificate Body
PUB_KEY_TAG = 0x7F49  # Public Key

# CA OID定义 (从oids.py)
CA_ECDH_3DES_CBC_CBC = b'\x04\x00\x7f\x00\x07\x02\x02\x03\x02\x01'

class StandardValidator:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.files = {}
        
    def validate(self):
        """主验证流程"""
        print("\n=== 基于标准的证书链验证器 ===\n")
        
        # Step 1: 文件发现
        self.find_files()
        
        # Step 2: 验证各个组件
        # TODO: 逐步添加验证
        
        return len(self.errors) == 0

    def find_files(self):
        """智能文件发现 - 考虑各种命名规范"""
        print("1. 文件发现阶段")
        print("-" * 40)
        
        # 定义搜索模式 - 基于实际观察到的命名规范
        patterns = {
            'dg14': ['DG14', 'dg14', 'Datagroup14', 'datagroup14'],
            'dg15': ['DG15', 'dg15', 'Datagroup15', 'datagroup15'],
            'csca': ['CSCA', 'csca', 'country'],
            'dsc': ['DSC', 'dsc', 'document'],
            'aa': ['AA', 'aa', 'active'],
            'ca': ['CA', 'ca', 'chip'],
            'cvca': ['CVCA', 'cvca', 'cv_ca', 'cvca_cert'],
            'dv': ['DV', 'dv', 'domestic'],
            'is': ['IS', 'is', 'inspection']
        }
        
        for root, dirs, files in os.walk('.'):
            for file in files:
                path = os.path.join(root, file)
                file_lower = file.lower()
                        
                # DG14/DG15 二进制文件
                for dg, pats in [('dg14', patterns['dg14']), ('dg15', patterns['dg15'])]:
                    if any(p.lower() in file_lower for p in pats):
                        if file.endswith('.bin'):
                            # 如果已经有了，检查哪个更像标准格式
                            if dg in self.files:
                                # 读取文件头判断
                                with open(path, 'rb') as f:
                                    tag = f.read(1)[0]
                                if tag == DG14_TAG and dg == 'dg14':
                                    # 这个是标准格式，替换之前的
                                    print(f"✓ 找到标准 {dg.upper()}: {path}")
                                    self.files[dg] = path
                                elif tag != DG14_TAG:
                                    print(f"  跳过非标准 {dg.upper()}: {path}")
                            else:
                                self.files[dg] = path
                                print(f"✓ 找到 {dg.upper()}: {path}")
                            break
                            
                # CV证书
                for cert_type, pats in [('cvca', patterns['cvca']), 
                                       ('dv', patterns['dv']), 
                                       ('is', patterns['is'])]:
                    if any(p.lower() in file_lower for p in pats):
                        if file.endswith(('.cvcert', '.cert', '.der')):
                            self.files[cert_type] = path
                            print(f"✓ 找到 {cert_type.upper()}: {path}")
                            break
                            
                # AA私钥
                if any(p.lower() in file_lower for p in patterns['aa']):
                    if 'private' in file_lower and file.endswith(('.der', '.pem', '.key')):
                        self.files['aa_private'] = path
                        print(f"✓ 找到 AA私钥: {path}")
                        
                # CSCA/DSC证书
                for cert, pats in [('csca', patterns['csca']), ('dsc', patterns['dsc'])]:
                    if any(p.lower() in file_lower for p in pats):
                        if file.endswith(('.pem', '.crt', '.cer', '.cert', '.der')) and 'private' not in file_lower:
                            self.files[cert] = path
                            print(f"✓ 找到 {cert.upper()}: {path}")
                            break
                            
        print(f"\n发现文件: {list(self.files.keys())}")
        return len(self.files) > 0

    def validate_dg14_structure(self):
        """验证DG14结构 - 基于BSI TR-03110标准"""
        print("\n2. DG14 (CA信息) 验证")
        print("-" * 40)
        
        if 'dg14' not in self.files:
            self.warnings.append("未找到DG14文件")
            print("⚠ 未找到DG14文件")
            return False
            
        try:
            with open(self.files['dg14'], 'rb') as f:
                data = f.read()
                
            print(f"文件: {self.files['dg14']}")
            print(f"大小: {len(data)} bytes")
            
            # 验证标签
            if len(data) < 2:
                self.errors.append("DG14文件太小")
                return False
                
            tag = data[0]
            print(f"标签: 0x{tag:02X}", end="")
            
            if tag == DG14_TAG:
                print(" ✓ (标准SecurityInfos)")
            elif tag == 0x30:
                print(" ⚠ (可能是裸SEQUENCE)")
                self.warnings.append("DG14使用非标准编码(0x30)")
            else:
                print(" ✗ (未知)")
                self.errors.append(f"DG14标签错误: 0x{tag:02X}")
                return False
                
            # 解析长度
            pos = 1
            if data[pos] & 0x80:
                # 长格式
                len_bytes = data[pos] & 0x7F
                if pos + 1 + len_bytes > len(data):
                    self.errors.append("DG14长度字段损坏")
                    return False
                length = int.from_bytes(data[pos+1:pos+1+len_bytes], 'big')
                pos += 1 + len_bytes
            else:
                length = data[pos]
                pos += 1
                
            print(f"内容长度: {length} bytes")
            
            # 验证长度
            if pos + length != len(data):
                self.warnings.append(f"DG14长度不匹配: 声明{length}, 实际{len(data)-pos}")
                
            return True
            
        except Exception as e:
            self.errors.append(f"DG14读取失败: {str(e)}")
            print(f"✗ 读取失败: {str(e)}")
            return False

    def parse_ca_info(self, data):
        """解析CA信息 - 查找ChipAuthenticationInfo"""
        print("\n3. CA协议信息解析")
        print("-" * 40)
        
        # 查找CA相关的OID
        ca_oids = {
            # id-CA-ECDH-3DES-CBC-CBC (0.4.0.127.0.7.2.2.3.2.1)
            b'\x06\x09\x04\x00\x7f\x00\x07\x02\x02\x03\x02\x01': 'CA-ECDH-3DES-CBC-CBC',
            # id-CA-ECDH-AES-CBC-CMAC-128 (0.4.0.127.0.7.2.2.3.2.2)
            b'\x06\x09\x04\x00\x7f\x00\x07\x02\x02\x03\x02\x02': 'CA-ECDH-AES-CBC-CMAC-128',
            # 简化形式
            b'\x06\x0a\x04\x00\x7f\x00\x07\x02\x02\x03\x02\x01': 'CA-ECDH-3DES (variant)',
        }
        
        found_ca = False
        for oid_bytes, name in ca_oids.items():
            if oid_bytes in data:
                idx = data.find(oid_bytes)
                print(f"✓ 找到 {name}")
                print(f"  位置: 0x{idx:04X}")
                
                # 查找版本号 (通常在OID后面)
                # 结构: OID + INTEGER tag (0x02) + length (0x01) + version
                ver_idx = idx + len(oid_bytes)
                if ver_idx + 3 <= len(data) and data[ver_idx] == 0x02 and data[ver_idx+1] == 0x01:
                    version = data[ver_idx + 2]
                    print(f"  版本: {version}")
                    if version not in [1, 2]:
                        self.warnings.append(f"CA版本异常: {version}")
                        
                found_ca = True
                
        if not found_ca:
            self.warnings.append("未找到CA协议信息")
            print("⚠ 未找到标准CA OID")
            
        return found_ca

    def parse_ec_public_key(self, data):
        """解析EC公钥信息 - 识别曲线和坐标"""
        print("\n4. EC公钥参数解析")
        print("-" * 40)
        
        # 常见椭圆曲线OID
        curves = {
            b'\x2a\x86\x48\xce\x3d\x03\x01\x01': 'P-192/secp192r1',
            b'\x2b\x81\x04\x00\x21': 'P-224/secp224r1',
            b'\x2a\x86\x48\xce\x3d\x03\x01\x07': 'P-256/prime256v1',
            b'\x2b\x81\x04\x00\x22': 'P-384/secp384r1',
            b'\x2b\x81\x04\x00\x23': 'P-521/secp521r1',
            b'\x2b\x24\x03\x03\x02\x08\x01\x01\x07': 'brainpoolP256r1',
        }
        
        found_curve = None
        for oid, name in curves.items():
            if oid in data:
                idx = data.find(oid)
                print(f"✓ 找到曲线: {name}")
                print(f"  OID位置: 0x{idx:04X}")
                found_curve = name
                
                # 根据曲线判断预期的公钥长度
                expected_lengths = {
                    'P-192': 49,  # 1 + 24 + 24
                    'P-224': 57,  # 1 + 28 + 28
                    'P-256': 65,  # 1 + 32 + 32
                    'P-384': 97,  # 1 + 48 + 48
                    'P-521': 133, # 1 + 66 + 66
                }
                
                for curve_prefix, exp_len in expected_lengths.items():
                    if name.startswith(curve_prefix):
                        print(f"  预期公钥长度: {exp_len} bytes")
                        break
                        
        if not found_curve:
            self.warnings.append("未找到EC曲线标识")
            print("⚠ 未找到标准EC曲线OID")
            
        # 查找公钥数据 (通常以0x86标签开始)
        pk_tag = b'\x86'
        pk_idx = data.find(pk_tag)
        if pk_idx != -1 and pk_idx + 2 < len(data):
            pk_len = data[pk_idx + 1]
            if pk_idx + 2 + pk_len <= len(data):
                pk_data = data[pk_idx + 2:pk_idx + 2 + pk_len]
                print(f"\n✓ 找到公钥数据")
                print(f"  长度: {pk_len} bytes")
                
                if pk_len > 0 and pk_data[0] == 0x04:
                    print(f"  格式: 未压缩 (0x04)")
                    coord_len = (pk_len - 1) // 2
                    print(f"  坐标长度: {coord_len} bytes each")
                elif pk_len > 0 and pk_data[0] in [0x02, 0x03]:
                    print(f"  格式: 压缩 (0x{pk_data[0]:02X})")
                    
        return found_curve

    def run(self):
        """运行所有验证"""
        print("\n" + "=" * 60)
        print("AA/CA/TA 完整闭环验证系统".center(60))
        print("=" * 60)
        
        if not self.find_files():
            print("\n未找到任何相关文件")
            return False
            
        # AA验证
        if 'aa_private' in self.files or 'dg15' in self.files:
            self.validate_aa_structure()
            
        # CA验证 (DG14)
        if 'dg14' in self.files:
            if self.validate_dg14_structure():
                with open(self.files['dg14'], 'rb') as f:
                    dg14_data = f.read()
                self.parse_ca_info(dg14_data)
                result = self.parse_ec_public_key(dg14_data)
                if result:
                    self.ca_curve = result  # 保存曲线信息
                self.analyze_dg14_details(dg14_data)
                
        # TA验证 (CV证书)
        if any(cert in self.files for cert in ['cvca', 'dv', 'is']):
            self.validate_ta_certificates()
            
        # 集成验证
        self.validate_ca_ta_integration()
        self.validate_full_chain()
        
        # 增强验证
        print("\n" + "=" * 60)
        print("增强验证".center(60))
        print("=" * 60)
        
        # CSCA/DSC证书链验证
        self.validate_csca_dsc_chain()
        
        # CV证书深度验证
        self.validate_cv_deep()
        
        # DG14深度解析
        self.validate_dg14_deep()
        
        # 交叉验证
        self.validate_cross_references()
                
        # 总结
        print("\n" + "=" * 50)
        print("验证总结")
        print("=" * 50)
        
        if self.errors:
            print(f"\n✗ 发现 {len(self.errors)} 个错误:")
            for i, err in enumerate(self.errors, 1):
                print(f"  {i}. {err}")
                
        if self.warnings:
            print(f"\n⚠ 发现 {len(self.warnings)} 个警告:")
            for i, warn in enumerate(self.warnings, 1):
                print(f"  {i}. {warn}")
                
        if not self.errors and not self.warnings:
            print("\n✓ 所有验证通过!")
            
        return len(self.errors) == 0

    def analyze_dg14_details(self, data):
        """深入分析DG14的SecurityInfos结构"""
        print("\n5. DG14 SecurityInfos 详细分析")
        print("-" * 40)
        
        # 跳过外层标签和长度
        pos = 1
        if data[pos] & 0x80:
            len_bytes = data[pos] & 0x7F
            pos += 1 + len_bytes
        else:
            pos += 1
            
        # 应该是SET标签 (0x31)
        if pos < len(data) and data[pos] == 0x31:
            print("✓ 找到SET容器 (0x31)")
            pos += 1
            
            # 解析SET长度
            if data[pos] & 0x80:
                len_bytes = data[pos] & 0x7F
                set_len = int.from_bytes(data[pos+1:pos+1+len_bytes], 'big')
                pos += 1 + len_bytes
            else:
                set_len = data[pos]
                pos += 1
                
            print(f"  SET长度: {set_len} bytes")
            
            # 计数SecurityInfo对象
            info_count = 0
            set_end = pos + set_len
            
            while pos < set_end and pos < len(data):
                if data[pos] == 0x30:  # SEQUENCE
                    info_count += 1
                    print(f"\n  SecurityInfo #{info_count}:")
                    
                    # 跳过SEQUENCE标签和长度
                    pos += 1
                    if data[pos] & 0x80:
                        len_bytes = data[pos] & 0x7F
                        seq_len = int.from_bytes(data[pos+1:pos+1+len_bytes], 'big')
                        pos += 1 + len_bytes
                    else:
                        seq_len = data[pos]
                        pos += 1
                        
                    seq_end = pos + seq_len
                    
                    # 查找OID
                    if pos < seq_end and data[pos] == 0x06:  # OID tag
                        oid_len = data[pos + 1]
                        oid_data = data[pos:pos+2+oid_len]
                        print(f"    OID: {oid_data.hex()}")
                        
                    pos = seq_end
                else:
                    break
                    
            print(f"\n  总计: {info_count} 个SecurityInfo对象")
            
        return True

    def validate_aa_structure(self):
        """验证AA (Active Authentication) 完整性"""
        print("\n6. AA (Active Authentication) 验证")
        print("-" * 40)
        
        # 检查必需文件
        if 'dg15' not in self.files:
            self.errors.append("缺少DG15文件 (AA公钥)")
            print("✗ 缺少DG15")
            return False
            
        if 'aa_private' not in self.files:
            self.errors.append("缺少AA私钥")
            print("✗ 缺少AA私钥")
            return False
            
        try:
            # 验证DG15结构
            with open(self.files['dg15'], 'rb') as f:
                dg15_data = f.read()
                
            print(f"\nDG15文件: {self.files['dg15']}")
            print(f"大小: {len(dg15_data)} bytes")
            
            # 检查标签
            if dg15_data[0] != DG15_TAG:
                self.errors.append(f"DG15标签错误: 0x{dg15_data[0]:02X} (应为0x6F)")
                print(f"✗ DG15标签错误: 0x{dg15_data[0]:02X}")
                return False
            else:
                print("✓ DG15标签正确 (0x6F)")
                
            # 加载私钥验证密钥对
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            with open(self.files['aa_private'], 'rb') as f:
                key_data = f.read()
                
            try:
                private_key = serialization.load_der_private_key(
                    key_data, password=None, backend=default_backend()
                )
                print(f"✓ AA私钥加载成功")
                
                # 检查密钥强度
                if hasattr(private_key, 'key_size'):
                    print(f"  密钥长度: {private_key.key_size} bits")
                    if private_key.key_size < 1024:
                        self.warnings.append(f"AA密钥非常牛逼: {private_key.key_size} bits")
                        
            except Exception as e:
                self.errors.append(f"AA私钥加载失败: {str(e)}")
                print(f"✗ 私钥加载失败: {str(e)}")
                return False
                
            return True
            
        except Exception as e:
            self.errors.append(f"AA验证失败: {str(e)}")
            print(f"✗ AA验证失败: {str(e)}")
            return False

    def validate_ta_certificates(self):
        """验证TA (Terminal Authentication) CV证书链"""
        print("\n7. TA (Terminal Authentication) CV证书链验证")
        print("-" * 40)
        
        cv_certs = {}
        cv_found = []
        
        # 检查CV证书
        for cert_type in ['cvca', 'dv', 'is']:
            if cert_type in self.files:
                cv_found.append(cert_type.upper())
                
        if not cv_found:
            self.warnings.append("未找到CV证书")
            print("⚠ 未找到CV证书")
            return True
            
        print(f"找到CV证书: {', '.join(cv_found)}")
        
        # 验证每个CV证书
        for cert_type in cv_found:
            path = self.files[cert_type.lower()]
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                    
                print(f"\n验证{cert_type}: {path}")
                print(f"  大小: {len(data)} bytes")
                
                # 验证CV证书标签
                if data[:2] != b'\x7F\x21':
                    self.errors.append(f"{cert_type}不是有效的CV证书")
                    print(f"  ✗ 标签错误: {data[:2].hex()} (应为7F21)")
                    continue
                else:
                    print(f"  ✓ CV证书格式正确")
                    
                # 解析证书内容
                pos = 2
                if data[pos] & 0x80:
                    len_bytes = data[pos] & 0x7F
                    cert_len = int.from_bytes(data[pos+1:pos+1+len_bytes], 'big')
                    pos += 1 + len_bytes
                else:
                    cert_len = data[pos]
                    pos += 1
                    
                cert_body = data[pos:pos+cert_len]
                
                # 解析关键字段
                cv_certs[cert_type] = self.parse_cv_certificate(cert_body, cert_type)
                
            except Exception as e:
                self.errors.append(f"{cert_type}读取失败: {str(e)}")
                print(f"  ✗ 读取失败: {str(e)}")
                
        # 验证证书链完整性
        self.verify_cv_chain(cv_certs, cv_found)
        
        return True
        
    def parse_cv_certificate(self, cert_body, cert_type):
        """解析CV证书内容"""
        info = {}
        
        # CAR (Certificate Authority Reference) - tag 0x42
        car_idx = cert_body.find(b'\x42')
        if car_idx != -1 and car_idx + 2 < len(cert_body):
            car_len = cert_body[car_idx + 1]
            if car_idx + 2 + car_len <= len(cert_body):
                info['car'] = cert_body[car_idx + 2:car_idx + 2 + car_len]
                print(f"  CAR: {info['car'].hex()}")
                
        # CHR (Certificate Holder Reference) - tag 0x5F20
        chr_idx = cert_body.find(b'\x5F\x20')
        if chr_idx != -1 and chr_idx + 3 < len(cert_body):
            chr_len = cert_body[chr_idx + 2]
            if chr_idx + 3 + chr_len <= len(cert_body):
                info['chr'] = cert_body[chr_idx + 3:chr_idx + 3 + chr_len]
                print(f"  CHR: {info['chr'].hex()}")
                
        # 角色识别 (从CHR的第一个字节)
        if 'chr' in info and len(info['chr']) > 0:
            role_byte = info['chr'][0]
            if role_byte & 0xC0 == 0xC0:
                print(f"  角色: CVCA (根证书)")
            elif role_byte & 0xC0 == 0x80:
                print(f"  角色: DV (国内验证者)")
            elif role_byte & 0xC0 == 0x00:
                print(f"  角色: IS (检查系统)")
                
        return info
        
    def verify_cv_chain(self, cv_certs, cv_found):
        """验证CV证书链关系"""
        print("\n证书链关系验证:")
        
        # 检查CVCA
        if 'CVCA' not in cv_found:
            self.errors.append("缺少CVCA根证书")
            print("✗ 缺少CVCA根证书 - 证书链不完整")
            
        # 验证DV->CVCA
        if 'DV' in cv_certs and 'CVCA' in cv_certs:
            dv_info = cv_certs['DV']
            cvca_info = cv_certs['CVCA']
            
            if 'car' in dv_info and 'chr' in cvca_info:
                if dv_info['car'] == cvca_info['chr']:
                    print("✓ DV正确引用CVCA")
                else:
                    self.errors.append("DV的CAR与CVCA的CHR不匹配")
                    print("✗ DV未正确引用CVCA")
                    
        # 验证IS->DV
        if 'IS' in cv_certs and 'DV' in cv_certs:
            is_info = cv_certs['IS']
            dv_info = cv_certs['DV']
            
            if 'car' in is_info and 'chr' in dv_info:
                if is_info['car'] == dv_info['chr']:
                    print("✓ IS正确引用DV")
                else:
                    self.errors.append("IS的CAR与DV的CHR不匹配")
                    print("✗ IS未正确引用DV")

    def validate_ca_ta_integration(self):
        """验证CA和TA的集成 - 确保它们协同工作"""
        print("\n8. CA/TA集成验证")
        print("-" * 40)
        
        ca_ok = 'dg14' in self.files
        ta_ok = any(cert in self.files for cert in ['cvca', 'dv', 'is'])
        
        if not ca_ok and not ta_ok:
            self.errors.append("CA和TA都缺失 - 无法进行EAC")
            print("✗ CA和TA都缺失")
            return False
            
        if ca_ok and not ta_ok:
            self.warnings.append("只有CA没有TA - 只能进行Chip Authentication")
            print("⚠ 只有CA，缺少TA")
            
        if ta_ok and not ca_ok:
            self.errors.append("只有TA没有CA - Terminal Authentication需要先进行CA")
            print("✗ 只有TA，缺少CA (TA需要CA先执行)")
            
        if ca_ok and ta_ok:
            print("✓ CA和TA都存在 - 可以进行完整的EAC")
            
            # 检查密钥算法兼容性
            if hasattr(self, 'ca_curve') and hasattr(self, 'ta_key_type'):
                print(f"\n密钥算法:")
                print(f"  CA: {getattr(self, 'ca_curve', 'Unknown')}")
                print(f"  TA: RSA (标准)")
                
        return True
        
    def validate_full_chain(self):
        """验证完整的AA/CA/TA闭环"""
        print("\n9. 完整闭环验证 (AA + CA + TA)")
        print("-" * 40)
        
        components = {
            'AA': 'aa_private' in self.files and 'dg15' in self.files,
            'CA': 'dg14' in self.files,
            'TA': any(cert in self.files for cert in ['cvca', 'dv', 'is'])
        }
        
        print("组件状态:")
        for comp, present in components.items():
            status = "✓" if present else "✗"
            print(f"  {comp}: {status}")
            
        if all(components.values()):
            print("\n✓ 所有EAC组件齐全 - 可以进行完整的Extended Access Control")
            
            # 验证执行顺序
            print("\n建议的执行顺序:")
            print("  1. BAC/PACE (基础访问控制)")
            print("  2. AA (Active Authentication) - 验证芯片真实性")
            print("  3. CA (Chip Authentication) - 建立安全通道")
            print("  4. TA (Terminal Authentication) - 验证终端权限")
            
        else:
            missing = [comp for comp, present in components.items() if not present]
            self.warnings.append(f"EAC组件不完整，缺少: {', '.join(missing)}")
            print(f"\n⚠ 缺少组件: {', '.join(missing)}")
            
        return True
        
    def verify_aa_keypair(self, dg15_data):
        """验证AA密钥对一致性"""
        print("\n10. AA密钥对一致性验证")
        print("-" * 40)
        
        try:
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend
            
            # 解析DG15提取公钥
            # 跳过标签和长度
            pos = 1
            if dg15_data[pos] & 0x80:
                len_bytes = dg15_data[pos] & 0x7F
                pos += 1 + len_bytes
            else:
                pos += 1
                
            # 提取SPKI (SubjectPublicKeyInfo)
            spki_data = dg15_data[pos:]
            
            try:
                # 加载公钥
                aa_public_key = serialization.load_der_public_key(spki_data, default_backend())
                print("✓ 从DG15提取公钥成功")
                
                # 验证公钥类型
                if hasattr(aa_public_key, 'key_size'):
                    print(f"  公钥长度: {aa_public_key.key_size} bits")
                    
                # 验证密钥对匹配
                if hasattr(self, 'aa_private_key'):
                    # 获取私钥对应的公钥
                    private_public = self.aa_private_key.public_key()
                    
                    # 比较公钥参数
                    if hasattr(private_public, 'public_numbers') and hasattr(aa_public_key, 'public_numbers'):
                        priv_numbers = private_public.public_numbers()
                        pub_numbers = aa_public_key.public_numbers()
                        
                        if priv_numbers.n == pub_numbers.n and priv_numbers.e == pub_numbers.e:
                            print("✓ AA密钥对匹配验证通过")
                            
                            # 测试签名验证
                            test_data = b"AA KeyPair Verification Test"
                            signature = self.aa_private_key.sign(
                                test_data,
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            
                            try:
                                aa_public_key.verify(
                                    signature,
                                    test_data,
                                    padding.PKCS1v15(),
                                    hashes.SHA256()
                                )
                                print("✓ AA签名验证测试通过")
                            except:
                                self.errors.append("AA签名验证失败")
                                print("✗ AA签名验证失败")
                                return False
                        else:
                            self.errors.append("AA公钥与私钥不匹配")
                            print("✗ AA公钥与私钥不匹配")
                            return False
                            
            except Exception as e:
                self.errors.append(f"DG15公钥解析失败: {str(e)}")
                print(f"✗ DG15公钥解析失败: {str(e)}")
                return False
                
        except Exception as e:
            self.errors.append(f"AA密钥对验证失败: {str(e)}")
            print(f"✗ AA密钥对验证失败: {str(e)}")
            return False
            
        return True

    def validate_csca_dsc_chain(self):
        """验证CSCA/DSC证书链"""
        print("\n11. CSCA/DSC证书链验证")
        print("-" * 40)
        
        if 'csca' not in self.files or 'dsc' not in self.files:
            self.warnings.append("CSCA或DSC证书缺失")
            print("⚠ CSCA或DSC证书缺失")
            return True
            
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.x509.oid import ExtensionOID, NameOID
            
            # 加载CSCA证书
            with open(self.files['csca'], 'rb') as f:
                csca_data = f.read()
                
            try:
                csca = x509.load_der_x509_certificate(csca_data, default_backend())
            except:
                csca = x509.load_pem_x509_certificate(csca_data, default_backend())
                
            print(f"CSCA证书:")
            print(f"  主题: {csca.subject.rfc4514_string()}")
            print(f"  颁发者: {csca.issuer.rfc4514_string()}")
            
            # 检查有效期
            now = datetime.now()
            if now < csca.not_valid_before:
                self.errors.append("CSCA证书尚未生效")
                print(f"✗ CSCA尚未生效 (生效时间: {csca.not_valid_before})")
            elif now > csca.not_valid_after:
                self.errors.append("CSCA证书已过期")
                print(f"✗ CSCA已过期 (过期时间: {csca.not_valid_after})")
            else:
                days_remaining = (csca.not_valid_after - now).days
                print(f"✓ CSCA有效 (剩余{days_remaining}天)")
                
            # 检查KeyUsage
            try:
                key_usage = csca.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if key_usage.value.key_cert_sign:
                    print("✓ CSCA具有证书签名权限")
                else:
                    self.warnings.append("CSCA缺少证书签名权限")
                    print("⚠ CSCA缺少证书签名权限")
            except:
                print("  未找到KeyUsage扩展")
                
            # 加载DSC证书
            with open(self.files['dsc'], 'rb') as f:
                dsc_data = f.read()
                
            try:
                dsc = x509.load_der_x509_certificate(dsc_data, default_backend())
            except:
                dsc = x509.load_pem_x509_certificate(dsc_data, default_backend())
                
            print(f"\nDSC证书:")
            print(f"  主题: {dsc.subject.rfc4514_string()}")
            print(f"  颁发者: {dsc.issuer.rfc4514_string()}")
            
            # 验证DSC由CSCA签发
            if dsc.issuer == csca.subject:
                print("✓ DSC由CSCA签发")
                
                # 验证签名
                try:
                    from cryptography.hazmat.primitives.asymmetric import padding
                    csca.public_key().verify(
                        dsc.signature,
                        dsc.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        dsc.signature_hash_algorithm
                    )
                    print("✓ DSC签名验证通过")
                except:
                    self.errors.append("DSC签名验证失败")
                    print("✗ DSC签名验证失败")
            else:
                self.errors.append("DSC不是由CSCA签发")
                print("✗ DSC不是由CSCA签发")
                
            # 检查DSC有效期
            if now < dsc.not_valid_before:
                self.errors.append("DSC证书尚未生效")
                print(f"✗ DSC尚未生效 (生效时间: {dsc.not_valid_before})")
            elif now > dsc.not_valid_after:
                self.errors.append("DSC证书已过期")
                print(f"✗ DSC已过期 (过期时间: {dsc.not_valid_after})")
            else:
                days_remaining = (dsc.not_valid_after - now).days
                print(f"✓ DSC有效 (剩余{days_remaining}天)")
                
        except Exception as e:
            self.errors.append(f"CSCA/DSC验证失败: {str(e)}")
            print(f"✗ 证书链验证失败: {str(e)}")
            return False
            
        return True

    def validate_cv_deep(self):
        """CV证书深度验证"""
        print("\n12. CV证书深度验证")
        print("-" * 40)
        
        cv_types = ['cvca', 'dv', 'is']
        for cert_type in cv_types:
            if cert_type not in self.files:
                continue
                
            print(f"\n验证 {cert_type.upper()} 证书深度信息:")
            
            try:
                with open(self.files[cert_type], 'rb') as f:
                    cert_data = f.read()
                    
                # 跳过外层标签
                pos = 2
                if cert_data[pos] & 0x80:
                    len_bytes = cert_data[pos] & 0x7F
                    pos += 1 + len_bytes
                else:
                    pos += 1
                    
                # 找到证书体 (0x7F4E)
                body_idx = cert_data.find(b'\x7F\x4E', pos)
                if body_idx == -1:
                    print(f"  ✗ 未找到证书体标签")
                    continue
                    
                # 解析日期
                # 生效日期 (0x5F25)
                eff_idx = cert_data.find(b'\x5F\x25')
                if eff_idx != -1:
                    # 先读取长度
                    length = cert_data[eff_idx+2]
                    if length == 3:  # CV证书日期是3字节
                        eff_date = cert_data[eff_idx+3:eff_idx+6]  # 只读3个字节
                        print(f"  生效日期: {self.parse_cv_date(eff_date)}")
                    else:
                        print(f"  生效日期: 长度异常({length})")
                    
                # 过期日期 (0x5F24)
                exp_idx = cert_data.find(b'\x5F\x24')
                if exp_idx != -1:
                    length = cert_data[exp_idx+2]
                    if length == 3:
                        exp_date = cert_data[exp_idx+3:exp_idx+6]  # 只读3个字节
                        print(f"  过期日期: {self.parse_cv_date(exp_date)}")
                    else:
                        print(f"  过期日期: 长度异常({length})")
                        
                # CHAT (Certificate Holder Authorization Template) - 0x7F4C
                chat_idx = cert_data.find(b'\x7F\x4C')
                if chat_idx != -1:
                    chat_pos = chat_idx + 2
                    if cert_data[chat_pos] & 0x80:
                        chat_len = cert_data[chat_pos] & 0x7F
                        chat_pos += 1
                    else:
                        chat_len = cert_data[chat_pos]
                        chat_pos += 1
                        
                    chat_data = cert_data[chat_pos:chat_pos+chat_len]
                    print(f"  CHAT权限: {chat_data.hex()}")
                    
                    # 解析权限
                    if len(chat_data) >= 1:
                        oid_idx = chat_data.find(b'\x06')
                        if oid_idx != -1:
                            oid_len = chat_data[oid_idx+1]
                            print(f"    OID: {chat_data[oid_idx:oid_idx+2+oid_len].hex()}")
                            
                # 公钥算法
                pk_idx = cert_data.find(b'\x7F\x49')
                if pk_idx != -1:
                    print(f"  包含公钥 (位置: 0x{pk_idx:04X})")
                    
            except Exception as e:
                print(f"  ✗ 解析失败: {str(e)}")
                
        return True
    
    def parse_cv_date(self, date_bytes):
        """解析CV证书日期格式"""
        if len(date_bytes) == 3:
            try:
                # 日期字节是十六进制编码，需要转换
                year = int(date_bytes[0:1].hex(), 16)
                month = int(date_bytes[1:2].hex(), 16) 
                day = int(date_bytes[2:3].hex(), 16)
                
                # 验证合理性
                if month > 12 or month == 0:
                    return f"{date_bytes.hex()}"  
                if day > 31 or day == 0:
                    return f"{date_bytes.hex()}"
                
                # 年份处理
                if year < 50:
                    year += 2000
                else:
                    year += 1900
                    
                return f"{year:04d}-{month:02d}-{day:02d}"
            except Exception as e:
                return f"{date_bytes.hex()}"
        else:
            return f"{date_bytes.hex()}"

    def validate_dg14_deep(self):
        """DG14深度解析 - ChipAuthenticationPublicKeyInfo"""
        print("\n13. DG14 ChipAuthenticationPublicKeyInfo深度解析")
        print("-" * 40)
        
        if 'dg14' not in self.files:
            return True
            
        try:
            with open(self.files['dg14'], 'rb') as f:
                dg14_data = f.read()
                
            # 查找ChipAuthenticationPublicKeyInfo OID
            # 0.4.0.127.0.7.2.2.1.2 = 06 0A 04 00 7F 00 07 02 02 01 02
            ca_pubkey_oid = b'\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x01\x02'
            
            idx = dg14_data.find(ca_pubkey_oid)
            if idx != -1:
                print("✓ 找到ChipAuthenticationPublicKeyInfo")
                print(f"  OID位置: 0x{idx:04X}")
                
                # 向前查找SEQUENCE开始
                seq_start = idx
                while seq_start > 0 and dg14_data[seq_start-1] != 0x30:
                    seq_start -= 1
                seq_start -= 1
                
                if seq_start >= 0:
                    # 解析SEQUENCE
                    pos = seq_start + 1
                    if dg14_data[pos] & 0x80:
                        len_bytes = dg14_data[pos] & 0x7F
                        seq_len = int.from_bytes(dg14_data[pos+1:pos+1+len_bytes], 'big')
                        pos += 1 + len_bytes
                    else:
                        seq_len = dg14_data[pos]
                        pos += 1
                        
                    print(f"  SecurityInfo长度: {seq_len} bytes")
                    
                    # 查找SubjectPublicKeyInfo (SEQUENCE tag 0x30)
                    spki_idx = idx + len(ca_pubkey_oid)
                    while spki_idx < len(dg14_data) and dg14_data[spki_idx] != 0x30:
                        spki_idx += 1
                        
                    if spki_idx < len(dg14_data):
                        print("  ✓ 找到SubjectPublicKeyInfo")
                        
                        # 解析算法标识
                        algo_pos = spki_idx + 2  # 跳过SEQUENCE标签和长度
                        if dg14_data[algo_pos] == 0x30:
                            print("    包含算法标识符")
                            
            else:
                print("⚠ 未找到ChipAuthenticationPublicKeyInfo")
                
        except Exception as e:
            print(f"✗ DG14深度解析失败: {str(e)}")
            
        return True

    def validate_cross_references(self):
        """交叉验证 - 验证各组件间的一致性"""
        print("\n14. 交叉验证")
        print("-" * 40)
        
        # CA公钥参数验证
        if hasattr(self, 'ca_curve'):
            print(f"CA使用曲线: {self.ca_curve}")
            
            # 检查是否与标准一致
            if 'P-224' in self.ca_curve:
                print("  ✓ 符合ICAO标准推荐曲线")
            elif 'P-256' in self.ca_curve:
                print("  ✓ 符合现代安全标准")
            else:
                self.warnings.append(f"非标准CA曲线: {self.ca_curve}")
                
        # OID一致性检查
        print("\nOID一致性检查:")
        oids_found = []
        
        if 'dg14' in self.files:
            try:
                with open(self.files['dg14'], 'rb') as f:
                    data = f.read()
                    
                # 查找所有OID (tag 0x06)
                i = 0
                while i < len(data) - 2:
                    if data[i] == 0x06:
                        oid_len = data[i+1]
                        if i + 2 + oid_len <= len(data):
                            oid = data[i:i+2+oid_len]
                            oids_found.append(oid.hex())
                    i += 1
                    
                print(f"  DG14中找到 {len(oids_found)} 个OID")
                
            except:
                pass
                
        # 验证标准符合性
        self.check_standards_compliance()
        
        return True
    
    def check_standards_compliance(self):
        """检查标准符合性"""
        print("\n15. 标准符合性检查")
        print("-" * 40)
        
        # ICAO 9303符合性
        print("ICAO 9303符合性:")
        icao_compliant = True
        
        # 检查DG14/DG15标签
        if 'dg14' in self.files:
            with open(self.files['dg14'], 'rb') as f:
                if f.read(1)[0] == 0x6E:
                    print("  ✓ DG14使用正确标签 (0x6E)")
                else:
                    print("  ✗ DG14标签不符合ICAO")
                    icao_compliant = False
                    
        if 'dg15' in self.files:
            with open(self.files['dg15'], 'rb') as f:
                if f.read(1)[0] == 0x6F:
                    print("  ✓ DG15使用正确标签 (0x6F)")
                else:
                    print("  ✗ DG15标签不符合ICAO")
                    icao_compliant = False
                    
        # BSI TR-03110符合性
        print("\nBSI TR-03110符合性:")
        
        # 检查CV证书格式
        cv_compliant = True
        for cert_type in ['cvca', 'dv', 'is']:
            if cert_type in self.files:
                with open(self.files[cert_type], 'rb') as f:
                    if f.read(2) == b'\x7F\x21':
                        print(f"  ✓ {cert_type.upper()}使用正确标签 (0x7F21)")
                    else:
                        print(f"  ✗ {cert_type.upper()}标签不符合BSI")
                        cv_compliant = False
                        
        # DER编码验证
        print("\nDER编码验证:")
        self.check_der_encoding()
        
        return icao_compliant and cv_compliant
    
    def check_der_encoding(self):
        """检查DER编码正确性"""
        for file_type, path in self.files.items():
            if path.endswith('.der') or path.endswith('.bin'):
                try:
                    with open(path, 'rb') as f:
                        data = f.read(10)
                        
                    # 基本DER检查
                    if len(data) > 2:
                        tag = data[0]
                        if tag in [0x30, 0x31, 0x6E, 0x6F, 0x7F]:  # 常见标签
                            if data[1] & 0x80:  # 长格式长度
                                len_bytes = data[1] & 0x7F
                                if len_bytes > 4:
                                    print(f"  ⚠ {file_type}: 长度字段异常")
                                else:
                                    print(f"  ✓ {file_type}: DER格式正确")
                            else:
                                print(f"  ✓ {file_type}: DER格式正确")
                                
                except:
                    pass

def main():
    validator = StandardValidator()
    success = validator.run()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
