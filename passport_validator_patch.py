#!/usr/bin/env python3
"""
护照验证器补丁 - 修复DG15解析和AA证书链验证
可以直接导入到现有验证器中使用
"""

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import binascii


def validate_dg15_enhanced(self) -> dict:
    """
    增强版DG15验证 - 替换原有的validate_dg15方法
    正确处理DG15的ASN.1结构
    """
    self.log("="*50)
    self.log("开始验证DG15 (增强版)")
    
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
        
        self.log(f"DG15文件大小: {len(dg15_data)} bytes")
        self.log(f"前32字节: {binascii.hexlify(dg15_data[:32]).decode()}")
        
        # 解析DG15结构
        pos = 0
        spki_data = None
        
        # Step 1: 检查外层标签
        if dg15_data[0] == 0x6F:
            # 标准DG15格式 - Application[15]
            self.log("检测到标准DG15格式 (标签: 6F)")
            pos = 1
            # 解析长度
            length, len_bytes = self._parse_der_length(dg15_data[pos:])
            pos += len_bytes
            spki_data = dg15_data[pos:pos+length]
            
        elif dg15_data[0] == 0x5F and dg15_data[1] == 0x0F:
            # 扩展标签格式
            self.log("检测到扩展DG15格式 (标签: 5F0F)")
            pos = 2
            length, len_bytes = self._parse_der_length(dg15_data[pos:])
            pos += len_bytes
            spki_data = dg15_data[pos:pos+length]
            
        elif dg15_data[0] == 0x30:
            # 可能直接是SubjectPublicKeyInfo
            self.log("未检测到DG15标签，可能直接是SubjectPublicKeyInfo")
            spki_data = dg15_data
            
        else:
            # 尝试查找SEQUENCE标签
            self.log(f"未知格式，首字节: {hex(dg15_data[0])}")
            # 搜索SEQUENCE (0x30)
            for i in range(min(10, len(dg15_data))):
                if dg15_data[i] == 0x30:
                    self.log(f"在偏移{i}找到SEQUENCE标签")
                    spki_data = dg15_data[i:]
                    break
        
        if not spki_data:
            result['errors'].append("无法找到有效的SubjectPublicKeyInfo结构")
            self.log("错误: 无法找到有效的SubjectPublicKeyInfo结构", "ERROR")
        else:
            # Step 2: 解析公钥
            try:
                # 使用cryptography解析
                public_key = serialization.load_der_public_key(spki_data, default_backend())
                
                if isinstance(public_key, rsa.RSAPublicKey):
                    result['details']['key_type'] = 'RSA'
                    result['details']['key_size'] = public_key.key_size
                    numbers = public_key.public_numbers()
                    result['details']['modulus_length'] = numbers.n.bit_length()
                    result['details']['exponent'] = numbers.e
                    
                    # AA标准检查
                    if public_key.key_size == 1024:
                        self.log("RSA密钥长度: 1024位 (符合AA标准)")
                    else:
                        self.log(f"RSA密钥长度: {public_key.key_size}位 (警告: AA标准要求1024位)", "WARNING")
                        result['errors'].append(f"非标准RSA密钥长度: {public_key.key_size}位")
                    
                    # 显示模数前64位
                    mod_hex = format(numbers.n, 'X')
                    self.log(f"模数 (前64字符): {mod_hex[:64]}...")
                    self.log(f"指数: {numbers.e}")
                    
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    result['details']['key_type'] = 'EC'
                    result['details']['curve'] = public_key.curve.name
                    self.log(f"EC密钥曲线: {public_key.curve.name}")
                    
                # 保存公钥供后续使用
                self.trust_chain['dg15_public_key'] = public_key
                self.log(f"成功解析{result['details']['key_type']}公钥")
                result['valid'] = True
                
            except Exception as e:
                # 如果cryptography失败，尝试pyasn1
                self.log(f"Cryptography解析失败: {e}", "WARNING")
                self.log("尝试使用pyasn1解析...")
                
                try:
                    # 解析SubjectPublicKeyInfo
                    spki, _ = der_decoder.decode(spki_data)
                    
                    # 提取算法OID
                    if len(spki) >= 2 and len(spki[0]) >= 1:
                        oid = str(spki[0][0])
                        self.log(f"算法OID: {oid}")
                        
                        if oid == "1.2.840.113549.1.1.1":  # rsaEncryption
                            result['details']['key_type'] = 'RSA'
                            # 解析RSA公钥
                            key_bits = spki[1]
                            if isinstance(key_bits, univ.BitString):
                                key_bytes = key_bits.asOctets()
                                rsa_key, _ = der_decoder.decode(key_bytes)
                                if len(rsa_key) >= 2:
                                    modulus = int(rsa_key[0])
                                    exponent = int(rsa_key[1])
                                    result['details']['modulus_length'] = modulus.bit_length()
                                    result['details']['exponent'] = exponent
                                    self.log(f"pyasn1解析成功: RSA {modulus.bit_length()}位")
                                    result['valid'] = True
                                    
                except Exception as e2:
                    result['errors'].append(f"ASN.1解析失败: {str(e2)}")
                    self.log(f"ASN.1解析失败: {str(e2)}", "ERROR")
                    
    except Exception as e:
        result['errors'].append(f"DG15读取错误: {str(e)}")
        self.log(f"DG15读取错误: {str(e)}", "ERROR")
        
    self.validation_results['dg15'] = result
    return result


def _parse_der_length(self, data: bytes) -> tuple:
    """解析DER长度编码 - 辅助方法"""
    if not data:
        return 0, 0
        
    first_byte = data[0]
    if first_byte & 0x80 == 0:
        # 短格式
        return first_byte, 1
    else:
        # 长格式
        num_bytes = first_byte & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            raise ValueError(f"无效的长度编码: {num_bytes}")
        length = 0
        for i in range(num_bytes):
            if i + 1 >= len(data):
                raise ValueError("长度字节不足")
            length = (length << 8) | data[i + 1]
        return length, num_bytes + 1


def patch_validator(validator_class):
    """
    给现有的验证器类打补丁
    使用方法:
    from passport_validator_patch import patch_validator
    patch_validator(PassportCertificateValidator)
    """
    # 替换validate_dg15方法
    validator_class.validate_dg15 = validate_dg15_enhanced
    validator_class._parse_der_length = _parse_der_length
    print("✓ 验证器补丁已应用: DG15解析增强")


# 独立测试函数
def test_dg15_file(filename):
    """测试DG15文件解析"""
    print(f"\n测试DG15文件: {filename}")
    print("-" * 60)
    
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            
        print(f"文件大小: {len(data)} bytes")
        print(f"前32字节: {binascii.hexlify(data[:32]).decode()}")
        
        # 创建一个模拟的验证器实例
        class MockValidator:
            def log(self, msg, level="INFO"):
                print(f"[{level}] {msg}")
                
            def calculate_sha256(self, data):
                import hashlib
                return hashlib.sha256(data).hexdigest()
                
            def read_file(self, path):
                with open(path, 'rb') as f:
                    return f.read()
                    
            FILE_PATHS = {'dg15': filename}
            trust_chain = {}
            validation_results = {}
        
        validator = MockValidator()
        result = validate_dg15_enhanced(validator)
        
        print(f"\n解析结果: {'成功' if result['valid'] else '失败'}")
        if result['valid']:
            print(f"密钥类型: {result['details'].get('key_type', 'Unknown')}")
            if result['details'].get('key_type') == 'RSA':
                print(f"密钥长度: {result['details'].get('key_size', result['details'].get('modulus_length', 'Unknown'))} bits")
                print(f"公钥指数: {result['details'].get('exponent', 'Unknown')}")
        else:
            print("错误:")
            for error in result['errors']:
                print(f"  - {error}")
                
    except Exception as e:
        print(f"测试失败: {e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_dg15_file(sys.argv[1])
    else:
        print("用法: python passport_validator_patch.py <DG15文件路径>")