#!/usr/bin/env python3
"""
DG15 Parser Fix - 正确解析DG15并提取AA公钥
根据ICAO 9303标准实现
"""

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ, namedtype, tag, char
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import binascii


class DG15Parser:
    """正确的DG15解析器"""
    
    # DG15 标签定义 (ICAO 9303 Part 10)
    DG15_TAG = 0x6F  # Application[15]
    
    def parse_dg15(self, dg15_data: bytes) -> dict:
        """
        解析DG15数据并提取公钥
        
        DG15结构 (根据ICAO 9303):
        6F - Application[15]
          [length]
          30 - SEQUENCE (SubjectPublicKeyInfo)
            30 - SEQUENCE (AlgorithmIdentifier)
              06 - OID
              ... parameters ...
            03 - BIT STRING (subjectPublicKey)
              00 - unused bits
              [actual public key data]
        """
        result = {
            'success': False,
            'public_key': None,
            'key_type': None,
            'key_details': {},
            'raw_spki': None,
            'errors': []
        }
        
        try:
            # Step 1: 检查并跳过DG15标签
            pos = 0
            if len(dg15_data) < 3:
                result['errors'].append("DG15数据太短")
                return result
                
            # 检查Application[15]标签 (0x6F或0x5F0F)
            if dg15_data[0] == 0x6F:
                # 短标签格式
                pos = 1
                tag_desc = "6F (Application[15])"
            elif dg15_data[0] == 0x5F and dg15_data[1] == 0x0F:
                # 长标签格式
                pos = 2
                tag_desc = "5F0F (Application[15])"
            else:
                # 可能没有外层标签，直接是SubjectPublicKeyInfo
                pos = 0
                tag_desc = "无外层标签"
                
            print(f"DG15标签: {tag_desc}")
            
            # Step 2: 解析长度
            if pos > 0:
                length, length_bytes = self._parse_length(dg15_data[pos:])
                pos += length_bytes
                print(f"DG15内容长度: {length} bytes")
            
            # Step 3: 提取SubjectPublicKeyInfo
            spki_data = dg15_data[pos:]
            result['raw_spki'] = spki_data
            
            # Step 4: 使用cryptography解析公钥
            try:
                public_key = serialization.load_der_public_key(spki_data, default_backend())
                result['public_key'] = public_key
                result['success'] = True
                
                # 提取密钥详情
                if isinstance(public_key, rsa.RSAPublicKey):
                    result['key_type'] = 'RSA'
                    numbers = public_key.public_numbers()
                    result['key_details'] = {
                        'key_size': public_key.key_size,
                        'modulus_bits': numbers.n.bit_length(),
                        'exponent': numbers.e,
                        'modulus_hex': format(numbers.n, 'X')[:64] + '...' if len(format(numbers.n, 'X')) > 64 else format(numbers.n, 'X')
                    }
                    print(f"成功解析RSA公钥: {public_key.key_size} bits")
                    
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    result['key_type'] = 'EC'
                    numbers = public_key.public_numbers()
                    result['key_details'] = {
                        'curve': public_key.curve.name,
                        'x': format(numbers.x, 'X')[:32] + '...',
                        'y': format(numbers.y, 'X')[:32] + '...'
                    }
                    print(f"成功解析EC公钥: {public_key.curve.name}")
                    
            except Exception as e:
                # 如果cryptography解析失败，尝试手动解析ASN.1
                print(f"Cryptography解析失败: {e}")
                print("尝试手动ASN.1解析...")
                self._manual_parse_spki(spki_data, result)
                
        except Exception as e:
            result['errors'].append(f"DG15解析错误: {str(e)}")
            print(f"错误: {e}")
            
        return result
    
    def _parse_length(self, data: bytes) -> tuple:
        """解析DER长度编码"""
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
    
    def _manual_parse_spki(self, spki_data: bytes, result: dict):
        """手动解析SubjectPublicKeyInfo结构"""
        try:
            # 使用pyasn1解析
            spki, remainder = der_decoder.decode(spki_data)
            
            if len(spki) >= 2:
                # spki[0] 是 AlgorithmIdentifier
                # spki[1] 是 subjectPublicKey (BIT STRING)
                
                # 获取算法OID
                if len(spki[0]) >= 1:
                    oid = str(spki[0][0])
                    print(f"算法OID: {oid}")
                    
                    if oid == "1.2.840.113549.1.1.1":  # RSA
                        result['key_type'] = 'RSA'
                        # 解析RSA公钥
                        key_bits = spki[1]
                        if isinstance(key_bits, univ.BitString):
                            key_bytes = key_bits.asOctets()
                            # RSA公钥是一个SEQUENCE包含modulus和exponent
                            rsa_key, _ = der_decoder.decode(key_bytes)
                            if len(rsa_key) >= 2:
                                modulus = int(rsa_key[0])
                                exponent = int(rsa_key[1])
                                result['key_details'] = {
                                    'modulus_bits': modulus.bit_length(),
                                    'exponent': exponent
                                }
                                result['success'] = True
                                print(f"手动解析成功: RSA {modulus.bit_length()} bits")
                                
        except Exception as e:
            result['errors'].append(f"手动ASN.1解析失败: {str(e)}")


def fix_dg15_parsing(validator_instance):
    """
    修复现有验证器的DG15解析
    这个函数可以直接替换或增强现有的validate_dg15方法
    """
    parser = DG15Parser()
    
    # 读取DG15文件
    if 'dg15' not in validator_instance.FILE_PATHS:
        print("错误: 未找到DG15文件")
        return None
        
    dg15_path = validator_instance.FILE_PATHS['dg15']
    print(f"\n解析DG15文件: {dg15_path}")
    print("-" * 50)
    
    try:
        with open(dg15_path, 'rb') as f:
            dg15_data = f.read()
            
        print(f"文件大小: {len(dg15_data)} bytes")
        print(f"前16字节: {binascii.hexlify(dg15_data[:16]).decode()}")
        
        # 解析DG15
        result = parser.parse_dg15(dg15_data)
        
        if result['success']:
            print("\n✓ DG15解析成功!")
            print(f"密钥类型: {result['key_type']}")
            print(f"密钥详情: {result['key_details']}")
            
            # 更新验证器的信任链
            validator_instance.trust_chain['dg15_public_key'] = result['public_key']
            
            # 更新验证结果
            if 'dg15' not in validator_instance.validation_results:
                validator_instance.validation_results['dg15'] = {}
                
            validator_instance.validation_results['dg15'].update({
                'valid': True,
                'details': {
                    'key_type': result['key_type'],
                    **result['key_details']
                }
            })
        else:
            print("\n✗ DG15解析失败!")
            for error in result['errors']:
                print(f"  - {error}")
                
        return result
        
    except Exception as e:
        print(f"文件读取错误: {e}")
        return None


# 测试函数
if __name__ == "__main__":
    # 测试DG15解析
    parser = DG15Parser()
    
    # 测试数据示例 (您可以用实际的DG15数据替换)
    test_dg15_rsa = bytes.fromhex(
        "6F81A0"  # Application[15], length 160
        "3081A0"  # SEQUENCE (SubjectPublicKeyInfo)
        "300D"    # SEQUENCE (AlgorithmIdentifier)
        "0609"    # OID
        "2A864886F70D010101"  # rsaEncryption
        "0500"    # NULL
        "03818E00"  # BIT STRING
        "30818902818100"  # RSA public key...
    )
    
    result = parser.parse_dg15(test_dg15_rsa)
    print(f"测试结果: {result}")