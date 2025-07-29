import os
import sys
import subprocess
import secrets
import glob
import random
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pyasn1.type import univ, namedtype, char
from pyasn1.codec.der import encoder, decoder
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding

# 国家数据字典（保持不变）
COUNTRY_DATA = {
    # ... 保持原有的国家数据 ...
}

# ... 其他字典和辅助函数保持不变 ...

class UnifiedCertChainGenerator:
    """统一证书链（移除TA，保留CA）"""
    
    def __init__(self, custom_timestamp=None, org_code=None):
        self.country_2 = None
        self.specific_issuing_authority = None
        self.output_dir = None
        self.csca_private_key = None
        self.csca_cert = None
        self.dsc_private_key = None
        self.dsc_cert = None
        self.aa_keys = {}
        self.custom_timestamp = custom_timestamp
        self.org_code = org_code
        self.ca_ec_keys = {}  # 保留CA密钥
        # 移除了：cvca, dv, is 相关的属性

    # ... 保持原有的基础方法 ...
    
    def generate_eac_components(self):
        """生成EAC组件（仅CA，不含TA）"""
        print("\n 生成EAC组件")
        
        # 只生成CA密钥和DG14，不生成CV证书链
        self.generate_ca_ec_keys()
        self.generate_dg14_file()
        
        print("✓ CA/DG14 生成完成")
    
    # 移除以下方法：
    # - generate_cvca_certificate
    # - generate_dv_certificate  
    # - generate_is_certificate
    # - CVCertificate 类
    
    def generate_ca_ec_keys(self):
        """生成CA的EC P-256密钥对"""
        print("  → 生成CA密钥对 (EC P-256)...")
        
        # 生成P-256密钥
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # 保存私钥（DER格式，用于阶段零注入）
        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 获取公钥点
        public_numbers = public_key.public_numbers()
        x_bytes = public_numbers.x.to_bytes(32, 'big')
        y_bytes = public_numbers.y.to_bytes(32, 'big')
        public_point = b'\x04' + x_bytes + y_bytes
        
        self.ca_ec_keys = {
            'private': private_key,
            'public': public_key,
            'private_der': private_der,
            'public_point': public_point
        }
        
        # 保存文件...
        
    def generate_dg14_file(self):
        """生成DG14（仅包含CA信息）"""
        print("  → 生成DG14文件...")
        
        ca_public_key = self.ca_ec_keys['public']
        
        # 构建DG14...（保持原有逻辑）