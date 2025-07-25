#!/usr/bin/env python3
"""
生成测试数据用于护照证书链验证脚本测试
注意：这些是测试数据，不能用于实际的护照验证！
"""

import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ, namedtype, tag
import datetime


def generate_csca_certificate():
    """生成测试用CSCA证书"""
    print("生成CSCA证书...")
    
    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # 创建证书
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Country"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CSCA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).sign(private_key, hashes.SHA256(), backend=default_backend())
    
    # 保存证书
    with open("csca_cert.der", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
        
    # 保存私钥（用于签发DSC）
    with open("csca_private.der", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    print("CSCA证书已生成: csca_cert.der")
    return cert, private_key


def generate_dsc_certificate(csca_cert, csca_private_key):
    """生成测试用DSC证书"""
    print("生成DSC证书...")
    
    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 创建证书
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Country"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test DSC"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        csca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(csca_cert.public_key()),
        critical=False,
    ).sign(csca_private_key, hashes.SHA256(), backend=default_backend())
    
    # 保存证书
    with open("dsc_cert.der", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
        
    print("DSC证书已生成: dsc_cert.der")
    return cert, private_key


def generate_dg14():
    """生成测试用DG14数据"""
    print("生成DG14数据...")
    
    # SecurityInfo结构
    class SecurityInfo(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('protocol', univ.ObjectIdentifier()),
            namedtype.NamedType('requiredData', univ.Any()),
            namedtype.OptionalNamedType('optionalData', univ.Any())
        )
    
    # 创建ChipAuthentication SecurityInfo
    ca_info = SecurityInfo()
    ca_info['protocol'] = univ.ObjectIdentifier('0.4.0.127.0.7.2.2.3.2.4')  # id-CA-ECDH-AES-CBC-CMAC-256
    ca_info['requiredData'] = univ.Integer(1)
    
    # 创建TerminalAuthentication SecurityInfo
    ta_info = SecurityInfo()
    ta_info['protocol'] = univ.ObjectIdentifier('0.4.0.127.0.7.2.2.2.1.2')  # id-TA-RSA-v1-5-SHA-256
    ta_info['requiredData'] = univ.Integer(1)
    
    # 创建SecurityInfos SET
    security_infos = univ.SetOf(componentType=SecurityInfo())
    security_infos.append(ca_info)
    security_infos.append(ta_info)
    
    # 编码为DER
    dg14_data = der_encoder.encode(security_infos)
    
    # 保存DG14
    with open("dg14.bin", "wb") as f:
        f.write(dg14_data)
        
    print("DG14已生成: dg14.bin")


def generate_dg15_and_aa_keypair():
    """生成测试用DG15和AA密钥对"""
    print("生成DG15和AA密钥对...")
    
    # 生成RSA1024密钥对（符合AA要求）
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    
    # 保存公钥为DG15
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open("dg15.bin", "wb") as f:
        f.write(public_key_der)
        
    # 保存私钥
    with open("aa_private.der", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    print("DG15已生成: dg15.bin")
    print("AA私钥已生成: aa_private.der")


def generate_ca_s_value():
    """生成测试用CA S值"""
    print("生成CA S值...")
    
    # 生成一个256位的S值（对应P-256曲线）
    # 实际的S值应该是椭圆曲线私钥的标量部分
    import secrets
    s_value = secrets.token_bytes(32)  # 32字节 = 256位
    
    with open("ca_s_value.bin", "wb") as f:
        f.write(s_value)
        
    print("CA S值已生成: ca_s_value.bin")


def main():
    """主函数"""
    print("开始生成测试数据...")
    print("="*50)
    print("警告：这些是测试数据，不能用于实际的护照验证！")
    print("="*50)
    print()
    
    # 生成CSCA
    csca_cert, csca_key = generate_csca_certificate()
    
    # 生成DSC
    generate_dsc_certificate(csca_cert, csca_key)
    
    # 生成DG14
    generate_dg14()
    
    # 生成DG15和AA密钥对
    generate_dg15_and_aa_keypair()
    
    # 生成CA S值
    generate_ca_s_value()
    
    # 清理临时文件
    if os.path.exists("csca_private.der"):
        os.remove("csca_private.der")
        
    print()
    print("="*50)
    print("测试数据生成完成！")
    print("现在可以运行: python passport_certificate_validator.py")
    print("="*50)


if __name__ == "__main__":
    main()