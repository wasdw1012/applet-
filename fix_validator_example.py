#!/usr/bin/env python3
"""
示例：如何修复现有的护照验证器
"""

# 导入现有的验证器
from passport_certificate_validator import PassportCertificateValidator

# 导入补丁
from passport_validator_patch import patch_validator

# 应用补丁
patch_validator(PassportCertificateValidator)

# 现在可以正常使用验证器，DG15解析已经被修复
if __name__ == "__main__":
    validator = PassportCertificateValidator()
    
    # 运行验证
    validator.validate()
    
    # 生成报告
    validator.generate_report()