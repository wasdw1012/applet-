#!/usr/bin/env python3
"""DG14解析调试工具"""

import os
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ
import binascii

def debug_parse_dg14():
    # 查找DG14文件
    dg14_file = None
    for file in os.listdir('.'):
        if file.endswith('DG14.bin'):
            dg14_file = file
            break
    
    if not dg14_file:
        print("未找到DG14文件")
        return
        
    print(f"解析文件: {dg14_file}")
    
    with open(dg14_file, 'rb') as f:
        dg14_data = f.read()
    
    print(f"\nDG14文件大小: {len(dg14_data)} 字节")
    print(f"前20字节: {binascii.hexlify(dg14_data[:20]).decode()}")
    
    # 查找SecurityInfos (SET OF)
    security_infos_data = None
    if dg14_data[0] == 0x6E:  # DG14标签
        print("\n检测到DG14标签 (0x6E)")
        pos = 1
        if dg14_data[pos] & 0x80:  # 长形式长度
            len_bytes = dg14_data[pos] & 0x7F
            pos += 1
            length = int.from_bytes(dg14_data[pos:pos+len_bytes], 'big')
            pos += len_bytes
            security_infos_data = dg14_data[pos:pos+length]
    elif dg14_data[0] == 0x31:  # 直接是SET
        print("\n直接是SET结构")
        security_infos_data = dg14_data
    
    if not security_infos_data:
        print("未找到SecurityInfos数据")
        return
        
    print(f"\nSecurityInfos数据大小: {len(security_infos_data)} 字节")
    print(f"前20字节: {binascii.hexlify(security_infos_data[:20]).decode()}")
    
    # 解析SecurityInfos
    try:
        decoded, remainder = der_decoder.decode(security_infos_data)
        print(f"\n解析成功，包含 {len(decoded)} 个SecurityInfo")
        
        for i, security_info in enumerate(decoded):
            print(f"\n--- SecurityInfo[{i}] ---")
            print(f"类型: {type(security_info)}")
            print(f"长度: {len(security_info) if hasattr(security_info, '__len__') else 'N/A'}")
            
            if hasattr(security_info, '__getitem__'):
                for j in range(len(security_info)):
                    item = security_info[j]
                    print(f"\n  元素[{j}]:")
                    print(f"    类型: {type(item)}")
                    print(f"    值: {item}")
                    
                    # 特殊处理OID
                    if j == 0:
                        if hasattr(item, 'prettyPrint'):
                            print(f"    prettyPrint: {item.prettyPrint()}")
                        if hasattr(item, 'asTuple'):
                            print(f"    asTuple: {item.asTuple()}")
                        if hasattr(item, '__str__'):
                            print(f"    str: {str(item)}")
                    
                    # 特殊处理Integer
                    if j in [1, 2]:
                        if hasattr(item, 'hasValue'):
                            print(f"    hasValue: {item.hasValue()}")
                        if hasattr(item, '__int__'):
                            try:
                                print(f"    int(): {int(item)}")
                            except Exception as e:
                                print(f"    int()失败: {e}")
                        
                        # 检查是否是嵌套的Sequence
                        if hasattr(item, '__getitem__'):
                            print(f"    是Sequence，包含 {len(item)} 个元素")
                            for k in range(min(3, len(item))):
                                print(f"      子元素[{k}]: {type(item[k])} = {item[k]}")
    
    except Exception as e:
        print(f"\n解析失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_parse_dg14()