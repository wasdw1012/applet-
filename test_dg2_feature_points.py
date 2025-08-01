#!/usr/bin/env python3
"""测试DG2文件中的特征点是否正确保存"""

import sys
from binascii import hexlify

def parse_tlv(data, offset=0):
    """解析TLV结构"""
    if offset >= len(data):
        return None
    
    tag = data[offset]
    offset += 1
    
    # 处理多字节标签
    if tag & 0x1F == 0x1F:
        tag = (tag << 8) | data[offset]
        offset += 1
    
    # 获取长度
    length_byte = data[offset]
    offset += 1
    
    if length_byte & 0x80:
        # 长形式
        num_octets = length_byte & 0x7F
        length = int.from_bytes(data[offset:offset+num_octets], 'big')
        offset += num_octets
    else:
        # 短形式
        length = length_byte
    
    value = data[offset:offset+length]
    return tag, length, value, offset + length

def find_feature_points(data, indent=""):
    """递归查找特征点数据（标签0x92）"""
    offset = 0
    found_points = False
    
    while offset < len(data):
        result = parse_tlv(data, offset)
        if not result:
            break
            
        tag, length, value, next_offset = result
        
        print(f"{indent}标签: 0x{tag:02X} (长度: {length})")
        
        # 检查是否是特征点标签
        if tag == 0x92:
            print(f"{indent}  >>> 找到特征点数据！ <<<")
            if length >= 2:
                num_points = int.from_bytes(value[0:2], 'big')
                print(f"{indent}  特征点数量: {num_points}")
                
                offset_in_value = 2
                for i in range(num_points):
                    if offset_in_value + 5 <= length:
                        point_type = value[offset_in_value]
                        x = int.from_bytes(value[offset_in_value+1:offset_in_value+3], 'big')
                        y = int.from_bytes(value[offset_in_value+3:offset_in_value+5], 'big')
                        print(f"{indent}  特征点 {i+1}: 类型=0x{point_type:02X}, X={x}, Y={y}")
                        offset_in_value += 5
            found_points = True
        
        # 如果是容器标签，递归解析
        if tag in [0x75, 0x7F61, 0x7F60, 0xA1]:
            print(f"{indent}  进入嵌套结构...")
            found_in_nested = find_feature_points(value, indent + "    ")
            found_points = found_points or found_in_nested
        
        offset = next_offset
    
    return found_points

def main():
    if len(sys.argv) != 2:
        print("用法: python test_dg2_feature_points.py <DG2文件>")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    try:
        with open(filename, 'rb') as f:
            dg2_data = f.read()
        
        print(f"\n解析 DG2 文件: {filename}")
        print(f"文件大小: {len(dg2_data)} 字节")
        print("\n开始解析结构：")
        print("-" * 60)
        
        found = find_feature_points(dg2_data)
        
        print("-" * 60)
        if found:
            print("\n✓ 成功找到特征点数据！")
        else:
            print("\n✗ 警告：未找到特征点数据（标签0x92）！")
            
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()