#!/usr/bin/env python3
import sys

def find_tag_in_data(data, target_tag):
    """在数据中查找特定标签"""
    positions = []
    for i in range(len(data) - 1):
        if data[i] == target_tag:
            positions.append(i)
    return positions

if len(sys.argv) != 2:
    print("用法: python check_feature_points.py <DG2文件>")
    sys.exit(1)

with open(sys.argv[1], 'rb') as f:
    dg2_data = f.read()

print(f"DG2文件大小: {len(dg2_data)} 字节")
print(f"前100字节（hex）: {dg2_data[:100].hex()}")

# 查找特征点标签 0x92
positions = find_tag_in_data(dg2_data, 0x92)
if positions:
    print(f"\n找到特征点标签(0x92)在位置: {positions}")
    for pos in positions:
        # 显示标签周围的数据
        start = max(0, pos - 10)
        end = min(len(dg2_data), pos + 20)
        print(f"  位置 {pos} 附近: {dg2_data[start:end].hex()}")
else:
    print("\n警告: 未找到特征点标签(0x92)!")

# 查找其他关键标签
print("\n其他标签位置:")
print(f"  0x75 (DG2): {find_tag_in_data(dg2_data, 0x75)}")
print(f"  0x7F61 (生物特征信息组): {find_tag_in_data(dg2_data, 0x7F61)}")
print(f"  0x7F60 (生物特征信息模板): {find_tag_in_data(dg2_data, 0x7F60)}")
print(f"  0xA1 (生物特征头): {find_tag_in_data(dg2_data, 0xA1)}")
print(f"  0x5F2E (生物特征数据块): {find_tag_in_data(dg2_data, 0x5F2E)}")