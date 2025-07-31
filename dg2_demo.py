#!/usr/bin/env python3
"""
DG2 数据分析演示脚本
展示 DG2 文件的完整分析功能
"""

import os
import sys
from datetime import datetime

def run_demo():
    """运行 DG2 分析演示"""
    
    print("=" * 60)
    print("DG2 数据分析演示")
    print("ICAO 9303 标准的 DG2 (Data Group 2) 文件分析")
    print("=" * 60)
    print()
    
    # 检查示例文件
    if not os.path.exists('sample_dg2.bin'):
        print("[错误] 未找到示例 DG2 文件 'sample_dg2.bin'")
        print("请先运行: python3 gen_dg2_simple.py <图像文件> --out sample_dg2.bin")
        return
    
    print("1. DG2 文件基本信息")
    print("-" * 40)
    os.system("python3 dg2_analysis.py analyze sample_dg2.bin")
    print()
    
    input("按回车继续查看详细 JSON 分析...")
    print("\n2. 详细 JSON 格式分析")
    print("-" * 40)
    os.system("python3 dg2_analysis.py analyze sample_dg2.bin --json | head -50")
    print()
    
    input("按回车继续提取图像...")
    print("\n3. 从 DG2 文件提取图像")
    print("-" * 40)
    os.system("python3 dg2_analysis.py extract sample_dg2.bin --output demo_extracted.jpg")
    print()
    
    input("按回车继续生成结构可视化...")
    print("\n4. DG2 结构可视化")
    print("-" * 40)
    os.system("python3 dg2_analysis.py visualize sample_dg2.bin --structure --output demo_structure.png")
    print()
    
    input("按回车继续生成特征点可视化...")
    print("\n5. 面部特征点可视化")
    print("-" * 40)
    os.system("python3 dg2_analysis.py visualize sample_dg2.bin --features --output demo_features.png")
    print()
    
    input("按回车继续生成完整报告...")
    print("\n6. 生成完整分析报告")
    print("-" * 40)
    os.system("python3 dg2_analysis.py report sample_dg2.bin --output demo_report.txt")
    print()
    
    # 显示报告内容
    print("报告内容预览:")
    print("-" * 40)
    if os.path.exists('demo_report.txt'):
        with open('demo_report.txt', 'r', encoding='utf-8') as f:
            print(f.read()[:500] + "...")
    print()
    
    print("=" * 60)
    print("演示完成！生成的文件:")
    print("-" * 40)
    demo_files = [
        'demo_extracted.jpg',
        'demo_structure.png',
        'demo_features.png',
        'demo_report.txt'
    ]
    
    for file in demo_files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            print(f"  {file:<25} ({size:,} 字节)")
    
    print()
    print("DG2 分析功能总结:")
    print("-" * 40)
    print("✓ 解析 DG2 文件结构 (TLV 格式)")
    print("✓ 提取生物特征元数据")
    print("✓ 提取并保存面部图像")
    print("✓ 解析面部特征点坐标")
    print("✓ 可视化数据结构组成")
    print("✓ 在图像上标注特征点")
    print("✓ 生成综合分析报告")
    print("✓ 支持 JSON 格式输出")
    print()

if __name__ == '__main__':
    # 如果没有示例 DG2 文件，先生成一个
    if not os.path.exists('sample_dg2.bin'):
        print("正在生成示例 DG2 文件...")
        if os.path.exists('sample_passport_photo.jpg'):
            os.system("python3 gen_dg2_simple.py sample_passport_photo.jpg --out sample_dg2.bin")
        else:
            print("[错误] 未找到示例图像文件")
            sys.exit(1)
    
    run_demo()