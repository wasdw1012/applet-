#!/usr/bin/env python3
"""
DG2 Data Analysis Tool
Comprehensive analysis tool for ICAO 9303 DG2 (Data Group 2) files
"""

import os
import sys
import argparse
import struct
import hashlib
import json
from datetime import datetime
from typing import Dict, Tuple, Optional, List, Any
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
import io

# Import DG2 generation functions
from gen_dg2_simple import (
    DG2_TAG, BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, BIOMETRIC_INFO_TEMPLATE_TAG,
    BIOMETRIC_HEADER_TEMPLATE_TAG, BIOMETRIC_DATA_BLOCK_TAG,
    ICAO_HEADER_VERSION_TAG, BIOMETRIC_TYPE_TAG, BIOMETRIC_SUBTYPE_TAG,
    CREATION_DATE_TIME_TAG, VALIDITY_PERIOD_TAG, CREATOR_TAG,
    FORMAT_OWNER_TAG, FORMAT_TYPE_TAG, IMAGE_WIDTH_TAG, IMAGE_HEIGHT_TAG,
    FEATURE_POINTS_TAG, SAMPLE_NUMBER_TAG,
    BIOMETRIC_TYPE_FACIAL_FEATURES, FORMAT_TYPE_FACIAL_JPG, FORMAT_TYPE_FACIAL_JP2
)

class DG2Analyzer:
    """DG2 Data Analyzer for ICAO 9303 compliant files"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.dg2_data = None
        self.parsed_structure = {}
        self.image_data = None
        self.metadata = {}
        
    def parse_tlv(self, data: bytes, offset: int = 0) -> Tuple[int, int, bytes, int]:
        """Parse TLV (Tag-Length-Value) structure"""
        if offset >= len(data):
            raise ValueError("Offset exceeds data length")
            
        # Parse tag
        tag = data[offset]
        offset += 1
        
        # If high bit is set, tag is multi-byte
        if tag & 0x1F == 0x1F:
            tag = (tag << 8) | data[offset]
            offset += 1
            
        # Parse length
        length_octet = data[offset]
        offset += 1
        
        if length_octet & 0x80:
            # Long form
            num_octets = length_octet & 0x7F
            length = int.from_bytes(data[offset:offset+num_octets], 'big')
            offset += num_octets
        else:
            # Short form
            length = length_octet
            
        # Extract value
        value = data[offset:offset+length]
        offset += length
        
        return tag, length, value, offset
        
    def parse_dg2(self, dg2_path: str) -> Dict[str, Any]:
        """Parse DG2 file and extract all components"""
        with open(dg2_path, 'rb') as f:
            self.dg2_data = f.read()
            
        print(f"[分析] 读取DG2文件: {dg2_path} ({len(self.dg2_data)} 字节)")
        
        # Parse main DG2 structure
        tag, length, value, offset = self.parse_tlv(self.dg2_data)
        
        if tag != DG2_TAG:
            raise ValueError(f"非DG2文件，期望标签0x{DG2_TAG:02X}，实际标签0x{tag:02X}")
            
        self.parsed_structure['dg2_tag'] = tag
        self.parsed_structure['dg2_length'] = length
        
        # Parse biometric info group template
        tag, length, value, _ = self.parse_tlv(value)
        
        if tag != BIOMETRIC_INFO_GROUP_TEMPLATE_TAG:
            raise ValueError(f"无效的生物特征信息组模板标签: 0x{tag:04X}")
            
        # Parse sample number (optional)
        offset = 0
        if value[offset] == SAMPLE_NUMBER_TAG:
            tag, length, sample_num, offset = self.parse_tlv(value, offset)
            self.parsed_structure['sample_number'] = int.from_bytes(sample_num, 'big')
            
        # Parse biometric info template
        tag, length, bio_info, offset = self.parse_tlv(value, offset)
        
        if tag != BIOMETRIC_INFO_TEMPLATE_TAG:
            raise ValueError(f"无效的生物特征信息模板标签: 0x{tag:04X}")
            
        # Parse biometric header template
        header_tag, header_length, header_value, bio_offset = self.parse_tlv(bio_info)
        
        if header_tag != BIOMETRIC_HEADER_TEMPLATE_TAG:
            raise ValueError(f"无效的生物特征头部模板标签: 0x{header_tag:02X}")
            
        # Parse header fields
        self._parse_header(header_value)
        
        # Parse biometric data block
        data_tag, data_length, data_value, _ = self.parse_tlv(bio_info, bio_offset)
        
        if data_tag != BIOMETRIC_DATA_BLOCK_TAG:
            raise ValueError(f"无效的生物特征数据块标签: 0x{data_tag:04X}")
            
        self.image_data = data_value
        self.parsed_structure['image_data_length'] = len(self.image_data)
        
        return self.parsed_structure
        
    def _parse_header(self, header_data: bytes):
        """Parse biometric header template"""
        offset = 0
        
        while offset < len(header_data):
            tag, length, value, offset = self.parse_tlv(header_data, offset)
            
            if tag == ICAO_HEADER_VERSION_TAG:
                self.metadata['header_version'] = f"{value[0]}.{value[1]}"
            elif tag == BIOMETRIC_TYPE_TAG:
                self.metadata['biometric_type'] = value[0]
                self.metadata['biometric_type_name'] = 'Facial Features' if value[0] == BIOMETRIC_TYPE_FACIAL_FEATURES else f'Unknown ({value[0]})'
            elif tag == BIOMETRIC_SUBTYPE_TAG:
                self.metadata['biometric_subtype'] = value[0]
            elif tag == CREATION_DATE_TIME_TAG:
                self.metadata['creation_datetime'] = value.decode('ascii')
            elif tag == VALIDITY_PERIOD_TAG:
                from_date = value[:8].decode('ascii')
                to_date = value[8:16].decode('ascii')
                self.metadata['validity_period'] = f"{from_date} - {to_date}"
            elif tag == CREATOR_TAG:
                self.metadata['creator'] = value.decode('ascii', errors='ignore').strip()
            elif tag == FORMAT_OWNER_TAG:
                self.metadata['format_owner'] = int.from_bytes(value, 'big')
            elif tag == FORMAT_TYPE_TAG:
                format_type = int.from_bytes(value, 'big')
                self.metadata['format_type'] = format_type
                if format_type == FORMAT_TYPE_FACIAL_JPG:
                    self.metadata['format_type_name'] = 'JPEG'
                elif format_type == FORMAT_TYPE_FACIAL_JP2:
                    self.metadata['format_type_name'] = 'JPEG2000'
                else:
                    self.metadata['format_type_name'] = f'Unknown ({format_type})'
            elif tag == IMAGE_WIDTH_TAG:
                self.metadata['image_width'] = int.from_bytes(value, 'big')
            elif tag == IMAGE_HEIGHT_TAG:
                self.metadata['image_height'] = int.from_bytes(value, 'big')
            elif tag == FEATURE_POINTS_TAG:
                self._parse_feature_points(value)
                
    def _parse_feature_points(self, feature_data: bytes):
        """Parse facial feature points"""
        points = []
        offset = 0
        point_count = 0
        
        while offset + 8 <= len(feature_data):
            # Each feature point: type(1) + major(1) + minor(1) + x(2) + y(2) + reserved(1)
            point_type = feature_data[offset]
            major = feature_data[offset + 1]
            minor = feature_data[offset + 2]
            x = int.from_bytes(feature_data[offset + 3:offset + 5], 'big')
            y = int.from_bytes(feature_data[offset + 5:offset + 7], 'big')
            
            points.append({
                'type': point_type,
                'major': major,
                'minor': minor,
                'x': x,
                'y': y
            })
            
            offset += 8
            point_count += 1
            
        self.metadata['feature_points'] = points
        self.metadata['feature_points_count'] = point_count
        
    def extract_image(self, output_path: Optional[str] = None) -> Optional[Image.Image]:
        """Extract image from DG2 data"""
        if not self.image_data:
            print("[错误] 未找到图像数据")
            return None
            
        try:
            # Try to load image
            img = Image.open(io.BytesIO(self.image_data))
            
            if output_path:
                img.save(output_path)
                print(f"[提取] 图像已保存到: {output_path}")
                
            return img
        except Exception as e:
            print(f"[错误] 无法解析图像数据: {e}")
            return None
            
    def analyze(self, dg2_path: str) -> Dict[str, Any]:
        """Perform complete analysis of DG2 file"""
        # Parse DG2 structure
        self.parse_dg2(dg2_path)
        
        # Calculate statistics
        analysis = {
            'file_info': {
                'path': dg2_path,
                'size': len(self.dg2_data),
                'sha256': hashlib.sha256(self.dg2_data).hexdigest()
            },
            'structure': self.parsed_structure,
            'metadata': self.metadata,
            'statistics': {
                'overhead': len(self.dg2_data) - self.parsed_structure.get('image_data_length', 0),
                'compression_ratio': self.parsed_structure.get('image_data_length', 0) / len(self.dg2_data) if self.dg2_data else 0
            }
        }
        
        return analysis
        
    def visualize_structure(self, output_path: Optional[str] = None):
        """Visualize DG2 structure as a diagram"""
        if not self.dg2_data:
            print("[错误] 未加载DG2数据")
            return
            
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
        
        # Structure visualization
        structure_sizes = [
            ('DG2 Header', 50),  # Approximate
            ('Biometric Info Template', 100),  # Approximate
            ('Biometric Header', 200),  # Approximate
            ('Image Data', self.parsed_structure.get('image_data_length', 0))
        ]
        
        labels, sizes = zip(*structure_sizes)
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
        
        ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax1.set_title('DG2 结构组成')
        
        # Metadata visualization
        metadata_text = []
        for key, value in self.metadata.items():
            if key != 'feature_points':  # Skip feature points for text display
                metadata_text.append(f"{key}: {value}")
                
        ax2.text(0.1, 0.9, '\n'.join(metadata_text), transform=ax2.transAxes,
                fontsize=10, verticalalignment='top', fontfamily='monospace')
        ax2.axis('off')
        ax2.set_title('DG2 元数据')
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path)
            print(f"[可视化] 结构图已保存到: {output_path}")
        else:
            plt.show()
            
    def visualize_feature_points(self, output_path: Optional[str] = None):
        """Visualize facial feature points on the extracted image"""
        if not self.image_data:
            print("[错误] 未找到图像数据")
            return
            
        img = self.extract_image()
        if not img:
            return
            
        # Convert to numpy array for plotting
        img_array = np.array(img)
        
        plt.figure(figsize=(10, 10))
        plt.imshow(img_array)
        
        # Plot feature points if available
        if 'feature_points' in self.metadata:
            for i, point in enumerate(self.metadata['feature_points']):
                plt.scatter(point['x'], point['y'], c='red', s=50, marker='o')
                plt.text(point['x'] + 5, point['y'] + 5, str(i), color='red', fontsize=8)
                
        plt.title(f"DG2 图像与特征点 ({self.metadata.get('feature_points_count', 0)} 个特征点)")
        plt.axis('off')
        
        if output_path:
            plt.savefig(output_path)
            print(f"[可视化] 特征点图已保存到: {output_path}")
        else:
            plt.show()
            
    def generate_report(self, output_path: str):
        """Generate comprehensive analysis report"""
        analysis = {
            'file_info': {
                'path': 'N/A',
                'size': len(self.dg2_data),
                'sha256': hashlib.sha256(self.dg2_data).hexdigest()
            },
            'structure': self.parsed_structure,
            'metadata': self.metadata,
            'statistics': {
                'overhead': len(self.dg2_data) - self.parsed_structure.get('image_data_length', 0),
                'compression_ratio': self.parsed_structure.get('image_data_length', 0) / len(self.dg2_data) if self.dg2_data else 0
            }
        }
        
        report = f"""DG2 数据分析报告
=====================================
生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

文件信息
--------
路径: {analysis['file_info']['path']}
大小: {analysis['file_info']['size']} 字节
SHA256: {analysis['file_info']['sha256']}

DG2 结构
--------
DG2 标签: 0x{analysis['structure']['dg2_tag']:02X}
DG2 长度: {analysis['structure']['dg2_length']} 字节
图像数据长度: {analysis['structure']['image_data_length']} 字节

元数据
------
"""
        
        for key, value in self.metadata.items():
            if key == 'feature_points':
                report += f"特征点数量: {self.metadata.get('feature_points_count', 0)}\n"
            else:
                report += f"{key}: {value}\n"
                
        report += f"""
统计信息
--------
数据开销: {analysis['statistics']['overhead']} 字节
压缩比率: {analysis['statistics']['compression_ratio']:.2%}

特征点详情
----------
"""
        
        if 'feature_points' in self.metadata:
            for i, point in enumerate(self.metadata['feature_points']):
                report += f"  点 {i}: 类型={point['type']}, 位置=({point['x']}, {point['y']})\n"
                
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
            
        print(f"[报告] 分析报告已保存到: {output_path}")
        
def main():
    parser = argparse.ArgumentParser(
        description="DG2 数据分析工具 - 符合 ICAO 9303 标准的 DG2 文件分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  分析 DG2 文件:
    python dg2_analysis.py analyze DG2.bin
    
  提取图像:
    python dg2_analysis.py extract DG2.bin --output extracted.jpg
    
  可视化结构:
    python dg2_analysis.py visualize DG2.bin --structure
    
  可视化特征点:
    python dg2_analysis.py visualize DG2.bin --features
    
  生成完整报告:
    python dg2_analysis.py report DG2.bin --output report.txt
"""
    )
    
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='分析 DG2 文件')
    analyze_parser.add_argument('dg2_file', help='DG2 文件路径')
    analyze_parser.add_argument('--json', action='store_true', help='输出 JSON 格式')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='提取图像')
    extract_parser.add_argument('dg2_file', help='DG2 文件路径')
    extract_parser.add_argument('--output', '-o', help='输出图像路径')
    
    # Visualize command
    vis_parser = subparsers.add_parser('visualize', help='可视化 DG2 数据')
    vis_parser.add_argument('dg2_file', help='DG2 文件路径')
    vis_parser.add_argument('--structure', action='store_true', help='可视化结构')
    vis_parser.add_argument('--features', action='store_true', help='可视化特征点')
    vis_parser.add_argument('--output', '-o', help='输出图像路径')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='生成分析报告')
    report_parser.add_argument('dg2_file', help='DG2 文件路径')
    report_parser.add_argument('--output', '-o', default='dg2_report.txt', help='报告输出路径')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    analyzer = DG2Analyzer(verbose=True)
    
    if args.command == 'analyze':
        analysis = analyzer.analyze(args.dg2_file)
        if args.json:
            # Convert numpy types for JSON serialization
            def convert_types(obj):
                if isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, np.ndarray):
                    return obj.tolist()
                elif isinstance(obj, dict):
                    return {k: convert_types(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_types(v) for v in obj]
                return obj
                
            print(json.dumps(convert_types(analysis), indent=2, ensure_ascii=False))
        else:
            print("\n[分析结果]")
            print(f"文件大小: {analysis['file_info']['size']} 字节")
            print(f"SHA256: {analysis['file_info']['sha256']}")
            print(f"图像格式: {analyzer.metadata.get('format_type_name', 'Unknown')}")
            print(f"图像尺寸: {analyzer.metadata.get('image_width', 'N/A')}x{analyzer.metadata.get('image_height', 'N/A')}")
            print(f"特征点数: {analyzer.metadata.get('feature_points_count', 0)}")
            
    elif args.command == 'extract':
        analyzer.parse_dg2(args.dg2_file)
        output_path = args.output or f"{os.path.splitext(args.dg2_file)[0]}_extracted.jpg"
        analyzer.extract_image(output_path)
        
    elif args.command == 'visualize':
        analyzer.parse_dg2(args.dg2_file)
        if args.structure:
            output_path = args.output or f"{os.path.splitext(args.dg2_file)[0]}_structure.png"
            analyzer.visualize_structure(output_path)
        if args.features:
            output_path = args.output or f"{os.path.splitext(args.dg2_file)[0]}_features.png"
            analyzer.visualize_feature_points(output_path)
        if not args.structure and not args.features:
            print("[错误] 请指定 --structure 或 --features 选项")
            
    elif args.command == 'report':
        analyzer.parse_dg2(args.dg2_file)
        analyzer.generate_report(args.output)

if __name__ == '__main__':
    main()