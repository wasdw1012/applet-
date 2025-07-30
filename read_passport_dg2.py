#!/usr/bin/env python3
"""
使用ACR122U读取护照DG2数据
需要安装: pip install pyscard pycryptodome
"""

import hashlib
from Crypto.Cipher import DES3
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import struct

class PassportReader:
    def __init__(self):
        self.connection = None
        self.kseed = None
        self.kenc = None
        self.kmac = None
        self.ssc = None
        
    def connect_reader(self):
        """连接ACR122U读卡器"""
        reader_list = readers()
        if not reader_list:
            raise Exception("未找到读卡器")
        
        print(f"找到读卡器: {reader_list[0]}")
        self.connection = reader_list[0].createConnection()
        self.connection.connect()
        
    def send_command(self, apdu, secure=False):
        """发送APDU命令"""
        if secure and self.kenc and self.kmac:
            # TODO: 实现安全消息封装
            pass
            
        print(f"发送: {toHexString(apdu)}")
        data, sw1, sw2 = self.connection.transmit(apdu)
        print(f"接收: {toHexString(data)} SW:{sw1:02X}{sw2:02X}")
        
        if sw1 == 0x90 and sw2 == 0x00:
            return data
        else:
            raise Exception(f"命令失败: SW={sw1:02X}{sw2:02X}")
    
    def compute_mrz_key(self, document_number, date_of_birth, date_of_expiry):
        """计算MRZ密钥"""
        # 确保文档号码为9位
        doc_num = document_number.upper().ljust(9, '<')
        
        # 计算校验位
        def compute_check_digit(data):
            weight = [7, 3, 1]
            total = 0
            for i, char in enumerate(data):
                if char.isdigit():
                    value = int(char)
                elif char.isalpha():
                    value = ord(char) - ord('A') + 10
                else:
                    value = 0
                total += value * weight[i % 3]
            return str(total % 10)
        
        # 添加校验位
        doc_num_check = compute_check_digit(doc_num)
        dob_check = compute_check_digit(date_of_birth)
        doe_check = compute_check_digit(date_of_expiry)
        
        # 组合MRZ信息
        mrz_info = doc_num + doc_num_check + date_of_birth + dob_check + date_of_expiry + doe_check
        print(f"MRZ信息: {mrz_info}")
        
        # 计算SHA-1哈希
        h = hashlib.sha1(mrz_info.encode('ascii')).digest()
        
        # 取前16字节作为Kseed
        self.kseed = h[:16]
        
        # 派生加密和MAC密钥
        self.kenc = self.derive_key(self.kseed, 1)
        self.kmac = self.derive_key(self.kseed, 2)
        
        print(f"Kenc: {self.kenc.hex()}")
        print(f"Kmac: {self.kmac.hex()}")
    
    def derive_key(self, kseed, counter):
        """派生密钥"""
        D = kseed + struct.pack('>I', counter)
        h = hashlib.sha1(D).digest()
        
        # 调整奇偶校验位
        ka = self.adjust_parity(h[:8])
        kb = self.adjust_parity(h[8:16])
        
        return ka + kb
    
    def adjust_parity(self, key_bytes):
        """调整DES密钥奇偶校验位"""
        adjusted = bytearray()
        for byte in key_bytes:
            # 计算前7位的奇偶性
            parity = 0
            for i in range(7):
                parity ^= (byte >> i) & 1
            # 设置最低位为奇校验
            adjusted_byte = (byte & 0xFE) | (parity ^ 1)
            adjusted.append(adjusted_byte)
        return bytes(adjusted)
    
    def perform_bac(self):
        """执行基本访问控制(BAC)"""
        # 1. 获取随机数
        get_challenge = [0x00, 0x84, 0x00, 0x00, 0x08]
        rnd_icc = self.send_command(get_challenge)
        
        # 2. 生成随机数和密钥
        import os
        rnd_ifd = os.urandom(8)
        k_ifd = os.urandom(16)
        
        # 3. 构建认证数据
        s = rnd_ifd + rnd_icc + k_ifd
        
        # 4. 加密
        cipher = DES3.new(self.kenc, DES3.MODE_CBC, b'\x00' * 8)
        e_ifd = cipher.encrypt(s)
        
        # 5. 计算MAC
        # 这里简化了MAC计算，实际需要ISO 9797-1 MAC算法
        mac_input = self.pad_data(e_ifd)
        cipher_mac = DES3.new(self.kmac, DES3.MODE_CBC, b'\x00' * 8)
        mac_full = cipher_mac.encrypt(mac_input)
        m_ifd = mac_full[-8:]
        
        # 6. 发送外部认证命令
        ext_auth_data = e_ifd + m_ifd
        ext_auth = [0x00, 0x82, 0x00, 0x00, len(ext_auth_data)] + list(ext_auth_data)
        
        response = self.send_command(ext_auth)
        
        # 7. 解析响应并建立会话密钥
        # TODO: 完整实现会话密钥派生
        print("BAC认证成功")
        
    def pad_data(self, data):
        """ISO 9797-1填充"""
        padded = data + b'\x80'
        while len(padded) % 8 != 0:
            padded += b'\x00'
        return padded
    
    def select_dg2(self):
        """选择DG2文件"""
        # SELECT FILE命令选择DG2 (文件ID: 0102)
        select_dg2 = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x02]
        self.send_command(select_dg2)
        
    def read_dg2(self):
        """读取DG2数据"""
        # 首先读取前4字节获取长度
        read_length = [0x00, 0xB0, 0x00, 0x00, 0x04]
        header = self.send_command(read_length)
        
        # 解析TLV获取总长度
        if header[0] == 0x75:  # DG2标签
            if header[1] == 0x82:  # 长格式长度
                total_length = (header[2] << 8) | header[3]
                header_size = 4
            elif header[1] == 0x81:  # 单字节长度
                total_length = header[2]
                header_size = 3
            else:  # 短格式长度
                total_length = header[1]
                header_size = 2
        else:
            raise Exception("不是有效的DG2文件")
        
        print(f"DG2总长度: {total_length + header_size} 字节")
        
        # 分块读取完整数据
        dg2_data = bytearray(header)
        offset = len(header)
        
        while offset < total_length + header_size:
            # 每次最多读取256字节
            chunk_size = min(256, total_length + header_size - offset)
            read_cmd = [0x00, 0xB0, offset >> 8, offset & 0xFF, chunk_size]
            chunk = self.send_command(read_cmd)
            dg2_data.extend(chunk)
            offset += len(chunk)
            
        return bytes(dg2_data)
    
    def extract_face_image(self, dg2_data):
        """从DG2数据中提取面部图像"""
        # 简单查找JPEG标记
        jpeg_start = dg2_data.find(b'\xFF\xD8')
        jpeg_end = dg2_data.find(b'\xFF\xD9')
        
        if jpeg_start != -1 and jpeg_end != -1:
            jpeg_data = dg2_data[jpeg_start:jpeg_end + 2]
            print(f"找到JPEG图像，大小: {len(jpeg_data)} 字节")
            
            # 保存图像
            with open("passport_photo.jpg", "wb") as f:
                f.write(jpeg_data)
            print("图像已保存为 passport_photo.jpg")
            return jpeg_data
        else:
            print("未找到JPEG图像")
            return None

def main():
    # MRZ信息（需要根据实际护照修改）
    DOCUMENT_NUMBER = "123456789"  # 9位文档号
    DATE_OF_BIRTH = "900101"       # YYMMDD格式
    DATE_OF_EXPIRY = "250101"      # YYMMDD格式
    
    reader = PassportReader()
    
    try:
        # 连接读卡器
        reader.connect_reader()
        
        # 计算MRZ密钥
        reader.compute_mrz_key(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY)
        
        # 执行BAC认证
        reader.perform_bac()
        
        # 选择并读取DG2
        reader.select_dg2()
        dg2_data = reader.read_dg2()
        
        # 保存原始DG2数据
        with open("dg2_raw.bin", "wb") as f:
            f.write(dg2_data)
        print(f"DG2原始数据已保存，共 {len(dg2_data)} 字节")
        
        # 提取面部图像
        reader.extract_face_image(dg2_data)
        
    except Exception as e:
        print(f"错误: {e}")
        
if __name__ == "__main__":
    main()