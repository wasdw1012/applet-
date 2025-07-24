
#这里是个人化精准摘抄的AA和CA的写入部署。开头代码写入逻辑，但是在最后的main 还有一小段逻辑，我会注释说明

# 扩展：AA密钥写入
def encode_length(length: int) -> bytes:
    """
    编码BER-TLV长度字段
    """
    if length < 0x80:
        # 短格式：0-127字节
        return bytes([length])
    elif length <= 0xFF:
        # 长格式：128-255字节
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        # 长格式：256-65535字节
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        raise ValueError(f"长度太大: {length}")

def build_aa_key_payload(tag: int, key_component_data: bytes) -> bytes:
    """
    根据抄袭马蒂诺卡端的逻辑，构建非常巧妙的BER-TLV载荷
    
    期望的格式：
    [外层标签][外层长度][外层值-被跳过][内层标签0x04][内层长度][密钥数据]
    """
    # 重要发现：skipValue()意味着外层值是空的，内层TLV是并列的！
    # 外层TLV：tag + 长度0 + 空值
    outer_tlv = bytes([tag, 0x00])  # 长度为0的TLV
    
    # 内层TLV：OCTET STRING (0x04) + 长度 + 密钥数据  
    inner_tlv = b'\x04' + encode_length(len(key_component_data)) + key_component_data
    
    # 连接：外层TLV + 内层TLV （并列，不是嵌套！）绝对有无数傻逼死在这里~
    return outer_tlv + inner_tlv

def parse_pkcs8_private_key(der_data: bytes) -> tuple[bytes, bytes]:
    """
      解析PKCS#8格式的RSA私钥，提取模数和私指数
    
    PKCS#8结构：
    PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey (OCTET STRING包含PKCS#1私钥)
    }
    """
    print("\n  开始解析PKCS#8私钥格式...")
    
    def read_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
        """读取ASN.1长度字段"""
        if data[offset] & 0x80 == 0:
            # 短格式
            return data[offset], offset + 1
        else:
            # 长格式
            length_bytes = data[offset] & 0x7F
            if length_bytes == 0:
                raise ValueError("无限长度格式不支持")
            length = 0
            for i in range(length_bytes):
                length = (length << 8) | data[offset + 1 + i]
            return length, offset + 1 + length_bytes
    
    def read_asn1_integer(data: bytes, offset: int) -> tuple[bytes, int]:
        """读取ASN.1 INTEGER"""
        if data[offset] != 0x02:
            raise ValueError(f"期望INTEGER标签0x02，得到0x{data[offset]:02X}")
        length, new_offset = read_asn1_length(data, offset + 1)
        value = data[new_offset:new_offset + length]
        
        # 移除前导零
        while len(value) > 1 and value[0] == 0x00:
            value = value[1:]
            
        return value, new_offset + length
    
    try:
        offset = 0
        
        # 1. 外层SEQUENCE
        if der_data[offset] != 0x30:
            raise ValueError(f"期望SEQUENCE标签0x30，得到0x{der_data[offset]:02X}")
        
        seq_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ PKCS#8 SEQUENCE长度: {seq_length} 字节")
        
        # 2. Version INTEGER (应该是0)
        version, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Version: {int.from_bytes(version, 'big')}")
        
        # 3. AlgorithmIdentifier SEQUENCE
        if der_data[offset] != 0x30:
            raise ValueError(f"期望AlgorithmIdentifier SEQUENCE，得到0x{der_data[offset]:02X}")
        
        alg_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ AlgorithmIdentifier长度: {alg_length} 字节")
        
        # 跳过整个AlgorithmIdentifier
        offset += alg_length
        
        # 4. PrivateKey OCTET STRING
        if der_data[offset] != 0x04:
            raise ValueError(f"期望PrivateKey OCTET STRING，得到0x{der_data[offset]:02X}")
        
        octet_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ PrivateKey OCTET STRING长度: {octet_length} 字节")
        
        # 5. 提取内部的PKCS#1私钥
        pkcs1_data = der_data[offset:offset + octet_length]
        print(f"✓ 提取PKCS#1数据，长度: {len(pkcs1_data)} 字节")
        
        # 6. 解析PKCS#1格式
        print("\n  解析内部PKCS#1格式...")
        return parse_pkcs1_private_key(pkcs1_data)
        
    except Exception as e:
        print(f"× PKCS#8解析失败: {e}")
        print(f"  详细诊断:")
        print(f"   文件大小: {len(der_data)} 字节")
        if len(der_data) >= 20:
            print(f"   前20字节: {der_data[:20].hex().upper()}")
        raise

def parse_pkcs1_private_key(der_data: bytes) -> tuple[bytes, bytes]:
    """
      解析PKCS#1格式的RSA私钥
    
    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e  
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER   -- (inverse of q) mod p
    }
    """
    
    def read_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
        """读取ASN.1长度字段"""
        if data[offset] & 0x80 == 0:
            return data[offset], offset + 1
        else:
            length_bytes = data[offset] & 0x7F
            if length_bytes == 0:
                raise ValueError("无限长度格式不支持")
            length = 0
            for i in range(length_bytes):
                length = (length << 8) | data[offset + 1 + i]
            return length, offset + 1 + length_bytes
    
    def read_asn1_integer(data: bytes, offset: int) -> tuple[bytes, int]:
        """读取ASN.1 INTEGER"""
        if data[offset] != 0x02:
            raise ValueError(f"期望INTEGER标签0x02，得到0x{data[offset]:02X}")
        length, new_offset = read_asn1_length(data, offset + 1)
        value = data[new_offset:new_offset + length]
        
        # 移除前导零
        while len(value) > 1 and value[0] == 0x00:
            value = value[1:]
            
        return value, new_offset + length
    
    try:
        offset = 0
        
        # 1. 外层SEQUENCE
        if der_data[offset] != 0x30:
            raise ValueError(f"期望SEQUENCE标签0x30，得到0x{der_data[offset]:02X}")
        
        seq_length, offset = read_asn1_length(der_data, offset + 1)
        print(f"✓ PKCS#1 SEQUENCE长度: {seq_length} 字节")
        
        # 2. Version
        version, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Version: {int.from_bytes(version, 'big')}")
        
        # 3. Modulus (n)
        modulus, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Modulus长度: {len(modulus)} 字节 ({len(modulus)*8} bits)")
        
        # 4. Public Exponent (e) - 跳过
        pub_exp, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Public Exponent: {int.from_bytes(pub_exp, 'big')}")
        
        # 5. Private Exponent (d)
        private_exp, offset = read_asn1_integer(der_data, offset)
        print(f"✓ Private Exponent长度: {len(private_exp)} 字节")
        
        if DEBUG_MODE:
            print(f"\n  RSA密钥组件:")
            print(f"   Modulus (前16字节): {modulus[:16].hex().upper()}...")
            print(f"   Private Exp (前16字节): {private_exp[:16].hex().upper()}...")
        
        return modulus, private_exp
        
    except Exception as e:
        print(f"× PKCS#1解析失败: {e}")
        if len(der_data) >= 20:
            print(f"  前20字节: {der_data[:20].hex().upper()}")
            context = der_data[max(0, offset-10):offset+10] if 'offset' in locals() else der_data[:20]
            if context:
                print(f"  周围字节: {context.hex().upper()}")
        raise



def write_aa_secret(connection, key_file_path: str = "AA_RSA1024_private.der"):
    """
    【阶段零：机密注入】
    在任何其他个人化操作之前，通过专用通道写入AA私钥。
    """
    print("\n" + "="*60)
    print(">> 阶段零：机密注入 (写入AA私钥)")
    print("="*60)

    # 1. 同目录查找RSA1024关键字文件
    script_dir = os.path.dirname(__file__)
    found_key_path = None
    
    # 先尝试默认文件名
    default_path = os.path.join(script_dir, key_file_path)
    if os.path.exists(default_path):
        found_key_path = default_path
    else:
        # 搜索包含RSA1024的文件
        for filename in os.listdir(script_dir):
            if 'RSA_1024' in filename and filename.endswith('.der'):
                found_key_path = os.path.join(script_dir, filename)
                break
    
    if not found_key_path:
        print(f"× [FAIL] 未找到RSA1024私钥文件!")
        print(">> 🚨 缺少机密文件，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开")
        except:
            print("！ [DISCONNECT] 断卡失败")
        exit(1)
    
    key_file_path = found_key_path
    print(f"√ 找到AA私钥: {os.path.basename(key_file_path)}")

    # 2. 解析AA私钥文件
    print(f"-> 解析AA私钥文件: {key_file_path}")
    try:
        with open(key_file_path, 'rb') as f:
            key_data = f.read()
        
        print(f"✓ 文件读取成功: {len(key_data)} 字节")
        
        # 自动检测格式并解析
        try:
            modulus, private_exponent = parse_pkcs8_private_key(key_data)
        except Exception as e:
            print(f"！ PKCS#8解析失败，尝试PKCS#1格式: {e}")
            modulus, private_exponent = parse_pkcs1_private_key(key_data)
        
        print(f"√ AA私钥解析成功!")
        print(f"   密钥长度: {len(modulus)*8} bits")
        print(f"   Modulus: {len(modulus)} 字节")
        print(f"   Private Exponent: {len(private_exponent)} 字节")
        
    except Exception as e:
        print(f"× [FAIL] AA私钥解析失败: {e}")
        print(">> 🚨 机密注入失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开 - 手动断电重新开始")
        except:
            print("！ [DISCONNECT] 断卡失败，手动断电")
        print(">> 🛑 程序终止 - 手动断电后重新运行")
        exit(1)

    # 3. SELECT AID (确保正与Applet对话)
    print("-> 选择护照应用...")
    aid_bytes = bytes([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) + aid_bytes
    resp_data, sw = send_apdu(connection, apdu, "AA_SELECT_AID")
    if sw != 0x9000:
        print(f"× [FAIL] 机密注入失败：选择Applet失败，SW={hex(sw)}")
        print(">> 🚨 Applet选择失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开 - 手动断电重新开始")
        except:
            print("！ [DISCONNECT] 断卡失败，手动断电")
        print(">> 🛑 程序终止 - 手动断电后重新运行")
        exit(1)
    print("✓ 护照应用已准备好接收机密...")

    # 4. 通过绿色通道写入AA密钥组件（一次性TLV格式）
    try:
        print("\n-> 开始机密注入...")
        
        # 构造并发送模数 (P2=0x60)
        print("-> 构造并发送AA模数...")
        modulus_payload = build_aa_key_payload(0x60, modulus)
        
        # 支持扩展长度APDU
        if len(modulus_payload) <= 255:
            apdu_mod = bytes([0x00, 0xDA, 0x00, 0x60, len(modulus_payload)]) + modulus_payload
        else:
            # 扩展长度格式：CLA INS P1 P2 00 LenHi LenLo Data
            apdu_mod = bytes([0x00, 0xDA, 0x00, 0x60, 0x00, 
                             (len(modulus_payload) >> 8) & 0xFF, 
                             len(modulus_payload) & 0xFF]) + modulus_payload
        
        print(f"   TLV载荷长度: {len(modulus_payload)} 字节")
        print(f"   APDU总长度: {len(apdu_mod)} 字节")
        if DEBUG_MODE:
            print(f"   TLV格式: {modulus_payload[:20].hex().upper()}...")
        
        resp_data, sw = send_apdu(connection, apdu_mod, "PUT_AA_MODULUS_TLV")
        if sw != 0x9000:
            raise RuntimeError(f"写入AA模数失败, SW={sw:04X}")
        print("✓ 模数注入成功！")
        #私钥必须一发APDU打进去，护照机制这样设定的！
        
        # 构造并发送私钥指数 (P2=0x61)
        print("-> 构造并发送AA私钥指数...")
        exp_payload = build_aa_key_payload(0x61, private_exponent)
        
        # 支持扩展长度APDU
        if len(exp_payload) <= 255:
            apdu_exp = bytes([0x00, 0xDA, 0x00, 0x61, len(exp_payload)]) + exp_payload
        else:
            # 扩展长度格式：CLA INS P1 P2 00 LenHi LenLo Data
            apdu_exp = bytes([0x00, 0xDA, 0x00, 0x61, 0x00, 
                             (len(exp_payload) >> 8) & 0xFF, 
                             len(exp_payload) & 0xFF]) + exp_payload
        
        print(f"   TLV载荷长度: {len(exp_payload)} 字节")
        print(f"   APDU总长度: {len(apdu_exp)} 字节")
        if DEBUG_MODE:
            print(f"   TLV格式: {exp_payload[:20].hex().upper()}...")
        
        resp_data, sw = send_apdu(connection, apdu_exp, "PUT_AA_EXPONENT_TLV")
        if sw != 0x9000:
            raise RuntimeError(f"写入AA私钥指数失败, SW={sw:04X}")
        print("✓ 私钥指数注入成功！")
        print("\n√ [SUCCESS] 阶段零：机密注入完成！AA私钥已写入。")
        print(">> 绿色通道机密注入成功！")
        print("="*60)
        
    except Exception as e:
        print(f"× [FAIL] 机密注入失败: {e}")
        print(">> 🚨 密钥写入失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开 - 手动断电重新开始")
        except:
            print("！ [DISCONNECT] 断卡失败，手动断电")
        print(">> 🛑 程序终止 - 手动断电后重新运行")
        exit(1)


def build_ca_key_payload(tag: int, key_component_data: bytes) -> bytes:
    """
    格式纯抄AA
    [外层标签][外层长度0][内层标签0x04][内层长度][密钥数据]
    """
    # 外层TLV：tag + 长度0
    outer_tlv = bytes([tag, 0x00])
    
    # 内层TLV：OCTET STRING (0x04) + 长度 + 密钥数据
    inner_tlv = b'\x04' + encode_length(len(key_component_data)) + key_component_data
    
    # 连接：外层TLV + 内层TLV（并列结构）
    return outer_tlv + inner_tlv


def write_ca_secret(connection, country_code: str = "CA_P224_private_s.bin"):
    """
    【阶段零：机密注入】写入CA私钥S值
    """
    print("\n" + "="*60)
    print(">> 阶段零：机密注入 (写入CA密钥)")
    print("="*60)

    # 初始化变量
    script_dir = os.path.dirname(__file__)
    found_key_path = None

    # 1. 先尝试默认文件名
    default_path = os.path.join(script_dir, country_code)
    if os.path.exists(default_path):
        found_key_path = default_path
    else:
        # 搜索包含CA_P224的文件
        for filename in os.listdir(script_dir):
            if 'CA_P224_private_s' in filename and filename.endswith('.bin'):
                found_key_path = os.path.join(script_dir, filename)
                break
    
    if not found_key_path:
        print(f"× [FAIL] 未找到CA_P224_private_s文件!")
        print(">> 🚨 缺少机密文件，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开")
        except:
            print("！ [DISCONNECT] 断卡失败")
        exit(1)
    
    print(f"√ 找到CA私钥: {os.path.basename(found_key_path)}")

    # 2. 读取密钥文件
    try:
        with open(found_key_path, 'rb') as f:
            s_value = f.read()
            
        print(f"✓ S值读取成功: {len(s_value)} 字节")
        
        # 验证长度
        if len(s_value) != 28:
            raise ValueError(f"CA私钥S值长度错误: 期望28字节，实际{len(s_value)}字节")

    except Exception as e:
        print(f"× [FAIL] CA密钥读取失败: {e}")
        print(">> 🚨 机密读取失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开")
        except:
            print("！ [DISCONNECT] 断卡失败")
        exit(1)

    # 3. 跳过SELECT AID规避一切回读的可能发生
    print("-> 复用已选择的护照应用会话...")
    print("✓ 使用现有会话写入CA密钥...")

    # 4. 写入CA密钥组件
    try:
        print("\n-> 开始CA机密注入...")
        
        # 构造并发送CA私钥S值 (P2=0x63)
        print("-> 写入CA私钥S值...")
        # 使用CA专用的TLV格式构建函数
        s_payload = build_ca_key_payload(0x63, s_value)
        
        # 支持扩展长度APDU（虽然CA密钥不需要，但保持与AA一致）
        if len(s_payload) <= 255:
            apdu_s = bytes([0x00, 0xDA, 0x00, 0x63, len(s_payload)]) + s_payload
        else:
            # 扩展长度格式：CLA INS P1 P2 00 LenHi LenLo Data
            apdu_s = bytes([0x00, 0xDA, 0x00, 0x63, 0x00, 
                           (len(s_payload) >> 8) & 0xFF, 
                           len(s_payload) & 0xFF]) + s_payload
        
        print(f"   S值长度: {len(s_value)} 字节")
        print(f"   TLV载荷长度: {len(s_payload)} 字节")
        print(f"   APDU总长度: {len(apdu_s)} 字节")
        if DEBUG_MODE:
            print(f"   TLV格式: {s_payload[:20].hex().upper()}...")
        
        resp_data, sw = send_apdu(connection, apdu_s, "PUT_CA_PRIVATE_S")
        if sw != 0x9000:
            raise RuntimeError(f"写入CA私钥S值失败, SW={sw:04X}")
        print("✓ CA私钥S值注入成功！")
        
        print("\n√ [SUCCESS] CA密钥注入完成！")
        print("="*60)
        
    except Exception as e:
        print(f"× [FAIL] CA机密注入失败: {e}")
        print(">> 🚨 CA密钥写入失败，必须断卡！")
        try:
            connection.disconnect()
            print("√ [DISCONNECT] 卡片已断开")
        except:
            print("！ [DISCONNECT] 断卡失败")
        exit(1)
        
        
###上面的代码结束，下面是main结构的代码

if __name__ == "__main__":
    try:
        doc_nr = ""    
        dob = ""
        doe = ""
        com_path = "COM.bin"
        dg1_path = "DG1.bin"
        dg2_path = "DG2.bin"
        dg11_path = "DG11.bin"
        dg12_path = "DG12.bin"
        dg14_path = "DG14.bin" 
        dg15_path = "DG15.bin"
        sod_path = "SOD.bin"
        aid = "A0 00 00 02 47 10 01"
        
        # 🚨 阶段零：机密注入
        # 在任何其他个人化操作之前写入AA私钥
        print("\n" + "="*80)
        print(" 启动passport个人化")
        print("="*80)
        
        # 连接读卡器
        connection = connect_reader()
        
        # 🚨在这里插入！设置官方超时（单位：秒）
        # 这是 pyscard 库自带的功能，比自己写线程更稳定！
        connection.TIMEOUT = 30  # 设置30秒超时
        
        # 🚨这里就是最完美的插入点！
        # 【阶段零：机密注入】- 利用绿色通道写入AA私钥
        print("\n>>  执行阶段零：机密注入...")
        write_aa_secret(connection, "AA_RSA1024_private.der")
        
        # 写入CA密钥
        write_ca_secret(connection, "CA_P224_private_s.bin")
        
        # 如果执行到这里，说明机密注入成功，继续标准个人化
        print(">> √ 阶段零完成！AA和CA密钥已写入！")
        print(">>  开始阶段一：安全报文机制下继续烧卡")
        
        # 然后执行原有的、完整的、不可修改的个人化流程
        success = personalize_passport(doc_nr, dob, doe, com_path, dg1_path, dg2_path, dg11_path, dg12_path, dg14_path, dg15_path, sod_path, aid, connection)
        
        if not success:
            input("\n[PAUSE] Press Enter to exit...")
            
    except KeyboardInterrupt:
        print("\n\n[STOP] Operation cancelled by user")
    except Exception as e:
        print(f"\n[FAIL] Critical error: {e}")
        if DEBUG_MODE:
            traceback.print_exc()
        input("\n[PAUSE] Press Enter to exit...")
        
    finally:
        # 新增：无论成功失败，都生成APDU分析报告！
        try:
            print(f"\n   Generating final APDU analysis report...")
            apdu_analyzer.generate_session_report()
            print("  [ANALYSIS] Complete session analysis saved to 'apdu_analysis_report.txt'")
            print("  [ANALYSIS] This report contains:")
            print("             ├── Complete APDU command/response history")
            print("             ├── Timing performance analysis")
            print("             ├── Data integrity verification")
            print("             ├── Error pattern analysis")
            print("             └── Hardware performance statistics")
            print("  [ANALYSIS] Use this for debugging and optimization!")
        except Exception as report_error:
            print(f"[WARN] Failed to generate analysis report: {report_error}")
        
        try:
            # 尝试清理连接（如果还活跃）
            print(f"\n[CLEANUP] Checking connection status...")
            if 'connection' in locals() and connection:
                connection.disconnect()
                print("[OK] Reader disconnected in cleanup")
            else:
                print("[INFO] Connection already closed")
        except:
            print("[INFO] Connection cleanup completed")
            pass
            
            
            #结束。