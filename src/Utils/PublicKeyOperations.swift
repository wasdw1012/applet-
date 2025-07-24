//
//  PublicKeyOperations.swift
//
//  CA认证中的公钥操作工具函数
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
public class PublicKeyOperations {
    
    /// 从OpenSSL公钥对象中提取公钥数据
    /// - Parameter key: OpenSSL的EVP_PKEY对象
    /// - Returns: 公钥的原始字节数据
    public static func getPublicKeyData(from key:OpaquePointer) -> [UInt8]? {
        var data : [UInt8] = []
        // 获取密钥类型
        let v = EVP_PKEY_base_id( key )
        
        if v == EVP_PKEY_DH || v == EVP_PKEY_DHX {
            // DH公钥提取
            guard let dh = EVP_PKEY_get0_DH(key) else {
                return nil
            }
            var dhPubKey : OpaquePointer?
            DH_get0_key(dh, &dhPubKey, nil)
            
            // 将大数转换为字节数组
            let nrBytes = (BN_num_bits(dhPubKey)+7)/8
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            _ = BN_bn2bin(dhPubKey, &data)
            
        } else if v == EVP_PKEY_EC {
            // ECDH公钥提取
            guard let ec = EVP_PKEY_get0_EC_KEY(key),
                let ec_pub = EC_KEY_get0_public_key(ec),
                let ec_group = EC_KEY_get0_group(ec) else {
                return nil
            }
            
            // 获取点的编码格式（压缩或非压缩）
            let form = EC_KEY_get_conv_form(ec)
            
            // 计算编码后的长度
            let len = EC_POINT_point2oct(ec_group, ec_pub, form, nil, 0, nil)
            data = [UInt8](repeating: 0, count: Int(len))
            if len == 0 {
                return nil
            }
            
            // 将EC点编码为字节数组
            _ = EC_POINT_point2oct(ec_group, ec_pub, form, &data, len, nil)
        }
        
        return data
    }
    
    /// 计算DH/ECDH共享密钥
    /// - Parameters:
    ///   - privateKeyPair: 本地私钥
    ///   - publicKey: 对方公钥
    /// - Returns: 共享密钥字节数组
    public static func computeSharedSecret( privateKeyPair: OpaquePointer, publicKey: OpaquePointer ) -> [UInt8] {
        
        var secret : [UInt8]
        let keyType = EVP_PKEY_base_id( privateKeyPair )
        
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            // DH共享密钥计算
            let dh = EVP_PKEY_get1_DH(privateKeyPair);
            
            // 获取对方的公钥值
            let dh_pub = EVP_PKEY_get1_DH(publicKey)
            var bn = BN_new()
            DH_get0_key( dh_pub, &bn, nil )
            
            // 计算共享密钥
            secret = [UInt8](repeating: 0, count: Int(DH_size(dh)))
            let len = DH_compute_key(&secret, bn, dh);
            
            Logger.openSSL.debug( "DH shared secret length: \(len)" )
        } else {
            // ECDH共享密钥计算
            let ctx = EVP_PKEY_CTX_new(privateKeyPair, nil)
            defer{ EVP_PKEY_CTX_free(ctx) }
            
            // 初始化密钥派生
            if EVP_PKEY_derive_init(ctx) != 1 {
                Logger.openSSL.error( "EVP_PKEY_derive_init failed" )
            }
            
            // 设置对方公钥
            if EVP_PKEY_derive_set_peer( ctx, publicKey ) != 1 {
                Logger.openSSL.error( "EVP_PKEY_derive_set_peer failed" )
            }
            
            // 获取共享密钥长度
            var keyLen = 0
            if EVP_PKEY_derive(ctx, nil, &keyLen) != 1 {
                Logger.openSSL.error( "EVP_PKEY_derive (get length) failed" )
            }
            
            // 派生共享密钥
            secret = [UInt8](repeating: 0, count: keyLen)
            if EVP_PKEY_derive(ctx, &secret, &keyLen) != 1 {
                Logger.openSSL.error( "EVP_PKEY_derive failed" )
            }
        }
        return secret
    }
    
    /// 基于参数生成密钥对
    /// - Parameter params: 包含域参数的公钥对象
    /// - Returns: 新生成的密钥对
    public static func generateKeyPair(from params: OpaquePointer) -> OpaquePointer? {
        var keyPair : OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(params, nil)
        defer { EVP_PKEY_CTX_free(pctx) }
        
        // 初始化密钥生成
        guard EVP_PKEY_keygen_init(pctx) == 1 else {
            return nil
        }
        
        // 生成密钥对
        guard EVP_PKEY_keygen(pctx, &keyPair) == 1 else {
            return nil
        }
        
        return keyPair
    }
    
    /// 从ASN.1编码的数据中解析公钥
    /// - Parameter keyData: DER编码的SubjectPublicKeyInfo
    /// - Returns: 解析后的公钥对象
    public static func parsePublicKey(from keyData: [UInt8]) -> OpaquePointer? {
        var publicKey : OpaquePointer? = nil
        let _ = keyData.withUnsafeBytes { (ptr) in
            var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            publicKey = d2i_PUBKEY(nil, &newPtr, keyData.count)
        }
        return publicKey
    }
    
    /// 将OID字符串转换为ASN.1编码
    /// - Parameter oid: OID字符串（如"0.4.0.127.0.7.2.2.1.1"）
    /// - Returns: ASN.1编码的字节数组
    public static func encodeOID(_ oid: String) -> [UInt8] {
        // OID编码规则：
        // 第一个字节 = 40 * 第一个数字 + 第二个数字
        // 后续数字使用可变长度编码
        let components = oid.split(separator: ".").compactMap { Int($0) }
        guard components.count >= 2 else { return [] }
        
        var encoded = [UInt8]()
        
        // 编码前两个数字
        encoded.append(UInt8(40 * components[0] + components[1]))
        
        // 编码剩余数字
        for i in 2..<components.count {
            let value = components[i]
            if value <= 127 {
                encoded.append(UInt8(value))
            } else {
                // 多字节编码
                var temp = [UInt8]()
                var v = value
                while v > 0 {
                    temp.insert(UInt8(v & 0x7F), at: 0)
                    v >>= 7
                }
                // 设置高位标志
                for j in 0..<temp.count-1 {
                    temp[j] |= 0x80
                }
                encoded += temp
            }
        }
        
        // 添加ASN.1标签和长度
        var result = [UInt8]()
        result.append(0x06)  // OID标签
        result.append(UInt8(encoded.count))
        result += encoded
        
        return result
    }
}

// MARK: - 密钥类型常量
extension PublicKeyOperations {
    // OpenSSL EVP_PKEY类型
    static let EVP_PKEY_DH = 28
    static let EVP_PKEY_DHX = 920
    static let EVP_PKEY_EC = 408
}