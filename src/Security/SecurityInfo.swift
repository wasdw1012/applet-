//
//  SecurityInfo.swift
//
//  安全信息基类和解析逻辑
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15,*)
public class SecurityInfo {
    
    // MARK: - CA相关OID定义
    
    // 芯片认证公钥OID
    static let ID_PK_DH_OID = "0.4.0.127.0.7.2.2.1.1"     // DH公钥
    static let ID_PK_ECDH_OID = "0.4.0.127.0.7.2.2.1.2"   // ECDH公钥
    
    // 芯片认证算法OID
    static let ID_CA_DH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.1.1"
    static let ID_CA_ECDH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.2.1"
    static let ID_CA_DH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.1.2"
    static let ID_CA_DH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.1.3"
    static let ID_CA_DH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.1.4"
    static let ID_CA_ECDH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.2.2"
    static let ID_CA_ECDH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.2.3"
    static let ID_CA_ECDH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.2.4"
    
    // 基类方法 - 子类必须重写
    public func getObjectIdentifier() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    public func getProtocolOIDString() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    // MARK: - 解析SecurityInfo
    
    /// 从ASN.1对象创建相应的SecurityInfo实例
    /// - Parameters:
    ///   - object: ASN.1解析后的对象
    ///   - body: 原始数据
    /// - Returns: 相应的SecurityInfo子类实例
    static func getInstance( object : ASN1Item, body: [UInt8] ) -> SecurityInfo? {
        // SecurityInfo结构：
        // SEQUENCE {
        //   protocol OBJECT IDENTIFIER,
        //   requiredData ANY DEFINED BY protocol,
        //   optionalData ANY DEFINED BY protocol OPTIONAL
        // }
        
        let oid = object.getChild(0)?.value ?? ""
        let requiredData = object.getChild(1)!
        var optionalData : ASN1Item? = nil
        if (object.getNumberOfChildren() == 3) {
            optionalData = object.getChild(2)
        }
        
        // 根据OID创建相应的实例
        if ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(oid) {
            // 解析公钥信息
            let keyData : [UInt8] = [UInt8](body[requiredData.pos ..< requiredData.pos+requiredData.headerLen+requiredData.length])
            
            // 使用OpenSSL解析SubjectPublicKeyInfo
            var subjectPublicKeyInfo : OpaquePointer? = nil
            let _ = keyData.withUnsafeBytes { (ptr) in
                var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                subjectPublicKeyInfo = d2i_PUBKEY(nil, &newPtr, keyData.count)
            }
            
            if let subjectPublicKeyInfo = subjectPublicKeyInfo {
                if optionalData == nil {
                    return ChipAuthenticationPublicKeyInfo(oid:oid, pubKey:subjectPublicKeyInfo)
                } else {
                    // 包含keyId
                    let keyId = Int(optionalData!.value, radix: 16)
                    return ChipAuthenticationPublicKeyInfo(oid:oid, pubKey:subjectPublicKeyInfo, keyId: keyId)
                }
            }
            
        } else if ChipAuthenticationInfo.checkRequiredIdentifier(oid) {
            // 解析CA算法信息
            let version = Int(requiredData.value) ?? -1
            if let optionalData = optionalData {
                let keyId = Int(optionalData.value, radix: 16)
                return ChipAuthenticationInfo(oid: oid, version: version, keyId: keyId)
            } else {
                return ChipAuthenticationInfo(oid: oid, version: version)
            }
        }
        // 这里可以添加其他SecurityInfo类型的解析（如PACEInfo、ActiveAuthenticationInfo等）
        
        return nil
    }
}

// MARK: - ASN.1辅助结构

/// 简化的ASN.1项表示
class ASN1Item {
    var pos: Int = 0
    var headerLen: Int = 0
    var length: Int = 0
    var value: String = ""
    var children: [ASN1Item] = []
    
    func getNumberOfChildren() -> Int {
        return children.count
    }
    
    func getChild(_ index: Int) -> ASN1Item? {
        guard index < children.count else { return nil }
        return children[index]
    }
}