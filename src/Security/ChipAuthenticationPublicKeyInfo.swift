//
//  ChipAuthenticationPublicKeyInfo.swift
//  
//  定义芯片认证公钥信息
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationPublicKeyInfo : SecurityInfo {
    var oid : String
    var pubKey : OpaquePointer  // OpenSSL公钥对象
    var keyId : Int?
    
    
    // 检查OID是否为支持的公钥类型
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return ID_PK_DH_OID == oid
            || ID_PK_ECDH_OID == oid
    }
    
    init(oid:String, pubKey:OpaquePointer, keyId: Int? = nil) {
        self.oid = oid
        self.pubKey = pubKey
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return ChipAuthenticationPublicKeyInfo.toProtocolOIDString(oid:oid)
    }

    // 获取密钥ID，如果未设置则返回0（表示只有一个密钥）
    public func getKeyId() -> Int {
        return keyId ?? 0
    }
    

    private static func toProtocolOIDString(oid : String) -> String {
        if ID_PK_DH_OID == oid {
            return "id-PK-DH"
        }
        if ID_PK_ECDH_OID == oid {
            return "id-PK-ECDH"
        }
        
        return oid
    }

}