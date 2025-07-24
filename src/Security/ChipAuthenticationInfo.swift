//
//  ChipAuthenticationInfo.swift
//  
//  定义芯片认证信息，包括OID、版本和密钥ID
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationInfo : SecurityInfo {
    
    var oid : String
    var version : Int
    var keyId : Int?
    
    // 检查OID是否为支持的CA算法
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_ECDH_3DES_CBC_CBC_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_192_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_256_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid
    }
    
    init(oid: String, version: Int, keyId: Int? = nil) {
        self.oid = oid
        self.version = version
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return ChipAuthenticationInfo.toProtocolOIDString(oid:oid)
    }
    
    // 获取密钥ID，如果未设置则返回0（表示只有一个密钥）
    public func getKeyId() -> Int {
        return keyId ?? 0
    }
    
    /// 返回密钥协商算法 - DH或ECDH
    /// - Parameter oid: 对象标识符
    /// - Returns: 密钥协商算法
    /// - Throws: 无效OID时抛出InvalidDataPassed错误
    public static func toKeyAgreementAlgorithm( oid : String ) throws -> String {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_192_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_256_OID == oid {
            return "DH";
        } else if ID_CA_ECDH_3DES_CBC_CBC_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return "ECDH";
        }
        
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup key agreement algorithm - invalid oid" )
    }
    
    /// 返回加密算法 - DESede或AES
    /// - Parameter oid: 对象标识符
    /// - Returns: 加密算法类型
    /// - Throws: 无效OID时抛出InvalidDataPassed错误
    public static func toCipherAlgorithm( oid : String ) throws -> String {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_ECDH_3DES_CBC_CBC_OID == oid {
            return "DESede";
        } else if ID_CA_DH_AES_CBC_CMAC_128_OID == oid
                    || ID_CA_DH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_DH_AES_CBC_CMAC_256_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return "AES";
        }
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup cipher algorithm - invalid oid" )
    }
    
    /// 返回密钥长度（位数：128、192或256）
    /// - Parameter oid: 对象标识符
    /// - Returns: 密钥长度（位）
    /// - Throws: 无效OID时抛出InvalidDataPassed错误
    public static func toKeyLength( oid : String ) throws -> Int {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_ECDH_3DES_CBC_CBC_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid {
            return 128;
        } else if ID_CA_DH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid {
            return 192;
        } else if ID_CA_DH_AES_CBC_CMAC_256_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return 256;
        }
        
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to get key length - invalid oid" )
    }
    
    // OID到可读字符串的转换
    private static func toProtocolOIDString(oid : String) -> String {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid {
            return "id-CA-DH-3DES-CBC-CBC"
        }
        if ID_CA_DH_AES_CBC_CMAC_128_OID == oid {
            return "id-CA-DH-AES-CBC-CMAC-128"
        }
        if ID_CA_DH_AES_CBC_CMAC_192_OID == oid {
            return "id-CA-DH-AES-CBC-CMAC-192"
        }
        if ID_CA_DH_AES_CBC_CMAC_256_OID == oid {
            return "id-CA-DH-AES-CBC-CMAC-256"
        }
        if ID_CA_ECDH_3DES_CBC_CBC_OID == oid {
            return "id-CA-ECDH-3DES-CBC-CBC"
        }
        if ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid {
            return "id-CA-ECDH-AES-CBC-CMAC-128"
        }
        if ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid {
            return "id-CA-ECDH-AES-CBC-CMAC-192"
        }
        if ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return "id-CA-ECDH-AES-CBC-CMAC-256"
        }
        
        return oid
    }
}