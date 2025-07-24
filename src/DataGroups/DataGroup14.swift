//
//  DataGroup14.swift
//
//  DG14包含安全信息，包括CA认证所需的公钥信息
//

import Foundation

// SecurityInfos ::= SET of SecurityInfo
// SecurityInfo ::= SEQUENCE {
//    protocol OBJECT IDENTIFIER,
//    requiredData ANY DEFINED BY protocol,
//    optionalData ANY DEFINED BY protocol OPTIONAL
@available(iOS 13, macOS 10.15, *)
public class DataGroup14 : DataGroup {
    private var asn1 : ASN1Item!
    public private(set) var securityInfos : [SecurityInfo] = [SecurityInfo]()

    public override var datagroupType: DataGroupId { .DG14 }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        let p = SimpleASN1DumpParser()
        asn1 = try p.parse(data: Data(body))
        
        // 遍历ASN.1结构，解析每个SecurityInfo
        for i in 0 ..< asn1.getNumberOfChildren() {
            if let child = asn1.getChild(i),
               let secInfo = SecurityInfo.getInstance( object:child, body : body ) {
                securityInfos.append(secInfo)
            }
        }
    }
}