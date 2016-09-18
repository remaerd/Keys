//
//  Hash.swift
//  Keys
//
//  Created by Sean Cheng on 8/9/15.
//
//

import Foundation
import CommonCrypto


public extension Data {
  
  public var MD2: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_MD2_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_MD2(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_MD2_DIGEST_LENGTH))
  }
  
  
  public var MD4: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_MD4_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_MD4(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_MD4_DIGEST_LENGTH))
  }
  
  
  public var MD5: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_MD5(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_MD5_DIGEST_LENGTH))
  }
  
  
  public var SHA1: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_SHA1(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_SHA1_DIGEST_LENGTH))
  }
  
  
  public var SHA224: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_SHA224(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_SHA224_DIGEST_LENGTH))
  }
  
  
  public var SHA256: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_SHA256(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_SHA256_DIGEST_LENGTH))
  }
  
  
  public var SHA384: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_SHA384(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_SHA384_DIGEST_LENGTH))
  }
  
  
  public var SHA512: Data {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    var pointer : UnsafePointer<UInt8>? = nil
    withUnsafeBytes({ (ptr) in pointer = ptr})
    CC_SHA512(pointer, CC_LONG(count), &hash)
    return Data(bytes: UnsafePointer<UInt8>(hash), count: Int(CC_SHA512_DIGEST_LENGTH))
  }
}


public extension String {
  
  public var MD2: String? {
    return String(digestData: hashData?.MD2, length: CC_MD2_DIGEST_LENGTH)
  }
  
  
  public var MD4: String? {
    return String(digestData: hashData?.MD4, length: CC_MD4_DIGEST_LENGTH)
  }
  
  
  public var MD5: String? {
    return String(digestData: hashData?.MD5, length: CC_MD5_DIGEST_LENGTH)
  }
  
  
  public var SHA1: String? {
    return String(digestData: hashData?.SHA1, length: CC_SHA1_DIGEST_LENGTH)
  }
  
  
  public var SHA224: String? {
    return String(digestData: hashData?.SHA224, length: CC_SHA224_DIGEST_LENGTH)
  }
  
  
  public var SHA256: String? {
    return String(digestData: hashData?.SHA256, length: CC_SHA256_DIGEST_LENGTH)
  }
  
  
  public var SHA384: String? {
    return String(digestData: hashData?.SHA384, length: CC_SHA384_DIGEST_LENGTH)
  }
  
  
  public var SHA512: String? {
    return String(digestData: hashData?.SHA512, length: CC_SHA512_DIGEST_LENGTH)
  }
  
  
  fileprivate var hashData: Data?
  {
    return data(using: String.Encoding.utf8, allowLossyConversion: false)
  }
  
  
  fileprivate init?(digestData: Data?, length: Int32) {
    guard let digestData = digestData else { return nil }
    var digest = [UInt8](repeating: 0, count: Int(length))
    (digestData as NSData).getBytes(&digest, length: Int(length) * MemoryLayout<UInt8>.size)
    
    var string = ""
    for i in 0..<length {
      string += String(format: "%02x", digest[Int(i)])
    }
    self.init(string)
  }
}
