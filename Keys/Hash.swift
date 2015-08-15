//
//  Hash.swift
//  Keys
//
//  Created by Sean Cheng on 8/9/15.
//
//

import Foundation
import CommonCrypto


public extension NSData {
  
  public var MD2: NSData {
    var hash = [UInt8](count: Int(CC_MD2_DIGEST_LENGTH), repeatedValue: 0)
    CC_MD2(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_MD2_DIGEST_LENGTH))
  }
  
  
  public var MD4: NSData {
    var hash = [UInt8](count: Int(CC_MD4_DIGEST_LENGTH), repeatedValue: 0)
    CC_MD4(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_MD4_DIGEST_LENGTH))
  }
  
  
  public var MD5: NSData {
    var hash = [UInt8](count: Int(CC_MD5_DIGEST_LENGTH), repeatedValue: 0)
    CC_MD5(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_MD5_DIGEST_LENGTH))
  }
  
  
  public var SHA1: NSData {
    var hash = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
    CC_SHA1(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_SHA1_DIGEST_LENGTH))
  }
  
  
  public var SHA224: NSData {
    var hash = [UInt8](count: Int(CC_SHA224_DIGEST_LENGTH), repeatedValue: 0)
    CC_SHA224(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_SHA224_DIGEST_LENGTH))
  }
  
  
  public var SHA256: NSData {
    var hash = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
    CC_SHA256(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_SHA256_DIGEST_LENGTH))
  }
  
  
  public var SHA384: NSData {
    var hash = [UInt8](count: Int(CC_SHA384_DIGEST_LENGTH), repeatedValue: 0)
    CC_SHA384(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_SHA384_DIGEST_LENGTH))
  }
  
  
  public var SHA512: NSData {
    var hash = [UInt8](count: Int(CC_SHA512_DIGEST_LENGTH), repeatedValue: 0)
    CC_SHA512(bytes, CC_LONG(length), &hash)
    return NSData(bytes: hash, length: Int(CC_SHA512_DIGEST_LENGTH))
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
  
  
  private var hashData: NSData? {
    guard let cstr = cStringUsingEncoding(NSUTF8StringEncoding) else { return nil }
    return NSData(bytes: cstr, length: lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
  }
  
  
  private init?(digestData: NSData?, length: Int32) {
    guard let digestData = digestData else { return nil }
    var digest = [UInt8](count: Int(length), repeatedValue: 0)
    digestData.getBytes(&digest, length: Int(length) * sizeof(UInt8))
    
    var string = ""
    for i in 0..<length {
      string += String(format: "%02x", digest[Int(i)])
    }
    self.init(string)
  }
}
