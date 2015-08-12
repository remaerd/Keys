//
//  Hash.swift
//  Keys
//
//  Created by Sean Cheng on 8/9/15.
//
//

import Foundation
import CommonCrypto

public enum HashType {
  case SHA256
  case SHA512
}


public enum HashError : ErrorType {
  case InvalidString
}


public extension NSData {
  
  public func hash(hashType: HashType = .SHA256) -> NSData {
    
    let hash : NSData
    switch hashType {
    case .SHA256:
      var hashBytes = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
      CC_SHA256(self.bytes, CC_LONG(self.length), &hashBytes)
      hash = NSData(bytes: hashBytes, length: Int(CC_SHA256_DIGEST_LENGTH))
    case .SHA512:
      var hashBytes = [UInt8](count: Int(CC_SHA512_DIGEST_LENGTH), repeatedValue: 0)
      CC_SHA512(self.bytes, CC_LONG(self.length), &hashBytes)
      hash = NSData(bytes: hashBytes, length: Int(CC_SHA512_DIGEST_LENGTH))
    }
    return hash
  }
}


public extension String {
  
  public func hash(hashType: HashType = .SHA256) throws -> NSData {
    guard let data = self.dataUsingEncoding(NSUTF8StringEncoding) else { throw HashError.InvalidString }
    return data.hash(hashType)
  }
}
