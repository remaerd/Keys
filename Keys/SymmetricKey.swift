//
//  SymmetricKey.swift
//  Keys
//
//  Created by Sean Cheng on 8/8/15.
//
//

import Foundation
import CommonCrypto


public struct SymmetricKey : KeyType, Encryptable, Decryptable {
  
  public enum Error : ErrorType {
    case EncryptError
  }
  
  
  public let options    : Options
  public let cryptoKey  : NSData
  public let IV         : NSData
  public var hmacKey    : NSData?
  
  
  public struct Options {
    let keySize     : Int
    let seperateKey : Bool
    let algoritm    : CCAlgorithm
    let options     : CCOptions
    let hmac        : CCHmacAlgorithm
    
    
    public var algoritmBlockSize : Int {
      switch self.algoritm {
      case CCAlgorithm(kCCAlgorithmAES): return kCCBlockSizeAES128
      case CCAlgorithm(kCCAlgorithmAES128): return kCCBlockSizeAES128
      default : return 0
      }
    }
  }
  
  
  public static var DefaultOptions : Options {
    return Options(keySize: kCCKeySizeAES256, seperateKey: true, algoritm: CCAlgorithm(kCCAlgorithmAES), options: CCOptions(kCCOptionPKCS7Padding), hmac: CCHmacAlgorithm(kCCHmacAlgSHA256))
  }
  
  
  public static func new(options:Options = DefaultOptions) -> SymmetricKey {
    let data = NSData.randomData(options.keySize)
    let hmac = NSData.randomData(options.keySize)
    let iv = NSData.randomIV(kCCBlockSizeAES128)
    let key = try! SymmetricKey(key: data, hmacKey: hmac, IV:iv)
    return key
  }
  
  
  public init(key: NSData, hmacKey: NSData? = nil, IV: NSData, options: Options = SymmetricKey.DefaultOptions) throws {
    self.cryptoKey = key
    self.IV = IV
    self.hmacKey = hmacKey
    self.options = options
  }
  
  
  public var strength : Int {
    return 0
  }
  
  
  public func encrypt(data: NSData) throws -> NSData {
    let encryptedData = NSMutableData(length: data.length + self.options.algoritmBlockSize)!
    let encryptedMoved = UnsafeMutablePointer<Int>()
    let result = CCCrypt(CCOperation(kCCEncrypt), self.options.algoritm, self.options.options, self.cryptoKey.bytes, self.cryptoKey.length, self.IV.bytes, data.bytes, data.length, encryptedData.mutableBytes, encryptedData.length, encryptedMoved)
    if result != CCCryptorStatus(kCCSuccess) { throw Error.EncryptError }
    else { return encryptedData }
  }
  
  
  public func decrypt(data: NSData) throws -> NSData {
    let decryptedData = NSMutableData(length: data.length - self.options.algoritmBlockSize)!
    let decryptedMoved = UnsafeMutablePointer<Int>()
    let result = CCCrypt(CCOperation(kCCDecrypt), self.options.algoritm, self.options.options, self.cryptoKey.bytes, self.cryptoKey.length, self.IV.bytes, data.bytes, data.length, decryptedData.mutableBytes, decryptedData.length, decryptedMoved)
    if result != Int32(kCCSuccess) { throw Error.EncryptError }
    else { return decryptedData }
  }
  
  
  public func signature(data: NSData) throws -> NSData {
    let hash = data.hash(HashType.SHA256)
    let macPointer = UnsafeMutablePointer<Void>()
    var key = self.hmacKey
    if key == nil { key = self.cryptoKey }
    CCHmac(self.options.hmac, key!.bytes, key!.length, hash.bytes, hash.length, macPointer)
    return NSData(bytes: macPointer, length: Int(CC_SHA256_DIGEST_LENGTH))
  }
  
  
  public func verify(data: NSData, signature: NSData) throws -> Bool {
    do {
      let signatureData = try self.signature(data)
      if signatureData == signature { return true }
      else { return false }
    } catch {
      throw error
    }
  }
}

