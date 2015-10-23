//
//  Password.swift
//  Keys
//
//  Created by Sean Cheng on 8/8/15.
//
//

import Foundation
import CommonCrypto


/// 密码。 用于加密对对称密钥。 不能直接用于加密数据。
public struct Password {
  
  public enum Error : ErrorType {
    case CannotCreatePassword
  }
  
  
  public let salt     : NSData
  public let options  : Options
  public let rounds   : Int
  
  let data            : NSData
  
  
  public struct Options {
    let keySize   : Int
    let saltSize  : Int
    let PBKDF     : CCPBKDFAlgorithm
    let PRF       : CCPseudoRandomAlgorithm
  }
  
  
  public static var DefaultOptions : Options {
    return Options(keySize: Int(CC_SHA512_DIGEST_LENGTH),
      saltSize: 8,
      PBKDF: CCPBKDFAlgorithm(kCCPBKDF2),
      PRF: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512))
  }
  
  
  public lazy var key : SymmetricKey = {
    return try! SymmetricKey(key: self.data, options: SymmetricKey.DefaultOptions)
  }()
  
  
  public static func new(strength: KeyStrength = KeyStrength.Regular) -> Password {
    let randomString = String.randomString(32)
    let key = try! Password(password: randomString)
    return key
  }
  
  
  public init(password:String, salt:NSData = NSData.randomData(Password.DefaultOptions.saltSize), roundCount: Int? = nil, options: Options = Password.DefaultOptions) throws {
    let derivedData = NSMutableData(length: options.keySize)!
    let saltBytes = UnsafePointer<UInt8>(salt.bytes)
    let saltLength = salt.length
    let password = password.dataUsingEncoding(NSUTF8StringEncoding)!
    let passwordPointer = UnsafePointer<Int8>(password.bytes)
    let passwordLength = password.length
    let derivedDataPointer = UnsafeMutablePointer<UInt8>(derivedData.mutableBytes)
    let derivedDataLength = derivedData.length
    let count: UInt32
    if roundCount != nil { count = UInt32(roundCount!) }
    else { count = CCCalibratePBKDF( options.PBKDF, passwordLength, saltLength, options.PRF, derivedDataLength, 1000 ) }
    
    let result = CCKeyDerivationPBKDF(options.PBKDF, passwordPointer, passwordLength, saltBytes, saltLength, options.PRF, count, derivedDataPointer, derivedDataLength)
    if Int(result) != kCCSuccess { throw Error.CannotCreatePassword }
    
    self.data = derivedData
    self.rounds = Int(count)
    self.salt = salt
    self.options = options
  }
  
  
  /// 加密对称密钥
  mutating public func encrypt(key:SymmetricKey) throws -> (key: NSData, IV: NSData) {
    do {
      let data = NSMutableData(data: key.cryptoKey)
      if let hmacKey = key.hmacKey { data.appendData(hmacKey) }
      let encryptKey = try self.key.encrypt(data)
      return (encryptKey, key.IV)
    } catch {
      throw error
    }
  }
  
  
  /// 解密对称密钥
  mutating public func decrypt(key:NSData, IV: NSData, options: SymmetricKey.Options = SymmetricKey.DefaultOptions) throws -> SymmetricKey {
    do {
      let keyData = try self.key.decrypt(key)
      let symmetricKey = try SymmetricKey(key: keyData, IV: IV, options: options)
      return symmetricKey
    } catch {
      throw error
    }
  }
}