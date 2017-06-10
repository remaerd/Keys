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
  
  public enum Exception : Error {
    case cannotCreatePassword
  }
  
  
  public let salt     : Data
  public let options  : Options
  public let rounds   : Int
  
  let data            : Data
  
  
  public struct Options
  {
    public let saltSize  : Int
    public let PBKDF     : CCPBKDFAlgorithm
    public let PRF       : CCPseudoRandomAlgorithm
  }
  
  
  public static var DefaultOptions : Options
  {
    return Options(
      saltSize: 8,
      PBKDF: CCPBKDFAlgorithm(kCCPBKDF2),
      PRF: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512))
  }
  
  
  public lazy var key : SymmetricKey =
  {
    return try! SymmetricKey(key: self.data, options: SymmetricKey.DefaultOptions)
  }()
  
  
  public static func new(_ strength: KeyStrength = KeyStrength.regular) -> Password
  {
    let randomString = String.randomString(15)
    let key = try! Password(password: randomString)
    return key
  }
  
  
  public init(password:String, salt:Data = Data.randomData(Password.DefaultOptions.saltSize), roundCount: Int? = nil, options: Options = Password.DefaultOptions) throws
  {
    var saltPointer : UnsafePointer<UInt8>? = nil
    salt.withUnsafeBytes { (pointer : UnsafePointer<UInt8>) in saltPointer = pointer }
    
    let passwordData = password.data(using: String.Encoding.utf8)!
    var passwordPointer : UnsafePointer<Int8>? = nil
    passwordData.withUnsafeBytes { (pointer : UnsafePointer<Int8>) in passwordPointer = pointer }
    
    let derivedDataLength : Int
    
    switch Int(options.PRF)
    {
    case kCCPRFHmacAlgSHA1: derivedDataLength = Int(CC_SHA1_DIGEST_LENGTH); break;
    case kCCPRFHmacAlgSHA224: derivedDataLength = Int(CC_SHA224_DIGEST_LENGTH); break;
    case kCCPRFHmacAlgSHA256: derivedDataLength = Int(CC_SHA256_DIGEST_LENGTH); break;
    case kCCPRFHmacAlgSHA384: derivedDataLength = Int(CC_SHA384_DIGEST_LENGTH); break;
    case kCCPRFHmacAlgSHA512: derivedDataLength = Int(CC_SHA512_DIGEST_LENGTH); break;
    default: throw Exception.cannotCreatePassword
    }
    
    var derivedData = Data(count:derivedDataLength)
    var derivedDataPointer : UnsafeMutablePointer<UInt8>? = nil
    derivedData.withUnsafeMutableBytes { (pointer : UnsafeMutablePointer<UInt8>) in derivedDataPointer = pointer }
    
    let count: UInt32
    if roundCount != nil { count = UInt32(roundCount!) }
    else { count = CCCalibratePBKDF(options.PBKDF, passwordData.count, salt.count, options.PRF, derivedDataLength, 300 ) }
    
    let result = CCKeyDerivationPBKDF(options.PBKDF, passwordPointer!, passwordData.count, saltPointer!, salt.count, options.PRF, count, derivedDataPointer, derivedDataLength)
    if Int(result) != kCCSuccess { throw Exception.cannotCreatePassword }
    
    self.data = derivedData
    self.rounds = Int(count)
    self.salt = salt
    self.options = options
  }
  
  
  /// 加密对称密钥
  mutating public func encrypt(_ key:SymmetricKey) throws -> (key: Data, IV: Data) {
    do {
      var _data = key.cryptoKey
      if let hmacKey = key.hmacKey { _data.append(hmacKey as Data) }
      let encryptKey = try self.key.encrypt(_data)
      return (encryptKey, key.IV)
    } catch {
      throw error
    }
  }
  
  
  /// 解密对称密钥
  mutating public func decrypt(_ key:Data, IV: Data, options: SymmetricKey.Options = SymmetricKey.DefaultOptions) throws -> SymmetricKey {
    do {
      let keyData = try self.key.decrypt(key)
      let symmetricKey = try SymmetricKey(key: keyData, IV: IV, options: options)
      return symmetricKey
    } catch {
      throw error
    }
  }
}
