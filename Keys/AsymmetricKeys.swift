//
//  AsymmetricKeys.swift
//  Keys
//
//  Created by Sean Cheng on 8/11/15.
//
//

import Foundation
import CommonCrypto


// 非对称密钥组。 用于加密需要传输到其他设备时用到的数据。
public struct AsymmetricKeys {
  
  public typealias Keys = (publicKey:PublicKey, privateKey:PrivateKey)
  
  
  public enum Exception : Error {
    case cannotCreateSecKeyFromData
    case notFound
    case deleteError
  }
  
  
  public struct Options {
    
    public let keySize          : CFNumber
    public let cryptoPadding    : SecPadding
    public let signaturePadding : SecPadding
    public let tag              : String
    
    
    public static var Default : Options {
      return Options(tag: TemporaryKeyTag, size: 2048 as CFNumber, cryptoPadding: SecPadding.PKCS1, signaturePadding: SecPadding.PKCS1SHA1)
    }
    
    
    public init(tag:String, size:CFNumber, cryptoPadding: SecPadding, signaturePadding: SecPadding) {
      self.tag = tag
      self.keySize = size
      self.cryptoPadding = cryptoPadding
      self.signaturePadding = signaturePadding
    }
  }
  
  
  fileprivate static func generateSecKeys(_ options: Options) -> Keys
  {
    let parameters = [kSecAttrType as String:kSecAttrKeyTypeRSA,
                      kSecAttrKeySizeInBits as String: options.keySize,
                      kSecAttrLabel as String: options.tag] as [String : Any]
    var publicKeyPointer : SecKey?
    var privateKeyPointer : SecKey?
    SecKeyGeneratePair(parameters as CFDictionary, &publicKeyPointer, &privateKeyPointer)
    let publicKey = PublicKey(key: publicKeyPointer!, options: options)
    let privateKey = PrivateKey(key: privateKeyPointer!, options: options)
    return Keys(publicKey,privateKey)
  }
  
  
  public static func generateKeyPair(_ options:Options = Options.Default) -> Keys
  {
    return generateSecKeys(options)
  }
  
  
  public static func generateKeyPairs(_ options:Options = Options.Default) -> (cryptoKeys: Keys, validationKeys: Keys) {
    let cryptoKeys = generateSecKeys(options)
    let validationKeys = generateSecKeys(options)
    return (cryptoKeys: cryptoKeys, validationKeys: validationKeys)
  }
  
  
  public static func get(_ privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil , options: Options = Options.Default) throws -> (cryptoKeys: Keys, validationKeys: Keys?) {
    
    func secKeyWithTag(_ tag:String) throws -> SecKey {
      let query = [
        String(kSecClassKey): kSecClass,
        String(kSecAttrApplicationTag): tag,
        String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        String(kSecReturnRef): true
      ] as [String : Any]
      let keyPointer : UnsafeMutablePointer<AnyObject?>? = nil
      let result = SecItemCopyMatching(query as CFDictionary, keyPointer)
      if result != OSStatus(kCCSuccess) { throw Exception.notFound }
      else { return keyPointer!.pointee as! SecKey }
    }
    
    
    func keysWithTags(_ privateTag:String, publicTag:String) throws -> Keys {
      let privateKeyRef = try secKeyWithTag(privateTag)
      let publicKeyRef = try secKeyWithTag(publicTag)
      let privateKey = PrivateKey(key: privateKeyRef, options: options)
      let publicKey = PublicKey(key: publicKeyRef, options: options)
      return Keys(publicKey,privateKey)
    }
    
    
    do {
      let keys = try keysWithTags(privateTag, publicTag: publicTag)
      var validationKeys : Keys?
      if let publicT = validationPublicTag, let privateT = validationPrivateTag {
        validationKeys = try keysWithTags(privateT, publicTag: publicT)
      }
      return (cryptoKeys: keys, validationKeys: validationKeys)
    } catch {
      throw error
    }
  }
  
  
  public func save(_ privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil) throws {
    
  }
  
  
  public func remove() throws {
    
  }
  
  
  public static func removeKeyWithTag(_ tag:String) throws {
    let query = [
      String(kSecClassKey): kSecClass,
      String(kSecAttrApplicationTag): tag
    ] as [String : Any]
    let result = SecItemDelete(query as CFDictionary)
    if result != OSStatus(kCCSuccess) { throw Exception.deleteError }
  }
}


// 私钥。 用于加密与获得数据验证码
public struct PrivateKey : Decryptable {
  
  public enum Exception : Error {
    case cannotDecryptData
    case cannotSignData
  }
  
  
  public var tag      : String?
  public var key      : SecKey
  public var options  : AsymmetricKeys.Options
  
  
  fileprivate init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}


// 公钥。 用于解密与验证数据
public struct PublicKey : Encryptable {
  
  public enum Exception : Error {
    case cannotEncryptData
    case cannotVerifyData
  }
  
  
  public var tag      : String?
  public var key      : SecKey!
  public var options  : AsymmetricKeys.Options
  
  
  fileprivate init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}
