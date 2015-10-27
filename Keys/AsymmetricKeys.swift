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
  
  
  public enum Error : ErrorType {
    case CannotCreateSecKeyFromData
    case NotFound
    case DeleteError
  }
  
  
  public struct Options {
    
    public let keySize          : CFNumber
    public let cryptoPadding    : SecPadding
    public let signaturePadding : SecPadding
    public let tag              : String
    
    
    public static var Default : Options {
      return Options(tag: TemporaryKeyTag, size: 2048, cryptoPadding: SecPadding.PKCS1, signaturePadding: SecPadding.PKCS1SHA1)
    }
    
    
    public init(tag:String, size:CFNumber, cryptoPadding: SecPadding, signaturePadding: SecPadding) {
      self.tag = tag
      self.keySize = size
      self.cryptoPadding = cryptoPadding
      self.signaturePadding = signaturePadding
    }
  }
  
  
  private static func generateSecKeys(options: Options) -> Keys {
    let parameters = [String(kSecAttrKeyType):kSecAttrKeyTypeRSA,
                      String(kSecAttrKeySizeInBits): options.keySize,
                      String(kSecAttrLabel): options.tag]
    var publicKeyPointer : SecKey?
    var privateKeyPointer : SecKey?
    SecKeyGeneratePair(parameters, &publicKeyPointer, &privateKeyPointer)
    let publicKey = PublicKey(key: publicKeyPointer!, options: options)
    let privateKey = PrivateKey(key: privateKeyPointer!, options: options)
    return Keys(publicKey,privateKey)
  }
  
  
  public static func generateKeyPair(options:Options = Options.Default) -> Keys {
    return AsymmetricKeys.generateSecKeys(options)
  }
  
  
  public static func generateKeyPairs(options:Options = Options.Default) -> (cryptoKeys: Keys, validationKeys: Keys) {
    let cryptoKeys = AsymmetricKeys.generateSecKeys(options)
    let validationKeys = AsymmetricKeys.generateSecKeys(options)
    return (cryptoKeys: cryptoKeys, validationKeys: validationKeys)
  }
  
  
  public static func get(privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil , options: Options = AsymmetricKeys.Options.Default) throws -> (cryptoKeys: Keys, validationKeys: Keys?) {
    
    func secKeyWithTag(tag:String) throws -> SecKey {
      let query = [
        String(kSecClassKey): kSecClass,
        String(kSecAttrApplicationTag): tag,
        String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        String(kSecReturnRef): true
      ]
      let keyPointer = UnsafeMutablePointer<AnyObject?>()
      let result = SecItemCopyMatching(query, keyPointer)
      if result != OSStatus(kCCSuccess) { throw Error.NotFound }
      else { return keyPointer.memory as! SecKey }
    }
    
    
    func keysWithTags(privateTag:String, publicTag:String) throws -> Keys {
      let privateKeyRef = try secKeyWithTag(privateTag)
      let publicKeyRef = try secKeyWithTag(publicTag)
      let privateKey = PrivateKey(key: privateKeyRef, options: options)
      let publicKey = PublicKey(key: publicKeyRef, options: options)
      return Keys(publicKey,privateKey)
    }
    
    
    do {
      let keys = try keysWithTags(privateTag, publicTag: publicTag)
      var validationKeys : Keys?
      if let publicT = validationPublicTag, privateT = validationPrivateTag {
        validationKeys = try keysWithTags(privateT, publicTag: publicT)
      }
      return (cryptoKeys: keys, validationKeys: validationKeys)
    } catch {
      throw error
    }
  }
  
  
  public func save(privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil) throws {
    
  }
  
  
  public func remove() throws {
    
  }
  
  
  public static func removeKeyWithTag(tag:String) throws {
    let query = [
      String(kSecClassKey): kSecClass,
      String(kSecAttrApplicationTag): tag
    ]
    let result = SecItemDelete(query)
    if result != OSStatus(kCCSuccess) { throw Error.DeleteError }
  }
}


// 私钥。 用于加密与获得数据验证码
public struct PrivateKey : Decryptable {
  
  public enum Error : ErrorType {
    case CannotDecryptData
    case CannotSignData
  }
  
  
  public var tag      : String?
  public var key      : SecKey
  public var options  : AsymmetricKeys.Options
  
  
  private init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}


// 公钥。 用于解密与验证数据
public struct PublicKey : Encryptable {
  
  public enum Error : ErrorType {
    case CannotEncryptData
    case CannotSignData
  }
  
  
  public var tag      : String?
  public var key      : SecKey!
  public var options  : AsymmetricKeys.Options
  
  
  private init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}