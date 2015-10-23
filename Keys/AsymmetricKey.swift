//
//  AsymmetricKey.swift
//  Keys
//
//  Created by Sean Cheng on 10/24/15.
//
//

import Foundation


public struct AsymmetricKey {
  
  public struct Options {
    
    public let keyType  : CFString
    public let keySize  : CFNumber
    public let padding  : SecPadding
    public let tag      : String
    
    
    public static var Default : Options {
      return Options(type: kSecAttrKeyTypeRSA, size: 2048 ,padding: SecPadding.PKCS1, tag: TemporaryKeyTag)
    }
    
    
    public init(type:CFString,size:CFNumber, padding: SecPadding, tag: String) {
      self.tag = tag
      self.keyType = type
      self.keySize = size
      self.padding = padding
    }
  }
  
  
  public var key      : SecKey!
  public var options  : AsymmetricKey.Options
  
  
  public enum Error : ErrorType {
    case CannotCreateSecKeyFromData
    case NotFound
    case DeleteError
    case CannotDecryptData
    case CannotEncryptData
    case CannotSignData
    case CannotVerifyData
  }
  
  
  public static func generateKeyPair(options:Options = Options.Default) -> (publicKey:AsymmetricKey,privateKey:AsymmetricKey) {
    let parameters = [String(kSecAttrKeyType):options.keyType,
      String(kSecAttrKeySizeInBits): options.keySize,
      String(kSecAttrLabel): options.tag]
    var publicKeyPointer : SecKey?
    var privateKeyPointer : SecKey?
    SecKeyGeneratePair(parameters, &publicKeyPointer, &privateKeyPointer)
    let publicKey = AsymmetricKey(key: publicKeyPointer!, options: options)
    let privateKey = AsymmetricKey(key: privateKeyPointer!, options: options)
    return (privateKey:privateKey,publicKey:publicKey)
  }
  
  
  public static func generateKeyPairs(options:Options = Options.Default) -> (privateCryptoKey:AsymmetricKey,publicCryptoKey:AsymmetricKey,privateSignKey:AsymmetricKey,publicSignKey:AsymmetricKey) {
    let cryptoKeys = self.generateKeyPair(options)
    let signKeys = self.generateKeyPair(options)
    return (privateCryptoKey:cryptoKeys.privateKey, publicCryptoKey:cryptoKeys.publicKey, privateSignKey:signKeys.privateKey, publicSignKey:signKeys.publicKey)
  }
  
  
  init(key:SecKey,options:Options) {
    self.key = key
    self.options = options
  }
}