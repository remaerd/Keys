//
//  Keys.swift
//  Keys
//
//  通用的密钥协议与随机参数扩展
//
//  Created by Sean Cheng on 8/8/15.
//

import Foundation
import CommonCrypto


// 密钥强度
public enum KeyStrength {
  case Weak
  case Regular
  case Strong
}


// 密钥协议
public protocol KeyType {
  var strength  : Int { get }
}


// 可用于加密内容的密钥
public protocol Encryptable : KeyType {
  
  func encrypt(data:NSData) throws -> NSData
  func signature(data:NSData) throws -> NSData
}


// 可用于解密内容的密钥
public protocol Decryptable : KeyType {
  
  func decrypt(data:NSData) throws -> NSData
  func verify(data:NSData, signature: NSData) throws -> Bool
}


// 随机字串符
public extension String {
  
  public static func randomString(length:Int) -> String {
    
    let letters : NSString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    var string = ""
    
    for (var i=0; i < letters.length; i++){
      let index = Int(arc4random_uniform(UInt32(letters.length)))
      let character = String(letters.characterAtIndex(index))
      string += character
    }
    
    return string
  }
}


// 随机 NSData 数据
public extension NSData {
  
  public static func randomData(length:Int) -> NSData {
    let data = NSMutableData(length: length)!
    SecRandomCopyBytes(kSecRandomDefault, length, UnsafeMutablePointer<UInt8>(data.mutableBytes))
    return data
  }
  
  
  public static func randomIV(blockSize : Int) -> NSData {
    var randomIV : [UInt8] = [UInt8]()
    var i : Int = 0
    while i < blockSize {
      randomIV.append(UInt8(truncatingBitPattern: arc4random_uniform(256)))
      i += 1
    }
    return NSData(bytes: UnsafePointer<Void>(randomIV), length: randomIV.count)
  }
}

