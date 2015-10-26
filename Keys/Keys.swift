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


// 用于生成 SecKey 时用到的临时 Keychain 标签
public var TemporaryKeyTag = "com.zhengxingzhi.keys.temp"


/// 密钥强度
public enum KeyStrength {
  case Weak
  case Regular
  case Strong
}


/// 可用于加密内容的密钥
public protocol Encryptable {
  
  /// 加密数据
  func encrypt(data:NSData) throws -> NSData
  
  /// 验证数据
  func verify(data:NSData, signature: NSData) throws -> Bool
  
  /// 加密数据后嵌入数据验证码
//  func encryptThenMac(data:NSData) throws -> NSData
}


/// 可用于解密内容的密钥
public protocol Decryptable {
  
  /// 解密数据
  func decrypt(data:NSData) throws -> NSData
  
  /// 获得数据验证码
  func signature(data:NSData) throws -> NSData
  
  /// 验证数据后再解密
//  func verifyThenDecrypt(data:NSData) throws -> NSData
}


public extension String {
  
  /// 随机字串符
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


public extension NSData {
  
  /// 随机 NSData 数据
  public static func randomData(length:Int) -> NSData {
    let data = NSMutableData(length: length)!
    SecRandomCopyBytes(kSecRandomDefault, length, UnsafeMutablePointer<UInt8>(data.mutableBytes))
    return data
  }
  
  
  /// 对称密钥用的随机 IV 数据
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

