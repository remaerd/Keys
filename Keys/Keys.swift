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
  case weak
  case regular
  case strong
}


/// 可用于加密内容的密钥
public protocol Encryptable {
  
  /// 加密数据
  func encrypt(_ data:Data) throws -> Data
  
  /// 验证数据
  func verify(_ data:Data, signature: Data) throws -> Bool
  
  /// 加密数据后嵌入数据验证码
//  func encryptThenMac(data:NSData) throws -> NSData
}


/// 可用于解密内容的密钥
public protocol Decryptable {
  
  /// 解密数据
  func decrypt(_ data:Data) throws -> Data
  
  /// 获得数据验证码
  func signature(_ data:Data) throws -> Data
  
  /// 验证数据后再解密
//  func verifyThenDecrypt(data:NSData) throws -> NSData
}


public extension String {
  
  /// 随机字串符
  public static func randomString(_ length:Int) -> String {
    
    let letters : NSString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    var string = ""
    
    for _ in 0 ..< letters.length {
      let index = Int(arc4random_uniform(UInt32(letters.length)))
      let character = String(letters.character(at: index))
      string += character
    }
    
    return string
  }
}


public extension Data
{
  /// 随机 NSData 数据
  public static func randomData(_ length:Int) -> Data
  {
    var data = Data(count:length)
    var pointer : UnsafeMutablePointer<UInt8>? = nil
    data.withUnsafeMutableBytes { (ptr : UnsafeMutablePointer<UInt8>) in pointer = ptr }
    _ = SecRandomCopyBytes(kSecRandomDefault, length, pointer!)
    return data
  }
}

