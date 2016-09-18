//
//  AsymmetricKeysTests.swift
//  Keys
//
//  Created by Sean Cheng on 8/11/15.
//
//

import XCTest
@testable import Keys


class AsymmetricKeyTests: XCTestCase {
  
  func testOpenSSLKey() {
    let publicKeyData = try! Data(contentsOf: Bundle(for: self.classForCoder).url(forResource: "keys-public", withExtension: "pem")!)
    let privateKeyData = try! Data(contentsOf: Bundle(for: self.classForCoder).url(forResource: "keys-private", withExtension: "pem")!)
    let secretData = "Hello Me".data(using: String.Encoding.utf8)!
    do {
      let publicKey = try PublicKey(publicKey: publicKeyData)
      print(publicKey)
      let privateKey = try PrivateKey(privateKey: privateKeyData)
      print(privateKey)
      let secret = try publicKey.encrypt(secretData)
      let decryptedSecret = try privateKey.decrypt(secret)
      XCTAssertEqual(secretData, decryptedSecret)
      print(NSString(data: decryptedSecret, encoding: String.Encoding.utf8.rawValue))
    } catch {
      XCTFail()
    }
  }
  
  
  func testAsymmetricKey() {
    let keys = AsymmetricKeys.generateKeyPair()
    let secretData = "Hello World".data(using: String.Encoding.utf8)!
    do {
      let secret = try keys.publicKey.encrypt(secretData)
      let decryptedSecret = try keys.privateKey.decrypt(secret)
      XCTAssertEqual(secretData, decryptedSecret)
    } catch {
      XCTFail()
    }
  }
  
  
  func testDecryptNodeJSEncryptedData() {
    let encryptedString = "POeVBWNhsXOcZAw8R/pv6edPIdVM9p1Ux47BMKuWHggLfkUpT3LaGKzwcYA2zInpBnf4GEZzq7wR5/LO14QvCMLWPwgQ/SYlgFkaPA4+lIsUIGEMRGD76YPwmiulgctHiukhQxSpq0ObvJyuLis9+3uS5uUvAoYBhAiuPujgf0t47+bSc3ToB1HgCiPyw12e5zKl0RvjYGClb06ID5jPzA9SwtucKrAanyAz4L0P/aQNqTpIlmhrc6ht+ObxgVq55SL4n7vn2JPGq6zllpv/aNrNzu/BnesU8VH6GWzXG29v8LrKnZwNHDW7VvoMnJ3PNCXLb19tocJLnP6/WF26WQ=="
    let data = Data(base64Encoded: encryptedString, options: Data.Base64DecodingOptions.ignoreUnknownCharacters)!
    let privateKeyData = try! Data(contentsOf: Bundle(for: self.classForCoder).url(forResource: "keys-private", withExtension: "pem")!)
    do {
      let privateKey = try PrivateKey(privateKey:privateKeyData)
      let decryptedData = try privateKey.decrypt(data)
      let decryptedString = NSString(data: decryptedData, encoding: String.Encoding.utf8.rawValue)
      XCTAssertEqual(decryptedString, "Hello World")
    } catch {
      XCTFail()
    }
  }
  
  
  func testSignAndVerify() {
    let keys = AsymmetricKeys.generateKeyPair()
    let data = "Hello World".data(using: String.Encoding.utf8)!
    do {
      let signature = try keys.privateKey.signature(data)
      let result = try keys.publicKey.verify(data, signature: signature)
      XCTAssertTrue(result)
    } catch {
      XCTFail()
    }
  }
  
  
  func testOpenSSLKeySignAndVerify() {
    let publicKeyData = try! Data(contentsOf: Bundle(for: self.classForCoder).url(forResource: "keys-public", withExtension: "pem")!)
    let privateKeyData = try! Data(contentsOf: Bundle(for: self.classForCoder).url(forResource: "keys-private", withExtension: "pem")!)
    let secretData = "Hello Me".data(using: String.Encoding.utf8)!
    do {
      let publicKey = try PublicKey(publicKey: publicKeyData)
      let privateKey = try PrivateKey(privateKey: privateKeyData)
      let signature = try privateKey.signature(secretData)
      let result = try publicKey.verify(secretData, signature: signature)
      XCTAssertTrue(result)
    } catch {
      XCTFail()
    }
  }
  
  
  func testVerifyOpenSSLSignedData() {
    let signatureString = "V32BIi/KI3neTd9BCScitCHoI3a6n/AS44DdT3sXy6JdY5+sDLIFhroByRLirUxhI2MO3Zj9mPf2GFVl11K862tawO8BLMZtH28t9ipHIDeFZc2nuMMeAyEm9jhejvj92hidmfZ+r7HGTNKTMdcxJAiHztHopoU2AF0lJkEvuLHc4Yllrg6d/G54AUqRbKz0RFlHwXVL0lgyobKFrLdkH2PwuORglTvOvceUSMm2cM39bqqTxg6n8f9pG3nWt7pXQ2W3lJGYUIhm4JhLDuq96TpRj44UWH4kF3YT1nqnVzF+u3AKhGSiFbcsBkTeAI2M4tTouiE1d+tz/UzlM/1egw=="
    let secretData = "Hello World".data(using: String.Encoding.utf8)!
    let publicKeyData = try! Data(contentsOf: Bundle(for: self.classForCoder).url(forResource: "keys-public", withExtension: "pem")!)
    let signatureData = Data(base64Encoded: signatureString, options: .ignoreUnknownCharacters)!
    do {
      let publicKey = try PublicKey(publicKey: publicKeyData)
      let result = try publicKey.verify(secretData, signature: signatureData)
      XCTAssertTrue(result)
    } catch {
      XCTFail()
    }
  }
}
