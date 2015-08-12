//
//  PasswordTests.swift
//  Tests
//
//  Created by Sean Cheng on 8/11/15.
//
//

import XCTest
import Keys


class PasswordTests: XCTestCase {
  
  func testCreatePassword() {
    do {
      let password = try Password(password: "HelloWorld")
      print(password)
    } catch {
      XCTFail("Cannot create password")
    }
  }
  
  
  func testRandomPassword() {
    let password = Password.new()
    print(password)
//    XCTAssertTrue(password != nil, "Cannot create random password")
  }
  
  
  func testPasswordSimilarity() {
    do {
      let password = try Password(password:"HelloWorld")
      let newPassword = try Password(password:"HelloWorld", salt:password.salt, roundCount: password.rounds)
      print(password)
      print(newPassword)
      XCTAssertEqual(password.data, newPassword.data)
    } catch {
      XCTFail("Cannot create password")
    }
  }
  
  
  func testPasswordUnique() {
    do {
      let password = try Password(password:"HelloWorld")
      let newPassword = try Password(password:"HelloWorld")
      print(password)
      print(newPassword)
      XCTAssertNotEqual(password.data, newPassword.data)
    } catch {
      XCTFail("Cannot create password")
    }
  }
  
  
  func testWrapSymmetricKey() {
    do {
      let key = SymmetricKey()
      var password = try Password(password:"Hello")
      let encryptedKeyData = try password.encrypt(key)
      print(encryptedKeyData)
      let decryptedKey = try password.decrypt(encryptedKeyData.key, hmacKey: encryptedKeyData.hmac, IV: encryptedKeyData.IV)
      print(decryptedKey)
      XCTAssertTrue(decryptedKey.cryptoKey == key.cryptoKey, "Invalid wrapping symmetric key")
    } catch {
      XCTFail("Cannot wrap symmetric key")
    }
  }
}
