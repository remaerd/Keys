//
//  SymmetricKeyTests.swift
//  Keys
//
//  Created by Sean Cheng on 8/11/15.
//
//

import XCTest
import Keys


class SymmetricKeyTests: XCTestCase {
  
  var key : SymmetricKey?
  
  func testCreateSymmetricKey() {
    self.key = SymmetricKey.new()
    print(self.key?.cryptoKey)
    print(self.key?.hmacKey)
    print(self.key?.IV)
    print(self.key?.options)
    XCTAssertTrue(self.key != nil, "Cannot create symmetric key")
  }
  
  
  func testEncrypt() {
    let data = "HelloWorld".dataUsingEncoding(NSUTF8StringEncoding)!
    do {
      let encryptedData = try self.key?.encrypt(data)
      print(encryptedData)
    } catch {
      XCTFail("Cannot encrypt data")
    }
  }
}

