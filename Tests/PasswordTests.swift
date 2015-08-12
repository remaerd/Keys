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
  
  var password : Password?
  
  
  override func setUp() {
    super.setUp()
    // Put setup code here. This method is called before the invocation of each test method in the class.
  }
  
  override func tearDown() {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    super.tearDown()
  }
  
  
  func testCreatePassword() {
    do {
      self.password = try Password(password: "HelloWorld")
      print(self.password?.data)
      print(self.password?.options)
      print(self.password?.salt)
      print(self.password?.rounds)
    } catch {
      XCTFail("Cannot create password")
    }
  }
}
