import XCTest
@testable import Aliyun

let AccessKeyId = "ACSKEY".sysEnv
let AccessKeySecret = "ACSPWD".sysEnv

class AliyunTests: XCTestCase {
  func testSignature() {
    let toSign = "GET&%2F&AccessKeyId%3Dtestid%26Action%3DDescribeRegions%26Format%3DXML%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf%26SignatureVersion%3D1.0%26TimeStamp%3D2016-02-23T12%253A46%253A24Z%26Version%3D2014-05-26"
    let signed = AcsRequest.Sign(toSign, keySecret: "testsecret")
    let expected = "CT9X0VtwR86fNWSnsc6v8YGOjuE="
    XCTAssertEqual(signed, expected)
  }

  func testToSign() {
    let p = ["TimeStamp": "2016-02-23T12:46:24Z", "Format": "XML",
             "AccessKeyId": "testid", "Action":"DescribeRegions",
             "SignatureMethod": "HMAC-SHA1",
             "SignatureNonce": "3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf",
             "Version": "2014-05-26", "SignatureVersion": "1.0"]
    let expected = "GET&%2F&AccessKeyId%3Dtestid%26Action%3DDescribeRegions%26Format%3DXML%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf%26SignatureVersion%3D1.0%26TimeStamp%3D2016-02-23T12%253A46%253A24Z%26Version%3D2014-05-26"
    let q = AcsRequest.CanonicalizedQuery(queryParamters: p)
    XCTAssertEqual(expected, q)
  }

  func testRegions() {
    print(AccessKeyId, AccessKeySecret)
    let ex = expectation(description: "testRegions")
    AcsRequest.EcsDescribeRegions(accessKeyId: AccessKeyId, accessKeySecrect: AccessKeySecret) {
      regions, msg in
      XCTAssertGreaterThan(regions.count, 0)
      print(regions)
      print(msg)
      ex.fulfill()
    }
    wait(for: [ex], timeout: 10)
  }

  static var allTests = [
    ("testSignature", testSignature),
    ("testToSign", testToSign),
    ("testRegions", testRegions)
    ]
}
