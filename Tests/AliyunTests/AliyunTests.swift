import XCTest
@testable import Aliyun

var access = AcsCredential()
let passwd = "PASSWD".sysEnv
let REGION = "cn-hongkong"
let solo = true

class AliyunTests: XCTestCase {
  override func setUp() {
    access.key = "ACSKEY".sysEnv
    access.secret = "ACSPWD".sysEnv
  }

  func testSecurityGroup() {
    let now = time(nil)
    let groupName = "PerfectSecurityGroup.\(now)"
    let ecs = ECS(access: access)
    var exp = expectation(description: "securityGroupCreation")
    ecs.createSecurityGroup(region: REGION, name: groupName, description: "testing") { id, message in
      exp.fulfill()
      XCTAssertTrue(message.isEmpty)
    }
    wait(for: [exp], timeout: 10)
    exp = expectation(description: "securityGroupDescription")
    ecs.describeSecurityGroups(region: REGION) { groups, message in
      exp.fulfill()
      XCTAssertGreaterThan(groups.count, 0)
    }
    wait(for: [exp], timeout: 10)
    exp = expectation(description: "securityGroupDeletion")
    ecs.deleteSecurityGroup(region: REGION, id: groupName) { success, message in
      exp.fulfill()
      XCTAssertTrue(success)
    }
    wait(for: [exp], timeout: 10)
  }
  func testKeyPairs() {
    let now = time(nil)
    let keys = (["pkey1", "pkey2"]).map { String(format: "\($0)%02x", now) }
    let ecs = ECS(access: access)
    let exps = keys.map { expectation(description: $0) }
    for i in 0...1 {
      let k = keys[i]
      let exp = exps[i]
      ecs.createKeyPair(region: REGION, name: k) { keyPair, msg in
        if let kp = keyPair {
          XCTAssertEqual(kp.KeyPairName, k)
          print(kp)
          exp.fulfill()
        } else {
          XCTFail(msg)
        }
      }
    }
    wait(for: exps, timeout: 30)
    var exp = expectation(description: "keyDescription")
    ecs.describeKeyPairs(region: REGION) { keylist, message in
      exp.fulfill()
      XCTAssertGreaterThan(keylist.count, 1)
      print(keylist)
    }
    wait(for: [exp], timeout: 20)
    exp = expectation(description: "keyDeletion")
    ecs.deleteKeyPairs(region: REGION, keyNames: keys) { success, message in
      XCTAssertTrue(success)
      exp.fulfill()
    }
    wait(for: [exp], timeout: 10)
  }

  func testRegions() {
    let ecs = ECS(access: access)
    let exp = expectation(description: "regions")
    ecs.describeRegions { regions in
      exp.fulfill()
      XCTAssertGreaterThan(regions.count, 0)
      print(regions)
    }
    wait(for: [exp], timeout: 10)
  }
  func testExample() {
    let a:[Any] = [1, 2, 3, "four", "five"]
    XCTAssertEqual(a.aliJSON, "[\"1\",\"2\",\"3\",\"four\",\"five\"]")
    print("PATH".sysEnv)
    XCTAssertEqual("HelloWorld".signSha1HMACToBase64("secret"), "+QF9FxJDiELqSr9zA5u5E9t04XU=")
  }

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

  static var allTests = [
    ("testExample", testExample),
    ("testSignature", testSignature),
    ("testToSign", testToSign),
    ("testRegions", testRegions),
    ("testKeyPairs", testKeyPairs),
    ("testSecurityGroup", testSecurityGroup)
    ]
}
