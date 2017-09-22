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
    var newGroupId = ""
    var exp = expectation(description: "securityGroupCreation")
    ecs.createSecurityGroup(region: REGION, name: groupName, description: "testing") { id, err in
      exp.fulfill()
      XCTAssertNotNil(id)
      XCTAssertNil(err)
      newGroupId = id ?? ""
    }
    wait(for: [exp], timeout: 10)
    XCTAssertFalse(newGroupId.isEmpty)
    exp = expectation(description: "securityGroupDescription")
    ecs.describeSecurityGroups(region: REGION) { groups, err in
      exp.fulfill()
      XCTAssertGreaterThan(groups.count, 0)
      XCTAssertNil(err)
      guard let grp = (groups.first { $0.SecurityGroupName == groupName }),
      grp.SecurityGroupId == newGroupId else {
        XCTFail("new created group is not found")
        return
      }
    }
    wait(for: [exp], timeout: 10)
    exp = expectation(description: "grantSecurityRule")
    ecs.authorizeSecurityGroup(region: REGION, securityGroupId: newGroupId, ipProtocol: "TCP", portRange: "8080/8181", directionInbound: true, ip: "0.0.0.0/0", policy: "accept", priority: "1", nicType: "internet") {
      err in
      XCTAssertNil(err)
      exp.fulfill()
    }
    wait(for: [exp], timeout: 10)
    exp = expectation(description: "listSecurityRules")
    var newRule: PermissionType? = nil
    ecs.describeSecurityGroupAttribute(region: REGION, securityGroupId: newGroupId) { perm, err in
      XCTAssertNil(err)
      XCTAssertGreaterThan(perm.count, 0)
      print(perm)
      let filter = perm.filter { $0.IpProtocol == "TCP" && $0.PortRange == "8080/8181"}
      XCTAssertGreaterThan(filter.count, 0)
      newRule = filter.first
      exp.fulfill()
    }
    wait(for: [exp], timeout: 10)
    exp = expectation(description: "revokeSecurityRules")
    guard let rule = newRule else {
      XCTFail("new rule is not found")
      return
    }
    ecs.revokeSecurityGroup(region: REGION, securityGroupId: newGroupId, permission: rule) { err in
      XCTAssertNil(err)
      exp.fulfill()
    }
    wait(for: [exp], timeout: 10)
    ecs.debug = false
    exp = expectation(description: "securityGroupDeletion")
    ecs.deleteSecurityGroup(region: REGION, id: groupName) { err in
      exp.fulfill()
      XCTAssertNil(err)
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
      ecs.createKeyPair(region: REGION, name: k) { keyPair, err in
        if let kp = keyPair {
          XCTAssertEqual(kp.KeyPairName, k)
          exp.fulfill()
        } else {
          XCTFail(err?.localizedDescription ?? "unknown")
        }
      }
    }
    wait(for: exps, timeout: 30)
    var exp = expectation(description: "keyDescription")
    ecs.describeKeyPairs(region: REGION) { keylist, message in
      exp.fulfill()
      XCTAssertGreaterThan(keylist.count, 1)
    }
    wait(for: [exp], timeout: 20)
    exp = expectation(description: "keyDeletion")
    ecs.deleteKeyPairs(region: REGION, keyNames: keys) { err in
      XCTAssertNil(err)
      exp.fulfill()
    }
    wait(for: [exp], timeout: 10)
  }

  func testRegions() {
    let ecs = ECS(access: access)
    let exp = expectation(description: "regions")
    ecs.describeRegions { regions, err in
      exp.fulfill()
      XCTAssertGreaterThan(regions.count, 0)
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
    //("testSecurityGroup", testSecurityGroup)
    ]
}
