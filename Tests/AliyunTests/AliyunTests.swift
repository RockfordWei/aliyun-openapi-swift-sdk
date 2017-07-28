import XCTest
@testable import Aliyun

public class Sync {
  private var pending = true
  public func done() { pending = false }

  public func wait(_ timeout: Int = 5, _ action: @escaping (Sync) -> Void) {
    action(self)
    let now = time(nil)
    var then = now
    var shouldWait = true
    repeat {
      then = time(nil)
      usleep(10000)
      shouldWait = (then - now) < timeout
    } while pending && shouldWait
  }
}

let access = AcsCredential()

class AliyunTests: XCTestCase {


  override func setUp() {
    AcsRequest.Debug = true
    access.id = "default"
    access.key = "ACSKEY".sysEnv
    access.secret = "ACSPWD".sysEnv
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

  func testSecurityGroups() {
    let ecs = ECS(access: access)
    Sync().wait { sync in
      ecs.describeSecurityGroups(region: "us-east-1") { securityGroups, message in
        sync.done()
        XCTAssertGreaterThan(securityGroups.count, 0)
        print(securityGroups)
      }
    }
  }

  func testRegions() {

    let ecs = ECS(access: access)
    Sync().wait { sync in
      ecs.describeRegions { regions in
        sync.done()
        XCTAssertGreaterThan(regions.count, 0)
        print(regions)
      }
    }
  }

  func testKeyPairs() {
    let now = time(nil)
    let region = "us-east-1"
    let keys = (["pkey1", "pkey2"]).map { String(format: "\($0)%02x", now) }
    for k in keys {
      Sync().wait { sync in
        let ecs = ECS(access: access)
        ecs.createKeyPair(region: region, name: k) { keyPair, msg in
          if let kp = keyPair {
            XCTAssertEqual(kp.name, k)
            print(kp)
          } else {
            XCTFail(msg)
          }
          sync.done()
        }
      }
    }
    let ecs = ECS(access: access)
    Sync().wait { sync in
      ecs.deleteKeyPairs(region: region, keyNames: keys) { suc, msg in
        XCTAssertTrue(suc)
        XCTAssertTrue(msg.isEmpty)
        sync.done()
      }
    }
  }

  func testInstanceTypes() {
    let ecs = ECS(access: access)
    Sync().wait { sync in
      ecs.describeImageSupportInstanceTypes(region: "us-east-1", imageId: "ubuntu_16_0402_64_40G_base_20170222.vhd") { types, msg in
        XCTAssertGreaterThan(types.count, 0)
        print(types)
        sync.done()
      }
    }
  }

  func testInstances() {
    let ecs = ECS(access: access)
    Sync().wait { sync in
      ecs.describeInstances(region: "us-east-1") { instances, msg in
        XCTAssertFalse(msg.contains("Error") || msg.contains("Exception") || msg.contains("Invalid"))
        print(instances)
        print(msg)
        sync.done()
      }
    }
  }

  static var allTests = [
    ("testSignature", testSignature),
    ("testToSign", testToSign),
    ("testRegions", testRegions),
    ("testKeyPairs", testKeyPairs),
    ("testInstanceTypes", testInstanceTypes),
    ("testInstances", testInstances)
    ]
}







