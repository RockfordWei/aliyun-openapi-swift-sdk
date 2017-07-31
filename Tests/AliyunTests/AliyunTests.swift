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
let passwd = "PASSWD".sysEnv
let REGION = "cn-hongkong"

class AliyunTests: XCTestCase {


  override func setUp() {
    // AcsRequest.Debug = true
    access.id = "default"
    access.key = "ACSKEY".sysEnv
    access.secret = "ACSPWD".sysEnv
  }

  func testInstances() {
    let ecs = ECS(access: access)
    var objectiveInstanceId: String? = nil
    let region = REGION
    let tags = ["Perfect":"1"]
    Sync().wait { sync in
      ecs.createInstance(region: region, securityGroupId: "sg-j6c58xjb4po9jq2hsc0u", name: "PT-01", description: "PerfectTemplate Test Instance", keyPair: "TestKey", tags: tags) {
        instanceId, msg in
        objectiveInstanceId = instanceId
        print("--------------- INSTANCE CREATION ----------------")
        if let id = instanceId {
          print(id)
        } else {
          XCTFail(msg)
        }
        sync.done()
      }
    }
    sleep(5)
    Sync().wait { sync in
      ecs.loadInstances(region: region, tags: tags) { insts, msgs in
        print("############ INSTANCE STATUS ###################")
        XCTAssertGreaterThan(insts.count, 0)
        print(insts)
        sync.done()
      }
    }
    if let id = objectiveInstanceId{
      Sync().wait { sync in
        ecs.allocateIP(instanceId: id) { ipAddress, msg in
          sync.done()
          guard let ip = ipAddress else {
            XCTFail(msg)
            return
          }
          print("+++++++++++++++++ IP ADDRESS +++++++++++++++")
          print("ssh -i ~/.ssh/TestKey.pem root@\(ip)")
        }
      }
      Sync().wait { sync in
        ecs.startInstance(instanceId: id) { success, message in
          XCTAssertTrue(success)
          print(message)
          sync.done()
        }
      }
    }
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
      ecs.describeSecurityGroups(region: REGION) { securityGroups, message in
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
    let keys = (["pkey1", "pkey2"]).map { String(format: "\($0)%02x", now) }
    for k in keys {
      Sync().wait { sync in
        let ecs = ECS(access: access)
        ecs.createKeyPair(region: REGION, name: k) { keyPair, msg in
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
      ecs.deleteKeyPairs(region: REGION, keyNames: keys) { suc, msg in
        XCTAssertTrue(suc)
        XCTAssertTrue(msg.isEmpty)
        sync.done()
      }
    }
  }

  func testInstanceTypes() {
    let ecs = ECS(access: access)
    Sync().wait { sync in
      ecs.describeImageSupportInstanceTypes(region: REGION, imageId: "ubuntu_16_0402_64_40G_base_20170222.vhd") { types, msg in
        XCTAssertGreaterThan(types.count, 0)
        print(types)
        sync.done()
      }
    }
  }

  static var allTests = [
    ("testInstances", testInstances),
    ("testSignature", testSignature),
    ("testToSign", testToSign),
    ("testRegions", testRegions),
    ("testKeyPairs", testKeyPairs),
    ("testInstanceTypes", testInstanceTypes)
    ]
}







