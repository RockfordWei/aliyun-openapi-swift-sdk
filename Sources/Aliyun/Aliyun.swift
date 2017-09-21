//
//  Aliyun.swift
//  Perfect-Aliyun
//
//  Created by Rockford Wei on 2017-07-19.
//  Copyright © 2017 PerfectlySoft. All rights reserved.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2017 - 2018 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

import Foundation
import Crypto

public extension Array {
  public var aliJSON : String {
    let joined = self.map { "\"\($0)\""  }.joined(separator: ",")
    return "[\(joined)]"
  }
}

public extension Data {
  public func stringValue() -> String {
    return String(data: self, encoding: .utf8) ?? ""
  }
}

public extension String {

  public var sysEnv: String {
    guard let e = getenv(self) else { return "" }
    return String(cString: e)
  }

  public var urlEncoded: String {
    let lowers = Character("a")...Character("z")
    let uppers = Character("A")...Character("Z")
    let numbers = Character("0")...Character("9")
    let remains = [Character("."), Character("-"), Character("*"), Character("_")]
    return self.characters.map { char -> String in
      if lowers.contains(char) || uppers.contains(char) || numbers.contains(char) || remains.contains(char) {
        return String(describing: char)
      } else if char == Character(" ") {
        return "+"
      } else {
        let a = String(describing: char).unicodeScalars.first?.value ?? 0
        return String(format: "%%%02X", a)
      }
      }.joined()
  }
  public var percentEncode: String {
    return self.urlEncoded
      .replacingOccurrences(of: "+", with: "%20")
      .replacingOccurrences(of: "*", with: "%2A")
      .replacingOccurrences(of: "%7E", with: "~")
  }
  public func signSha1HMACToBase64(_ secret: String) -> String {
    let str = self.cString(using: .utf8)
    let strlen = self.lengthOfBytes(using: .utf8)

    let key = secret.cString(using: .utf8)
    let keylen = secret.lengthOfBytes(using: .utf8)

    let size = Int(CC_SHA1_DIGEST_LENGTH)
    let cHMAC = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
    cHMAC.initialize(to: 0)

    defer { cHMAC.deallocate(capacity: size) }
    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), key, keylen, str, strlen, cHMAC)
    let res = Data(bytes: cHMAC, count: size)
    return res.base64EncodedString()
  }
}

public enum Exception: Error {
  case invalidURL
  case unknown
}

public struct IpAddressSetType: Codable {
  public var IpAddress: [String] = []
}

public struct Region: Codable {
  public var RegionId = ""
  public var LocalName = ""
}

public struct AcsCredential: Codable {
  public var key = ""
  public var secret = ""
}

public struct AcsKeyPair: Codable {
  public var KeyPairName = ""
  public var KeyPairFingerPrint = ""
  public var PrivateKeyBody: String? = nil
}

public struct SecurityGroup: Codable {
  public var CreationTime = ""
  public var Tags : [String] = []
  public var SecurityGroupId = ""
  public var SecurityGroupName = ""
  public var Description = ""
  public var AvailableInstanceAmount = 0
  public var VpcId = ""
}

public struct PermissionType: Codable {
  public var IpProtocol = ""
  public var PortRange = ""
  public var SourceCidrIp = ""
  public var SourceGroupId = ""
  public var SourceGroupOwnerAccount = ""
  public var DestCidrIp = ""
  public var DestGroupId = ""
  public var DestGroupOwnerAccount = ""
  public var Policy = ""
  public var NicType = ""
  public var Priority = ""
  public var Direction = ""
  public var Description = ""
  public var CreateTime = ""
}

public struct InstanceType: Codable {
  public var InstanceTypeId = ""
  public var CpuCoreCount = 0
  public var MemorySize = 0.0
  public var InstanceTypeFamily = ""
}

public enum ChargeTypeInternet: String {
  case PayByTraffic = "PayByTraffic"
  case PayByBandwidth = "PayByBandwidth"
}

public enum ChargeTypeInstance: String {
  case PrePaid = "PrePaid"
  case PostPaid = "PostPaid"
}

public struct VpcAttributesType: Codable {
  public var VpcId = ""
  public var VSwitchId = ""
  public var PrivateIpAddress = IpAddressSetType()
  public var NatIpAddress = ""
}

public struct LockReasonType: Codable {
  public var LockReason: [String] = []
}

public struct EipAddressSetType: Codable {
  public var RegionId = ""
  public var IpAddress = ""
  public var AllocationId = ""
  public var Status = ""
  public var InstanceType = ""
  public var InstanceId = ""
  public var Bandwidth = 0
  public var InternetChargeType = ""
  public var OperationLocks = LockReasonType()
  public var AllocationTime: String = ""
}

public struct Instance: Codable {
  public var InstanceId = ""
  public var InstanceName = ""
  public var Description = ""
  public var ImageId = ""
  public var RegionId = ""
  public var ZoneId = ""
  public var Cpu = 0
  public var Memory = 0
  public var InstanceType = ""
  public var InstanceTypeFamily = ""
  public var HostName = ""
  public var SerialNumber = ""
  public var Status = ""
  public var SecurityGroupIds: [String] = []
  public var EipAddress = EipAddressSetType()
  public var PublicIpAddress = IpAddressSetType()
  public var InternetMaxBandwidthIn = 0
  public var InternetMaxBandwidthOut = 0
  public var InternetChargeType = ""
  public var CreationTime = ""
  public var InnerIpAddress = IpAddressSetType()
  public var InstanceNetworkType = ""
  public var OperationLocks = LockReasonType()
  public var InstanceChargeType = ""
  public var DeviceAvaiable = false
  public var IoOptimized = false
  public var ExpiredTime = ""
  public var KeyPairName = ""
  public var VpcAttributes = VpcAttributesType()
}

public class AcsRequest {
  public var method = "GET"
  public let timeFormatter = DateFormatter()
  public var version = "2014-05-26"
  public var timeStamp = ""
  public let credential: AcsCredential
  public let format = "JSON"
  public var `protocol` = "https"
  public var domain = "aliyuncs.com"
  public let signatureMethod = "HMAC-SHA1"
  public let signatureVersion = "1.0"
  public var parameters:[String: String] = [:]
  public var nonce = ""
  public var debug = false

  public init(access: AcsCredential) {
    self.credential = access
    timeFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    timeFormatter.timeZone = TimeZone(secondsFromGMT: 0)
    timeStamp = self.timeFormatter.string(from: Date())
    nonce = UUID().uuidString
  }
  public static func CanonicalizedQuery(method: String = "GET", queryParamters: [String: String]) -> String {
    let canonicalized = queryParamters.keys.sorted().map { key in
      let k = key
      let v = queryParamters[key] ?? ""
      return k + "=" + v.percentEncode
      }.joined(separator: "&")
    return method + "&" + "/".percentEncode + "&" + canonicalized.percentEncode
  }
  public static func Sign(_ stringToSign: String, keySecret: String) -> String {
    return stringToSign.signSha1HMACToBase64(keySecret + "&")
  }

  public func generateURL(product: String, action: String, regionId: String = "") -> String {
    let template = ["SignatureVersion": self.signatureVersion,
                    "SignatureMethod": self.signatureMethod,
                    "SignatureNonce": nonce,
                    "Action": action,
                    "Format": self.format,
                    "Version": self.version,
                    "AccessKeyId": self.credential.key]

    var p =  template
    p["Timestamp"] = self.timeStamp
    p["SignatureMethod"] = self.signatureMethod
    if !regionId.isEmpty {
      p["RegionId"] = regionId
    }
    for (k, v) in self.parameters {
      p[k] = v
    }
    let query = AcsRequest.CanonicalizedQuery(method: self.method, queryParamters: p)
    let signature = AcsRequest.Sign(query, keySecret: self.credential.secret)
    if self.debug {
      print("to sign:")
      print(query)
      print("signed:")
      print(signature)
    }
    var u = template
    u["Signature"] = signature.urlEncoded
    u["Timestamp"] = timeStamp.urlEncoded
    return self.protocol + "://" + product + "." + self.domain + "/?"
      + u.map { $0.key + "=" + $0.value }.joined(separator: "&")
  }
  public func perform(product: String, action: String, regionId: String = "", completion: @escaping (Data?, Error?) -> Void) {
    var url = self.generateURL(product: product, action: action, regionId: regionId) + "&Version=\(self.version)"

    if parameters.count > 0 {
      url += "&" + parameters.map { key, value -> String in
        let k = key.urlEncoded
        let v = value.urlEncoded
        return "\(k)=\(v)"
        }.joined(separator: "&")
    }

    if !regionId.isEmpty {
      url += "&RegionId=\(regionId)"
    }

    if self.debug {
      print(url)
    }

    guard let u = URL(string: url) else {
      completion(nil, Exception.invalidURL)
      return
    }
    let config = URLSessionConfiguration.default
    let session = URLSession(configuration: config)
    let task = session.dataTask(with: u) { completion($0, $2) }
    task.resume()
  }
}

public class ECS:AcsRequest {
  public let product = "ecs"

  public func describeRegions(_ completion: @escaping ([Region]) -> Void ) {
    self.perform(product: self.product, action: "DescribeRegions") { data, err in
      guard let d = data else {
        let e = err ?? Exception.unknown
        print(e)
        completion([])
        return
      }
      struct ResponseTypeRegions: Codable {
        public var RequestId = ""
        public var Regions: [String:[Region]] = [:]
      }

      let dec = JSONDecoder()
      do {
        let regions = try dec.decode(ResponseTypeRegions.self, from: d)
        if let r = regions.Regions["Region"] {
          completion(r)
        } else {
          print("Unexpected regions format:", d.stringValue())
          completion([])
        }
      }catch {
        print(error.localizedDescription)
        completion([])
      }
    }
  }

  public func createKeyPair(region: String, name: String, _ completion: @escaping (AcsKeyPair?, String) -> Void ) {
    self.parameters = ["KeyPairName": name]
    self.perform(product: self.product, action: "CreateKeyPair", regionId: region) { data, err in
      guard let d = data else {
        let e = err ?? Exception.unknown
        completion(nil, e.localizedDescription)
        return
      }
      let dec = JSONDecoder()
      do {
        let acs = try dec.decode(AcsKeyPair.self, from: d)
        completion(acs, "")
      }catch {
        completion(nil, error.localizedDescription)
      }
    }
  }

  public func deleteKeyPairs(region: String, keyNames: [String], _ completion: @escaping (Bool, String) ->  Void) {
    self.parameters = ["KeyPairNames": keyNames.aliJSON]
    self.perform(product: self.product, action: "DeleteKeyPairs", regionId: region) { data, err in
      guard let d = data else {
        let e = err ?? Exception.unknown
        completion(false, e.localizedDescription)
        return
      }
      let msg = d.stringValue()
      if msg.contains("Error") || msg.contains("Invalid") {
        completion(false, msg)
      } else {
        completion(true, "")
      }
    }
  }

  public func describeKeyPairs(region: String, _ completion: @escaping ([AcsKeyPair], String ) -> Void ) {
    self.parameters = ["PageSize":"50"]
    self.perform(product: self.product, action: "DescribeKeyPairs", regionId: region) { data, err in
      guard let d = data else {
        let e = err ?? Exception.unknown
        completion([], e.localizedDescription)
        return
      }
      print(d.stringValue())
      struct ResponseTypeAcsKeys: Codable {
        public var PageNumber = 0
        public var TotalCount = 0
        public var KeyPairs: [String:[AcsKeyPair]] = [:]
        public var PageSize = 0
        public var RequestId = ""
      }
      let dec = JSONDecoder()
      do {
        let keys = try dec.decode(ResponseTypeAcsKeys.self, from: d)
        if let r = keys.KeyPairs["KeyPair"] {
          completion(r, "")
        } else {
          completion([], d.stringValue())
        }
      }catch {
        completion([], error.localizedDescription)
      }

    }
  }
}








