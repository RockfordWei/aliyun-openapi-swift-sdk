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

public extension Character {
    /// Get Unicode Int value
    public var unicode: Int {
        var unicode: Int = 0
        for scalar in String(self).unicodeScalars {
            unicode = Int(scalar.value)
        }
        return unicode
    }
}

public extension String {

  public var sysEnv: String {
    guard let e = getenv(self) else { return "" }
    return String(cString: e)
  }

  public var urlEncoded: String {
    let unreserved = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_.~"
    var encode: String = ""
    let _ = self.characters.map({ c in
        if unreserved.contains(c) {
            // Unreserved
            encode.append(c)
        }
        else {
            let ch = c.unicode
            var indexes: [Int]?
            if ch <= 0x007F {
                // The rest of ASCII
                indexes = [ch]
            }
            else if ch <= 0x07FF {
                // 0x007F < ch <= 0x07FF
                indexes = [0xC0 | (ch >> 6), 0x80 | (ch & 0x3F)]
            }
            else if ch <= 0xFFFF {
                // 0x07FF < ch <= 0xFFFF
                indexes = [0xE0 | (ch >> 12), 0x80 | ((ch >> 6) & 0x3F), 0x80 | (ch & 0x3F)]
            }
            else if ch <= 0x1FFFFF {
                // 0xFFFF < ch <= 0x1FFFFF
                indexes = [0xF0 | (ch >> 18), 0x80 | ((ch >> 12) & 0x3F),
                           0x80 | ((ch >> 6) & 0x3F), 0x80 | (ch & 0x3F)]
            }
            // Get encoding from (Hexadecimal Table)["%00", "%01", "%02"..."%FD", "%FE", "%FF"]
            if let indexes = indexes {
                for index in indexes {
                    let row: Int = index / 8
                    let column: Int = index % 8
                    let left: Int = row / 2
                    let right: Int = (row % 2 == 0) ? column : column + 8
                    encode.append(String.init(format: "%%%X%X", left, right))
                }
            }
            else {
                // If encode unsuccessfully
                encode.append(c)
            }
        }
    })
    return encode
  }
  public var percentEncode: String {
    return self.urlEncoded
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
  case unknown(raw: String)
}

public struct CommonResponse: Decodable {
  public var RequestId = ""
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
  public var Tags : [String:[String]] = [:]
  public var SecurityGroupId = ""
  public var SecurityGroupName = ""
  public var Description = ""
  public var AvailableInstanceAmount: Int? = nil
  public var VpcId = ""
}

public struct PermissionType: Codable {
  public var SourceCidrIp = ""
  public var DestCidrIp = ""
  public var Description = ""
  public var NicType = ""
  public var DestGroupName = ""
  public var PortRange = ""
  public var DestGroupId = ""
  public var Direction = ""
  public var Priority = 0
  public var IpProtocol = ""
  public var SourceGroupOwnerAccount = ""
  public var Policy = ""
  public var CreateTime = ""
  public var SourceGroupId = ""
  public var DestGroupOwnerAccount = ""
  public var SourceGroupName = ""
}

public struct SecurityGroupAttribute: Codable {
  public var SecurityGroupId = ""
  public var InnerAccessPolicy = ""
  public var SecurityGroupName = ""
  public var Description = ""
  public var RegionId = ""
  public var RequestId = ""
  public var Permissions: [String:[PermissionType]] = [:]
  public var VpcId = ""
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
  public var SecurityGroupIds: [String: [String]] = [:]
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

public class AcsRequest{
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
  let jsonDecoder = JSONDecoder()

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

  /// Perform a request by returning JSON type with an error if happends.
  /// The JSON type can be any codable struct. To perform a request, declare
  /// the json type in the callback function as a parameter.
  /// For example, if an InstanceType is expected, then try
  /// ```
  ///   acs.perform(... ) {
  ///     (json: InstanceType?, err) in
  ///     ...
  ///   }
  /// ```
  /// - parameters:
  ///   - product: String, the product name. For ECS, it is "ecs".
  ///   - action: String, the action name.
  ///   - regionId: String, the region id.
  ///   - verboseErrorCheck: Bool, default is false. If the returning result is not explicity required, set this variable to true. In such a case, callback(nil, nil) will indicate success, otherwise the error will be available. If the result is a CommonResponse type, then the value of this param must set to true.
  ///   - completion: callback with two parameters: (_ jsonStruct: Decodable?, _ e: Error?)
  ///     - JSON: json struct to parse back
  ///     - Error: exception on performing request or parsing json response.
  public func perform<JSON>
    (product: String, action: String, regionId: String = "",
     verboseErrorCheck : Bool = false,
     completion: @escaping (JSON?, Error?) -> Void)
    where JSON: Decodable {

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
    let task = session.dataTask(with: u) { data, code, err in
      guard let d = data else {
        completion(nil, err)
        return
      }
      if self.debug {
        print(d.stringValue())
      }
      if verboseErrorCheck {
        let msg = d.stringValue()
        if msg.contains("Error") || msg.contains("Invalid") {
          completion(nil, Exception.unknown(raw: msg))
        } else {
          completion(nil, nil)
        }
      } else {
        do {
          let json = try self.jsonDecoder.decode(JSON.self, from: d)
          completion(json, nil)
        } catch {
          completion(nil, error)
        }
      }
    }
    task.resume()
  }
}

public class ECS:AcsRequest {
  public let product = "ecs"

  public func describeRegions(_ completion: @escaping ([Region], Error?) -> Void ) {
    struct ResponseTypeRegions: Decodable {
      public var RequestId = ""
      public var Regions: [String:[Region]] = [:]
    }

    self.perform(product: self.product, action: "DescribeRegions") {
      (resp: ResponseTypeRegions?, err) in
      completion(resp?.Regions["Region"] ?? [], err)
    }
  }

  public func createKeyPair(region: String, name: String, _ completion: @escaping (AcsKeyPair?, Error?) -> Void ) {
    self.parameters = ["KeyPairName": name]
    self.perform(product: self.product, action: "CreateKeyPair", regionId: region) {
      (resp: AcsKeyPair?, err) in
      completion(resp, err)
    }
  }

  public func deleteKeyPairs(region: String, keyNames: [String], _ completion: @escaping (Error?) ->  Void) {
    self.parameters = ["KeyPairNames": keyNames.aliJSON]
    self.perform(product: self.product, action: "DeleteKeyPairs",
                 regionId: region, verboseErrorCheck: true) {
      (_ : CommonResponse?, err) in
      completion(err)
    }
  }

  public func describeKeyPairs(region: String, _ completion: @escaping ([AcsKeyPair], Error? ) -> Void ) {
    self.parameters = ["PageSize":"50"]
    struct ResponseTypeAcsKeys: Decodable {
      public var PageNumber = 0
      public var TotalCount = 0
      public var KeyPairs: [String:[AcsKeyPair]] = [:]
      public var PageSize = 0
      public var RequestId = ""
    }
    self.perform(product: self.product, action: "DescribeKeyPairs",
                 regionId: region) {
      ( resp: ResponseTypeAcsKeys?, err) in
      completion(resp?.KeyPairs["KeyPair"] ?? [], err)
    }
  }

  public func createSecurityGroup(region: String, name: String, description: String, _ completion: @escaping (String?, Error?) -> Void ) {
    self.parameters = ["SecurityGroupName": name, "Description": description]
    struct ResponseTypeSecurityGroup: Decodable {
      public var SecurityGroupId: String? = nil
      public var RequestId = ""
    }
    self.perform(product: self.product, action: "CreateSecurityGroup",
                 regionId: region) {
      (resp: ResponseTypeSecurityGroup?, err) in
      completion(resp?.SecurityGroupId, err)
    }
  }

  public func deleteSecurityGroup(region: String, id: String, _ completion: @escaping (Error?) -> Void ) {
    self.parameters = ["SecurityGroupId": id]
    self.perform(product: self.product, action: "DeleteSecurityGroup",
                 regionId: region, verboseErrorCheck: true) {
      (_: CommonResponse?, err) in
      completion(err)
    }
  }

  public func describeSecurityGroups(region: String, _ completion: @escaping ([SecurityGroup], Error?)->()) {
    self.parameters = ["PageSize":"50"]
    struct ResponseTypeSecurityGroups: Decodable {
      public var TotalCount = 0
      public var PageNumber = 0
      public var PageSize = 0
      public var RegionId = ""
      public var SecurityGroups: [String:[SecurityGroup]] = [:]
      public var RequestId = ""
    }
    self.perform(product: self.product, action: "DescribeSecurityGroups", regionId: region) {
      (resp: ResponseTypeSecurityGroups?, err) in
      completion(resp?.SecurityGroups["SecurityGroup"] ?? [], err)
    }
  }
  public func authorizeSecurityGroup(region: String, securityGroupId: String, ipProtocol: String, portRange: String, directionInbound: Bool, ip:String, policy: String, priority: String, nicType: String, _ completion: @escaping (Error?) -> Void ) {
    self.parameters = ["SecurityGroupId": securityGroupId, "IpProtocol": ipProtocol,
                       "PortRange": portRange, "Policy": policy, "Priority": priority, "NicType": nicType]
    let action:  String
    if directionInbound {
      self.parameters["SourceCidrIp"] = ip
      action = "AuthorizeSecurityGroup"
    } else {
      action = "AuthorizeSecurityGroupEgress"
      self.parameters["DestCidrIp"] = ip
    }
    self.perform(product: self.product, action: action, regionId:  region, verboseErrorCheck: true) {
      (_: CommonResponse?, err) in
      completion(err)
    }
  }

  public func revokeSecurityGroup(region: String, securityGroupId:String, permission: PermissionType, _ completion: @escaping (Error?) -> Void ) {
    self.parameters = ["SecurityGroupId": securityGroupId,
                       "IpProtocol": permission.IpProtocol,
                       "PortRange": permission.PortRange]
    let action: String
    if permission.Direction == "ingress"{
      action = "RevokeSecurityGroup"
      self.parameters["SourceCidrIp"] = permission.SourceCidrIp
    } else {
      action = "RevokeSecurityGroupEgress"
      self.parameters["DestCidrIp"] = permission.DestCidrIp
    }
    self.perform(product: self.product, action: action, regionId:  region, verboseErrorCheck: true) {
      (_: CommonResponse?, err) in
      completion(err)
    }
  }

  public func describeSecurityGroupAttribute(region: String, securityGroupId: String, _ completion: @escaping ([PermissionType], Error?) -> Void ) {
    self.parameters = ["SecurityGroupId": securityGroupId]
    self.perform(product: self.product, action: "DescribeSecurityGroupAttribute", regionId: region) {
      (resp: SecurityGroupAttribute?, err) in
      completion(resp?.Permissions["Permission"] ?? [], err)
    }
  }

  public func describeImageSupportInstanceTypes(region: String, imageId: String, _ completion: @escaping ([InstanceType], Error?) -> Void) {
    struct ResponseType: Decodable {
      public var InstanceTypes: [String:[InstanceType]] = [:]
      public var RequestId = ""
    }
    self.parameters = ["ImageId": imageId]
    self.perform(product: self.product, action: "DescribeImageSupportInstanceTypes", regionId: region) {
      (resp: ResponseType?, err)  in
      completion(resp?.InstanceTypes["InstanceType"] ?? [], err)
    }
  }

  public func createInstance
    (region: String, imageId: String = "ubuntu_16_0402_64_40G_base_20170222.vhd",
     securityGroupId: String, instanceType: String = "ecs.n1.tiny",
     name: String, description: String,
     chargeTypeInternet: ChargeTypeInternet = .PayByTraffic,
     chargeTypeInstance: ChargeTypeInstance = .PostPaid,
     maxBandwidthIn: Int = 1, maxBandwidthOut: Int = 1,
     keyPair: String, password: String? = nil,
     tags: [String: String], completion: @escaping (String?, Error?) -> Void) {

    self.parameters = [
      "ImageId": imageId, "SecurityGroupId": securityGroupId,
      "InstanceType": instanceType,
      "InstanceName": name,
      "Description": description,
      "InternetChargeType": chargeTypeInternet.rawValue,
      "InstanceChargeType": chargeTypeInstance.rawValue,
      "InternetMaxBandwidthIn": "\(maxBandwidthIn)",
      "InternetMaxBandwidthOut": "\(maxBandwidthOut)",
      "KeyPairName": keyPair
    ]
    if let pwd = password {
      self.parameters["Password"] = pwd
    }
    var counter = 0
    for (k, v) in tags {
      counter += 1
      if counter > 5 { break }
      self.parameters["Tag.\(counter).Key"] = k
      self.parameters["Tag.\(counter).Value"] = v
    }

    struct ResponseType: Decodable {
      public var InstanceId = ""
      public var RequestId = ""
    }
    self.perform(product: self.product, action: "CreateInstance", regionId: region) {
      (resp: ResponseType?, err) in
      completion(resp?.InstanceId, err)
    }
  }

  private func lookupInstancesBy(region: String, pageNumber: Int = 0, instances:[Instance] = [], err: Error? = nil, completion: @escaping ([Instance], Error?) -> Void ) {

    struct ResponseType: Decodable {
      public var TotalCount = 0
      public var PageNumber = 0
      public var PageSize = 0
      public var Instances: [String: [Instance]] = [:]
      public var RequestId = ""
    }
    self.parameters["PageNumber"] = "\(pageNumber)"
    self.perform(product: self.product, action: "DescribeInstances", regionId:  region) {
      (resp: ResponseType?, err) in

      guard let r = resp else {
        completion([], err)
        return
      }

      let next = r.TotalCount > r.PageNumber * r.PageSize ? r.PageNumber + 1 : 0
      var inst = instances
      inst.append(contentsOf: r.Instances["Instance"] ?? [])
      guard next > 0 else {
        completion(inst, nil)
        return
      }
      self.lookupInstancesBy(region: region, pageNumber: next, instances: inst, completion: completion)
    }
  }

  public func loadInstances(region: String, tags: [String: String] = [:], completion: @escaping ([Instance], Error?) -> Void) {
    var counter = 0
    for (k, v) in tags {
      counter += 1
      if counter > 5 { break }
      self.parameters["Tag\(counter)Key"] = k
      self.parameters["Tag\(counter)Value"] = v
    }
    self.parameters["PageNumber"] = "1"
    self.parameters["PageSize"] = "100"

    self.lookupInstancesBy(region: region, pageNumber: 1, completion: completion)
  }

  public func startInstance(instanceId: String, completion: @escaping (Error?) -> Void) {
    self.parameters = ["InstanceId": instanceId]
    self.perform(product: self.product, action: "StartInstance", verboseErrorCheck: true) {
      (_: CommonResponse?, err) in
      completion(err)
    }
  }

  public func stopInstance(instanceId: String, completion: @escaping (Error?) -> Void) {
    self.parameters = ["InstanceId": instanceId]
    self.perform(product: self.product, action: "StopInstance", verboseErrorCheck: true) {
      (_: CommonResponse?, err) in
      completion(err)
    }
  }

  public func deleteInstance(instanceId: String, completion: @escaping (Error?) -> Void ) {
    self.parameters = ["InstanceId": instanceId]
    self.perform(product: self.product, action: "DeleteInstance", verboseErrorCheck: true) {
      (_: CommonResponse?, err) in
      completion(err)
    }
  }

  public func allocateIP(instanceId: String, completion: @escaping (String?, Error?) -> Void) {
    struct ResponseType: Decodable {
      public var IpAddress = ""
      public var RequestId = ""
    }
    self.parameters = ["InstanceId": instanceId]
    self.perform(product: self.product, action: "AllocatePublicIpAddress") {
      (resp: ResponseType?, err) in
      completion(resp?.IpAddress, err)
    }
  }
}








