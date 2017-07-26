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
import PerfectLib
import PerfectCrypto
import PerfectCURL

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
}

public class AcsRequest {
  public var method = "GET"
  public let timeFormatter = DateFormatter()
  public let product: String
  public var version = "2014-05-26"
  public let action: String
  public var regionId = ""
  public var timeStamp = ""
  public let accessKeyId: String
  public let accessKeySecret: String
  public let format = "JSON"
  public var `protocol` = "https"
  public var domain = "aliyuncs.com"
  public let signatureMethod = "HMAC-SHA1"
  public let signatureVersion = "1.0"
  public var parameters:[String: String] = [:]

  public init(product: String, action: String, regionId: String = "", accessKeyId: String, accessKeySecret: String) {
    self.product = product
    self.action = action
    self.regionId = regionId
    self.accessKeyId = accessKeyId
    self.accessKeySecret = accessKeySecret
    timeFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    timeFormatter.timeZone = TimeZone(secondsFromGMT: 0)
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
    var bytes = stringToSign.sign(.sha1, key: HMACKey(keySecret + "&"))?.encode(.base64)
    bytes?.append(0)
    if let b = bytes {
      return String(cString: b)
    } else {
      return ""
    }
  }

  public static var Nonce: String {
    return UUID().string
  }

  public var url: String {
    let timestamp = self.timeFormatter.string(from: Date())
    let nonce = AcsRequest.Nonce
    let template = ["SignatureVersion": self.signatureVersion,
                    "SignatureMethod": self.signatureMethod,
                    "SignatureNonce": nonce,
                    "Action": self.action,
                    "Format": self.format,
                    "Version": self.version,
                    "AccessKeyId": self.accessKeyId]

    var p =  template
    p["TimeStamp"] = timestamp
    p["SignatureMethod"] = self.signatureMethod
    if !regionId.isEmpty {
      p["RegionId"] = self.regionId
    }
    for (k, v) in parameters {
      p[k] = v
    }
    let query = AcsRequest.CanonicalizedQuery(method: self.method, queryParamters: p)
    let signature = AcsRequest.Sign(query, keySecret: self.accessKeySecret)
    var u = template
    u["Signature"] = signature
    u["TimeStamp"] = timestamp.urlEncoded
    return self.protocol + "://" + self.product + "." + self.domain + "/?"
      + u.map { $0.key + "=" + $0.value }.joined(separator: "&")
  }

  public func perform(completion: @escaping ([String: Any], String) -> Void) {
    _ = CURLRequest(self.url).perform { confirmation in
      do {
        let resp = try confirmation()
        let json: [String: Any] = resp.bodyJSON
        completion(json, "")
      }catch {
        completion([:], "\(error)")
      }
    }
  }
}

public struct Region {
  public let id: String
  public let name: String
  public init(_ dic: [String: Any] = [:]) {
    id = dic["RegionId"] as? String ?? ""
    name = dic["LocalName"] as? String ?? ""
  }
}

public extension AcsRequest {
  public static func EcsDescribeRegions(accessKeyId: String, accessKeySecrect: String, completion: @escaping ([Region], String) -> Void ) {
    let a = AcsRequest(product: "ecs", action: "DescribeRegions", accessKeyId: accessKeyId, accessKeySecret: accessKeySecrect)
    a.perform { json, msg in
      if let a = json["Regions"] as? [String: Any],
        let b = a["Region"] as? [Any] {
        let c = b.map { i -> Region in
          if let r = i as? [String: Any] {
            return Region(r)
          } else {
            return Region()
          }
        }
        completion(c, msg)
      } else {
        completion([], msg)
      }
    }
  }
}








