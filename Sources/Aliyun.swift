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


public class Region: PerfectLib.JSONConvertible, CustomStringConvertible, Equatable {

  public var id = ""
  public var name = ""
  public init() { }

  public static func ==(lhs: Region, rhs: Region) -> Bool {
    return lhs.id == rhs.id && lhs.name == rhs.name
  }

  public func setJSONValues(_ values:[String:Any]) {
    id = values["RegionId"] as? String ?? ""
    name = values["LocalName"] as? String ?? ""
  }
  public func getJSONValues() -> [String:Any] {
    return ["RegionId": id, "LocalName": name]
  }
  public func jsonEncodedString() throws -> String {
    return try self.getJSONValues().jsonEncodedString()
  }
  public var description: String {
    return (try? self.jsonEncodedString()) ?? "{Region:: JSON Fault}"
  }
}

public class AcsCredential: PerfectLib.JSONConvertible, CustomStringConvertible, Equatable {
  public var id = ""
  public var key = ""
  public var secret = ""
  public static func ==(lhs: AcsCredential, rhs: AcsCredential) -> Bool {
    return lhs.id == rhs.id && lhs.key == rhs.key && lhs.secret == rhs.secret
  }

  public func setJSONValues(_ values:[String:Any]) {
    id = values["id"] as? String ?? ""
    key = values["key"] as? String ?? ""
    secret = values["secret"] as? String ?? ""
  }
  public func getJSONValues() -> [String:Any] {
    return ["id": id, "key": key, "secret": secret]
  }
  public func jsonEncodedString() throws -> String {
    return try self.getJSONValues().jsonEncodedString()
  }
  public var description: String {
    return (try? self.jsonEncodedString()) ?? "{Region:: JSON Fault}"
  }
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
  public static var Debug = false

  public init(access: AcsCredential) {
    self.credential = access
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

  public func generateURL(product: String, action: String, regionId: String = "") -> String {
    let timestamp = self.timeFormatter.string(from: Date())
    let nonce = AcsRequest.Nonce
    let template = ["SignatureVersion": self.signatureVersion,
                    "SignatureMethod": self.signatureMethod,
                    "SignatureNonce": nonce,
                    "Action": action,
                    "Format": self.format,
                    "Version": self.version,
                    "AccessKeyId": self.credential.key]

    var p =  template
    p["TimeStamp"] = timestamp
    p["SignatureMethod"] = self.signatureMethod
    if !regionId.isEmpty {
      p["RegionId"] = regionId
    }
    for (k, v) in parameters {
      p[k] = v
    }
    let query = AcsRequest.CanonicalizedQuery(method: self.method, queryParamters: p)
    let signature = AcsRequest.Sign(query, keySecret: self.credential.secret)
    if AcsRequest.Debug {
      print(query)
      print(signature)
    }
    var u = template
    u["Signature"] = signature.urlEncoded
    u["TimeStamp"] = timestamp.urlEncoded
    return self.protocol + "://" + product + "." + self.domain + "/?"
      + u.map { $0.key + "=" + $0.value }.joined(separator: "&")
  }

  public func perform(product: String, action: String, regionId: String = "", completion: @escaping ([String: Any], String) -> Void) {
    let url = self.generateURL(product: product, action: action, regionId: regionId)
    if AcsRequest.Debug {
      print(url)
    }
    _ = CURLRequest(url).perform { confirmation in
      do {
        let resp = try confirmation()
        if AcsRequest.Debug {
          print(resp.bodyString)
        }
        let json: [String: Any] = resp.bodyJSON
        completion(json, "")
      }catch {
        completion([:], "\(error)")
      }
    }
  }
}

public class ECS: AcsRequest {
  public let product = "ecs"

  public func describeRegions(_ completion: @escaping ([Region]) -> Void ) {
    self.perform(product: self.product, action: "DescribeRegions") {
      json, msg in
      if let a = json["Regions"] as? [String: Any],
        let b = a["Region"] as? [Any] {
        let c = b.map { i -> Region in
          let r = Region()
          if let d = i as? [String: Any] {
            r.setJSONValues(d)
          }
          return r
        }
        completion(c)
      } else {
        completion([])
      }//end if
    }
  }
}






