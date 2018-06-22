//
//  FDEEncryptor.swift
//  Crypt
//
//  Created by Andrew Dunham on 5/11/18.
//  Copyright © 2018 Graham Gilbert. All rights reserved.
//

import Foundation
import Sodium
import os.log

class FDEEncryptor {
  private static var sodium = Sodium()
  private static let log = OSLog(subsystem: "com.grahamgilbert.crypt", category: "FDEEncryptor")

  private var recipientPK: Data;

  init?(_ hexKey: String) {
    guard let key = FDEEncryptor.hexDecode(hexKey) else {
      os_log("could not hex decode encryption key", log: FDEEncryptor.log, type: .error)
      return nil
    }

    self.recipientPK = key;
  }

  private static func hexDecode(_ str: String) -> Data? {
    return sodium.utils.hex2bin(str, ignore: " \n")
  }

  private static func hexEncode(_ str: String) -> String? {
    return sodium.utils.bin2hex(str.data(using: .utf8)!)
  }

  // seal will encrypt a single string value, returning the encrypted data as a hex string
  func seal(_ data: String) -> String? {
    let enc = FDEEncryptor.sodium.box.seal(message: data.data(using: .utf8)!,
                                           recipientPublicKey: recipientPK)

    if let encBytes = enc {
      return FDEEncryptor.sodium.utils.bin2hex(encBytes)
    } else {
      return nil
    }
  }

  // The list of keys to seal in "sealPlist". If a value exists with
  // any of these keys, and if it's a supported data type, it will be
  // replaced with the sealed value.
  private static let sealKeys = ["RecoveryKey"];

  // sealPlist will seal a `fdesetup` plist
  func sealPlist(_ pl: NSDictionary) -> NSDictionary {
    let copied = NSMutableDictionary(dictionary: pl)

    for key in FDEEncryptor.sealKeys {
      guard let obj = copied.object(forKey: key) else {
        continue;
      }

      if let val = obj as? String {
        // Seal the input, and overwrite the input key
        if let sealed = self.seal(val) {
          copied[key] = sealed
        } else {
          os_log("could not perform encryption on key %@", log: FDEEncryptor.log, type: .error, key as CVarArg)
          copied[key] = "encryption error"
        }
      } else {
        // TODO: should we handle other types of object?
        os_log("unknown data type for key %@", log: FDEEncryptor.log, type: .info)
      }
    }

    return copied
  }
}
