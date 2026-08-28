import Darwin
import Foundation
import Security

private let isolatedValidationService = "com.github.b1rd33.nordmac.validation"
private let loginValidationService = "com.github.b1rd33.nordmac.validation.native"
private let sessionPattern = try! NSRegularExpression(pattern: "^nordmac-keychain-native-validation-[a-f0-9]{32}$")

private struct Target {
    let keychain: SecKeychain
    let service: String
}

private func fail(_ message: String, status: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(status)
}

private func openKeychain(_ path: String, description: String) -> SecKeychain {
    var keychain: SecKeychain?
    let status = SecKeychainOpen(path, &keychain)
    guard status == errSecSuccess, let keychain else {
        fail("open \(description) Keychain: \(status)")
    }
    return keychain
}

private func validationTarget(_ arguments: [String]) -> Target {
    if arguments.count == 4, arguments[3] == "--login-keychain-validation" {
        guard getuid() != 0, geteuid() != 0 else { fail("login Keychain validation cannot run as root") }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        guard home.hasPrefix("/Users/"), !home.contains("//"), !home.contains("/./"), !home.contains("/../") else {
            fail("invalid login Keychain home")
        }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: home)
            let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
            guard owner == getuid() else { fail("login Keychain home ownership is invalid") }
        } catch {
            fail("inspect login Keychain home")
        }
        let path = home + "/Library/Keychains/login.keychain-db"
        return Target(keychain: openKeychain(path, description: "login"), service: loginValidationService)
    }
    guard arguments.count == 5, arguments[3] == "--validation-keychain" else {
        fail("production Keychain target is disabled")
    }
    let rawPath = arguments[4]
    guard rawPath.hasPrefix("/private/tmp/"),
          !rawPath.contains("//"), !rawPath.contains("/./"), !rawPath.contains("/../") else {
        fail("validation Keychain path is not canonical")
    }
    let path = rawPath
    let pathString = path as NSString
    let directoryPath = pathString.deletingLastPathComponent
    let name = (directoryPath as NSString).lastPathComponent
    let range = NSRange(name.startIndex..<name.endIndex, in: name)
    guard pathString.lastPathComponent == "validation.keychain-db" else { fail("invalid validation Keychain filename") }
    guard (directoryPath as NSString).deletingLastPathComponent == "/private/tmp" else { fail("invalid validation Keychain parent") }
    guard sessionPattern.firstMatch(in: name, range: range) != nil else { fail("invalid validation Keychain session") }
    do {
        let attributes = try FileManager.default.attributesOfItem(atPath: directoryPath)
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value
        guard owner == getuid(), permissions == 0o700 else {
            fail("validation Keychain directory ownership is invalid")
        }
    } catch {
        fail("inspect validation Keychain directory")
    }
    return Target(keychain: openKeychain(path, description: "validation"), service: isolatedValidationService)
}

private func baseQuery(account: String, service: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
}

private func searchQuery(account: String, target: Target) -> [String: Any] {
    var query = baseQuery(account: account, service: target.service)
    query[kSecMatchSearchList as String] = [target.keychain]
    return query
}

let arguments = CommandLine.arguments
guard arguments.count >= 3 else { fail("missing operation or credential kind") }
let operation = arguments[1]
let account = arguments[2]
guard account == "access-token" || account == "nordlynx-private-key" else {
    fail("invalid credential kind")
}
private let target = validationTarget(arguments)
private let query = searchQuery(account: account, target: target)

switch operation {
case "create":
    let secret = FileHandle.standardInput.readDataToEndOfFile()
    guard !secret.isEmpty, secret.count <= 4096 else { fail("invalid secret length") }
    var add = baseQuery(account: account, service: target.service)
    add[kSecUseKeychain as String] = target.keychain
    add[kSecValueData as String] = secret
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { fail("create failed: \(status)") }
case "replace":
    let secret = FileHandle.standardInput.readDataToEndOfFile()
    guard !secret.isEmpty, secret.count <= 4096 else { fail("invalid secret length") }
    let update = [kSecValueData as String: secret] as CFDictionary
    let status = SecItemUpdate(query as CFDictionary, update)
    guard status == errSecSuccess else { fail("replace failed: \(status)") }
case "put":
    let secret = FileHandle.standardInput.readDataToEndOfFile()
    guard !secret.isEmpty, secret.count <= 4096 else { fail("invalid secret length") }
    let update = [kSecValueData as String: secret] as CFDictionary
    var status = SecItemUpdate(query as CFDictionary, update)
    if status == errSecItemNotFound {
        var add = baseQuery(account: account, service: target.service)
        add[kSecUseKeychain as String] = target.keychain
        add[kSecValueData as String] = secret
        status = SecItemAdd(add as CFDictionary, nil)
    }
    guard status == errSecSuccess else { fail("put failed: \(status)") }
case "get":
    var find = query
    find[kSecReturnData as String] = true
    find[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(find as CFDictionary, &result)
    if status == errSecItemNotFound { exit(44) }
    guard status == errSecSuccess, let data = result as? Data, !data.isEmpty else {
        fail("get failed: \(status)")
    }
    FileHandle.standardOutput.write(data)
case "delete":
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecItemNotFound { exit(44) }
    guard status == errSecSuccess else { fail("delete failed: \(status)") }
default:
    fail("invalid operation")
}
