import LocalAuthentication

/// Gates a security-relevant action behind Touch ID or the device password.
/// Used to keep rule enable/disable from being a silent, unauthenticated
/// toggle a LOLBin-style attacker could flip to blind detection.
enum RuleAuthenticator {
    static func authenticate(reason: String, completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            DiagnosticsLog.write("rule-auth: unavailable (\(error?.localizedDescription ?? "no biometry/password set"))")
            completion(false)
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalError in
            DispatchQueue.main.async {
                if !success, let evalError {
                    DiagnosticsLog.write("rule-auth: failed (\(evalError.localizedDescription))")
                }
                completion(success)
            }
        }
    }
}
