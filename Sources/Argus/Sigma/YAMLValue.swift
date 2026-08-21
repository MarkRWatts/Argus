import Foundation

/// A minimal YAML document tree — just enough to represent what Sigma rule
/// files actually use (block mappings, block sequences, scalars). Not a
/// general-purpose YAML 1.2 implementation: no anchors/aliases, no flow
/// style (`{a: b}` / `[a, b]`), no multi-line block scalars (`|`/`>`).
/// Every construct here was verified against real files fetched from
/// SigmaHQ/sigma before being added — see YAMLParserTests.
/// A single mapping entry. A named struct rather than an anonymous labeled
/// tuple — an indirect enum recursing through `[(key: String, value: Self)]`
/// tuple arrays reproducibly triggers a Swift compiler "circular reference"
/// false positive once enough files in the module reference the type; a
/// named struct payload doesn't.
struct YAMLPair {
    let key: String
    let value: YAMLValue
}

indirect enum YAMLValue {
    case scalar(String)
    case sequence([YAMLValue])
    case mapping([YAMLPair])

    var stringValue: String? {
        if case .scalar(let s) = self { return s }
        return nil
    }

    var sequenceValue: [YAMLValue]? {
        if case .sequence(let s) = self { return s }
        return nil
    }

    var mappingValue: [YAMLPair]? {
        if case .mapping(let m) = self { return m }
        return nil
    }

    subscript(key: String) -> YAMLValue? {
        mappingValue?.first { $0.key == key }?.value
    }

    /// Flattens a value that's conventionally either a single scalar or a
    /// list of scalars into a `[String]` — the common Sigma idiom for
    /// "one value or several".
    var stringList: [String] {
        switch self {
        case .scalar(let s): return [s]
        case .sequence(let items): return items.compactMap(\.stringValue)
        case .mapping: return []
        }
    }
}
