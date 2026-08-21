import Foundation

/// Hand-rolled indentation-based parser for the block-style YAML subset
/// Sigma rule files use in practice. Deliberately narrow in scope — see
/// YAMLValue's doc comment — but handles the real constructs found in
/// SigmaHQ's macOS and Linux process_creation rule sets: nested block
/// mappings/sequences, sequences of mappings (`- key: value` with
/// continuation keys aligned two spaces in), quoted and unquoted scalars,
/// and trailing `# comment`s stripped outside of quotes.
enum YAMLParser {
    struct Line {
        let indent: Int
        let text: String // content after indent, with any trailing comment already stripped
    }

    static func parseDocuments(_ raw: String) -> [YAMLValue] {
        parseDocumentsWithSource(raw).map(\.value)
    }

    /// Same as `parseDocuments`, but pairs each parsed value with its own
    /// slice of the original text — needed so a multi-rule file can still
    /// show each individual rule's real source in a "view raw YAML" UI,
    /// not the whole batch.
    static func parseDocumentsWithSource(_ raw: String) -> [(text: String, value: YAMLValue)] {
        // Sigma allows multiple rules per file, separated by a `---` line.
        let chunks = raw
            .components(separatedBy: "\n")
            .reduce(into: [[String]]()) { chunks, line in
                if line.trimmingCharacters(in: .whitespaces) == "---" {
                    chunks.append([])
                } else {
                    if chunks.isEmpty { chunks.append([]) }
                    chunks[chunks.count - 1].append(line)
                }
            }

        return chunks.compactMap { chunkLines -> (text: String, value: YAMLValue)? in
            let text = chunkLines.joined(separator: "\n")
            let lines = tokenize(text)
            guard !lines.isEmpty else { return nil }
            var pos = 0
            let value = parseNode(lines, &pos, indent: lines[0].indent)
            return (text.trimmingCharacters(in: .whitespacesAndNewlines), value)
        }
    }

    // MARK: - Tokenizing

    private static func tokenize(_ raw: String) -> [Line] {
        var lines: [Line] = []
        for rawLine in raw.components(separatedBy: "\n") {
            guard let firstNonSpace = rawLine.firstIndex(where: { $0 != " " }) else { continue } // blank line
            let indent = rawLine.distance(from: rawLine.startIndex, to: firstNonSpace)
            var content = String(rawLine[firstNonSpace...])
            if content.hasPrefix("#") { continue } // full-line comment
            content = stripTrailingComment(content)
            content = content.trimmingCharacters(in: .whitespaces)
            guard !content.isEmpty else { continue }
            lines.append(Line(indent: indent, text: content))
        }
        return lines
    }

    /// Strips a `# ...` comment that isn't inside a quoted scalar.
    private static func stripTrailingComment(_ s: String) -> String {
        var inSingle = false
        var inDouble = false
        var result = ""
        var previousWasSpace = true
        for ch in s {
            if ch == "'" && !inDouble { inSingle.toggle() }
            else if ch == "\"" && !inSingle { inDouble.toggle() }
            else if ch == "#" && !inSingle && !inDouble && previousWasSpace {
                break
            }
            result.append(ch)
            previousWasSpace = (ch == " ")
        }
        return result
    }

    // MARK: - Parsing

    private static func parseNode(_ lines: [Line], _ pos: inout Int, indent: Int) -> YAMLValue {
        guard pos < lines.count, lines[pos].indent == indent else { return .scalar("") }
        if isSequenceLine(lines[pos].text) {
            return parseSequence(lines, &pos, indent: indent)
        }
        return parseMapping(lines, &pos, indent: indent)
    }

    private static func isSequenceLine(_ text: String) -> Bool {
        text == "-" || text.hasPrefix("- ")
    }

    private static func parseSequence(_ lines: [Line], _ pos: inout Int, indent: Int) -> YAMLValue {
        var items: [YAMLValue] = []
        while pos < lines.count, lines[pos].indent == indent, isSequenceLine(lines[pos].text) {
            let text = lines[pos].text
            let rest = text == "-" ? "" : String(text.dropFirst(2))
            pos += 1

            if rest.isEmpty {
                if pos < lines.count, lines[pos].indent > indent {
                    items.append(parseNode(lines, &pos, indent: lines[pos].indent))
                } else {
                    items.append(.scalar(""))
                }
            } else if let (key, value) = splitKeyValue(rest) {
                // "- key: value" — an inline mapping; continuation keys are
                // conventionally aligned two spaces past the dash.
                items.append(parseInlineMapping(lines, &pos, firstKey: key, firstValue: value, continuationIndent: indent + 2))
            } else {
                items.append(.scalar(unquote(rest)))
            }
        }
        return .sequence(items)
    }

    private static func parseInlineMapping(
        _ lines: [Line], _ pos: inout Int,
        firstKey: String, firstValue: String?, continuationIndent: Int
    ) -> YAMLValue {
        var pairs: [YAMLPair] = []
        pairs.append(YAMLPair(key: firstKey, value: resolveValue(lines, &pos, inlineValue: firstValue, blockIndentMinimum: continuationIndent)))

        while pos < lines.count, lines[pos].indent == continuationIndent, !isSequenceLine(lines[pos].text),
              let (key, value) = splitKeyValue(lines[pos].text) {
            pos += 1
            pairs.append(YAMLPair(key: key, value: resolveValue(lines, &pos, inlineValue: value, blockIndentMinimum: continuationIndent)))
        }
        return .mapping(pairs)
    }

    private static func parseMapping(_ lines: [Line], _ pos: inout Int, indent: Int) -> YAMLValue {
        var pairs: [YAMLPair] = []
        while pos < lines.count, lines[pos].indent == indent, !isSequenceLine(lines[pos].text),
              let (key, value) = splitKeyValue(lines[pos].text) {
            pos += 1
            pairs.append(YAMLPair(key: key, value: resolveValue(lines, &pos, inlineValue: value, blockIndentMinimum: indent + 1)))
        }
        return .mapping(pairs)
    }

    /// Given a key's inline value text (nil/empty means "value is a nested
    /// block on following lines"), returns the resolved YAMLValue.
    private static func resolveValue(_ lines: [Line], _ pos: inout Int, inlineValue: String?, blockIndentMinimum: Int) -> YAMLValue {
        if let inlineValue, isBlockScalarIndicator(inlineValue) {
            return .scalar(consumeBlockScalar(lines, &pos, minIndent: blockIndentMinimum))
        }
        if let inlineValue, !inlineValue.isEmpty {
            return .scalar(unquote(inlineValue))
        }
        if pos < lines.count, lines[pos].indent >= blockIndentMinimum {
            return parseNode(lines, &pos, indent: lines[pos].indent)
        }
        return .scalar("")
    }

    /// `|`, `|-`, `|+`, `>`, `>-`, `>+` — literal/folded block scalar
    /// headers. We don't distinguish literal-vs-folded newline handling
    /// (both are joined with spaces here); good enough since every field
    /// that uses this in practice is free-form prose (description, etc.),
    /// never something Argus parses structurally.
    private static func isBlockScalarIndicator(_ s: String) -> Bool {
        ["|", "|-", "|+", ">", ">-", ">+"].contains(s)
    }

    private static func consumeBlockScalar(_ lines: [Line], _ pos: inout Int, minIndent: Int) -> String {
        var parts: [String] = []
        while pos < lines.count, lines[pos].indent >= minIndent {
            parts.append(lines[pos].text)
            pos += 1
        }
        return parts.joined(separator: " ")
    }

    /// Splits `key: value` (or `key:` with nil value) on the first
    /// unquoted `": "` or a trailing unquoted `:`. Returns nil if the line
    /// isn't a key line at all (shouldn't happen for well-formed Sigma).
    private static func splitKeyValue(_ text: String) -> (key: String, value: String?)? {
        var inSingle = false
        var inDouble = false
        let chars = Array(text)
        var i = 0
        while i < chars.count {
            let ch = chars[i]
            if ch == "'" && !inDouble { inSingle.toggle() }
            else if ch == "\"" && !inSingle { inDouble.toggle() }
            else if ch == ":" && !inSingle && !inDouble {
                let isEnd = i == chars.count - 1
                let isSpaceAfter = !isEnd && chars[i + 1] == " "
                if isEnd || isSpaceAfter {
                    let key = String(chars[0..<i]).trimmingCharacters(in: .whitespaces)
                    let valueStart = isEnd ? i + 1 : i + 2
                    let value = valueStart <= chars.count
                        ? String(chars[valueStart...]).trimmingCharacters(in: .whitespaces)
                        : ""
                    return (key, value.isEmpty ? nil : value)
                }
            }
            i += 1
        }
        return nil
    }

    private static func unquote(_ s: String) -> String {
        if s.count >= 2, s.hasPrefix("'"), s.hasSuffix("'") {
            let inner = String(s.dropFirst().dropLast())
            return inner.replacingOccurrences(of: "''", with: "'")
        }
        if s.count >= 2, s.hasPrefix("\""), s.hasSuffix("\"") {
            let inner = String(s.dropFirst().dropLast())
            return inner
                .replacingOccurrences(of: "\\\"", with: "\"")
                .replacingOccurrences(of: "\\\\", with: "\\")
        }
        return s
    }
}
