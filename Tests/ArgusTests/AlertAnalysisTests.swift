import XCTest
@testable import Argus

final class AlertAnalysisTests: XCTestCase {
    private func json(_ object: Any) -> Data {
        try! JSONSerialization.data(withJSONObject: object)
    }

    // MARK: - Request

    func testRequestBodyCarriesModelFallbackAndAlert() throws {
        let body = try AlertAnalysis.requestBody(
            eventJSON: #"{"command":"cat ~/.zsh_history"}"#,
            ruleSources: [(title: "Suspicious History File Operations", yaml: "title: Suspicious History File Operations")]
        )
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(decoded["model"] as? String, "claude-opus-5-5")
        XCTAssertEqual(decoded["fallbacks"] as? String, "default")
        XCTAssertEqual((decoded["output_config"] as? [String: Any])?["effort"] as? String, "high")
        XCTAssertNil(decoded["thinking"], "Opus 5.5 rejects disabled thinking; leave it adaptive by omission")

        let messages = try XCTUnwrap(decoded["messages"] as? [[String: Any]])
        let prompt = try XCTUnwrap(messages.first?["content"] as? String)
        XCTAssertTrue(prompt.contains("<alert>\n{\"command\":\"cat ~/.zsh_history\"}\n</alert>"))
        XCTAssertTrue(prompt.contains("<sigma_rule title=\"Suspicious History File Operations\">"))
    }

    func testPromptNotesMissingRuleSources() {
        let prompt = AlertAnalysis.userPrompt(eventJSON: "{}", ruleSources: [])
        XCTAssertTrue(prompt.contains("No Sigma source is available"))
    }

    func testURLRequestHeaders() {
        let body = Data(#"{"model":"claude-opus-5-5"}"#.utf8)
        let request = AlertAnalysis.urlRequest(body: body, apiKey: "sk-test")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.httpBody, body)
        XCTAssertEqual(request.url, AlertAnalysis.endpoint)
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-api-key"), "sk-test")
        XCTAssertEqual(request.value(forHTTPHeaderField: "anthropic-version"), "2023-06-01")
        XCTAssertEqual(request.value(forHTTPHeaderField: "anthropic-beta"), AlertAnalysis.fallbackBeta)
        XCTAssertGreaterThan(request.timeoutInterval, 60)
    }

    // MARK: - Response

    func testParseJoinsTextBlocksAndSkipsOthers() {
        let data = json([
            "stop_reason": "end_turn",
            "content": [
                ["type": "thinking", "thinking": ""],
                ["type": "text", "text": "Likely false positive."],
                ["type": "text", "text": "The match is `.history`."],
            ],
        ])
        XCTAssertEqual(AlertAnalysis.parse(status: 200, data: data),
                       .success("Likely false positive.\n\nThe match is `.history`."))
    }

    func testParseNotesTruncation() throws {
        let data = json(["stop_reason": "max_tokens", "content": [["type": "text", "text": "Partial"]]])
        let text = try AlertAnalysis.parse(status: 200, data: data).get()
        XCTAssertTrue(text.hasPrefix("Partial"))
        XCTAssertTrue(text.contains("cut off"))
    }

    func testParseRefusalIsCheckedBeforeContent() {
        let data = json([
            "stop_reason": "refusal",
            "stop_details": ["type": "refusal", "category": "cyber", "explanation": "Declined."],
            "content": [],
        ])
        XCTAssertEqual(AlertAnalysis.parse(status: 200, data: data), .failure(.refused("Declined.")))
    }

    func testParseAPIErrors() {
        let unauthorized = json(["type": "error", "error": ["type": "authentication_error", "message": "invalid x-api-key"]])
        guard case .failure(let failure) = AlertAnalysis.parse(status: 401, data: unauthorized) else {
            return XCTFail("expected failure")
        }
        XCTAssertTrue(failure.message.contains("API key was rejected"))

        let overloaded = json(["type": "error", "error": ["type": "overloaded_error", "message": "Overloaded"]])
        XCTAssertEqual(AlertAnalysis.parse(status: 529, data: overloaded), .failure(.api(status: 529, message: "Overloaded")))
        XCTAssertEqual(AlertAnalysis.parse(status: 502, data: Data("<html>".utf8)), .failure(.api(status: 502, message: "HTTP 502")))
    }

    func testParseMalformedSuccess() {
        XCTAssertEqual(AlertAnalysis.parse(status: 200, data: Data("nope".utf8)), .failure(.malformed))
        XCTAssertEqual(AlertAnalysis.parse(status: 200, data: json(["stop_reason": "end_turn", "content": []])), .failure(.malformed))
    }
}
