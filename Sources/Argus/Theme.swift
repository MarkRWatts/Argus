import SwiftUI

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: alpha
        )
    }
}

enum Theme {
    static let bg = Color(hex: 0x0a0e14)
    static let surface = Color(hex: 0x10161f)
    static let surfaceRaised = Color(hex: 0x161d29)
    static let border = Color(hex: 0x1e2938)
    static let text = Color(hex: 0xe8eef4)
    static let muted = Color(hex: 0x7c8ba0)
    static let dim = Color(hex: 0x4a5768)
    static let accent = Color(hex: 0xff9d4d)
    /// Provenance ("via claude") chips. Deliberately violet — a hue the
    /// severity palette (green/yellow/amber/red) never uses, so an
    /// attribution chip can be prominent without ever being mistaken for a
    /// severity signal.
    static let provenance = Color(hex: 0xa98bfa)

    static func color(for severity: Severity) -> Color {
        switch severity {
        case .info: return Color(hex: 0x3ddc97)
        case .watch: return Color(hex: 0xffe066)
        case .elevated: return Color(hex: 0xffb84d)
        case .critical: return Color(hex: 0xff5c5c)
        }
    }

    static let mono = Font.system(.body, design: .monospaced)
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}
