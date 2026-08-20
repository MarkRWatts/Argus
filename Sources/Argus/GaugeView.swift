import SwiftUI

/// Arced risk meter — sweeps 0...100 across a 270° arc, colored by severity band.
struct GaugeView: View {
    let score: Double
    let level: Severity

    private let startAngle = Angle(degrees: 135)
    private let sweep = 270.0

    var body: some View {
        ZStack {
            Circle()
                .trim(from: 0, to: sweep / 360)
                .stroke(Theme.border, style: StrokeStyle(lineWidth: 10, lineCap: .round))
                .rotationEffect(startAngle)

            Circle()
                .trim(from: 0, to: (sweep / 360) * min(1, score / 100))
                .stroke(
                    AngularGradient(
                        colors: [Theme.color(for: .info), Theme.color(for: .watch), Theme.color(for: .elevated), Theme.color(for: .critical)],
                        center: .center,
                        startAngle: startAngle,
                        endAngle: .degrees(startAngle.degrees + sweep)
                    ),
                    style: StrokeStyle(lineWidth: 10, lineCap: .round)
                )
                .rotationEffect(startAngle)
                .shadow(color: Theme.color(for: level).opacity(0.5), radius: 6)
                .animation(.easeOut(duration: 0.6), value: score)

            VStack(spacing: 2) {
                Text("\(Int(score.rounded()))")
                    .font(Theme.mono(34, weight: .semibold))
                    .foregroundStyle(Theme.text)
                    .contentTransition(.numericText())
                    .animation(.easeOut(duration: 0.4), value: score)
                Text(level.label)
                    .font(Theme.mono(11, weight: .bold))
                    .tracking(1.5)
                    .foregroundStyle(Theme.color(for: level))
            }
        }
        .frame(width: 128, height: 128)
    }
}
