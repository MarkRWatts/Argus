import SwiftUI

/// Rolling 5-minute histogram of matched-rule volume, bucketed into 5s slots.
struct SparklineView: View {
    let activityLog: [(Date, Int)]
    let accent: Color

    private let windowSeconds: Double = 300
    private let bucketSeconds: Double = 5

    private var buckets: [Double] {
        let bucketCount = Int(windowSeconds / bucketSeconds)
        var result = [Double](repeating: 0, count: bucketCount)
        let now = Date()
        for (date, count) in activityLog {
            let age = now.timeIntervalSince(date)
            guard age >= 0, age <= windowSeconds else { continue }
            let idx = bucketCount - 1 - Int(age / bucketSeconds)
            guard idx >= 0, idx < bucketCount else { continue }
            result[idx] += Double(count)
        }
        return result
    }

    var body: some View {
        GeometryReader { geo in
            let data = buckets
            let maxVal = max(1, data.max() ?? 1)
            let w = geo.size.width
            let h = geo.size.height
            let stepX = w / CGFloat(max(1, data.count - 1))

            ZStack(alignment: .topLeading) {
                // faint grid
                Path { path in
                    for i in 0...3 {
                        let y = h * CGFloat(i) / 3
                        path.move(to: CGPoint(x: 0, y: y))
                        path.addLine(to: CGPoint(x: w, y: y))
                    }
                }
                .stroke(Theme.border.opacity(0.5), lineWidth: 0.5)

                let points: [CGPoint] = data.enumerated().map { i, v in
                    CGPoint(x: CGFloat(i) * stepX, y: h - (CGFloat(v) / CGFloat(maxVal)) * (h - 4) - 2)
                }

                if points.count > 1 {
                    Path { path in
                        path.move(to: CGPoint(x: points[0].x, y: h))
                        path.addLines(points)
                        path.addLine(to: CGPoint(x: points.last!.x, y: h))
                        path.closeSubpath()
                    }
                    .fill(
                        LinearGradient(colors: [accent.opacity(0.35), accent.opacity(0.02)],
                                       startPoint: .top, endPoint: .bottom)
                    )

                    Path { path in
                        path.addLines(points)
                    }
                    .stroke(accent.opacity(0.85), style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round))

                    if let last = points.last, (data.last ?? 0) > 0 {
                        Circle()
                            .fill(accent)
                            .frame(width: 5, height: 5)
                            .shadow(color: accent.opacity(0.8), radius: 3)
                            .position(last)
                    }
                }
            }
        }
    }
}
