import SwiftUI

/// The centerpiece visualization: newly-observed processes launch from a central
/// "kernel" node and drift outward into orbit, fading as they age out. Severity
/// sets color and size; a process whose parent is still visible in the ring gets
/// a connecting arc drawn to it, so a whole attack chain visibly clusters instead
/// of reading as disconnected log lines.
struct OrbitView: View {
    let nodes: [OrbitNode]
    let riskLevel: Severity
    let reduceMotion: Bool

    private let lifespan: Double = 14

    var body: some View {
        TimelineView(.animation(minimumInterval: reduceMotion ? 0.5 : 1.0 / 30.0)) { timeline in
            Canvas { context, size in
                let center = CGPoint(x: size.width / 2, y: size.height / 2)
                let maxRadius = min(size.width, size.height) / 2 * 0.92
                let now = timeline.date

                drawRings(context: &context, center: center, maxRadius: maxRadius)
                drawKernel(context: &context, center: center, now: now)

                var positions: [Int32: CGPoint] = [:]
                for node in nodes {
                    let age = max(0, now.timeIntervalSince(node.bornAt))
                    let t = min(1, age / lifespan)
                    let radius = 26 + (maxRadius - 26) * easeOut(t)
                    let swirl = reduceMotion ? 0.0 : age * 4.0
                    let angle = (node.angle + swirl) * .pi / 180
                    let p = CGPoint(x: center.x + radius * cos(angle), y: center.y + radius * sin(angle))
                    positions[node.pid] = p
                }

                // Parent → child arcs first, so dots draw on top.
                for node in nodes {
                    guard let p = positions[node.pid], let parentP = positions[node.ppid] else { continue }
                    var path = Path()
                    path.move(to: parentP)
                    path.addLine(to: p)
                    context.stroke(path, with: .color(Theme.color(for: node.severity).opacity(0.35)), lineWidth: 1)
                }

                for node in nodes {
                    guard let p = positions[node.pid] else { continue }
                    let age = max(0, now.timeIntervalSince(node.bornAt))
                    let t = min(1, age / lifespan)
                    let fadeIn = min(1, age / 0.35)
                    let fadeOut = t > 0.75 ? max(0, 1 - (t - 0.75) / 0.25) : 1
                    let opacity = fadeIn * fadeOut
                    let isBenign = node.severity == .info
                    let baseSize: CGFloat = isBenign ? 3.5 : (7 + CGFloat(node.severity.rawValue) * 2)
                    let color = Theme.color(for: node.severity)

                    if !isBenign {
                        let glowRect = CGRect(x: p.x - baseSize, y: p.y - baseSize, width: baseSize * 2, height: baseSize * 2)
                        context.fill(Path(ellipseIn: glowRect), with: .color(color.opacity(0.25 * opacity)))
                    }
                    let dotRect = CGRect(x: p.x - baseSize / 2, y: p.y - baseSize / 2, width: baseSize, height: baseSize)
                    context.fill(Path(ellipseIn: dotRect), with: .color(color.opacity(opacity)))
                }
            }
        }
    }

    private func easeOut(_ t: Double) -> Double {
        1 - pow(1 - t, 2)
    }

    private func drawRings(context: inout GraphicsContext, center: CGPoint, maxRadius: CGFloat) {
        for fraction in [0.35, 0.62, 0.92] {
            let r = maxRadius * fraction
            let rect = CGRect(x: center.x - r, y: center.y - r, width: r * 2, height: r * 2)
            context.stroke(Path(ellipseIn: rect), with: .color(Theme.border.opacity(0.6)), lineWidth: 1)
        }
    }

    private func drawKernel(context: inout GraphicsContext, center: CGPoint, now: Date) {
        let pulse = reduceMotion ? 0.5 : (sin(now.timeIntervalSinceReferenceDate * 2.2) + 1) / 2
        let color = Theme.color(for: riskLevel)
        let coreRadius: CGFloat = 9
        let glowRadius = coreRadius + CGFloat(6 + pulse * 6)

        let glowRect = CGRect(x: center.x - glowRadius, y: center.y - glowRadius, width: glowRadius * 2, height: glowRadius * 2)
        context.fill(Path(ellipseIn: glowRect), with: .color(color.opacity(0.22)))

        let coreRect = CGRect(x: center.x - coreRadius, y: center.y - coreRadius, width: coreRadius * 2, height: coreRadius * 2)
        context.fill(Path(ellipseIn: coreRect), with: .color(color))
        context.stroke(Path(ellipseIn: coreRect), with: .color(Theme.bg), lineWidth: 2)
    }
}
