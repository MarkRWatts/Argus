import SwiftUI
import AppKit

/// Reports whether the `NSWindow` hosting this view is actually on screen.
///
/// SwiftUI keeps a hidden window's view graph alive: the dashboard after it's
/// closed (Argus hides rather than destroys it) and the menu-bar flyout after
/// `orderOut(nil)` both keep re-evaluating bodies, running `TimelineView`
/// ticks and committing Core Animation frames on every `ProcessMonitor`
/// publish — measured at ~25–50% CPU with neither window visible. Views use
/// this to swap in a placeholder while hidden so nothing renders for nobody.
///
/// Driven by `NSWindow.occlusionState`, which flips on `orderOut`, close,
/// minimize, and being fully covered by other windows alike.
struct WindowVisibilityReader: NSViewRepresentable {
    @Binding var isVisible: Bool

    func makeNSView(context: Context) -> TrackingView {
        let view = TrackingView()
        view.onChange = { visible in
            if isVisible != visible { isVisible = visible }
        }
        return view
    }

    func updateNSView(_ nsView: TrackingView, context: Context) {}

    final class TrackingView: NSView {
        var onChange: ((Bool) -> Void)?
        private var observer: NSObjectProtocol?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let observer { NotificationCenter.default.removeObserver(observer) }
            observer = nil
            guard let window else { return }
            observer = NotificationCenter.default.addObserver(
                forName: NSWindow.didChangeOcclusionStateNotification, object: window, queue: .main
            ) { [weak self] _ in
                self?.report()
            }
            report()
        }

        private func report() {
            guard let window else { return }
            let visible = window.occlusionState.contains(.visible)
            // Deferred: this can fire mid view-update, where mutating
            // SwiftUI state directly is undefined behavior.
            DispatchQueue.main.async { [weak self] in self?.onChange?(visible) }
        }

        deinit {
            if let observer { NotificationCenter.default.removeObserver(observer) }
        }
    }
}

extension View {
    /// Renders `self` only while the hosting window is on screen; otherwise
    /// an empty placeholder of the same frame, so a hidden window stops
    /// laying out, animating, and drawing entirely.
    func renderedOnlyWhenVisible(_ isVisible: Binding<Bool>) -> some View {
        ZStack {
            if isVisible.wrappedValue {
                self
            } else {
                Color.clear
            }
        }
        .background(WindowVisibilityReader(isVisible: isVisible))
    }
}
