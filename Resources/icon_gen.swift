import AppKit
import CoreGraphics

let size = 1024
let img = NSImage(size: NSSize(width: size, height: size))
img.lockFocus()
guard let ctx = NSGraphicsContext.current?.cgContext else { fatalError() }

func hex(_ h: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat((h >> 16) & 0xFF)/255, green: CGFloat((h >> 8) & 0xFF)/255, blue: CGFloat(h & 0xFF)/255, alpha: a)
}

let rect = CGRect(x: 0, y: 0, width: size, height: size)
let corner: CGFloat = CGFloat(size) * 0.225
let path = CGPath(roundedRect: rect, cornerWidth: corner, cornerHeight: corner, transform: nil)
ctx.addPath(path)
ctx.clip()

// Background vertical gradient: near-black slate down to a touch lighter.
let bgColors = [hex(0x0a0e14), hex(0x141c28)] as CFArray
let bgGradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: bgColors, locations: [0, 1])!
ctx.drawLinearGradient(bgGradient, start: CGPoint(x: 0, y: size), end: CGPoint(x: 0, y: 0), options: [])

let center = CGPoint(x: CGFloat(size) / 2, y: CGFloat(size) / 2)

// Faint orbit rings, echoing the in-app visualization.
ctx.setStrokeColor(hex(0x2a3646, 0.8))
for r in [190.0, 280.0, 370.0] {
    ctx.setLineWidth(3)
    ctx.strokeEllipse(in: CGRect(x: center.x - r, y: center.y - r, width: r * 2, height: r * 2))
}

// A few "orbiting" node dots for texture.
let nodeSpecs: [(CGFloat, CGFloat, CGFloat, CGColor)] = [
    (190, 40, 10, hex(0x3ddc97)),
    (280, 160, 8, hex(0xffb84d)),
    (280, 260, 14, hex(0xff5c5c)),
    (370, 300, 9, hex(0xffe066)),
    (190, 210, 8, hex(0x3ddc97)),
]
for (r, deg, dotR, color) in nodeSpecs {
    let rad = deg * .pi / 180
    let p = CGPoint(x: center.x + r * cos(rad), y: center.y + r * sin(rad))
    ctx.setFillColor(color.copy(alpha: 0.9)!)
    ctx.fillEllipse(in: CGRect(x: p.x - dotR, y: p.y - dotR, width: dotR * 2, height: dotR * 2))
}

// Vesica (eye) shape via two overlapping circular arcs.
let eyeWidth: CGFloat = 620
let eyeHeight: CGFloat = 300
let eyePath = CGMutablePath()
let leftPoint = CGPoint(x: center.x - eyeWidth / 2, y: center.y)
let rightPoint = CGPoint(x: center.x + eyeWidth / 2, y: center.y)
let archR = eyeWidth * 0.62
eyePath.move(to: leftPoint)
eyePath.addQuadCurve(to: rightPoint, control: CGPoint(x: center.x, y: center.y + eyeHeight / 2))
eyePath.addQuadCurve(to: leftPoint, control: CGPoint(x: center.x, y: center.y - eyeHeight / 2))
eyePath.closeSubpath()

ctx.saveGState()
ctx.addPath(eyePath)
ctx.setFillColor(hex(0x10161f))
ctx.setShadow(offset: .zero, blur: 40, color: hex(0xff9d4d, 0.35))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(eyePath)
ctx.setLineWidth(10)
ctx.setStrokeColor(hex(0xe8eef4, 0.9))
ctx.strokePath()
ctx.restoreGState()

// Glowing amber iris/pupil.
let irisR: CGFloat = 92
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 60, color: hex(0xff9d4d, 0.9))
let irisColors = [hex(0xffcf94), hex(0xff9d4d)] as CFArray
let irisGradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: irisColors, locations: [0, 1])!
ctx.drawRadialGradient(irisGradient, startCenter: center, startRadius: 0, endCenter: center, endRadius: irisR, options: [])
ctx.restoreGState()

let pupilR: CGFloat = 30
ctx.setFillColor(hex(0x0a0e14))
ctx.fillEllipse(in: CGRect(x: center.x - pupilR, y: center.y - pupilR, width: pupilR * 2, height: pupilR * 2))

img.unlockFocus()

guard let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    fatalError("png conversion failed")
}
let outPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon_1024.png"
try! png.write(to: URL(fileURLWithPath: outPath))
print("wrote \(outPath)")
