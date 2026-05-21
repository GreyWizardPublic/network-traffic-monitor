#!/usr/bin/swift
import AppKit
import CoreGraphics

let size: CGFloat = 1024
let mid = size / 2

let bitmapRep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(size), pixelsHigh: Int(size),
    bitsPerSample: 8, samplesPerPixel: 4,
    hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0, bitsPerPixel: 0
)!

NSGraphicsContext.saveGraphicsState()
let ctx = NSGraphicsContext(bitmapImageRep: bitmapRep)!
NSGraphicsContext.current = ctx
let cg = ctx.cgContext

// ── 1. Background gradient (ocean teal → deep teal-blue) ─────────────────
let bgColors = [
    CGColor(red: 0.10, green: 0.32, blue: 0.58, alpha: 1),
    CGColor(red: 0.05, green: 0.18, blue: 0.44, alpha: 1),
]
let bgGrad = CGGradient(
    colorsSpace: CGColorSpaceCreateDeviceRGB(),
    colors: bgColors as CFArray,
    locations: [0, 1]
)!
cg.drawLinearGradient(bgGrad,
    start: CGPoint(x: 0, y: size),
    end: CGPoint(x: size, y: 0),
    options: [])

// ── 2. Radial glow behind the orb (cyan-teal) ────────────────────────────
let glowColors = [
    CGColor(red: 0.25, green: 0.78, blue: 0.92, alpha: 0.42),
    CGColor(red: 0.10, green: 0.45, blue: 0.75, alpha: 0.0),
]
let glowGrad = CGGradient(
    colorsSpace: CGColorSpaceCreateDeviceRGB(),
    colors: glowColors as CFArray,
    locations: [0, 1]
)!
cg.drawRadialGradient(glowGrad,
    startCenter: CGPoint(x: mid, y: mid), startRadius: 0,
    endCenter: CGPoint(x: mid, y: mid), endRadius: size * 0.54,
    options: [])

// ── 3. Thin frosted glass orb ─────────────────────────────────────────────
let orbR: CGFloat = 340
let orbRect = CGRect(x: mid - orbR, y: mid - orbR, width: orbR*2, height: orbR*2)

cg.saveGState()
cg.addEllipse(in: orbRect)
cg.clip()

// Near-clear fill — thin glass feel, slight teal tint
let orbBg = [
    CGColor(red: 1.0, green: 1.0, blue: 1.0, alpha: 0.06),
    CGColor(red: 0.70, green: 0.95, blue: 1.0, alpha: 0.22),
]
let orbBgGrad = CGGradient(
    colorsSpace: CGColorSpaceCreateDeviceRGB(),
    colors: orbBg as CFArray,
    locations: [0, 1]
)!
cg.drawRadialGradient(orbBgGrad,
    startCenter: CGPoint(x: mid - orbR*0.15, y: mid + orbR*0.15),
    startRadius: 0,
    endCenter: CGPoint(x: mid, y: mid),
    endRadius: orbR,
    options: [])
cg.restoreGState()

// Glass ring
cg.addEllipse(in: orbRect.insetBy(dx: 1, dy: 1))
cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.50))
cg.setLineWidth(2.5)
cg.strokePath()

// ── 4. Network node glyph (hexagon ring + 3-arm hub) ─────────────────────
// Outer hexagon: 6 vertices at radius hexR, connected edge-to-edge
let hexR: CGFloat = 230
let hexDotR: CGFloat = 20
let spokeDotR: CGFloat = 14

// Draw the 6 hexagon edges
cg.saveGState()
cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.72))
cg.setLineWidth(10)
cg.setLineCap(.round)
cg.setLineJoin(.round)
let hexPath = CGMutablePath()
for i in 0..<6 {
    let angle0 = CGFloat(i) * .pi / 3 - .pi / 6   // flat-top orientation
    let angle1 = CGFloat(i + 1) * .pi / 3 - .pi / 6
    let p0 = CGPoint(x: mid + hexR * cos(angle0), y: mid + hexR * sin(angle0))
    let p1 = CGPoint(x: mid + hexR * cos(angle1), y: mid + hexR * sin(angle1))
    if i == 0 { hexPath.move(to: p0) } else { hexPath.move(to: p0) }
    hexPath.addLine(to: p1)
}
cg.addPath(hexPath)
cg.strokePath()
cg.restoreGState()

// 3 internal spokes from center to alternating vertices (0°, 120°, 240°)
cg.saveGState()
cg.setLineWidth(10)
cg.setLineCap(.round)
for i in [0, 2, 4] {
    let angle = CGFloat(i) * .pi / 3 - .pi / 6
    let vx = mid + hexR * cos(angle)
    let vy = mid + hexR * sin(angle)
    let alpha: CGFloat = i == 0 ? 1.0 : (i == 2 ? 0.80 : 0.60)
    cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: alpha))
    cg.move(to: CGPoint(x: mid, y: mid))
    cg.addLine(to: CGPoint(x: vx, y: vy))
    cg.strokePath()
}
cg.restoreGState()

// 6 vertex dots on hexagon ring
for i in 0..<6 {
    let angle = CGFloat(i) * .pi / 3 - .pi / 6
    let vx = mid + hexR * cos(angle)
    let vy = mid + hexR * sin(angle)
    let spokeVertex = (i % 2 == 0)  // spoke-connected vertices are brighter
    let dotAlpha: CGFloat = spokeVertex ? 1.0 : 0.72
    cg.addEllipse(in: CGRect(x: vx - hexDotR, y: vy - hexDotR,
                              width: hexDotR*2, height: hexDotR*2))
    cg.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: dotAlpha))
    cg.fillPath()
}

// 3 midpoint dots on non-spoke edges (halfway along each non-spoke edge)
for i in [1, 3, 5] {
    let angle0 = CGFloat(i) * .pi / 3 - .pi / 6
    let angle1 = CGFloat(i + 1) * .pi / 3 - .pi / 6
    let mx = mid + hexR * (cos(angle0) + cos(angle1)) / 2
    let my = mid + hexR * (sin(angle0) + sin(angle1)) / 2
    cg.addEllipse(in: CGRect(x: mx - spokeDotR, y: my - spokeDotR,
                              width: spokeDotR*2, height: spokeDotR*2))
    cg.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.55))
    cg.fillPath()
}

// Center node (the client device)
let centerR: CGFloat = 34
cg.addEllipse(in: CGRect(x: mid - centerR, y: mid - centerR,
                          width: centerR*2, height: centerR*2))
cg.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
cg.fillPath()

// ── 5. Specular highlight ─────────────────────────────────────────────────
cg.saveGState()
cg.addEllipse(in: orbRect)
cg.clip()

let hlColors = [
    CGColor(red: 1, green: 1, blue: 1, alpha: 0.72),
    CGColor(red: 1, green: 1, blue: 1, alpha: 0.0),
]
let hlGrad = CGGradient(
    colorsSpace: CGColorSpaceCreateDeviceRGB(),
    colors: hlColors as CFArray,
    locations: [0, 1]
)!
cg.drawRadialGradient(hlGrad,
    startCenter: CGPoint(x: mid - orbR*0.38, y: mid + orbR*0.42),
    startRadius: 0,
    endCenter: CGPoint(x: mid - orbR*0.38, y: mid + orbR*0.42),
    endRadius: orbR * 0.48,
    options: [])
cg.restoreGState()

// Thin bright crescent at top-left rim
cg.saveGState()
let hlEllipseOuter = orbRect.insetBy(dx: 6, dy: 6)
let hlEllipseInner = orbRect.insetBy(dx: 38, dy: 38).offsetBy(dx: 22, dy: -22)
let hlPath = CGMutablePath()
hlPath.addEllipse(in: hlEllipseOuter)
hlPath.addEllipse(in: hlEllipseInner)
cg.addPath(hlPath)
cg.clip(using: .evenOdd)
let crescentColors = [
    CGColor(red: 1, green: 1, blue: 1, alpha: 0.72),
    CGColor(red: 1, green: 1, blue: 1, alpha: 0.0),
]
let crescentGrad = CGGradient(
    colorsSpace: CGColorSpaceCreateDeviceRGB(),
    colors: crescentColors as CFArray,
    locations: [0, 1]
)!
cg.drawLinearGradient(crescentGrad,
    start: CGPoint(x: mid - orbR*0.7, y: mid + orbR*0.7),
    end: CGPoint(x: mid, y: mid),
    options: [])
cg.restoreGState()

// ── 6. Soft vignette ──────────────────────────────────────────────────────
let vigColors = [
    CGColor(red: 0, green: 0, blue: 0, alpha: 0.0),
    CGColor(red: 0, green: 0, blue: 0, alpha: 0.28),
]
let vigGrad = CGGradient(
    colorsSpace: CGColorSpaceCreateDeviceRGB(),
    colors: vigColors as CFArray,
    locations: [0.55, 1]
)!
cg.drawRadialGradient(vigGrad,
    startCenter: CGPoint(x: mid, y: mid), startRadius: size * 0.38,
    endCenter: CGPoint(x: mid, y: mid), endRadius: size * 0.80,
    options: [.drawsAfterEndLocation])

NSGraphicsContext.restoreGraphicsState()

// ── Write PNG ─────────────────────────────────────────────────────────────
let outPath = "/Users/greywizard/Claude/Code/network-traffic-monitor/ios/NTMClient/NTMClient/Resources/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png"
let pngData = bitmapRep.representation(using: .png, properties: [:])!
try! pngData.write(to: URL(fileURLWithPath: outPath))
print("NTMClient icon written to \(outPath) (\(pngData.count / 1024) KB)")
