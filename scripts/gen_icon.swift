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

// ── 1. Background gradient (deep space: midnight blue → indigo) ──────────
let bgColors = [
    CGColor(red: 0.04, green: 0.06, blue: 0.18, alpha: 1),
    CGColor(red: 0.09, green: 0.05, blue: 0.28, alpha: 1),
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

// ── 2. Subtle radial glow behind the orb ────────────────────────────────
let glowColors = [
    CGColor(red: 0.20, green: 0.45, blue: 1.0, alpha: 0.35),
    CGColor(red: 0.10, green: 0.20, blue: 0.80, alpha: 0.0),
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

// ── 3. Frosted glass orb ─────────────────────────────────────────────────
let orbR: CGFloat = 340
let orbRect = CGRect(x: mid - orbR, y: mid - orbR, width: orbR*2, height: orbR*2)

// base fill (semi-transparent white)
cg.saveGState()
cg.addEllipse(in: orbRect)
cg.clip()

let orbBg = [
    CGColor(red: 0.55, green: 0.72, blue: 1.0, alpha: 0.18),
    CGColor(red: 0.30, green: 0.50, blue: 0.95, alpha: 0.28),
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

// glass stroke (thin ring)
cg.addEllipse(in: orbRect.insetBy(dx: 1, dy: 1))
cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.30))
cg.setLineWidth(2)
cg.strokePath()

// ── 4. Network pulse / radar glyph ───────────────────────────────────────
// Three concentric arcs (top-right quarter, expanding) — radar/signal style
cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.90))
cg.setLineCap(.round)

let arcRadii: [CGFloat] = [90, 170, 250]
let arcLineWidths: [CGFloat] = [18, 14, 10]
let arcAlphas: [CGFloat] = [1.0, 0.75, 0.50]

for (i, r) in arcRadii.enumerated() {
    cg.saveGState()
    cg.setLineWidth(arcLineWidths[i])
    cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: arcAlphas[i]))
    // arc: from 225° to 315° (bottom-ish, sweeping left to right through top)
    // Let's do a bottom-center pointing arc: 210°–330° = signal radiating up
    let startAngle = CGFloat.pi * 1.17   // ~210°
    let endAngle   = CGFloat.pi * 1.83   // ~330°
    cg.addArc(center: CGPoint(x: mid, y: mid - 40),
              radius: r,
              startAngle: startAngle,
              endAngle: endAngle,
              clockwise: false)
    cg.strokePath()
    cg.restoreGState()
}

// Center dot
cg.addEllipse(in: CGRect(x: mid - 22, y: mid - 62, width: 44, height: 44))
cg.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
cg.fillPath()

// ── 5. Specular highlight (top-left lens flare) ──────────────────────────
cg.saveGState()
cg.addEllipse(in: orbRect)
cg.clip()

let hlColors = [
    CGColor(red: 1, green: 1, blue: 1, alpha: 0.55),
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
    endRadius: orbR * 0.52,
    options: [])
cg.restoreGState()

// Thin bright crescent highlight at top-left rim
cg.saveGState()
let hlEllipseOuter = orbRect.insetBy(dx: 8, dy: 8)
let hlEllipseInner = orbRect.insetBy(dx: 45, dy: 45).offsetBy(dx: 20, dy: -20)
let hlPath = CGMutablePath()
hlPath.addEllipse(in: hlEllipseOuter)
hlPath.addEllipse(in: hlEllipseInner)
cg.addPath(hlPath)
cg.clip(using: .evenOdd)
let crescentColors = [
    CGColor(red: 1, green: 1, blue: 1, alpha: 0.60),
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

// ── 6. Vignette ───────────────────────────────────────────────────────────
let vigColors = [
    CGColor(red: 0, green: 0, blue: 0, alpha: 0.0),
    CGColor(red: 0, green: 0, blue: 0, alpha: 0.45),
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
let outPath = "/Users/greywizard/Claude/Code/network-traffic-monitor/ios/NTMDashboard/NTMDashboard/Resources/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png"
let pngData = bitmapRep.representation(using: .png, properties: [:])!
try! pngData.write(to: URL(fileURLWithPath: outPath))
print("Icon written to \(outPath) (\(pngData.count / 1024) KB)")
