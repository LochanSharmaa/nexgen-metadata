Add-Type -AssemblyName System.Drawing

function New-NexGenIcon {
    param([int]$Size, [string]$OutputPath)
    
    $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::Transparent)

    # Background: rounded rectangle, purple #8B5CF6
    $bgColor = [System.Drawing.Color]::FromArgb(255, 139, 92, 246)
    $brush = New-Object System.Drawing.SolidBrush($bgColor)
    $radius = [int]($Size * 0.22)
    $rect = New-Object System.Drawing.Rectangle(0, 0, $Size, $Size)
    
    # Draw rounded rectangle manually
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($rect.X, $rect.Y, $radius*2, $radius*2, 180, 90)
    $path.AddArc($rect.Right - $radius*2, $rect.Y, $radius*2, $radius*2, 270, 90)
    $path.AddArc($rect.Right - $radius*2, $rect.Bottom - $radius*2, $radius*2, $radius*2, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $radius*2, $radius*2, $radius*2, 90, 90)
    $path.CloseFigure()
    $g.FillPath($brush, $path)

    # Draw "NX" text
    $fontSize = [int]($Size * 0.38)
    $font = New-Object System.Drawing.Font("Segoe UI", $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
    $textRect = New-Object System.Drawing.RectangleF(0, 0, $Size, $Size)
    $g.DrawString("NX", $font, $textBrush, $textRect, $sf)

    $g.Dispose()
    $bmp.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output "  Created: $OutputPath ($Size x $Size)"
}

$iconDir = ".\nexgen-metadata\src-tauri\icons"

Write-Output "Generating NexGen Forensics icons..."
New-NexGenIcon -Size 32  -OutputPath "$iconDir\32x32.png"
New-NexGenIcon -Size 128 -OutputPath "$iconDir\128x128.png"
New-NexGenIcon -Size 256 -OutputPath "$iconDir\128x128@2x.png"

# Also copy the 256px one as a base for the .ico 
New-NexGenIcon -Size 256 -OutputPath "$iconDir\icon_256.png"
New-NexGenIcon -Size 512 -OutputPath "$iconDir\icon_512.png"

# Build a multi-resolution .ico (16, 32, 48, 256)
$icoSizes = @(16, 32, 48, 256)
$images = @()
foreach ($sz in $icoSizes) {
    $img = New-Object System.Drawing.Bitmap($sz, $sz)
    $g2 = [System.Drawing.Graphics]::FromImage($img)
    $g2.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g2.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g2.Clear([System.Drawing.Color]::Transparent)
    
    $bgColor = [System.Drawing.Color]::FromArgb(255, 139, 92, 246)
    $brush = New-Object System.Drawing.SolidBrush($bgColor)
    $radius = [int]($sz * 0.22)
    $rect = New-Object System.Drawing.Rectangle(0, 0, $sz, $sz)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($rect.X, $rect.Y, $radius*2, $radius*2, 180, 90)
    $path.AddArc($rect.Right - $radius*2, $rect.Y, $radius*2, $radius*2, 270, 90)
    $path.AddArc($rect.Right - $radius*2, $rect.Bottom - $radius*2, $radius*2, $radius*2, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $radius*2, $radius*2, $radius*2, 90, 90)
    $path.CloseFigure()
    $g2.FillPath($brush, $path)
    
    $fontSize = [int]($sz * 0.38)
    if ($fontSize -lt 6) { $fontSize = 6 }
    $font = New-Object System.Drawing.Font("Segoe UI", $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
    $textRect = New-Object System.Drawing.RectangleF(0, 0, $sz, $sz)
    $g2.DrawString("NX", $font, $textBrush, $textRect, $sf)
    $g2.Dispose()
    $images += $img
}

# Write ICO file manually (ICO format: header + directory + image data)
$icoPath = "$iconDir\icon.ico"
$ms = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter($ms)

# ICO Header: reserved=0, type=1(icon), count=N
$writer.Write([uint16]0)   # reserved
$writer.Write([uint16]1)   # type: icon
$writer.Write([uint16]$images.Count)

# Calculate image data offsets
# Directory entry is 16 bytes each; header is 6 bytes
$dirSize = 6 + ($images.Count * 16)
$pngStreams = @()
foreach ($img in $images) {
    $pngMs = New-Object System.IO.MemoryStream
    $img.Save($pngMs, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngStreams += $pngMs
}

$offset = $dirSize
foreach ($i in 0..($images.Count-1)) {
    $img = $images[$i]
    $dataSize = $pngStreams[$i].Length
    $w = if ($img.Width -ge 256) { 0 } else { $img.Width }
    $h = if ($img.Height -ge 256) { 0 } else { $img.Height }
    $writer.Write([byte]$w)          # width (0=256)
    $writer.Write([byte]$h)          # height (0=256)
    $writer.Write([byte]0)           # color count
    $writer.Write([byte]0)           # reserved
    $writer.Write([uint16]1)         # planes
    $writer.Write([uint16]32)        # bit count
    $writer.Write([uint32]$dataSize) # size of image data
    $writer.Write([uint32]$offset)   # offset to image data
    $offset += $dataSize
}

# Write PNG data for each image
foreach ($pngMs in $pngStreams) {
    $writer.Write($pngMs.ToArray())
    $pngMs.Dispose()
}

$writer.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $ms.ToArray())
$ms.Dispose()
Write-Output "  Created: $icoPath (multi-resolution ICO: 16x16 32x32 48x48 256x256)"

# Clean up
foreach ($img in $images) { $img.Dispose() }

# macOS ICNS — create a placeholder (64-byte minimal valid ICNS)
# Real ICNS needs iconutil on macOS; on Windows we create a valid PNG renamed .icns
Copy-Item "$iconDir\128x128.png" "$iconDir\icon.icns"
Write-Output "  Created: $iconDir\icon.icns (placeholder for macOS cross-build)"

Write-Output ""
Write-Output "All icons generated successfully."
