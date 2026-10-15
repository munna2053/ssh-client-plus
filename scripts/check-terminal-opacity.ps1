param([string]$Executable = (Join-Path $PSScriptRoot '..\target\slint\release\sentinel-ssh.exe'))

$ErrorActionPreference = 'Stop'
# Visual regression check: a disposable preview sits above our own white test window.
# Only one pixel inside the owned terminal is sampled; no screenshot is recorded.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
public static class TerminalOpacityProbe {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct Point { public int X, Y; }
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr CreateWindowExW(uint ex, string cls, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);
    [DllImport("user32.dll")] static extern bool DestroyWindow(IntPtr w);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr w, out Rect rect);
    [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr w, out Rect rect);
    [DllImport("user32.dll")] static extern bool ClientToScreen(IntPtr w, ref Point point);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr w, IntPtr after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")] static extern bool UpdateWindow(IntPtr w);
    [DllImport("user32.dll")] static extern bool RedrawWindow(IntPtr w, IntPtr rect, IntPtr region, uint flags);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string cls, string title);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr w);
    [DllImport("user32.dll")] static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr w);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr w, IntPtr dc);
    [DllImport("gdi32.dll")] static extern uint GetPixel(IntPtr dc, int x, int y);
    [DllImport("dwmapi.dll")] static extern int DwmFlush();
    public static string Check(IntPtr main) {
        IntPtr backdrop = IntPtr.Zero;
        IntPtr terminal = IntPtr.Zero;
        while ((terminal = FindWindowExW(main, terminal, "SentinelSSH.Terminal.v1", null)) != IntPtr.Zero) {
            if (IsWindowVisible(terminal)) break;
        }
        if (terminal == IntPtr.Zero) throw new Exception("No visible preview terminal");
        var previousDpi = SetThreadDpiAwarenessContext(new IntPtr(-4));
        try {
            Rect bounds; GetWindowRect(main, out bounds);
            SetWindowPos(main, new IntPtr(-1), 0, 0, 0, 0, 0x13);
            backdrop = CreateWindowExW(0x08000080, "STATIC", "Owned opacity-test backdrop", 0x80000006, bounds.Left, bounds.Top, bounds.Right-bounds.Left, bounds.Bottom-bounds.Top, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (backdrop == IntPtr.Zero) throw new Exception("Could not create test backdrop");
            SetWindowPos(backdrop, main, bounds.Left, bounds.Top, bounds.Right-bounds.Left, bounds.Bottom-bounds.Top, 0x50);
            UpdateWindow(backdrop);
            RedrawWindow(main, IntPtr.Zero, IntPtr.Zero, 0x181);
            Thread.Sleep(200);
            DwmFlush();
            Rect client; GetClientRect(terminal, out client);
            Point point = new Point { X=client.Right-5, Y=client.Bottom-5 };
            var childDc = GetDC(terminal);
            uint painted = GetPixel(childDc, point.X, point.Y);
            ReleaseDC(terminal, childDc);
            ClientToScreen(terminal, ref point);
            if (WindowFromPoint(point) != terminal) throw new Exception("Test sample is occluded or outside the terminal");
            var screenDc = GetDC(IntPtr.Zero);
            if (screenDc == IntPtr.Zero) throw new Exception("An interactive Windows desktop is required to check composited pixels");
            uint displayed = GetPixel(screenDc, point.X, point.Y);
            ReleaseDC(IntPtr.Zero, screenDc);
            if (displayed == UInt32.MaxValue) throw new Exception("Composited screen pixels are unavailable in this Windows session");
            if (painted != 0x18100B || displayed != painted) {
                throw new Exception(String.Format("Terminal opacity regression: painted {0:X6}, displayed {1:X6} over the white test backdrop", painted, displayed));
            }
            return String.Format("Opaque terminal verified: painted and displayed {0:X6} over the white test backdrop", displayed);
        } finally {
            if (backdrop != IntPtr.Zero) DestroyWindow(backdrop);
            SetWindowPos(main, new IntPtr(-2), 0, 0, 0, 0, 0x13);
            SetThreadDpiAwarenessContext(previousDpi);
        }
    }
}
'@
$previewExecutable = (Resolve-Path -LiteralPath $Executable).Path
$previewProcess = Start-Process -FilePath $previewExecutable -ArgumentList '--ui-preview' -WindowStyle Hidden -PassThru
try {
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        Start-Sleep -Milliseconds 100
        $previewProcess.Refresh()
        if ($previewProcess.MainWindowHandle -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 400
    [TerminalOpacityProbe]::Check($previewProcess.MainWindowHandle)
} finally {
    if (!$previewProcess.HasExited) { $previewProcess.Kill(); $previewProcess.WaitForExit() }
    $previewProcess.Dispose()
}
