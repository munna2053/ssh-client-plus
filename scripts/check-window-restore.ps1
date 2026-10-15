param([string]$Executable = (Join-Path $PSScriptRoot '..\target\slint\release\sentinel-ssh.exe'))

$ErrorActionPreference = 'Stop'
# Inspect only a disposable preview's presented client pixels, without asking Slint
# to take a snapshot or invalidate the window (either would hide a repaint bug).
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Threading;
public static class WindowRestoreProbe {
    [StructLayout(LayoutKind.Sequential)] struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr window);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr window, IntPtr dc);
    [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string cls, string title);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")] static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr target, int x, int y, int width, int height, IntPtr source, int sourceX, int sourceY, uint flags);
    [DllImport("dwmapi.dll")] static extern int DwmFlush();

    static byte[] Pixels(IntPtr window, double logicalHeight) {
        Rect client;
        if (!GetClientRect(window, out client)) throw new Exception("Could not read the preview bounds");
        int height = Math.Min(client.Bottom, (int)Math.Round(logicalHeight * GetDpiForWindow(window) / 96.0));
        using (var bitmap = new Bitmap(client.Right, height, PixelFormat.Format32bppRgb)) {
            using (var graphics = Graphics.FromImage(bitmap)) {
                var source = GetDC(window);
                var target = graphics.GetHdc();
                try {
                    if (source == IntPtr.Zero || !BitBlt(target, 0, 0, bitmap.Width, bitmap.Height, source, 0, 0, 0x00CC0020))
                        throw new Exception("The presented preview pixels are unavailable");
                } finally {
                    graphics.ReleaseHdc(target);
                    if (source != IntPtr.Zero) ReleaseDC(window, source);
                }
            }
            var data = bitmap.LockBits(new Rectangle(0, 0, bitmap.Width, bitmap.Height), ImageLockMode.ReadOnly, PixelFormat.Format32bppRgb);
            try {
                var pixels = new byte[data.Stride * data.Height];
                Marshal.Copy(data.Scan0, pixels, 0, pixels.Length);
                return pixels;
            } finally { bitmap.UnlockBits(data); }
        }
    }

    static bool Glyph(byte[] pixels, int offset) {
        return pixels[offset] > 160 && pixels[offset+1] > 160 && pixels[offset+2] > 160;
    }

    static void Compare(byte[] baseline, byte[] restored, string label) {
        if (restored.Length != baseline.Length) throw new Exception(label + ": restore changed the view size");
        int glyphs = 0, missing = 0;
        for (int i = 0; i < baseline.Length; i += 4) {
            if (!Glyph(baseline, i)) continue;
            glyphs++;
            if (!Glyph(restored, i)) missing++;
        }
        if (glyphs < 150) throw new Exception(label + ": preview text/icons were unavailable before the check");
        if (missing > Math.Max(5, glyphs / 100))
            throw new Exception(String.Format("{0}: {1}/{2} text/icon pixels disappeared", label, missing, glyphs));
    }

    public static string Check(IntPtr window) {
        var previousDpi = SetThreadDpiAwarenessContext(new IntPtr(-4));
        try {
            SetWindowPos(window, new IntPtr(-1), 0, 0, 0, 0, 0x13);
            IntPtr terminal = IntPtr.Zero;
            while ((terminal = FindWindowExW(window, terminal, "SentinelSSH.Terminal.v1", null)) != IntPtr.Zero)
                if (IsWindowVisible(terminal)) break;
            if (terminal == IntPtr.Zero) throw new Exception("No visible preview terminal");
            for (int mode = 0; mode < 2; mode++) {
                if (mode == 1) ShowWindow(window, 3); // SW_MAXIMIZE
                Thread.Sleep(500);
                DwmFlush();
                var header = Pixels(window, 44);
                var output = Pixels(terminal, 200);
                Compare(header, header, "Compact row baseline");
                Compare(output, output, "Terminal baseline");
                for (int cycle = 1; cycle <= 3; cycle++) {
                    ShowWindow(window, 6); // SW_MINIMIZE
                    Thread.Sleep(250);
                    if (!IsIconic(window)) throw new Exception("Preview did not minimize");
                    Rect client; GetClientRect(terminal, out client);
                    if (client.Right <= 1 || client.Bottom <= 1) throw new Exception("Minimizing collapsed the terminal grid");
                    ShowWindow(window, 9); // SW_RESTORE (also restores the maximized state)
                    Thread.Sleep(500);
                    DwmFlush();
                    if (IsIconic(window)) throw new Exception("Preview did not restore");
                    string context = String.Format("{0} window, restore {1}", mode == 0 ? "Normal" : "Maximized", cycle);
                    Compare(header, Pixels(window, 44), "Compact row: " + context);
                    Compare(output, Pixels(terminal, 200), "Terminal output: " + context);
                }
            }
            return "Compact row text/icons and terminal output survived 6 minimize/restore cycles (normal and maximized).";
        } finally {
            SetWindowPos(window, new IntPtr(-2), 0, 0, 0, 0, 0x13);
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
    Start-Sleep -Milliseconds 500
    if ($previewProcess.HasExited -or $previewProcess.MainWindowHandle -eq [IntPtr]::Zero) { throw 'The disposable preview did not start.' }
    [WindowRestoreProbe]::Check($previewProcess.MainWindowHandle)
} finally {
    if (!$previewProcess.HasExited) { $previewProcess.Kill(); $previewProcess.WaitForExit() }
    $previewProcess.Dispose()
}
