# GIMP 3 batch script: render the SVG sources into one layer per size and export a Windows icon.
# Run through scripts/build-icon.ps1, which supplies SENTINEL_ICON_DIR and SENTINEL_PREVIEW_DIR.
import os

import gi

gi.require_version("Gimp", "3.0")
from gi.repository import Gimp, Gio

ICON_DIR = os.environ["SENTINEL_ICON_DIR"]
PREVIEW_DIR = os.environ.get("SENTINEL_PREVIEW_DIR", "")
# Small sizes use a simplified glyph; the shield detail would blur below 32 pixels.
SIZES = [256, 64, 48, 40, 32, 24, 20, 16]
SMALL_LIMIT = 24
pdb = Gimp.get_pdb()


def run(name, **arguments):
    procedure = pdb.lookup_procedure(name)
    config = procedure.create_config()
    config.set_property("run-mode", Gimp.RunMode.NONINTERACTIVE)
    for key, value in arguments.items():
        config.set_property(key.replace("_", "-"), value)
    result = procedure.run(config)
    if result.index(0) != Gimp.PDBStatusType.SUCCESS:
        raise RuntimeError(f"{name} failed: {result.index(0)}")
    return result


def render(size):
    source = "sentinel-ssh-small.svg" if size <= SMALL_LIMIT else "sentinel-ssh.svg"
    return run(
        "file-svg-load",
        file=Gio.File.new_for_path(os.path.join(ICON_DIR, source)),
        width=size,
        height=size,
        keep_ratio=True,
        prefer_native_dimensions=False,
    ).index(1)


icon = render(SIZES[0])
icon.get_layers()[0].set_name(f"{SIZES[0]}px")
if PREVIEW_DIR:
    run("file-png-export", image=icon, file=Gio.File.new_for_path(os.path.join(PREVIEW_DIR, f"{SIZES[0]}.png")), options=None)
for size in SIZES[1:]:
    image = render(size)
    layer = Gimp.Layer.new_from_drawable(image.get_layers()[0], icon)
    layer.set_name(f"{size}px")
    icon.insert_layer(layer, None, len(icon.get_layers()))
    if PREVIEW_DIR:
        run("file-png-export", image=image, file=Gio.File.new_for_path(os.path.join(PREVIEW_DIR, f"{size}.png")), options=None)
    image.delete()

run("file-ico-export", image=icon, file=Gio.File.new_for_path(os.path.join(ICON_DIR, "sentinel-ssh.ico")), options=None)
icon.delete()
print("Exported", os.path.join(ICON_DIR, "sentinel-ssh.ico"))
