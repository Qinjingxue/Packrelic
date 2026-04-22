import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from test_config import get_test_tools, make_tempdir_kwargs


MINIMAL_JPEG_BYTES = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb004300"
    "080606070605080707070909080a0c140d0c0b0b0c19120f13"
    "1d1a1f1e1d1a1c1c20242e2720222c231c1c2837292c303134"
    "34341f27393d38323c2e333432ffc0000b0800010001010111"
    "00ffc40014000100000000000000000000000000000008ffda"
    "0008010100003f00d2cf20ffd9"
)

PAYLOAD_BYTES = 2 * 1024 * 1024 + 256 * 1024
MARKER_TEXT = "synthetic-test-payload"


def _require_seven_zip() -> Path:
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        raise FileNotFoundError("7z.exe was not found. Check tests/test_config.json tool candidates.")
    return seven_zip


def _run_cmd(cmd, cwd: Path):
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(map(str, cmd))}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _write_large_marker_file(path: Path, label: str, size_bytes: int = PAYLOAD_BYTES):
    path.parent.mkdir(parents=True, exist_ok=True)
    chunk = (f"{MARKER_TEXT}::{label}::".encode("utf-8") * 4096)[:65536]
    with open(path, "wb") as handle:
        remaining = size_bytes
        while remaining > 0:
            piece = chunk[: min(len(chunk), remaining)]
            handle.write(piece)
            remaining -= len(piece)


def _write_placeholder_binary(path: Path, label: str, size_bytes: int = PAYLOAD_BYTES):
    path.parent.mkdir(parents=True, exist_ok=True)
    chunk = (f"{label}::placeholder::".encode("utf-8") * 4096)[:65536]
    with open(path, "wb") as handle:
        remaining = size_bytes
        while remaining > 0:
            piece = chunk[: min(len(chunk), remaining)]
            handle.write(piece)
            remaining -= len(piece)


def create_7z_archive(source_dir: Path, output_path: Path):
    seven_zip = _require_seven_zip()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _run_cmd([str(seven_zip), "a", str(output_path), str(source_dir), "-mx=0", "-y"], output_path.parent)
    return output_path


def create_zip_archive(source_dir: Path, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_STORED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source_dir))
    return output_path


def create_disguised_jpeg_archive(output_dir: Path, carrier_name: str = "fakepicture.jpg") -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    source_dir = output_dir / "_fakepicture_src"
    _write_large_marker_file(source_dir / "payload.bin", "fakepicture")
    (source_dir / "notes.txt").write_text("synthetic disguised archive carrier\n", encoding="utf-8")

    archive_path = output_dir / "_fakepicture_hidden.7z"
    create_7z_archive(source_dir, archive_path)

    carrier_path = output_dir / carrier_name
    carrier_path.write_bytes(MINIMAL_JPEG_BYTES + archive_path.read_bytes())

    shutil.rmtree(source_dir, ignore_errors=True)
    archive_path.unlink(missing_ok=True)
    return {
        "path": carrier_path,
        "kind": "disguised_jpeg_archive",
    }


def create_synthetic_rpgmaker_game(output_dir: Path, dir_name: str = "rpgmakertest") -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    game_root = output_dir / dir_name
    (game_root / "www" / "js").mkdir(parents=True, exist_ok=True)
    (game_root / "www" / "data").mkdir(parents=True, exist_ok=True)
    (game_root / "www" / "fonts").mkdir(parents=True, exist_ok=True)
    (game_root / "www" / "img").mkdir(parents=True, exist_ok=True)

    (game_root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 1024)
    (game_root / "www" / "js" / "rpg_core.js").write_text("// synthetic rpg maker core\n", encoding="utf-8")
    (game_root / "www" / "js" / "plugins.js").write_text("var $plugins = [];\n", encoding="utf-8")
    (game_root / "www" / "data" / "Map001.json").write_text('{"displayName":"Synthetic Map"}\n', encoding="utf-8")
    _write_large_marker_file(game_root / "www" / "img" / "Title1.png.bin", "rpgmaker-visible-payload")

    protected_src = output_dir / "_rpgmaker_font_archive_src"
    _write_large_marker_file(protected_src / "font_payload.bin", "rpgmaker-protected-archive")
    (protected_src / "readme.txt").write_text("This archive simulates a protected embedded resource.\n", encoding="utf-8")
    protected_archive = game_root / "www" / "fonts" / "jfdotfont-20150527.7z"
    create_7z_archive(protected_src, protected_archive)
    shutil.rmtree(protected_src, ignore_errors=True)
    return {
        "path": game_root,
        "kind": "synthetic_rpgmaker_game",
        "protected_rel_paths": ["www/fonts/jfdotfont-20150527.7z"],
    }


def create_synthetic_rpgmaker_archive(output_dir: Path, archive_name: str = "rpgmakertest.7z") -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    game_info = create_synthetic_rpgmaker_game(output_dir, dir_name="rpgmakertest")
    game_root = game_info["path"]

    outer_archive = output_dir / archive_name
    create_7z_archive(game_root, outer_archive)
    shutil.rmtree(game_root, ignore_errors=True)
    return {
        "path": outer_archive,
        "kind": "synthetic_rpgmaker_archive",
        "protected_rel_path": "www/fonts/jfdotfont-20150527.7z",
    }


def create_synthetic_renpy_game(output_dir: Path, dir_name: str = "renpy_game") -> dict:
    root = output_dir / dir_name
    (root / "game").mkdir(parents=True, exist_ok=True)
    (root / "renpy").mkdir(parents=True, exist_ok=True)
    (root / "lib").mkdir(parents=True, exist_ok=True)
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    (root / "game" / "options.rpy").write_text("define config.name = 'Synthetic RenPy'\n", encoding="utf-8")
    _write_placeholder_binary(root / "game" / "data.rpa", "renpy-rpa")
    return {
        "path": root,
        "kind": "synthetic_renpy_game",
        "protected_rel_paths": ["game/data.rpa"],
    }


def create_synthetic_godot_game(output_dir: Path, dir_name: str = "godot_game") -> dict:
    root = output_dir / dir_name
    (root / "packs").mkdir(parents=True, exist_ok=True)
    (root / "godot_game.exe").write_bytes(b"MZ" + b"\x00" * 1024)
    (root / "project.godot").write_text("[application]\nconfig/name=\"Synthetic Godot\"\n", encoding="utf-8")
    _write_placeholder_binary(root / "data.pck", "godot-data-pck")
    _write_placeholder_binary(root / "packs" / "mod.pck", "godot-mod-pck")
    return {
        "path": root,
        "kind": "synthetic_godot_game",
        "protected_rel_paths": ["data.pck", "packs/mod.pck"],
    }


def create_synthetic_nwjs_game(output_dir: Path, dir_name: str = "nwjs_game") -> dict:
    root = output_dir / dir_name
    package_src = root / "_package_src"
    package_src.mkdir(parents=True, exist_ok=True)
    (package_src / "package.json").write_text('{"name":"synthetic-nw","main":"index.html"}\n', encoding="utf-8")
    _write_large_marker_file(package_src / "payload.bin", "nwjs-package")
    (root / "nw.exe").write_bytes(b"MZ" + b"\x00" * 1024)
    create_zip_archive(package_src, root / "package.nw")
    shutil.rmtree(package_src, ignore_errors=True)
    return {
        "path": root,
        "kind": "synthetic_nwjs_game",
        "protected_rel_paths": ["package.nw"],
    }


def create_synthetic_electron_game(output_dir: Path, dir_name: str = "electron_game") -> dict:
    root = output_dir / dir_name
    (root / "resources" / "app.asar.unpacked").mkdir(parents=True, exist_ok=True)
    (root / "app.exe").write_bytes(b"MZ" + b"\x00" * 1024)
    _write_placeholder_binary(root / "resources" / "app.asar", "electron-app-asar")
    (root / "resources" / "app.asar.unpacked" / "helper.txt").write_text("synthetic electron unpacked helper\n", encoding="utf-8")
    return {
        "path": root,
        "kind": "synthetic_electron_game",
        "protected_rel_paths": ["resources/app.asar"],
    }


def create_generic_zip_archive(output_dir: Path, archive_name: str = "generic.zip") -> dict:
    source_dir = output_dir / "_generic_zip_src"
    source_dir.mkdir(parents=True, exist_ok=True)
    _write_large_marker_file(source_dir / "payload.bin", "generic-zip")
    (source_dir / "notes.txt").write_text("generic extractable zip archive\n", encoding="utf-8")
    archive_path = output_dir / archive_name
    create_zip_archive(source_dir, archive_path)
    shutil.rmtree(source_dir, ignore_errors=True)
    return {
        "path": archive_path,
        "kind": "generic_zip_archive",
    }


def create_runtime_semantic_dataset(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    items = {
        "rpg_maker_game": create_synthetic_rpgmaker_game(output_dir),
        "renpy_game": create_synthetic_renpy_game(output_dir),
        "godot_game": create_synthetic_godot_game(output_dir),
        "nwjs_game": create_synthetic_nwjs_game(output_dir),
        "electron_app_game": create_synthetic_electron_game(output_dir),
        "generic_zip": create_generic_zip_archive(output_dir),
        "disguised_archive": create_disguised_jpeg_archive(output_dir),
    }
    return {
        "path": output_dir,
        "items": items,
    }


def create_profile_dataset(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    disguised = create_disguised_jpeg_archive(output_dir)
    (output_dir / "README.txt").write_text("synthetic profile dataset\n", encoding="utf-8")
    return {
        "path": output_dir,
        "generated_items": [disguised["path"].name, "README.txt"],
    }


def create_cli_smoke_dataset(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    disguised = create_disguised_jpeg_archive(output_dir)
    rpgmaker = create_synthetic_rpgmaker_archive(output_dir)
    (output_dir / "plain.txt").write_text("synthetic smoke dataset\n", encoding="utf-8")
    return {
        "path": output_dir,
        "generated_items": [
            disguised["path"].name,
            rpgmaker["path"].name,
            "plain.txt",
        ],
    }


def temporary_generated_dir(prefix: str):
    kwargs = {"prefix": prefix}
    kwargs.update(make_tempdir_kwargs())
    return tempfile.TemporaryDirectory(**kwargs)
