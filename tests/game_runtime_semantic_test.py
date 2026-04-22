import os
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
TESTS_ROOT = os.path.dirname(os.path.abspath(__file__))
if TESTS_ROOT not in sys.path:
    sys.path.insert(0, TESTS_ROOT)

from smart_unpacker import DecompressionEngine
from smart_unpacker.core.engine import Engine
from synthetic_samples import create_runtime_semantic_dataset, create_synthetic_rpgmaker_archive


class GameRuntimeSemanticTest(unittest.TestCase):
    def make_engine(self, root: Path) -> Engine:
        engine = Engine(str(root), [], lambda _msg: None, lambda: None)
        engine.max_workers_limit = 1
        engine.current_concurrency_limit = 1
        return engine

    def inspect_relative(self, engine: Engine, root: Path, relative_path: str):
        path = root / Path(relative_path)
        relations = engine._build_directory_relationships(str(path.parent), [path.name], scan_root=str(root))
        relation = relations[path.name]
        scene_context = engine._resolve_scene_context_for_path(str(path.parent), str(root))
        info = engine.inspect_archive_candidate(str(path), relation=relation, scene_context=scene_context)
        return scene_context, info

    @staticmethod
    def rel_posix(path: Path, base: Path) -> str:
        return str(path.relative_to(base)).replace("\\", "/")

    def collect_inventory(self, base_dir: Path):
        files = []
        for path in sorted(base_dir.rglob("*")):
            if path.is_file():
                rel_path = self.rel_posix(path, base_dir)
                files.append(
                    {
                        "path": rel_path,
                        "size": path.stat().st_size,
                        "suffix": path.suffix.lower(),
                        "top_level": rel_path.split("/", 1)[0],
                    }
                )
        return files

    def summarize_nested_tasks(self, tasks, game_root: Path):
        summary = []
        for task in tasks:
            archive_path = Path(task.main_path)
            rel_path = self.rel_posix(archive_path, game_root)
            main_info = task.group_info.main_info
            summary.append(
                {
                    "path": rel_path,
                    "decision": main_info.decision,
                    "should_extract": task.group_info.group_should_extract,
                    "scene_role": main_info.scene_role,
                    "detected_ext": main_info.detected_ext,
                }
            )
        return summary

    def collect_semantic_candidates(self, engine: Engine, game_root: Path):
        scene_context = engine._detect_scene_context(str(game_root))
        candidates = []
        for root, _, files in os.walk(game_root):
            files.sort()
            relations = engine._build_directory_relationships(root, files, scan_root=str(game_root))
            for filename in files:
                relation = relations[filename]
                info = engine.inspect_archive_candidate(relation.path, relation=relation, scene_context=scene_context)
                rel_path = self.rel_posix(Path(relation.path), game_root)
                same_stem_dir = Path(relation.path).with_suffix("")
                candidates.append(
                    {
                        "path": rel_path,
                        "decision": info.decision,
                        "should_extract": info.should_extract,
                        "scene_role": info.scene_role,
                        "detected_ext": info.detected_ext,
                        "probe_detected_archive": info.probe_detected_archive,
                        "magic_matched": info.magic_matched,
                        "neighbor_extract_dir": self.rel_posix(same_stem_dir, game_root) if same_stem_dir.is_dir() else None,
                        "reasons": list(info.reasons),
                    }
                )
        return scene_context, candidates

    def test_runtime_layouts_protect_engine_archives_and_generic_controls_still_extract(self):
        with tempfile.TemporaryDirectory() as td:
            dataset = create_runtime_semantic_dataset(Path(td))
            items = dataset["items"]

            engine_expectations = {
                "rpg_maker_game": {
                    "root": items["rpg_maker_game"]["path"],
                    "protected_paths": items["rpg_maker_game"]["protected_rel_paths"],
                    "scene_type": "rpg_maker_game",
                },
                "renpy_game": {
                    "root": items["renpy_game"]["path"],
                    "protected_paths": items["renpy_game"]["protected_rel_paths"],
                    "scene_type": "renpy_game",
                },
                "godot_game": {
                    "root": items["godot_game"]["path"],
                    "protected_paths": items["godot_game"]["protected_rel_paths"],
                    "scene_type": "godot_game",
                },
                "nwjs_game": {
                    "root": items["nwjs_game"]["path"],
                    "protected_paths": items["nwjs_game"]["protected_rel_paths"],
                    "scene_type": "nwjs_game",
                },
                "electron_app_game": {
                    "root": items["electron_app_game"]["path"],
                    "protected_paths": items["electron_app_game"]["protected_rel_paths"],
                    "scene_type": "electron_app_game",
                },
            }

            for expected in engine_expectations.values():
                engine = self.make_engine(expected["root"])
                context = engine._detect_scene_context(str(expected["root"]))
                self.assertEqual(context.scene_type, expected["scene_type"])
                self.assertEqual(engine.scan_archives_readonly(), [])

                for rel_path in expected["protected_paths"]:
                    scene_context, info = self.inspect_relative(engine, expected["root"], rel_path)
                    self.assertEqual(scene_context.scene_type, expected["scene_type"])
                    self.assertEqual(info.scene_role, "embedded_resource_archive")
                    self.assertEqual(info.decision, "not_archive")
                    self.assertFalse(info.should_extract)
                    self.assertTrue(any("目录语义保护" in reason for reason in info.reasons))

            control_root = Path(td) / "generic_controls"
            control_root.mkdir(parents=True, exist_ok=True)
            generic_zip = items["generic_zip"]["path"]
            disguised_archive = items["disguised_archive"]["path"]
            generic_engine = self.make_engine(Path(td))

            generic_zip_scene, generic_zip_info = self.inspect_relative(generic_engine, generic_zip.parent, generic_zip.name)
            self.assertEqual(generic_zip_scene.scene_type, "generic")
            self.assertEqual(generic_zip_info.decision, "archive")
            self.assertTrue(generic_zip_info.should_extract)

            disguised_scene, disguised_info = self.inspect_relative(generic_engine, disguised_archive.parent, disguised_archive.name)
            self.assertEqual(disguised_scene.scene_type, "generic")
            self.assertEqual(disguised_info.decision, "archive")
            self.assertTrue(disguised_info.should_extract)
            self.assertTrue(disguised_info.probe_detected_archive)

    def test_rpg_maker_outer_archive_extracts_but_nested_resource_archive_stays_protected(self):
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            generated = create_synthetic_rpgmaker_archive(temp_root)
            source_archive = generated["path"]
            protected_rel_path = generated["protected_rel_path"]

            workspace_dir = temp_root / "workspace"
            workspace_dir.mkdir(parents=True, exist_ok=True)
            staged_archive = workspace_dir / source_archive.name
            staged_archive.write_bytes(source_archive.read_bytes())

            logs = []
            engine = DecompressionEngine(str(workspace_dir), [], logs.append, lambda: None)
            engine.max_workers_limit = 1
            engine.current_concurrency_limit = 1

            initial_tasks = engine.scan_archives()
            self.assertEqual(len(initial_tasks), 1)
            self.assertEqual(Path(initial_tasks[0].main_path).name, source_archive.name)

            summary = engine.run()
            self.assertEqual(summary.success_count, 1)

            top_level_output = workspace_dir / source_archive.stem
            self.assertTrue(top_level_output.is_dir())

            game_root = top_level_output
            self.assertTrue((game_root / "www").is_dir())
            self.assertTrue((game_root / "Game.exe").is_file())

            protected_archive = game_root / Path(*protected_rel_path.split("/"))
            protected_extract_dir = protected_archive.with_suffix("")
            self.assertTrue(protected_archive.is_file())
            self.assertFalse(protected_extract_dir.exists())
            self.assertFalse(any("[EXTRACT] 开始:" in line and protected_archive.name in line for line in logs))
            self.assertFalse(any("[EXTRACT] 成功:" in line and protected_archive.name in line for line in logs))

            scene_context, semantic_candidates = self.collect_semantic_candidates(engine, game_root)
            self.assertEqual(scene_context.scene_type, "rpg_maker_game")
            protected_candidates = [
                item
                for item in semantic_candidates
                if item["path"] == protected_rel_path and item["scene_role"] == "embedded_resource_archive"
            ]
            self.assertEqual(len(protected_candidates), 1)
            self.assertEqual(protected_candidates[0]["decision"], "not_archive")
            self.assertFalse(protected_candidates[0]["should_extract"])
            self.assertIsNone(protected_candidates[0]["neighbor_extract_dir"])

            nested_tasks = engine.scan_archives(str(game_root))
            nested_task_summary = self.summarize_nested_tasks(nested_tasks, game_root)
            self.assertFalse(
                any(item["path"] == protected_rel_path and item["should_extract"] for item in nested_task_summary)
            )

            inventory = self.collect_inventory(game_root)
            inventory_summary = {
                "file_count": len(inventory),
                "total_bytes": sum(item["size"] for item in inventory),
                "top_level_distribution": dict(sorted(Counter(item["top_level"] for item in inventory).items())),
            }
            self.assertGreaterEqual(inventory_summary["file_count"], 5)


if __name__ == "__main__":
    unittest.main()
