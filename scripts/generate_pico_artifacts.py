#!/usr/bin/env python3
import argparse
import gzip
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def write_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def copy_file(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def build_forensics_grep(dst_root):
    src_root = ROOT / "repos" / "start-problem-dev" / "example-problems" / "forensics-grep"
    target = dst_root / "forensics-grep" / "war-and-peace.flag.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    flag = "picoCTF{gr3p_15_4_5up3rp0w3r_c001d00d}"
    tmp_flag = None
    try:
        shutil.copy2(src_root / "war-and-peace.txt", target)
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(flag)
            tmp_flag = pathlib.Path(handle.name)
        subprocess.run(
            [
                "python3",
                str(src_root / "byteblast.py"),
                str(target),
                str(tmp_flag),
                "49998",
            ],
            check=True,
            cwd=ROOT,
        )
    finally:
        if tmp_flag and tmp_flag.exists():
            tmp_flag.unlink()


def build_forensics_disk(dst_root):
    src_root = ROOT / "repos" / "start-problem-dev" / "example-problems" / "forensics-disk"
    out_dir = dst_root / "forensics-disk"
    out_dir.mkdir(parents=True, exist_ok=True)
    working_img = out_dir / "disk.flag.img"
    final_img = out_dir / "disk.flag.img.gz"
    flag = "picoCTF{d15k_513uth_facefeed}"
    tmp_flag = None
    try:
        with gzip.open(src_root / "disk.img.gz", "rb") as src, open(working_img, "wb") as dst:
            shutil.copyfileobj(src, dst)
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(flag)
            tmp_flag = pathlib.Path(handle.name)
        subprocess.run(
            [
                "python3",
                str(src_root / "byteblast.py"),
                str(working_img),
                str(tmp_flag),
                "509014036",
            ],
            check=True,
            cwd=ROOT,
        )
        with open(working_img, "rb") as src, gzip.open(final_img, "wb") as dst:
            shutil.copyfileobj(src, dst)
    finally:
        if working_img.exists():
            working_img.unlink()
        if tmp_flag and tmp_flag.exists():
            tmp_flag.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()

    dst_root = pathlib.Path(args.output_root) / "start-problem-dev"
    dst_root.mkdir(parents=True, exist_ok=True)

    write_text(dst_root / "sanity-static-flag" / "flag.txt", "picoCTF{s4n1ty_d0wnl04d3d}\n")
    copy_file(
        ROOT / "repos" / "start-problem-dev" / "example-problems" / "reversing-python" / "picker-I.py",
        dst_root / "reversing-python" / "picker-I.py",
    )
    copy_file(
        ROOT / "repos" / "start-problem-dev" / "example-problems" / "perceptron-gate" / "perceptron_gate.py",
        dst_root / "perceptron-gate" / "perceptron_gate.py",
    )
    build_forensics_grep(dst_root)
    build_forensics_disk(dst_root)


if __name__ == "__main__":
    main()
