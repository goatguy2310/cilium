import os
import shutil
import argparse
import subprocess


def globalize_symbols(obj_files, out):
    """Globalize static symbols in BPF object files to make them visible for dumping."""
    os.makedirs(out, exist_ok=True)
    for obj_file in obj_files:
        print(f"Processing {obj_file}...")
        base_name = os.path.basename(obj_file)
        output_path = os.path.join(out, base_name)

        try:
            nm_out = subprocess.check_output(["nm", obj_file], text=True)
            static_syms = [
                parts[2] for line in nm_out.splitlines()
                if len(parts := line.split()) >= 3 and parts[1] == 't'
            ]

            if static_syms:
                globalize_cmd = ["llvm-objcopy"]
                for sym in static_syms:
                    globalize_cmd.extend(["--globalize-symbol", sym])
                globalize_cmd.extend([obj_file, output_path])
                subprocess.run(globalize_cmd, check=True)
            else:
                shutil.copy(obj_file, output_path)

            print(f"Saved globalized object file to {output_path}")
        except Exception as e:
            print(f"Error procnessing {obj_file}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare BPF object files for use.")

    parser.add_argument("--files", nargs="*", type=str, help="Path to the BPF object file(s) to be prepared. Leave empty to search from current directory.")
    parser.add_argument("--output_dir", type=str, help="Directory where the prepared BPF object file(s) will be saved.")

    args = parser.parse_args()

    print("Initializing BPF object file globalization...")
    bpf_obj_files = args.files or []
    if not bpf_obj_files:
        print("No input files provided, searching current directory...")
        cwd = os.getcwd()
        bpf_obj_files = [os.path.join(cwd, f) for f in os.listdir(cwd) if f.endswith(".o")]
    print(f"Found BPF object files: {bpf_obj_files}")

    if not args.output_dir:
        print("No output directory provided, using default '.globalized_objs' in current directory.")
        args.output_dir = os.path.join(os.getcwd(), ".globalized_objs")

    globalize_symbols(bpf_obj_files, args.output_dir)
