import os
import json
import argparse
import subprocess

import globalize_bpf_obj

BPF_FS_PATH = "/sys/fs/bpf"

DEFAULT_PIN_PATH = os.path.join(BPF_FS_PATH, "test")

def guess_prog_type(filename):
    name_type_map = {
        "bpf_lxc.o": "classifier",
        "bpf_host.o": "classifier",
        "bpf_overlay.o": "classifier",
        "bpf_wireguard.o": "classifier",
        "bpf_net.o": "classifier",
        "bpf_network.o": "classifier",
        "bpf_xdp.o": "xdp",
    }
    return name_type_map.get(filename, None)

def cleanup_bpf_fs():
    """Remove all entries in the BPF filesystem."""
    if not os.path.isdir(BPF_FS_PATH):
        return
    for entry in os.listdir(BPF_FS_PATH):
        subprocess.run(["rm", "-rf", os.path.join(BPF_FS_PATH, entry)], check=False)

def load_program(file_path, base_name, pin_path=None):
    if pin_path is None:
        pin_path = DEFAULT_PIN_PATH
    cleanup_bpf_fs()

    os.makedirs(pin_path, exist_ok=True)

    load_cmd = ["bpftool", "prog", "loadall", file_path, pin_path]

    prog_type = guess_prog_type(base_name)
    if prog_type:
        load_cmd.extend(["type", prog_type])
    print(load_cmd)

    result = subprocess.run(load_cmd, text=True)
    return result.returncode == 0

def get_current_btf_id(pin_path=None):
    if pin_path is None:
        pin_path = DEFAULT_PIN_PATH
    first_file = os.listdir(pin_path)[0]
    prog_cmd = ["bpftool", "prog", "show", "pinned", os.path.join(pin_path, first_file), "-j"]
    progshow_out = subprocess.check_output(prog_cmd, text=True)
    return json.loads(progshow_out)["btf_id"]

def get_prog_by_btf_id(btf_id):
    prog_cmd = ["bpftool", "prog", "list", "-j"]
    proglist_out = subprocess.check_output(prog_cmd, text=True)
    prog_list = json.loads(proglist_out)
    return [prog for prog in prog_list if prog.get("btf_id", -1) == btf_id]

def dump_jited_code(prog_id):
    dump_cmd = ["bpftool", "prog", "dump", "jited", "id", str(prog_id)]
    return subprocess.check_output(dump_cmd, text=True)

def dump_jit_bpf(obj_files, out, globalize, skip_jit=False):
    if globalize:
        print("Globalization enabled. Processing files...")
        prepared_obj_dir = ".globalized_objs"
        os.makedirs(prepared_obj_dir, exist_ok=True)

        globalize_bpf_obj.globalize_symbols(obj_files, prepared_obj_dir)
        obj_files = [os.path.join(prepared_obj_dir, os.path.basename(f)) for f in obj_files]
        print(f"New object file list: {obj_files}")

    pin_path = DEFAULT_PIN_PATH
    prog_sizes = dict()
    if not skip_jit:
        os.makedirs(out, exist_ok=True)
    for obj_file in obj_files:
        try:
            print(f"Processing {obj_file}...")

            base_name = os.path.basename(obj_file)
            output_dir = ""
            if not skip_jit:
                name_without_ext = os.path.splitext(base_name)[0]
                output_dir = os.path.join(out, f"{name_without_ext}_jit_dumps")
                os.makedirs(output_dir, exist_ok=True)

            if load_program(obj_file, base_name, pin_path=pin_path):
                print(f"Loaded all programs of {obj_file} successfully!")
            else:
                print(f"Failed loading all programs of {obj_file}. Skipping...")
                continue

            btf_id = get_current_btf_id(pin_path=pin_path)
            prog_list = get_prog_by_btf_id(btf_id)

            print(f"Found {len(prog_list)} programs with BTF ID {btf_id}.")
            if not skip_jit:
                  print("Extracting JITed outputs...")

            prog_sizes[base_name] = []
            for prog in prog_list:
                prog_id = prog["id"]
                name = prog.get("name", f"prog_{prog_id}")
                prog_sizes[base_name].append((name, prog.get("bytes_jited", 0)))
                if skip_jit:
                    continue

                jited_code = dump_jited_code(prog_id)
                output_file = os.path.join(output_dir, f"{name}.s")

                with open(output_file, "w") as out_file:
                    out_file.write(jited_code)

            print(f"Successfully extracted info of {len(prog_list)} programs of {base_name}.")
            if not skip_jit:
                print(f"JITed code written to {output_dir}")

            cleanup_bpf_fs()
            print(f"Unloaded {len(prog_list)} programs of {base_name}")
        except Exception as e:
            print(f"Error processing {obj_file}: {e}")

    return prog_sizes

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract JITed code of BPF object files by loading and dumping using bpftool.")

    parser.add_argument("--files", nargs="*", type=str, help="Path to the BPF object file(s) to extract JITed code out of. Leave empty to search from current directory.")
    parser.add_argument("--output_dir", type=str, help="Directory where the output dump will be saved.")
    parser.add_argument("--no_globalize", action="store_true")

    args = parser.parse_args()

    print("Initializing BPF JITed code dumper...")
    bpf_obj_files = args.files or []
    if bpf_obj_files == ["default"]:
        bpf_obj_files = ["bpf_lxc.o", "bpf_host.o", "bpf_overlay.o", "bpf_xdp.o"]
    elif not bpf_obj_files:
        print("No input files provided, searching current directory...")
        cwd = os.getcwd()
        bpf_obj_files = [os.path.join(cwd, f) for f in os.listdir(cwd) if f.endswith(".o")]

    print(f"Found BPF object files: {bpf_obj_files}")

    if not args.output_dir:
        print("No output directory provided, using default 'jit_dumps' in current directory.")
        args.output_dir = os.path.join(os.getcwd(), "jit_dumps")

    dump_jit_bpf(bpf_obj_files, args.output_dir, not args.no_globalize)
