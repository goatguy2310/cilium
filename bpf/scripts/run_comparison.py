import os
import argparse
import subprocess

import dump_jited_bpf

def rebuild_obj_files(flags=None, log_file=None):
    if flags is None:
        flags = []
    try:
        if log_file:
            with open(log_file, "w") as f:
                subprocess.run(["make", "clean"], stdout=f, stderr=subprocess.STDOUT, check=True)
                subprocess.run(["make"] + flags, stdout=f, stderr=subprocess.STDOUT, check=True)
        else:
            subprocess.run(["make", "clean"], check=True)
            subprocess.run(["make"] + flags, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error during rebuild: {e}")
        return False
    return True

def get_jit_sizes(log_file=None):
    print("Extracting JIT info...")
    if not rebuild_obj_files(["JB=bpf"], log_file=log_file):
        return {}
    cwd = os.getcwd()
    obj_files = [os.path.join(cwd, f) for f in os.listdir(cwd) if f.endswith(".o")]

    return dump_jited_bpf.dump_jit_bpf(obj_files, out=None, globalize=True, skip_jit=True)

def get_native_sizes(log_file=None):
    print("Extracting native compilation info...")
    if not rebuild_obj_files(["JB=native"], log_file=log_file):
        return {}
    cwd = os.getcwd()
    obj_files = [os.path.join(cwd, f) for f in os.listdir(cwd) if f.endswith(".o")]

    prog_sizes = dict()
    for obj_file in obj_files:
        print(f"Analyzing ELF of {obj_file}...")
        base_name = os.path.basename(obj_file)

        try:
            nm_out = subprocess.check_output(["nm", "-S", "-t", "d", obj_file], text=True) 
            prog_sizes[base_name] = [
                (parts[3], int(parts[1])) for line in nm_out.splitlines()
                if len(parts := line.split()) >= 4 and parts[2] in ('t', 'T')
            ]
        except Exception as e:
            print(f"Error processing {obj_file}: {e}")
    return prog_sizes

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run binary size comparison between JITed and native compilation of Cilium")
    parser.add_argument("--jit-log", default="logs/jit_build.log", help="Log file for JIT build output")
    parser.add_argument("--native-log", default="logs/native_build.log", help="Log file for native build output")
    args = parser.parse_args()

    print("Initializing JITed vs native compilation binary size experiment...")

    os.makedirs(os.path.dirname(args.jit_log), exist_ok=True)
    os.makedirs(os.path.dirname(args.native_log), exist_ok=True)

    jit_sizes = get_jit_sizes(log_file=args.jit_log)
    nat_sizes = get_native_sizes(log_file=args.native_log)

    for obj_file, jit_progs in jit_sizes.items():
        if obj_file not in nat_sizes:
            continue

        nat_progs = dict(nat_sizes[obj_file])
        rows = []
        jit_total, nat_total = 0, 0

        for prog, jit_sz in jit_progs:
            if prog not in nat_progs:
                continue
            nat_sz = nat_progs[prog]
            diff = nat_sz - jit_sz
            pct = ((nat_sz - jit_sz) / jit_sz * 100) if jit_sz != 0 else None
            rows.append((prog, jit_sz, nat_sz, diff, pct))
            jit_total += jit_sz
            nat_total += nat_sz

        if not rows:
            continue

        # Calculate totals
        total_diff = nat_total - jit_total
        total_pct = ((nat_total - jit_total) / jit_total * 100) if jit_total != 0 else None

        # Calculate column widths
        def fmt_diff(diff, pct):
            pct_str = f"({pct:+.1f}%)" if pct is not None else ""
            return f"{diff:+d}b {pct_str}"

        total_pct_str = fmt_diff(total_diff, total_pct)
        col_prog = max(len("Program"), len("**Total**"), max(len(p) for p, *_ in rows))
        col_jit = max(len("JIT Size"), len(f"**{jit_total}**"), max(len(str(j)) for _, j, *_ in rows))
        col_nat = max(len("Native Size"), len(f"**{nat_total}**"), max(len(str(n)) for _, _, n, *_ in rows))
        col_diff = max(len("Diff"), len(f"**{total_pct_str}**"), max(len(fmt_diff(d, p)) for _, _, _, d, p in rows))

        # Print markdown table
        print(f"\n## {obj_file}\n")
        print(f"| {'Program':<{col_prog}} | {'JIT Size':>{col_jit}} | {'Native Size':>{col_nat}} | {'Diff':>{col_diff}} |")
        print(f"|{'-' * (col_prog + 2)}|{'-' * (col_jit + 2)}|{'-' * (col_nat + 2)}|{'-' * (col_diff + 2)}|")
        for prog, jit_sz, nat_sz, diff, pct in rows:
            diff_str = fmt_diff(diff, pct)
            print(f"| {prog:<{col_prog}} | {jit_sz:>{col_jit}} | {nat_sz:>{col_nat}} | {diff_str:>{col_diff}} |")
        print(f"| {'**Total**':<{col_prog}} | {f'**{jit_total}**':>{col_jit}} | {f'**{nat_total}**':>{col_nat}} | {f'**{total_pct_str}**':>{col_diff}} |")
