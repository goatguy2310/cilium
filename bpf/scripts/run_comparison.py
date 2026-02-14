import os
import json
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

def fmt_diff(diff, pct):
    """Format difference with percentage."""
    pct_str = f"({pct:+.1f}%)" if pct is not None else ""
    return f"{diff:+d}b {pct_str}"

def calculate_diff_and_pct(nat_sz, jit_sz):
    """Calculate the difference and percentage between native and JIT sizes."""
    diff = nat_sz - jit_sz
    pct = ((nat_sz - jit_sz) / jit_sz * 100) if jit_sz != 0 else None
    return diff, pct

def print_markdown_table(headers, rows, totals):
    """Print a markdown table with the given headers, rows, and totals.
    Column widths are calculated automatically based on content."""
    # Calculate column widths
    col_widths = []
    for i in range(len(headers)):
        max_width = len(headers[i])
        max_width = max(max_width, len(totals[i]))
        for row in rows:
            max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)

    # Print header
    header_line = "|"
    separator_line = "|"
    for header, width, align in zip(headers, col_widths, ['<', '>', '>', '>']):
        header_line += f" {header:{align}{width}} |"
        separator_line += f"{'-' * (width + 2)}|"
    print(header_line)
    print(separator_line)

    # Print data rows
    for row in rows:
        row_line = "|"
        for val, width, align in zip(row, col_widths, ['<', '>', '>', '>']):
            row_line += f" {val:{align}{width}} |"
        print(row_line)

    # Print totals row
    total_line = "|"
    for val, width, align in zip(totals, col_widths, ['<', '>', '>', '>']):
        total_line += f" {val:{align}{width}} |"
    print(total_line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run binary size comparison between JITed and native compilation of Cilium")
    parser.add_argument("--log-dir", default="logs/", help="Directory for build log files and results. Default: ./logs/")
    parser.add_argument("--sort-obj", action="store_true", help="Sort output by total size of object files")
    parser.add_argument("--sort-prog", action="store_true", help="Sort output of each obj file by size of programs")
    parser.add_argument("--sort", action="store_true", help="Enable both sorting options")
    parser.add_argument("--total", action="store_true", help="Print only the total binary sizes of each object file")
    parser.add_argument("--from-saved", action="store_true", help="Load results from past runs. Stored at <log-dir>/results.json")
    args = parser.parse_args()

    if args.sort:
        args.sort_obj = True
        args.sort_prog = True

    print("Initializing JITed vs native compilation binary size experiment...")

    os.makedirs(args.log_dir, exist_ok=True)

    result_file = os.path.join(args.log_dir, "results.json")
    if args.from_saved and os.path.exists(result_file):
        print("Loading results from saved file...")

        with open(result_file, "r") as f:
            result_json = json.load(f)

        jit_sizes = result_json["jit_sizes"]
        nat_sizes = result_json["nat_sizes"]
    else:
        if args.from_saved:
            print(f"Warning: --from-saved specified but no saved results found at {result_file}")
        print("Running new experiments...")
        jit_sizes = get_jit_sizes(log_file=os.path.join(args.log_dir, "jit_logs.txt"))
        nat_sizes = get_native_sizes(log_file=os.path.join(args.log_dir, "native_logs.txt"))

        result_json = {
            "jit_sizes": jit_sizes,
            "nat_sizes": nat_sizes,
        }
        with open(result_file, "w") as f:
            json.dump(result_json, f, indent=2)

    if args.sort_obj:
        def total_size(sizes):
            return sum(sz for _, sz in sizes)
        obj_files = sorted(
            jit_sizes.keys(),
            key=lambda of: (total_size(jit_sizes.get(of, [])), total_size(nat_sizes.get(of, []))),
            reverse=True
        )
    else:
        obj_files = sorted(jit_sizes.keys())

    if not args.total:
        print("\nGenerating detailed comparison tables...")
        for obj_file in obj_files:
            jit_progs = jit_sizes[obj_file]

            if obj_file not in nat_sizes:
                continue

            nat_progs = dict(nat_sizes[obj_file])
            rows = []
            jit_total, nat_total = 0, 0

            for prog, jit_sz in jit_progs:
                if prog not in nat_progs:
                    continue
                nat_sz = nat_progs[prog]
                diff, pct = calculate_diff_and_pct(nat_sz, jit_sz)
                rows.append((prog, jit_sz, nat_sz, diff, pct))
                jit_total += jit_sz
                nat_total += nat_sz

            if not rows:
                continue

            if args.sort_prog:
                rows.sort(key=lambda r: (r[1], r[2]), reverse=True)
            else:
                rows.sort(key=lambda r: r[0])  # Sort by program name

            # Calculate overall totals for this object file
            total_diff, total_pct = calculate_diff_and_pct(nat_total, jit_total)
            total_pct_str = fmt_diff(total_diff, total_pct)

            # Print table
            print(f"\n### {obj_file}\n")
            headers = ["Program", "JIT Size", "Native Size", "Diff"]
            formatted_rows = [
                (prog, str(jit_sz), str(nat_sz), fmt_diff(diff, pct))
                for prog, jit_sz, nat_sz, diff, pct in rows
            ]
            totals = ["**Total**", f"**{jit_total}**", f"**{nat_total}**", f"**{total_pct_str}**"]
            print_markdown_table(headers, formatted_rows, totals)
    else:
        # Calculate and print total sizes for each object file
        print("\nGenerating total size comparison table...")

        rows = []
        jit_total, nat_total = 0, 0
        for obj_file in obj_files:
            nat_sz = sum(sz for _, sz in nat_sizes.get(obj_file, []))
            jit_sz = sum(sz for _, sz in jit_sizes.get(obj_file, []))
            diff, pct = calculate_diff_and_pct(nat_sz, jit_sz)
            rows.append((obj_file, jit_sz, nat_sz, diff, pct))
            jit_total += jit_sz
            nat_total += nat_sz

        # Calculate grand totals across all object files
        total_diff, total_pct = calculate_diff_and_pct(nat_total, jit_total)
        total_pct_str = fmt_diff(total_diff, total_pct)

        # Print table
        print(f"\n### Total Sizes\n")
        headers = ["Object File", "JIT Size", "Native Size", "Diff"]
        formatted_rows = [
            (obj_file, str(jit_sz), str(nat_sz), fmt_diff(diff, pct))
            for obj_file, jit_sz, nat_sz, diff, pct in rows
        ]
        totals = ["**Total**", f"**{jit_total}**", f"**{nat_total}**", f"**{total_pct_str}**"]
        print_markdown_table(headers, formatted_rows, totals)
