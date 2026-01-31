import os
import argparse
import subprocess

import dump_jited_bpf

def rebuild_obj_files(flags=[]):
    try:
        subprocess.run(["make", "clean"], stdout=None, stderr=subprocess.STDOUT)
        subprocess.run(["make"] + flags, stdout=None, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f"Error during rebuild: {e}")
        return False
    return True

def get_jit_sizes():
    print("Extracting JIT info...")
    if not rebuild_obj_files(["JB=bpf"]):
        return {}
    cwd = os.getcwd()
    obj_files = [os.path.join(cwd, f) for f in os.listdir(cwd) if f.endswith(".o")]

    return dump_jited_bpf.dump_jit_bpf(obj_files, out=None, globalize=True, skip_jit=True)

def get_native_sizes():
    print("Extracting native compilation info...")
    if not rebuild_obj_files(["JB=native"]):
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
                if len(parts := line.split()) >= 4 and (parts[2] == 't' or parts[2] == 'T')
            ]
        except Exception as e:
            print(f"Error processing {obj_file}: {e}")
    return prog_sizes

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run binary size comparison between JITed and native compilation of Cilium")

    print("Initializing JITed vs native compilation binary size experiment...")

    jit_sizes = get_jit_sizes()
    nat_sizes = get_native_sizes()

    for obj_file, jit_progs in jit_sizes.items():
        if obj_file not in nat_sizes:
            continue

        jit_total, nat_total = 0, 0
        nat_progs = nat_sizes[obj_file]
        for prog, sz in jit_progs:
            if prog not in nat_progs:
                continue

            jit_total += sz
            nat_total += nat_progs[prog][1]

        print(f"{obj_file}: JITed = {jit_total}, native = {nat_total}, diff = {nat_total - jit_total}, rate = {1 - nat_total / jit_total if jit_total != 0 else None}")
