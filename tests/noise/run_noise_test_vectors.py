#!/usr/bin/python

import json
import sys
import subprocess

def fail(protocol_name: str, variable: str, expected: str, result: str, filename: str):
    print(f"{filename}: {protocol_name}: failed: {variable} expected value \"{expected}\" but got \"{result}\"")
    return False

def check(expected: dict, result: dict, filename: str):
    success = True
    protocol_name = expected['protocol_name']

    for variable in expected:
        if variable == "messages":
            for i in range(0, len(expected[variable])):
                if expected[variable][i]["payload"] != result[variable][i]["payload"]:
                    success = fail(protocol_name, f"{variable}[{i}].payload", expected[variable][i]["payload"], result[variable][i]["payload"], filename)
                if expected[variable][i]["ciphertext"] != result[variable][i]["ciphertext"]:
                    success = fail(protocol_name, f"{variable}[{i}].ciphertext", expected[variable][i]["ciphertext"], result[variable][i]["ciphertext"], filename)
        else:
            if expected[variable] != result[variable]:
                success = fail(protocol_name, variable, expected[variable], result[variable], filename)

    if success:
        print(f"{filename}: {protocol_name}: ok")
    else:
        exit(1)

def run_test_binary(test_binary: str, result_output_file: str, args: list) -> None:
    base_args = [
        #"valgrind",
        #"-s",
        #"--leak-check=full",
        test_binary,
        "--output-file",
        result_output_file,
    ]
    subprocess.call(base_args + args)

def get_supported_handshakes(test_binary: str, result_output_file: str) -> list:
    run_test_binary(test_binary, result_output_file, ["--print-supported"])
    with open(result_output_file, "r") as f:
        return [line.strip() for line in f.readlines()]

if __name__ == "__main__":
    test_binary = sys.argv[1]
    result_output_file = sys.argv[2]

    supported_handshakes = get_supported_handshakes(test_binary, result_output_file)
    tested_handshakes = list()

    for i in range(3, len(sys.argv)):
        test_vectors_file = sys.argv[i]
        with open(test_vectors_file, "r") as f:
            tmp = json.load(f)
            for vector in tmp["vectors"]:
                if vector["protocol_name"] in supported_handshakes:
                    # Some test vectors specify empty lists instead of omitting the key completely
                    # which breaks check(), this simply removes those empty lists
                    keys = ["init_psks", "resp_psks"]
                    for key in keys:
                        if key in vector and vector[key] == []:
                            #print(f"removing empty list of key \"{key}\" from {vector['protocol_name']} ({test_vectors_file})")
                            del vector[key]

                    # Run the test
                    args = []

                    for variable in vector:
                        if variable in ["handshake_hash"]:
                            continue
                        elif variable == "messages":
                            for msg in vector[variable]:
                                args.append("--message")
                                args.append(msg["payload"])
                        elif variable == "init_psks" or variable == "resp_psks":
                            for msg in vector[variable]:
                                args.append(f"--{variable}")
                                args.append(msg)
                        else:
                            args.append(f"--{variable}")
                            args.append(vector[variable])

                    run_test_binary(test_binary, result_output_file, args)

                    with open(result_output_file, "r") as f:
                        result = json.load(f)

                    check(vector, result, test_vectors_file)
                    tested_handshakes.append(vector["protocol_name"])

    all_handshakes_tested = True
    for handshake in supported_handshakes:
        if not handshake in tested_handshakes:
            print(f"Handshake {handshake} does not have a test vector")
            all_handshakes_tested = False

    if not all_handshakes_tested:
        exit(1)

    exit(0)
