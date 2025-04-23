#!/usr/bin/env python3
import argparse

def arabic_to_ascii(word):
    """
    Convert an Arabic word to its ASCII-compatible Punycode representation.
    This utilizes Python's built-in 'idna' encoding.
    """
    try:
        punycode = word.encode('idna').decode('ascii')
        return punycode
    except Exception as e:
        return f"Error: {e}"

def main():
    # Set up argument parser to accept input and output file paths.
    parser = argparse.ArgumentParser(
        description="Convert a list of Arabic words to ASCII-compatible (Punycode) representations."
    )
    parser.add_argument("-l", "--list", required=True, help="Path to the input file containing Arabic words (one per line).")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file to save the Punycode results.")
    args = parser.parse_args()

    try:
        # Read Arabic words from the input file.
        with open(args.list, "r", encoding="utf-8") as infile:
            words = [line.strip() for line in infile if line.strip()]
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    # Convert each Arabic word to its ASCII-compatible representation.
    results = [arabic_to_ascii(word) for word in words]

    try:
        # Write the results to the output file.
        with open(args.output, "w", encoding="utf-8") as outfile:
            for result in results:
                outfile.write(result + "\n")
        print(f"Results have been saved to '{args.output}'.")
    except Exception as e:
        print(f"Error writing output file: {e}")

if __name__ == "__main__":
    main()
