#!/usr/bin/env python3
import argparse
from itertools import product

def arabic_to_english_phonetic(line, translation_dict):
    """
    Convert an Arabic word to its phonetic representations in English.
    """
    result = []
    for char in line:
        # Append possible translations or empty if the character isn't in the dictionary
        result.append(translation_dict.get(char, [""]))
    return combine_patterns(result)

def combine_patterns(patterns):
    """
    Combine all possible combinations of phonetic patterns.
    Example: [["a"], ["7", "h"], ["b"]] -> ["a7b", "ahb"]
    """
    if not patterns:
        return [""]
    return ["".join(comb) for comb in product(*patterns)]

# Arabic to English phonetic dictionary with alternative patterns
arabic_to_english_dict = {
    "ء": [""],
    "ا": ["a"],
    "أ": ["a"],
    "إ": ["i"],
    "آ": ["aa"],
    "ب": ["b"],
    "ت": ["t"],
    "ث": ["th", "z"],
    "ج": ["j"],
    "ح": ["h", "7"],
    "خ": ["kh", "5"],
    "د": ["d"],
    "ذ": ["dh", "z"],
    "ر": ["r"],
    "ز": ["z"],
    "س": ["s"],
    "ش": ["sh"],
    "ص": ["s"],
    "ض": ["d"],
    "ط": ["t", "6"],
    "ظ": ["z"],
    "ع": ["", "3"],
    "غ": ["gh", "3"],
    "ف": ["f"],
    "ق": ["q", "8"],
    "ك": ["k"],
    "ل": ["l"],
    "م": ["m"],
    "ن": ["n"],
    "ه": ["h"],
    "و": ["w"],
    "ي": ["y"],
    "ة": ["h"],
}

def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="Convert Arabic words to their English phonetic representation.")
    parser.add_argument("-l", "--list", required=True, help="Path to the input file containing Arabic words.")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file to save unique phonetic words.")
    args = parser.parse_args()

    input_file = args.list
    output_file = args.output

    # Initialize a set to store unique phonetic words
    unique_phonetics = set()

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            print("Processing Arabic to Phonetic Translations...")
            for line in file:
                line = line.strip()  # Remove extra spaces and newlines
                phonetic_translations = arabic_to_english_phonetic(line, arabic_to_english_dict)
                unique_phonetics.update(phonetic_translations)  # Add all possible patterns

        # Save unique phonetic words to the output file
        with open(output_file, "w", encoding="utf-8") as outfile:
            for word in sorted(unique_phonetics):  # Sort for better readability
                outfile.write(word + "\n")

        print(f"Unique phonetic words have been saved to '{output_file}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
