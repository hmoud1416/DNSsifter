import argparse
import requests
import time

# Function to translate a single word to Arabic using Google Cloud Translation API
def translate_word_to_arabic_api(word, api_key):
    try:
        # Define the API endpoint and payload
        api_url = "https://translation.googleapis.com/language/translate/v2"
        payload = {
            "q": word,
            "source": "en",
            "target": "ar",
            "key": api_key
        }
        
        # Send the request to the Google Cloud Translation API
        response = requests.post(api_url, data=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        # Extract the translated word from the response
        translated_text = response.json().get("data", {}).get("translations", [{}])[0].get("translatedText", "")
        return translated_text.strip()
    
    except Exception as e:
        print(f"[!] Error translating word '{word}' with API: {e}")
        return None

# Function to translate a single word to Arabic using googletrans library
def translate_word_to_arabic_free(word, translator):
    try:
        # Translate the word to Arabic
        translated = translator.translate(word, src="en", dest="ar")
        return translated.text.strip()
    except Exception as e:
        print(f"[!] Error translating word '{word}' with googletrans: {e}")
        return None

# Main function to process a wordlist and generate Arabic translations
def translate_wordlist_to_arabic(wordlist_file, output_file, api_key=None):
    # Initialize the translator based on whether an API key is provided
    if api_key:
        print("[+] Using Google Cloud Translation API with API key...")
    else:
        print("[+] Using free googletrans library...")
        from googletrans import Translator
        translator = Translator()

    # Open the wordlist file and prepare the output file
    with open(wordlist_file, "r", encoding="utf-8") as infile, \
         open(output_file, "w", encoding="utf-8") as outfile:
        
        # Read all words from the wordlist
        words = infile.read().splitlines()
        total_words = len(words)
        print(f"[+] Total words to translate: {total_words}")
        
        # Iterate over each word and translate it
        for i, word in enumerate(words, start=1):
            if api_key:
                # Use the Google Cloud Translation API
                translated_word = translate_word_to_arabic_api(word, api_key)
            else:
                # Use the free googletrans library
                translated_word = translate_word_to_arabic_free(word, translator)
            
            if translated_word:
                # Write the result to the output file
                outfile.write(f"{word}\t{translated_word}\n")
                print(f"[+] ({i}/{total_words}) Translated: {word} -> {translated_word}")
            
            # Add a delay to avoid hitting API rate limits
            time.sleep(0.1)  # Adjust the delay as needed

# Entry Point
if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Translate English words to Arabic.")
    parser.add_argument("-l", "--wordlist", required=True, help="Path to the input wordlist file")
    parser.add_argument("-o", "--output", required=True, help="Path to save the output translations")
    parser.add_argument("-k", "--apikey", help="Google Cloud Translation API key (optional)")

    # Parse arguments
    args = parser.parse_args()

    # Run the translation process
    translate_wordlist_to_arabic(args.wordlist, args.output, args.apikey)
