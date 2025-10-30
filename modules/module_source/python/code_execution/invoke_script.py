import base64
import sys
import urllib.request

def download_script(script_url):
    """Download a Python script from a URL using urllib (part of standard library)."""
    try:
        with urllib.request.urlopen(script_url) as response:
            return response.read().decode('utf-8')
    except urllib.error.URLError as e:
        print("[!] Failed to download the script from %s: %s" % (script_url, str(e)))
        sys.exit(1)

def decode_base64_script(encoded_script):
    """Decode a base64-encoded Python script."""
    try:
        script_bytes = base64.b64decode(encoded_script)
        return script_bytes.decode('utf-8')
    except base64.binascii.Error as e:
        print("[!] Failed to decode the base64 script: %s" % str(e))
        sys.exit(1)

def execute_python_script(script_content, function_command=None):
    """Execute a Python script and optionally run a function/command."""
    try:
        script_globals = {}
        exec(script_content, script_globals)

        if function_command:
            function_parts = function_command.split(' ')
            function_name = function_parts[0]
            function_args = function_parts[1:]

            if function_name in script_globals:
                func = script_globals[function_name]
                output = func(*function_args)
                print(output)
            else:
                print("[!] Function '%s' not found in the script." % function_name)
    except Exception as e:
        print("[!] Failed to execute the Python script: %s" % str(e))
        sys.exit(1)

def main(encoded_script=None, script_url=None, function_command=None):
    script_content = None

    if script_url:
        script_content = download_script(script_url)
        encoded_script = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')

    if encoded_script:
        script_content = decode_base64_script(encoded_script)

    if not script_content:
        print("[!] No valid script provided (either as a URL or base64 encoded script).")
        sys.exit(1)

    execute_python_script(script_content, function_command)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Load and execute a Python script either from a URL or as a base64-encoded string, then optionally run a function within the script with parameters."
    )
    parser.add_argument('--encoded-script', help="Base64-encoded Python script")
    parser.add_argument('--script-url', help="URL to download a Python script from")
    parser.add_argument('--function-command', help="The function command to run after the script is loaded (e.g., 'my_function arg1 arg2')", default=None)

    args = parser.parse_args()

    main(args.encoded_script, args.script_url, args.function_command)
