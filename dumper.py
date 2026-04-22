import os

# CONFIGURATION: Add the specific folders or files you want to include
INCLUDE_LIST = {
    '.github',           # Includes the entire .github folder
    'intelligence',      # Includes the entire intelligence folder
    'storage',           # Includes the entire storage folder
    'core',              # Includes the entire core folder
    'api',               # Includes the entire api folder
    'task_queue',        # Includes the entire task_queue folder
    'workers',           # Includes the entire workers folder
    'scanner',           # Includes the entire scanner folder
    'app.py',            # Includes a specific file
    'api/main.py',       # Includes a nested file
    'requirements.txt',  # Includes config files
    'docker-compose.yml',# Includes config files
    'dockerfile',       # Includes config files
    'templates',         # Includes the entire templates folder
    'Procfile',         # Includes config files
        # Includes test files
        # Includes utility scripts

}

# EXTENSION FILTER: Only dump these types of files
ALLOWED_EXTENSIONS = {'.py', '.txt', '.md', '.yml', '.yaml', '.html', '.css', '.js'}

def is_selected(file_path, root_path):
    relative_path = os.path.relpath(file_path, root_path)
    
    # Check if the file itself is in the list
    if relative_path in INCLUDE_LIST:
        return True
    
    # Check if the file is inside one of the included folders
    for item in INCLUDE_LIST:
        if relative_path.startswith(item + os.sep) or relative_path.startswith(item + "/"):
            return True
            
    return False

def dump_selective_project(root_path, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"SELECTED PROJECT DUMP\nIncluded Items: {', '.join(INCLUDE_LIST)}\n\n")
        
        for root, dirs, files in os.walk(root_path):
            # Skip hidden directories like .git
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for filename in files:
                file_path = os.path.join(root, filename)
                
                # Check if this file is selected and has a valid extension
                if is_selected(file_path, root_path):
                    ext = os.path.splitext(filename)[1].lower()
                    if ext in ALLOWED_EXTENSIONS:
                        relative_path = os.path.relpath(file_path, root_path)
                        
                        f.write(f"\n{'='*20} FILE: {relative_path} {'='*20}\n\n")
                        try:
                            with open(file_path, 'r', encoding='utf-8') as src:
                                f.write(src.read())
                            f.write("\n")
                            print(f"Added: {relative_path}")
                        except Exception as e:
                            f.write(f"[Error reading file: {e}]\n")

if __name__ == "__main__":
    current_dir = os.getcwd()
    output_name = 'selective_project_dump.txt'
    dump_selective_project(current_dir, output_name)
    print(f"\n✅ Done! Dump saved to {output_name}")