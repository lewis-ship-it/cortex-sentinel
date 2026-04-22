import os

def generate_tree(startpath, exclude_dirs=None):
    if exclude_dirs is None:
        exclude_dirs = {'.git', '__pycache__', 'venv', '.env', 'node_modules', '.idea', '.vscode'}
    
    print(f"Project Structure: {os.path.basename(os.getcwd())}")
    
    for root, dirs, files in os.walk(startpath):
        # Modify dirs in-place to skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print(f"{indent}{os.path.basename(root)}/")
        
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            # Skip hidden files
            if not f.startswith('.'):
                print(f"{subindent}{f}")

if __name__ == "__main__":
    generate_tree('.')