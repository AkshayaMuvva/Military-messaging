#!/usr/bin/env python3
"""
Convert all rounded CSS borders to sharp box-style design with clip-path polygons
"""
import re
import os

# Mapping of border-radius values to clip-path corner sizes
CORNER_MAPPING = {
    '50%': None,  # Keep circular elements as-is (e.g., logo containers)
    '1.5rem': '20px',  # Large cards
    '1rem': '16px',     # Medium cards
    '0.75rem': '10px',  # Form elements, buttons
    '0.5rem': '8px',    # Small elements
    '5px': '5px',
}

def create_clip_path(corner_size):
    """Create clip-path polygon for angled corners"""
    return f"clip-path: polygon({corner_size} 0, 100% 0, 100% calc(100% - {corner_size}), calc(100% - {corner_size}) 100%, 0 100%, 0 {corner_size});"

def convert_file(filepath):
    """Convert a single template file to box-style"""
    print(f"\nProcessing: {filepath}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    conversions = 0
    
    # Find all border-radius declarations in CSS (not inline styles)
    # Pattern: border-radius: VALUE;
    pattern = r'border-radius:\s*([\d.]+(?:rem|px|%));\s*\n'
    
    def replace_border_radius(match):
        nonlocal conversions
        value = match.group(1)
        
        # Keep circular elements
        if value == '50%':
            return match.group(0)
        
        # Get corner size from mapping
        corner_size = CORNER_MAPPING.get(value, '10px')
        
        conversions += 1
        # Replace with border-radius: 0 and add clip-path
        return f'border-radius: 0;\n            {create_clip_path(corner_size)}\n'
    
    content = re.sub(pattern, replace_border_radius, content)
    
    # Also update borders to be sharper (1px -> 2px) in card-like elements
    # This is more nuanced, so we'll do it selectively
    
    if content != original_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  ✅ Converted {conversions} border-radius declarations")
        return True
    else:
        print(f"  ℹ️  No changes needed")
        return False

def main():
    templates_dir = r'c:\Users\yours\Desktop\Neural-Nomads-main\templates'
    
    # Skip already completed files
    skip_files = {'index.html', 'login.html', 'register.html'}
    
    files_to_convert = [
        'send_message.html',
        'inbox.html',
        'message_display.html',
        'status.html',
        'error.html',
        'message_destroyed.html',
        'user_keys.html'
    ]
    
    print("=" * 60)
    print("Converting templates to box-style design")
    print("=" * 60)
    
    converted = 0
    for filename in files_to_convert:
        filepath = os.path.join(templates_dir, filename)
        if os.path.exists(filepath):
            if convert_file(filepath):
                converted += 1
        else:
            print(f"⚠️  File not found: {filepath}")
    
    print("\n" + "=" * 60)
    print(f"✅ Conversion complete! Updated {converted} files.")
    print("=" * 60)

if __name__ == '__main__':
    main()
