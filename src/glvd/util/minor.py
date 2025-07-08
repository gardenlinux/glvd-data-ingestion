import re

def extract_minor(version):
     if version is None:
         return ''
     # Remove epoch if present (e.g., '1:' in '1:1.37.0-5')
     version = version.split(':', 1)[-1]
     # Extract the numeric part before any dash or plus
     main_part = re.split(r'[-+]', version)[0]
     # Split by dot and take first two numeric components
     parts = main_part.split('.')
     if len(parts) >= 2:
         return f"{parts[0]}.{parts[1]}"
     elif len(parts) == 1:
         return parts[0]
     else:
         return ''
