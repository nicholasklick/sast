
import tempfile

def create_temp_file():
    # Insecure temporary file creation
    filename = tempfile.mktemp()
    with open(filename, 'w') as f:
        f.write('This is a temporary file.')
    return filename

create_temp_file()
