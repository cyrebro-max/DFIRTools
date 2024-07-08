from configparser import ConfigParser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from collections import OrderedDict
import subprocess
import shutil
import py7zr
import os

# Define the default configuration options with ordered sections
config_options = OrderedDict([
    ('Forensic Action', OrderedDict([
        ('Parse', 'no'),
        ('Collect', 'no')
    ])),
    ('System Information', OrderedDict([
        ('Processes', 'no'),
        ('Processes Including Service Names', 'no'),
        ('Process Hashes', 'no'),
        ('System Information', 'no'),
        ('Drivers', 'no'),
        ('Drives', 'no'),
        ('Local Users', 'no'),
        ('Local Groups', 'no'),
        ('Kerberos Tickets', 'no'),
        ('Domain Information', 'no')
    ])),
    ('Program Execution', OrderedDict([
        ('Sysinternals Executions', 'no'),
        ('Amcache \\ RecentFileCache', 'no'),
        ('Program Compatibility Assistant (PCA)', 'no'),
        ('Jump Lists', 'no'),
        ('Prefetches', 'no'),
        ('UserAssist', 'no'),
        ('Shimcache', 'no'),
        ('Powershell History', 'no'),
        ('WMI OBJECTS.DATA', 'no'),
        ('ActivitiesCache', 'no'),
        ('BAM', 'no')
    ])),
    ('File Download', OrderedDict([
        ('Downloads Folders', 'no'),
        ('Installed Programs', 'no')
    ])),
    ('Network Activity', OrderedDict([
        ('TCP Connections', 'no'),
        ('Network Adapters', 'no'),
        ('Network IP Address', 'no'),
        ('Network IP Configuration', 'no'),
        ('Named Pipes', 'no'),
        ('Hosts file', 'no'),
        ('Network Shares', 'no'),
        ('Route Print', 'no'),
        ('ARP Table', 'no'),
        ('SRUM', 'no'),
        ('Active Sessions', 'no'),
        ('DNS Client Cache', 'no'),
        ('RDP Direct Connections', 'no'),
        ('RDP Connections in Registry', 'no'),
        ('NetworkCards Connections', 'no'),
        ('PuTTY SSH Connections', 'no'),
        ('WinSCP Connections', 'no'),
        ('FileZilla Files', 'no')
    ])),
    ('File and Folder Usage', OrderedDict([
        ('MFT Collect', 'no'),
        ('MFT Parse', 'no'),
        ('UsnJournal', 'no'),
        ('Recent Documents - From Registry', 'no'),
        ('WinkeyR History (Run)', 'no'),
        ('Recent Folders', 'no'),
        ('Recycle Bins folder and TLE file', 'no'),
        ('Temporary Burn Folders', 'no'),
        ('WordWheelQuery', 'no'),
        ('ShellBags', 'no'),
        ('WinRAR History', 'no'),
        ('7-Zip History', 'no'),
        ('Temp Folders', 'no')
    ])),
    ('Office Documents Usage', OrderedDict([
        ('Recent Office', 'no'),
        ('Unsaved Office Files', 'no'),
        ('Outlook Opened Files Folder', 'no'),
        ('Office Documents History', 'no'),
        ('ReadingLocations', 'no')
    ])),
    ('USB and External Device Usage', OrderedDict([
        ('USB History', 'no'),
        ('Mount Points', 'no'),
        ('Windows Portable Devices', 'no')
    ])),
    ('Browser Usage', OrderedDict([
        ('Chrome Files', 'no'),
        ('Internet Explorer Files', 'no'),
        ('Firefox Files', 'no'),
        ('Edge Files', 'no')
    ])),
    ('Persistence Artifacts', OrderedDict([
        ('All Scheduled Tasks', 'no'),
        ('Services', 'no'),
        ('Autoruns', 'no'),
        ('WMI Providers', 'no'),
        ('Start Menu Programs', 'no'),
        ('User Startup Programs', 'no'),
        ('Accessibility Features', 'no')
    ])),
    ('Additional Artifacts', OrderedDict([
        ('Registry Hives', 'no'),
        ('Event Logs', 'no'),
        ('SQL Logs', 'no'),
        ('IIS Logs', 'no'),
        ('TeamViewer Logs', 'no'),
        ('AnyDesk Logs', 'no'),
        ('MegaSync Files', 'no'),
        ('WmiExec Output Files', 'no')
    ]))
])

class CaseSensitiveConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

class CategoryCheckbox(ttk.Checkbutton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sub_options = []

##def zip_folder_with_password(folder_path, zip_file_name, password):
##    # Create the command to execute
##    command = ['7z', 'a', '-tzip', '-p{}'.format(password), zip_file_name, folder_path]
##
##    # Run the command using subprocess
##    try:
##        subprocess.run(command, check=True)
##        print(f'Successfully created password-protected zip archive: {zip_file_name}')
##    except subprocess.CalledProcessError as e:
##        print(f'Error occurred: {e}')

def zip_folder_with_password(folder_path, zip_file_name, password):
    if not zip_file_name.endswith('.zip'):
        zip_file_name += '.zip'

    with py7zr.SevenZipFile(zip_file_name, 'w', password=password) as archive:
        for foldername, subfolders, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                arcname = os.path.relpath(file_path, folder_path)
                archive.write(file_path, arcname)
    
    print(f'Successfully created password-protected zip archive: {zip_file_name}')

def generate_config_file():
    config_parser = CaseSensitiveConfigParser()
    
    case_name = case_name_entry.get().strip()
    if not case_name:
        messagebox.showerror("Error", "Please enter a valid case name.")
        return

    # Create a directory for the case name if it doesn't exist
    case_directory = f"CYREBRO Windows Collector - {case_name}"
    if not os.path.exists(case_directory):
        os.makedirs(case_directory)

    # Create a directory for dependencies within the case directory if it doesn't exist
    dependencies_directory = os.path.join(case_directory, "Dependencies")
    if not os.path.exists(dependencies_directory):
        os.makedirs(dependencies_directory)

    config = CaseSensitiveConfigParser()

    # Update the configuration options based on checkbox selections
    for section, options in config_options.items():
        config[section] = {}
        for option, value in options.items():
            config[section][option] = 'yes' if value.get() else 'no'

    # Save the additional files to the configuration file
    additional_files = get_additional_files()
    if additional_files:
        config['Additional Files'] = additional_files

    # Save the configuration to a file within the case directory
    config_file_path = os.path.join(case_directory, 'config.ini')
    with open(config_file_path, 'w') as config_file:
        config.write(config_file)

    # Check if any of the specified options are selected
    copy_rawcopy = any(config_options[section].get(option, False) for section, options in config_options.items() for option in ['SRUM', 'Internet Explorer Files', 'Amcache', 'MFT Collect', 'Registry Hives'])


    if copy_rawcopy:
        # Copy RawCopy from the Dependencies folder
        shutil.copy("Dependencies/RawCopy.exe", dependencies_directory)

    # Copy the required files based on selected options to the dependencies directory
    for section, options in config_options.items():
        for option, value in options.items():
            if value.get():
                if option == 'Jump Lists':
                    shutil.copy("Dependencies/JLECmd.exe", dependencies_directory)
                elif option == 'ShellBags':
                    shutil.copy("Dependencies/SBECmd.exe", dependencies_directory)
                elif option == 'SRUM':
                    shutil.copy("Dependencies/SrumECmd.exe", dependencies_directory)
                elif option == 'Shimcache':
                    shutil.copy("Dependencies/AppCompatCacheParser.exe", dependencies_directory)
                elif option == 'Amcache \\ RecentFileCache':
                    shutil.copy("Dependencies/AmcacheParser.exe", dependencies_directory)
                elif option == 'Autoruns':
                    shutil.copy("Dependencies/autorunsc.exe", dependencies_directory)
                elif option == 'UsnJournal':
                    shutil.copy("Dependencies/ExtractUsnJrnl.exe", dependencies_directory)
                elif option == 'MFT Parse':
                    shutil.copy("Dependencies/MFTECmd.exe", dependencies_directory)

    # Copy the file specified in the path textbox to the case directory
    additional_file_path = bamboo_entry.get().strip()
    if additional_file_path:
        additional_file_name = os.path.basename(additional_file_path)
        destination_path = os.path.join(case_directory, additional_file_name)
        shutil.copy(additional_file_path, destination_path)

    ## Zip the contents of the case directory with password protection
    zip_file_path = os.path.join(os.getcwd(), f"{case_directory}.zip")
    password = "CyR3br0!%#"
    zip_folder_with_password(case_directory,zip_file_path,password)
    
    ## Remove the case directory after creating the zip file
    shutil.rmtree(case_directory)

    messagebox.showinfo(
        "Success",
        "Config file and required files have been generated."
    )

def update_category_options(event):
    category_checkbox = event.widget
    sub_options = category_checkbox.sub_options

    # Update the options based on the category checkbox state
    category_checkbox_value = category_checkbox.var.get()
    for option_checkbox, var in sub_options:
        var.set(not category_checkbox_value)

def create_option_checkbox(frame, option, value):
    var = tk.BooleanVar(value=value == 'yes')
    checkbox = ttk.Checkbutton(frame, text=option, variable=var)
    checkbox.grid(row=len(frame.winfo_children()), column=0, sticky='w', padx=(40, 0))  # Adjust the column and add padding
    return checkbox, var

def create_additional_file_entry(frame):
    entry = ttk.Entry(frame, width=50)
    entry.grid(row=len(frame.winfo_children()), column=0, sticky='w', padx=(40, 0), pady=5)  # Adjust the column and add padding
    return entry

def add_additional_file():
    additional_file_entry = create_additional_file_entry(additional_files_frame)
    additional_files_entries.append(additional_file_entry)
    canvas.update_idletasks()  # Update the canvas to display the newly added entry
    frame.update_idletasks()  # Update the scrollable frame
    canvas.configure(scrollregion=canvas.bbox('all'))  # Adjust the scrollable region

def get_additional_files():
    additional_files = OrderedDict()
    for i, entry in enumerate(additional_files_entries):
        path = entry.get().strip()
        if path:
            # Add quotation marks if not already present
            if not (path.startswith('"') and path.endswith('"')):
                path = f'"{path}"'
            additional_files[f'Path{i+1}'] = path
    return additional_files

def browse_bamboo_path():
    # Get the current working directory
    current_directory = os.getcwd()

    # Open the file explorer dialog in the current directory
    filepath = filedialog.askopenfilename(initialdir=current_directory, filetypes=[('Executable Files', '*.exe')])

    # Update the selected filepath in the entry field
    bamboo_entry.delete(0, tk.END)
    bamboo_entry.insert(tk.END, filepath)

# Create the GUI application
root = tk.Tk()
root.title('Bamboo Package Generator')
root.geometry("450x400")  # Set the window size to 400x400 pixels
root.resizable(False, False)

# Create a frame for the case name entry
case_name_frame = ttk.Frame(root)
case_name_frame.pack(pady=10, padx=20, anchor='w')

# Create the "Case Name" label and entry
case_name_label = ttk.Label(case_name_frame, text="Case Name:")
case_name_label.pack(side='left')

case_name_entry = ttk.Entry(case_name_frame, width=30)
case_name_entry.pack(side='left')

# Create the "Select Bamboo" feature
bamboo_frame = ttk.Frame(root)
bamboo_frame.pack(pady=(0, 10), padx=20, anchor='w')

bamboo_label = ttk.Label(bamboo_frame, text="Select Bamboo:")
bamboo_label.pack(side='left')

bamboo_entry = ttk.Entry(bamboo_frame, width=30)
bamboo_entry.pack(side='left')

browse_button = ttk.Button(bamboo_frame, text='Browse', command=browse_bamboo_path)
browse_button.pack(side='left')

# Create a scrollable frame
scroll_frame = ttk.Frame(root)
scroll_frame.pack(fill='both', expand=True)

canvas = tk.Canvas(scroll_frame)
canvas.pack(side='left', fill='both', expand=True)

scrollbar = ttk.Scrollbar(scroll_frame, orient='vertical', command=canvas.yview)
scrollbar.pack(side='right', fill='y')

canvas.configure(yscrollcommand=scrollbar.set)
canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))

frame = ttk.Frame(canvas)
canvas.create_window((0, 0), window=frame, anchor='nw')

# Bind the mouse wheel event to scroll the Canvas
canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(-1 * (event.delta // 120), "units"))

# Create checkboxes for each configuration option
for row, (section, options) in enumerate(config_options.items()):
    section_frame = ttk.Frame(frame)
    section_frame.grid(row=row, column=0, sticky='w', padx=20)  # Add padding

    # Create a category checkbox
    category_var = tk.BooleanVar()
    category_checkbox = CategoryCheckbox(section_frame, text=section, variable=category_var)
    category_checkbox.grid(row=0, column=0, sticky='w')
    category_checkbox.var = category_var  # Store the variable reference

    # Bind the category checkbox to the update function
    category_checkbox.sub_options = []
    category_checkbox.bind('<Button-1>', update_category_options)

    # Create checkboxes for options within the category
    for col, (option, default_value) in enumerate(options.items()):
        checkbox, var = create_option_checkbox(section_frame, option, default_value)
        options[option] = var
        category_checkbox.sub_options.append((checkbox, var))

# Create the "Additional Files" section
additional_files_frame = ttk.Frame(frame)
additional_files_frame.grid(row=len(config_options), column=0, sticky='w', pady=(10, 0), padx=20)  # Add padding

additional_files_label = ttk.Label(additional_files_frame, text='Additional Files:')
additional_files_label.grid(row=0, column=0, sticky='w')

additional_files_entries = []
add_file_button = ttk.Button(additional_files_frame, text='+ Add File', command=add_additional_file)
add_file_button.grid(row=1, column=0, sticky='w')

# Create a button to generate the config file
generate_button = ttk.Button(root, text='Create Package', command=generate_config_file)
generate_button.pack(pady=10)

# Start the GUI event loop
root.mainloop()
