#!/usr/bin/env python3

import time
import os
from cryptography.fernet import Fernet
import sys
import keyboard
import pyfiglet
import subprocess
import platform

def show_loading_animation(duration):
    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        animation = "|/-\\"
        for char in animation:
            print(f"\rPlease Wait.. {char}", end="")
            sys.stdout.flush()
            time.sleep(0.1)

    # Clear the line after the loading animation
    print("\r" + " " * 20 + "\r")

print('''                                                                                                                                                                                                                                                                          
VVVVVVVV           VVVVVVVV                                lllllll         tttt          lllllll                                           
V::::::V           V::::::V                                l:::::l      ttt:::t          l:::::l                                           
V::::::V           V::::::V                                l:::::l      t:::::t          l:::::l                                           
V::::::V           V::::::V                                l:::::l      t:::::t          l:::::l                                           
 V:::::V           V:::::Vaaaaaaaaaaaaa  uuuuuu    uuuuuu   l::::lttttttt:::::ttttttt     l::::lyyyyyyy           yyyyyyynnnn  nnnnnnnn    
  V:::::V         V:::::V a::::::::::::a u::::u    u::::u   l::::lt:::::::::::::::::t     l::::l y:::::y         y:::::y n:::nn::::::::nn  
   V:::::V       V:::::V  aaaaaaaaa:::::au::::u    u::::u   l::::lt:::::::::::::::::t     l::::l  y:::::y       y:::::y  n::::::::::::::nn 
    V:::::V     V:::::V            a::::au::::u    u::::u   l::::ltttttt:::::::tttttt     l::::l   y:::::y     y:::::y   nn:::::::::::::::n
     V:::::V   V:::::V      aaaaaaa:::::au::::u    u::::u   l::::l      t:::::t           l::::l    y:::::y   y:::::y      n:::::nnnn:::::n
      V:::::V V:::::V     aa::::::::::::au::::u    u::::u   l::::l      t:::::t           l::::l     y:::::y y:::::y       n::::n    n::::n
       V:::::V:::::V     a::::aaaa::::::au::::u    u::::u   l::::l      t:::::t           l::::l      y:::::y:::::y        n::::n    n::::n
        V:::::::::V     a::::a    a:::::au:::::uuuu:::::u   l::::l      t:::::t    tttttt l::::l       y:::::::::y         n::::n    n::::n
         V:::::::V      a::::a    a:::::au:::::::::::::::uul::::::l     t::::::tttt:::::tl::::::l       y:::::::y          n::::n    n::::n
          V:::::V       a:::::aaaa::::::a u:::::::::::::::ul::::::l     tt::::::::::::::tl::::::l        y:::::y           n::::n    n::::n
           V:::V         a::::::::::aa:::a uu::::::::uu:::ul::::::l       tt:::::::::::ttl::::::l       y:::::y            n::::n    n::::n
            VVV           aaaaaaaaaa  aaaa   uuuuuuuu  uuuullllllll         ttttttttttt  llllllll      y:::::y             nnnnnn    nnnnnn
                                                                                                      y:::::y                              
                                                                A Fernet Cryptographic Vault.        y:::::y                by Sidharth P.L
                                                                                                    y:::::y                                
                                                                                                   y:::::y                                 
                                                                                                  yyyyyyy                                                                                                                                                                                                                                                                                                                                                                             
''')
print("Welcome to (Vaultlyn) The Fernet Cryptographic Vault V1.4.5")
print("©Medusa Infosystems India")
show_loading_animation(3)

def getpass_asterisk(prompt):
    if platform.system() == 'Windows':
        import msvcrt
        print(prompt, end='', flush=True)
        password = ''
        while True:
            char = msvcrt.getch().decode('utf-8')
            if char == '\r' or char == '\n':
                print()
                break
            elif char == '\b' and password:
                password = password[:-1]
                print('\b \b', end='', flush=True)
            else:
                password += char
                print('*', end='', flush=True)
    else:
        import termios
        import tty
        print(prompt, end='', flush=True)
        password = ''
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                char = sys.stdin.read(1)
                if char == '\r' or char == '\n':
                    print()
                    break
                elif char == '\b' and password:
                    password = password[:-1]
                    print('\b \b', end='', flush=True)
                else:
                    password += char
                    print('*', end='', flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return password
    
    #Replace the '/path/to/directory' according to your system, locate the directory which you created.

if os.path.exists("/path/to/directory/SFCV_Decrypting_Passcode/user_name.txt"):
    user_name_file = "/path/to/directory/SFCV_Decrypting_Passcode/user_name.txt"
    with open(user_name_file, "r") as file:
        user_name_content = file.read()
        user_name = user_name_content

    welcometext = f"Welcome, {user_name}"
    font = "small"

    welcome_with_username = pyfiglet.figlet_format(welcometext, font=font)
    print(welcome_with_username)
else:
    uname_welcome = f"Welcome to Vaultlyn"
    font = "small"
    welcome_without_username = pyfiglet.figlet_format(uname_welcome, font=font)

#print(f"Welcome to your Vault, {user_name}")
print("*Please run the setup if Running for the first time.* Default Passcode = 'ApplePie'")
while True:
    print('''             -----------------------------------------------------------
             |                Choose an option:                        |
             |                                                         | 
             |    [1] Encrypt	                 [2] Decrypt           |
             |                                                         |
             |                                                         |
             |    [3] Change Passcode            [4] What's this       |
             |                                                         |
             |                                                         |
             |    [5] Terminate Program          [6] Forget Passcode   |
             |                                                         |
             |                                                         |
             |    [7] Nominee Login              [8] Change User Info  |
             |                                                         |
             |                                                         |
             |    [0] Run Setup                                        |
             |                                                         |
             -----------------------------------------------------------''')

    mainMenu = input("Choose any option between 1-8: ")

    if os.path.exists("/path/to/directory/SFCV_Decrypting_Passcode/decryption_passcode.txt"):

        decryption_current_passcode = "/path/to/directory/SFCV_Decrypting_Passcode/decryption_passcode.txt"
        with open(decryption_current_passcode, "r") as file:
            decryption_passcode_content = file.read()

        decryption_passcode = decryption_passcode_content
    else:
        print("Passcode Configuration file not found. Switching to Default passcode.")
        decryption_passcode = "ApplePie"

    if mainMenu == '1':
        files = []
        for file in os.listdir():
            if file == "sfcv.py" or file == "thekey.key":
                continue
            if os.path.isfile(file):
                files.append(file)
        print(files)

        initialInp = input("Do you wish to encrypt all the files in this directory? (Y/N): ")
        if initialInp.lower() == 'y':
            key = Fernet.generate_key()

            with open("thekey.key", "wb") as thekey:
                thekey.write(key)

            for file in files:
                with open(file, "rb") as thefile:
                    contents = thefile.read()
                contents_encrypted = Fernet(key).encrypt(contents)
                with open(file, "wb") as thefile:
                    thefile.write(contents_encrypted)
            
            print("This directory is now encrypting")
            show_loading_animation(2)
            print("Encryption successful.")
            time.sleep(3)
        else:
            print("Vaultlyn Encryption Terminated.")

    elif mainMenu == '2':
        print("Please enter your passcode for Decrypting your files.")
        show_loading_animation(1)
        chances = 3

        while chances > 0:
            phrase = getpass_asterisk("Enter the verification phrase: ")

            if phrase == decryption_passcode:
                print("Verification successful!")
                files = []

                for file in os.listdir():
                    if file == "sfcv.py" or file == "thekey.key":
                        continue
                    if os.path.isfile(file):
                        files.append(file)
                
                print(files)

                with open("thekey.key", "rb") as key:
                    secretkey = key.read()
                
                print("Passcode Verified successfully.")
                for file in files:
                    with open(file, "rb") as thefile:
                        contents = thefile.read()
                    contents_decrypted = Fernet(secretkey).decrypt(contents)
                    with open(file, "wb") as thefile:
                        thefile.write(contents_decrypted)
                show_loading_animation(2)
                print("Files Decrypted successfully")
                time.sleep(3)
                break

            else:
                chances -= 1
                print(f"Verification failed! {chances} chances remaining.")

            if chances == 0:
                print("Verification failed! Exiting...")
    elif mainMenu == '3':
        verify_for_changing = getpass_asterisk("Enter the current passcode: ")
        print("Verification Successful..")
        show_loading_animation(2)
        if verify_for_changing == decryption_passcode:    
            change_d_passcode = input("Enter a passcode to set for decryption: ")

            d_passcode = "/path/to/directory/SFCV_Decrypting_Passcode/decryption_passcode.txt"

            with open(d_passcode, "w") as file:
                file.write(change_d_passcode)
            show_loading_animation(1)
            print("Passcode is set successfully..")
        else:
            print("Verification Failed..")
            show_loading_animation(2)
    elif mainMenu == '4':
        print('''This is Vaultlyn, A Fernet Cryptography Vault Program. Made by Sidharth from Medusa Infosystems.
        This Program was made by Python and Cryptography.Fernet Library to function. The syntax is so simple and made for free for public users to use.
        Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key.
        Fernet is an implementation of symmetric (also known as “secret key”) authenticated cryptography.
        Fernet also has support for implementing key rotation''')
        show_loading_animation(4)
        moveToMenu = input("(Hit enter to go to Main Menu) ")
        pass
    elif mainMenu == '5':
        print("Program Terminated..")
        show_loading_animation(3)
        sys.exit()
    elif mainMenu == '6':
        print("Please answer the security questions to reset the passcode.")
        show_loading_animation(1)
        firstSchl = input("What is the first school you attended: ")
        print("Verified")
        show_loading_animation(1)
        if firstSchl.lower() == 'ezhil montessori':
            nickname = input("What is your childhood nickname: ")
            print("Verified")
            show_loading_animation(1)
            if nickname.lower() == 'sidhu':
                bestfriend = input("What is your bestfriend's name: ")
                print("Verified")
                show_loading_animation(1)
                if bestfriend.lower() == 'shreyas':
                    print("Verification success.")
                    show_loading_animation(1)
                    newPasscode = input("Enter the new passcode: ")

                    d_passcode = "/path/to/directory/SFCV_Decrypting_Passcode/decryption_passcode.txt"

                    with open(d_passcode, "w") as file:
                        file.write(newPasscode)
                        show_loading_animation(1)
                        print("Passcode is set successfully..")
                        def on_key_press(event):
                            if event.name == 'enter':
                                pass
                        keyboard.on_press(on_key_press)
                else:
                    print("Verification Failed.")
                    show_loading_animation(1)
                    pass
            else:
                print("Verification failed")
                show_loading_animation(1)
                pass
        else:
            print("Verification failed")
            show_loading_animation(1)
    elif mainMenu == '7':
        print(f"You have selected Nominee login. This login method is created for people who can access this file other than {user_name}.")
        show_loading_animation(1)

        nominee_1_path = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_1.txt"
        nominee_1_relation_path = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_1_relation.txt"
        if os.path.exists(nominee_1_path):
            nominee_2_path = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_2.txt"
            nominee_2_relation_path = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_2_relation.txt"
            if os.path.exists(nominee_2_path):
                show_loading_animation(2)
                print(f"{user_name} have 2 Nominees for this vault.")
                with open(nominee_1_path, 'r') as file:
                    nominee_1_show = file.read()
                with open(nominee_2_path, 'r') as file:
                    nominee_2_show = file.read()
                print(f"[1] {nominee_1_show}    [2] {nominee_2_show}")
                nominees_input = input("Enter the Nominee no: ")
                if nominees_input == '1':
                    with open(nominee_1_relation_path,'r') as file:
                        nominee1_relation_show = file.read()
                    print(f"You have selected {nominee_1_show}.")
                    print(f"You are {user_name}'s {nominee1_relation_show}.")
                    show_loading_animation(1)
                    print("[1] View Files     [2] Nominee Decryption access")
                    nominee_1_action = input(f"Hello, {nominee_1_show}! What would you like to do: ")
                    if nominee_1_action == '1':
                        current_file_path = os.path.abspath(__file__)
                        file_directory = os.path.dirname(current_file_path)
                        os.startfile(file_directory)
                    elif nominee_1_action == '2':
                        print(f"Sorry, {user_name} has not given you that rights.")
                        #Can modify according to your needs.
                    pass
                    #Action for the Nominee 1::
                elif nominees_input == '2':
                    with open(nominee_2_relation_path,'r') as file:
                        nominee2_relation_show = file.read()
                    print(f"You have selected {nominee_2_show}.")
                    show_loading_animation(2)
                    print(f"You are {user_name}'s {nominee2_relation_show}.")
                    show_loading_animation(1)
                    print("[1] View Files     [2] Nominee Decryption access")
                    nominee_2_action = input(f"Hello, {nominee_2_show}! What would you like to do: ")
                    if nominee_2_action == '1':
                        current_file_path = os.path.abspath(__file__)
                        file_directory = os.path.dirname(current_file_path)
                        os.startfile(file_directory)
                    elif nominee_2_action == '2':
                        print(f"Sorry, {user_name} has not given you that rights.")
                        #Can modify according to your needs.
                else:
                    print("Sorry, Please enter a valid Nominee number. Try Again..")
                    pass
            else:
                show_loading_animation(2)
                print(f"{user_name} have 1 Nominee for this vault.")
                with open(nominee_1_path, 'r') as file:
                    nominee_1_show = file.read()
                print(f"[1] {nominee_1_show}")
                nominees_input = input("Enter Nominee Number (1) (If you are a legal gaurdian and not listed, Please hit 'g' and hit enter): ")
                if nominees_input == '1':
                    print(f"You have selected {nominee_1_show}.")
                    show_loading_animation(2)
                    print(f"You are {user_name}'s {nominee1_relation_show}.")
                    show_loading_animation(1)
                    print("[1] View decrypted files     [2] Nominee Decryption access")
                    nominee_1_action = input(f"Hello, {nominee_1_show}! What would you like to do: ")
                    if nominee_1_action == '1':
                        current_file_path = os.path.abspath(__file__)
                        file_directory = os.path.dirname(current_file_path)
                        os.startfile(file_directory)
                    elif nominee_1_action == '2':
                        print(f"Sorry, {user_name} has not given you that rights.")
        else:
            show_loading_animation(2)
            print(f"{user_name} have no nominees for this vault.")
            pass
    elif mainMenu == '8':
        infoPass = getpass_asterisk("Please enter your passcode: ")
        if infoPass == decryption_passcode:
            print("What info would you like to change..")
            print("[1] Name     [2] E-mail     [3] Edit Nominees")
            infoEdit = input("Choose an option between(1-3): ")
            if infoEdit == '1':
                change_user_name = input("Enter the new Name: ")

                user_name_file = "/path/to/directory/SFCV_Decrypting_Passcode/user_name.txt"

                with open(user_name_file, "w") as file:
                    file.write(change_user_name)
                show_loading_animation(1)
                print("Name updated successfully")
            elif infoEdit == '2':
                email_area = input("Please enter your E-Mail: ")

                user_mail_file = "/path/to/directory/SFCV_Decrypting_Passcode/user_mail.txt"

                with open(user_mail_file, "w") as file:
                    file.write(email_area)
                show_loading_animation(1)
                print("E-Mail has been updated successfully.")
            elif infoEdit == '3':
                nominee_1_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_1.txt"
                nominee_2_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_2.txt"
                nominee_1_relation_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_1_relation.txt"
                nominee_2_relation_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_2_relation.txt"
                show_loading_animation(2)
                if os.path.exists(nominee_2_file):
                    with open(nominee_1_file, 'r') as file:
                        nominee_1_show = file.read()
                    with open(nominee_2_file, 'r') as file:
                        nominee_2_show = file.read()
                    print(f"{user_name} has two nominees for this vault.")
                    print(f"[1] {nominee_1_show}    [2] {nominee_2_show}")
                    nominee_edit_select = input("Select a nominee: ")
                    if nominee_edit_select == '1':
                        show_loading_animation(1)
                        nominee_1_name = input("Please enter the nominee's name: ")
                        show_loading_animation(1)
                        nominee_1_relation = input(f"Please enter your relationship with {nominee_1_name}: ")
                        with open(nominee_1_file, 'w') as file:
                            file.write(nominee_1_name)
                        with open(nominee_1_relation_file, 'w') as file:
                            file.write(nominee_1_relation)
                        show_loading_animation(2)
                        print("Nominee successfully edited.")
                    elif nominee_edit_select == '2':
                        nominee_2_name = input("Please enter the nominee's name: ")
                        show_loading_animation(1)
                        nominee_2_relation = input(f"Please enter your relationship with {nominee_2_name}: ")
                        with open(nominee_2_file, 'w') as file:
                            file.write(nominee_2_name)
                        with open(nominee_2_relation_file, 'w') as file:
                            file.write(nominee_2_relation)
                        show_loading_animation(2)
                        print("Nominee successfully edited.")
                    else:
                        print("Sorry, No data found")
                        continue
                else:
                    add_nominee_2_req = input("Are you trying to add a new nominee to the vault?(y/n): ")
                    if add_nominee_2_req.lower() == 'y':
                        add_nominee_2 = input("Enter the new Nominee name: ")
                        add_nominee_2_relation = input(f"What is your relationship with the {add_nominee_2}: ")
                        with open(nominee_2_file, 'w') as file:
                            file.write(add_nominee_2)
                        with open(nominee_2_relation_file, 'w') as file:
                            file.write(add_nominee_2_relation)
                    else:
                        show_loading_animation(1)
                        nominee_1_name = input("Please enter the nominee's name: ")
                        show_loading_animation(1)
                        nominee_1_relation = input(f"Please enter your relationship with {nominee_1_name}: ")
                        with open(nominee_1_file, 'w') as file:
                            file.write(nominee_1_name)
                        with open(nominee_1_relation_file, 'w') as file:
                            file.write(nominee_1_relation)
                        show_loading_animation(2)
                        print("Nominee successfully edited.")
        else:
            print("Choose a vaid option. Try Again")
            pass
    elif mainMenu == '0':
        print("Welcome to Vaultlyn Setup.")
        show_loading_animation(1)
        print("Please wait...")
        show_loading_animation(1)
        print("Before proceeding with the setup. Please create these text files on these folder,")
        operating_system = sys.platform
        if operating_system.startswith('win'):
            print("Please create a folder as C:/Users/User/SFCV_Decrypting_Passcode/")
            show_loading_animation(1)
            print("Please configure the file path in the code. (You can replace them all at once)")
            confrmtn1 = input("If you have already configured please press 'y' and skip this process. If not, just hit enter normally.")
            if confrmtn1 == 'y':
                pass
            else:
                try:
                    source_path = sys.argv[0]
                    editor = 'notepad'
                    subprocess.Popen([editor, source_path])
                except Exception as e:
                    print(f"An error occured: {e}")
                    pass
        elif operating_system.startswith('linux'):
            print("Please create a folder as /Home/USER/SFCV_Decrypting_Passcode/")
            show_loading_animation(1)
            print("Please configure the file path in the code. (You can replace them all at once)")
            confrmtn1 = input("If you have already configured please press 'y' and skip this process. If not, just hit enter normally.")
            if confrmtn1 == 'y':
                pass
            else:
                try:
                    source_path = sys.argv[0]
                    editor = 'xdg-open'
                    subprocess.Popen([editor, source_path])
                except Exception as e:
                    print(f"An error occured: {e}")
                    pass
        else:
            print("We are sorry, Vaultlyn is officially unsupported for this OS. But you can modify the source code to use this program in your platform.")
        show_loading_animation(1)
        nameInput = input("Please enter your name: ")
        user_name_file = "/path/to/directory/SFCV_Decrypting_Passcode/user_name.txt"
        with open(user_name_file, "w") as file:
            file.write(nameInput)
        show_loading_animation(1)
        print("Name successfully loaded.")
        mail_input = input("Please enter your E-Mail Address: ")
        user_mail_file = "/path/to/directory/SFCV_Decrypting_Passcode/user_mail.txt"
        with open(user_mail_file, "w") as file:
            file.write(mail_input)
        show_loading_animation(1)
        print("Mail successfully loaded")
        passcode_input = getpass_asterisk("Please setup a Passcode for the vault: ")
        d_passcode = "/path/to/directory/SFCV_Decrypting_Passcode/decryption_passcode.txt"
        with open(d_passcode, "w") as file:
            file.write(passcode_input)
        print("Passcode has been set successfully.")
        show_loading_animation(1)
        print("Now let's add nominees to your vault. These nominees can access your vault when you're not available.")
        show_loading_animation(3)
        nominee_1_reg = input("Please enter a nominee who can access your files when you are not around: ")
        nominee_1_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_1.txt"
        with open(nominee_1_file, "w") as file:
            file.write(nominee_1_reg)
        with open(nominee_1_file, "r") as file:
            nominee_1_show = file.read()
        nominee_1_relation = input(f"What is your relationship with {nominee_1_show}? (Eg.Parent, Sibling, Spouse, Friend): ")
        nominee_1_relation_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_1_relation.txt"
        with open(nominee_1_relation_file, 'w') as file:
            file.write(nominee_1_relation)
        show_loading_animation(2)
        print("Nominee added successfully.")
        nominee_2_reg_req = input("Do you wish to add a second nominee to your vault(y/n): ")
	user_name = "/path/to/directory/SFCV_Decrypting_Passcode/user_name.txt"
        if nominee_2_reg_req == 'y':
            show_loading_animation(2)
            nominee_2_reg = input("Add your second Nominee: ")
            nominee_2_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_2.txt"
            with open(nominee_2_file, "w") as file:
                file.write(nominee_2_reg)
            with open(nominee_2_file, "r") as file:
                nominee_2_show = file.read()
            nominee_2_relation = input(f"What is your relationship with {nominee_2_show}? (Eg.Parent, Sibling, Spouse, Friend): ")
            nominee_2_relation_file = "/path/to/directory/SFCV_Decrypting_Passcode/nominee_2_relation.txt"
            with open(nominee_2_relation_file, 'w') as file:
                file.write(nominee_2_relation)
            show_loading_animation(2)
            print("Nominees added successfully")
            time.sleep(1)
            print("Vaultlyn is now only supports upto 2 nominees. You can moderate the code to change the limit.")
            show_loading_animation(3)
        else:
            show_loading_animation(1)
            print("Your Nominee has been added.")
            pass
        print("Your setup is completed successfully.")
        show_loading_animation(1)
        with open(user_name_file, "r") as file:
            file.read()
            print(f"Welcome to Vaultlyn, {user_name}")
        show_loading_animation(3)
    else:
        print("Please select a valid option.")
        show_loading_animation(1)
        pass
