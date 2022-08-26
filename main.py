#importing modules

from tkinter import *
import ast
import random
import pyperclip
from twilio.rest import Client

account_sid = 'your_account_sid'
auth_token = 'your_authentication_token'
client = Client(account_sid, auth_token)

phfile=open("number.txt", "r")
phcontents=phfile.read()
phdict=ast.literal_eval(phcontents)
phfile.close()

f0=open("data.txt", "r")
icontents = f0.read()
dict = ast.literal_eval(icontents)
f0.close()

def register(): #designing screen for registration
    #TopLevel widget works similar to Frame
    global reg_screen
    reg_screen=Toplevel(main_screen) #the global screen variable is passed in argument
    reg_screen.title("Registration")
    reg_screen.geometry("750x750")
    reg_screen['bg'] = '#333333'

    #setting global variables
    global username
    global password
    global UsernameEntry
    global PassEntry
    global PhNoEntry
    global phno
    # setting text variables
    username=StringVar()
    password=StringVar()
    phno=StringVar()
    # setting label for user's instructions
    Label(reg_screen, text="Enter your details below",  bg="black", fg="white", width=100, height=1).pack()
    Label(reg_screen, text="", bg='#333333').pack()

    #setting username label
    UsernameLable=Label(reg_screen, text="Username: ",bg = "#f57a3d")
    UsernameLable.pack()

    # entry widget is a standard Tkinter widget used to enter or display a single line of text
    UsernameEntry=Entry(reg_screen, textvariable=username)
    UsernameEntry.pack()
    Label(reg_screen, text="", bg='#333333').pack()
    #setting password label
    PassLable = Label(reg_screen, text="Password: ",bg = "#f57a3d")
    PassLable.pack()

    #setting password entry
    PassEntry = Entry(reg_screen, textvariable=password, show='^')
    PassEntry.pack()
    Label(reg_screen, text="", bg='#333333').pack()

    #giving user option to allow program to generate a random password
    Label(reg_screen, text="Or you can also let us generate a password!",bg = "#f57a3d").pack()
    Label(reg_screen, text="", bg='#333333').pack()
    Button(reg_screen, text="Generate Password", width=15, height=1,bg = "#21ada8", command=pass_gen).pack()
    Label(reg_screen, text="", bg='#333333').pack()
    #password strength instructions

    Label(reg_screen, text="Please enter a strong password",bg = "#21ada8").pack()
    Label(reg_screen,
          text="A strong password contains:\n\n 1)Minimum 8 characters.\n 2)The alphabets must be between [a-z]\n 3)At least one alphabet should be of Upper Case [A-Z]\n 4)At least 1 number or digit between [0-9]\n 5)At least 1 character from [ _ or @ or $ ]",bg = "#f57a3d").pack()
    Label(reg_screen, text="", bg='#333333').pack()


    Label(reg_screen, text="Enter your Phone Number(with your country code): ", bg="#f57a3d").pack()
    PhNoEntry = Entry(reg_screen, textvariable=phno)
    PhNoEntry.pack()
    # setting register button
    Button(reg_screen, text="Register", width=10, height=2, bg = "#21ada8",command=reg_data).pack()

def pass_gen(): #defining function to generate random password
    global pass_gen_screen
    pass_gen_screen=Toplevel(reg_screen)
    pass_gen_screen.title("Password Generator")
    pass_gen_screen.geometry("500x500")
    pass_gen_screen['bg'] = '#333333'
    Label(pass_gen_screen, text="Here's your password:",bg = "#f57a3d").pack()
    Label(pass_gen_screen, text="", bg='#333333').pack()
    lower="abcdefghijklmnopqrstuvwxyz"
    upper=lower.upper()
    num="0123456789"
    symbol="@$_"

    #to randomly select atleast one character from each character set above
    rand_digit = random.choice(lower)
    rand_upper = random.choice(upper)
    rand_lower = random.choice(num)
    rand_symbol = random.choice(symbol)
    rand=rand_symbol+rand_lower+rand_upper+rand_digit

    #combining all the randomly selected characters
    all=lower+upper+num+symbol

    #selecting randomly again and adding more characters to increase length of password
    password="".join(random.sample(all,4))
    password=rand+password
    Label(pass_gen_screen, text=password, bg = "#f57a3d" ).pack()
    def Copy_password():
        pyperclip.copy(password) #the pyperclip module has copy() function that can send text to computer's clipboard
        pass_gen_screen.destroy() #deleting popup for password generator
    Button(pass_gen_screen, text='COPY TO CLIPBOARD',bg = "#f57a3d", command=Copy_password).pack(pady=5) #to copy the generated password to clipboard

# defining login function
def login():
    global login_screen

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()

    global username_login_entry
    global password_login_entry

    login_screen=Toplevel(main_screen)
    login_screen.title("Login")
    login_screen.geometry("750x750")
    Label(login_screen, text="Please enter details below to login", bg="black", fg="white", width=100, height=1).pack()

    Label(login_screen, text="", bg='#333333' ).pack()
    login_screen['bg'] = '#333333'

    Label(login_screen, text="Username: ",bg = "#f57a3d").pack()
    username_login_entry = Entry(login_screen, textvariable=username_verify)
    username_login_entry.pack()
    Label(login_screen, text="", bg='#333333').pack()
    Label(login_screen, text="Password: ",bg = "#f57a3d").pack()
    password_login_entry = Entry(login_screen, textvariable=password_verify, show='^')
    password_login_entry.pack()
    Label(login_screen, text="", bg='#333333').pack()
    Button(login_screen, text="Forgot Password", width=15, height=1,bg = "#21ada8", command=forgot_password).pack()
    Label(login_screen, text="", bg='#333333').pack()
    Button(login_screen, text="Login", width=10, height=1,bg = "#21ada8", command=login_check).pack()


def reg_data():
    global password_info
    global phno_info
    #to get username and password
    username_info=username.get()
    password_info=password.get()
    phno_info=phno.get()

    #opening file in write mode
    fc = open("data.txt", "r")
    ccontents = fc.read()
    # ast.literal_eval safely evaluates an expression node or a string containing a Python literal or container display.
    cdict = ast.literal_eval(ccontents)
    fc.close()
    if username_info!="":
    #checking whether entered details already exist in file
        if username_info in cdict:
            user_exists()
        else:
            #checking if the password meets our definition of strong password
            if strength_check(password_info):

                dict[username_info] = password_info
                f1 = open("data.txt", "w")

                #writes entered registered info into text file in the form of dictionary
                f1.write(str(dict))
                f1.close()
                #setting a label for showing success information on screen
                Label(reg_screen, text="Registration Success", fg="#333333", font=("cambria", 11), bg='#333333').pack()
                Label(reg_screen, text="Registration Success!", fg="cyan", font=("cambria", 11), bg='#333333').pack()
            else:
                not_strong()
    else:
        empty_username()

    phdict[username_info] = phno_info
    numberfile=open("number.txt", "w")
    numberfile.write(str(phdict))
    numberfile.close()

def strength_check(x):
    l, u, p, d = 0, 0, 0, 0

    if (len(x) >= 8):
        for i in x:

            # counting lowercase alphabets
            if (i.islower()):
                l += 1

                # counting uppercase alphabets
            if (i.isupper()):
                u += 1

                # counting digits
            if (i.isdigit()):
                d += 1

                # counting the mentioned special characters
            if (i == '@' or i == '$' or i == '_'):
                p += 1
    if (l >= 1 and u >= 1 and p >= 1 and d >= 1 and l + p + u + d == len(x)):
        return True
    else:
        return False


def not_strong():
    global not_strong_screen
    not_strong_screen = Toplevel(reg_screen)
    not_strong_screen.title("Password not strong")
    not_strong_screen.geometry("250x100")
    not_strong_screen['bg'] = '#333333'
    Label(not_strong_screen, text="Password not strong enough\n Enter a stronger password.", bg = "#f57a3d").pack()
    Label(not_strong_screen, text="", bg='#333333')
    Button(not_strong_screen, text="OK", command=delete_not_strong).pack()

def empty_username():
    global empty_username_screen
    empty_username_screen=Toplevel(reg_screen)
    empty_username_screen.title("Username blank")
    empty_username_screen.geometry("250x100")
    empty_username_screen['bg'] = '#333333'
    Label(empty_username_screen, text="Username cannot be left empty", bg = "#f57a3d").pack()
    Label(empty_username_screen, text="", bg='#333333')
    Button(empty_username_screen, text="OK", command=delete_empty_username).pack()

def login_check():
    global username1

    #getting username and password
    username1 = username_verify.get()
    password1 = password_verify.get()

    #opening file in read mode
    f2=open("data.txt", "r")
    contents = f2.read()
    dictionary = ast.literal_eval(contents)
    f2.close()


    #defining verification conditions
    if username1 in dictionary:
        if password1==dictionary[username1]:
            login_sucess()
        else:
            incorrect_pass()
    else:
        user_not_found()


def user_exists(): #designing pop-up to notify user that entered details already exist for a user
    global user_exists_screen
    user_exists_screen=Toplevel(reg_screen)
    user_exists_screen.title("user exists")
    user_exists_screen.geometry("350x100")
    user_exists_screen['bg'] = '#333333'
    Label(user_exists_screen, text="Uer already exists, please register using a different username", bg = "#f57a3d").pack()
    Button(user_exists_screen, text="OK", command=delete_user_exists).pack()


def login_sucess():
    file = open("number.txt", "r")
    contents = file.read()
    dictionary = ast.literal_eval(contents)
    file.close()

    global login_success_screen #making login_success screen global
    login_success_screen = Toplevel(login_screen)
    login_success_screen.title("Success")
    login_success_screen.geometry("350x100")
    Label(login_success_screen, text="Login Success",bg = "#f57a3d").pack()
    login_success_screen['bg'] = '#333333'
    #creating an OK button
    Button(login_success_screen, text="OK", command=delete_login_success).pack()



def forgot_password():
    global otp
    otp=StringVar()
    global otpgen
    global otpmessage
    username1=username_verify.get()
    f2 = open("data.txt", "r")
    contents = f2.read()
    dictionary1 = ast.literal_eval(contents)
    f2.close()
    if username1 in dictionary1:

        file = open("number.txt", "r")
        contents = file.read()
        dictionary = ast.literal_eval(contents)
        file.close()
        username1 = username_verify.get()
        otpgen=str(random.randrange(100000, 999999))
        otpmessage="Your OTP to reset your forgotten password is: "+otpgen
        global forgot_password_screen
        forgot_password_screen = Toplevel(login_screen)
        forgot_password_screen.title("Forgot Password")
        forgot_password_screen.geometry("500x200")
        forgot_password_screen['bg'] = '#333333'
        message = client.messages.create(body=otpmessage, from_='your_twilion_phoneNumber',
                                     to=dictionary[username1])
        Label(forgot_password_screen, text="Please enter the OTP your received on your registered phone number",bg = "#f57a3d" ).pack()
        global otp_entry
        otp_entry=Entry(forgot_password_screen, text=otp).pack()
        Button(forgot_password_screen, text="Verify", command=otp_verify).pack()
    else:
        Label(login_screen, text="User does not exist", bg="red").pack()


def otp_verify():
    global otp_verify_screen

    otp_check=otp.get()
    if otpgen==otp_check:
        change_pass()
    else:
        otp_verify_screen = Toplevel(forgot_password_screen)
        otp_verify_screen.title("Wrong OTP")
        otp_verify_screen.geometry("350x100")
        otp_verify_screen['bg'] = '#333333'
        Label(otp_verify_screen, text="Wrong OTP entered").pack()

def change_pass():
    global change_pass_screen
    global pass_update_entry

    change_pass_screen = Toplevel(forgot_password_screen)
    change_pass_screen.title("Change Password")
    change_pass_screen.geometry("350x100")
    change_pass_screen['bg'] = '#333333'
    global pass_update
    global pass_update_info
    pass_update=StringVar()
    Label(change_pass_screen, text="Type in your new password and press update: ",bg = "#f57a3d").pack()
    Label(change_pass_screen, text="", bg="#333333").pack()
    password_update_entry = Entry(change_pass_screen, textvariable=pass_update)
    password_update_entry.pack()
    Button(change_pass_screen, text="Update", command=save_new_pass, bg="#21ada8").pack()

def save_new_pass():
    pass_update_info = pass_update.get()
    username1 = username_verify.get()
    dict[username1]=pass_update_info
    passupdatefile=open("data.txt", "w")
    passupdatefile.write(str(dict))
    passupdatefile.close()
    change_pass_screen.destroy()

def incorrect_pass(): #pop-up for invalid password if the user enters wrong password
    global password_not_recon_screen
    password_not_recon_screen = Toplevel(login_screen)
    password_not_recon_screen.title("Wrong Password")
    password_not_recon_screen.geometry("350x100")
    password_not_recon_screen['bg'] = '#333333'
    Label(password_not_recon_screen, text="Invalid Password ", bg = "#f57a3d").pack()
    Button(password_not_recon_screen, text="OK", command=delete_password_not_recognised).pack()

def user_not_found(): #designing pop-up if user enters wrong username
    global user_not_found_screen
    user_not_found_screen = Toplevel(login_screen)
    user_not_found_screen.title("User Not Found")
    user_not_found_screen.geometry("350x100")
    user_not_found_screen['bg'] = '#333333'
    Label(user_not_found_screen, text="User Not Found", bg = "#f57a3d").pack()
    Button(user_not_found_screen, text="OK", command=delete_user_not_found_screen).pack()

def delete_user_exists(): #deleting pop-up for existing user condition
    user_exists_screen.destroy()

def delete_login_success(): #defining function for deleting the popup
    login_success_screen.destroy()

def delete_password_not_recognised(): #deleting pop-up for incorrect password
    password_not_recon_screen.destroy()


def delete_user_not_found_screen(): #deleting pop-up for user not found
    user_not_found_screen.destroy()

def delete_not_strong():
    not_strong_screen.destroy()

def delete_empty_username():
    empty_username_screen.destroy()

def welcome_screen():
    global main_screen
    main_screen = Tk() #creating a GUI window
    main_screen.geometry("300x250") #Setting configuration of GUI window
    main_screen.title("Register/Log-in") # setting title of GUI window
    main_screen['bg'] = '#333333'

    #creating a form label
    Label(text="Login Or Register", bg="black", fg="white", width="300", height="2", font=("Cambria", 13)).pack()
    Label(text="", bg='#333333').pack()

    #creating login button
    Button(text="Login",bg = "#f57a3d", height="2", width="30", command=login).pack()
    Label(text="", bg='#333333').pack()

    #creating register button
    Button(text="Register",bg = "#f57a3d", height="2", width="30", command=register).pack()

    main_screen.mainloop() #to start the GUI

welcome_screen() # calling the welcome_screen function