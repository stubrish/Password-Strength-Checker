import re
import math
import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip  # For clipboard functionality

# Utility functions
def is_common_password(password):
    """Check if the password is in the list of common passwords."""
    try:
        with open("10-million-password-list-top-1000000.txt", "r") as file:
            common_passwords = set(line.strip() for line in file)
        return password.lower() in common_passwords
    except FileNotFoundError:
        print("Common passwords file not found. Skipping common password check.")
        return False

def check_for_sequences(password):
    """Check if the password contains sequential characters like 'abcd' or '1234'."""
    sequences = ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789']
    
    for i in range(len(password) - 3):
        segment = password[i:i + 4]
        if any(segment in seq for seq in sequences):
            return f"Password cannot contain sequences like '{segment}'."
    
    return None

def check_consecutive_characters(password):
    """Check if the password contains more than two consecutive identical characters."""
    if re.search(r'(.)\1{2,}', password):  # Search for three or more consecutive identical characters
        return "Password cannot have three or more consecutive identical characters."
    return None

def check_other_parameters(password):
    """Check for various password rules: consecutive chars, sequences."""
    consecutive_check = check_consecutive_characters(password)
    if consecutive_check:
        return consecutive_check

    sequence_check = check_for_sequences(password)
    if sequence_check:
        return sequence_check

    return None

def password_character_variety(password):
    """Check for character variety in the password (uppercase, lowercase, digits, special chars)."""
    special_char_pattern = r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]'
    
    return {
        'has_upper': any(c.isupper() for c in password),
        'has_lower': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': re.search(special_char_pattern, password) is not None
    }

def password_character_variety_feedback(password):
    """Provide specific feedback about missing character types."""
    variety = password_character_variety(password)
    missing = []
    if not variety['has_upper']:
        missing.append("uppercase letter")
    if not variety['has_lower']:
        missing.append("lowercase letter")
    if not variety['has_digit']:
        missing.append("digit")
    if not variety['has_special']:
        missing.append("special character")
    if missing:
        return f"Password is missing: {', '.join(missing)}."
    return None

def password_checker(password):
    """Check if the password meets all strength requirements (rules and character variety)."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."

    if is_common_password(password):  # Check if password is common
        return False, "Password is too common. Choose a more unique password."

    char_variety = password_character_variety(password)
    
    if message := check_other_parameters(password):
        return False, message

    if all(char_variety.values()):
        return True, None
    else:
        return False, password_character_variety_feedback(password)

# Password security metrics functions
def calculate_entropy(password):
    """Calculate the entropy of a password based on its character set."""
    length = len(password)
    char_set_size = 0
    if any(c.islower() for c in password):
        char_set_size += 26
    if any(c.isupper() for c in password):
        char_set_size += 26
    if any(c.isdigit() for c in password):
        char_set_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
        char_set_size += 32
    entropy = length * math.log2(char_set_size) if char_set_size else 0
    return entropy, char_set_size

def calculate_password_score(password):
    """Calculate a password strength score (0 to 100)."""
    length_score = min(len(password) * 2, 40)  # Max 40 points for length
    variety_score = sum(password_character_variety(password).values()) * 10  # Max 40 points for variety
    entropy_score = min(calculate_entropy(password)[0], 20)  # Max 20 points for entropy
    return length_score + variety_score + entropy_score

def classify_entropy(entropy):
    """Classify the password strength based on entropy value."""
    if entropy < 40:
        return "Weak"
    elif 40 <= entropy < 60:
        return "Moderate"
    else:
        return "Strong"

def estimate_crack_time(password_length, char_set_size):
    """Estimate time to crack a password using brute force at 1 trillion guesses per second."""
    guesses_per_second = 10**12  # 1 trillion guesses per second (modern GPU)
    total_combinations = char_set_size ** password_length
    time_to_crack = total_combinations / guesses_per_second
    return time_to_crack

def format_crack_time(seconds):
    """Convert seconds to a human-readable format with units like million, billion, etc."""
    minute, hour, day, year = 60, 3600, 86400, 31536000

    if seconds < minute:
        return f"{seconds:.2f} seconds"
    elif seconds < hour:
        return f"{seconds / minute:.2f} minutes"
    elif seconds < day:
        return f"{seconds / hour:.2f} hours"
    elif seconds < year:
        return f"{seconds / day:.2f} days"
    else:
        years = seconds / year
        if years < 1_000:
            return f"{years:.2f} years"
        elif years < 1_000_000:
            return f"{years / 1_000:.2f} thousand years"
        elif years < 1_000_000_000:
            return f"{years / 1_000_000:.2f} million years"
        elif years < 1_000_000_000_000:
            return f"{years / 1_000_000_000:.2f} billion years"
        else:
            return f"{years / 1_000_000_000_000:.2f} trillion years"

# GUI-related functions
def update_password_strength(event=None):
    """Update password strength meter and show feedback after clicking 'Check' or pressing Enter."""
    password = password_entry.get()

    if len(password) < 12:
        strength_label.config(text="Password must be at least 12 characters long!", fg="red")
        strength_meter['value'] = 0
        entropy_label.config(text="")
        crack_time_label.config(text="")
        return

    is_strong, message = password_checker(password)
    if not is_strong:
        strength_label.config(text=message, fg="red")
        strength_meter['value'] = 0
        entropy_label.config(text="")
        crack_time_label.config(text="")
        return

    entropy, char_set_size = calculate_entropy(password)
    entropy_classification = classify_entropy(entropy)
    time_to_crack = estimate_crack_time(len(password), char_set_size)
    password_score = calculate_password_score(password)

    # Update progress bar and labels based on the password score
    strength_meter['value'] = password_score
    if password_score < 50:
        strength_label.config(text="Weak", fg="red")
    elif 50 <= password_score < 80:
        strength_label.config(text="Moderate", fg="orange")
    else:
        strength_label.config(text="Strong", fg="green")

    entropy_label.config(text=f"Entropy: {entropy:.2f} bits")
    crack_time_label.config(text=f"Estimated Time to Crack: {format_crack_time(time_to_crack)}")

    # Update password history
    update_password_history(password)

def toggle_password_visibility():
    """Toggle between showing and hiding the password with a symbol."""
    if password_entry.cget('show') == '':
        password_entry.config(show="*")
        toggle_button.config(text="👁")  # Show symbol for hidden password
    else:
        password_entry.config(show="")
        toggle_button.config(text="🔒")  # Show symbol for visible password

def show_password_tips():
    """Display tips for creating strong passwords."""
    tips = """
    Tips for Strong Passwords:
    - Use at least 12 characters.
    - Include uppercase, lowercase, digits, and special characters.
    - Avoid common words or sequences.
    """
    messagebox.showinfo("Password Tips", tips)

def update_password_history(password):
    """Update the password history with the latest password."""
    password_history.append(password)
    history_text.config(state=tk.NORMAL)
    history_text.delete(1.0, tk.END)  # Clear the history text
    for i, pwd in enumerate(password_history, 1):
        history_text.insert(tk.END, f"{i}. {pwd}\n")
    history_text.config(state=tk.DISABLED)
    history_text.yview(tk.END)  # Scroll to the bottom

def clear_password_history():
    """Clear the password history."""
    password_history.clear()
    history_text.config(state=tk.NORMAL)
    history_text.delete(1.0, tk.END)
    history_text.config(state=tk.DISABLED)

def toggle_dark_mode():
    """Toggle between light and dark mode."""
    global is_dark_mode
    is_dark_mode = not is_dark_mode

    if is_dark_mode:  # Dark mode
        window.config(bg="#2d2d2d")
        label.config(bg="#2d2d2d", fg="#ffffff")
        password_entry.config(bg="#3b3b3b", fg="#ffffff", insertbackground="white")
        toggle_button.config(bg="#3b3b3b", fg="#ffffff")
        strength_label.config(bg="#2d2d2d", fg="#ffffff")
        entropy_label.config(bg="#2d2d2d", fg="#ffffff")
        crack_time_label.config(bg="#2d2d2d", fg="#ffffff")
        history_label.config(bg="#2d2d2d", fg="#ffffff")
        history_text.config(bg="#3b3b3b", fg="#ffffff", insertbackground="white")
        check_button.config(bg="#3b3b3b", fg="#ffffff")
        tips_button.config(bg="#3b3b3b", fg="#ffffff")
        copy_button.config(bg="#3b3b3b", fg="#ffffff")
        dark_mode_button.config(text="☀️ Light Mode", bg="#3b3b3b", fg="#ffffff")
        history_frame.config(bg="#2d2d2d")
        clear_button.config(bg="#3b3b3b", fg="#ffffff")
        button_frame.config(bg="#2d2d2d")  # Update button_frame background
        history_buttons_frame.config(bg="#2d2d2d")  # Update history_buttons_frame background
    else:  # Light mode
        window.config(bg="#ffffff")
        label.config(bg="#ffffff", fg="#000000")
        password_entry.config(bg="#ffffff", fg="#000000", insertbackground="black")
        toggle_button.config(bg="#ffffff", fg="#000000")
        strength_label.config(bg="#ffffff", fg="#000000")
        entropy_label.config(bg="#ffffff", fg="#000000")
        crack_time_label.config(bg="#ffffff", fg="#000000")
        history_label.config(bg="#ffffff", fg="#000000")
        history_text.config(bg="#ffffff", fg="#000000", insertbackground="black")
        check_button.config(bg="#ffffff", fg="#000000")
        tips_button.config(bg="#ffffff", fg="#000000")
        copy_button.config(bg="#ffffff", fg="#000000")
        dark_mode_button.config(text="🌙 Dark Mode", bg="#ffffff", fg="#000000")
        history_frame.config(bg="#ffffff")
        clear_button.config(bg="#ffffff", fg="#000000")
        button_frame.config(bg="#ffffff")  # Update button_frame background
        history_buttons_frame.config(bg="#ffffff")  # Update history_buttons_frame background

def copy_to_clipboard():
    """Copy the password to the clipboard."""
    password = password_entry.get()
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password has been copied to the clipboard.")

# Create the GUI window
window = tk.Tk()
window.title("Password Strength Checker")
window.geometry("500x500")
window.resizable(True, True)  # Allow resizing and maximizing
window.config(bg="#ffffff")

# Dark mode state
is_dark_mode = False

# Create and place widgets
label = tk.Label(window, text="Enter Your Password:", font=("Helvetica", 12), bg="#ffffff")
label.pack(pady=10)

# Frame to hold password entry and toggle button
password_frame = tk.Frame(window, bg="#ffffff")
password_frame.pack(pady=10)

# Password entry inside the frame
password_entry = tk.Entry(password_frame, width=40, font=("Helvetica", 12), show="*", bg="#ffffff")
password_entry.pack(side="left")

# Show/Hide password toggle button (with an eye symbol) next to the password entry
toggle_button = tk.Button(password_frame, text="👁", command=toggle_password_visibility, font=("Helvetica", 12), bg="#ffffff")
toggle_button.pack(side="left")

# Bind the Enter key to trigger the password strength check
password_entry.bind("<Return>", update_password_strength)

# Password Strength Meter (Progress Bar) - initially hidden
strength_meter = ttk.Progressbar(window, orient="horizontal", length=300, mode="determinate")
strength_meter.pack(pady=10)
strength_meter['value'] = 0  # Initially empty bar

strength_label = tk.Label(window, text="", font=("Helvetica", 12), bg="#ffffff")
strength_label.pack(pady=5)

entropy_label = tk.Label(window, text="", font=("Helvetica", 10), bg="#ffffff")
entropy_label.pack()

crack_time_label = tk.Label(window, text="", font=("Helvetica", 10), bg="#ffffff")
crack_time_label.pack()

# Button to check password strength
check_button = tk.Button(window, text="Check Password Strength", command=update_password_strength, font=("Helvetica", 12), bg="#ffffff")
check_button.pack(pady=10)

# Frame to hold "Tips" and "Copy" buttons side by side
button_frame = tk.Frame(window, bg="#ffffff")
button_frame.pack(pady=10)

# Button to show password tips (smaller)
tips_button = tk.Button(button_frame, text="Tips", command=show_password_tips, font=("Helvetica", 10), bg="#ffffff")
tips_button.pack(side="left", padx=5)  # Added padx for spacing

# Button to copy password to clipboard (smaller)
copy_button = tk.Button(button_frame, text="Copy", command=copy_to_clipboard, font=("Helvetica", 10), bg="#ffffff")
copy_button.pack(side="left", padx=5)  # Added padx for spacing

# Password History
password_history = []
history_label = tk.Label(window, text="Password History:", font=("Helvetica", 12), bg="#ffffff")
history_label.pack(pady=10)

# Frame to hold history text and scrollbar
history_frame = tk.Frame(window, bg="#ffffff")
history_frame.pack()

# Password history text with scrollbar
history_text = tk.Text(history_frame, height=5, width=50, state=tk.DISABLED, bg="#ffffff")
history_text.pack(side="left", fill="y")

# Vertical scrollbar for history text
scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=history_text.yview)
scrollbar.pack(side="right", fill="y")

# Configure the text widget to work with the scrollbar
history_text.config(yscrollcommand=scrollbar.set)

# Frame to hold "Clear History" and "Dark Mode" buttons side by side
history_buttons_frame = tk.Frame(window, bg="#ffffff")
history_buttons_frame.pack(pady=5)

# Button to clear password history
clear_button = tk.Button(history_buttons_frame, text="Clear History", command=clear_password_history, font=("Helvetica", 10), bg="#ffffff")
clear_button.pack(side="left", padx=5)  # Added padx for spacing

# Dark Mode Toggle Button
dark_mode_button = tk.Button(history_buttons_frame, text="🌙 Dark Mode", command=toggle_dark_mode, font=("Helvetica", 10), bg="#ffffff")
dark_mode_button.pack(side="left", padx=5)  # Added padx for spacing

# Start the GUI event loop
window.mainloop()