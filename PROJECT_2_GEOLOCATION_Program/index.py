import bcrypt
import csv
import requests
import re
import logging
from getpass import getpass

logging.basicConfig(
    filename='user_activity.log',  
    level=logging.INFO,  
    format='%(asctime)s - %(levelname)s - %(message)s' 
)

def eventLogs(event_message, event_type="info"):
    """Logs an event to the log file."""
    if event_type == "info":
        logging.info(event_message)
    elif event_type == "error":
        logging.error(event_message)
    elif event_type == "warning":
        logging.warning(event_message)

def is_email_registered(email):
    try:
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) < 2:
                    continue
                if row[0] == email:
                    return True
    except FileNotFoundError:
        eventLogs("CSV file not found for user data.", "error")
    return False

def signup():
    print("=== Sign Up ===")
    email = input("Enter your email: ")
    
    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print("Invalid email format.")
        return
    
    if is_email_registered(email):
        print("Email is already registered.")
        return

    # Get user password and security question
    password = getpass("Enter your password: ")
    if not pass_validate(password):
        return
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    security_question = input("Enter your security question (for password recovery): ")
    security_answer = getpass("Enter your security answer: ")

    try:
        with open('regno.csv', mode='a', newline='') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow([email, hashed_password, security_question, security_answer])
        eventLogs(f"New user signed up: {email}")
        print("User registered successfully!")
    except Exception as e:
        eventLogs(f"Error during signup: {e}", "error")

def pass_validate(password):
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) \
            or not re.search(r"\d", password) or not re.search(r"[!@#\$%\^&\*]", password):
        print("Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.")
        return False
    return True

def user_auth(email, password):
    try:
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) < 2:
                    continue
                if row[0] == email:
                    if bcrypt.checkpw(password.encode('utf-8'), row[1].encode('utf-8')):
                        eventLogs(f"Successful login for user: {email}")
                        return True
                    else:
                        eventLogs(f"Failed login attempt (wrong password) for user: {email}", "warning")
                        return False
            eventLogs(f"Failed login attempt (email not found): {email}", "warning")
    except Exception as e:
        eventLogs(f"Error during login: {e}", "error")
    return False

def pass_reset():
    print("=== Forgot Password ===")
    email = input("Enter your registered email: ")

    try:
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) < 4:
                    continue
                if row[0] == email:
                    eventLogs(f"Password reset requested for user: {email}")
                    answer = getpass(f"Answer to your security question: {row[2]} ")
                    if answer == row[3]:
                        new_password = getpass("Enter new password: ")
                        if pass_validate(new_password):
                            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                            pass_update(email, hashed_password)
                            eventLogs(f"Password reset successful for user: {email}")
                            print("Password reset successful.")
                        return
                    else:
                        eventLogs(f"Failed password reset attempt (wrong answer) for user: {email}", "warning")
                        print("Incorrect answer to the security question.")
                        return
            eventLogs(f"Password reset attempt failed (email not found): {email}", "warning")
            print("Email not found.")
    except Exception as e:
        eventLogs(f"Error during password reset: {e}", "error")

def pass_update(email, new_hashed_password):
    try:
        rows = []
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) >= 2 and row[0] == email:
                    row[1] = new_hashed_password
                rows.append(row)
        
        with open('regno.csv', mode='w', newline='') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerows(rows)
    except Exception as e:
        eventLogs(f"Error updating password for user: {email}: {e}", "error")

def fetch_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            public_ip = response.json()['ip']
            eventLogs(f"Public IP fetched successfully: {public_ip}")
            return public_ip
        else:
            eventLogs("Failed to fetch public IP.", "error")
            print("Unable to fetch your IP address. Please check your internet connection.")
    except Exception as e:
        eventLogs(f"Error fetching public IP: {e}", "error")
        print(f"Error fetching IP: {e}")
    return None

def fetch_geolocation(ip_address):
    try:
        api_url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                eventLogs(f"Geolocation fetched for IP: {ip_address}")
                print(f"Country: {data['country']}")
                print(f"City: {data['city']}")
                print(f"Region: {data['regionName']}")
                print(f"Latitude: {data['lat']}")
                print(f"Longitude: {data['lon']}")
                print(f"Timezone: {data['timezone']}")
                print(f"ISP: {data['isp']}")
            else:
                eventLogs(f"Failed to fetch geolocation for IP: {ip_address}", "warning")
                print("Geolocation data not found for this IP.")
        else:
            eventLogs("Error fetching geolocation data.", "error")
            print("Error fetching geolocation data.")
    except Exception as e:
        eventLogs(f"Error fetching geolocation: {e}", "error")
        print(f"Error fetching geolocation: {e}")

def main():
    print("=== Welcome to the IP Geolocation App ===")
    while True:
        choice = input("1. Sign Up\n2. Log In\n3. Forgot Password\n4. Exit\nEnter your choice: ")

        if choice == '1':
            signup()
        elif choice == '2':
            email = input("Enter your email: ")
            password = getpass("Enter your password: ")

            if user_auth(email, password):
                print("Login successful!")
                while True:
                    ip_choice = input("Enter an IP address or press Enter to use your own IP: ")
                    if not ip_choice:
                        ip_choice = fetch_ip()
                        if not ip_choice:
                            break
                    fetch_geolocation(ip_choice)
                    break
            else:
                print("Login failed. Please check your credentials.")
        elif choice == '3':
            pass_reset()
        elif choice == '4':
            print("Goodbye! See you soon my friend :)")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
