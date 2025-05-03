import os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import random
import string

# --- Configuration ---
# Replace with the path to your service account JSON key file
SERVICE_ACCOUNT_FILE = 'path/to/your/service_account_key.json'
# Replace with the email of a Google Workspace administrator in your domain
ADMIN_EMAIL = 'admin@yourdomain.com'
# Replace with your domain name
YOUR_DOMAIN = 'yourdomain.com'

# OAuth scopes required for managing users and OUs
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.orgunit',
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.user.alias'
]

# List of users to create
users_to_create = [
    {"firstName": "Alex", "lastName": "B", "email": f"alex.bell@{YOUR_DOMAIN}", "title": "IT Manager", "orgUnitPath": "/Executive"},
    {"firstName": "Kalani", "lastName": "B", "email": f"kalani.b@{YOUR_DOMAIN}", "title": "Executive Assistant", "orgUnitPath": "/Employees"},
    {"firstName": "Mark", "lastName": "J", "email": f"mark.j@{YOUR_DOMAIN}", "title": "Consultant", "orgUnitPath": "/Employees"},
    {"firstName": "Izumi", "lastName": "E", "email": f"izumi.e@{YOUR_DOMAIN}", "title": "HR Manager", "orgUnitPath": "/Executive"},
    {"firstName": "Sam", "lastName": "M", "email": f"samantha.m@{YOUR_DOMAIN}", "title": "CEO", "orgUnitPath": "/Executive"},
    {"firstName": "Timothy", "lastName": "L", "email": f"timothy.l@{YOUR_DOMAIN}", "title": "Finance Manager", "orgUnitPath": "/Executive"},
    {"firstName": "Cruz", "lastName": "M", "email": f"cruz.m@{YOUR_DOMAIN}", "title": "Support Engineer Contractor", "orgUnitPath": "/Employees"},
    {"firstName": "Lars", "lastName": "E", "email": f"lars.e@{YOUR_DOMAIN}", "title": "Support Engineer", "orgUnitPath": "/Employees"},
]

# List of OUs to create
ous_to_create = ["/Executive", "/Employees", "/Contractors"]

# --- Helper Function to Generate Password ---
def generate_temp_password(length=12):
    """Generates a random temporary password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# --- Main Script ---
def main():
    """Shows basic usage of the Admin SDK Directory API."""
    creds = None
    try:
        # Authenticate using the service account with domain-wide delegation
        creds = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        delegated_creds = creds.with_subject(ADMIN_EMAIL)

        # Build the Directory API service
        service = build('admin', 'directory_v1', credentials=delegated_creds)

        print("Authenticated successfully.")

        # --- Create Organizational Units ---
        print("\nCreating Organizational Units...")
        for ou_path in ous_to_create:
            ou_name = ou_path.split('/')[-1] # Get the last part of the path as the name
            ou_body = {
                'name': ou_name,
                'parentOrgUnitPath': '/'.join(ou_path.split('/')[:-1]) if len(ou_path.split('/')) > 2 else '/', # Set parent path correctly
                'blockInheritance': False, # Adjust as needed
                'description': f'Organizational Unit for {ou_name}'
            }
            try:
                result = service.orgunits().insert(customer='my_customer', body=ou_body).execute()
                print(f"OU '{ou_path}' created successfully.")
            except HttpError as error:
                # Check if the error is because the OU already exists (status code 409)
                if error.resp.status == 409:
                    print(f"OU '{ou_path}' already exists.")
                else:
                    print(f"An error occurred creating OU '{ou_path}': {error}")

        # --- Create Users ---
        print("\nCreating User Accounts...")
        for user_data in users_to_create:
            temp_password = generate_temp_password()
            user_body = {
                'primaryEmail': user_data['email'],
                'name': {
                    'givenName': user_data['firstName'],
                    'familyName': user_data['lastName']
                },
                'password': temp_password,
                'orgUnitPath': user_data['orgUnitPath'],
                'suspended': False,
                'changePasswordAtNextLogin': True, # Force user to change password on first login
                'customSchemas': {
                    'EmployeeDetails': { # Assuming you have a custom schema named 'EmployeeDetails'
                        'EmployeeTitle': user_data['title']
                    }
                    # You might need to adjust custom schema field names based on your setup
                }
            }
            try:
                result = service.users().insert(body=user_body).execute()
                print(f"User '{user_data['email']}' created successfully.")
                # Note: You should securely store or provide the temporary password to the user.
                # For this exercise, you might just print it or log it securely.
                # print(f"Temporary password for {user_data['email']}: {temp_password}") # Be cautious printing passwords
            except HttpError as error:
                 # Check if the error is because the user already exists (status code 409)
                if error.resp.status == 409:
                    print(f"User '{user_data['email']}' already exists.")
                else:
                    print(f"An error occurred creating user '{user_data['email']}': {error}")


    except HttpError as error:
        print(f'An API error occurred: {error}')
    except FileNotFoundError:
        print(f"Error: Service account key file not found at {SERVICE_ACCOUNT_FILE}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
