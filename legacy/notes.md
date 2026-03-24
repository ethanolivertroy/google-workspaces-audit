### **Prerequisites**

Before you can run the code, you'll need to set up a few things in your Google Cloud project and Google Workspace Admin console:

1. **Google Cloud Project:** If you don't have one, create a Google Cloud project.  
2. **Enable the Admin SDK API:** In your Google Cloud project, enable the "Admin SDK" API.  
3. **Create a Service Account:** Create a service account in your Google Cloud project. This service account will act on behalf of your Google Workspace administrator to create users and OUs.  
4. **Download Service Account Key:** Download the JSON key file for your service account. Keep this file secure.  
5. **Delegate Domain-Wide Authority:** This is a crucial step. In your Google Workspace Admin console, go to Security \> Access and data control \> API controls. Under "Domain-wide delegation," click Manage Domain Wide Delegation. Add a new API client with the Client ID of your service account and the following OAuth scopes:  
   * https://www.googleapis.com/auth/admin.directory.orgunit (for managing OUs)  
   * https://www.googleapis.com/auth/admin.directory.user (for managing users)  
   * https://www.googleapis.com/auth/admin.directory.user.alias (optional, but good to include for user aliases)  
6. **Install Google Client Libraries:** Install the necessary Python client libraries:  
   pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib

### **Steps to Programmatically Create Users and OUs**

The process involves the following steps:

1. **Authentication:** Authenticate using the service account with domain-wide delegation. You'll need the path to your service account JSON key file and the email address of a Google Workspace administrator in your domain to impersonate.  
2. **Create Organizational Units (OUs):** Use the Directory API to create the /Executive, /Employees, and /Contractors OUs if they don't already exist.  
3. **Create Users:** Iterate through your list of users. For each user, use the Directory API to create the user account, specifying their first name, last name, email address, password (you'll need to generate temporary passwords or handle this securely), employee title, and the correct organizational unit path.




# FedRAMP Stuff

## Add Support

### IL4
https://support.google.com/a/answer/13881245?hl=en&ref_topic=14267325&sjid=12056201397706241487-NA