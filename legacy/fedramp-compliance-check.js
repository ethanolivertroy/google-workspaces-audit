/**
 * Google Workspace FedRAMP Compliance Checker
 * 
 * This script uses the Google Workspace Admin SDK APIs to verify FedRAMP compliance settings
 * across your Google Workspace environment. It's based on the official FedRAMP compliance
 * requirements from Google Cloud.
 * 
 * Reference: https://cloud.google.com/security/compliance/fedramp
 */

const { google } = require('googleapis');
const fs = require('fs');
const readline = require('readline');

// Configuration
const CONFIG = {
  credentialsPath: './credentials.json',
  reportOutputPath: './fedramp-compliance-report.json',
  scopes: [
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.domain.readonly',
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly',
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
    'https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly',
    'https://www.googleapis.com/auth/admin.directory.customer.readonly',
    'https://www.googleapis.com/auth/apps.licensing'
  ]
};

// Define FedRAMP compliance checks
const FEDRAMP_CHECKS = [
  {
    id: 'fedramp-authorized-services',
    name: 'FedRAMP Authorized Services',
    description: 'Check if only FedRAMP authorized services are enabled for users within FedRAMP boundary',
    status: 'Not Checked',
    details: '',
    fixSteps: 'In Admin Console, navigate to Apps > Google Workspace > Services. Ensure only FedRAMP authorized services are enabled.'
  },
  {
    id: 'data-region-policy',
    name: 'Data Region Policy',
    description: 'Verify data region policy is set to United States for FedRAMP compliance',
    status: 'Not Checked',
    details: '',
    fixSteps: 'In Admin Console, go to Account > Settings > Data Regions and set the policy to United States.'
  },
  {
    id: 'assured-controls',
    name: 'Assured Controls',
    description: 'Check if Assured Controls add-on is enabled (Enterprise Plus only)',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Purchase and enable the Assured Controls add-on for your Google Workspace Enterprise Plus subscription.'
  },
  {
    id: 'access-transparency',
    name: 'Access Transparency',
    description: 'Verify that Access Transparency is enabled to monitor Google staff actions',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Go to Security > Access Transparency in Admin Console and enable this feature.'
  },
  {
    id: 'password-policy',
    name: 'Password Policy',
    description: 'Check if password policy meets FedRAMP requirements (minimum 12 chars, complexity, etc.)',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Navigate to Security > Password management in Admin Console and update settings to require minimum 12 characters, complexity, and 60-day expiration.'
  },
  {
    id: 'two-step-verification',
    name: 'Two-Step Verification',
    description: 'Verify 2-Step Verification is enforced for all users',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Go to Security > 2-Step Verification in Admin Console and enforce for all users.'
  },
  {
    id: 'admin-privileges',
    name: 'Admin Privileges',
    description: 'Check if admin privileges follow the principle of least privilege',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Review admin role assignments in Admin > Account > Admin roles and ensure only necessary privileges are assigned.'
  },
  {
    id: 'audit-logging',
    name: 'Audit Logging',
    description: 'Verify comprehensive audit logging is enabled for monitoring',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Configure audit logging in Admin > Security > Audit and investigation tools.'
  },
  {
    id: 'security-center',
    name: 'Security Center',
    description: 'Check if Security Center is configured (Enterprise Plus only)',
    status: 'Not Checked',
    details: '',
    fixSteps: 'If using Enterprise Plus, go to Security > Security Center and ensure it is properly configured.'
  },
  {
    id: 'data-loss-prevention',
    name: 'Data Loss Prevention',
    description: 'Check if DLP policies are configured to prevent data leakage',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Set up DLP policies in Security > Data protection to prevent accidental data leakage of sensitive information.'
  },
  {
    id: 'context-aware-access',
    name: 'Context-Aware Access',
    description: 'Verify context-aware access policies are in place to restrict access based on context (Enterprise Plus)',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Configure context-aware access in Security > Access and data control > Context-Aware Access.'
  },
  {
    id: 'endpoint-management',
    name: 'Endpoint Management',
    description: 'Check if endpoint management is configured for devices',
    status: 'Not Checked',
    details: '',
    fixSteps: 'Set up endpoint management in Devices > Mobile & endpoints.'
  }
];

// FedRAMP authorized services for Workspace
const FEDRAMP_AUTHORIZED_SERVICES = [
  'Gmail',
  'Calendar',
  'Drive and Docs',
  'Meet',
  'Chat',
  'Google Voice',
  'Classroom',
  'Keep',
  'Groups for Business',
  'Google Cloud Search',
  'Sites',
  'Vault',
  'Security Center'
];

// Main function
async function checkFedRAMPCompliance() {
  let complianceReport = {
    timestamp: new Date().toISOString(),
    domainName: '',
    edition: '',
    overallStatus: 'Not Compliant',
    checks: FEDRAMP_CHECKS,
    summary: {
      compliant: 0,
      nonCompliant: 0,
      notChecked: FEDRAMP_CHECKS.length
    },
    recommendations: []
  };

  try {
    // Authenticate
    const auth = await getAuth();
    console.log('✓ Authentication successful');

    // Get domain information
    const directory = google.admin({ version: 'directory_v1', auth });
    try {
      const domainResponse = await directory.domains.list({
        customer: 'my_customer'
      });
      
      if (domainResponse.data.domains && domainResponse.data.domains.length > 0) {
        complianceReport.domainName = domainResponse.data.domains[0].domainName;
        console.log(`✓ Retrieved domain: ${complianceReport.domainName}`);
      }
    } catch (error) {
      console.error('Error retrieving domain information:', error);
    }

    // Get customer information (to determine edition)
    try {
      const customerResponse = await directory.customers.get({
        customerKey: 'my_customer'
      });
      
      if (customerResponse.data) {
        complianceReport.edition = customerResponse.data.customerDomain || 'Unknown';
        console.log(`✓ Retrieved customer information`);
      }
    } catch (error) {
      console.error('Error retrieving customer information:', error);
    }

    // Run compliance checks
    await checkAuthorizedServices(auth, complianceReport);
    await checkDataRegionPolicy(auth, complianceReport);
    await checkAssuredControls(auth, complianceReport);
    await checkAccessTransparency(auth, complianceReport);
    await checkPasswordPolicy(auth, complianceReport);
    await checkTwoStepVerification(auth, complianceReport);
    await checkAdminPrivileges(auth, complianceReport);
    await checkAuditLogging(auth, complianceReport);
    await checkSecurityCenter(auth, complianceReport);
    await checkDLP(auth, complianceReport);
    await checkContextAwareAccess(auth, complianceReport);
    await checkEndpointManagement(auth, complianceReport);

    // Generate recommendations for non-compliant checks
    generateRecommendations(complianceReport);

    // Determine overall status
    if (complianceReport.summary.nonCompliant === 0 && complianceReport.summary.notChecked === 0) {
      complianceReport.overallStatus = 'Compliant';
    } else if (complianceReport.summary.nonCompliant > 0) {
      complianceReport.overallStatus = 'Not Compliant';
    } else {
      complianceReport.overallStatus = 'Partially Checked';
    }

    // Save report
    fs.writeFileSync(CONFIG.reportOutputPath, JSON.stringify(complianceReport, null, 2));
    
    // Display summary
    console.log('\n=== FedRAMP Compliance Report Summary ===');
    console.log(`Domain: ${complianceReport.domainName}`);
    console.log(`Edition: ${complianceReport.edition}`);
    console.log(`Overall Status: ${complianceReport.overallStatus}`);
    console.log(`Compliant Checks: ${complianceReport.summary.compliant}`);
    console.log(`Non-Compliant Checks: ${complianceReport.summary.nonCompliant}`);
    console.log(`Checks Not Performed: ${complianceReport.summary.notChecked}`);
    console.log(`Report saved to: ${CONFIG.reportOutputPath}`);

    if (complianceReport.recommendations.length > 0) {
      console.log('\n=== Key Recommendations ===');
      complianceReport.recommendations.forEach((rec, index) => {
        console.log(`${index + 1}. ${rec}`);
      });
    }

  } catch (error) {
    console.error('Error during compliance check:', error);
  }
}

// Generate recommendations based on non-compliant checks
function generateRecommendations(report) {
  const nonCompliantChecks = report.checks.filter(check => check.status === 'Not Compliant');
  
  nonCompliantChecks.forEach(check => {
    report.recommendations.push(`${check.name}: ${check.fixSteps}`);
  });
}

// Helper: Authentication with OAuth2
async function getAuth() {
  try {
    const credentials = JSON.parse(fs.readFileSync(CONFIG.credentialsPath));
    const { client_secret, client_id, redirect_uris } = credentials.installed || credentials.web;
    
    const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);

    // Check if we have a token stored
    try {
      const token = fs.readFileSync('./token.json');
      oAuth2Client.setCredentials(JSON.parse(token));
      return oAuth2Client;
    } catch (e) {
      return await getNewToken(oAuth2Client);
    }
  } catch (error) {
    console.error('Error loading credentials:', error);
    throw error;
  }
}

// Helper: Get a new OAuth token
async function getNewToken(oAuth2Client) {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: CONFIG.scopes,
  });
  
  console.log('Authorize this app by visiting this URL:', authUrl);
  
  const code = await promptUserForCode();
  
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    
    // Save the token for future use
    fs.writeFileSync('./token.json', JSON.stringify(tokens));
    
    return oAuth2Client;
  } catch (error) {
    console.error('Error retrieving access token:', error);
    throw error;
  }
}

// Helper: Command line prompt for auth code
function promptUserForCode() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    
    rl.question('Enter the code from that page here: ', (code) => {
      rl.close();
      resolve(code);
    });
  });
}

// Check 1: FedRAMP Authorized Services
async function checkAuthorizedServices(auth, report) {
  console.log('\nChecking FedRAMP Authorized Services...');
  
  try {
    // This would require the Service Management API
    // In a real implementation, you'd fetch all enabled services and compare against the authorized list
    
    // Since direct API for this is not available for Workspace, we provide manual validation guidance
    const checkIndex = report.checks.findIndex(check => check.id === 'fedramp-authorized-services');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. Please check Admin Console > Apps > Google Workspace > Services and ensure only FedRAMP authorized services are enabled for users in FedRAMP boundary.';
    
    // List authorized services for reference
    report.checks[checkIndex].details += `\n\nFedRAMP authorized services for Google Workspace include: ${FEDRAMP_AUTHORIZED_SERVICES.join(', ')}`;
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking authorized services:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'fedramp-authorized-services');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 2: Data Region Policy
async function checkDataRegionPolicy(auth, report) {
  console.log('Checking Data Region Policy...');
  
  try {
    // Currently, there is no direct API to check data region policy settings
    // This would require manual verification in the Admin Console
    
    const checkIndex = report.checks.findIndex(check => check.id === 'data-region-policy');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. For FedRAMP compliance, data region should be set to United States. Check in Admin Console > Account > Settings > Data Regions.';
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking data region policy:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'data-region-policy');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 3: Assured Controls
async function checkAssuredControls(auth, report) {
  console.log('Checking Assured Controls...');
  
  try {
    // This would require checking licensing information through the Licensing API
    // Unfortunately, direct API access to check for this add-on is limited
    
    const checkIndex = report.checks.findIndex(check => check.id === 'assured-controls');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. Assured Controls is an add-on for Enterprise Plus edition that allows precise control over cloud service provider access.';
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking Assured Controls:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'assured-controls');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 4: Access Transparency
async function checkAccessTransparency(auth, report) {
  console.log('Checking Access Transparency...');
  
  try {
    // API for checking if Access Transparency is enabled is not directly available
    
    const checkIndex = report.checks.findIndex(check => check.id === 'access-transparency');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. Access Transparency provides logs of actions taken by Google staff. Verify this is enabled in Admin Console > Security > Access Transparency.';
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking Access Transparency:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'access-transparency');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 5: Password Policy
async function checkPasswordPolicy(auth, report) {
  console.log('Checking Password Policy...');
  
  try {
    const directory = google.admin({ version: 'directory_v1', auth });
    
    // Get password policy settings
    const response = await directory.customers.get({
      customerKey: 'my_customer'
    });
    
    if (response.data && response.data.passwordStatus) {
      const passwordPolicy = response.data.passwordStatus;
      let isCompliant = true;
      let details = [];
      
      // Check minimum length (FedRAMP requires at least 12 characters)
      if (!passwordPolicy.passwordMinimumLength || passwordPolicy.passwordMinimumLength < 12) {
        isCompliant = false;
        details.push(`Password minimum length is ${passwordPolicy.passwordMinimumLength || 'not set'}, should be at least 12 characters`);
      }
      
      // Check complexity requirements
      if (!passwordPolicy.enforcePasswordPolicy) {
        isCompliant = false;
        details.push('Password policy enforcement is not enabled');
      }
      
      // Check password expiration (FedRAMP requires maximum 60 days)
      if (!passwordPolicy.passwordMaximumLength || passwordPolicy.passwordMaximumLength > 60) {
        isCompliant = false;
        details.push(`Password expiration is ${passwordPolicy.passwordMaximumLength || 'not set'} days, should be 60 days or less`);
      }
      
      const checkIndex = report.checks.findIndex(check => check.id === 'password-policy');
      
      if (isCompliant) {
        report.checks[checkIndex].status = 'Compliant';
        report.checks[checkIndex].details = 'Password policy meets FedRAMP requirements';
        report.summary.compliant++;
      } else {
        report.checks[checkIndex].status = 'Not Compliant';
        report.checks[checkIndex].details = `Password policy does not meet FedRAMP requirements: ${details.join('; ')}`;
        report.summary.nonCompliant++;
      }
      
      report.summary.notChecked--;
    } else {
      const checkIndex = report.checks.findIndex(check => check.id === 'password-policy');
      report.checks[checkIndex].status = 'Not Checked';
      report.checks[checkIndex].details = 'Could not retrieve password policy settings';
    }
  } catch (error) {
    console.error('Error checking Password Policy:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'password-policy');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 6: Two-Step Verification
async function checkTwoStepVerification(auth, report) {
  console.log('Checking Two-Step Verification...');
  
  try {
    const directory = google.admin({ version: 'directory_v1', auth });
    
    // Get 2SV settings
    const response = await directory.customers.get({
      customerKey: 'my_customer'
    });
    
    if (response.data && response.data.isEnforcedIn2Sv) {
      const checkIndex = report.checks.findIndex(check => check.id === 'two-step-verification');
      report.checks[checkIndex].status = 'Compliant';
      report.checks[checkIndex].details = '2-Step Verification is enforced domain-wide';
      report.summary.compliant++;
      report.summary.notChecked--;
    } else {
      const checkIndex = report.checks.findIndex(check => check.id === 'two-step-verification');
      report.checks[checkIndex].status = 'Not Compliant';
      report.checks[checkIndex].details = '2-Step Verification is not enforced domain-wide';
      report.summary.nonCompliant++;
      report.summary.notChecked--;
    }
  } catch (error) {
    console.error('Error checking Two-Step Verification:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'two-step-verification');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 7: Admin Privileges
async function checkAdminPrivileges(auth, report) {
  console.log('Checking Admin Privileges...');
  
  try {
    const directory = google.admin({ version: 'directory_v1', auth });
    
    // Get role assignments
    const response = await directory.roleAssignments.list({
      customer: 'my_customer'
    });
    
    if (response.data && response.data.items) {
      const roleAssignments = response.data.items;
      const superAdminAssignments = roleAssignments.filter(role => role.roleId === '101'); // Super Admin role ID
      
      // Get total admin count
      const adminCount = roleAssignments.length;
      const superAdminCount = superAdminAssignments.length;
      
      // For FedRAMP, principle of least privilege means minimizing super admin accounts
      // Using a threshold of 3 super admins as a reasonable assumption
      const isCompliant = superAdminCount <= 3;
      
      const checkIndex = report.checks.findIndex(check => check.id === 'admin-privileges');
      
      if (isCompliant) {
        report.checks[checkIndex].status = 'Compliant';
        report.checks[checkIndex].details = `Admin role assignments follow principle of least privilege. Total admin accounts: ${adminCount}, Super admin accounts: ${superAdminCount}`;
        report.summary.compliant++;
      } else {
        report.checks[checkIndex].status = 'Not Compliant';
        report.checks[checkIndex].details = `Too many super admin accounts (${superAdminCount}). For principle of least privilege, limit super admin accounts to 3 or fewer. Total admin accounts: ${adminCount}`;
        report.summary.nonCompliant++;
      }
      
      report.summary.notChecked--;
    } else {
      const checkIndex = report.checks.findIndex(check => check.id === 'admin-privileges');
      report.checks[checkIndex].status = 'Not Checked';
      report.checks[checkIndex].details = 'Could not retrieve admin role assignments';
    }
  } catch (error) {
    console.error('Error checking Admin Privileges:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'admin-privileges');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 8: Audit Logging
async function checkAuditLogging(auth, report) {
  console.log('Checking Audit Logging...');
  
  try {
    const reports = google.admin({ version: 'reports_v1', auth });
    
    // Try to fetch admin audit logs to check if audit logging is enabled
    const response = await reports.activities.list({
      userKey: 'all',
      applicationName: 'admin',
      maxResults: 1
    });
    
    const isLoggingEnabled = response.data && response.data.items && response.data.items.length > 0;
    
    const checkIndex = report.checks.findIndex(check => check.id === 'audit-logging');
    
    if (isLoggingEnabled) {
      report.checks[checkIndex].status = 'Compliant';
      report.checks[checkIndex].details = 'Audit logging is enabled and capturing events';
      report.summary.compliant++;
    } else {
      report.checks[checkIndex].status = 'Not Compliant';
      report.checks[checkIndex].details = 'Audit logging does not appear to be capturing events';
      report.summary.nonCompliant++;
    }
    
    report.summary.notChecked--;
  } catch (error) {
    console.error('Error checking Audit Logging:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'audit-logging');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 9: Security Center
async function checkSecurityCenter(auth, report) {
  console.log('Checking Security Center...');
  
  try {
    // API for checking Security Center configuration is not available
    // This requires Enterprise Plus and manual verification
    
    const checkIndex = report.checks.findIndex(check => check.id === 'security-center');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. Security Center is available for Enterprise Plus users. Check Admin Console > Security > Security Center.';
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking Security Center:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'security-center');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 10: Data Loss Prevention
async function checkDLP(auth, report) {
  console.log('Checking Data Loss Prevention...');
  
  try {
    // API for checking DLP configuration is not available
    // This requires manual verification
    
    const checkIndex = report.checks.findIndex(check => check.id === 'data-loss-prevention');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. Check Admin Console > Security > Data protection to verify if DLP rules are configured.';
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking DLP:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'data-loss-prevention');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 11: Context-Aware Access
async function checkContextAwareAccess(auth, report) {
  console.log('Checking Context-Aware Access...');
  
  try {
    // API for checking Context-Aware Access is not available
    // This requires Enterprise Plus and manual verification
    
    const checkIndex = report.checks.findIndex(check => check.id === 'context-aware-access');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. Context-Aware Access is available for Enterprise Plus users. Check Admin Console > Security > Access and data control > Context-Aware Access.';
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking Context-Aware Access:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'context-aware-access');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Check 12: Endpoint Management
async function checkEndpointManagement(auth, report) {
  console.log('Checking Endpoint Management...');
  
  try {
    // API for checking endpoint management is not available
    // This requires manual verification
    
    const checkIndex = report.checks.findIndex(check => check.id === 'endpoint-management');
    report.checks[checkIndex].status = 'Not Checked';
    report.checks[checkIndex].details = 'Manual verification required. Check Admin Console > Devices > Mobile & endpoints to verify endpoint management settings.';
    
    // Don't update summary as this requires manual verification
  } catch (error) {
    console.error('Error checking Endpoint Management:', error);
    
    const checkIndex = report.checks.findIndex(check => check.id === 'endpoint-management');
    report.checks[checkIndex].status = 'Error';
    report.checks[checkIndex].details = `Error during check: ${error.message}`;
  }
}

// Run the compliance check
checkFedRAMPCompliance();