import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os

def send_emails(sender_email, sender_password, subject, html_template_path, recipients_file_path):
    """
    Send emails to all recipients in the provided list file
    """
    try:
        with open(html_template_path, "r", encoding="utf-8") as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"Error: HTML template file '{html_template_path}' not found.")
        return
    except Exception as e:
        print(f"Error loading HTML template: {e}")
        return


    try:
        with open(recipients_file_path, "r") as f:
            recipient_emails = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Recipients file '{recipients_file_path}' not found.")
        return
    except Exception as e:
        print(f"Error loading recipients list: {e}")
        return

    # SMTP Configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    # Connect to SMTP server
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        
        # Send to each recipient
        success_count = 0
        failed_emails = []
        
        for recipient_email in recipient_emails:
            try:
                # Create a new message for each recipient
                message = MIMEMultipart("alternative")
                message["Subject"] = subject
                message["From"] = sender_email
                message["To"] = recipient_email
                
                # Attach HTML content
                html_part = MIMEText(html_content, "html")
                message.attach(html_part)
                
                # Send email
                server.sendmail(sender_email, recipient_email, message.as_string())
                success_count += 1
                print(f"✓ Email sent to: {recipient_email}")
                
                # Add a small delay to avoid rate limiting
                time.sleep(1)
                
            except Exception as e:
                failed_emails.append((recipient_email, str(e)))
                print(f"✗ Failed to send to {recipient_email}: {e}")
                
        # Close SMTP connection
        server.quit()
        
        # Print summary
        print("\n--- Email Campaign Summary ---")
        print(f"Total recipients: {len(recipient_emails)}")
        print(f"Successfully sent: {success_count}")
        print(f"Failed: {len(failed_emails)}")
        
        if failed_emails:
            print("\nFailed recipients:")
            for email, error in failed_emails:
                print(f"  - {email}: {error}")
                
    except Exception as e:
        print(f"SMTP server connection error: {e}")

if __name__ == "__main__":
    # Email configuration
    sender_email = "eng.ahmed.abdel@gmail.com"
    sender_password = "application password here"  # Use an app password if 2FA is enabled
    subject = "Exam Link For HAV SIEBENS"
    
    # File paths
    html_template_path ="email_template1.html"
    recipients_file_path ="recipients.txt"
    
    # Send emails
    send_emails(sender_email, sender_password, subject, html_template_path, recipients_file_path)