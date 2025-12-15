
import email
import csv
import os
import mailbox
import re
from email.header import decode_header  


class EmailHeaderExtractor:
    def __init__(self):
        self.headers_to_extract = [
            'From', 'To', 'Subject', 'Date', 'Message-ID',
            'Return-Path', 'Received', 'Reply-To', 'Sender',
            'Content-Type', 'Authentication-Results',
            'DKIM-Signature'
        ]

    def decode_header_value(self, header_value):
        """Decode MIME-encoded email headers safely."""
        try:
            if isinstance(header_value, str):
                return header_value.strip()
            else:
                decoded_parts = []
                if hasattr(header_value, '__iter__') and not isinstance(header_value, str):
                    for part in header_value:
                        if isinstance(part, tuple):
                            bytes_data, encoding = part
                            if encoding:
                                decoded_parts.append(bytes_data.decode(encoding, errors='ignore'))
                            else:
                                decoded_parts.append(bytes_data.decode('utf-8', errors='ignore'))
                        else:
                            decoded_parts.append(str(part))
                    return ' '.join(decoded_parts).strip()
                else:
                    return str(header_value).strip()
        except:
            return str(header_value).strip()

    def extract_ip(self, msg):
        ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ipv6_regex = r'\b[0-9a-fA-F:]{2,}\b'

        xip = msg.get('X-Originating-IP', '')
        if xip:
            m = re.search(ipv4_regex, xip)
            if m:
                return m.group(0)

        auth_results = msg.get_all('Authentication-Results', []) or []
        for line in auth_results:
            m = re.search(r'sender IP is\s+(' + ipv4_regex + r')', line)
            if m:
                return m.group(1)

        received_headers = msg.get_all('Received', []) or []

        for rec in reversed(received_headers):
            ips = re.findall(ipv4_regex, rec)
            for ip in ips:
                if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.'):
                    continue
                if ip.startswith('172.'):
                    try:
                        second = int(ip.split('.')[1])
                        if 16 <= second <= 31:
                            continue
                    except:
                        pass
                return ip

        for rec in reversed(received_headers):
            m = re.search(ipv6_regex, rec)
            if m:
                return m.group(0)

        return ""

    def extract_headers_and_body(self, msg):
        """Extract headers, plain text body, HTML body, and Source_IP."""
        try:
            data = {}

            for header in self.headers_to_extract:
                header_value = msg.get(header, '')
                data[header] = self.decode_header_value(header_value)

            data['Source_IP'] = self.extract_ip(msg)

            data['Body_Text'] = self.extract_body_text(msg)
            data['Body_HTML'] = self.extract_body_html(msg)

            data['Body_Text'] = f"Subject: {data['Subject']}\n\n" + data['Body_Text']

            return data

        except Exception as e:
            print(f"Error processing email: {str(e)}")
            data = {header: '' for header in self.headers_to_extract}
            data['Source_IP'] = ''
            data['Body_Text'] = ''
            data['Body_HTML'] = ''
            return data

    def extract_from_eml_file(self, file_path):
        """Process single .eml email file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                email_content = file.read()

            msg = email.message_from_string(email_content)
            data = self.extract_headers_and_body(msg)
            data['Filename'] = os.path.basename(file_path)
            return data

        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")
            empty_data = {header: '' for header in self.headers_to_extract}
            empty_data['Filename'] = os.path.basename(file_path)
            empty_data['Source_IP'] = ''
            empty_data['Body_Text'] = ''
            empty_data['Body_HTML'] = ''
            return empty_data

    def extract_from_mbox_file(self, file_path):
        """Extract emails from .mbox file containing multiple messages."""
        all_emails = []
        try:
            mbox = mailbox.mbox(file_path)
            print(f"Processing mbox file: {file_path} ({len(mbox)} emails)")

            for i, msg in enumerate(mbox):
                try:
                    data = self.extract_headers_and_body(msg)
                    data['Filename'] = f"{os.path.basename(file_path)}_email_{i+1}"
                    all_emails.append(data)
                except:
                    empty_data = {header: '' for header in self.headers_to_extract}
                    empty_data['Filename'] = f"{os.path.basename(file_path)}_email_{i+1}_error"
                    empty_data['Source_IP'] = ''
                    empty_data['Body_Text'] = ''
                    empty_data['Body_HTML'] = ''
                    all_emails.append(empty_data)

            return all_emails

        except Exception as e:
            print(f"Error processing mbox {file_path}: {str(e)}")
            empty_data = {header: '' for header in self.headers_to_extract}
            empty_data['Filename'] = os.path.basename(file_path) + "_error"
            empty_data['Source_IP'] = ''
            empty_data['Body_Text'] = ''
            empty_data['Body_HTML'] = ''
            return [empty_data]

    def extract_body_text(self, msg):
        """Extract the plain text body only."""
        try:
            body_text = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode('utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
            return body_text.strip()
        except:
            return ""

    def extract_body_html(self, msg):
        """Extract the HTML body only."""
        try:
            body_html = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html += payload.decode('utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_html = payload.decode('utf-8', errors='ignore')
            return body_html.strip()
        except:
            return ""

    def process_directory(self, input_directory, output_csv):
        all_data = []

        print("🚀 Starting Email Header and Body Extraction...")
        print("Supported formats: .eml and .mbox\n")

        for filename in os.listdir(input_directory):
            file_path = os.path.join(input_directory, filename)

            if os.path.isfile(file_path):
                ext = os.path.splitext(filename.lower())[1]

                if ext == ".eml":
                    print(f"Processing .eml file: {filename}")
                    all_data.append(self.extract_from_eml_file(file_path))

                elif ext == ".mbox":
                    print(f"Processing .mbox file: {filename}")
                    all_data.extend(self.extract_from_mbox_file(file_path))

        if all_data:
            with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Filename'] + self.headers_to_extract + ['Source_IP', 'Body_Text', 'Body_HTML']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for data in all_data:
                    writer.writerow(data)

            print(f"\n✅ Extraction completed: {len(all_data)} emails processed.")
            print(f"📁 Results saved to: {output_csv}")

        else:
            print("❌ No .eml or .mbox files found!")

if __name__ == "__main__":
    extractor = EmailHeaderExtractor()
    input_dir = "/home/stiti/data"
    output_file = "/home/stiti/isthistheend/csv/email.csv"
    extractor.process_directory(input_dir, output_file)
