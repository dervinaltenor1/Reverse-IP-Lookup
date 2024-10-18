import requests
import json
import sqlite3
import time
import datetime
import whois
import logging
from sqlite3 import Connection, Cursor
from config import DATABASE_FILE, REVERSE_LOOKUP_JSON, WHOIS_JSON, TIME_BETWEEN_REQUESTS


def setup_logger() -> None:
    logging.basicConfig(
        filename = "reverse_ip.log",
        level = logging.DEBUG,
        format = "%(asctime)s - %(levelname)s - %(message)s",
        filemode = "a"
    )
setup_logger()

TARGET_KEYS: set[str] = {'updated_date', 'creation_date', 'expiration_date'}

def run_whois(ip_address: str, whois_data_list: list[dict]) -> None:
    """Perform a WHOIS lookup for the given IP address."""

    logging.info(f"Attempting whois lookup for: {ip_address}")

    try:
        # Perform WHOIS lookup
        domain = whois.whois(ip_address)

        if domain:
            whois_data_list.append(domain)
            logging.info(f"Successfully retrieved WHOIS data for: {ip_address}")
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {ip_address}: {e}")

def get_ip() -> list[str]:
    """Retrieve malicious IPs from the database."""

    conn: Connection = None
    logging.info("Attempting to connect to sqlite database.")

    try:
        conn = sqlite3.connect(DATABASE_FILE) # Connect to the database
        logging.info("Succesfully connected to database.")
        cursor: Cursor = conn.cursor()

        # Execute SQL query to fetch IPs
        cursor.execute("SELECT ip FROM malicious_ips;")
        
        # Return a list of IPs
        return [ip[0] for ip in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Database error: {e}")

        # Return an empty list in case of an error
        return []
    finally:
        if conn:
            # Ensure the database connection is closed
            conn.close()
            logging.info("Closed SQLite connection")


def reverse_search_ip(ip_address: str, data_list: list[dict]) -> None:
    """Perform a reverse IP search and store the results."""
    logging.info(f"Reverse searching {ip_address}")

    try:
        # Make a request to the API
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        response.raise_for_status()  # Raise an error for bad HTTP responses

        # Parse the response JSON
        data = response.json()

        # Check if the response contains an error
        if 'status' in data and data['status'] == 'fail':
            logging.error(f"Error: {data.get('message', 'Unknown error occurred')}")
            return

        logging.info(f"Succesfully reverse searched {ip_address}")
        data_list.append(data)

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as req_err:
        logging.error(f"Request error occurred: {req_err}")
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON from response.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def save_to_json(data_list: list[dict], file: str) -> None:
    """Save the provided data list to a JSON file."""

    if file == WHOIS_JSON:
        # Convert dates if saving WHOIS data
        data_list = convert_dates(data_list)

    logging.info(f"Attempting to save to json file: {file}")

    try:
        # Open the file for writing
        with open(file, 'w') as json_file:
            # Write the JSON data
            json.dump(data_list, json_file, indent=4)
            logging.info(f"Succesfully saved to json file: {file}")
    except Exception as e:
        logging.error(f"Couldnt save to json file: {e}")


def convert_dates(data_list: list[dict]) -> list[dict]:
    """Convert datetime fields in the data list to ISO format."""

    try:
        for item in data_list:
            for key, value in item.items():
                # Check if the key is in TARGET_KEYS
                if key in TARGET_KEYS:
                    # Convert the datetime value
                    item[key] = convert_datetime(value)

        # Return the modified list
        return data_list
    except Exception as e:
        logging.error(f"Couldnt convert dates to iso format: {e}")
        # Return an empty list on error
        return []

def convert_datetime(dt):
    """Convert datetime or a list of datetimes to ISO format."""

    if isinstance(dt, list): # If the input is a list
        return [d.isoformat() for d in dt if isinstance(d, datetime.datetime)]  # Convert each datetime
    elif isinstance(dt, datetime.datetime): # If it's a single datetime
        return dt.isoformat() # Convert to ISO format
    return dt # Return the original value if it's not a datetime


def main() -> None:
    logging.info("Starting reverse IP searching")

    try:
        ip_list: list[str] = get_ip() # Retrieve the list of IPs

        # Check if the list is empty
        if not ip_list:
            logging.warning("No IP addresses found in the database.")
            return
        
        data_list: list[dict] = []
        whois_data_list: list[dict] = []

        for ip in ip_list:
            if ip:
                reverse_search_ip(ip, data_list)
                run_whois(ip, whois_data_list)

                # Wait before the next request
                time.sleep(TIME_BETWEEN_REQUESTS)
        
        # Save reverse search results to JSON
        save_to_json(data_list, REVERSE_LOOKUP_JSON)

        # Save WHOIS results to JSON
        save_to_json(whois_data_list, WHOIS_JSON)
        logging.info("Finished reverse searching and creating json files")

    except Exception as e:
        logging.error(f"Unexpected error occured: {e}")


if __name__ == '__main__':
    main()