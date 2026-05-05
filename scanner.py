"""PortPulse - Multi-threaded Port Scanner & Banner Grabber.

This module provides the core scanning engine for the PortPulse tool.
It implements TCP socket connection handling, banner grabbing, and
service identification by matching captured banners against a local
signature database.

Author: egetangoren
License: MIT
"""

import json
import socket
import os
from typing import Dict, Any, Optional


class PortScanner:
    """Core port scanning engine with banner grabbing and service identification.

    This class manages TCP socket connections to target hosts, captures
    service banners from open ports, and identifies running services by
    matching banner content against a local signature database loaded
    from 'signatures.json'.

    Attributes:
        target: The target IP address or hostname to scan.
        timeout: Socket connection timeout in seconds.
        signatures: Dictionary of port signatures loaded from the
            local signature database file.
    """

    DEFAULT_TIMEOUT: float = 2.0
    MAX_BANNER_LENGTH: int = 1024
    SIGNATURES_FILE: str = "signatures.json"

    def __init__(self, target: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        """Initializes the PortScanner with a target host and timeout.

        Args:
            target: The target IP address or hostname to scan.
            timeout: Socket connection timeout in seconds. Defaults to 2.0.
        """
        self.target: str = target
        self.timeout: float = timeout
        self.signatures: Dict[str, Any] = self._load_signatures()

    def _load_signatures(self) -> Dict[str, Any]:
        """Loads the service signature database from the JSON file.

        Reads the 'signatures.json' file located in the same directory as
        this script. The file contains known port-to-service mappings and
        banner keyword patterns used for service identification.

        Returns:
            A dictionary mapping port numbers (as strings) to their
            service information including name, description, and keywords.

        Raises:
            FileNotFoundError: If the signatures file does not exist.
            json.JSONDecodeError: If the signatures file contains invalid JSON.
        """
        signatures_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            self.SIGNATURES_FILE
        )

        try:
            with open(signatures_path, "r", encoding="utf-8") as file:
                signatures: Dict[str, Any] = json.load(file)
                return signatures
        except FileNotFoundError:
            print(f"[!] Warning: Signature file '{self.SIGNATURES_FILE}' "
                  f"not found. Service identification will be limited.")
            return {}
        except json.JSONDecodeError as error:
            print(f"[!] Warning: Failed to parse '{self.SIGNATURES_FILE}': "
                  f"{error}. Service identification will be limited.")
            return {}

    def grab_banner(self, ip: str, port: int) -> str:
        """Attempts to grab the service banner from an open port.

        Establishes a TCP socket connection to the specified IP and port,
        then reads up to 1024 bytes of data (the service banner or welcome
        message) within the configured timeout period.

        Args:
            ip: The target IP address or hostname to connect to.
            port: The target TCP port number.

        Returns:
            The captured banner string, stripped of leading/trailing
            whitespace. Returns an empty string if the connection fails,
            times out, or no banner data is received.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))

                # Some services send a banner immediately upon connection.
                # Others require an initial request (e.g., HTTP).
                try:
                    banner: bytes = sock.recv(self.MAX_BANNER_LENGTH)
                    return banner.decode("utf-8", errors="ignore").strip()
                except socket.timeout:
                    # The service is open but did not send a banner
                    # within the timeout period.
                    return ""

        except socket.timeout:
            return ""
        except socket.error:
            return ""
        except ConnectionRefusedError:
            return ""
        except OSError:
            return ""

    def identify_service(self, port: int, banner: str) -> str:
        """Identifies the service running on a port using banner analysis.

        Performs a case-insensitive comparison of the captured banner text
        against the keyword list defined in the signature database for the
        given port. If a keyword match is found, the corresponding service
        name is returned. If no banner was captured or no keyword matches,
        the default service name from the signature database is used as a
        fallback based on the port number alone.

        Args:
            port: The TCP port number where the service was detected.
            banner: The captured banner string from the service. Can be
                an empty string if no banner was obtained.

        Returns:
            The identified service name (e.g., "SSH", "HTTP", "FTP").
            Returns "Unknown" if the port is not in the signature database
            and no banner match could be made.
        """
        port_key: str = str(port)
        signature: Optional[Dict[str, Any]] = self.signatures.get(port_key)

        # If we have a banner, attempt keyword matching.
        if banner and signature:
            banner_lower: str = banner.lower()
            keywords: list = signature.get("keywords", [])

            for keyword in keywords:
                if keyword.lower() in banner_lower:
                    return signature.get("service", "Unknown")

        # Fallback: use the default service name from the signature database
        # based on the port number, even if no banner was captured.
        if signature:
            return signature.get("service", "Unknown")

        return "Unknown"
