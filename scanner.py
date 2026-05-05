"""PortPulse - Multi-threaded Port Scanner & Banner Grabber.

This module provides the core scanning engine for the PortPulse tool.
It implements TCP socket connection handling, banner grabbing, and
service identification by matching captured banners against a local
signature database.

Author: egetangoren
License: MIT
"""

import json
import os
import queue
import socket
import threading
from typing import Any, Dict, List, Optional


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
        self._lock: threading.Lock = threading.Lock()

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

    def scan_port(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Scans a single port on the target host.

        Attempts to establish a TCP connection to the specified port. If the
        port is open, performs banner grabbing and service identification.

        Args:
            ip: The target IP address or hostname.
            port: The TCP port number to scan.

        Returns:
            A dictionary containing scan results for an open port with keys:
                - 'port': The scanned port number.
                - 'status': Always 'open' for returned results.
                - 'service': The identified service name.
                - 'banner': The captured banner string (may be empty).
            Returns None if the port is closed or the connection was refused.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result_code: int = sock.connect_ex((ip, port))

                if result_code == 0:
                    # Port is open. Attempt banner grabbing.
                    banner: str = self.grab_banner(ip, port)
                    service: str = self.identify_service(port, banner)

                    return {
                        "port": port,
                        "status": "open",
                        "service": service,
                        "banner": banner
                    }

        except socket.timeout:
            pass
        except socket.error:
            pass
        except ConnectionRefusedError:
            pass
        except OSError:
            pass

        return None

    def _worker(
        self,
        ip: str,
        port_queue: queue.Queue,
        results: List[Dict[str, Any]]
    ) -> None:
        """Worker thread function that processes ports from the queue.

        Continuously pulls port numbers from the shared queue, scans each
        port using the scan_port method, and appends successful results to
        the shared results list in a thread-safe manner.

        This method is designed to run as the target function for each
        worker thread in the thread pool.

        Args:
            ip: The target IP address or hostname to scan.
            port_queue: A thread-safe queue containing port numbers to scan.
            results: A shared list where open port scan results are stored.
                Access is synchronized using a threading lock.
        """
        while not port_queue.empty():
            try:
                port: int = port_queue.get_nowait()
            except queue.Empty:
                break

            result: Optional[Dict[str, Any]] = self.scan_port(ip, port)

            if result is not None:
                with self._lock:
                    results.append(result)

            port_queue.task_done()

    def scan_range(
        self,
        ip: str,
        ports: List[int],
        thread_count: int = 10
    ) -> List[Dict[str, Any]]:
        """Scans a range of ports concurrently using multiple threads.

        Populates a thread-safe queue with the specified port numbers,
        spawns the requested number of worker threads, and waits for all
        threads to complete. Results are collected and returned sorted by
        port number.

        Args:
            ip: The target IP address or hostname to scan.
            ports: A list of TCP port numbers to scan.
            thread_count: The number of concurrent worker threads to use.
                Defaults to 10. The actual count is capped at the number
                of ports to avoid spawning idle threads.

        Returns:
            A list of dictionaries representing open ports, sorted in
            ascending order by port number. Each dictionary contains:
                - 'port': The open port number.
                - 'status': Always 'open'.
                - 'service': The identified service name.
                - 'banner': The captured banner text.
        """
        port_queue: queue.Queue = queue.Queue()
        results: List[Dict[str, Any]] = []

        # Populate the queue with target ports.
        for port in ports:
            port_queue.put(port)

        # Cap the thread count to the number of ports to prevent idle threads.
        effective_thread_count: int = min(thread_count, len(ports))

        # Spawn worker threads.
        threads: List[threading.Thread] = []
        for _ in range(effective_thread_count):
            thread: threading.Thread = threading.Thread(
                target=self._worker,
                args=(ip, port_queue, results),
                daemon=True
            )
            thread.start()
            threads.append(thread)

        # Wait for all threads to finish.
        for thread in threads:
            thread.join()

        # Return results sorted by port number.
        return sorted(results, key=lambda x: x["port"])
