"""PortPulse - Multi-threaded Port Scanner & Banner Grabber.

This module provides the core scanning engine for the PortPulse tool.
It implements TCP socket connection handling, banner grabbing, and
service identification by matching captured banners against a local
signature database.

Author: egetangoren
License: MIT
"""

import argparse
import json
import os
import queue
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama for cross-platform terminal color support.
init(autoreset=True)


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


def parse_ports(port_string: str, signatures: Dict[str, Any]) -> List[int]:
    """Parses a user-provided port specification into a list of integers.

    Supports three input formats:
        - Comma-separated values: "22,80,443"
        - Hyphen-delimited range: "20-100"
        - Default: If None or empty, returns all ports from the signature database.

    Args:
        port_string: The raw port specification string from the CLI.
            Can be None to use the default signature-based port list.
        signatures: The loaded signature database dictionary, used
            to determine default ports when no specification is given.

    Returns:
        A sorted list of unique integer port numbers to scan.

    Raises:
        SystemExit: If the port string contains invalid values that
            cannot be parsed as integers or valid ranges.
    """
    if not port_string:
        # Default: scan all ports defined in the signature database.
        return sorted([int(port) for port in signatures.keys()])

    ports: List[int] = []

    # Check if the input is a range (e.g., "20-100").
    if "-" in port_string and "," not in port_string:
        try:
            parts: List[str] = port_string.split("-")
            start: int = int(parts[0])
            end: int = int(parts[1])

            if start > end:
                print(f"{Fore.RED}[!] Error: Invalid port range. "
                      f"Start ({start}) must be <= End ({end}).")
                sys.exit(1)

            if start < 1 or end > 65535:
                print(f"{Fore.RED}[!] Error: Port numbers must be "
                      f"between 1 and 65535.")
                sys.exit(1)

            ports = list(range(start, end + 1))
        except (ValueError, IndexError):
            print(f"{Fore.RED}[!] Error: Invalid port range format. "
                  f"Use 'START-END' (e.g., '20-100').")
            sys.exit(1)
    else:
        # Comma-separated values (e.g., "22,80,443").
        try:
            for part in port_string.split(","):
                port: int = int(part.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    print(f"{Fore.YELLOW}[!] Warning: Skipping invalid "
                          f"port number {port}. Must be 1-65535.")
        except ValueError:
            print(f"{Fore.RED}[!] Error: Invalid port format. Use "
                  f"comma-separated values (e.g., '22,80,443') or "
                  f"a range (e.g., '20-100').")
            sys.exit(1)

    return sorted(list(set(ports)))


def print_banner(target: str, port_count: int, thread_count: int) -> None:
    """Displays the PortPulse ASCII art banner and scan configuration.

    Prints a stylized ASCII art header followed by the scan parameters
    including target host, number of ports, and thread count.

    Args:
        target: The target IP address or hostname being scanned.
        port_count: The total number of ports to be scanned.
        thread_count: The number of concurrent threads to be used.
    """
    banner: str = f"""
{Fore.CYAN}{Style.BRIGHT}
 ██████╗  ██████╗ ██████╗ ████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
 ██████╔╝██║   ██║██████╔╝   ██║   ██████╔╝██║   ██║██║     ███████╗█████╗
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝
 ██║     ╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  Multi-threaded Port Scanner & Banner Grabber{Style.RESET_ALL}
{Fore.BLUE}  ─────────────────────────────────────────────{Style.RESET_ALL}
"""
    print(banner)
    print(f"  {Fore.YELLOW}[*]{Fore.WHITE} Target   : {Fore.GREEN}{target}")
    print(f"  {Fore.YELLOW}[*]{Fore.WHITE} Ports    : {Fore.GREEN}{port_count}")
    print(f"  {Fore.YELLOW}[*]{Fore.WHITE} Threads  : {Fore.GREEN}{thread_count}")
    print(f"  {Fore.BLUE}─────────────────────────────────────────────{Style.RESET_ALL}")
    print()


def display_results(
    results: List[Dict[str, Any]],
    elapsed_time: float
) -> None:
    """Formats and displays scan results as a colored ASCII table.

    Uses the tabulate library to render open port results in a
    grid-formatted table with colored status indicators. Also prints
    a summary line with the total number of open ports found and
    the total scan duration.

    Args:
        results: A list of dictionaries containing scan results.
            Each dictionary must have keys: 'port', 'status',
            'service', and 'banner'.
        elapsed_time: The total scan duration in seconds.
    """
    if not results:
        print(f"  {Fore.YELLOW}[!] No open ports found.{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}[*] Scan completed in "
              f"{elapsed_time:.2f} seconds.{Style.RESET_ALL}")
        return

    # Build table rows with colored status.
    table_data: List[List[str]] = []
    for entry in results:
        banner_display: str = entry["banner"][:60] + "..." \
            if len(entry["banner"]) > 60 else entry["banner"]
        if not banner_display:
            banner_display = f"{Fore.YELLOW}N/A{Style.RESET_ALL}"

        table_data.append([
            f"{Fore.CYAN}{entry['port']}{Style.RESET_ALL}",
            f"{Fore.GREEN}{entry['status'].upper()}{Style.RESET_ALL}",
            f"{Fore.WHITE}{entry['service']}{Style.RESET_ALL}",
            banner_display
        ])

    headers: List[str] = [
        f"{Fore.WHITE}{Style.BRIGHT}PORT{Style.RESET_ALL}",
        f"{Fore.WHITE}{Style.BRIGHT}STATUS{Style.RESET_ALL}",
        f"{Fore.WHITE}{Style.BRIGHT}SERVICE{Style.RESET_ALL}",
        f"{Fore.WHITE}{Style.BRIGHT}BANNER{Style.RESET_ALL}"
    ]

    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    print()
    print(f"  {Fore.GREEN}[+] {len(results)} open port(s) found.")
    print(f"  {Fore.BLUE}[*] Scan completed in "
          f"{elapsed_time:.2f} seconds.{Style.RESET_ALL}")


def save_results_to_json(
    results: List[Dict[str, Any]],
    output_path: str,
    target: str,
    elapsed_time: float
) -> None:
    """Saves scan results to a JSON file.

    Writes the scan results along with metadata (target, timestamp,
    duration) to the specified output file in JSON format.

    Args:
        results: A list of dictionaries containing scan results.
        output_path: The file path to write the JSON output to.
        target: The target IP address or hostname that was scanned.
        elapsed_time: The total scan duration in seconds.
    """
    output_data: Dict[str, Any] = {
        "target": target,
        "scan_duration_seconds": round(elapsed_time, 2),
        "total_open_ports": len(results),
        "results": results
    }

    try:
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(output_data, file, indent=4, ensure_ascii=False)
        print(f"  {Fore.GREEN}[+] Results saved to: {output_path}")
    except IOError as error:
        print(f"  {Fore.RED}[!] Error saving results: {error}")


def main() -> None:
    """Main entry point for the PortPulse CLI application.

    Parses command-line arguments, initializes the scanner, executes
    the multi-threaded port scan, and displays or saves the results.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="PortPulse",
        description="Multi-threaded Port Scanner & Banner Grabber.",
        epilog="Example: python scanner.py 192.168.1.1 -p 22,80,443 -t 20"
    )

    parser.add_argument(
        "target",
        type=str,
        help="Target IP address or hostname to scan."
    )
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default=None,
        help="Ports to scan. Comma-separated (e.g., '22,80,443') "
             "or range (e.g., '20-100'). Defaults to common ports."
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads. Default: 10."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Save results to a JSON file (e.g., 'results.json')."
    )

    args: argparse.Namespace = parser.parse_args()

    # Initialize the scanner.
    scanner: PortScanner = PortScanner(target=args.target)

    # Parse the port specification.
    ports: List[int] = parse_ports(args.ports, scanner.signatures)

    # Display the startup banner.
    print_banner(args.target, len(ports), args.threads)

    # Execute the scan and measure elapsed time.
    print(f"  {Fore.YELLOW}[*] Scanning in progress..."
          f"{Style.RESET_ALL}\n")

    start_time: float = time.time()
    results: List[Dict[str, Any]] = scanner.scan_range(
        ip=args.target,
        ports=ports,
        thread_count=args.threads
    )
    end_time: float = time.time()
    elapsed_time: float = end_time - start_time

    # Display results.
    display_results(results, elapsed_time)

    # Optionally save results to JSON.
    if args.output:
        print()
        save_results_to_json(results, args.output, args.target, elapsed_time)

    print()


if __name__ == "__main__":
    main()
