#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import asyncio
import ipaddress
import mmap
import secrets
import subprocess
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Set, AsyncGenerator

import aiodns
import httpx
import orjson
import pyperclip
from loguru import logger
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Button, DataTable, Footer, Header, Static, RichLog, Input, Label, Checkbox, Select, DirectoryTree

# Configure logging
logger.remove()
logger.add(
    "logs/dnsscanner_{time}.log",
    rotation="50 MB",
    compression="zip",
    level="DEBUG",
)


class StatsWidget(Static):
    """Display scan statistics."""

    found = reactive(0)
    scanned = reactive(0)
    total = reactive(0)
    speed = reactive(0.0)
    elapsed = reactive(0.0)

    def render(self) -> str:
        """Render the stats."""
        return f"""[b cyan]DNS Scanner Statistics[/b cyan]

[yellow]Total IPs:[/yellow] {self.total:,}
[yellow]Scanned:[/yellow] {self.scanned:,}
[green]Found:[/green] {self.found}
[yellow]Speed:[/yellow] {self.speed:.1f} IPs/sec
[yellow]Elapsed:[/yellow] {self.elapsed:.1f}s
"""


class CustomProgressBar(Static):
    """Custom progress bar with ▓▒ style and float percentage."""

    progress = reactive(0.0)
    total = reactive(100.0)
    bar_width = 40  # Width of the bar in characters

    def render(self) -> str:
        """Render the custom progress bar."""
        if self.total <= 0:
            percent = 0.0
        else:
            percent = (self.progress / self.total) * 100
        
        # Calculate filled portion
        filled = int((percent / 100) * self.bar_width)
        empty = self.bar_width - filled
        
        # Build the bar with ▓ for filled and ▒ for empty
        bar = "▓" * filled + "▒" * empty
        
        # Color: green for filled, dim for empty
        return f"[green]{bar[:filled]}[/green][dim]{bar[filled:]}[/dim] [cyan]{percent:.2f}%[/cyan]"
    
    def update_progress(self, progress: float, total: float) -> None:
        """Update progress values."""
        self.progress = progress
        self.total = total


class DNSScannerTUI(App):
    """DNS Scanner with Textual TUI."""

    # Set Dracula theme as default
    ENABLE_COMMAND_PALETTE = False  # Disable command palette
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    /* Start Screen Styles */
    #start-screen {
        width: 100%;
        height: 100%;
        align: center middle;
    }
    
    #start-form {
        width: 80;
        height: auto;
        border: solid cyan;
        padding: 2;
        margin: 2;
    }
    
    #start-title {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: cyan;
        padding: 1;
    }
    
    .form-row {
        width: 100%;
        height: 3;
        margin: 1 0;
    }
    
    .form-label {
        width: 20;
        padding: 0 1;
    }
    
    .form-input {
        width: 1fr;
    }
    
    #file-browser-container {
        width: 100%;
        height: 15;
        border: solid green;
        margin: 1 0;
        display: none;
    }
    
    DirectoryTree {
        height: 100%;
    }
    
    Select {
        width: 1fr;
    }
    
    #progress-container {
        width: 100%;
        height: 3;
        margin: 0 1;
        border: solid cyan;
        padding: 0 1;
    }

    #start-buttons {
        width: 100%;
        height: auto;
        align: center middle;
        margin-top: 2;
    }
    
    /* Scan Screen Styles */
    #scan-screen {
        width: 100%;
        height: 100%;
    }

    #stats {
        width: 100%;
        height: auto;
        border: solid green;
        padding: 1;
        margin: 1;
    }

    #progress-bar {
        width: 100%;
        max-width: 100%;
        height: 1;
        content-align: center middle;
    }

    #main-content {
        width: 100%;
        height: 1fr;
    }

    #results {
        width: 60%;
        height: 100%;
        border: solid cyan;
        margin: 1;
    }

    #logs {
        width: 40%;
        height: 100%;
        border: solid yellow;
        margin: 1;
    }

    #controls {
        width: 100%;
        height: auto;
        margin: 1;
        align: center middle;
    }

    Button {
        margin: 0 1;
    }

    DataTable {
        height: 100%;
    }

    RichLog {
        height: 100%;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "save_results", "Save"),
    ]

    def __init__(self):
        super().__init__()
        self.subnet_file = ""
        self.domain = ""
        self.dns_type = "A"
        self.concurrency = 100
        self.random_subdomain = False
        self.test_slipstream = False
        self.slipstream_path = str(Path(__file__).parent / "slipstream-client" / "windows" / "slipstream-client.exe")
        self.slipstream_domain = ""
        self.found_servers: Set[str] = set()
        self.server_times: dict[str, float] = {}
        self.proxy_results: dict[str, str] = {}  # IP -> "Success", "Failed", or "Testing"
        self.start_time = 0.0
        self.last_update_time = 0.0
        self.last_table_update_time = 0.0
        self.current_scanned = 0
        self.table_needs_rebuild = False
        self.scan_started = False
        
        # Slipstream parallel testing config
        self.slipstream_max_concurrent = 3
        self.slipstream_base_port = 10800  # Base port, will use 10800, 10801, 10802
        self.available_ports: deque = deque()  # Available ports for testing
        self.slipstream_semaphore: asyncio.Semaphore = None  # Will be created in async context
        self.pending_slipstream_tests: deque = deque()  # Queue for pending tests
        self.slipstream_tasks: set = set()  # Track running slipstream tasks

    def compose(self) -> ComposeResult:
        """Create child widgets."""
        yield Header(show_clock=False)
        
        # Start Screen
        with Container(id="start-screen"):
            with Vertical(id="start-form"):
                yield Static("[b cyan]🔍 DNS Scanner Configuration[/b cyan]", id="start-title")
                
                with Horizontal(classes="form-row"):
                    yield Label("CIDR File:", classes="form-label")
                    yield Input(placeholder="Enter path or click Browse", id="input-file", classes="form-input")
                    yield Button("📂 Browse", id="browse-btn", variant="primary")
                
                with Container(id="file-browser-container"):
                    yield DirectoryTree(".", id="file-browser")
                
                with Horizontal(classes="form-row"):
                    yield Label("Domain:", classes="form-label")
                    yield Input(placeholder="e.g., google.com", id="input-domain", classes="form-input", value="google.com")
                
                with Horizontal(classes="form-row"):
                    yield Label("DNS Type:", classes="form-label")
                    yield Select(
                        [("A (IPv4)", "A"), ("AAAA (IPv6)", "AAAA"), ("MX (Mail)", "MX"), ("TXT", "TXT"), ("NS", "NS")],
                        value="A",
                        id="input-type",
                        classes="form-input"
                    )
                
                with Horizontal(classes="form-row"):
                    yield Label("Concurrency:", classes="form-label")
                    yield Input(placeholder="100", id="input-concurrency", classes="form-input", value="100")
                
                with Horizontal(classes="form-row"):
                    yield Label("Random Subdomain:", classes="form-label")
                    yield Checkbox("Enable", id="input-random")
                
                with Horizontal(classes="form-row"):
                    yield Label("Test with Slipstream:", classes="form-label")
                    yield Checkbox("Enable Proxy Test", id="input-slipstream")
                
                with Horizontal(id="start-buttons"):
                    yield Button("🚀 Start Scan", id="start-scan-btn", variant="success")
                    yield Button("🛑 Exit", id="exit-btn", variant="error")
        
        # Scan Screen (initially hidden)
        with Container(id="scan-screen"):
            yield StatsWidget(id="stats")
            with Container(id="progress-container"):
                yield CustomProgressBar(id="progress-bar")
            with Horizontal(id="main-content"):
                with Container(id="results"):
                    yield DataTable(id="results-table")
                with Container(id="logs"):
                    yield RichLog(id="log-display", highlight=True, markup=True)
            with Horizontal(id="controls"):
                yield Button("💾 Save Results", id="save-btn", variant="success")
                yield Button("🛑 Quit", id="quit-btn", variant="error")
        
        yield Footer()

    def on_mount(self) -> None:
        """Initialize when app is mounted."""
        # Set Dracula theme
        self.theme = "dracula"
        
        # Hide scan screen initially
        self.query_one("#scan-screen").display = False
        
        # Setup results table
        table = self.query_one("#results-table", DataTable)
        table.add_columns("IP Address", "Response Time", "Status", "Proxy Test")
        table.cursor_type = "row"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "start-scan-btn":
            self._start_scan_from_form()
        elif event.button.id == "browse-btn":
            # Toggle file browser visibility
            browser = self.query_one("#file-browser-container")
            browser.display = not browser.display
        elif event.button.id == "exit-btn":
            self.exit()
        elif event.button.id == "save-btn":
            self.action_save_results()
        elif event.button.id == "quit-btn":
            self.exit()

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection from directory tree."""
        # Set the selected file path
        file_input = self.query_one("#input-file", Input)
        file_input.value = str(event.path)
        # Hide browser
        self.query_one("#file-browser-container").display = False

    def _start_scan_from_form(self) -> None:
        """Get values from form and start scanning."""
        # Get form values
        file_input = self.query_one("#input-file", Input)
        domain_input = self.query_one("#input-domain", Input)
        type_select = self.query_one("#input-type", Select)
        concurrency_input = self.query_one("#input-concurrency", Input)
        random_checkbox = self.query_one("#input-random", Checkbox)
        slipstream_checkbox = self.query_one("#input-slipstream", Checkbox)
        
        self.subnet_file = file_input.value.strip()
        self.domain = domain_input.value.strip()
        self.slipstream_domain = self.domain
        self.dns_type = str(type_select.value) if type_select.value else "A"
        self.random_subdomain = random_checkbox.value
        self.test_slipstream = slipstream_checkbox.value
        
        try:
            self.concurrency = int(concurrency_input.value.strip() or "100")
        except ValueError:
            self.concurrency = 100
        
        # Validate
        if not self.subnet_file:
            self.notify("Please enter a CIDR file path!", severity="error")
            return
        
        if not Path(self.subnet_file).exists():
            self.notify(f"File not found: {self.subnet_file}", severity="error")
            return
        
        if not self.domain:
            self.notify("Please enter a domain!", severity="error")
            return
        
        # Switch to scan screen
        self.query_one("#start-screen").display = False
        self.query_one("#scan-screen").display = True
        
        # Setup log display
        log_widget = self.query_one("#log-display", RichLog)
        log_widget.write("[bold cyan]DNS Scanner Log[/bold cyan]")
        log_widget.write(f"[yellow]Subnet file:[/yellow] {self.subnet_file}")
        log_widget.write(f"[yellow]Domain:[/yellow] {self.domain}")
        log_widget.write(f"[yellow]DNS Type:[/yellow] {self.dns_type}")
        log_widget.write(f"[yellow]Concurrency:[/yellow] {self.concurrency}")
        log_widget.write(f"[yellow]Slipstream Test:[/yellow] {'Enabled' if self.test_slipstream else 'Disabled'}")
        log_widget.write("[green]Starting scan...[/green]\n")
        
        # Start scanning
        self.scan_started = True
        self.run_worker(self._scan_async(), exclusive=True)

    async def _scan_async(self) -> None:
        """Async scanning logic."""
        # Reset state for re-scanning
        self.found_servers.clear()
        self.server_times.clear()
        self.proxy_results.clear()
        self.current_scanned = 0
        self.table_needs_rebuild = False
        
        # Initialize slipstream parallel testing
        self.slipstream_semaphore = asyncio.Semaphore(self.slipstream_max_concurrent)
        self.available_ports = deque(range(self.slipstream_base_port, self.slipstream_base_port + self.slipstream_max_concurrent))
        self.pending_slipstream_tests.clear()
        self.slipstream_tasks.clear()
        
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_table_update_time = self.start_time

        # Notify user about CIDR loading
        self.notify("Reading CIDR file...", severity="information", timeout=3)
        self._log("[cyan]Analyzing CIDR file...[/cyan]")
        await asyncio.sleep(0)
        
        # Fast count of lines to estimate total
        loop = asyncio.get_event_loop()
        line_count = await loop.run_in_executor(None, self._count_file_lines, self.subnet_file)
        
        if line_count == 0:
            self._log("[red]ERROR: No valid subnets found in file![/red]")
            self.notify("No valid subnets! Check CIDR file format.", severity="error")
            return
        
        self._log(f"[cyan]Found {line_count} CIDR entries. Starting scan...[/cyan]")
        await asyncio.sleep(0)
        
        # Estimate total IPs (rough estimate: assume average /24)
        estimated_ips = line_count * 254
        
        try:
            stats = self.query_one("#stats", StatsWidget)
            stats.total = estimated_ips
            progress_bar = self.query_one("#progress-bar", CustomProgressBar)
            progress_bar.update_progress(0, estimated_ips)
        except Exception:
            pass
        
        logger.info(f"Starting chunked scan with concurrency {self.concurrency}")
        self._log("[cyan]Scan mode: Streaming chunks (no pre-loading)[/cyan]")
        self._log(f"[cyan]Concurrency: {self.concurrency} workers[/cyan]")
        await asyncio.sleep(0)
        
        self.notify("Scanning in real-time...", severity="information", timeout=3)

        # Create semaphore
        sem = asyncio.Semaphore(self.concurrency)
        
        # Stream IPs and scan in chunks - START IMMEDIATELY!
        self._log("[green]Starting real-time streaming scan...[/green]")
        await asyncio.sleep(0)
        
        chunk_size = 500  # Process 500 IPs at a time
        active_tasks = []
        chunk_num = 0
        
        async for ip_chunk in self._stream_ips_from_file():
            chunk_num += 1
            
            # Create tasks for this chunk
            for ip in ip_chunk:
                task = asyncio.create_task(self._test_dns_with_callback(ip, sem))
                active_tasks.append(task)
            
            # Process completed tasks periodically
            if len(active_tasks) >= chunk_size:
                self._log(f"[dim]Processing chunk {chunk_num}...[/dim]")
                # Wait for some tasks to complete
                done, active_tasks = await asyncio.wait(active_tasks, return_when=asyncio.FIRST_COMPLETED)
                
                # Process completed results
                for task in done:
                    try:
                        result = await task
                        await self._process_result(result)
                    except Exception as e:
                        logger.error(f"Task error: {e}")
                
                active_tasks = list(active_tasks)
                await asyncio.sleep(0)  # Yield to UI
        
        # Wait for all remaining tasks
        self._log("[cyan]Finishing remaining scans...[/cyan]")
        if active_tasks:
            done, _ = await asyncio.wait(active_tasks)
            for task in done:
                try:
                    result = await task
                    await self._process_result(result)
                except Exception as e:
                    logger.error(f"Task error: {e}")

        self._log(f"[cyan]Scan complete. Scanned: {self.current_scanned}, Found: {len(self.found_servers)}[/cyan]")
        logger.info(f"Scan complete. Scanned: {self.current_scanned}, Found: {len(self.found_servers)}")

        # Final table rebuild
        self._rebuild_table()
        
        # Wait for all pending slipstream tests to complete
        if self.test_slipstream and self.slipstream_tasks:
            self._log(f"[cyan]Waiting for {len(self.slipstream_tasks)} slipstream tests to complete...[/cyan]")
            if self.slipstream_tasks:
                await asyncio.gather(*self.slipstream_tasks, return_exceptions=True)
            self._rebuild_table()  # Rebuild after all tests complete
        
        # Auto-save results
        self._auto_save_results()
        
        self.notify("Scan complete! Results auto-saved.", severity="information")

    def _count_file_lines(self, filepath: str) -> int:
        """Fast line counting for CIDR file."""
        count = 0
        try:
            with open(filepath, 'rb') as f:
                for line in f:
                    line_str = line.strip()
                    if line_str and not line_str.startswith(b'#'):
                        count += 1
        except Exception:
            pass
        return count

    def _load_subnets(self) -> list[ipaddress.IPv4Network]:
        """Load subnets from file using fast mmap-based reading."""
        subnets = []
        logger.info(f"Loading subnets from {self.subnet_file}")
        try:
            # Fast reading using mmap for large files
            with open(self.subnet_file, 'r+b') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                    for line in iter(mmapped.readline, b""):
                        try:
                            line_str = line.decode('utf-8', errors='ignore').strip()
                            if line_str and not line_str.startswith("#"):
                                subnets.append(ipaddress.IPv4Network(line_str, strict=False))
                        except Exception as e:
                            logger.warning(f"Failed to parse line: {line_str[:50]} - {e}")
                            pass
        except (ValueError, OSError) as e:
            logger.warning(f"mmap failed: {e}, falling back to regular reading")
            # Fallback to regular reading if mmap fails (e.g., empty file)
            try:
                with open(self.subnet_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            try:
                                subnets.append(ipaddress.IPv4Network(line, strict=False))
                            except Exception as e:
                                logger.warning(f"Failed to parse line: {line[:50]} - {e}")
                                pass
            except Exception as e:
                logger.error(f"Failed to read subnet file: {e}")
        
        logger.info(f"Loaded {len(subnets)} subnets")
        return subnets

    async def _stream_ips_from_file(self) -> AsyncGenerator[list[str], None]:
        """Stream IPs from CIDR file in chunks without loading everything into memory."""
        chunk = []
        chunk_size = 500  # Yield 500 IPs at a time
        rng = secrets.SystemRandom()
        
        loop = asyncio.get_event_loop()
        
        def read_and_process():
            """Blocking function to read file and yield subnet chunks."""
            subnets = []
            try:
                with open(self.subnet_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            try:
                                subnet = ipaddress.IPv4Network(line, strict=False)
                                subnets.append(subnet)
                            except Exception:
                                pass
            except Exception as e:
                logger.error(f"Failed to read file: {e}")
            return subnets
        
        # Read subnets
        subnets = await loop.run_in_executor(None, read_and_process)
        rng.shuffle(subnets)
        
        # Generate IPs from subnets
        for net in subnets:
            # Split into /24 chunks
            if net.prefixlen >= 24:
                chunks = [net]
            else:
                chunks = list(net.subnets(new_prefix=24))
            
            rng.shuffle(chunks)
            
            for subnet_chunk in chunks:
                if subnet_chunk.num_addresses == 1:
                    chunk.append(str(subnet_chunk.network_address))
                else:
                    ips = list(subnet_chunk.hosts())
                    rng.shuffle(ips)
                    for ip in ips:
                        chunk.append(str(ip))
                        
                        # Yield chunk when it reaches size
                        if len(chunk) >= chunk_size:
                            yield chunk
                            chunk = []
                            await asyncio.sleep(0)  # Yield to event loop
        
        # Yield remaining IPs
        if chunk:
            yield chunk
    
    async def _test_dns_with_callback(self, ip: str, sem: asyncio.Semaphore) -> tuple[str, bool, float]:
        """Test DNS and return result tuple."""
        return await self._test_dns(ip, sem)
    
    async def _process_result(self, result: tuple[str, bool, float]) -> None:
        """Process a single DNS test result."""
        if isinstance(result, tuple):
            ip, is_valid, response_time = result
            
            # Update scanned count
            self.current_scanned += 1
            
            if is_valid:
                # Add to found servers and table immediately
                self._add_result(ip, response_time)
                self._log(f"[green]✓ Found DNS: {ip} ({response_time*1000:.0f}ms)[/green]")
                
                # Queue slipstream test if enabled (non-blocking)
                if self.test_slipstream:
                    self.proxy_results[ip] = "Pending"
                    task = asyncio.create_task(self._queue_slipstream_test(ip))
                    self.slipstream_tasks.add(task)
                    task.add_done_callback(self.slipstream_tasks.discard)
            
            # Update UI periodically
            if self.current_scanned % 10 == 0:
                current_time = time.time()
                elapsed = current_time - self.start_time
                
                try:
                    stats = self.query_one("#stats", StatsWidget)
                    stats.scanned = self.current_scanned
                    stats.elapsed = elapsed
                    stats.speed = self.current_scanned / elapsed if elapsed > 0 else 0
                    stats.found = len(self.found_servers)
                    
                    progress_bar = self.query_one("#progress-bar", CustomProgressBar)
                    progress_bar.update_progress(self.current_scanned, stats.total)
                except Exception:
                    pass

    def _collect_ips(self, subnets: list[ipaddress.IPv4Network]) -> list[str]:
        """Collect all IPs from subnets in random order using CSPRNG."""
        logger.info(f"Collecting IPs from {len(subnets)} subnets")
        all_ips = []
        rng = secrets.SystemRandom()  # Cryptographically secure RNG
        
        # Shuffle subnets first for randomization
        subnets_copy = list(subnets)
        rng.shuffle(subnets_copy)
        
        for net in subnets_copy:
            # Split into /24 chunks
            if net.prefixlen >= 24:
                chunks = [net]
            else:
                chunks = list(net.subnets(new_prefix=24))
            
            # Shuffle chunks for random order
            rng.shuffle(chunks)

            for chunk in chunks:
                # For /32 (single IP), just use the network address
                if chunk.num_addresses == 1:
                    all_ips.append(str(chunk.network_address))
                else:
                    # Get usable IPs (skip network and broadcast)
                    ips = list(chunk.hosts())
                    # Shuffle IPs within each chunk
                    rng.shuffle(ips)
                    all_ips.extend([str(ip) for ip in ips])

        logger.info(f"Collected {len(all_ips)} IPs to scan")
        return all_ips

    async def _test_dns(self, ip: str, sem: asyncio.Semaphore) -> tuple[str, bool, float]:
        """Test if IP is a DNS server that responds (even if answer is empty)."""
        async with sem:
            try:
                domain = self.domain
                if self.random_subdomain:
                    prefix = secrets.token_hex(4)
                    domain = f"{prefix}.{domain}"

                # 2 second timeout for DNS servers
                resolver = aiodns.DNSResolver(nameservers=[ip], timeout=2.0, tries=1)

                start = time.time()
                try:
                    # Use query method instead of query_dns for better compatibility
                    result = await resolver.query(domain, self.dns_type)
                    elapsed = time.time() - start

                    # If we got a result and it's under 2000ms, it's a valid DNS server
                    if result and elapsed < 2.0:
                        logger.debug(f"{ip}: DNS responded - {type(result)} in {elapsed*1000:.0f}ms")
                        return (ip, True, elapsed)
                    elif result:
                        # Too slow, reject it
                        logger.debug(f"{ip}: DNS too slow - {elapsed*1000:.0f}ms")
                        return (ip, False, 0)
                    
                    # No response
                    return (ip, False, 0)
                
                except aiodns.error.DNSError as dns_err:
                    elapsed = time.time() - start
                    # DNS errors like NXDOMAIN, NODATA, etc. mean the DNS server IS working
                    # Only connection/timeout errors mean it's not a valid DNS server
                    error_code = dns_err.args[0] if dns_err.args else 0
                    
                    # Error codes that indicate a working DNS server:
                    # 1 = NXDOMAIN (domain doesn't exist - but DNS is working!)
                    # 4 = NODATA (no records found - but DNS is working!)
                    # 3 = NXRRSET (RR type doesn't exist - but DNS is working!)
                    if error_code in (1, 3, 4) and elapsed < 2.0:
                        logger.debug(f"{ip}: DNS working with error code {error_code} in {elapsed*1000:.0f}ms")
                        return (ip, True, elapsed)
                    elif error_code in (1, 3, 4):
                        # Working but too slow
                        logger.debug(f"{ip}: DNS working but too slow - {elapsed*1000:.0f}ms")
                        return (ip, False, 0)
                    
                    # Other DNS errors = not a valid/working DNS server
                    logger.debug(f"{ip}: DNS error code {error_code} - not valid")
                    return (ip, False, 0)

            except asyncio.TimeoutError:
                logger.debug(f"{ip}: Timeout")
                return (ip, False, 0)
            except Exception as e:
                logger.debug(f"{ip}: Exception - {type(e).__name__}: {str(e)[:50]}")
                return (ip, False, 0)

    def _add_result(self, ip: str, response_time: float) -> None:
        """Add a found server to results immediately, resort periodically."""
        self.found_servers.add(ip)
        self.server_times[ip] = response_time
        
        # Add to table immediately for instant feedback
        try:
            table = self.query_one("#results-table", DataTable)
            
            server_ms = response_time * 1000
            if server_ms < 100:
                server_time_str = f"[green]{server_ms:.0f}ms[/green]"
            elif server_ms < 300:
                server_time_str = f"[yellow]{server_ms:.0f}ms[/yellow]"
            else:
                server_time_str = f"[red]{server_ms:.0f}ms[/red]"
            
            # Get proxy status
            proxy_status = self.proxy_results.get(ip, "N/A")
            if proxy_status == "Success":
                proxy_str = "[green]✓ Passed[/green]"
            elif proxy_status == "Failed":
                proxy_str = "[red]✗ Failed[/red]"
            elif proxy_status == "Testing":
                proxy_str = "[yellow]⏳ Testing...[/yellow]"
            elif proxy_status == "Pending":
                proxy_str = "[dim]⏳ Queued[/dim]"
            else:
                proxy_str = "[dim]N/A[/dim]"
            
            table.add_row(
                ip,
                server_time_str,
                "[green]Active[/green]",
                proxy_str,
            )
        except Exception:
            pass
        
        # Mark table for periodic resort
        self.table_needs_rebuild = True
        
        # Resort table every 2 seconds to maintain sorted order
        current_time = time.time()
        if current_time - self.last_table_update_time >= 2.0:
            self._rebuild_table()
            self.last_table_update_time = current_time
    
    def _rebuild_table(self) -> None:
        """Rebuild the entire table with sorted results."""
        if not self.table_needs_rebuild:
            return
        
        try:
            table = self.query_one("#results-table", DataTable)
            
            # Clear and rebuild table sorted by response time
            table.clear()
            sorted_servers = sorted(self.server_times.items(), key=lambda x: x[1])
            
            for server_ip, server_time in sorted_servers:
                server_ms = server_time * 1000
                if server_ms < 100:
                    server_time_str = f"[green]{server_ms:.0f}ms[/green]"
                elif server_ms < 300:
                    server_time_str = f"[yellow]{server_ms:.0f}ms[/yellow]"
                else:
                    server_time_str = f"[red]{server_ms:.0f}ms[/red]"
                
                # Get proxy status
                proxy_status = self.proxy_results.get(server_ip, "N/A")
                if proxy_status == "Success":
                    proxy_str = "[green]✓ Passed[/green]"
                elif proxy_status == "Failed":
                    proxy_str = "[red]✗ Failed[/red]"
                elif proxy_status == "Testing":
                    proxy_str = "[yellow]⏳ Testing...[/yellow]"
                elif proxy_status == "Pending":
                    proxy_str = "[dim]⏳ Queued[/dim]"
                else:
                    proxy_str = "[dim]N/A[/dim]"
                
                table.add_row(
                    server_ip,
                    server_time_str,
                    "[green]Active[/green]",
                    proxy_str,
                )
            
            self.table_needs_rebuild = False
        except Exception:
            pass  # Ignore errors during rebuild

    async def _queue_slipstream_test(self, dns_ip: str) -> None:
        """Queue and run slipstream test with semaphore for max concurrent tests."""
        async with self.slipstream_semaphore:
            # Get an available port
            while not self.available_ports:
                await asyncio.sleep(0.1)  # Wait for a port to become available
            
            port = self.available_ports.popleft()
            
            try:
                self.proxy_results[dns_ip] = "Testing"
                self._update_table_row(dns_ip)  # Update UI to show testing status
                self._log(f"[cyan]Testing {dns_ip} with slipstream on port {port}...[/cyan]")
                
                result = await self._test_slipstream_proxy(dns_ip, port)
                self.proxy_results[dns_ip] = result
                
                if result == "Success":
                    self._log(f"[green]✓ Proxy test PASSED: {dns_ip}[/green]")
                else:
                    self._log(f"[red]✗ Proxy test FAILED: {dns_ip}[/red]")
                
                self._update_table_row(dns_ip)  # Update UI with final result
                
            finally:
                # Return port to pool
                self.available_ports.append(port)
    
    def _update_table_row(self, ip: str) -> None:
        """Update a single row in the table for the given IP."""
        self.table_needs_rebuild = True
        self._rebuild_table()
    
    async def _test_slipstream_proxy(self, dns_ip: str, port: int) -> str:
        """Test DNS server using slipstream proxy on a specific port.
        
        Args:
            dns_ip: The DNS IP to test
            port: The port to use for slipstream
        
        Returns:
            "Success" if proxy works, "Failed" otherwise
        """
        process = None
        try:
            # Build slipstream command with dynamic port
            cmd = [
                self.slipstream_path,
                "--resolver", f"{dns_ip}:53",
                "--resolver", "8.8.4.4:53",
                "--tcp-listen-port", str(port),
                "--domain", self.slipstream_domain
            ]
            
            # Start slipstream process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            # Wait for "Connection ready" message (15 second timeout)
            connection_ready = False
            try:
                async with asyncio.timeout(15):
                    while True:
                        line = await process.stdout.readline()
                        if not line:
                            break
                        
                        line_str = line.decode('utf-8', errors='ignore').strip()
                        if "Connection ready" in line_str:
                            connection_ready = True
                            self._log(f"[cyan]{dns_ip}: Connection ready on port {port}[/cyan]")
                            break
            except asyncio.TimeoutError:
                self._log(f"[yellow]{dns_ip}: Slipstream connection timeout (15s)[/yellow]")
                return "Failed"
            
            if not connection_ready:
                return "Failed"
            
            # Test the proxy with google.com using dynamic port
            # Mid-high timeout (15 seconds) as requested
            proxy_url = f"http://127.0.0.1:{port}"
            test_success = False
            
            # Try HTTP proxy first
            try:
                async with httpx.AsyncClient(
                    proxy=proxy_url,
                    timeout=15.0,  # Mid-high timeout
                    follow_redirects=True
                ) as client:
                    response = await client.get("http://google.com")
                    if response.status_code in (200, 301, 302):
                        test_success = True
                        self._log(f"[green]{dns_ip}: HTTP proxy test passed (status {response.status_code})[/green]")
            except Exception:
                # Try SOCKS5 proxy
                try:
                    async with httpx.AsyncClient(
                        proxy=f"socks5://127.0.0.1:{port}",
                        timeout=15.0,  # Mid-high timeout
                        follow_redirects=True
                    ) as client:
                        response = await client.get("http://google.com")
                        if response.status_code in (200, 301, 302):
                            test_success = True
                            self._log(f"[green]{dns_ip}: SOCKS5 proxy test passed (status {response.status_code})[/green]")
                except Exception:
                    self._log(f"[red]{dns_ip}: Both HTTP and SOCKS5 proxy tests failed[/red]")
            
            return "Success" if test_success else "Failed"
            
        except Exception as e:
            self._log(f"[red]Slipstream error for {dns_ip}: {str(e)[:50]}[/red]")
            return "Failed"
        finally:
            # Always kill the slipstream process
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
    
    def _log(self, message: str) -> None:
        """Add message to log display."""
        try:
            log_widget = self.query_one("#log-display", RichLog)
            log_widget.write(message)
        except Exception:
            pass  # Widget might not be ready yet

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle double-click on DNS row to copy IP to clipboard."""
        table = self.query_one("#results-table", DataTable)
        row_key = event.row_key
        row = table.get_row(row_key)
        
        if row and len(row) > 0:
            ip = str(row[0]).strip()
            try:
                pyperclip.copy(ip)
                self.notify(f"{ip} copied!", severity="information", timeout=2)
            except Exception as e:
                self.notify(f"Copy failed: {str(e)[:30]}", severity="warning")

    def _auto_save_results(self) -> None:
        """Auto-save results at end of scan.
        
        When slipstream testing is enabled, only save DNS servers that passed the proxy test.
        """
        # Filter servers based on test mode
        if self.test_slipstream:
            # Only save servers that passed proxy test
            passed_servers = {
                ip: time for ip, time in self.server_times.items()
                if self.proxy_results.get(ip) == "Success"
            }
            if not passed_servers:
                self._log("[yellow]No DNS servers passed proxy test - nothing to save.[/yellow]")
                self._log(f"[yellow]Total DNS found: {len(self.found_servers)}, Passed proxy: 0[/yellow]")
                logger.warning(f"No servers passed proxy test. Total found: {len(self.found_servers)}")
                return
            servers_to_save = passed_servers
            self._log(f"[cyan]Saving {len(passed_servers)}/{len(self.found_servers)} DNS servers that passed proxy test...[/cyan]")
            logger.info(f"Saving {len(passed_servers)} servers that passed proxy test")
        else:
            # Save all found servers
            if not self.found_servers:
                self._log("[yellow]No DNS servers found to save.[/yellow]")
                return
            servers_to_save = self.server_times
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_dir = Path("results")
        output_dir.mkdir(exist_ok=True)

        # Save TXT with datetime filename
        txt_file = output_dir / f"{timestamp}.txt"
        
        # Sort by response time for output
        sorted_servers = sorted(servers_to_save.items(), key=lambda x: x[1])
        
        with open(txt_file, "w") as f:
            f.write(f"# DNS Scanner Results - {timestamp}\n")
            f.write(f"# Domain: {self.domain} | Type: {self.dns_type}\n")
            if self.test_slipstream:
                f.write("# Slipstream Test: ENABLED (only passed servers)\n")
            f.write(f"# Total Saved: {len(servers_to_save)}\n")
            f.write("#" + "="*50 + "\n\n")
            for server_ip, server_time in sorted_servers:
                f.write(f"{server_ip}\n")

        self._log(f"[green]✓ Results auto-saved to: {txt_file}[/green]")
        logger.info(f"Results auto-saved to {txt_file}")

    def action_save_results(self) -> None:
        """Save results to file.
        
        When slipstream testing is enabled, only save DNS servers that passed the proxy test.
        """
        # Filter servers based on test mode
        if self.test_slipstream:
            passed_servers = {
                ip: time for ip, time in self.server_times.items()
                if self.proxy_results.get(ip) == "Success"
            }
            if not passed_servers:
                self.notify("No servers passed proxy test!", severity="warning")
                return
            servers_to_save = passed_servers
        else:
            if not self.found_servers:
                self.notify("No results to save!", severity="warning")
                return
            servers_to_save = self.server_times

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_dir = Path("results")
        output_dir.mkdir(exist_ok=True)

        # Save JSON
        json_file = output_dir / f"scan_{timestamp}.json"
        elapsed = time.time() - self.start_time
        
        # Sort by response time
        sorted_servers = sorted(servers_to_save.items(), key=lambda x: x[1])
        servers_list = [ip for ip, _ in sorted_servers]
        
        data = {
            "scan_info": {
                "domain": self.domain,
                "dns_type": self.dns_type,
                "slipstream_test": self.test_slipstream,
                "total_found": len(self.found_servers),
                "total_passed_proxy": len([ip for ip in self.proxy_results if self.proxy_results[ip] == "Success"]) if self.test_slipstream else 0,
                "total_saved": len(servers_to_save),
                "elapsed_seconds": elapsed,
                "timestamp": timestamp,
            },
            "servers": servers_list,
        }

        with open(json_file, "wb") as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))

        # Save TXT
        txt_file = output_dir / f"scan_{timestamp}.txt"
        with open(txt_file, "w") as f:
            for server in servers_list:
                f.write(f"{server}\n")

        self.notify(f"Saved {len(servers_list)} servers: {json_file.name}", severity="information")
        logger.info(f"Results saved to {json_file}")


def main():
    """Main entry point."""
    try:
        Path("logs").mkdir(exist_ok=True)
        Path("results").mkdir(exist_ok=True)

        logger.info("DNS Scanner TUI starting")

        app = DNSScannerTUI()
        app.run()

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
