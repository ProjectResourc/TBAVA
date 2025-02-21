from flask import Flask, request, jsonify, render_template, send_file
from flask_socketio import SocketIO, emit
import subprocess
import json
from pathlib import Path
import os
import shlex
import logging
import re
import uuid
from datetime import datetime

# Define the base directory (penetration_testing_framework/)
BASE_DIR = Path(__file__).parent.resolve()

# Initialize Flask app with custom template and static folders
app = Flask(
    __name__,
    template_folder=str(BASE_DIR),                # Templates are in the root directory
    static_folder=str(BASE_DIR / 'static')          # Static files are in 'static/' directory
)

# Initialize SocketIO with CORS allowed for all origins
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging to output to both file and console
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(BASE_DIR / "server.log"),
        logging.StreamHandler()
    ]
)

# Define the path to the knowledge base JSON
KNOWLEDGE_BASE_PATH = BASE_DIR / 'dynamic_tools_commands.json'

def validate_knowledge_base(knowledge_base):
    """
    Validates the structure of the knowledge base JSON.
    Ensures that each phase, tool, and command adhere to the expected format.
    """
    if not isinstance(knowledge_base, dict):
        raise ValueError("Knowledge base should be a dictionary at the top level.")

    for phase, details in knowledge_base.items():
        if not isinstance(details, dict):
            raise ValueError(f"Details for phase '{phase}' should be a dictionary.")

        # Validate 'commands' section
        commands = details.get('commands')
        if commands is not None:
            if not isinstance(commands, dict):
                raise ValueError(f"'commands' in phase '{phase}' should be a dictionary.")
            
            for tool, cmds in commands.items():
                if not isinstance(cmds, list):
                    raise ValueError(f"Commands for tool '{tool}' under phase '{phase}' should be a list.")
                
                for cmd in cmds:
                    if isinstance(cmd, dict):
                        if 'command' not in cmd:
                            raise KeyError(f"Missing 'command' key in tool '{tool}' under phase '{phase}': {cmd}")
                    elif isinstance(cmd, str):
                        logging.warning(f"Command for tool '{tool}' under phase '{phase}' is a string. Consider using a dictionary for consistency.")
                    else:
                        raise ValueError(f"Unsupported command format in tool '{tool}' under phase '{phase}': {cmd}")

        # Validate 'cli_tools' and 'web_tools' if necessary
        for tool_type in ['cli_tools', 'web_tools']:
            tools = details.get(tool_type, [])
            if not isinstance(tools, list):
                raise ValueError(f"'{tool_type}' in phase '{phase}' should be a list.")
            for tool in tools:
                if not isinstance(tool, str):
                    raise ValueError(f"Tool names in '{tool_type}' under phase '{phase}' should be strings.")

# Check if the knowledge base JSON exists
if not KNOWLEDGE_BASE_PATH.exists():
    logging.error(f"Knowledge base JSON not found at {KNOWLEDGE_BASE_PATH.resolve()}")
    raise FileNotFoundError(f"Knowledge base JSON not found at {KNOWLEDGE_BASE_PATH.resolve()}")

# Load and validate the knowledge base JSON
try:
    with KNOWLEDGE_BASE_PATH.open('r') as f:
        KNOWLEDGE_BASE = json.load(f)
    logging.info(f"Knowledge base loaded successfully from {KNOWLEDGE_BASE_PATH.resolve()}")
    validate_knowledge_base(KNOWLEDGE_BASE)
except json.JSONDecodeError as e:
    logging.error(f"Error decoding JSON: {e}")
    raise
except Exception as e:
    logging.error(f"Unexpected error loading knowledge base: {e}")
    raise

# Define the base reports directory
BASE_REPORTS_DIR = BASE_DIR / 'static' / 'reports'
BASE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def is_valid_ip(ip):
    """
    Validates an IPv4 address.
    """
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not pattern.match(ip):
        return False
    parts = ip.split('.')
    for part in parts:
        if not 0 <= int(part) <= 255:
            return False
    return True

@app.route('/')
def welcome():
    """
    Serves the welcome.html page.
    (The extraction log will be loaded directly in the HTML via an iframe.)
    """
    try:
        return render_template('welcome.html')
    except Exception as e:
        logging.error(f"Error rendering welcome.html: {e}", exc_info=True)
        return "Welcome page not found.", 500

@app.route('/index.html')
def index_page():
    """
    Serves the index.html page and passes the content of server.log.
    """
    server_log_path = BASE_DIR / "server.log"
    server_log_content = ""
    if server_log_path.exists():
        server_log_content = server_log_path.read_text(encoding="utf-8", errors="replace")
    try:
        return render_template('index.html', server_log=server_log_content)
    except Exception as e:
        logging.error(f"Error rendering index.html: {e}", exc_info=True)
        return "Index page not found.", 500

# NEW ROUTE: Serve extraction.log directly.
@app.route('/extraction_log')
def extraction_log_file():
    """
    Serves the extraction.log file as plain text.
    """
    log_path = BASE_DIR / "extraction.log"
    if log_path.exists():
        return send_file(str(log_path), mimetype="text/plain")
    else:
        return "No log available.", 404

@app.route('/start-extraction', methods=['POST'])
def start_extraction():
    """
    Endpoint to start the extraction process by running the extraction_script.py.
    """
    try:
        # Call the extraction_script.py using subprocess
        result = subprocess.run(['python3', 'extraction_script.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check if the script ran successfully
        if result.returncode == 0:
            logging.info("Extraction script completed successfully.")
            return jsonify({'status': 'Extraction process started.'}), 200
        else:
            error_msg = f"Error running extraction script: {result.stderr}"
            logging.error(error_msg)
            return jsonify({'error': error_msg}), 500
    except Exception as e:
        logging.error(f"Error executing extraction script: {e}")
        return jsonify({'error': f"An error occurred: {str(e)}"}), 500

@app.route('/extraction-status', methods=['GET'])
def extraction_status():
    """
    Endpoint to check the status of the extraction process.
    For demonstration purposes, this always returns "completed."
    In a real implementation, update this based on the actual process.
    """
    status = "completed"  # Update this dynamically as needed
    return jsonify({"status": status})

@app.route('/start_pentest', methods=['POST'])
def start_pentest():
    """
    Endpoint to initiate the penetration test.
    """
    ip_address = request.form.get('ip')
    logging.debug(f"Received IP address: {ip_address}")

    # Validate the IP address
    if not ip_address or not is_valid_ip(ip_address):
        logging.warning("Invalid IP address received.")
        return jsonify({'error': 'A valid IPv4 address is required.'}), 400

    # Create a unique session ID using UUID
    session_id = uuid.uuid4().hex
    logging.info(f"Generated session ID: {session_id}")

    # Emit an event to the frontend to notify that pentest has started
    socketio.emit('pentest_started', {'ip': ip_address, 'session_id': session_id})
    logging.info(f"Pentest started for IP: {ip_address} with session ID: {session_id}")

    # Start the penetration test in a background thread
    socketio.start_background_task(target=execute_pentest, ip=ip_address, session_id=session_id)

    return jsonify({'status': 'Pentest started.', 'session_id': session_id}), 200

@socketio.on('connect')
def handle_connect():
    """
    Handles new client connections.
    """
    logging.info('Client connected')
    emit('terminal_output', {'output': 'Connected to the server.\n'})

def execute_pentest(ip, session_id):
    """
    Executes penetration testing commands based on the knowledge base and the provided IP.
    Streams output to the frontend in real-time and saves outputs to report files.
    """
    logging.info(f"Starting penetration test on IP: {ip} with session ID: {session_id}")

    reports_dir = BASE_REPORTS_DIR / session_id
    # Create directories for each phase
    for phase in KNOWLEDGE_BASE.keys():
        phase_key = phase.lower().replace(' ', '_')
        (reports_dir / phase_key).mkdir(parents=True, exist_ok=True)
    (reports_dir / 'reports').mkdir(parents=True, exist_ok=True)

    # Initialize a dictionary to store report data
    report_data = {
        'reconnaissance_reports': {},
        'scanning_reports': {},
        'exploitation_reports': {},
        'maintenance_reports': {},
        'covering_tracks_reports': {}
    }

    # Initialize an errors list
    errors = []

    for phase, details in KNOWLEDGE_BASE.items():
        phase_key = phase.lower().replace(' ', '_')
        logging.info(f"Executing phase: {phase}")
        socketio.emit('terminal_output', {'output': f'\n=== Phase: {phase} ===\n'})

        cli_tools = details.get('cli_tools', [])
        web_tools = details.get('web_tools', [])
        commands = details.get('commands', {})

        if not commands:
            logging.warning(f"No commands found for phase '{phase}'. Skipping command execution for this phase.")
            socketio.emit('terminal_output', {'output': f"No commands found for phase '{phase}'. Skipping.\n"})
            continue

        for tool, cmds in commands.items():
            for cmd in cmds:
                # Handle both dict and string types for cmd
                if isinstance(cmd, dict):
                    command = cmd.get('command')
                    cmd_type = cmd.get('type', 'CLI')  # Default to CLI if not specified
                elif isinstance(cmd, str):
                    command = cmd
                    cmd_type = 'CLI'
                else:
                    logging.warning(f"Unsupported command format: {cmd}")
                    socketio.emit('terminal_output', {'output': f"Unsupported command format: {cmd}\n"})
                    continue

                if not command:
                    logging.warning(f"No command found for tool {tool} in phase {phase}")
                    socketio.emit('terminal_output', {'output': f"No command found for tool {tool} in phase {phase}\n"})
                    continue

                # Replace placeholders with actual values
                command = command.replace('{TARGET_IP}', ip).replace('{ip}', ip)
                port = '80'  # Default port
                command = command.replace('{PORT}', port)

                logging.info(f"Executing command: {command} (Type: {cmd_type})")
                socketio.emit('terminal_output', {'output': f'$ {command}\n'})

                try:
                    # Split the command into arguments safely
                    args = shlex.split(command)
                    logging.debug(f"Command arguments: {args}")

                    # Execute the command
                    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    # Define the output file path
                    safe_tool_name = re.sub(r'\W+', '_', tool.lower())
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_filename = f"{safe_tool_name}_{timestamp}.txt"
                    output_file_path = reports_dir / phase_key / output_filename

                    with open(output_file_path, 'w') as output_file:
                        # Stream stdout and save to file
                        for line in iter(process.stdout.readline, ''):
                            if line:
                                socketio.emit('terminal_output', {'output': line})
                                logging.debug(f"STDOUT: {line.strip()}")
                                output_file.write(line)
                        process.stdout.close()

                        # Stream stderr and save to file
                        for line in iter(process.stderr.readline, ''):
                            if line:
                                socketio.emit('terminal_output', {'output': line})
                                logging.debug(f"STDERR: {line.strip()}")
                                output_file.write(line)
                        process.stderr.close()

                    # Wait for the command to complete
                    return_code = process.wait()
                    logging.info(f"Command '{command}' exited with code {return_code}")

                    if return_code != 0:
                        error_msg = f"Command '{command}' exited with code {return_code}\n"
                        errors.append(error_msg)
                        socketio.emit('terminal_output', {'output': error_msg})
                        logging.error(error_msg)
                except FileNotFoundError:
                    error_msg = f"Command not found: {command.split()[0]}\n"
                    errors.append(error_msg)
                    socketio.emit('terminal_output', {'output': error_msg})
                    logging.error(error_msg)
                except Exception as e:
                    error_msg = f"Error executing command '{command}': {str(e)}\n"
                    errors.append(error_msg)
                    socketio.emit('terminal_output', {'output': error_msg})
                    logging.exception("An unexpected error occurred during command execution.")

                # Update report_data
                report_key = f"{phase_key}_reports"
                if report_key in report_data:
                    report_data[report_key][tool] = output_filename

    # Handle errors after all commands have been processed
    if errors:
        errors_file = reports_dir / 'reports' / 'errors.txt'
        with errors_file.open('w') as ef:
            ef.writelines(errors)
        logging.info("Errors encountered during pentest. Saved to errors.txt")
        socketio.emit('terminal_output', {'output': "Errors encountered during pentest. Check errors.txt for details.\n"})

    # Generate final reports (Placeholder: Create empty files)
    final_report_pdf = reports_dir / 'reports' / 'final_report.pdf'
    final_report_html = reports_dir / 'reports' / 'final_report.html'
    final_report_md = reports_dir / 'reports' / 'final_report.md'

    for report_file in [final_report_pdf, final_report_html, final_report_md]:
        report_file.touch()

    # Create additional report files
    anomalous_ports = reports_dir / 'reports' / 'anomalous_ports.txt'
    cves_found = reports_dir / 'reports' / 'cves_found.txt'
    remediation = reports_dir / 'reports' / 'remediation.txt'

    for file in [anomalous_ports, cves_found, remediation]:
        file.touch()

    logging.info("Penetration testing completed.")
    socketio.emit('pentest_completed', {'message': 'Penetration testing completed.', 'session_id': session_id})

@app.route('/dashboard/<session_id>')
def dashboard(session_id):
    """
    Renders the dashboard with penetration testing reports for a given session.
    """
    reports_path = BASE_REPORTS_DIR / session_id

    if not reports_path.exists():
        logging.error(f"Reports for session {session_id} not found.")
        return "Reports not found.", 404

    # Initialize dictionaries to hold report mappings
    reconnaissance_reports = {}
    scanning_reports = {}
    exploitation_reports = {}
    maintenance_reports = {}
    covering_tracks_reports = {}

    # Create a mapping from phase to the corresponding reports dictionary
    phase_to_reports = {
        'reconnaissance_reports': reconnaissance_reports,
        'scanning_reports': scanning_reports,
        'exploitation_reports': exploitation_reports,
        'maintenance_reports': maintenance_reports,
        'covering_tracks_reports': covering_tracks_reports
    }

    # Populate report mappings for each phase
    for phase in KNOWLEDGE_BASE.keys():
        phase_key = phase.lower().replace(' ', '_')
        phase_dir = reports_path / phase_key
        if phase_dir.exists():
            for report_file in phase_dir.glob('*.txt'):
                tool_name = report_file.stem.replace('_', ' ').title()
                report_filename = report_file.name
                report_data_key = f"{phase_key}_reports"
                if report_data_key in phase_to_reports:
                    phase_to_reports[report_data_key][tool_name] = report_filename

    # Pass all report data to the template
    return render_template('dashboard.html',
                           reports_dir=session_id,
                           reconnaissance_reports=reconnaissance_reports,
                           scanning_reports=scanning_reports,
                           exploitation_reports=exploitation_reports,
                           maintenance_reports=maintenance_reports,
                           covering_tracks_reports=covering_tracks_reports)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
