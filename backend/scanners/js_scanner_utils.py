import asyncio
import json
import os
import tempfile
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

async def run_retire_js(js_content: str) -> List[Dict[str, Any]]:
    """
    Runs the retire.js CLI tool on the provided JavaScript content.
    Returns the raw JSON output from retire.js.
    """
    if not js_content.strip():
        return []

    # Create a temporary file to store the JS content
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".js", encoding="utf-8") as temp_js_file:
        temp_js_file.write(js_content)
        temp_js_file_path = temp_js_file.name

    try:
        # Execute retire.js CLI
        command = ["retire", "--path", temp_js_file_path, "--outputformat", "json"]
        logger.debug(f"Running retire.js command: {' '.join(command)}")

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.error(f"retire.js scan failed: {stderr.decode()}")
            return []

        # Parse JSON output
        try:
            retire_output = json.loads(stdout.decode())
            # retire.js output structure: {"data": [...], "warnings": [...]}
            return retire_output.get("data", [])
        except json.JSONDecodeError:
            logger.error(f"Could not decode retire.js JSON output: {stdout.decode()}")
            return []
    except FileNotFoundError:
        logger.error("retire.js command not found. Is Node.js and retire installed and in PATH?")
        return []
    except Exception as e:
        logger.error(f"Error running retire.js: {e}", exc_info=True)
        return []
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_js_file_path):
            os.remove(temp_js_file_path) 

def _create_error_finding(description: str) -> dict:
    return { "type": "error", "severity": "INFO", "title": "JS Scanner Utils Error", "description": description, "location": "Utility", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
