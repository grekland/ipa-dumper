import os 
import sys
import frida
import threading
import shutil
import argparse
import paramiko
from scp import SCPClient
from tqdm import tqdm
import logging
import zipfile
import stat
from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass
import time
import textwrap

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("runtime.log","w", "utf-8"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

@dataclass
class SSHConfig:
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_filename: Optional[str] = None

    def __post_init__(self):
        if not self.password and not self.key_filename:
            raise ValueError("Either password or key_filename must be provided")

class IpaBuilder:
    def __init__(self, output_dir: Optional[str] = None) -> None:
        self.script_dir = Path(__file__).parent
        self.dump_js = self.script_dir / 'res' / 'dump.js'
        self.output_dir = Path(output_dir or Path.home() / 'Downloads' / 'ios_dumps')
        self.payload_dir = self.output_dir / 'Payload'
        self.file_dict: Dict[str, str] = {}
        self.finished = threading.Event()
        self.ssh_client = None
        self.ssh_config = None

    def connect_ssh(self, config: SSHConfig) -> None:
        """Establish SSH connection with retries and exponential backoff"""
        self.ssh_config = config
        self._create_ssh_connection()

    def _create_ssh_connection(self) -> None:
        """Create a new SSH connection"""
        try:
            if self.ssh_client:
                self.ssh_client.close()
            
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname=self.ssh_config.host,
                port=self.ssh_config.port,
                username=self.ssh_config.username,
                password=self.ssh_config.password,
                key_filename=self.ssh_config.key_filename
            )
            logger.info("SSH connection established successfully")
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            raise

    def _ensure_ssh_connection(self) -> None:
        """Ensure SSH connection is active, reconnect if necessary"""
        try:
            if not self.ssh_client or not self.ssh_client.get_transport() or not self.ssh_client.get_transport().is_active():
                logger.info("Reconnecting SSH...")
                self._create_ssh_connection()
        except Exception as e:
            logger.error(f"Error checking SSH connection: {e}")
            self._create_ssh_connection()

    def _handle_dump_payload(self, payload: dict, progress_callback) -> None:
        try:
            self._ensure_ssh_connection()
            with SCPClient(self.ssh_client.get_transport(), progress=progress_callback) as scp:
                try:
                    scp.get(payload['dump'], str(self.payload_dir / ''))
                    index = payload['path'].find('.app/')
                    self.file_dict[Path(payload['dump']).name] = payload['path'][index + 5:]
                except Exception as e:
                    logger.error(f"Failed to transfer file: {e}")
                    raise
        except Exception as e:
            logger.error(f"Failed to handle dump payload: {e}")

    def _handle_app_payload(self, payload: dict, progress_callback) -> None:
        try:
            self._ensure_ssh_connection()
            with SCPClient(self.ssh_client.get_transport(), progress=progress_callback) as scp:
                try:
                    scp.get(payload['app'], str(self.payload_dir / ''), recursive=True)
                    self.file_dict['app'] = Path(payload['app']).name
                except Exception as e:
                    logger.error(f"Failed to transfer app: {e}")
                    raise
        except Exception as e:
            logger.error(f"Failed to handle app payload: {e}")

    def __del__(self):
        """Cleanup SSH connection"""
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass

    def get_usb_iphone(self) -> frida.core.Device:
        """
        Retrieve the USB-connected iPhone. If multiple devices are connected,
        allow the user to select one. Automatically selects the device if only one is found.
        """
        for attempt in range(3):
            try:
                devices = frida.get_device_manager().enumerate_devices()
                usb_devices = [device for device in devices if device.type == 'usb']
                
                if not usb_devices:
                    logger.warning(f"No iPhone connected via USB. Attempt {attempt + 1}/3")
                    time.sleep(1)
                    continue
                
                if len(usb_devices) == 1:
                    logger.info(f"One iPhone detected: {usb_devices[0].name}")
                    return usb_devices[0]
                
                logger.info("Multiple devices detected. Please select one:")
                for idx, device in enumerate(usb_devices, start=1):
                    print(f"{idx}. {device.name} (ID: {device.id})")
                
                while True:
                    try:
                        choice = int(input("Enter the number of the device you want to use: "))
                        if 1 <= choice <= len(usb_devices):
                            selected_device = usb_devices[choice - 1]
                            logger.info(f"Selected device: {selected_device.name}")
                            return selected_device
                        else:
                            print("Invalid choice. Please try again.")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
            except Exception as e:
                logger.error(f"Error while detecting devices: {e}")
        
        logger.error("Failed to detect an iPhone after multiple attempts.")
        raise RuntimeError("No iPhone detected")

    def create_directories(self) -> None:
        """Create necessary directories"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.payload_dir.exists():
            shutil.rmtree(self.payload_dir, onerror=self._force_remove)
        self.payload_dir.mkdir(parents=True)

    def _force_remove(self, func, path, exc_info):
        """Force remove readonly files"""
        os.chmod(path, stat.S_IWRITE)
        func(path)

    def on_message(self, message: Dict[str, any], data: Optional[bytes]) -> None:
        if message.get('type') == 'error':
            logger.error(f"Frida Script Error: {message.get('description')}")
            return

        payload = message.get('payload')
        if not payload:
            return

        if isinstance(payload, dict) and payload.get('type') == 'log':
            log_message = payload.get('payload', '')
            logger.info(f"[JavaScript Log] {log_message}")
            return

        progress_bar = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)

        def update_progress(filename, size, sent):
            progress_bar.desc = Path(filename).name
            progress_bar.total = size
            progress_bar.update(sent - progress_bar.n)

        try:
            if 'dump' in payload:
                self._handle_dump_payload(payload, update_progress)
            elif 'app' in payload:
                self._handle_app_payload(payload, update_progress)
            elif 'done' in payload:
                self.finished.set()
        except Exception as e:
            logger.error(f"Error handling message: {e}")
        finally:
            progress_bar.close()

    def _handle_dump_payload(self, payload: dict, progress_callback) -> None:
        with SCPClient(self.ssh_client.get_transport(), progress=progress_callback) as scp:
            try:
                scp.get(payload['dump'], str(self.payload_dir / ''))
                index = payload['path'].find('.app/')
                self.file_dict[Path(payload['dump']).name] = payload['path'][index + 5:]
            except Exception as e:
                logger.error(f"Failed to handle dump payload: {e}")

    def _handle_app_payload(self, payload: dict, progress_callback) -> None:
        with SCPClient(self.ssh_client.get_transport(), progress=progress_callback) as scp:
            try:
                scp.get(payload['app'], str(self.payload_dir / ''), recursive=True)
                self.file_dict['app'] = Path(payload['app']).name
            except Exception as e:
                logger.error(f"Failed to handle app payload: {e}")

    def generate_ipa(self, display_name: str) -> None:
        """Generate IPA file from dumped contents"""
        try:
            ipa_path = self.output_dir / f"{display_name}.ipa"
            logger.info(f'Generating IPA: {ipa_path}')

            app_name = self.file_dict.get('app')
            if not app_name:
                raise RuntimeError("App name not found in file dictionary.")

            for key, value in self.file_dict.items():
                if key != 'app':
                    target_path = self.payload_dir / app_name / value
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(self.payload_dir / key, target_path)

            app_folder = self.payload_dir / app_name
            if not app_folder.exists() or not app_folder.is_dir():
                raise RuntimeError(f"The .app folder '{app_folder}' does not exist or is not a directory.")

            with zipfile.ZipFile(ipa_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in app_folder.rglob('*'):
                    if file_path.is_file():
                        zipf.write(file_path, file_path.relative_to(self.payload_dir.parent))

            logger.info(f'IPA generated successfully: {ipa_path}')
        except Exception as e:
            logger.error(f"Failed to generate IPA: {e}")
        finally:
            for item in self.payload_dir.iterdir():
                if item.is_dir() and item.name.endswith('.app'):
                    continue
                try:
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item, onerror=self._force_remove)
                except Exception as e:
                    logger.error(f"Failed to clean up {item}: {e}")


    def dump_app(self, app_identifier: str) -> bool:
        """Main method to dump the application"""
        session = None
        success = False
        start_time = time.time()
        
        try:
            logger.info("🔍 Searching for USB-connected iPhone...")
            device = self.get_usb_iphone()
            display_name = None

            logger.info("📱 Scanning for target application...")
            for app in device.enumerate_applications():
                if app_identifier in (app.identifier, app.name):
                    display_name = app.name
                    logger.info(f"✅ Found application: {display_name} ({app.identifier})")
                    
                    if not app.pid:
                        logger.info("📲 Launching application...")
                        pid = device.spawn([app.identifier])
                        session = device.attach(pid)
                        device.resume(pid)
                    else:
                        logger.info("🔗 Attaching to running application...")
                        session = device.attach(app.pid)
                    break

            if not session:
                logger.error(f"❌ Application '{app_identifier}' not found")
                return False

            logger.info(f"🚀 Starting dump process for: {display_name}")
            self.create_directories()

            with open(self.dump_js, 'r', encoding='utf-8') as f:
                script = session.create_script(f.read())
                script.on('message', self.on_message)
                script.load()
                
                logger.info("⏳ Dumping application contents...")
                script.post('dump')

                logger.info("⏳ Waiting for the dump to complete...")
                if not self.finished.wait(timeout=7200):
                    raise TimeoutError("Dump operation timed out")
                logger.info("✅ Dump operation completed successfully")

            logger.info("📦 Creating IPA file...")
            self.generate_ipa(display_name)
            
            elapsed_time = time.time() - start_time
            logger.info(f"✨ Dump completed successfully in {elapsed_time:.1f} seconds")
            logger.info(f"📍 Output location: {self.output_dir}")
            success = True
        finally:
            if session:
                try:
                    session.detach()
                    logger.info("🔌 Cleaned up session")
                except:
                    pass
            
            if success:
                print("\n" + "="*50)
                print("📱 iOS App Dump Summary")
                print("="*50)
                print(f"🎯 Target App: {display_name}")
                print(f"⏱️ Total Time: {elapsed_time:.1f} seconds")
                print(f"📂 Output Directory: {self.output_dir}")
                print(f"✅ Status: Success")
                print("="*50)
            else:
                print("\n" + "="*50)
                print("📱 iOS App Dump Summary")
                print("="*50)
                print(f"🎯 Target App: {app_identifier}")
                print("❌ Status: Failed")
                print(f"📝 Check logs for details")
                print("="*50)
            
            return success

def create_parser():
    """Create and return a well-formatted argument parser"""
    parser = argparse.ArgumentParser(
        description='iOS App Dumper - Extract decrypted IPA files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
            %(prog)s com.example.app
            %(prog)s "App Name" --host 192.168.1.100 --password mypass
            %(prog)s com.example.app --key-file ~/.ssh/id_rsa --output ~/Desktop/dumps
            
            Note: Either --password or --key-file must be provided for SSH authentication.
        ''')
    )

    parser.add_argument(
        'target',
        help='Bundle identifier or display name of the target app'
    )

    ssh_group = parser.add_argument_group('SSH Connection Options')
    ssh_group.add_argument(
        '--host',
        default='127.0.0.1',
        help='SSH hostname (default: 127.0.0.1)'
    )
    ssh_group.add_argument(
        '--port',
        type=int,
        default=22,
        help='SSH port (default: 22)'
    )
    ssh_group.add_argument(
        '--user',
        default='root',
        help='SSH username (default: root)'
    )
    ssh_group.add_argument(
        '--password',
        help='SSH password for authentication'
    )
    ssh_group.add_argument(
        '--key-file',
        help='Path to SSH private key file'
    )

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output',
        help='Custom output directory for dumped IPA'
    )

    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.password and not args.key_file:
        parser.error("Either --password or --key-file must be provided")

    ssh_config = SSHConfig(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        key_filename=args.key_file
    )

    try:
        print("\n🚀 Starting iOS App Dumper...")
        dumper = IpaBuilder(args.output)
        logger.info("🔑 Establishing SSH connection...")
        dumper.connect_ssh(ssh_config)
        
        success = dumper.dump_app(args.target)
        
        if not success:
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"❌ Fatal error during dump process: {e}")
        print("\n❌ Dump process failed. Check logs for details.")
        sys.exit(1)

if __name__ == '__main__':
    main()