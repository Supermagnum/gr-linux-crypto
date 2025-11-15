
import pmt
from gnuradio import gr
from PyQt5.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

try:
    from libnitrokey import NitrokeyManager

    NITROKEY_AVAILABLE = True
except ImportError:
    NITROKEY_AVAILABLE = False
    print(
        "Warning: libnitrokey Python bindings not available. PIN authentication will not work."
    )


class PinEntryDialog(QDialog):
    def __init__(self, parent=None, prompt="Enter Nitrokey PIN"):
        super().__init__(parent)
        self.setWindowTitle("Nitrokey PIN Entry")
        self.setModal(True)
        self.pin = None
        self.cancelled = False
        layout = QVBoxLayout()
        label = QLabel(prompt)
        layout.addWidget(label)
        self.pin_input = QLineEdit(self)
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.returnPressed.connect(self.submit_pin)
        layout.addWidget(self.pin_input)
        button_layout = QVBoxLayout()
        submit_button = QPushButton("Submit")
        submit_button.clicked.connect(self.submit_pin)
        button_layout.addWidget(submit_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.cancel)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        self.setLayout(layout)
        self.pin_input.setFocus()

    def submit_pin(self):
        self.pin = self.pin_input.text()
        if self.pin:
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "PIN cannot be empty")

    def cancel(self):
        self.cancelled = True
        self.reject()

    def get_pin(self):
        return self.pin if not self.cancelled else None


class blk(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(
            self, name="Nitrokey PIN Authenticator", in_sig=None, out_sig=None
        )
        self.message_port_register_out(pmt.intern("status"))
        self.authenticated = False
        self.nitrokey_manager = None
        self.last_button_state = False
        self.check_counter = 0
        self.button_var = None
        if NITROKEY_AVAILABLE:
            try:
                self.nitrokey_manager = NitrokeyManager.instance()
                if self.nitrokey_manager and self.nitrokey_manager.is_connected():
                    print("Nitrokey PIN Authenticator: Device connected")
                else:
                    print("Nitrokey PIN Authenticator: No device connected")
            except Exception as e:
                print(f"Nitrokey PIN Authenticator: Error connecting to device: {e}")

    def work(self, input_items, output_items):
        self.check_counter += 1
        if self.check_counter >= 100:
            self.check_counter = 0
            try:
                if self.button_var is None:
                    import __main__

                    if hasattr(__main__, "authenticate_button"):
                        self.button_var = getattr(__main__, "authenticate_button")
                if self.button_var:
                    button_value = self.button_var.value()
                    if (
                        button_value
                        and not self.last_button_state
                        and not self.authenticated
                    ):
                        self.authenticate_with_pin()
                    elif not button_value:
                        self.authenticated = False
                    self.last_button_state = button_value
            except Exception:
                pass
        return 0

    def authenticate_with_pin(self):
        if not NITROKEY_AVAILABLE or not self.nitrokey_manager:
            status_msg = pmt.intern("Nitrokey library not available")
            self.message_port_pub(pmt.intern("status"), status_msg)
            print("Nitrokey PIN Authenticator: Library not available")
            return
        try:
            if not self.nitrokey_manager.is_connected():
                devices = self.nitrokey_manager.list_devices()
                if not devices:
                    status_msg = pmt.intern("No Nitrokey device found")
                    self.message_port_pub(pmt.intern("status"), status_msg)
                    print("Nitrokey PIN Authenticator: No device found")
                    return
                if not self.nitrokey_manager.connect():
                    status_msg = pmt.intern("Failed to connect to Nitrokey")
                    self.message_port_pub(pmt.intern("status"), status_msg)
                    print("Nitrokey PIN Authenticator: Connection failed")
                    return
            from PyQt5.QtWidgets import QApplication

            app = QApplication.instance()
            parent = app.activeWindow() if app else None
            dialog = PinEntryDialog(parent, "Enter Nitrokey PIN for authentication")
            if dialog.exec_() == QDialog.Accepted:
                pin = dialog.get_pin()
                if pin:
                    try:
                        # Check slot status (not stored, just checked)
                        self.nitrokey_manager.get_password_safe_slot_status()
                        self.authenticated = True
                        status_msg = pmt.intern("Authentication successful")
                        self.message_port_pub(pmt.intern("status"), status_msg)
                        print("Nitrokey PIN Authenticator: Authentication successful")
                        pin = None
                    except Exception as e:
                        status_msg = pmt.intern(f"Authentication failed: {str(e)}")
                        self.message_port_pub(pmt.intern("status"), status_msg)
                        print(f"Nitrokey PIN Authenticator: Authentication failed: {e}")
                        self.authenticated = False
                else:
                    status_msg = pmt.intern("PIN entry cancelled")
                    self.message_port_pub(pmt.intern("status"), status_msg)
                    print("Nitrokey PIN Authenticator: PIN entry cancelled")
            else:
                status_msg = pmt.intern("PIN dialog cancelled")
                self.message_port_pub(pmt.intern("status"), status_msg)
                print("Nitrokey PIN Authenticator: Dialog cancelled")
        except Exception as e:
            status_msg = pmt.intern(f"Error: {str(e)}")
            self.message_port_pub(pmt.intern("status"), status_msg)
            print(f"Nitrokey PIN Authenticator: Error: {e}")
            import traceback

            traceback.print_exc()
