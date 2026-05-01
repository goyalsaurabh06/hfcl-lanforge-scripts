import copy
import csv
import importlib
import json
import logging
import os
import sys
import time
import string
import random
import threading
from itertools import islice
import paramiko
from datetime import datetime

import allure
import pytest
import csv
from scp import SCPClient
from tabulate import tabulate
import re
import pandas as pd

import subprocess
from typing import Dict, List, Any
import requests

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))
lfcli_base = importlib.import_module("py-json.LANforge.lfcli_base")
LFCliBase = lfcli_base.LFCliBase
realm = importlib.import_module("py-json.realm")
cv_test_manager = importlib.import_module("py-json.cv_test_manager")
cv_test = cv_test_manager.cv_test
lf_cv_base = importlib.import_module("py-json.lf_cv_base")
ChamberViewBase = lf_cv_base.ChamberViewBase
create_chamberview_dut = importlib.import_module("py-scripts.create_chamberview_dut")
DUT = create_chamberview_dut.DUT
create_chamberview = importlib.import_module("py-scripts.create_chamberview")
CreateChamberview = create_chamberview.CreateChamberview
sta_connect2 = importlib.import_module("py-scripts.sta_connect2")
StaConnect2 = sta_connect2.StaConnect2
lf_library = importlib.import_module("lf_libs")
lf_libs = lf_library.lf_libs
profile_utility = importlib.import_module("py-json.profile_utility")
ProfileUtility = profile_utility.ProfileUtility
Report = lf_library.Report
SCP_File = lf_library.SCP_File
sniffradio = importlib.import_module("py-scripts.lf_sniff_radio")
SniffRadio = sniffradio.SniffRadio
stascan = importlib.import_module("py-scripts.sta_scan_test")
StaScan = stascan.StaScan
cv_test_reports = importlib.import_module("py-json.cv_test_reports")
lf_report = cv_test_reports.lanforge_reports
createstation = importlib.import_module("py-scripts.create_station")
CreateStation = createstation.CreateStation
csvtoinflux = importlib.import_module("py-scripts.csv_to_influx")
CSVtoInflux = csvtoinflux.CSVtoInflux
lf_pcap = importlib.import_module("py-scripts.lf_pcap")
LfPcap = lf_pcap.LfPcap
modify_station = importlib.import_module("py-scripts.modify_station")
ModifyStation = modify_station.ModifyStation
station_profile = importlib.import_module("py-json.station_profile")
StationProfile = station_profile.StationProfile
lf_bandsteer = importlib.import_module("py-scripts.lf_bandsteer")
BandSteer = lf_bandsteer.BandSteer
try:
    # Try pip module (if future added)
    lf_tx_power = importlib.import_module("lanforge_scripts.lf_tx_power")

except ModuleNotFoundError:
    # Fallback → load from repo path
    BASE_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../hfcl-lanforge-scripts")
    )

    tx_power_path = os.path.join(BASE_DIR, "lf_tx_power.py")

    if not os.path.exists(tx_power_path):
        raise FileNotFoundError(f"lf_tx_power.py not found at {tx_power_path}")

    spec = importlib.util.spec_from_file_location("lf_tx_power", tx_power_path)
    lf_tx_power = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lf_tx_power)


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG, run_lf=False, influx_params=None,
                 local_report_path="../reports/"):
        super().__init__(lf_data, dut_data, run_lf, log_level)
        self.local_report_path = local_report_path
        self.influx_params = influx_params

    def run_tx_power_test(self, tx_config, get_target_object, get_testbed_details):
        """
        Execute TX Power Sweep Automation Using LANforge Script.

        This method acts as the integration layer between pytest test cases
        and the standalone TX power automation script (`lf_tx_power.py`).

        The TX power script performs:
            • Optional LANforge station creation
            • TX power sweep on DUT radio
            • RSSI measurement via LANforge client
            • TX power calculation using pathloss model
            • Report generation (HTML / CSV / XLSX)

        DUT automation inside the TX power script is disabled by default
        because DUT configuration (country, channel, bandwidth) is already
        handled by pytest fixtures.

        Therefore this method forces:

            skip_dut = True

        so the TX power script only performs measurement logic.

        Parameters
        ----------
        tx_config : dict
            Dictionary containing TX power execution parameters generated
            from pytest test cases.

            Example:

            {
                "band": "2g",
                "channel": 1,
                "bandwidth": 40,
                "ssid": "HFCL_2G",
                "ssidpw": "12345678",
                "security": "wpa2",
                "station": "sta_1",
                "radio": "wiphy0",
                "txpower": [11,12,13,14],
                "pathloss": 38,
                "antenna_gain": 0,
                "duration": 25,
                "create_station": True,
                "outfile": "tx_2g_1_40"
            }

        get_target_object : fixture
            Framework fixture providing DUT automation interface.
            Used for executing generic commands (ex: iw dev).

        Returns
        -------
        dict
            Paths of generated report files.

            {
                "html_report": ".../report/file.html",
                "csv_report": ".../report/file.csv",
                "xlsx_report": ".../report/file.xlsx"
            }

        Notes
        -----
        • Test cases do NOT control DUT automation.
        • TX power sweep is controlled by the TX script.
        • Test cases attach reports to Allure and perform validation.
        """

        # set attenuator to 0
        atten_sr = self.attenuator_serial()
        logging.info("atten ser:- " + str(atten_sr))
        if atten_sr:
            self.attenuator_modify("all", 'all', 0)
        self.pre_cleanup()

        # ---------------------------------------------------
        # Obtain DUT objects from framework
        # ---------------------------------------------------
        dut_object = get_target_object.dut_library_object
        target_object = get_target_object

        # ---------------------------------------------------
        # Always skip DUT automation inside TX script
        # ---------------------------------------------------
        tx_config["skip_dut"] = True
        tx_config["local_lf_report_dir"] = self.local_report_path
        port_data = self.wan_ports
        port = list(port_data.keys())
        upstream_port = port[0]
        tx_config["upstream_port"] = str(upstream_port.split(".")[2])
        tx_config["lfmgr"] = self.manager_ip
        tx_config["lfport"] = self.manager_http_port
        tx_config["series"] = "HFCL"
        tx_config["wifi_mode"] = "auto"
        tx_config["ieee80211w"] = str(1)
        tx_config.setdefault("scheme", "ssh")  # required by parser
        tx_config.setdefault("dest", self.manager_ip)  # controller IP
        tx_config.setdefault("port", "22")
        tx_config.setdefault("user", "root")
        tx_config.setdefault("passwd", "root")
        tx_config.setdefault("prompt", "#")

        tx_config.setdefault("log_level", "info")  # ⭐ your current error

        # WLAN related (script expects these names)
        tx_config.setdefault("wlan", "NA")
        tx_config.setdefault("wlan_id", "NA")
        # tx_config.setdefault("wlan_ssid", tx_config.get("ssid"))

        # Optional but often used
        tx_config.setdefault("create_wlan", False)
        tx_config.setdefault("no_cleanup_station", False)
        tx_config.setdefault("no_cleanup", False)
        tx_config.setdefault("log_level", "INFO")
        tx_config.setdefault("lf_logger_config_json", None)
        tx_config.setdefault("debug", False)

        tx_config.setdefault("test_rig", "HFCL")
        tx_config.setdefault("test_tag", None)
        tx_config.setdefault("dut_hw_version", "")
        tx_config.setdefault("dut_sw_version", "")
        tx_config.setdefault("dut_model_num", "")
        tx_config.setdefault("dut_serial_num", "")
        tx_config.setdefault("test_priority", "")
        tx_config.setdefault("test_id", "TX power")
        tx_config.setdefault("lfresource2", None)
        tx_config.setdefault("pf_ignore_offset", "0")
        tx_config.setdefault("adjust_nf", False)
        tx_config.setdefault("beacon_dbm_diff", "7")
        tx_config.setdefault("vht160", False)
        tx_config.setdefault("wave2", False)
        tx_config.setdefault("nss_4x4_override", False)
        tx_config.setdefault("nss_4x4_ap_adjust", False)
        tx_config.setdefault("set_nss", False)
        tx_config.setdefault("create_wlan", False)
        tx_config.setdefault("html_report", True)
        tx_config.setdefault("exit_on_fail", False)
        tx_config.setdefault("exit_on_error", False)
        tx_config.setdefault("wait_time", "180")
        tx_config.setdefault("wait_forever", False)
        tx_config.setdefault("show_lf_portmod", False)
        tx_config.setdefault("testbed_id", None)
        tx_config.setdefault("testbed_location", "default location")
        tx_config.setdefault("ap_info", [])
        tx_config.setdefault("module", None)
        tx_config.setdefault("module_scrapli", False)
        tx_config.setdefault("timeout", "3")
        tx_config.setdefault("tag_policy", "NA")
        tx_config.setdefault("policy_profile", "NA")
        tx_config.setdefault("ap_band_slot_24g", "NA")
        tx_config.setdefault("ap_band_slot_5g", "NA")
        tx_config.setdefault("ap_band_slot_6g", "NA")
        tx_config.setdefault("ap_dual_band_slot_5g", "NA")
        tx_config.setdefault("ap_dual_band_slot_6g", "NA")
        tx_config.setdefault("tx_pw_cmp_to_prev", False)
        tx_config.setdefault("keep_state", False)
        tx_config.setdefault("enable_all_bands", False)
        tx_config.setdefault("tx_power_adjust_6E", False)
        tx_config.setdefault("mtk7921k", False)
        tx_config.setdefault("mtk7921k_beacon", False)

        # ---------------------------------------------------
        # Execute TX power script
        # ---------------------------------------------------
        logging.info("Starting TX Power Script...")
        logging.getLogger().setLevel(logging.INFO)
        result = lf_tx_power.main(tx_config, target_object, dut_object)
        results_dir_name = result["results_dir_name"]
        logging.info(f"TX Power results directory: {results_dir_name}")
        report_dir = result.get("report_dir")
        client_data = result.get("client_info", [])
        logging.info("client data:- " + str(client_data))
        failures_tx = result.get("tx_power_failures", [])
        logging.info("failures_tx:- " + str(failures_tx))

        # if client_data:
        #     allure.attach(
        #         json.dumps(client_data, indent=4),
        #         name="Client Info Per TX Sweep",
        #         attachment_type=allure.attachment_type.JSON
        #     )

        # ⭐ convert to absolute path (critical fix)
        report_dir = os.path.abspath(report_dir) if report_dir else None
        results_dir_name = os.path.basename(report_dir)

        logging.info("report_dir: " + str(report_dir))
        logging.info(f"resolved results directory: {results_dir_name}")

        # ------------------------------------------------
        # Verify report directory exists
        # ------------------------------------------------
        if not os.path.isdir(report_dir):
            logging.error(f"Report directory not found: {report_dir}")
            return False

        try:

            self.attach_report_graphs(results_dir_name, "TX Power Report PDF")

            kpi_status = self.attach_report_kpi(results_dir_name)

            if not kpi_status:
                logging.error("KPI CSV not found")
                return False

        except Exception as e:
            logging.error(f"Report attachment failed: {e}")
            return False

        logging.info("TX Power report attached successfully")

        # ------------------------------------------------
        # KPI PASS/FAIL validation (FINAL LOGIC)
        # ------------------------------------------------
        try:
            kpi_file = os.path.join(report_dir, "kpi.csv")

            if not os.path.exists(kpi_file):
                logging.error(f"KPI file not found: {kpi_file}")
                return False

            # auto detect separator (tab/comma safe)
            df = pd.read_csv(kpi_file, sep=None, engine='python')

            if df.empty:
                logging.error("KPI file is empty")
                return False

            # normalize column names
            df.columns = [col.strip().lower() for col in df.columns]

            if "pass/fail" not in df.columns:
                logging.error(f"'pass/fail' column not found in KPI. Available columns: {df.columns}")
                return False

            status_list = df["pass/fail"].astype(str).str.strip().str.upper().tolist()

            fail_count = status_list.count("FAIL")
            logging.info("status_list:- " + str(status_list))
            logging.info("fail_count:- " + str(fail_count))

            if fail_count > 0:
                logging.error(f"TX Power FAILED → {fail_count} failures out of {len(status_list)}")

                # optional: print few failed rows for debug
                failed_rows = df[df["pass/fail"].str.upper() == "FAIL"]
                logging.error(f"Failed rows preview:\n{failed_rows.head(5)}")

                return False

            logging.info(f"TX Power PASSED → all {len(status_list)} entries passed")

        except Exception as e:
            logging.error(f"KPI validation failed: {e}")
            return False
        if failures_tx:
            pytest.fail("\n".join(failures_tx))

        return True

    def validate_protocol_formal_report(
            self,
            analysis,
            ap_config=None
    ):
        """
        Formal validation for 11k / 11v / 11r using:
        - AP Config (UCI)
        - Beacon Advertisement
        - Runtime Frame Behavior

        Returns:
            {
                "final_status": bool,
                "report": str
            }
        """

        protocol_details = analysis.get("protocol_details", {})
        frame_counts = analysis.get("frame_counts", {})

        # -----------------------------
        # STEP 2: AP CONFIG ACTUAL
        # -----------------------------
        actual_config = {
            "11k": ap_config.get("rrm") == "1" if ap_config else False,
            "11v": ap_config.get("bss_transition") == "1" if ap_config else False,
            "11r": ap_config.get("ieee80211r") == "1" if ap_config else False,
        }

        def build_11k():
            report = []
            result = "PASS"

            report.append("802.11k (Radio Resource Management) – Expected Behavior:\n")
            report.append("1. AP Configuration:")
            report.append("   - wireless.<vap>.rrm = 1\n")
            report.append("   - wireless.<vap>.rrm_neighbor_report = 1\n")
            report.append("   - wireless.<vap>.rrm_beacon_report = 1\n")

            report.append("2. Beacon Advertisement:")
            report.append("   - RM Enabled Capabilities IE (Tag 70)\n")

            report.append("3. Runtime Behavior:")
            report.append("   - Neighbor Report / RRM action frames must be observed")
            report.append("   - Filter: wlan.fixed.category_code == 5\n")

            report.append("\n802.11k – Observed Behavior:\n")

            # Config
            if actual_config["11k"]:
                report.append(" RRM enabled on AP")
            else:
                report.append(" RRM NOT enabled on AP")
                result = "FAIL"

            # Beacon
            beacon_present = any("RM Enabled" in d for d in protocol_details.get("11k", []))
            if beacon_present:
                report.append(" RM Enabled Capabilities IE present in beacon")
            else:
                report.append(" RM Capabilities IE NOT present in beacon")
                result = "FAIL"

            # Runtime
            if frame_counts.get("11k", 0) > 0:
                report.append(f" RRM action frames observed ({frame_counts['11k']} frames)")
            else:
                report.append(" No RRM action frames observed")
                result = "FAIL"

            # Verdict
            report.append(f"\nResult: {result}")

            if result == "FAIL":
                report.append("Reason: 11k expected behavior not fully satisfied")
                report.append("\nDebug Steps:")
                report.append("1. Verify client supports 802.11k")
                report.append("2. Check neighbor list configuration on AP")
                report.append("3. Ensure roaming trigger conditions are met")

            return "\n".join(report), result

        def build_11v():
            report = []
            result = "PASS"

            report.append("802.11v (BSS Transition Management) – Expected Behavior:\n")
            report.append("1. AP Configuration:")
            report.append("   - wireless.<vap>.bss_transition = 1\n")

            report.append("2. Beacon Advertisement:")
            report.append("   - Extended Capabilities IE (Tag 127)")
            report.append("   - BSS Transition bit set (Extended Capabilities Octet 3)\n")

            report.append("3. Runtime Behavior:")
            report.append("   - BTM Query / Request / Response frames must be observed")
            report.append("   - Filter: wlan.fixed.category_code == 10\n")

            report.append("\n802.11v – Observed Behavior:\n")

            # Config
            if actual_config["11v"]:
                report.append(" BSS Transition enabled on AP")
            else:
                report.append(" BSS Transition NOT enabled on AP")
                result = "FAIL"

            # Beacon
            beacon_present = any("Extended Capabilities" in d for d in protocol_details.get("11v", []))
            if beacon_present:
                report.append(" Extended Capabilities IE present in beacon")
            else:
                report.append(" Extended Capabilities IE NOT present in beacon")
                result = "FAIL"

            # Runtime
            if frame_counts.get("11v", 0) > 0:
                report.append(f" BTM frames observed ({frame_counts['11v']} frames)")
            else:
                report.append(" No BTM frames observed")
                result = "FAIL"

            # Verdict
            report.append(f"\nResult: {result}")

            if result == "FAIL":
                report.append("Reason: 11v expected behavior not fully satisfied")
                report.append("\nDebug Steps:")
                report.append("1. Verify client supports 802.11v")
                report.append("2. Check RSSI threshold for steering trigger")
                report.append("3. Inspect hostapd logs for BTM request generation")
                report.append("4. Ensure band steering policy is active")

            return "\n".join(report), result

        def build_11r():
            report = []
            result = "PASS"

            report.append("802.11r (Fast BSS Transition) – Expected Behavior:\n")
            report.append("1. AP Configuration:")
            report.append("   - ieee80211r = 1")
            report.append("   - mobility_domain must be configured\n")

            report.append("2. Beacon Advertisement:")
            report.append("   - Mobility Domain IE (Tag 54)\n")

            report.append("3. Runtime Behavior:")
            report.append("   - FT Authentication must occur")
            report.append("   - Filter: wlan.fixed.auth_alg == 2\n")

            report.append("\n802.11r – Observed Behavior:\n")

            # Config
            if actual_config["11r"]:
                report.append(" 802.11r enabled on AP")
            else:
                report.append(" 802.11r NOT enabled on AP")
                result = "FAIL"

            # Beacon
            beacon_present = any("Mobility Domain" in d for d in protocol_details.get("11r", []))
            if beacon_present:
                report.append(" Mobility Domain IE present in beacon")
            else:
                report.append(" Mobility Domain IE NOT present in beacon")
                result = "FAIL"

            # Runtime
            if frame_counts.get("11r", 0) > 0:
                report.append(f" FT Authentication observed ({frame_counts['11r']} frames)")
            else:
                report.append(" No FT Authentication observed")
                result = "FAIL"

            # Verdict
            report.append(f"\nResult: {result}")

            if result == "FAIL":
                report.append("Reason: 11r expected behavior not fully satisfied")
                report.append("\nDebug Steps:")
                report.append("1. Verify client supports 802.11r")
                report.append("2. Check FT over DS / FT over Air configuration")
                report.append("3. Validate PMK caching and key hierarchy")
                report.append("4. Ensure same Mobility Domain across APs")

            return "\n".join(report), result

        r11k, res_k = build_11k()
        r11v, res_v = build_11v()
        r11r, res_r = build_11r()

        reports = [
            r11k,
            "\n" + "=" * 80,
            r11v,
            "\n" + "=" * 80,
            r11r
        ]

        final_status = not ("FAIL" in [res_k, res_v, res_r])

        return {
            "final_status": final_status,
            "report": "\n\n".join(reports)
        }

    def analyze_sniffer_pcap(
            self,
            pcap_path: str,
            client_mac: str = None,
            bssid: str = None,
            mode: str = "band_steering",
            check_protocol: str = None,  # New: "11k", "11v", "11r", or None for all
            window: float = 15.0,
            bssid_list: list = None,
            show_events: bool = False,
            frame_view: bool = True,
    ):
        """
        Analyze PCAP for roaming/steering behavior

        Args:
            pcap_path: Path to PCAP file
            client_mac: Optional client MAC address. If provided, filters by client
            bssid: Optional BSSID (AP MAC). Used when no client MAC is provided
            mode: Analysis mode (band_steering, 11r_roaming, 11kv_roaming, 11kvr_roaming, 11kr_roaming, multi_roam)
            check_protocol: Specific protocol to check ("11k", "11v", "11r", or None for all)
            window: Time window for roam detection in seconds
            show_events: Whether to show supporting events
            frame_view: Whether to show detailed frame view
        """
        PASS_RESULTS = {
            "PASS_BAND_STEERING",
            "PASS_11R_ROAM",
            "PASS_11KV_ROAMING",
            "PASS_11KVR_ROAMING",
            "PASS_11KR",
            "PASS_11R_FT_ONLY",
            "PASS_BAND_STEERING_CLIENT_DRIVEN",
            "PASS_ROAM_DETECTED",
            "PASS_11K_CAPABILITY",
            "PASS_11K_ACTION_FRAME",
            "PASS_11VR_BEACON",
        }

        def norm(x):
            return (x or "").strip().lower()

        def parse_int(val):
            try:
                return int(val, 0)
            except:
                return None

        def band_from_channel(ch):
            try:
                c = int(ch)
            except:
                return "unknown"
            if 1 <= c <= 14:
                return "2.4G"
            if 36 <= c <= 177:
                return "5G"
            if 178 <= c <= 233:
                return "6G"
            return "unknown"

        def clean_quoted_value(val):
            """Remove quotes from quoted values"""
            if not val:
                return ""
            val = val.strip()
            if val.startswith('"') and val.endswith('"'):
                return val[1:-1]
            return val

        def parse_tag_numbers(tag_str):
            """Parse comma-separated tag numbers into a set"""
            if not tag_str:
                return set()
            tag_str = clean_quoted_value(tag_str)
            return {t.strip() for t in tag_str.split(",") if t.strip()}

        def decode_ssid(hex_ssid):
            """Decode hex SSID to readable string"""
            if not hex_ssid:
                return ""
            hex_ssid = clean_quoted_value(hex_ssid)
            if not hex_ssid or hex_ssid.startswith('"'):
                return hex_ssid
            try:
                if len(hex_ssid) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in hex_ssid):
                    return bytes.fromhex(hex_ssid).decode('utf-8', errors='ignore')
            except:
                pass
            return hex_ssid

        def pretty_filter(flt):
            return flt.replace("&&", "\n  and ").replace("||", "\n  or ")

        def build_filter_summary():
            filters = []
            if client_mac:
                filters.append(f"Client MAC = {norm(client_mac)}")

            if bssid:
                filters.append(f"BSSID = {norm(bssid)}")

            if check_protocol:
                filters.append(f"Protocol Filter = {check_protocol.upper()}")

            filters.append("Frame Types = Assoc/Reassoc/Auth/Action/Beacon/EAPOL")

            filters.append(f"Roam Window = {window}s")

            # Derived filters
            filters.append("Roam Criteria = BSSID transition within time window")

            filters.append("Band Filter = Derived from channel (2.4G/5G/6G)")

            return filters

        def build_static_logic_reference():
            return """
ANALYSIS LOGIC REFERENCE:

BAND STEERING:
  - Detect BTM Request (11v)
  - Check client moves to different BSSID
  - Validate band transition (2.4G ↔ 5G/6G)

802.11k:
  - RRM frames (category_code = 5)
  - Neighbor Report IE (tag 52)
  - RM Capabilities in beacon frame

802.11v:
  - BTM Request/Response (category_code = 10)
  - Extended Capabilities IE (tag 127)

802.11r:
  - FT Authentication (auth_alg = 2)
  - Mobility Domain IE (tag 54)
  - RSN FT AKM (tag 48)

ROAM DETECTION:
  - BSSID transition within time window
  - Assoc Response OR FT Authentication
            """

        # -------------------------------
        # TSHARK - Enhanced for 11k/11v/11r (supports client MAC or BSSID)
        # -------------------------------
        def run_tshark():
            # Build filter based on available identifiers
            filter_parts = []

            if client_mac:
                cmac = norm(client_mac)
                filter_parts.append(f'wlan.addr == {cmac}')

            if bssid_list:
                bssid_filter = " || ".join([f"wlan.bssid == {b}" for b in bssid_list])
                filter_parts.append(f"({bssid_filter})")

            # If no specific filter, analyze all relevant frames
            if not filter_parts:
                filter_parts.append('1')

            # Build protocol-specific filter if check_protocol is specified
            protocol_filter_parts = []
            if check_protocol == "11k":
                protocol_filter_parts.append(
                    '(wlan.fixed.category_code == 5 && (wlan.fixed.action_code == 0 || wlan.fixed.action_code == 1))')  # RRM frames
                protocol_filter_parts.append('wlan.tag.number == 52')  # Neighbor Report IE
            elif check_protocol == "11v":
                protocol_filter_parts.append(
                    '(wlan.fixed.category_code == 10 && (wlan.fixed.action_code == 6 || wlan.fixed.action_code == 7 || wlan.fixed.action_code == 8))')
                protocol_filter_parts.append('wlan.tag.number == 127')  # Extended Capabilities
            elif check_protocol == "11r":
                protocol_filter_parts.append('wlan.fixed.auth_alg == 2')  # FT Authentication
                protocol_filter_parts.append('wlan.tag.number == 54')  # Mobility Domain IE
                protocol_filter_parts.append('wlan.tag.number == 48')  # RSN IE with FT

            # Combine filters
            if protocol_filter_parts:
                frame_filter = (
                    f'({" || ".join(filter_parts)}) && ('
                    f'({" || ".join(protocol_filter_parts)})'
                    f')'
                )
            else:
                frame_filter = (
                    f'({" || ".join(filter_parts)}) && ('
                    f'wlan.fc.type == 2 || '  # DATA FRAMES
                    f'wlan.fc.type_subtype == 0 || '  # Assoc Req
                    f'wlan.fc.type_subtype == 1 || '  # Assoc Resp
                    f'wlan.fc.type_subtype == 2 || '  # Re-assoc Req
                    f'wlan.fc.type_subtype == 3 || '  # Re-assoc Resp
                    f'wlan.fc.type_subtype == 4 || '  # Probe Req
                    f'wlan.fc.type_subtype == 5 || '  # Probe Resp
                    f'wlan.fc.type_subtype == 8 || '  # Beacon
                    f'wlan.fc.type_subtype == 10 || '  # Disassoc
                    f'wlan.fc.type_subtype == 11 || '  # Auth
                    f'wlan.fc.type_subtype == 12 || '  # Deauth
                    f'wlan.fc.type_subtype == 13 || '  # Action
                    f'wlan.fixed.category_code == 5 || '  # RRM (11k)
                    f'wlan.fixed.category_code == 10 || '  # BTM (11v)
                    f'eapol)'  # EAPOL for 4-way handshake
                )

            cmd = [
                "tshark", "-r", pcap_path, "-Y", frame_filter,
                "-T", "fields",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "header=y",
                "-e", "frame.number",
                "-e", "frame.time_epoch",
                "-e", "wlan.ta",
                "-e", "wlan.ra",
                "-e", "wlan.sa",
                "-e", "wlan.da",
                "-e", "wlan.bssid",
                "-e", "wlan.ssid",
                "-e", "wlan.fc.type",
                "-e", "wlan.fc.type_subtype",
                "-e", "wlan.fixed.auth.alg",
                "-e", "wlan.fixed.category_code",
                "-e", "wlan.fixed.action_code",
                "-e", "wlan_radio.channel",
                "-e", "_ws.col.Info",
                "-e", "wlan.tag.number",
                "-e", "wlan.mobility_domain.mdid",
            ]

            out = subprocess.run(cmd, capture_output=True, text=True)
            if out.returncode != 0 and out.stderr:
                print(f"tshark warning: {out.stderr}", file=sys.stderr)

            frames = []
            lines = out.stdout.strip().split('\n')
            if not lines or len(lines) < 2:
                return [], frame_filter

            for line in lines[1:]:
                values = line.split('|')
                if len(values) < 17:
                    continue

                try:
                    ts_str = clean_quoted_value(values[1] if len(values) > 1 else "0")
                    ts_val = float(ts_str) if ts_str else 0.0
                except ValueError:
                    ts_val = 0.0

                frames.append({
                    "no": clean_quoted_value(values[0] if len(values) > 0 else ""),
                    "ts": ts_val,
                    "ta": norm(clean_quoted_value(values[2] if len(values) > 2 else "")),
                    "ra": norm(clean_quoted_value(values[3] if len(values) > 3 else "")),
                    "sa": norm(clean_quoted_value(values[4] if len(values) > 4 else "")),
                    "da": norm(clean_quoted_value(values[5] if len(values) > 5 else "")),
                    "bssid": norm(clean_quoted_value(values[6] if len(values) > 6 else "")),
                    "ssid": decode_ssid(values[7] if len(values) > 7 else ""),
                    # "subtype": parse_int(clean_quoted_value(values[8] if len(values) > 8 else "")),
                    "type": parse_int(clean_quoted_value(values[8])),
                    "subtype": parse_int(clean_quoted_value(values[9])),
                    "auth_alg": clean_quoted_value(values[10]),
                    "cat": parse_int(clean_quoted_value(values[11])),
                    "action": parse_int(clean_quoted_value(values[12])),
                    "channel": clean_quoted_value(values[13]),
                    "info": clean_quoted_value(values[14]),
                    "tag_numbers": clean_quoted_value(values[15]),
                    "mobility_domain": clean_quoted_value(values[16]) if len(values) > 16 else "",
                    # "auth_alg": clean_quoted_value(values[9] if len(values) > 9 else ""),
                    # "cat": parse_int(clean_quoted_value(values[10] if len(values) > 10 else "")),
                    # "action": parse_int(clean_quoted_value(values[11] if len(values) > 11 else "")),
                    # "channel": clean_quoted_value(values[12] if len(values) > 12 else ""),
                    # "info": clean_quoted_value(values[13] if len(values) > 13 else ""),
                    # "tag_numbers": clean_quoted_value(values[14] if len(values) > 14 else ""),
                    # "mobility_domain": clean_quoted_value(values[15] if len(values) > 15 else ""),
                })

            return sorted(frames, key=lambda x: x["ts"]), frame_filter

        def is_rrm_enabled_in_beacon(frames):
            for f in frames:
                if f["subtype"] == 8:  # Beacon
                    tags = parse_tag_numbers(f.get("tag_numbers", ""))
                    if "70" in tags:
                        return True
            return False

        def calculate_all_roam_times(events):
            """
            Detect multiple roam events and calculate roam time for each

            Returns:
                list of roam events with timing
            """

            roam_results = []

            for i, ev in enumerate(events):

                # ---------------------------
                # CASE 2: FT ROAM (11r)
                # ---------------------------
                if ev["kind"] == "ft_auth" and ev.get("type") == "request":
                    start = ev["ts"]

                    if roam_results and abs(roam_results[-1]["start_ts"] - start) < 0.05:
                        continue

                    for j in range(i, len(events)):
                        if events[j]["kind"] in ["reassoc_resp", "assoc_resp"]:
                            end = events[j]["ts"]

                            roam_results.append({
                                "type": "FT",
                                "roam_time_ms": round((end - start) * 1000, 2),
                                "start_ts": start,
                                "end_ts": end
                            })
                            break

                # ---------------------------
                # CASE 1: NON-FT ROAM
                # ---------------------------
                elif ev["kind"] in ["assoc_req", "reassoc_req"]:
                    start = ev["ts"]

                    if roam_results and abs(roam_results[-1]["start_ts"] - start) < 0.05:
                        continue

                    for j in range(i, len(events)):
                        if events[j]["kind"] in ["assoc_resp", "reassoc_resp"]:
                            end = events[j]["ts"]

                            roam_results.append({
                                "type": "NON_FT",
                                "roam_time_ms": round((end - start) * 1000, 2),
                                "start_ts": start,
                                "end_ts": end
                            })
                            break

            return roam_results

        def calculate_data_roam_time(events):
            """
            Calculate roam time:
            last DATA on old BSSID → first DATA on new BSSID
            """

            data_events = [e for e in events if e["kind"] == "data"]

            if not data_events:
                return []

            roam_results = []

            for i in range(1, len(data_events)):
                prev = data_events[i - 1]
                curr = data_events[i]

                if prev["bssid"] != curr["bssid"]:
                    roam_time = (curr["ts"] - prev["ts"]) * 1000

                    roam_results.append({
                        "from_bssid": prev["bssid"],
                        "to_bssid": curr["bssid"],
                        "roam_time_ms": round(roam_time, 2),
                        "start_ts": prev["ts"],
                        "end_ts": curr["ts"]
                    })

            return roam_results

        def check_no_eapol_on_target_ap(frames, events):
            """
            Validate that no EAPOL exchange happens on target AP after roam
            """

            # Step 1: detect roam transition
            roam = detect_roam_attempt(events)

            if not roam.get("roamed"):
                return {
                    "status": False,
                    "reason": "No roam detected"
                }

            target_bssid = roam["to_bssid"]
            roam_time = roam["trigger_ts"]

            # Step 2: find EAPOL frames after roam on target AP
            eapol_frames = []

            for f in frames:
                if f["bssid"] == target_bssid and f["ts"] >= roam_time:
                    info = f.get("info", "").lower()

                    if "eapol" in info or "key" in info:
                        eapol_frames.append(f)

            if eapol_frames:
                return {
                    "status": False,
                    "reason": f"EAPOL detected on target AP ({target_bssid})",
                    "count": len(eapol_frames)
                }

            return {
                "status": True,
                "reason": f"No EAPOL on target AP ({target_bssid})"
            }

        def detect_protocols(frames):
            """Detect 11k, 11v, 11r capabilities from frames with deduplication"""

            protocols = {
                '11k': {
                    'enabled': False,
                    'capability': False,
                    'action': False,
                    'frames': [],  # ONLY action frames
                    'details': set()
                },
                '11v': {'enabled': False, 'frames': [], 'details': set()},
                '11r': {'enabled': False, 'frames': [], 'details': set()},
            }

            seen_frames = {'11k': set(), '11v': set(), '11r': set()}

            for f in frames:
                tags = parse_tag_numbers(f.get("tag_numbers", ""))

                if bssid_list and f["bssid"] not in bssid_list:
                    continue

                # =====================================================
                # ✅ 802.11k CAPABILITY (Beacon / IE based)
                # =====================================================
                if "70" in tags:
                    protocols['11k']['capability'] = True
                    protocols['11k']['enabled'] = True
                    protocols['11k']['details'].add(f"{f['bssid']} => RM Enabled Capabilities IE")

                if "52" in tags:
                    protocols['11k']['capability'] = True
                    protocols['11k']['enabled'] = True
                    protocols['11k']['details'].add(f"{f['bssid']} => Neighbor Report IE")

                # =====================================================
                # ✅ 802.11k ACTION (STRICT CHECK)
                # =====================================================
                if f["cat"] == 5 and f["action"] in [0, 1]:
                    protocols['11k']['action'] = True
                    protocols['11k']['enabled'] = True

                    if f["no"] not in seen_frames['11k']:
                        protocols['11k']['frames'].append(f)
                        seen_frames['11k'].add(f["no"])

                    protocols['11k']['details'].add(
                        f"{f['bssid']} => RRM action (action={f['action']})"
                    )

                # =====================================================
                # ✅ 802.11v (BTM)
                # =====================================================
                if f["cat"] == 10 and f["action"] in [6, 7, 8]:
                    if f["no"] not in seen_frames['11v']:
                        protocols['11v']['enabled'] = True
                        protocols['11v']['frames'].append(f)
                        seen_frames['11v'].add(f["no"])

                    action_name = {
                        8: "Query",
                        6: "Request",
                        7: "Response"
                    }.get(f["action"], f"action={f['action']}")

                    protocols['11v']['details'].add(
                        f"{f['bssid']} => BTM {action_name}"
                    )

                if "127" in tags:
                    protocols['11v']['details'].add("Extended Capabilities IE")

                # =====================================================
                # ✅ 802.11r (FT)
                # =====================================================
                if str(f.get("auth_alg")) == "2":
                    if f["no"] not in seen_frames['11r']:
                        protocols['11r']['enabled'] = True
                        protocols['11r']['frames'].append(f)
                        seen_frames['11r'].add(f["no"])

                    protocols['11r']['details'].add(
                        f"{f['bssid']} => FT Authentication"
                    )

                if "54" in tags:
                    if f["no"] not in seen_frames['11r']:
                        protocols['11r']['enabled'] = True
                        protocols['11r']['frames'].append(f)
                        seen_frames['11r'].add(f["no"])

                    md_info = (
                        f"MDID={f.get('mobility_domain', '')}"
                        if f.get('mobility_domain') else "present"
                    )

                    protocols['11r']['details'].add(
                        f"{f['bssid']} => Mobility Domain IE ({md_info})"
                    )

                if "48" in tags:
                    protocols['11r']['details'].add(
                        f"{f['bssid']} => RSN IE (FT possible)"
                    )

            # Convert sets → lists
            for proto in protocols:
                protocols[proto]['details'] = list(protocols[proto]['details'])

            return protocols

        def extract_events(frames):
            """
                Extracts meaningful Wi-Fi protocol events from parsed frame data.

                This function scans through captured frames and converts low-level
                802.11 fields into structured, time-ordered events for analysis.

                It identifies:
                - 802.11v BTM events (request, response, query)
                - 802.11k RRM action frames
                - Association and reassociation (request/response)
                - 802.11r FT authentication (request/response)
                - Disassociation and deauthentication events

                Each event includes timestamp, frame number, band, and BSSID,
                enabling higher-level roaming and steering analysis.

                Returns:
                    List[dict]: Chronologically sorted list of extracted events
            """
            events = []
            for f in frames:
                band = band_from_channel(f["channel"])

                # 11v (BTM) events
                if f["cat"] == 10 and f["action"] in [6, 7, 8]:
                    if f["action"] == 6:
                        events.append({
                            "kind": "btm_request",
                            "ts": f["ts"],
                            "frame": f["no"],
                            "band": band,
                            "bssid": f["bssid"]
                        })
                    elif f["action"] == 7:
                        events.append({
                            "kind": "btm_response",
                            "ts": f["ts"],
                            "frame": f["no"],
                            "band": band,
                            "bssid": f["bssid"]
                        })
                    elif f["action"] == 8:
                        events.append({
                            "kind": "btm_query",
                            "ts": f["ts"],
                            "frame": f["no"],
                            "band": band,
                            "bssid": f["bssid"]
                        })

                # 11k events
                if f["cat"] == 5 and f["action"] in [0, 1]:
                    events.append({
                        "kind": "rrm_frame",
                        "ts": f["ts"],
                        "frame": f["no"],
                        "band": band,
                        "bssid": f["bssid"]
                    })

                # Association/Reassociation events
                if f["subtype"] in [0, 2]:
                    events.append({
                        "kind": "assoc_req" if f["subtype"] == 0 else "reassoc_req",
                        "ts": f["ts"],
                        "frame": f["no"],
                        "band": band,
                        "bssid": f["bssid"]
                    })

                if f["subtype"] in [1, 3]:
                    events.append({
                        "kind": "assoc_resp" if f["subtype"] == 1 else "reassoc_resp",
                        "ts": f["ts"],
                        "frame": f["no"],
                        "band": band,
                        "bssid": f["bssid"]
                    })

                # 11r FT Auth events - track both request and response
                if str(f.get("auth_alg")) == "2":
                    # Check if this is an FT authentication frame
                    # seq=1 usually indicates response, seq=0 or missing indicates request
                    if "response" in f.get("info", "").lower() or "seq=1" in f.get("info", ""):
                        # This is likely an FT auth response (completion)
                        events.append({
                            "kind": "ft_auth",
                            "ts": f["ts"],
                            "frame": f["no"],
                            "band": band,
                            "bssid": f["bssid"],
                            "type": "response"
                        })
                    else:
                        # FT auth request
                        events.append({
                            "kind": "ft_auth",
                            "ts": f["ts"],
                            "frame": f["no"],
                            "band": band,
                            "bssid": f["bssid"],
                            "type": "request"
                        })

                # De-Auth and Dis-assoc
                if f["subtype"] == 10:
                    events.append({
                        "kind": "disassoc",
                        "ts": f["ts"],
                        "frame": f["no"],
                        "band": band,
                        "bssid": f["bssid"]
                    })

                if f["subtype"] == 12:
                    events.append({
                        "kind": "deauth",
                        "ts": f["ts"],
                        "frame": f["no"],
                        "band": band,
                        "bssid": f["bssid"]
                    })

                # DATA frames
                if f.get("type") == 2:
                    events.append({
                        "kind": "data",
                        "ts": f["ts"],
                        "frame": f["no"],
                        "band": band,
                        "bssid": f["bssid"]
                    })

            return sorted(events, key=lambda x: x["ts"])

        def detect_prior_connection(events, idx):
            """Walk backwards to find the last confirmed association"""
            for j in range(idx - 1, -1, -1):
                if events[j]["kind"] in {"assoc_resp"} and events[j].get("bssid"):
                    return events[j]
            return None

        def detect_roam_attempt(events, window_sec=15.0):
            """Detect BSSID transition - works with both classic and FT roaming"""

            # First, collect all association points (both classic and FT)
            connection_points = []

            for i, ev in enumerate(events):
                # Classic association
                if ev["kind"] == "assoc_resp" and ev.get("bssid"):
                    connection_points.append({
                        "idx": i,
                        "ts": ev["ts"],
                        "bssid": ev["bssid"],
                        "band": ev.get("band"),
                        "type": "assoc"
                    })
                # FT authentication (11r roaming)
                elif ev["kind"] == "ft_auth" and ev.get("bssid"):
                    # Check if this is a successful FT auth (look for corresponding response)
                    # For simplicity, treat FT auth as a connection point
                    connection_points.append({
                        "idx": i,
                        "ts": ev["ts"],
                        "bssid": ev["bssid"],
                        "band": ev.get("band"),
                        "type": "ft_auth"
                    })

            # Sort by timestamp
            connection_points.sort(key=lambda x: x["ts"])

            # Look for transitions between different BSSIDs
            for i in range(1, len(connection_points)):
                prev = connection_points[i - 1]
                curr = connection_points[i]

                if prev["bssid"] != curr["bssid"]:
                    # Found a transition
                    time_diff = curr["ts"] - prev["ts"]
                    if time_diff <= window_sec:
                        return {
                            "roamed": True,
                            "from_bssid": prev["bssid"],
                            "to_bssid": curr["bssid"],
                            "from_band": prev["band"],
                            "to_band": curr["band"],
                            "trigger_ts": curr["ts"],
                            "method": curr["type"]
                        }

            # Fallback: Look for BTM followed by connection to new BSSID
            btm_events = [e for e in events if e["kind"] in ["btm_request", "btm_response"]]

            for btm in btm_events:
                for conn in connection_points:
                    if conn["ts"] > btm["ts"] and (conn["ts"] - btm["ts"]) <= window_sec:
                        # Find previous connection
                        prev_conn = None
                        for pc in connection_points:
                            if pc["ts"] < btm["ts"] and pc["bssid"] != conn["bssid"]:
                                prev_conn = pc
                                break

                        if prev_conn:
                            return {
                                "roamed": True,
                                "from_bssid": prev_conn["bssid"],
                                "to_bssid": conn["bssid"],
                                "from_band": prev_conn["band"],
                                "to_band": conn["band"],
                                "trigger_ts": btm["ts"],
                                "method": "btm_steered"
                            }

            return {"roamed": False}

        def analyze_band_steering(events):
            btm_reqs = [e for e in events if e["kind"] == "btm_request"]
            btm_resps = [e for e in events if e["kind"] == "btm_response"]

            if not btm_reqs:
                return "FAIL_BAND_STEERING", ["No BTM Request detected"]

            roam = detect_roam_attempt(events)

            if roam.get("roamed"):
                if btm_resps:
                    return "PASS_BAND_STEERING_CLIENT_DRIVEN", [
                        "11v observed",
                        f"Client moved: {roam['from_bssid']} → {roam['to_bssid']}",
                        f"Band: {roam['from_band']} → {roam['to_band']}",
                    ]
                return "PASS_BAND_STEERING", [
                    "11v observed",
                    f"Client moved: {roam['from_bssid']} → {roam['to_bssid']}",
                    f"Band: {roam['from_band']} → {roam['to_band']}",
                ]

            return "FAIL_BAND_STEERING", ["No Steer detected after BTM"]

        def analyze_11r_roaming(events, protocols):
            if not protocols['11r']['enabled']:
                return "FAIL_11R_NO_FT", ["No FT authentication (auth_alg=2) or Mobility Domain IE observed"]

            ft_events = [e for e in events if e["kind"] == "ft_auth"]
            if ft_events:
                return "PASS_11R_ROAM", [
                    f"FT authentication observed ({len(ft_events)} frames)",
                    "11r roaming detected"
                ]

            if protocols['11r']['enabled']:
                return "PASS_11R_FT_ONLY", [
                    "Mobility Domain IE present",
                    "11r capability confirmed"
                ]

            return "FAIL_11R_NO_FT", ["No 11r evidence found"]

        def analyze_11kv_roaming(events, protocols):
            has_k = protocols['11k']['enabled']
            has_v = protocols['11v']['enabled']

            if not has_k and not has_v:
                return "FAIL_NO_11KV_EVIDENCE", ["No 11k or 11v evidence observed"]

            roam = detect_roam_attempt(events)

            if roam.get("roamed"):
                details = [
                    f"11k: {'✓' if has_k else '✗'} | 11v: {'✓' if has_v else '✗'}",
                    f"Roam: {roam['from_bssid']} → {roam['to_bssid']}",
                    f"Band: {roam['from_band']} → {roam['to_band']}",
                ]
                return "PASS_11KV_ROAMING", details

            return "FAIL_11KV_NO_ROAM", ["No roam transition detected"]

        def analyze_11k(frames):
            rrm_beacon = is_rrm_enabled_in_beacon(frames)

            if not rrm_beacon:
                return "FAIL_NO_11K_BEACON", [
                    "RRM Enabled Capabilities IE (tag 70) not present in Beacon frames"
                ]

            return "PASS_11K_CAPABILITY", [
                "RRM Enabled Capabilities IE detected in Beacon frames",
                "802.11k capability is advertised by AP"
            ]

        def analyze_11k_action_frame(events):
            rrm_frames = [e for e in events if e["kind"] == "rrm_frame"]

            if not rrm_frames:
                return "FAIL_11K_NO_ACTION_FRAME", [
                    "No valid 802.11k RRM action frames found"
                ]

            return "PASS_11K_ACTION_FRAME", [
                f"Detected {len(rrm_frames)} RRM action frames",
                "802.11k action frame observed"
            ]

        def analyze_11vr_beacon(frames, events):
            has_11v = False
            has_11r = False

            for f in frames:
                if f["subtype"] != 8:  # Beacon only
                    continue

                tags = parse_tag_numbers(f.get("tag_numbers", ""))

                # 11v check → Extended Capabilities (Tag 127)
                if "127" in tags:
                    has_11v = True

                # 11r check → Mobility Domain (Tag 54)
                if "54" in tags:
                    has_11r = True

            if has_11v and has_11r:
                return "PASS_11VR_BEACON", [
                    "Extended Capabilities IE (Tag 127) present in Beacon",
                    "Mobility Domain IE (Tag 54) present in Beacon",
                    "802.11v and 802.11r capabilities are advertised"
                ]

            details = []
            if not has_11v:
                details.append("802.11v not detected: Extended Capabilities IE (Tag 127) missing in Beacon")
            if not has_11r:
                details.append("802.11r not detected: Mobility Domain IE (Tag 54) missing in Beacon")

            return "FAIL_11VR_BEACON", details

        def analyze_11kvr_roaming(events, protocols, frames):
            has_k = protocols['11k']['enabled']
            has_v = protocols['11v']['enabled']
            has_r = protocols['11r']['enabled']

            present = []
            if has_k:
                present.append("11k")
            if has_v:
                present.append("11v")
            if has_r:
                present.append("11r")

            if has_k and has_v and has_r:
                roam = detect_roam_attempt(events)
                md_present = False

                if roam.get("roamed"):
                    target_bssid = roam["to_bssid"]
                    roam_ts = roam["trigger_ts"]

                    for f in frames:
                        if f["bssid"] == target_bssid and f["ts"] >= roam_ts:
                            if f["subtype"] in [2, 3]:  # reassoc
                                tags = parse_tag_numbers(f.get("tag_numbers", ""))
                                if "54" in tags:
                                    md_present = True
                                    break

                if roam.get("roamed"):
                    if md_present:
                        return "PASS_11KVR_ROAMING", [
                            f"All three protocols observed: {', '.join(present)}",
                            f"Roam: {roam['from_bssid']} → {roam['to_bssid']}",
                            f"Band: {roam['from_band']} → {roam['to_band']}",
                            "Mobility Domain IE present in reassociation (11r OK)"
                        ]
                    else:
                        return "FAIL_11R_NO_MD", [
                            f"Protocols detected: {', '.join(present)}",
                            "Roam detected but Mobility Domain IE missing in reassociation"
                        ]
                    # return "PASS_11KVR_ROAMING", [
                    #     f"All three protocols observed: {', '.join(present)}",
                    #     f"Roam: {roam['from_bssid']} → {roam['to_bssid']}",
                    #     f"Band: {roam['from_band']} → {roam['to_band']}",
                    # ]
                return "WARN_11KVR_NO_ROAM", [
                    f"Protocols present: {', '.join(present)}",
                    "No BSSID transition detected"
                ]

            return "WARN_11KVR_PARTIAL_PROTOCOLS", [
                f"Present: {', '.join(present) if present else 'none'}",
                "Missing some protocols for full 11kvr roaming"
            ]

        def analyze_11kr_roaming(events, protocols):
            has_k = protocols['11k']['enabled']
            has_r = protocols['11r']['enabled']

            if not has_k and not has_r:
                return "FAIL_NO_11KR_EVIDENCE", ["Neither 11k nor 11r observed"]

            roam = detect_roam_attempt(events)

            if has_k and has_r:
                # if roam.get("roamed"):
                return "PASS_11KR", [
                    f"Both 11k and 11r were observed"
                ]
                # return "WARN_11KR_NO_ROAM", ["Protocols present but no roam detected"]

            return "WARN_11KR_PARTIAL", [
                f"11k {'was observed' if has_k else 'was not observed'} | 11r {'was observed' if has_r else 'was not observed'}",
                "Partial protocol support"
            ]

        def analyze_multi_roam(events):
            roams = []
            seen_targets = set()

            for i, ev in enumerate(events):
                if ev["kind"] not in {"assoc_req", "assoc_resp"}:
                    continue

                target_bssid = ev.get("bssid")
                if not target_bssid or target_bssid in seen_targets:
                    continue

                prior = detect_prior_connection(events, i)
                if not prior or not prior.get("bssid") or prior["bssid"] == target_bssid:
                    continue

                seen_targets.add(target_bssid)

                roams.append({
                    "from_bssid": prior["bssid"],
                    "to_bssid": target_bssid,
                    "from_band": prior["band"],
                    "to_band": ev["band"],
                })

            if not roams:
                return [{"result": "FAIL_NO_ROAM", "details": ["No roaming detected"]}]

            results = []
            for idx, roam in enumerate(roams, 1):
                results.append({
                    "result": "PASS_ROAM_DETECTED",
                    "details": [
                        f"Roam #{idx}",
                        f"From: {roam['from_bssid']} ({roam['from_band']})",
                        f"To: {roam['to_bssid']} ({roam['to_band']})",
                    ]
                })

            return results

        def check_specific_protocol(protocols, check_proto):
            """Check if a specific protocol is enabled and return appropriate result"""
            proto_map = {
                "11k": {"enabled": protocols['11k']['enabled'], "details": protocols['11k']['details'],
                        "frames": protocols['11k']['frames']},
                "11v": {"enabled": protocols['11v']['enabled'], "details": protocols['11v']['details'],
                        "frames": protocols['11v']['frames']},
                "11r": {"enabled": protocols['11r']['enabled'], "details": protocols['11r']['details'],
                        "frames": protocols['11r']['frames']},
            }

            proto_info = proto_map.get(check_proto.upper())
            if not proto_info:
                return "FAIL_INVALID_PROTOCOL", [f"Invalid protocol: {check_proto}"]

            if check_proto.lower() == "11k":
                if protocols['11k']['action']:
                    return "PASS_11K_ONLY", [
                        "11k action frames detected",
                        f"Frames: {len(protocols['11k']['frames'])}"
                    ]
                elif protocols['11k']['capability']:
                    return "WARN_11K_CAPABILITY_ONLY", [
                        "11k capability present but no action frames"
                    ]
                else:
                    return "FAIL_11K_NOT_ENABLED", [
                        "No 11k capability or action frames found"
                    ]
            else:
                if proto_info["enabled"]:
                    return f"PASS_{check_proto.upper()}_ONLY", [
                        f"{check_proto.upper()} protocol is enabled",
                        f"Evidence: {', '.join(proto_info['details'][:3])}",
                        f"Frames: {len(proto_info['frames'])}"
                    ]

                return f"FAIL_{check_proto.upper()}_NOT_ENABLED", [
                    f"{check_proto.upper()} protocol not detected",
                    "No supporting frames or IEs found"
                ]

        def build_compact_protocol_summary(protocols):
            """Build deduplicated protocol summary"""
            lines = []
            lines.append("\n" + "=" * 70)
            if client_mac:
                lines.append(f"CLIENT: {norm(client_mac)}")
            if bssid:
                lines.append(f"BSSID: {norm(bssid)}")
            lines.append(f"MODE  : {mode}")
            if check_protocol:
                lines.append(f"CHECK : {check_protocol.upper()} only")
            lines.append("=" * 70)

            # If checking specific protocol, show only that protocol
            if check_protocol:
                proto = check_protocol.upper()
                proto_name = {"11K": "802.11k (RRM)", "11V": "802.11v (BTM)", "11R": "802.11r (FT)"}.get(proto, proto)
                data = protocols[proto.lower()]
                status = "✓ ENABLED" if data['enabled'] else "✗ NOT DETECTED"

                lines.append(f"\n┌─ {proto_name}")
                lines.append(f"│  Status: {status}")
                lines.append(f"│  Frames: {len(data['frames'])}")

                if data['details']:
                    lines.append(f"│")
                    lines.append(f"│  Evidence:")
                    for detail in data['details'][:5]:
                        lines.append(f"│    • {detail}")

                lines.append(f"└─")
            else:
                # Show all protocols
                lines.append(
                    "\n┌───────────────┬──────────┬──────────────────────────────────────────────────────────────────────────────────")  # ┐
                lines.append("│ Protocol      │ Status   │ Evidence                            │")
                lines.append(
                    "├─────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────")  # ┤

                for proto, name in [('11k', '802.11k (RRM)'), ('11v', '802.11v (BTM)'), ('11r', '802.11r (FT)')]:
                    data = protocols[proto]
                    status = "✓ ENABLED" if data['enabled'] else "✗ NOT DETECTED"

                    lines.append(f"│ {name:<11}   │ {status:<8}   │                                     ")

                    if data['details']:
                        for i, detail in enumerate(data['details'][:3]):
                            if i == 0:
                                lines.append(f"│               │          │ • {detail:<35} ")
                            else:
                                lines.append(f"│               │          │   {detail:<35} ")

                    if data['frames']:
                        lines.append(f"│               │          │   ({len(data['frames'])} frames)   ")

                    lines.append(
                        "├─────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────")  # ┤

            return "\n".join(lines)

        def build_frame_view(frames):
            """Build detailed frame view (limited to unique frames)"""
            lines = []
            lines.append("\n" + "=" * 120)

            if check_protocol:
                lines.append(f"KEY {check_protocol.upper()} PROTOCOL FRAMES")
            else:
                lines.append("KEY PROTOCOL FRAMES (First occurrence per type)")

            lines.append("=" * 120)

            seen_types = set()
            shown_frames = []

            for f in frames:
                # Determine frame type
                if f["cat"] == 10 and f["action"] in [6, 7, 8]:
                    frame_type = f"BTM (action={f['action']})"
                elif f["cat"] == 5 and f["action"] in [0, 1]:
                    frame_type = "RRM (11k)"
                elif str(f.get("auth_alg")) == "2":
                    frame_type = "FT Auth (11r)"
                elif f["subtype"] == 0:
                    frame_type = "Association Request"
                elif f["subtype"] == 1:
                    frame_type = "Association Response"
                elif f["subtype"] == 2:
                    frame_type = "Reassociation Request"
                elif f["subtype"] == 3:
                    frame_type = "Reassociation Response"
                else:
                    continue

                # If checking specific protocol, filter by protocol
                if check_protocol:
                    if check_protocol == "11k" and f["cat"] != 5:
                        continue
                    if check_protocol == "11v" and not (f["cat"] == 10 and f["action"] in [6, 7, 8]):
                        continue
                    if check_protocol == "11r" and f.get("auth_alg") != "2" and "54" not in parse_tag_numbers(
                            f.get("tag_numbers", "")):
                        continue

                # Only show first occurrence of each frame type
                if frame_type not in seen_types:
                    seen_types.add(frame_type)
                    shown_frames.append((f, frame_type))

            if not shown_frames:
                return "\nNo relevant frames found"

            lines.append(f"{'Frame':>6} {'Time(s)':<12} {'CH':<6} {'Type':<25} {'BSSID':<18}")
            lines.append("-" * 80)

            for f, frame_type in shown_frames[:20]:
                band = band_from_channel(f["channel"])
                lines.append(
                    f"{f['no']:>6}  {f['ts']:.6f}  "
                    f"{f['channel']}({band}): {frame_type:<25} "
                    f"{f['bssid']:<18}"
                )

            lines.append("=" * 120)
            return "\n".join(lines)

        # -------------------------------
        # MAIN EXECUTION
        # -------------------------------
        bssid_list = [norm(b) for b in (bssid_list or []) if b]
        if bssid:
            bssid_list.append(norm(bssid))

        frames, tshark_filter = run_tshark()

        if not frames:
            return {
                "client_mac": norm(client_mac) if client_mac else None,
                "bssid": norm(bssid) if bssid else None,
                "mode": mode,
                "check_protocol": check_protocol,
                "result": "FAIL_NO_FRAMES",
                "details": ["No relevant frames found in capture"],
                "events": [],
                "protocols": {"11k": False, "11v": False, "11r": False},
                "protocol_details": {"11k": [], "11v": [], "11r": []},
                "frame_counts": {"11k": 0, "11v": 0, "11r": 0},
                "report_text": "No relevant frames found",
                "pass_status": False,
            }

        roam_metrics = {}
        data_roam = None
        protocols = detect_protocols(frames)
        events = extract_events(frames)
        eapol_check = None

        if mode == "11kvr_roaming":
            eapol_check = check_no_eapol_on_target_ap(frames, events)

        if mode == "11kvr_over_11kv_roaming":
            roam_metrics = calculate_all_roam_times(events)

        if mode == "11kvr_roaming_soft_roam":
            data_roam = calculate_data_roam_time(events)

        # Determine result based on mode and check_protocol
        if check_protocol:
            # Specific protocol check
            result, details = check_specific_protocol(protocols, check_protocol)
        else:
            # Regular mode-based analysis
            if mode == "band_steering":
                result, details = analyze_band_steering(events)

            elif mode in ["11r_roaming", "11r"]:
                result, details = analyze_11r_roaming(events, protocols)

            elif mode in ["11kv_roaming", "11kv"]:
                result, details = analyze_11kv_roaming(events, protocols)

            elif mode in ["11kvr_roaming", "11kvr", "11kvr_over_11kv_roaming", "11kvr_roaming_soft_roam"]:
                result, details = analyze_11kvr_roaming(events, protocols, frames)

            elif mode in ["11kr_roaming", "11kr"]:
                result, details = analyze_11kr_roaming(events, protocols)

            elif mode == "11k_action":
                result, details = analyze_11k_action_frame(events)

            elif mode == "11k":
                result, details = analyze_11k(frames)

            elif mode == "11vr":
                result, details = analyze_11vr_beacon(frames, events)

            elif mode == "multi_roam":
                multi_results = analyze_multi_roam(events)
                if multi_results:
                    result = multi_results[0]["result"]
                    details = multi_results[0]["details"]
                else:
                    result = "FAIL_NO_ROAM"
                    details = ["No roaming detected"]

            else:
                raise ValueError(f"Unsupported mode: {mode}")

        # -------------------------------
        # REPORT BUILDING
        # -------------------------------
        report = []
        report.append(build_compact_protocol_summary(protocols))

        report.append(f"\nRESULT: {result}")
        report.append("\nDETAILS:")
        for d in details:
            report.append(f"  • {d}")

        if show_events:
            report.append("\nSUPPORTING EVENTS (first 10):")
            for e in events[:10]:
                report.append(f"  [{e['frame']}] {e['kind']} @ {e['ts']:.6f}s | {e.get('band', '?')}")

        if frame_view:
            report.append(build_frame_view(frames))

        report.append("\nFILTERS USED:")
        for f in build_filter_summary():
            report.append(f"  • {f}")

        report.append("\nPCAP DISPLAY FILTER USED:")
        report.append(pretty_filter(tshark_filter))

        report.append(build_static_logic_reference())
        if mode == "11kvr_over_11kv_roaming":
            report.append("\nROAM TIME ANALYSIS:")

            if roam_metrics:
                for idx, r in enumerate(roam_metrics, 1):
                    report.append(
                        f"  • Roam #{idx}: {r['roam_time_ms']} ms ({r['type']})"
                    )
            else:
                report.append("  • No roam times detected")

        if mode == "11kvr_roaming_soft_roam":
            report.append("\nDATA ROAM TIME:")

            if isinstance(data_roam, list) and data_roam:
                for idx, r in enumerate(data_roam, 1):
                    report.append(
                        f"  • Roam #{idx}: {r['roam_time_ms']} ms "
                        f"({r['from_bssid']} → {r['to_bssid']})"
                    )
            else:
                report.append(" No data-based roam detected")

        if mode == "11kvr_roaming":
            report.append("\nEAPOL VALIDATION:")

            if eapol_check:
                if eapol_check["status"]:
                    report.append(f"  • PASS: {eapol_check['reason']}")
                else:
                    report.append(f"  • FAIL: {eapol_check['reason']}")

        return {
            "client_mac": norm(client_mac) if client_mac else None,
            "bssid": norm(bssid) if bssid else None,
            "mode": mode,
            "check_protocol": check_protocol,
            "result": result,
            "details": details,
            "events": events,
            "roam_times": roam_metrics if roam_metrics else [],
            # "data_roam_times": data_roam if mode == "11kvr_roaming" else [],
            "data_roam_times": data_roam if mode == "11kvr_roaming_soft_roam" else [],
            "eapol_validation": eapol_check if mode == "11kvr_roaming" else None,
            "protocols": {
                "11k": protocols['11k']['enabled'],
                "11v": protocols['11v']['enabled'],
                "11r": protocols['11r']['enabled']
            },
            "protocol_details": {
                "11k": protocols['11k']['details'],
                "11v": protocols['11v']['details'],
                "11r": protocols['11r']['details']
            },
            "frame_counts": {
                "11k": len(protocols['11k']['frames']),
                "11v": len(protocols['11v']['frames']),
                "11r": len(protocols['11r']['frames'])
            },
            "report_text": "\n".join(report),
            "pass_status": result in PASS_RESULTS,
        }

    def run_bandsteer_test(
            self,
            ssid,
            passkey,
            security,
            num_sta,
            test_type,
            steer_type,
            test_config,
            get_testbed_details=None,
            get_target_object=None
    ):
        """
        Execute Band Steering test cases based on test_type.

        Supported test types:
            - standard                 : Basic band steering validation
            - pre_assoc                : Steering before client association
            - post_assoc               : Steering after client association
            - neither_band_post_assoc  : No-pre/no-post steering behavior
            - stickiness               : Verify STA does not bounce back
            - steer_success_rate       : Steering success ≥ 5/6 iterations
            - performance              : Throughput impact during steering
            - vlan_standard            : Vlan band steering validation
            - client_isolation         : steering testcases with client isolation
            - UE based                 : steering with enterprise security AAA server
            - management_vlan          : steering test cases with mgmt vlan enabled

        Common validation across tests:
            - Initial band association verification
            - Client Connectivity
            - Connectivity b/w stations & AP (l3) validation
            - Layer3 Traffic (Load Based) Band Steering
            - Attenuation for (RSSI Based) Band Steering
            - BSSID/Channel Change for non-stationary clients
            - Iterations Pass/Fail criteria for few test cases

        Returns:
            ("PASS", result_dict) on success
            pytest.fail(...) on validation failure
        """

        dict_all_radios_2g = {"be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios, "ax200_radios": self.ax200_radios,
                              "mtk_radios": self.mtk_radios,
                              "wave2_2g_radios": self.wave2_2g_radios,
                              "wave1_radios": self.wave1_radios
                              }
        dict_all_radios_5g = {"be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios, "ax200_radios": self.ax200_radios,
                              "mtk_radios": self.mtk_radios,
                              "wave2_5g_radios": self.wave2_5g_radios,
                              "wave1_radios": self.wave1_radios
                              }

        # {'be200_radios': ['1.1.wiphy1'], 'ax210_radios': [], 'ax200_radios': [],
        #  'mtk_radios': ['1.1.wiphy0', '1.2.wiphy0', '1.2.wiphy1'], 'wave2_2g_radios': [], 'wave1_radios': []}
        #
        # {'be200_radios': ['1.1.wiphy1'], 'ax210_radios': [], 'ax200_radios': [],
        #  'mtk_radios': ['1.1.wiphy0', '1.2.wiphy0', '1.2.wiphy1'], 'wave2_5g_radios': [], 'wave1_radios': []}
        #
        # {'wave2_2g_radios': 64, 'wave2_5g_radios': 64, 'wave1_radios': 64, 'mtk_radios': 19, 'ax200_radios': 1,
        #  'ax210_radios': 1, 'be200_radios': 1}

        station_radio_map = {}

        def attach_attenuator_state(band_steer, title="Attenuator State"):
            atten_info = band_steer.get_atten_info()

            if not atten_info:
                return

            allure.attach(
                body=json.dumps(atten_info, indent=4),
                name=title,
                attachment_type=allure.attachment_type.JSON
            )

        def track_station_creation(radio, station_list):
            """Track which stations were created on which radio."""
            if radio not in station_radio_map:
                station_radio_map[radio] = []
            station_radio_map[radio].extend(station_list)

        # NOTE: standard test_type is same for both standard and few data vlan test cases.

        if test_type == "standard":
            """
                Test Cases TC_BS_13 and TC_BS_14
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- STA Creation --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- Initial Conditions --------------------
            if band_steer.steer_type == 'steer_fiveg':
                # get_target_object.dut_library_object.control_radio_band(band="5g", action="down")

                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 950, idx - 1)  # Initial attenuation to 40 for steer_fiveg case
                    band_steer.set_atten('1.1.3002', 950, idx - 3)  # module 1 and 2 setting to MAX
                    band_steer.set_atten('1.1.3002', 400, idx - 1)

                band_steer.create_clients(
                    radio=dict_all_radios_5g["mtk_radios"][0],
                    ssid=ssid,
                    passwd=passkey,
                    security=security,
                    station_list=sta_list,
                    station_flag="use-bss-transition",
                    sta_type="normal",
                    initial_band_pref="5GHz",
                    option=None
                )

            else:
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 950, idx - 3)  # Initial attenuation to 0 for steer_fiveg case
                    band_steer.set_atten('1.1.3002', 950, idx - 3)  # module 1 and 2 setting to MAX
                    band_steer.set_atten('1.1.3002', 0, idx - 1)

                band_steer.create_clients(
                    radio=dict_all_radios_5g["mtk_radios"][0],
                    ssid=ssid,
                    passwd=passkey,
                    security=security,
                    station_list=sta_list,
                    station_flag="use-bss-transition",
                    sta_type="normal",
                    initial_band_pref="5GHz",
                    option=None
                )

            # -------------------- Validate Initial Band --------------------
            # Attach Station IP map to allure report
            band_steer.get_station_ips()

            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)
            before_state = {}

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if band_steer.steer_type == 'steer_fiveg':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )

                elif band_steer.steer_type == 'steer_twog':
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.start_band_steer_test_standard(
                attenuator='1.1.3002', modules=[3, 4],
                steer='fiveg' if band_steer.steer_type == 'steer_fiveg' else 'twog')

            # temporarily waiting for 2 mins
            time.sleep(120)

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Band Steering Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta in sta_list:
                result = test_results.get(sta)
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE Steer RSSI {before_rssi}")
                print(f"[DEBUG] AFTER Steer RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            print("\nAnalysing Pcap")

            for sta in sta_list:
                client_mac = test_results.get(sta).get("client_mac")

                analysis = self.analyze_sniffer_pcap(
                    pcap_path=local_pcap,
                    client_mac=client_mac,
                    mode="band_steering",
                    show_events=True
                )

                allure.attach(
                    analysis["report_text"],
                    name=f"Band Steering Analysis {sta} - {client_mac}",
                    attachment_type=allure.attachment_type.TEXT
                )

                if not analysis["pass_status"]:
                    pcap_failures.append({
                        "sta": sta,
                        "client_mac": client_mac,
                        "reason": analysis["result"]
                    })

            all_pass = not functional_failures and not pcap_failures
            return all_pass, {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results
            }

        elif test_type == "pre_assoc":
            """
                Test Cases TC_BS_2 and TC_BS_3 Pre-Association Steering

                Purpose:
                Verify that a client is steered to 5GHz/2.4GHz during authentication when 2.4GHz/5Ghz is overloaded.

                Test Flow:
                1. Enable band steering with thresholds configured
                2. Connect STA1 and STA2 to 5GHz/2.4GHz
                3. Disconnect STA2
                4. Overload 5GHz/2.4GHz using traffic from STA1
                5. Move STA2 closer to AP to ensure strong 5GHz RSSI
                6. Attempt to reconnect STA2

                Expected Results:
                - AP rejects authentication on 5GHz/2.4GHz
                - STA2 associates successfully on 2.4GHz/5Ghz
                - Syslog shows authentication reject and steering completion
                - Sniffer confirms reassociation to 2.4GHz/5Ghz
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 2),
                max_attenuation=45,
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz",
                traffic="download"
            )
            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- STA Creation --------------------
            sta_list_1 = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"

            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=1, num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"

            sta_list = sta_list_1 + sta_list_2

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            print(f"[DEBUG] Station List: {sta_list}")
            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # -------------------- Start Sniffer --------------------
            # Start the Sniffer along with dummy client creation on 7996 radio
            band_steer.start_sniffer()

            # -------------------- Initial Attenuation --------------------
            # Steer_five means station that needed to be created on 2.4Ghz band.
            if band_steer.steer_type == 'steer_twog':
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 0, idx - 3)
                    band_steer.set_atten('1.1.3002', 0, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)

            else:
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 400, idx - 3)
                    band_steer.set_atten('1.1.3002', 400, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)

            time.sleep(5)  # wait to some time for attenuation to be applied

            # -------------------- Station Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],  # "1.2.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="2GHz" if band_steer.steer_type == 'steer_fiveg' else "5GHz",
                option=None
            )
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="2GHz" if band_steer.steer_type == 'steer_fiveg' else "5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list_2:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if band_steer.steer_type == 'steer_fiveg':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )

                elif band_steer.steer_type == 'steer_twog':
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)

            band_steer.stop_ping_cx()

            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if ping_status:
                print(f'[DEBUG] Admin Down {sta_list_2[0]}')
                band_steer.admin_down(sta_list_2[0])

                print(f"[DEBUG] Starting TCP Traffic on station {sta_list_1}")
                band_steer.create_specific_cx(station_list=sta_list_1)
                band_steer.start_traffic_cx()

                # -------------------- Trigger Steering --------------------
                start_time, end_time = band_steer.start_band_steer_test_standard(
                    attenuator='1.1.3009', modules=[1, 2],
                    steer='twog' if band_steer.steer_type == "steer_twog" else 'fiveg')

                # temporarily waiting for 2 mins (If not AP client initiates steering)
                time.sleep(120)

                print(f"[DEBUG] Start Time : {start_time}")
                print(f"[DEBUG] End Time : {end_time}")

                band_steer.admin_up(sta_list_2[0])

                # -------------------- Validate Steering --------------------
                after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
                after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
                after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

                after_state = {}

                # -------------------- Attenuator State --------------------
                attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

                print(f"[DEBUG] Stopping TCP Traffic on station {sta_list_1}")
                band_steer.stop_traffic_cx()

                allure.attach(
                    body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                    name="Layer3 Traffic Data",
                    attachment_type=allure.attachment_type.JSON
                )

                # Clean up traffic cross-connections
                band_steer.clean_traffic_cx()
                print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

                # -------------------- Stop Sniffer --------------------
                local_pcap = band_steer.stop_sniffer()

                try:
                    with open(local_pcap, "rb") as f:
                        allure.attach(
                            f.read(),
                            name="Band Steering Sniffer Capture",
                            attachment_type=allure.attachment_type.PCAP
                        )
                except Exception as e:
                    print("Allure attach failed:", e)

                stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

                test_results = {}
                after_state = {}
                for sta in sorted(stations):
                    test_results[sta] = {
                        "before_bssid": before_bssid.get(sta),
                        "before_channel": before_chan.get(sta),
                        "before_rssi": before_rssi.get(sta),
                        "after_bssid": after_bssid.get(sta),
                        "after_channel": after_chan.get(sta),
                        "after_rssi": after_rssi.get(sta),
                        "client_mac": mac_dict.get(sta)
                    }

                for sta in sta_list_2:
                    after_state[sta] = {
                        "bssid": after_bssid.get(sta),
                        "channel": after_chan.get(sta),
                        "rssi": after_rssi.get(sta)
                    }

                allure.attach(
                    body=json.dumps(after_state, indent=4),
                    name="After Band Steering Station BSSID & Channel",
                    attachment_type=allure.attachment_type.JSON
                )
                allure.attach(
                    body=json.dumps(test_results, indent=4),
                    name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                    attachment_type=allure.attachment_type.JSON
                )

                functional_failures = []
                pcap_failures = []
                for sta in sta_list_2:
                    result = test_results.get(sta)
                    before_bssid = result.get("before_bssid")
                    after_bssid = result.get("after_bssid")
                    before_channel = result.get("before_channel")
                    after_channel = result.get("after_channel")
                    before_rssi = result.get("before_rssi")
                    after_rssi = result.get("after_rssi")

                    if before_bssid == after_bssid:
                        functional_failures.append({
                            "sta": sta,
                            "client_mac": result.get("client_mac"),
                            "reason": "BSSID did not change",
                            "before": before_bssid,
                            "after": after_bssid
                        })

                print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

                # Attach the station-radio mapping to allure for debugging
                allure.attach(
                    body=json.dumps(station_radio_map, indent=4),
                    name="Station-Radio Mapping",
                    attachment_type=allure.attachment_type.JSON
                )
                # Collect supplicant logs for each radio
                for radio, stations in station_radio_map.items():
                    if stations:
                        print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                        self.get_supplicant_logs(radio=str(radio), sta_list=stations)

                print("\nAnalysing Pcap")

                for sta in sta_list_2:
                    client_mac = test_results.get(sta).get("client_mac")

                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="band_steering",
                        show_events=True
                    )

                    allure.attach(
                        analysis["report_text"],
                        name=f"Band Steering Analysis {sta} - {client_mac}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"]
                        })

                all_pass = not functional_failures and not pcap_failures
                return all_pass, {
                    "functional_failures": functional_failures,
                    "pcap_failures": pcap_failures,
                    "per_client": test_results
                }

            else:
                return False, {"error": "Stations are not Pinging Each other"}

        elif test_type == "post_assoc":
            """
                Test Cases TC_BS_4 and TC_BS_5 Post-Association Steering

                Purpose:
                Validate post-association steering when the 2.4GHz/5Ghz band becomes overloaded.

                Test Flow:
                1. Connect STA1, STA2, STA3 to 2.4GHz/5Ghz
                2. Inject traffic to overload 2.4GHz/5Ghz
                3. Verify overload detection via syslog
                4. Move STA2 and STA3 closer to AP
                5. Stop traffic selectively

                Expected Results:
                - STA2 and STA3 are steered from 2.4GHz/5Ghz to 5GHz/2.4GHz
                - Syslog and sniffer confirm disassociation and reassociation
                - Traffic continuity is maintained
            """

            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 2),
                max_attenuation=test_config.get("max_attenuation", 40),
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- STA Creation --------------------
            sta_list_1 = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_1}")

            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=1, num_sta=2,
                radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_2}")

            sta_list = sta_list_1 + sta_list_2

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # -------------------- Start Sniffer --------------------
            # Start the Sniffer along with dummy client creation on 7996 radio
            band_steer.start_sniffer()

            # -------------------- Initial Attenuation --------------------
            # Initial Attenuation that to be applied as per test case
            # Steer_five means station that needed to be created on 2.4Ghz band.
            if band_steer.steer_type == 'steer_twog':
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 0, idx - 3)
                    band_steer.set_atten('1.1.3002', 0, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)

            else:
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 400, idx - 3)
                    band_steer.set_atten('1.1.3002', 400, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Station Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],  # "1.2.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="2GHz" if band_steer.steer_type == 'steer_fiveg' else "5GHz",
                option=None
            )
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="2GHz" if band_steer.steer_type == 'steer_fiveg' else "5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list_2:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if band_steer.steer_type == 'steer_fiveg':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )

                elif band_steer.steer_type == 'steer_twog':
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Ping Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if ping_status:
                band_steer.create_specific_cx(station_list=sta_list)
                band_steer.start_traffic_cx()

                # -------------------- Trigger Steering --------------------
                start_time, end_time = band_steer.start_band_steer_test_standard(
                    attenuator='1.1.3009', modules=[1, 2],
                    steer='fiveg' if band_steer.steer_type == 'steer_fiveg' else 'twog')

                # temporarily waiting for 2 mins
                time.sleep(120)

                print(f"[DEBUG] Start Time : {start_time}")
                print(f"[DEBUG] End Time : {end_time}")

                band_steer.stop_traffic_cx()

                allure.attach(
                    body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                    name="Layer3 Traffic Data",
                    attachment_type=allure.attachment_type.JSON
                )

                # Clean up traffic cross-connections
                band_steer.clean_traffic_cx()
                print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

                # -------------------- Validate Steering --------------------
                after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
                after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
                after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

                # -------------------- Attenuator State --------------------
                attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

                # -------------------- Stop Sniffer --------------------
                local_pcap = band_steer.stop_sniffer()

                try:
                    with open(local_pcap, "rb") as f:
                        allure.attach(
                            f.read(),
                            name="Band Steering Sniffer Capture",
                            attachment_type=allure.attachment_type.PCAP
                        )
                except Exception as e:
                    print("Allure attach failed:", e)

                stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

                test_results = {}
                after_state = {}
                for sta in sorted(stations):
                    test_results[sta] = {
                        "before_bssid": before_bssid.get(sta),
                        "before_channel": before_chan.get(sta),
                        "before_rssi": before_rssi.get(sta),
                        "after_bssid": after_bssid.get(sta),
                        "after_channel": after_chan.get(sta),
                        "after_rssi": after_rssi.get(sta),
                        "client_mac": mac_dict.get(sta)
                    }

                for sta in sta_list_2:
                    after_state[sta] = {
                        "bssid": after_bssid.get(sta),
                        "channel": after_chan.get(sta),
                        "rssi": after_rssi.get(sta)
                    }

                allure.attach(
                    body=json.dumps(after_state, indent=4),
                    name="After Band Steering Station BSSID & Channel",
                    attachment_type=allure.attachment_type.JSON
                )
                allure.attach(
                    body=json.dumps(test_results, indent=4),
                    name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                    attachment_type=allure.attachment_type.JSON
                )

                band_steer.stop_traffic_cx()

                allure.attach(
                    body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                    name="Layer3 Traffic Data",
                    attachment_type=allure.attachment_type.JSON
                )

                # Clean up traffic cross-connections
                band_steer.clean_traffic_cx()
                print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

                functional_failures = []
                pcap_failures = []

                for sta in sta_list_2:
                    result = test_results.get(sta)
                    before_bssid = result.get("before_bssid")
                    after_bssid = result.get("after_bssid")
                    before_channel = result.get("before_channel")
                    after_channel = result.get("after_channel")
                    before_rssi = result.get("before_rssi")
                    after_rssi = result.get("after_rssi")

                    if before_bssid == after_bssid:
                        functional_failures.append({
                            "sta": sta,
                            "client_mac": result.get("client_mac"),
                            "reason": "BSSID did not change",
                            "before": before_bssid,
                            "after": after_bssid
                        })

                print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

                # Attach the station-radio mapping to allure for debugging
                allure.attach(
                    body=json.dumps(station_radio_map, indent=4),
                    name="Station-Radio Mapping",
                    attachment_type=allure.attachment_type.JSON
                )
                # Collect supplicant logs for each radio
                for radio, stations in station_radio_map.items():
                    if stations:
                        print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                        self.get_supplicant_logs(radio=str(radio), sta_list=stations)

                print("\nAnalysing Pcap")

                for sta in sta_list:
                    client_mac = test_results.get(sta).get("client_mac")

                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="band_steering",
                        show_events=True
                    )

                    allure.attach(
                        analysis["report_text"],
                        name=f"Band Steering Analysis {sta} - {client_mac}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"]
                        })

                all_pass = not functional_failures and not pcap_failures
                return all_pass, {
                    "functional_failures": functional_failures,
                    "pcap_failures": pcap_failures,
                    "per_client": test_results
                }

            else:
                return False, {"error": "Stations are not Pinging Each other"}

        elif test_type == "neither_band_post_assoc":
            """
                Test Cases TC_BS_6  Neither 2.4GHz nor 5GHz Overloaded – Post-Association Steering

                Purpose:
                Ensure correct steering behavior when neither band is overloaded.

                Test Flow:
                1. Connect STA1, STA2 on 2.4GHz and STA3, STA4 on 5GHz
                2. Inject balanced traffic on both bands
                3. Move STA2 closer for strong 5GHz RSSI
                4. Move STA4 closer for strong 2.4GHz RSSI
                5. Stop traffic and observe behavior

                Expected Results:
                - STA2 steers to 5GHz
                - STA4 steers to 2.4GHz
                - Steering decisions match RSSI and policy
            """

            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 2),
                max_attenuation=test_config.get("max_attenuation", 40),
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 0, idx - 3)
                band_steer.set_atten('1.1.3002', 400, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Sniffer --------------------
            # Starting Sniffer Before creating stations with dummy client creation on 7996 radio
            band_steer.start_sniffer()

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- STA Creation --------------------
            # Connection of 2 clients to 2Ghz band as per test case
            sta_list_1 = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_1}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_1)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="2GHz",
                option=None
            )

            # Connection of 2 clients to 5Ghz band as per test case
            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=2, num_sta=2,
                radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_2}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_2)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],  # "1.2.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            sta_list = sta_list_1 + sta_list_2
            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)
            # track_station_creation(dict_all_radios_5g["be200_radios"][0], sta_list_3)

            # -------------------- Validate Initial Band --------------------
            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            # before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_1)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_1)
            for sta, ch in before_chan.items():
                ch = int(ch)
                if ch is None or ch not in range(1, 15):
                    pytest.fail(
                        f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                        f"Observed band: 5Ghz  (Channel {ch}) \n"
                        f"Expected band: 2.4Ghz"
                    )

            # before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            for sta, ch in before_chan.items():
                if ch is None or ch < 36:
                    pytest.fail(
                        f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                        f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                        f"Expected band: 5Ghz"
                    )

            before_bssid = band_steer.get_bssids(as_dict=True, station_list=[sta_list_1[-1]] + [sta_list_2[-1]])
            before_chan = band_steer.get_channel(as_dict=True, station_list=[sta_list_1[-1]] + [sta_list_2[-1]])
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=[sta_list_1[-1]] + [sta_list_2[-1]])

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in [sta_list_1[-1]] + [sta_list_2[-1]]:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if ping_status:

                band_steer.create_specific_cx(station_list=sta_list)
                band_steer.start_traffic_cx()

                # -------------------- Trigger Steering --------------------
                start_time, end_time = band_steer.start_band_steer_test_standard(
                    attenuator='1.1.3009', modules=[1, 2], steer='twog')

                print(f"[DEBUG] Start Time : {start_time}")
                print(f"[DEBUG] End Time : {end_time}")

                start_time, end_time = band_steer.start_band_steer_test_standard(
                    attenuator='1.1.3002', modules=[3, 4], steer='fiveg')

                print(f"[DEBUG] Start Time : {start_time}")
                print(f"[DEBUG] End Time : {end_time}")

                # waiting for 2 mins
                time.sleep(120)
                band_steer.stop_traffic_cx()

                allure.attach(
                    body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                    name="Layer3 Traffic Data",
                    attachment_type=allure.attachment_type.JSON
                )

                # Clean up traffic cross-connections
                band_steer.clean_traffic_cx()
                print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

                # -------------------- Validate Steering --------------------
                after_bssid = band_steer.get_bssids(as_dict=True, station_list=[sta_list_1[-1]] + [sta_list_2[-1]])
                after_chan = band_steer.get_channel(as_dict=True, station_list=[sta_list_1[-1]] + [sta_list_2[-1]])
                after_rssi = band_steer.get_rssi(as_dict=True, station_list=[sta_list_1[-1]] + [sta_list_2[-1]])

                # -------------------- Attenuator State --------------------
                attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

                # -------------------- Stop Sniffer --------------------
                try:
                    local_pcap = band_steer.stop_sniffer()
                    with open(local_pcap, "rb") as f:
                        allure.attach(
                            f.read(),
                            name="Band Steering Sniffer Capture",
                            attachment_type=allure.attachment_type.PCAP
                        )
                except Exception as e:
                    print("Allure attach failed:", e)

                stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

                test_results = {}
                after_state = {}
                for sta in sorted(stations):
                    test_results[sta] = {
                        "before_bssid": before_bssid.get(sta),
                        "before_channel": before_chan.get(sta),
                        "before_rssi": before_rssi.get(sta),
                        "after_bssid": after_bssid.get(sta),
                        "after_channel": after_chan.get(sta),
                        "after_rssi": after_rssi.get(sta),
                        "client_mac": mac_dict.get(sta)
                    }

                for sta in [sta_list_1[-1]] + [sta_list_2[-1]]:
                    after_state[sta] = {
                        "bssid": after_bssid.get(sta),
                        "channel": after_chan.get(sta),
                        "rssi": after_rssi.get(sta)
                    }

                print(f"[DEBUG] After Steer Station Info {after_state}")
                allure.attach(
                    body=json.dumps(after_state, indent=4),
                    name="After Band Steering Station BSSID & Channel",
                    attachment_type=allure.attachment_type.JSON
                )
                allure.attach(
                    body=json.dumps(test_results, indent=4),
                    name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                    attachment_type=allure.attachment_type.JSON
                )

                functional_failures = []
                pcap_failures = []

                for sta in [sta_list_1[-1]] + [sta_list_2[-1]]:
                    result = test_results.get(sta)
                    before_bssid = result.get("before_bssid")
                    after_bssid = result.get("after_bssid")
                    before_channel = result.get("before_channel")
                    after_channel = result.get("after_channel")
                    # before_rssi = result.get("before_rssi")
                    # after_rssi = result.get("after_rssi")

                    if before_bssid == after_bssid:
                        functional_failures.append({
                            "sta": sta,
                            "client_mac": result.get("client_mac"),
                            "reason": "BSSID did not change",
                            "before": before_bssid,
                            "after": after_bssid
                        })
                print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

                # Attach the station-radio mapping to allure for debugging
                allure.attach(
                    body=json.dumps(station_radio_map, indent=4),
                    name="Station-Radio Mapping",
                    attachment_type=allure.attachment_type.JSON
                )
                # Collect supplicant logs for each radio
                for radio, stations in station_radio_map.items():
                    if stations:
                        print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                        self.get_supplicant_logs(radio=str(radio), sta_list=stations)

                print("\nAnalysing Pcap")

                for sta in sta_list:
                    client_mac = test_results.get(sta).get("client_mac")

                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="band_steering",
                        show_events=True
                    )

                    allure.attach(
                        analysis["report_text"],
                        name=f"Band Steering Analysis {sta} - {client_mac}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"]
                        })

                all_pass = not functional_failures and not pcap_failures
                return all_pass, {
                    "functional_failures": functional_failures,
                    "pcap_failures": pcap_failures,
                    "per_client": test_results
                }
            else:
                return False, {"error": "Stations are not Pinging Each other"}

        elif test_type == "stickiness":
            """
                Test Case: TC_BS_7 Band Steering Stickiness (Ping-Pong Avoidance)

                Purpose:
                Ensure clients do not oscillate between bands during the steering prohibit timer.

                Test Flow:
                1. Connect STA1, STA2 to 2.4GHz and STA3 to 5GHz
                2. Overload 2.4GHz and steer STA2 to 5GHz
                3. Stop traffic and normalize load
                4. Repeat steering cycle multiple times

                Expected Results:
                - STA2 remains on 5GHz until prohibit timer expires
                - No unnecessary band bouncing occurs
                - Syslog shows prohibit timer enforcement
            """

            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", "1.1.3002"),
                set_max_attenuators=test_config.get("set_max_attenuators"),
                step=test_config.get("step", 2),
                max_attenuation=test_config.get("max_attenuation", 40),
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            overall_status = "PASS"
            iteration_results = {}

            def record_failure(iteration, reason):
                """
                    Record a failure for a specific test iteration and update overall test status.

                    This helper function:
                    - Marks the overall test result as FAIL when any iteration fails
                    - Creates or updates an iteration-specific result entry
                    - Tracks one or more failure reasons per iteration for debugging and reporting

                    Args:
                        iteration (int): Iteration number in which the failure occurred
                        reason (str): Human-readable explanation describing the failure condition
                    """
                nonlocal overall_status
                overall_status = "FAIL"
                key = f"iteration_{iteration}"
                iteration_results.setdefault(key, {"status": "FAIL", "reasons": [], "results": {}})
                iteration_results[key]["status"] = "FAIL"
                iteration_results[key]["reasons"].append(reason)

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- Initial Attenuation --------------------
            for idx in range(3, 5):
                band_steer.set_atten("1.1.3009", 0, idx - 3)
                band_steer.set_atten("1.1.3002", 400, idx - 1)
                band_steer.set_atten("1.1.3002", 0, idx - 3)

            band_steer.start_sniffer()
            # get_target_object.dut_library_object.control_radio_band(band="5g", action="down")

            # -------------------- STA Creation --------------------
            sta_list_1 = band_steer.get_sta_list_before_creation(
                start_id=0, num_sta=2, radio=dict_all_radios_5g["mtk_radios"][0]
            )  # STA1 →  2.4G

            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=2, num_sta=1, radio=dict_all_radios_5g["mtk_radios"][1]
            )  # STA3 → 5G

            sta_list = sta_list_1 + sta_list_2
            band_steer.pre_cleanup(sta_list)

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid, passwd=passkey, security=security,
                station_list=sta_list_1, initial_band_pref="2GHz",
                station_flag="use-bss-transition", sta_type="normal"
            )

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],
                ssid=ssid, passwd=passkey, security=security,
                station_list=sta_list_2, initial_band_pref="5GHz",
                station_flag="use-bss-transition", sta_type="normal"
            )

            band_steer.station_list = sta_list

            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_1)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_1)
            for sta, ch in before_chan.items():
                ch = int(ch)
                if ch is None or ch not in range(1, 15):
                    pytest.fail(
                        f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                        f"Observed band: 5Ghz  (Channel {ch}) \n"
                        f"Expected band: 2.4Ghz"
                    )

            # before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            for sta, ch in before_chan.items():
                if ch is None or ch < 36:
                    pytest.fail(
                        f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                        f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                        f"Expected band: 5Ghz"
                    )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")

            if not ping_status:
                pytest.fail(f"[FAILED] {ping_status} Stations are not pinging each other")

            # -------------------- ITERATIONS --------------------
            for iteration in range(1, 6):
                print(f"\n===== ITERATION {iteration} START =====")
                test_results = {}

                # ---------- TRAFFIC + STEERING ----------
                band_steer.create_specific_cx(station_list=sta_list_1)
                band_steer.start_traffic_cx()

                # -------------------- Attenuator State --------------------
                attach_attenuator_state(band_steer, title=f"Attenuator State - Before Steering Iteration {iteration}")

                # -------------------- Attenuation Change --------------------
                band_steer.start_band_steer_test_standard(
                    attenuator="1.1.3002", modules=[3, 4], steer="fiveg"
                )
                time.sleep(120)

                # -------------------- Attenuator State --------------------
                attach_attenuator_state(band_steer, title=f"Attenuator State - After Steering Iteartino {iteration}")

                band_steer.stop_traffic_cx()
                allure.attach(
                    body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                    name=f"Layer3 Traffic-1 Data iteration {iteration}",
                    attachment_type=allure.attachment_type.JSON
                )

                # Clean up traffic cross-connections
                band_steer.clean_traffic_cx()
                print(f"[DEBUG] Traffic-1 data : {band_steer.traffic_cx_profile.traffic_data}")

                # ---------- VERIFY STA2 STEERED TO 5G ----------
                sta2 = sta_list_2[0]
                ch = int(band_steer.get_channel(as_dict=True, station_list=[sta2]).get(sta2, 0))
                if ch < 36:
                    record_failure(iteration, f"{sta2} did not steer to 5GHz (channel={ch})")

                # ---------- VERIFY STICKINESS ----------
                bounced = False
                for _ in range(10):
                    ch = int(band_steer.get_channel(as_dict=True, station_list=[sta2]).get(sta2, 0))
                    if 1 <= ch <= 14:
                        bounced = True
                        break
                    time.sleep(5)

                if bounced:
                    record_failure(iteration, f"{sta2} bounced back to 2.4GHz during prohibit timer")

                band_steer.create_specific_cx(station_list=[sta_list_1[-1]] + sta_list_2)
                band_steer.start_traffic_cx()

                # ---------- RESULTS ----------
                after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
                after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)

                for sta in sta_list:
                    test_results[sta] = {
                        "before_channel": before_chan.get(sta),
                        "after_channel": after_chan.get(sta),
                        "after_bssid": after_bssid.get(sta),
                    }

                key = f"iteration_{iteration}"
                if key not in iteration_results:
                    iteration_results[key] = {"status": "PASS", "reasons": [], "results": test_results}
                else:
                    iteration_results[key]["results"] = test_results

                allure.attach(
                    json.dumps(iteration_results[key], indent=4),
                    f"Iteration {iteration} Summary",
                    allure.attachment_type.JSON,
                )

                band_steer.stop_traffic_cx()
                allure.attach(
                    body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                    name=f"Layer3 Traffic-2 Data iteration {iteration}",
                    attachment_type=allure.attachment_type.JSON
                )

                # Clean up traffic cross-connections
                band_steer.clean_traffic_cx()
                print(f"[DEBUG] Traffic-2 data : {band_steer.traffic_cx_profile.traffic_data}")

            # -------------------- Stop Sniffer --------------------
            try:
                local_pcap = band_steer.stop_sniffer()
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Band Steering Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            allure.attach(
                json.dumps(iteration_results, indent=4),
                "Stickiness Test Summary",
                allure.attachment_type.JSON,
            )
            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            passed_count = sum(1 for r in iteration_results.values() if r.get("status") == "PASS")
            failed_count = sum(1 for r in iteration_results.values() if r.get("status") != "PASS")

            return overall_status, {
                "summary": {
                    "total_iterations": len(iteration_results),
                    "passed_iterations": passed_count,
                    "failed_iterations": failed_count
                },
                "iteration_results": iteration_results
            }

        elif test_type == "steer_success_rate":
            """
                Test Cases TC_BS_8 Band Steering Success Rate

                Purpose:
                Validate steering reliability by measuring success rate across multiple iterations.

                Test Flow:
                1. Connect STA1, STA2 to 2.4GHz and STA3 to 5GHz
                2. Overload 2.4GHz and steer STA2 to 5GHz
                3. Overload 5GHz and steer STA2 back to 2.4GHz
                4. Repeat the cycle six times

                Expected Results:
                - Steering occurs correctly in both directions
                - Minimum success rate of 5 out of 6 iterations
            """
            # Initialize BandSteer object
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,  # Should be 3 for this test
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 2),
                max_attenuation=test_config.get("max_attenuation", 40),
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # ---------- Initial Attenuation ----------
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 0, idx - 3)
                band_steer.set_atten('1.1.3002', 400, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # Track success count across iterations
            success_count = 0
            total_iterations = 6
            all_iteration_results = []

            # Start sniffer
            band_steer.start_sniffer()

            # Create STA1 (2.4GHz) - using first radio
            sta_list_1 = band_steer.get_sta_list_before_creation(
                start_id=0, num_sta=2, radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"

            # station pre-cleanup before creation
            band_steer.pre_cleanup(sta_list_1)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="2GHz",
                option=None
            )

            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=2, num_sta=1, radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"

            # station pre-cleanup before creation
            band_steer.pre_cleanup(sta_list_2)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],  # "1.2.wiphy1"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            # Combine all station lists
            sta_list = sta_list_1 + sta_list_2
            band_steer.station_list = sta_list

            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name=f"Station IPs ",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Verify Initial Connections --------------------
            # Verify STA1 and STA2 are on 2.4GHz
            sta_channels = band_steer.get_channel(as_dict=True, station_list=sta_list_1)
            for sta, channel in sta_channels.items():
                channel_int = int(channel)
                if channel_int >= 36:  # Not 2.4GHz
                    pytest.fail(f"[FAILED] {sta} not on 2.4GHz initially. Channel: {channel}")
            print(f"STA1 and STA2 on 2.4GHz (Channels: {sta_channels})")

            # Verify STA3 is on 5GHz
            sta2_channel = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            for sta, channel in sta2_channel.items():
                channel_int = int(channel)
                if channel_int < 36:  # Not 5GHz
                    pytest.fail(f"[FAILED] {sta} not on 5GHz initially. Channel: {channel}")
            print(f"STA3 on 5GHz (Channel: {sta2_channel})")

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")

            if not ping_status:
                return False, {"error": "Stations are not Pinging Each other"}

            for iteration in range(1, total_iterations + 1):
                print(f"\n{'=' * 60}")
                print(f"Starting Iteration {iteration}/{total_iterations}")
                print(f"{'=' * 60}")

                iteration_result = {
                    'iteration': iteration,
                    'sta2_steer_to_5g': False,
                    'sta2_steer_to_2g': False,
                    'passed': False
                }

                try:
                    # ========== STEP 5: Overload 2.4GHz Band ==========
                    print(f"\n[Iteration {iteration}] Overloading 2.4GHz band")

                    # Create traffic from AP to STA1 and STA2 (2.4GHz clients)
                    band_steer.create_specific_cx(station_list=sta_list_1)
                    band_steer.start_traffic_cx()

                    # ========== STEP 7: Move STA2 Close to AP (Strong 5GHz Signal) ==========
                    print(f"\n[Iteration {iteration}] Moving STA2 close to AP")
                    start_time, end_time = band_steer.start_band_steer_test_standard(
                        attenuator='1.1.3002', modules=[3, 4], steer='fiveg')

                    print(f"[DEBUG] Start Time {start_time}")
                    print(f"[DEBUG] End Time {end_time}")

                    # Record if STA2 steered to 5GHz
                    sta2_after_first_move = band_steer.get_channel(as_dict=True, station_list=[sta_list_1[-1]])
                    for sta, channel in sta2_after_first_move.items():
                        if int(channel) >= 36:  # Now on 5GHz
                            print(f"STA2 steered to 5GHz (Channel: {channel})")
                            iteration_result['sta2_steer_to_5g'] = True
                        else:
                            iteration_result['sta2_steer_to_5g'] = False
                            print(f"STA2 still on 2.4GHz (Channel: {channel})")

                    # -------------------- Attenuator State --------------------
                    attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

                    # ========== STEP 8: Stop Traffic to STA2 ==========
                    print(f"\n[Iteration {iteration}] Step 12: Stopping all traffic...")
                    band_steer.stop_traffic_cx()

                    allure.attach(
                        body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                        name="Layer3 Traffic-1 Data",
                        attachment_type=allure.attachment_type.JSON
                    )

                    # Clean up traffic cross-connections
                    band_steer.clean_traffic_cx()
                    print(f"[DEBUG] Traffic-1 data : {band_steer.traffic_cx_profile.traffic_data}")

                    time.sleep(20)  # wait for station to connect

                    sta2_before_steer = band_steer.get_channel(as_dict=True, station_list=[sta_list_1[-1]])
                    print(f"STA2 current channel: {sta2_before_steer}")
                    for sta, ch in sta2_before_steer.items():
                        if int(ch) < 36:
                            pytest.fail(
                                f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                                f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                                f"Expected band: 5Ghz"
                            )

                    # ========== STEP 9: Overload 5GHz Band ==========
                    print(f"\n[Iteration {iteration}] Step 9: Overloading 5GHz band...")

                    # Create traffic from AP to STA2 and STA3 (both should be on 5GHz now)
                    band_steer.create_specific_cx(station_list=sta_list_1 + sta_list_2)
                    band_steer.start_traffic_cx()

                    # ========== STEP 11: Move STA2 Away from AP (Strong 2.4GHz Signal) ==========
                    print(f"\n[Iteration {iteration}] Step 11: Moving STA2 away from AP...")

                    start_time, end_time = band_steer.start_band_steer_test_standard(
                        attenuator='1.1.3002', modules=[3, 4], steer='twog')

                    print(f"[DEBUG] Start Time {start_time}")
                    print(f"[DEBUG] End Time {end_time}")

                    # ========== STEP 12: Stop Traffic to STA2 ==========
                    print(f"\n[Iteration {iteration}] Step 12: Stopping all traffic...")
                    band_steer.stop_traffic_cx()

                    allure.attach(
                        body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                        name="Layer3 Traffic-2 Data",
                        attachment_type=allure.attachment_type.JSON
                    )

                    # Clean up traffic cross-connections
                    band_steer.clean_traffic_cx()
                    print(f"[DEBUG] Traffic-2 data : {band_steer.traffic_cx_profile.traffic_data}")

                    # ========== STEP 13: Check Final State ==========
                    print(f"\n[Iteration {iteration}] Step 13: Checking final state...")

                    sta2_final = band_steer.get_channel(as_dict=True, station_list=[sta_list_1[-1]])
                    for sta, channel in sta2_final.items():
                        if int(channel) < 36:  # Back to 2.4GHz
                            print(f"STA2 steered back to 2.4GHz (Channel: {channel})")
                            iteration_result['sta2_steer_to_2g'] = True
                        else:
                            iteration_result['sta2_steer_to_2g'] = False
                            print(f"STA2 still on 5GHz (Channel: {channel})")

                    # ========== Determine Iteration Success ==========
                    if iteration_result['sta2_steer_to_5g'] and iteration_result['sta2_steer_to_2g']:
                        success_count += 1
                        iteration_result['passed'] = True
                        print(f"Iteration {iteration} PASSED")
                    else:
                        print(f"Iteration {iteration} FAILED")

                    allure.attach(
                        body=json.dumps(iteration_result, indent=4),
                        name=f"Iteration {iteration} test results",
                        attachment_type=allure.attachment_type.JSON
                    )

                    all_iteration_results.append(iteration_result)

                    # ========== Cleanup for Next Iteration ==========
                    print(f"\n[Iteration {iteration}] Cleaning up...")
                    band_steer.pre_cleanup(sta_list)
                    time.sleep(5)

                except Exception as e:
                    print(f"\n[ERROR] Iteration {iteration} failed with exception: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    iteration_result['passed'] = False
                    iteration_result['error'] = e
                    all_iteration_results.append(iteration_result)

            # Stop sniffer and save capture
            pcap_file = band_steer.stop_sniffer()
            if pcap_file:
                try:
                    with open(pcap_file, "rb") as f:
                        allure.attach(
                            f.read(),
                            name=f"Band_Steering_Iteration",
                            attachment_type=allure.attachment_type.PCAP
                        )
                except Exception as e:
                    print(f"Warning: Could not attach pcap {e}")

            # ========== FINAL RESULTS AND SUCCESS RATE CALCULATION ==========
            print(f"\n{'=' * 60}")
            print("TEST COMPLETE - SUMMARY")
            print(f"{'=' * 60}")

            print(f"\nStarting band steering test...")
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)
            after_state = {}

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info")
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # Display iteration results
            for result in all_iteration_results:
                status = "PASS" if result.get('passed', False) else "FAIL"
                error = result.get('error', '')
                print(f"Iteration {result['iteration']}: {status} "
                      f"(2.4G->5G: {result['sta2_steer_to_5g']}, "
                      f"5G->2.4G: {result['sta2_steer_to_2g']}) {error}")

            # Calculate success rate
            success_rate = success_count / total_iterations
            print(f"\nSuccess Count: {success_count}/{total_iterations}")
            print(f"Success Rate: {success_rate:.2%}")

            # Attach summary to allure
            summary_text = f"Band Steering Success Rate Test\n"
            summary_text += f"Total Iterations: {total_iterations}\n"
            summary_text += f"Successful Iterations: {success_count}\n"
            summary_text += f"Success Rate: {success_rate:.2%}\n"
            summary_text += f"Required Success Rate: ≥{5 / 6:.2%}\n\n"

            for result in all_iteration_results:
                summary_text += f"Iteration {result['iteration']}: "
                summary_text += f"2.4G->5G: {result['sta2_steer_to_5g']}, "
                summary_text += f"5G->2.4G: {result['sta2_steer_to_2g']}, "
                summary_text += f"Status: {'PASS' if result.get('passed', False) else 'FAIL'}\n"

            allure.attach(
                summary_text,
                name="Band Steering Success Rate Summary",
                attachment_type=allure.attachment_type.TEXT
            )

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            # Final assertion based on expected output
            if success_count >= 5:
                print(f"\n✓ TEST PASSED: Success rate {success_count}/{total_iterations} ≥ 5/6")
                return True, {
                    'success_count': success_count,
                    'total_iterations': total_iterations,
                    'success_rate': success_rate,
                    'iteration_details': all_iteration_results
                }
            else:
                print(f"\n✗ TEST FAILED: Success rate {success_count}/{total_iterations} < 5/6")
                pytest.fail(
                    f"Band steering success rate insufficient: {success_count}/{total_iterations} (required ≥5/6)")

        elif test_type == "performance":
            """
                Test Cases TC_BS_9 Band Steering Performance Improvement

                Purpose:
                Verify throughput improvement after band steering under congestion.

                Test Flow:
                1. Connect multiple STAs to 5GHz
                2. Overload 5GHz with traffic
                3. Steer selected clients to 2.4GHz
                4. Measure throughput before and after steering

                Expected Results:
                - Clients are redistributed across bands
                - Throughput improves after steering
                - Traffic remains stable during transition
            """

            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 2),
                max_attenuation=test_config.get("max_attenuation", 40),
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # ---------- Initial Attenuation ----------
            for idx in range(3, 5):
                band_steer.set_atten("1.1.3009", 0, idx - 3)
                band_steer.set_atten("1.1.3002", 0, idx - 1)
                band_steer.set_atten("1.1.3002", 0, idx - 3)

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # Starting Sniffer Before creating stations with dummy client creation on 7996 radio
            band_steer.start_sniffer()

            # ---------- STA CREATION ----------
            # Connection of 1 client to 5Ghz band as per test case
            sta_list_1 = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_1}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_1)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            # Connection of 4 client to 5Ghz band as per test case
            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=1, num_sta=4,
                radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_2}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_2)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],  # "1.2.wiphy0",
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            sta_list = sta_list_1 + sta_list_2

            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            # ---------- VERIFY INITIAL BANDS ----------
            before_chan_5g = band_steer.get_channel(as_dict=True, station_list=sta_list)
            for sta, ch in before_chan_5g.items():
                if int(ch) < 36:
                    pytest.fail(
                        f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                        f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                        f"Expected band: 5Ghz"
                    )
            before_state = {}
            for sta in sta_list_2:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Initial phase Station info",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if not ping_status:
                return False, {"error": "Stations are not Pinging Each other"}

            band_steer.create_specific_cx(station_list=sta_list_1)
            band_steer.start_traffic_cx()

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list_2)
            band_steer.start_ping_cx()

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.start_band_steer_test_standard(
                attenuator='1.1.3009', modules=[1, 2], steer='twog')

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Ping Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            for station in sta_list_2:
                band_steer.admin_down(station)

            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 0, idx - 3)

            band_steer.create_specific_cx(station_list=sta_list_1, pairs=3)
            band_steer.start_traffic_cx()
            time.sleep(30)
            band_steer.stop_traffic_cx()

            allure.attach(
                body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                name="Layer3 Traffic-2 Data from AP to STA1 Iteration-1",
                attachment_type=allure.attachment_type.JSON
            )

            # Clean up traffic cross-connections
            band_steer.clean_traffic_cx()
            print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

            with allure.step("Record throughput values before reassociation"):
                snapshot_before = band_steer.get_throughput_snapshot(
                    label="Before STA reassociation"
                )

                allure.attach(
                    snapshot_before,
                    name="Throughput Before Reassociation",
                    attachment_type=allure.attachment_type.TEXT
                )

            for station in sta_list_2:
                band_steer.admin_up(station)

            band_steer.create_specific_cx(station_list=sta_list_1, pairs=3)
            band_steer.start_traffic_cx()
            time.sleep(30)
            band_steer.stop_traffic_cx()

            allure.attach(
                body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                name="Layer3 Traffic-2 Data from AP to STA1 Iteration-2",
                attachment_type=allure.attachment_type.JSON
            )

            # Clean up traffic cross-connections
            band_steer.clean_traffic_cx()
            print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            print(f"\n{'=' * 60}")
            print("Evaluating test results...")
            print(test_results)
            print(f"\n{'=' * 60}")

            for sta in sta_list_2:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            for _, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                # if before_bssid == after_bssid and before_channel == after_channel:
                #     return False, f'BSSID and Channel did not change after attenuation, before steer rssi {before_rssi} and after steer rssi {after_rssi}'
                #
                # if before_bssid == after_bssid:
                #     return False, f'BSSID did not change after attenuation, before steer rssi {before_rssi} and after steer rssi {after_rssi}'
                #
                # if before_channel == after_channel:
                #     return False, f'Channel did not change after attenuation, before steer rssi {before_rssi} and after steer rssi {after_rssi}'

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Band Steering Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            return True, test_results

        elif test_type == "vlan_standard":
            """
                Test Cases:
                    TC_BS_15 – Band Steering with DATA VLAN (2.4GHz → 5GHz)
                    TC_BS_16 – Band Steering with DATA VLAN (5GHz → 2.4GHz)

                Purpose:
                    Validate band steering functionality when SSID is configured with
                    Data VLAN enabled, ensuring seamless client transition between
                    2.4GHz and 5GHz bands while maintaining VLAN assignment and connectivity.

                Test Flow:
                    1. Login to the AP.
                    2. Navigate to Home → Sliding Menu → Sites → Select Site → SSIDs.
                    3. Configure SSID with:
                       - Security: WPA2 / WPA3 / WPA (as required)
                       - Radio Type: All
                       - Data VLAN: Enabled
                    4. Enable Band Steering and configure:
                       - Down-steering RSSI threshold
                       - Up-steering RSSI threshold
                       (Refer to dataset for values)
                    5. Save configuration.
                    6. Connect a client to the AP:
                       - For TC_BS_15: Ensure client initially connects to 2.4GHz.
                       - For TC_BS_16: Ensure client initially connects to 5GHz.
                    7. Verify:
                       - Client receives correct VLAN IP address.
                       - Client connectivity is stable.
                       - Associated interface (2G/5G) via CLI or GUI.
                    8. Change client position (near/far from AP) to trigger steering
                       between 2.4GHz and 5GHz.
                    9. Verify client transitions to target band.

                Expected Results:
                    - User can successfully login and configure VLAN-enabled SSID.
                    - Client connects with correct VLAN-assigned IP address.
                    - Band steering successfully moves client between 2.4GHz and 5GHz.
                    - Client is disassociated from original band and reassociated to target band.
                    - VLAN tagging remains intact after steering.
                    - Client connectivity remains uninterrupted during transition.
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][1],  # "1.1.wiphy1"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- QVLAN Creation --------------------
            vlan_id = 100
            self.add_vlan(vlan_ids=[vlan_id], build=True)

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- STA Creation --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=num_sta,
                radio=dict_all_radios_5g["mtk_radios"][1])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- Initial Conditions --------------------
            if band_steer.steer_type == 'steer_twog':
                for idx in range(3, 5):
                    band_steer.set_atten("1.1.3009", 0, idx - 3)
                    band_steer.set_atten("1.1.3002", 0, idx - 1)
                    band_steer.set_atten("1.1.3002", 0, idx - 3)
            else:
                for idx in range(3, 5):
                    band_steer.set_atten("1.1.3009", 400, idx - 3)
                    band_steer.set_atten("1.1.3002", 0, idx - 1)
                    band_steer.set_atten("1.1.3002", 0, idx - 3)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info {before_state}")

            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if band_steer.steer_type == 'steer_fiveg':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )

                elif band_steer.steer_type == 'steer_twog':
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.start_band_steer_test_standard(
                attenuator='1.1.3009', modules=[1, 2],
                steer='fiveg' if band_steer.steer_type == 'steer_fiveg' else 'twog')

            # temporarily waiting for 2 mins
            time.sleep(120)

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Band Steering Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta in sta_list:
                result = test_results.get(sta)
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE Steer RSSI {before_rssi}")
                print(f"[DEBUG] AFTER Steer RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })
            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            print("\nAnalysing Pcap")

            for sta in sta_list:
                client_mac = test_results.get(sta).get("client_mac")

                analysis = self.analyze_sniffer_pcap(
                    pcap_path=local_pcap,
                    client_mac=client_mac,
                    mode="band_steering",
                    show_events=True
                )

                allure.attach(
                    analysis["report_text"],
                    name=f"Band Steering Analysis {sta} - {client_mac}",
                    attachment_type=allure.attachment_type.TEXT
                )

                if not analysis["pass_status"]:
                    pcap_failures.append({
                        "sta": sta,
                        "client_mac": client_mac,
                        "reason": analysis["result"]
                    })

            all_pass = not functional_failures and not pcap_failures
            return all_pass, {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results
            }

        elif test_type == "client_isolation":
            """
                Test Case TC_BS_18 – Band Steering with Client Isolation Enabled

                Purpose:
                    Validate band steering functionality when Client Isolation is enabled
                    on a VLAN-configured SSID, ensuring clients are successfully steered
                    between 2.4GHz and 5GHz bands while maintaining isolation (no
                    inter-client communication).

                Test Flow:
                    1. Login to the AP.
                    2. Navigate to Home → Sliding Menu → Sites → Select Site → SSIDs.
                    3. Configure SSID with:
                       - Security: WPA2 / WPA3 / WPA (as required)
                       - Radio Type: All
                       - Data VLAN: Enabled
                       - Client Isolation: Enabled
                    4. Enable Band Steering and configure:
                       - Down-steering RSSI threshold
                       - Up-steering RSSI threshold
                       (Refer to dataset for values)
                    5. Save configuration.
                    6. Connect two clients to the AP:
                       - Initially connect both to 5GHz (or 2.4GHz for reverse validation).
                       - Verify both clients receive valid VLAN-assigned IP addresses.
                    7. Change client position (near/far from AP) to trigger band steering
                       from:
                       - 5GHz → 2.4GHz
                       - 2.4GHz → 5GHz
                    8. Throughout the steering process:
                       - Verify client connectivity to network.
                       - Attempt ping between the two clients continuously.
                    9. Repeat validation for both steering directions.

                Expected Results:
                    - User can successfully login and configure VLAN-enabled SSID
                      with Client Isolation and Band Steering enabled.
                    - Clients receive valid VLAN IP addresses.
                    - Band steering successfully moves clients between 5GHz and 2.4GHz.
                    - Clients are disassociated from original band and reassociated
                      to target band.
                    - Client-to-client communication (ping) is blocked at all times.
                    - Client isolation remains enforced before, during, and after steering.
                    - Network connectivity to gateway/external network remains stable.
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- QVLAN Creation --------------------
            vlan_id = 100
            self.add_vlan(vlan_ids=[vlan_id], build=True)

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- Initial Attenuation --------------------
            if band_steer.steer_type == 'steer_twog':
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 0, idx - 3)
                    band_steer.set_atten('1.1.3002', 0, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)
            else:
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 400, idx - 3)
                    band_steer.set_atten('1.1.3002', 0, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA Creation--------------------

            # Connection of 1 client to 5Ghz band as per test case
            sta_list_1 = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_1}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_1)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz" if band_steer.steer_type == "steer_twog" else "2Ghz",
                option=None
            )

            # Connection of 1 client to 5Ghz band as per test case
            sta_list_2 = band_steer.get_sta_list_before_creation(
                num_sta=1, start_id=1,
                radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_2}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_2)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],  # "1.2.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz" if band_steer.steer_type == "steer_twog" else "2Ghz",
                option=None
            )

            # wait for some time to associate the clients
            time.sleep(10)

            # Clean up if there are already existing station with same name
            sta_list = sta_list_1 + sta_list_2
            band_steer.station_list = sta_list

            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            # -------------------- Validate Initial Band --------------------
            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list_2:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if band_steer.steer_type == 'steer_fiveg':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )

                elif band_steer.steer_type == 'steer_twog':
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # --------------------- PING CHECK ----------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if ping_status:
                return False, 'Stations Pinging Each other even Client isolation is enabled.'

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.start_band_steer_test_standard(
                attenuator='1.1.3009', modules=[1, 2],
                steer='fiveg' if band_steer.steer_type == 'steer_fiveg' else 'twog')

            # temporarily waiting for 2 mins
            time.sleep(120)

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Band Steering Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list_2:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta in sta_list_2:
                result = test_results.get(sta)
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE Steer RSSI {before_rssi}")
                print(f"[DEBUG] AFTER Steer RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })
                print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )

            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            print("\nAnalysing Pcap")

            for sta in sta_list_2:
                client_mac = test_results.get(sta).get("client_mac")

                analysis = self.analyze_sniffer_pcap(
                    pcap_path=local_pcap,
                    client_mac=client_mac,
                    mode="band_steering",
                    show_events=True
                )

                allure.attach(
                    analysis["report_text"],
                    name=f"Band Steering Analysis {sta} - {client_mac}",
                    attachment_type=allure.attachment_type.TEXT
                )

                if not analysis["pass_status"]:
                    pcap_failures.append({
                        "sta": sta,
                        "client_mac": client_mac,
                        "reason": analysis["result"]
                    })

            all_pass = not functional_failures and not pcap_failures
            return all_pass, {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results
            }

        elif test_type == "UE":
            """
            Test Cases TC_BS_11 UE-Based Band Steering with EAP Security
            Purpose:
                Validate UE-based band steering functionality with Enterprise (EAP) security authentication.
            Test Flow:
                1. Configure local AAA server and AAA profile in the system
                2. Create SSID with Enterprise security and map to AAA server
                3. Enable band steering with configured thresholds
                4. Connect three wireless clients (STA1, STA2, STA3) to 2.4GHz band
                5. Verify connectivity via ping between all stations
                6. Overload 2.4GHz band by injecting traffic from AP to all three stations
                7. Verify AP detects 2.4GHz overload condition
                8. Move STA2 and STA3 closer to AP for strong 5GHz RSSI (above RSSISteeringPoint)
                9. Stop traffic to STA2 and verify steering to 5GHz via syslog and sniffer
                10. Stop traffic to STA3 and verify steering to 5GHz via syslog and sniffer
            Expected Results:
                - AAA server configuration and SSID mapping successful
                - All stations successfully connect to 2.4GHz band initially
                - Traffic injection and overload detection work correctly
                - STA2 disassociates from 2.4GHz and associates with 5GHz
                - STA3 disassociates from 2.4GHz and associates with 5GHz
                - Syslog confirms steering events and 5GHz associations
                - Sniffer traces show disconnection from 2.4GHz and connection to 5GHz
            """

            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 2),
                max_attenuation=test_config.get("max_attenuation", 40),
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 400, idx - 3)
                band_steer.set_atten('1.1.3002', 400, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- Start Sniffer --------------------
            # Starting Sniffer Before creating stations with dummy client creation on 7996 radio
            band_steer.start_sniffer()

            # -------------------- STA Creation --------------------
            # Connection of 2 clients to 2Ghz band as per test case
            sta_list_1 = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_1}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_1)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="enterprise",
                initial_band_pref="2GHz",
                option=None
            )

            # Connection of 1 client to 5Ghz band as per test case
            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=1, num_sta=2,
                radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"
            print(f"[DEBUG] Station List: {sta_list_2}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list_2)

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],  # "1.2.wiphy0"
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="enterprise",
                initial_band_pref="2GHz",
                option=None
            )

            sta_list = sta_list_1 + sta_list_2
            band_steer.station_list = sta_list

            # Attach Station IP map to allure report
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            # -------------------- Validate Initial Band --------------------
            # before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_1)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            for sta, ch in before_chan.items():
                ch = int(ch)
                if ch is None or ch not in range(1, 15):
                    pytest.fail(
                        f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                        f"Observed band: 5Ghz  (Channel {ch}) \n"
                        f"Expected band: 2.4Ghz"
                    )

            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list_2:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Ping Connectivity Check --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )
            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if ping_status:

                # ------------------------- Start TCP Traffic ------------------------
                band_steer.create_specific_cx(station_list=sta_list)
                band_steer.start_traffic_cx()

                start_time, end_time = band_steer.start_band_steer_test_standard(
                    attenuator='1.1.3009', modules=[1, 2], steer='fiveg')

                print(f"[DEBUG] Start Time : {start_time}")
                print(f"[DEBUG] End Time : {end_time}")

                # temporarily waiting for 2 mins
                time.sleep(120)

                band_steer.stop_traffic_cx()
                band_steer.clean_traffic_cx()

                # -------------------- Validate Steering --------------------
                after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
                after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
                after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

                # -------------------- Attenuator State --------------------
                attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

                # -------------------- Stop Sniffer --------------------\local_pcap = band_steer.stop_sniffer()
                local_pcap = band_steer.stop_sniffer()
                try:
                    with open(local_pcap, "rb") as f:
                        allure.attach(
                            f.read(),
                            name="Band Steering Sniffer Capture",
                            attachment_type=allure.attachment_type.PCAP
                        )
                except Exception as e:
                    print("Allure attach failed:", e)

                stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

                test_results = {}
                after_state = {}

                for sta in sorted(stations):
                    test_results[sta] = {
                        "before_bssid": before_bssid.get(sta),
                        "before_channel": before_chan.get(sta),
                        "before_rssi": before_rssi.get(sta),
                        "after_bssid": after_bssid.get(sta),
                        "after_channel": after_chan.get(sta),
                        "after_rssi": after_rssi.get(sta),
                        "client_mac": mac_dict.get(sta)
                    }
                for sta in sta_list_2:
                    after_state[sta] = {
                        "bssid": after_bssid.get(sta),
                        "channel": after_chan.get(sta),
                        "rssi": after_rssi.get(sta)
                    }

                print(f"[DEBUG] After Steer Station Info {after_state}")
                allure.attach(
                    body=json.dumps(after_state, indent=4),
                    name="After Band Steering Station BSSID & Channel",
                    attachment_type=allure.attachment_type.JSON
                )
                allure.attach(
                    body=json.dumps(test_results, indent=4),
                    name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                    attachment_type=allure.attachment_type.JSON
                )

                functional_failures = []
                pcap_failures = []
                for sta in sta_list_2:
                    result = test_results.get(sta)
                    before_bssid = result.get("before_bssid")
                    after_bssid = result.get("after_bssid")
                    before_channel = result.get("before_channel")
                    after_channel = result.get("after_channel")
                    before_rssi = result.get("before_rssi")
                    after_rssi = result.get("after_rssi")

                    print(f"[DEBUG] BEFORE Steer RSSI {before_rssi} Channel {before_channel}")
                    print(f"[DEBUG] AFTER Steer RSSI {after_rssi} Channel {after_channel}")

                    if before_bssid == after_bssid:
                        functional_failures.append({
                            "sta": sta,
                            "client_mac": result.get("client_mac"),
                            "reason": "BSSID did not change",
                            "before": before_bssid,
                            "after": after_bssid
                        })

                print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

                # Attach the station-radio mapping to allure for debugging
                allure.attach(
                    body=json.dumps(station_radio_map, indent=4),
                    name="Station-Radio Mapping",
                    attachment_type=allure.attachment_type.JSON
                )
                # Collect supplicant logs for each radio
                for radio, stations in station_radio_map.items():
                    if stations:
                        print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                        self.get_supplicant_logs(radio=str(radio), sta_list=stations)

                print("\nAnalysing Pcap")

                for sta in sta_list:
                    client_mac = test_results.get(sta).get("client_mac")

                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="band_steering",
                        show_events=True
                    )

                    allure.attach(
                        analysis["report_text"],
                        name=f"Band Steering Analysis {sta} - {client_mac}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"]
                        })

                all_pass = not functional_failures and not pcap_failures
                return all_pass, {
                    "functional_failures": functional_failures,
                    "pcap_failures": pcap_failures,
                    "per_client": test_results
                }

            else:
                return False, {"error": "Stations are not Pinging Each other"}

        elif test_type == "management_vlan_data_vlan_client_isolation":
            """
                Test Case TC_BS_17 Band Steering with Management VLAN, Data VLAN, and Client Isolation Enabled

                Purpose:
                    Validate band steering functionality when the AP is onboarded using
                    a Management VLAN and the SSID is configured with Data VLAN and
                    Client Isolation enabled. The test ensures successful steering
                    between 2.4GHz and 5GHz bands while maintaining VLAN separation,
                    management accessibility, and client isolation enforcement.

                Test Flow:
                    1. Onboard the AP using a Management VLAN.
                    2. Verify the AP is reachable and login to the AP via management IP.
                    3. Navigate to Home → Sliding Menu → Sites → Select Site → SSIDs.
                    4. Configure SSID with:
                       - Security: WPA2 / WPA3 / WPA (as required)
                       - Radio Type: All
                       - Data VLAN: Enabled
                       - Client Isolation: Enabled
                    5. Enable Band Steering and configure:
                       - Down-steering RSSI threshold
                       - Up-steering RSSI threshold
                       (Refer to dataset for values)
                    6. Save configuration.
                    7. Connect two clients to the SSID:
                       - Initially connect both clients to 5GHz (or 2.4GHz for reverse validation).
                       - Verify clients receive valid Data VLAN IP addresses.
                    8. Move clients closer/farther from the AP to trigger steering:
                       - 5GHz → 2.4GHz
                       - 2.4GHz → 5GHz
                    9. During steering:
                       - Verify client connectivity remains stable.
                       - Continuously attempt ping between clients to validate isolation.
                    10. Repeat validation for both steering directions.

                Expected Results:
                    - AP successfully operates on configured Management VLAN and remains accessible.
                    - User can login and configure SSID with Data VLAN, Client Isolation, and Band Steering.
                    - Clients receive correct IP addresses from Data VLAN (not Management VLAN).
                    - Band steering successfully moves clients between 2.4GHz and 5GHz.
                    - Clients are disassociated from original band and reassociated to target band.
                    - Client-to-client communication remains blocked at all times.
                    - Management VLAN remains unaffected during client steering.
                    - Network connectivity to gateway/external network remains stable.
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- Management VLAN Creation --------------------
            idx = 0
            qvlan_id = 100
            dut = get_target_object
            vlan_id = get_testbed_details["device_under_tests"][idx]["management_vlan"]
            self.add_vlan(vlan_ids=[vlan_id, qvlan_id], build=True)

            time.sleep(120)
            # -------------------- Management VLAN AP config --------------------
            dut.dut_library_object.attach_network_snapshot(idx, "Before DHCP VLAN")

            # ping_status = dut.dut_library_object.ping(
            #     "8.8.8.8",
            #     idx=idx,
            #     attach_name="Pre-Config(108) Internet Check"
            # )
            # if not ping_status:
            #     pytest.fail("Internet is not reachable before configuration push(108)")
            ret_val = dut.dut_library_object.verify_ap_connected_to_controller(idx=idx, attach_allure=False)
            if not ret_val:
                logging.error(" AP Went to Disconnected State after Applying Config, Checking again after 30 Seconds")
                time.sleep(60)
                ret_val = dut.dut_library_object.verify_ap_connected_to_controller(idx=idx,
                                                                                   attach_allure=False)
                if not ret_val:
                    pytest.fail("AP is in disconnected state from AMQP!!!")

                else:
                    logging.info("AP is in connected state to AMQP!!!")

            resp = dut.uprofile_utility_object.push_wan_dhcp_with_management_vlan(
                get_testbed_details, idx
            )
            if resp.status_code != 200:
                pytest.fail(f"HFCL push failed | status={resp.status_code} | body={resp.text}")
            logging.info("Waiting for 120s")
            time.sleep(120)

            dut.dut_library_object.attach_network_snapshot(idx, "After DHCP VLAN")
            dut.dut_library_object.validate_dhcp_with_management_vlan(idx, vlan_id)

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- STA Creation --------------------
            sta_list_1 = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])  # "1.1.wiphy0"

            sta_list_2 = band_steer.get_sta_list_before_creation(
                start_id=1, num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][1])  # "1.2.wiphy0"

            sta_list = sta_list_1 + sta_list_2

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list_1)
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list_2)

            print(f"[DEBUG] Station List: {sta_list}")
            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # -------------------- Initial Conditions --------------------
            if band_steer.steer_type == "steer_twog":
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3002', 0, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)
                    band_steer.set_atten('1.1.3009', 0, idx - 3)
            else:
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3002', 0, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)
                    band_steer.set_atten('1.1.3009', 400, idx - 3)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_1,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list_2,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            # Attach Station IP map to allure report
            band_steer.get_station_ips()

            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list_2:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if band_steer.steer_type == 'steer_fiveg':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )

                elif band_steer.steer_type == 'steer_twog':
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if ping_status:
                pytest.fail(f"[Status] {ping_status}: Station are pinging each other even Client Isolation is enabled")

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.start_band_steer_test_standard(
                attenuator='1.1.3009', modules=[1, 2],
                steer='twog' if band_steer.steer_type == "steer_twog" else 'fiveg')

            # temporarily waiting for 2 mins
            time.sleep(120)

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list_2)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list_2)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list_2)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Band Steering Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list_2:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )
            functional_failures = []
            pcap_failures = []
            for sta in sta_list_2:
                result = test_results.get(sta)
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE Steer RSSI {before_rssi}")
                print(f"[DEBUG] AFTER Steer RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })
            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            print("\nAnalysing Pcap")

            for sta in sta_list_2:
                client_mac = test_results.get(sta).get("client_mac")

                analysis = self.analyze_sniffer_pcap(
                    pcap_path=local_pcap,
                    client_mac=client_mac,
                    mode="band_steering",
                    show_events=True
                )

                allure.attach(
                    analysis["report_text"],
                    name=f"Band Steering Analysis {sta} - {client_mac}",
                    attachment_type=allure.attachment_type.TEXT
                )

                if not analysis["pass_status"]:
                    pcap_failures.append({
                        "sta": sta,
                        "client_mac": client_mac,
                        "reason": analysis["result"]
                    })

            all_pass = not functional_failures and not pcap_failures
            return all_pass, {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results
            }

        elif test_type == "standard_management_vlan":
            """
            Test case TC_BS_17 Standard Management VLAN with Band Steering

            Purpose:
                Verify that an AP configured with a Management VLAN allows client
                connectivity and supports band steering between 5 GHz and 2.4 GHz radios.

            Test Flow:
                1. Onboard the AP with Management VLAN.
                2. Verify Management VLAN connectivity and login to AP.
                3. Navigate to Home → Sites → Select Site → SSIDs.
                4. Configure SSID with:
                    - Security: WPA2/WPA3/WPA
                    - Radio Type: All
                5. Enable Band Steering.
                6. Configure Down steer and Up steer dBm values.
                7. Save the configuration.
                8. Connect one client (position client far to prefer 5 GHz).
                9. Verify client receives IP from native VLAN.
                10. Verify client is connected to 5 GHz radio (CLI and GUI).
                11. Move client near/far to trigger steering from 5 GHz to 2.4 GHz.

            Expected Results:
                - AP should successfully onboard with Management VLAN.
                - Management VLAN connectivity should work.
                - SSID should support WPA2/WPA/WPA3 security.
                - Client should connect successfully with Band Steering enabled.
                - Client should receive IP from native VLAN.
                - Client should initially associate to 5 GHz.
                - Client should disassociate from 5 GHz and reassociate to 2.4 GHz
                  when steering conditions are met.
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                steer_type=steer_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- Management VLAN Creation --------------------
            idx = 0
            dut = get_target_object
            vlan_id = get_testbed_details["device_under_tests"][idx]["management_vlan"]  # 200
            print('CREATING vlan 200')
            self.add_vlan(vlan_ids=[vlan_id], build=True)
            print('Created vlan 200')

            time.sleep(120)
            # -------------------- Management VLAN AP config --------------------

            dut.dut_library_object.attach_network_snapshot(idx, "Before DHCP VLAN")

            # ping_status = dut.dut_library_object.ping(
            #     "8.8.8.8",
            #     idx=idx,
            #     attach_name="Pre-Config(108) Internet Check"
            # )
            # if not ping_status:
            #     pytest.fail("Internet is not reachable before configuration push(108)")
            ret_val = dut.dut_library_object.verify_ap_connected_to_controller(idx=idx, attach_allure=False)
            if not ret_val:
                logging.error(" AP Went to Disconnected State after Applying Config, Checking again after 30 Seconds")
                time.sleep(60)
                ret_val = dut.dut_library_object.verify_ap_connected_to_controller(idx=idx,
                                                                                   attach_allure=False)
                if not ret_val:
                    pytest.fail("AP is in disconnected state from AMQP!!!")

                else:
                    logging.info("AP is in connected state to AMQP!!!")

            resp = dut.uprofile_utility_object.push_wan_dhcp_with_management_vlan(
                get_testbed_details, idx
            )
            if resp.status_code != 200:
                pytest.fail(f"HFCL push failed | status={resp.status_code} | body={resp.text}")
            logging.info("Waiting for 120s")
            time.sleep(120)

            dut.dut_library_object.attach_network_snapshot(idx, "After DHCP VLAN")
            dut.dut_library_object.validate_dhcp_with_management_vlan(idx, vlan_id)

            # -------------------- Initial Attenuation --------------------
            if band_steer.steer_type == 'steer_fiveg':
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 0, idx - 3)
                    band_steer.set_atten('1.1.3002', 0, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)
            else:
                band_steer.set_atten('1.1.3009', 400, idx - 3)
                band_steer.set_atten('1.1.3002', 0, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- SSID Scan results --------------------
            data_scan_ssid = self.scan_ssid(radio=dict_all_radios_5g["mtk_radios"][0], ssid=ssid)
            logging.info("ssid scan data: " + str(data_scan_ssid))

            # -------------------- STA Creation --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=num_sta,
                radio=dict_all_radios_5g["mtk_radios"][1])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][1], sta_list)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- Initial Conditions --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][1],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            # Attach Station IP map to allure report
            band_steer.get_station_ips()

            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Steering")

            print(f"\nStarting band steering test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before Steer Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if band_steer.steer_type == 'steer_fiveg':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before steering. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )

                elif band_steer.steer_type == 'steer_twog':
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before steering. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.start_band_steer_test_standard(
                attenuator='1.1.3009', modules=[1, 2],
                steer='fiveg' if band_steer.steer_type == 'steer_fiveg' else 'twog')

            # temporarily waiting for 2 mins
            time.sleep(120)

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Band Steering Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Band Steering Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )
            functional_failures = []
            pcap_failures = []
            for sta in sta_list:
                result = test_results.get(sta)
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE Steer RSSI {before_rssi}")
                print(f"[DEBUG] AFTER Steer RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })
            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            print("\nAnalysing Pcap")

            all_pass = not functional_failures and not pcap_failures
            for sta in sta_list:
                client_mac = test_results.get(sta).get("client_mac")

                analysis = self.analyze_sniffer_pcap(
                    pcap_path=local_pcap,
                    client_mac=client_mac,
                    mode="band_steering",
                    show_events=True
                )

                allure.attach(
                    analysis["report_text"],
                    name=f"Band Steering Analysis {sta} - {client_mac}",
                    attachment_type=allure.attachment_type.TEXT
                )

                if not analysis["pass_status"]:
                    pcap_failures.append({
                        "sta": sta,
                        "client_mac": client_mac,
                        "reason": analysis["result"]
                    })

            return all_pass, {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results
            }

    @staticmethod
    def build_ap_transition_summary(sta, before_state, after_state, current_AP1=True):
        lines = []
        lines.append("\nROAMING AP TRANSITION SUMMARY:")
        lines.append("=" * 60)

        before = before_state.get(sta, {})
        after = after_state.get(sta, {})

        lines.append(f"\nStation: {sta}")

        current_AP = 'AP1' if current_AP1 else 'AP2'
        target_AP = 'AP2' if current_AP1 else 'AP1'

        # Current AP
        lines.append(
            f"  Current {current_AP}  -> "
            f"BSSID: {before.get('bssid')} | "
            f"CH: {before.get('channel')} | "
            f"RSSI: {before.get('rssi')}"
        )

        # Target AP
        lines.append(
            f"  Target {target_AP}   -> "
            f"BSSID: {after.get('bssid')} | "
            f"CH: {after.get('channel')} | "
            f"RSSI: {after.get('rssi')}"
        )

        # Decision
        if before.get("bssid") != after.get("bssid"):
            lines.append("  Roam Status -> SUCCESS")
        else:
            lines.append("  Roam Status -> FAILED")

        lines.append("=" * 60)
        return "\n".join(lines)

    def start_hostapd_logging(self, get_target_object, testbed_details):
        """Start hostapd debug logging for all DUTs and save to files"""

        logging.info("Starting hostapd debug logging for all DUTs...")
        dut_count = len(testbed_details['device_under_tests'])

        for idx in range(dut_count):
            dut = get_target_object.dut_library_object

            try:
                logging.info(f"Starting hostapd logging for DUT index {idx}")

                # Use unique log file per DUT
                log_file = f"/tmp/hostapd_logs_dut{idx}.txt"

                # 1. Remove old logs
                dut.run_generic_command(
                    cmd=f"rm -f {log_file}",
                    idx=idx,
                    print_log=False,
                    attach_allure=False
                )

                # 2. Kill existing hostapd
                dut.run_generic_command(
                    cmd="killall hostapd",
                    idx=idx,
                    print_log=False,
                    attach_allure=False
                )

                # 3. Start hostapd in debug mode with DUT-specific log file
                dut.run_generic_command(
                    cmd=f"hostapd -g /var/run/hostapd/global -dddtK -f {log_file} -P /var/run/hostapd-global.pid &",
                    idx=idx,
                    print_log=False,
                    attach_allure=False
                )

                # 4. Bring Wifi back
                dut.run_generic_command(
                    cmd="wifi",
                    idx=idx,
                    print_log=False,
                    attach_allure=False
                )

                time.sleep(5)  # allow hostapd to stabilize

                # 5. Add start marker with DUT identifier
                identifier = testbed_details['device_under_tests'][idx].get('identifier', f'DUT_{idx}')
                dut.run_generic_command(
                    cmd=f'echo "========== HOSTAPD LOG START - {identifier} ==========" >> {log_file}',
                    idx=idx,
                    print_log=False,
                    attach_allure=False
                )

                logging.info(f"Hostapd logging started successfully for DUT index {idx}")

            except Exception as e:
                logging.error(f"Failed to start hostapd logging for DUT index {idx}: {e}")

    def stop_hostapd_logging(self, get_target_object, testbed_details):
        """Stop hostapd logging for all DUTs, fetch logs, and attach to Allure"""

        logging.info("Stopping hostapd logging and fetching logs for all DUTs...")
        dut_count = len(testbed_details['device_under_tests'])

        for idx in range(dut_count):
            dut = get_target_object.dut_library_object

            try:
                logging.info(f"Stopping hostapd logging for DUT index {idx}")

                log_file = f"/tmp/hostapd_logs_dut{idx}.txt"
                identifier = testbed_details['device_under_tests'][idx].get('identifier', f'DUT_{idx}')

                # 1. Add end marker
                dut.run_generic_command(
                    cmd=f'echo "========== HOSTAPD LOG END - {identifier} ==========" >> {log_file}',
                    idx=idx,
                    print_log=False,
                    attach_allure=False
                )

                # 2. Fetch logs
                logs = dut.run_generic_command(
                    cmd=f"cat {log_file}",
                    idx=idx,
                    print_log=False,
                    attach_allure=False
                )

                # 3. Attach to Allure with DUT identifier
                if logs and logs.strip():
                    allure.attach(
                        logs,
                        name=f"Hostapd Debug Logs - {identifier} - {idx}",
                        attachment_type=allure.attachment_type.TEXT
                    )
                    logging.info(f"Hostapd logs attached to Allure for DUT {identifier}")
                else:
                    logging.warning(f"Hostapd log file is empty for DUT {identifier}")

            except Exception as e:
                logging.error(f"Failed to fetch hostapd logs for DUT index {idx}: {e}")

    def run_roam_test(
            self,
            ssid,
            passkey,
            security,
            test_type,
            test_config,
            num_sta=1,
            roam_towards=None,
            steer_type=None,
            initial_band=None,
            get_testbed_details=None,
            get_target_object=None,
            setup_config=None
    ):
        dict_all_radios_2g = {"be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios, "ax200_radios": self.ax200_radios,
                              "mtk_radios": self.mtk_radios,
                              "wave2_2g_radios": self.wave2_2g_radios,
                              "wave1_radios": self.wave1_radios
                              }
        dict_all_radios_5g = {"be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios, "ax200_radios": self.ax200_radios,
                              "mtk_radios": self.mtk_radios,
                              "wave2_5g_radios": self.wave2_5g_radios,
                              "wave1_radios": self.wave1_radios
                              }

        station_radio_map = {}

        def attach_attenuator_state(band_steer, title="Attenuator State"):
            atten_info = band_steer.get_atten_info()

            if not atten_info:
                return

            allure.attach(
                body=json.dumps(atten_info, indent=4),
                name=title,
                attachment_type=allure.attachment_type.JSON
            )

        def track_station_creation(radio, station_list):
            """Track which stations were created on which radio."""
            if radio not in station_radio_map:
                station_radio_map[radio] = []
            station_radio_map[radio].extend(station_list)

        # 01
        if test_type == "test_enable_11k_from_canvas":
            """
            TC_K-V_01 : Test to Enable 802.11K feature from canvas
            """

            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=1,
                station_radio=test_config.get("station_radio", "1.1.wiphy0"),
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0]
            )
            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            time.sleep(60)

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            analysis = self.analyze_sniffer_pcap(
                pcap_path=local_pcap,
                bssid=test_config.get("bssid_5g"),  # Use AP's BSSID
                mode="11kr",
                bssid_list=bssid_list,
                show_events=True
            )
            allure.attach(
                json.dumps(analysis, indent=4),
                name="Roaming Sniffer Analysis",
                attachment_type=allure.attachment_type.JSON
            )

            allure.attach(
                analysis["report_text"],
                name=f"Roaming Summary",
                attachment_type=allure.attachment_type.TEXT
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "0",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )

            # Check results
            if analysis["pass_status"]:
                print(f"PASS: {analysis['result']}")
            else:
                print(f"FAIL: {analysis['result']}")
                print(f"Details: {analysis['details']}")

            return analysis["pass_status"], analysis

        # 02
        if test_type == "verify_action_frame_from_pcap":
            """
                TC_K-V_02 : Test to verify 802.11k feature action frame in wireshark
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- Initial Attenuation --------------------

            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Enable 802.11kvr --------------------
            # get_target_object.dut_library_object.configure_roaming_features(enable_11r=True,
            #                                                                 enable_11k=True,
            #                                                                 enable_11v=False)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Station MAC Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before roam Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Trigger Roaming --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Hostapd Log Capture --------------------

            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            test_results = {}
            after_state = {}

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition Summary",
                attachment_type=allure.attachment_type.TEXT
            )

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            for _, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    return False, 'BSSID/Channel are not matched after attenuation applied'

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )

            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            # With BSSID only

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            pcap_failures = []
            analysis = self.analyze_sniffer_pcap(
                pcap_path=local_pcap,
                bssid=test_config.get("bssid_5g"),  # Use AP's BSSID
                mode="11k_action",
                bssid_list=bssid_list,
                show_events=True
            )

            allure.attach(
                json.dumps(analysis, indent=4),
                name="Roaming Sniffer Analysis",
                attachment_type=allure.attachment_type.JSON
            )

            allure.attach(
                analysis["report_text"],
                name=f"Roaming Summary",
                attachment_type=allure.attachment_type.TEXT
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "0",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )

            if not analysis["pass_status"]:
                pcap_failures.append({
                    "bssid": test_config.get("bssid_5g"),
                    "reason": analysis["result"],
                    "details": analysis["details"]
                })

            all_pass = not pcap_failures
            # Check results
            if analysis["pass_status"]:
                print(f"PASS: {analysis['result']}")
            else:
                print(f"FAIL: {analysis['result']}")
                print(f"Details: {analysis['details']}")

            return all_pass, analysis

        # 03
        if test_type == "verify_bsst":
            """
                TC_K-V_03 : Enable the BSS Transition and verify the beacon
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            time.sleep(60)

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            # With BSSID only
            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            pcap_failures = []
            analysis = self.analyze_sniffer_pcap(
                pcap_path=local_pcap,
                bssid=test_config.get("bssid_5g"),  # Use AP's BSSID
                mode="11vr",
                bssid_list=bssid_list,
                show_events=True
            )
            allure.attach(
                json.dumps(analysis, indent=4),
                name="Roaming Sniffer Analysis",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                analysis["report_text"],
                name=f"Roaming Summary",
                attachment_type=allure.attachment_type.TEXT
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "0"
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            if not analysis["pass_status"]:
                pcap_failures.append({
                    "bssid": test_config.get("bssid_5g"),
                    "reason": analysis["result"],
                    "details": analysis["details"]
                })

            all_pass = not pcap_failures
            # Check results
            if analysis["pass_status"]:
                print(f"PASS: {analysis['result']}")
            else:
                print(f"FAIL: {analysis['result']}")
                print(f"Details: {analysis['details']}")

            return all_pass, analysis

        # 04
        if test_type == "verify_sniffer_pcap":
            """
                TC_K-V_04 : Verify the Load Balancing request—If an AP is heavily loaded, it sends out an 802.11v BSS Transition Management Request to an associated client.

            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- Initial Attenuation --------------------

            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=5,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before roam Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()
            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if not ping_status:
                pytest.fail(f"[Status] {ping_status}: Station are not pinging each other")

            print(f"[DEBUG] Starting TCP Traffic on station {sta_list}")
            band_steer.create_specific_cx(station_list=sta_list, tos='VO')
            band_steer.start_traffic_cx()

            # -------------------- Stop Traffic --------------------
            band_steer.stop_traffic_cx()
            allure.attach(
                body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                name="Layer3 Traffic Data from AP Iteration",
                attachment_type=allure.attachment_type.JSON
            )
            # Clean up traffic cross-connections
            band_steer.clean_traffic_cx()
            print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # With BSSID only
            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            pcap_failures = []
            analysis = self.analyze_sniffer_pcap(
                pcap_path=local_pcap,
                bssid=test_config.get("bssid_5g"),  # Use AP's BSSID
                mode="11vr",
                bssid_list=bssid_list,
                show_events=True
            )
            allure.attach(
                json.dumps(analysis, indent=4),
                name="Roaming Sniffer Analysis",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                analysis["report_text"],
                name=f"Roaming Summary",
                attachment_type=allure.attachment_type.TEXT
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "0"
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            if not analysis["pass_status"]:
                pcap_failures.append({
                    "bssid": test_config.get("bssid_5g"),
                    "reason": analysis["result"],
                    "details": analysis["details"]
                })

            all_pass = not pcap_failures
            # Check results
            if analysis["pass_status"]:
                print(f"PASS: {analysis['result']}")
            else:
                print(f"FAIL: {analysis['result']}")
                print(f"Details: {analysis['details']}")

            return all_pass, analysis

        # 05
        elif test_type == "11r_over_11kvr":
            """
                TC_K-V_5 : Test to validate roaming when 802.11R is disabled and 802.11K/V are enabled over 802.11KVR all are enabled
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1, radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)
            # -------------------- Initial Attenuation --------------------
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roaming")

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="normal",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            print(f"\nStarting Roaming test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }

            print(f"[DEBUG] Before roam Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Trigger Roaming --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Roaming --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roaming")

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}
            dut = None
            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition before 11r enable",
                attachment_type=allure.attachment_type.TEXT
            )

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Roam Station BSSID & Channel while 802.11r is disabled",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roaming Result – Per-Station Before vs After (BSSID & Channel) while 802.11r is disabled",
                attachment_type=allure.attachment_type.JSON
            )
            # TODO: Enable 802.11r from given SSID and roam again with same client
            # -------------------- Enable back 802.11r --------------------
            # get_target_object.dut_library_object.configure_roaming_features(enable_11r=True,
            #                                                                 enable_11k=True,
            #                                                                 enable_11v=True)

            # Enable 11r on all VAPs
            dut_count = len(get_testbed_details['device_under_tests'])

            for idx in range(dut_count):
                dut = get_target_object.dut_library_object

                vap_list = dut.get_vap_list(enabled_only=True)

                if not vap_list:
                    raise Exception("No VAPs found")

                for vap in vap_list:
                    print(f"Configuring 11r on {vap}")

                    # --------------------
                    # SET CONFIG
                    # --------------------
                    dut.run_generic_command(cmd=f"uci set wireless.{vap}.ieee80211r='1'", idx=idx)
                    dut.run_generic_command(cmd=f"uci set wireless.{vap}.mobility_domain='1234'", idx=idx)

                # Commit once (like best practice)
                dut.run_generic_command(cmd="uci commit wireless", idx=idx)
                dut.run_generic_command(cmd="wifi reload", idx=idx)

            time.sleep(15)

            band_steer.station_profile.set_command_flag("add_sta", "8021x_radius", 1)
            band_steer.station_profile.set_command_flag("add_sta", "ft-roam-over-ds", 1)
            band_steer.station_profile.set_wifi_extra(key_mgmt="FT-PSK",
                                                      psk=passkey)
            band_steer.station_profile.create(radio=dict_all_radios_5g["mtk_radios"][0], sta_names_=sta_list)
            band_steer.wait_until_ports_appear(sta_list=sta_list)
            band_steer.station_profile.admin_up()

            # -------------------- Initial Attenuation --------------------
            # setting attenuation to connect Back to AP1
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roaming")

            # To reassociate back to AP1
            time.sleep(20)

            print(f"\nStarting Roaming test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }

            print(f"[DEBUG] Before roam Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Steering")

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state, current_AP1=False)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition Summary after 11r enable",
                attachment_type=allure.attachment_type.TEXT
            )
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Roam Station BSSID & Channel while 802.11r is enabled",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roaming Result – Per-Station Before vs After (BSSID & Channel) while 802.11r is enabled",
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                # before_channel = result.get("before_channel")
                # after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_over_11kv_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )
                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )

                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            return all_pass, result_dict

        # 06 07
        elif test_type == "soft_roam_test":
            """
                TC_K-V_6 : Soft Roaming Test (AP1 → AP2) with Ping Traffic - 802.11k/v/r Enabled
                TC_K-V_7 : Soft Roaming Test (AP2 → AP1) with Ping Traffic - 802.11k/v/r Enabled
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            radio = "wifi0"
            channel = 149

            # Set channel
            dut = get_target_object.dut_library_object

            dut.run_generic_command(cmd=f"uci set wireless.{radio}.channel={channel}")
            dut.run_generic_command(cmd="uci commit wireless")
            dut.run_generic_command(cmd="wifi reload")

            time.sleep(15)

            # Verify via UCI
            output = dut.run_generic_command(cmd=f"uci get wireless.{radio}.channel")
            current_channel = str(output).strip().splitlines()[-1]

            print(f"[UCI] Channel set: {current_channel}")

            if str(current_channel) != str(channel):
                raise Exception(f"UCI mismatch! Expected {channel}, got {current_channel}")

            # Verify actual radio
            iw_output = dut.run_generic_command(cmd="iw dev")
            print(f"[IW OUTPUT]\n{iw_output}")

            if str(channel) not in str(iw_output):
                raise Exception(f"Radio not operating on channel {channel}")

            print(f"Channel {channel} successfully set on {radio}")

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)
            # -------------------- Initial Attenuation --------------------
            if roam_towards == "ap2":
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 900, idx - 3)
                    band_steer.set_atten('1.1.3002', 900, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)
            else:
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 900, idx - 3)
                    band_steer.set_atten('1.1.3002', 900, idx - 3)
                    band_steer.set_atten('1.1.3002', 0, idx - 1)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            print(f"\nStarting Roaming test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }

            print(f"[DEBUG] Before roam Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Trigger Steering --------------------
            if roam_towards == "ap2":
                start_time, end_time = band_steer.roam_test_standard(
                    attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])
            else:
                start_time, end_time = band_steer.roam_test_standard(
                    attenuator='1.1.3002', inc_modules=[3, 4], dec_modules=[1, 2])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = None
            if roam_towards == "ap2":
                ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                              after_state=after_state)
            else:
                ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                              after_state=after_state, current_AP1=False)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming_soft_roam",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )
                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )
                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            return all_pass, result_dict

        # 08
        elif test_type == "roam_enterprise_security":
            """
                TC_2.4.2_2 : Test to validate AP enabled roaming with enterprise security
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)
            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)
            # -------------------- Initial Attenuation --------------------

            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r_enterprise",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Validate Initial Band --------------------
            print(f"\nStarting Roaming test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }

            print(f"[DEBUG] Before roam Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("PCAP attach to Allure failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )
                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            return all_pass, result_dict

        # 09
        elif test_type == "roam_personal_security":
            """
                TC_2.4.2_2 : Test to validate AP enabled roaming with personal security
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)
            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)
            # -------------------- Initial Attenuation --------------------
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            # -------------------- Validate Initial Band --------------------
            print(f"\nStarting Roaming test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }

            print(f"[DEBUG] Before roam Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("PCAP attach to Allure failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )

            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )
                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            print("=" * 60)

            return all_pass, result_dict

        # 10
        elif test_type == "l2_mobility_domain":
            """
                TC_2.4.2_3 : Test to verify L2 roaming with Mobility domain
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            time.sleep(60)

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            # With BSSID only
            analysis = self.analyze_sniffer_pcap(
                pcap_path=local_pcap,
                bssid=test_config.get("bssid_5g"),  # Use AP's BSSID
                mode="11kvr",
                bssid_list=bssid_list,
                show_events=True
            )
            allure.attach(
                json.dumps(analysis, indent=4),
                name=f"Roaming Sniffer Analysis",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                analysis["report_text"],
                name=f"Roaming Summary",
                attachment_type=allure.attachment_type.TEXT
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # Check results
            if analysis["pass_status"]:
                print(f"PASS: {analysis['result']}")
            else:
                print(f"FAIL: {analysis['result']}")
                print(f"Details: {analysis['details']}")

            return analysis["pass_status"], analysis

        # 15 16
        elif test_type == "ap_l2_roam":
            """
               TC_ROAM-BANDSTEER_06 : Test to validate UE enabled roaming with fixed mac address
               TC_ROAM-BANDSTEER_05 : Test to validate AP enabled roaming
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                # sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r_enterprise",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before roam Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if not ping_status:
                pytest.fail(f"[Status] {ping_status}: Station are not pinging each other")

            print(f"[DEBUG] Starting TCP Traffic on station {sta_list}")
            band_steer.create_specific_cx(station_list=sta_list, tos='VO')
            band_steer.start_traffic_cx()

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Traffic --------------------
            band_steer.stop_traffic_cx()
            band_steer.clean_traffic_cx()

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )

                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Analysis {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            print("=" * 60)

            return all_pass, result_dict

        # 17 18 19 20
        elif test_type == "roaming_channel_check":
            """
               TC_ROAM-BANDSTEER_07 : L2 Roaming Enabled BS from 5GHz to 5GHz Same Channel
               TC_ROAM-BANDSTEER_08 : L2 Roaming Enabled BS from 5GHz to 5GHz different Channel
               TC_ROAM-BANDSTEER_09 : L2 Roaming Enabled BS from 2GHz to 2GHz Same Channel
               TC_ROAM-BANDSTEER_10 : L2 Roaming Enabled BS from 2GHz to 2GHz different Channel
            """

            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1"),
                sniff_channel_2=test_config.get("sniff_channel_2"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            expected_band = test_config.get("expected_band")
            channel_condition = test_config.get("channel_condition")

            if channel_condition == "different":
                if expected_band.lower() == "2g":
                    radio = "wifi1"
                    channel = 4
                elif expected_band.lower() == "5g":
                    radio = "wifi0"
                    channel = 157
                else:
                    raise ValueError("expected_band must be '2g' or '5g'")

                # Set channel
                dut_count = len(get_testbed_details['device_under_tests'])
                dut = None
                for idx in range(dut_count):
                    dut = get_target_object.dut_library_object

                    dut.run_generic_command(cmd=f"uci set wireless.{radio}.channel={channel}", idx=idx)
                    dut.run_generic_command(cmd="uci commit wireless", idx=idx)
                    dut.run_generic_command(cmd="wifi reload", idx=idx)

                    time.sleep(15)

                    # Verify via UCI
                    output = dut.run_generic_command(cmd=f"uci get wireless.{radio}.channel", idx=idx)
                    current_channel = str(output).strip().splitlines()[-1]

                    print(f"[UCI] Channel set: {current_channel}")

                    if str(current_channel) != str(channel):
                        raise Exception(f"UCI mismatch! Expected {channel}, got {current_channel}")

                    # Verify actual radio
                    iw_output = dut.run_generic_command(cmd="iw dev", idx=idx)
                    print(f"[IW OUTPUT]\n{iw_output}")

                    if str(channel) not in str(iw_output):
                        raise Exception(f"Radio not operating on channel {channel}")

                    print(f"Channel {channel} successfully set on {radio}")

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1, radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)
            # -------------------- Initial Attenuation --------------------
            if roam_towards == "ap2":
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 900, idx - 3)
                    band_steer.set_atten('1.1.3002', 900, idx - 1)
                    band_steer.set_atten('1.1.3002', 0, idx - 3)
            else:
                for idx in range(3, 5):
                    band_steer.set_atten('1.1.3009', 900, idx - 3)
                    band_steer.set_atten('1.1.3002', 900, idx - 3)
                    band_steer.set_atten('1.1.3002', 0, idx - 1)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            if channel_condition == "different":
                """ 
                    Due to hardware limitation on resource 3 lanforge, we are using
                    one of the moni interface on resource 1 for different channel case
                """
                band_steer.start_sniffer(different_resource=True)
            else:
                band_steer.start_sniffer()

            if initial_band == "2Ghz":
                # -------------------- 2Ghz STA Creation --------------------
                band_steer.create_clients(
                    radio=band_steer.station_radio,
                    ssid=ssid,
                    passwd=passkey,
                    security=security,
                    station_list=sta_list,
                    station_flag="use-bss-transition",
                    sta_type="enterprise",
                    initial_band_pref="2GHz",
                    option=None
                )

            else:
                # -------------------- 5Ghz STA Creation --------------------
                band_steer.create_clients(
                    radio=band_steer.station_radio,
                    ssid=ssid,
                    passwd=passkey,
                    security=security,
                    station_list=sta_list,
                    station_flag="use-bss-transition",
                    sta_type="enterprise",
                    initial_band_pref="5GHz",
                    option=None
                )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )

            print(f"\nStarting Roaming test...")
            before_bssid = band_steer.get_bssids(as_dict=True)
            before_chan = band_steer.get_channel(as_dict=True)
            before_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }

            print(f"[DEBUG] Before roam Station Info")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            for sta, ch in before_chan.items():
                ch = int(ch)
                if initial_band == '2Ghz':
                    # Expected: STA creation on band 2.4 GHz
                    if ch is None or ch not in range(1, 15):
                        pytest.fail(
                            f"[FAILED] {sta} is not on 2.4 GHz before Roaming. \n"
                            f"Observed band: 5Ghz  (Channel {ch}) \n"
                            f"Expected band: 2.4Ghz"
                        )
                else:
                    # Expected: STA creation on band 5 GHz
                    if ch is None or ch < 36:
                        pytest.fail(
                            f"[FAILED] {sta} is not on 5 GHz before Roaming. \n"
                            f"Observed band: 2.4Ghz  (Channel {ch}) \n"
                            f"Expected band: 5Ghz"
                        )

            # -------------------- Trigger Steering --------------------
            if roam_towards == "ap2":
                start_time, end_time = band_steer.roam_test_standard(
                    attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])
            else:
                start_time, end_time = band_steer.roam_test_standard(
                    attenuator='1.1.3002', inc_modules=[3, 4], dec_modules=[1, 2])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True)
            after_chan = band_steer.get_channel(as_dict=True)
            after_rssi = band_steer.get_rssi(as_dict=True)

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------------
            if channel_condition == "different":
                local_pcap = band_steer.stop_sniffer(different_resource=True)
                print(local_pcap, "PCAPP")
            else:
                local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():

                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")

                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")

                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                if before_channel is not None:
                    before_channel = int(before_channel)

                if after_channel is not None:
                    after_channel = int(after_channel)

                print(f"[DEBUG] {sta} BEFORE RSSI : {before_rssi}")
                print(f"[DEBUG] {sta} AFTER RSSI  : {after_rssi}")

                # --------------------------------------------------
                # Validate BSSID changed (Roaming happened)
                # --------------------------------------------------
                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

                # --------------------------------------------------
                # Validate Band
                # --------------------------------------------------
                if expected_band == "2g":
                    if after_channel not in range(1, 15):
                        functional_failures.append({
                            "sta": sta,
                            "client_mac": result.get("client_mac"),
                            "reason": f"{sta} expected to roam on 2.4GHz but got channel {after_channel}",
                            "before": before_bssid,
                            "after": after_bssid
                        })

                elif expected_band == "5g":
                    if after_channel < 36:
                        functional_failures.append({
                            "sta": sta,
                            "client_mac": result.get("client_mac"),
                            "reason": f"{sta} expected to roam on 5GHz but got channel {after_channel}",
                            "before": before_bssid,
                            "after": after_bssid
                        })

                # --------------------------------------------------
                # Validate Channel Condition
                # --------------------------------------------------
                if channel_condition == "same":
                    if before_channel != after_channel:
                        functional_failures.append({
                            "sta": sta,
                            "client_mac": result.get("client_mac"),
                            "reason": f"{sta} expected same channel roaming "
                                      f"(before={before_channel}, after={after_channel})",
                            "before": before_bssid,
                            "after": after_bssid
                        })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )

                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Analysis {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            print("=" * 60)

            return all_pass, result_dict

        # 23 24
        elif test_type == "4_way_handshake":
            """
               TC_ROAM-BANDSTEER_14 : Test to validate 4 way handshake during AP roaming
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r_enterprise",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before roam Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if not ping_status:
                pytest.fail(f"[Status] {ping_status}: Station are not pinging each other")

            print(f"[DEBUG] Starting TCP Traffic on station {sta_list}")
            band_steer.create_specific_cx(station_list=sta_list, tos='VO')
            band_steer.start_traffic_cx()

            # -------------------- Trigger Roaming --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Traffic --------------------
            band_steer.stop_traffic_cx()
            band_steer.clean_traffic_cx()

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }

            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )
                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            print("=" * 60)

            return all_pass, result_dict

        # 25
        elif test_type == "roaming_with_amqp":
            """
               TC_ROAM-BANDSTEER_15 : Test to validate AMQP session during roaming
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r_enterprise",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before roam Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if not ping_status:
                pytest.fail(f"[Status] {ping_status}: Station are not pinging each other")

            print(f"[DEBUG] Starting TCP Traffic on station {sta_list}")
            band_steer.create_specific_cx(station_list=sta_list, tos='VO')
            band_steer.start_traffic_cx()

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Traffic --------------------
            band_steer.stop_traffic_cx()
            band_steer.clean_traffic_cx()

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }
            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })
            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )

                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            print("=" * 60)

            return all_pass, result_dict

        # 26
        elif test_type == "roaming_with_VO":
            """
               TC_ROAM-BANDSTEER_16 : Test to validate client connectivity with video/voice call access during roaming
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=1,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before roam Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if not ping_status:
                pytest.fail(f"[Status] {ping_status}: Station are not pinging each other")

            print(f"[DEBUG] Starting TCP Traffic on station {sta_list}")
            band_steer.create_specific_cx(station_list=sta_list, tos='VO')
            band_steer.start_traffic_cx()

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Traffic --------------------
            band_steer.stop_traffic_cx()
            allure.attach(
                body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                name="Layer3 Traffic Data",
                attachment_type=allure.attachment_type.JSON
            )

            # Clean up traffic cross-connections
            band_steer.clean_traffic_cx()
            print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

            # -------------------- Stop Hostapd Log Capture --------------------

            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }
            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })

            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )

                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            print("=" * 60)

            return all_pass, result_dict

        # 27
        elif test_type == "l2_roaming_multi_client":
            """
               TC_ROAM-BANDSTEER_17 : Test to validate L2 roaming with multiple clients
            """
            band_steer = BandSteer(
                lanforge_ip=get_testbed_details["traffic_generator"]["details"]["manager_ip"],
                port=get_testbed_details.get("port", 8080),
                ssid=ssid,
                security=security,
                password=passkey,
                num_sta=num_sta,
                test_type=test_type,
                station_radio=dict_all_radios_5g["mtk_radios"][0],  # "1.1.wiphy0"
                sniff_radio_1=test_config.get("sniff_radio_1", "1.3.wiphy0"),
                sniff_radio_2=test_config.get("sniff_radio_2", "1.3.wiphy1"),
                sniff_channel_1=test_config.get("sniff_channel_1", "6"),
                sniff_channel_2=test_config.get("sniff_channel_2", "36"),
                upstream=list(get_testbed_details["traffic_generator"]["details"]["wan_ports"].keys())[0],
                attenuators=test_config.get("attenuators", '1.1.3002'),
                set_max_attenuators=test_config.get("set_max_attenuators", None),
                step=test_config.get("step", 5),
                max_attenuation=test_config.get("max_attenuation", 40),
                # Try connecting Far from AP for standard testcase
                wait_time=test_config.get("wait_time", 10),
                custom_wifi_cmd=test_config.get("custom_wifi_cmd", 'bgscan="simple:15:-65:60:4"'),
                initial_band_pref="5GHz"
            )
            for idx in range(3, 5):
                band_steer.set_atten('1.1.3009', 900, idx - 3)
                band_steer.set_atten('1.1.3002', 900, idx - 1)
                band_steer.set_atten('1.1.3002', 0, idx - 3)

            # -------------------- Start Hostapd Log Capture --------------------
            self.start_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Start Sniffer --------------------
            band_steer.start_sniffer()

            # -------------------- STA name series --------------------
            sta_list = band_steer.get_sta_list_before_creation(
                num_sta=5,
                radio=dict_all_radios_5g["mtk_radios"][0])
            print(f"[DEBUG] Station List: {sta_list}")

            # Clean up if there are already existing station with same name
            band_steer.pre_cleanup(sta_list)

            band_steer.station_list = sta_list

            # Track station-radio mapping
            track_station_creation(dict_all_radios_5g["mtk_radios"][0], sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - Before Roam")

            # -------------------- STA Creation --------------------
            band_steer.create_clients(
                radio=dict_all_radios_5g["mtk_radios"][0],
                ssid=ssid,
                passwd=passkey,
                security=security,
                station_list=sta_list,
                station_flag="use-bss-transition",
                sta_type="11r",
                initial_band_pref="5GHz",
                option=None
            )

            # -------------------- Validate Initial Band --------------------
            band_steer.get_station_ips()
            ip_text = ""
            for station, ip in band_steer.station_ips.items():
                ip_text += f"{station} : {ip}\n"

            allure.attach(
                ip_text,
                name="virtual client IP mapping",
                attachment_type=allure.attachment_type.TEXT
            )
            before_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            before_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            before_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Station MAC Map --------------------
            mac_dict = band_steer.get_mac(station_list=sta_list)

            allure.attach(
                body=json.dumps(mac_dict, indent=4),
                name="Virtual client MAC mapping ",
                attachment_type=allure.attachment_type.JSON
            )
            before_state = {}

            for sta in sta_list:
                before_state[sta] = {
                    "bssid": before_bssid.get(sta),
                    "channel": before_chan.get(sta),
                    "rssi": before_rssi.get(sta)
                }
            print(f"[DEBUG] Before roam Station Info {before_state}")
            allure.attach(
                body=json.dumps(before_state, indent=4),
                name="Before Roam Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )

            # -------------------- Start Continues Ping --------------------
            band_steer.create_ping_cx(station_list=sta_list)
            band_steer.start_ping_cx()

            time.sleep(30)
            band_steer.stop_ping_cx()
            ping_status = band_steer.check_connectivity(band_steer.ping_cx_profile)

            allure.attach(
                body=json.dumps(getattr(band_steer.ping_cx_profile, "traffic_data", {}), indent=4),
                name="Station Connectivity Check",
                attachment_type=allure.attachment_type.JSON
            )

            band_steer.clean_ping_cx()
            print(f"[DEBUG] Traffic data : {band_steer.ping_cx_profile.traffic_data}")

            # -------------------- Ping Status --------------------
            print(f"[DEBUG] Connectivity status : {ping_status}")
            if not ping_status:
                pytest.fail(f"[Status] {ping_status}: Station are not pinging each other")

            print(f"[DEBUG] Starting TCP Traffic on station {sta_list}")
            band_steer.create_specific_cx(station_list=sta_list, tos='VO')
            band_steer.start_traffic_cx()

            # -------------------- Trigger Steering --------------------
            start_time, end_time = band_steer.roam_test_standard(
                attenuator='1.1.3002', inc_modules=[1, 2], dec_modules=[3, 4])

            print(f"[DEBUG] Start Time : {start_time}")
            print(f"[DEBUG] End Time : {end_time}")

            # -------------------- Validate Steering --------------------
            after_bssid = band_steer.get_bssids(as_dict=True, station_list=sta_list)
            after_chan = band_steer.get_channel(as_dict=True, station_list=sta_list)
            after_rssi = band_steer.get_rssi(as_dict=True, station_list=sta_list)

            # -------------------- Attenuator State --------------------
            attach_attenuator_state(band_steer, title="Attenuator State - After Roam")

            # -------------------- Stop Traffic --------------------
            band_steer.stop_traffic_cx()
            allure.attach(
                body=json.dumps(getattr(band_steer.traffic_cx_profile, "traffic_data", {}), indent=4),
                name="Layer3 Traffic-2 Data from AP to STA1 Iteration-2",
                attachment_type=allure.attachment_type.JSON
            )

            # Clean up traffic cross-connections
            band_steer.clean_traffic_cx()
            print(f"[DEBUG] Traffic data : {band_steer.traffic_cx_profile.traffic_data}")

            # -------------------- Stop Hostapd Log Capture --------------------
            self.stop_hostapd_logging(get_target_object, get_testbed_details)

            # -------------------- Stop Sniffer --------------------
            local_pcap = band_steer.stop_sniffer()

            try:
                with open(local_pcap, "rb") as f:
                    allure.attach(
                        f.read(),
                        name="Roaming Sniffer Capture",
                        attachment_type=allure.attachment_type.PCAP
                    )
            except Exception as e:
                print("Allure attach failed:", e)

            stations = set(before_bssid) | set(before_chan) | set(after_bssid) | set(after_chan)

            test_results = {}
            after_state = {}

            for sta in sorted(stations):
                test_results[sta] = {
                    "before_bssid": before_bssid.get(sta),
                    "before_channel": before_chan.get(sta),
                    "before_rssi": before_rssi.get(sta),
                    "after_bssid": after_bssid.get(sta),
                    "after_channel": after_chan.get(sta),
                    "after_rssi": after_rssi.get(sta),
                    "client_mac": mac_dict.get(sta)
                }

            for sta in sta_list:
                after_state[sta] = {
                    "bssid": after_bssid.get(sta),
                    "channel": after_chan.get(sta),
                    "rssi": after_rssi.get(sta)
                }
            ap_summary = self.build_ap_transition_summary(sta=sta_list[0], before_state=before_state,
                                                          after_state=after_state)

            allure.attach(
                ap_summary,
                name="AP Roaming Transition",
                attachment_type=allure.attachment_type.TEXT
            )
            allure.attach(
                body=json.dumps(after_state, indent=4),
                name="After Band Steering Station BSSID & Channel",
                attachment_type=allure.attachment_type.JSON
            )
            allure.attach(
                body=json.dumps(test_results, indent=4),
                name="Roam Result – Per-Station Before vs After (BSSID & Channel)",
                attachment_type=allure.attachment_type.JSON
            )

            functional_failures = []
            pcap_failures = []
            for sta, result in test_results.items():
                before_bssid = result.get("before_bssid")
                after_bssid = result.get("after_bssid")
                before_channel = result.get("before_channel")
                after_channel = result.get("after_channel")
                before_rssi = result.get("before_rssi")
                after_rssi = result.get("after_rssi")

                print(f"[DEBUG] BEFORE roam RSSI {before_rssi}")
                print(f"[DEBUG] AFTER roam RSSI {after_rssi}")

                if before_bssid == after_bssid:
                    functional_failures.append({
                        "sta": sta,
                        "client_mac": result.get("client_mac"),
                        "reason": "BSSID did not change",
                        "before": before_bssid,
                        "after": after_bssid
                    })
            print(f"[DEBUG] Station-Radio Mapping: {station_radio_map}")

            # Attach the station-radio mapping to allure for debugging
            allure.attach(
                body=json.dumps(station_radio_map, indent=4),
                name="Station-Radio Mapping",
                attachment_type=allure.attachment_type.JSON
            )
            # Collect supplicant logs for each radio
            for radio, stations in station_radio_map.items():
                if stations:
                    print(f"[DEBUG] Collecting supplicant logs for radio {radio}, stations: {stations}")
                    self.get_supplicant_logs(radio=str(radio), sta_list=stations)

            bssid_list = []
            for device_id, device_data in setup_config.items():
                for idx, ssid in device_data["ssid_data"].items():
                    bssid_list.append(ssid['bssid'])

            for sta in sta_list:
                result = test_results.get(sta)
                client_mac = result.get("client_mac")

                if client_mac:
                    # Use client MAC for analysis
                    analysis = self.analyze_sniffer_pcap(
                        pcap_path=local_pcap,
                        client_mac=client_mac,
                        mode="11kvr_roaming",
                        bssid_list=bssid_list,
                        show_events=True,
                        frame_view=True
                    )

                    # allure.attach(
                    #     json.dumps(analysis, indent=4),
                    #     name=f"Roaming Sniffer Analysis {sta}",
                    #     attachment_type=allure.attachment_type.JSON
                    # )
                    allure.attach(
                        analysis["report_text"],
                        name=f"Roaming Summary {sta}",
                        attachment_type=allure.attachment_type.TEXT
                    )

                    if not analysis["pass_status"]:
                        pcap_failures.append({
                            "sta": sta,
                            "client_mac": client_mac,
                            "reason": analysis["result"],
                            "details": analysis["details"]
                        })

            formal = self.validate_protocol_formal_report(
                analysis=analysis,
                ap_config={
                    "ieee80211r": "1",
                    "bss_transition": "1",
                    "rrm": "1", 
                    "rrm_neighbor_report": "1",
                    "rrm_beacon_report": "1",
                }
            )
            allure.attach(
                formal["report"],
                name="Protocol Validation",
                attachment_type=allure.attachment_type.TEXT
            )
            # 6. Determine overall pass/fail
            all_pass = not functional_failures and not pcap_failures

            # 7. Prepare result dictionary (similar to band steering)
            result_dict = {
                "functional_failures": functional_failures,
                "pcap_failures": pcap_failures,
                "per_client": test_results,
                "total_clients": len(sta_list),
                "roamed_clients": len([r for r in test_results.values()
                                       if r.get("before_bssid") != r.get("after_bssid")]),
                "functional_pass": not functional_failures,
                "pcap_pass": not pcap_failures
            }

            # 8. Add protocol summary if available
            if 'analysis' in locals():
                result_dict["protocols"] = analysis.get("protocols", {})
                result_dict["protocol_details"] = analysis.get("protocol_details", {})

            # 9. Attach summary to allure
            allure.attach(
                body=json.dumps(result_dict, indent=4, default=str),
                name="Roaming Test Summary",
                attachment_type=allure.attachment_type.JSON
            )

            # 10. Print summary
            print("\n" + "=" * 60)
            print("ROAMING TEST SUMMARY")
            print("=" * 60)
            print(f"Total Clients: {result_dict['total_clients']}")
            print(f"Roamed Clients: {result_dict['roamed_clients']}")
            print(f"Functional Failures: {len(functional_failures)}")
            print(f"PCAP Analysis Failures: {len(pcap_failures)}")
            print(f"Overall Status: {'PASS' if all_pass else 'FAIL'}")

            if functional_failures:
                print("\nFunctional Failures:")
                for failure in functional_failures:
                    print(f"  • {failure.get('sta', 'Unknown')}: {failure.get('reason')}")
                    if failure.get('before_bssid') and failure.get('after_bssid'):
                        print(f"    BSSID: {failure['before_bssid']} → {failure['after_bssid']}")

            if pcap_failures:
                print("\nPCAP Analysis Failures:")
                for failure in pcap_failures:
                    print(f"  • {failure.get('sta', failure.get('bssid', 'Unknown'))}: {failure.get('reason')}")

            print("=" * 60)

            return all_pass, result_dict


if __name__ == '__main__':
    basic = {
        "target": "tip_2x",
        "controller": {
            "url": "https://sec-qa01.cicd.lab.wlan.tip.build:16001",
            "username": "tip@ucentral.com",
            "password": "OpenWifi%123"
        },
        "device_under_tests": [{
            "model": "edgecore_eap101",
            "supported_bands": ["2G", "5G"],
            "supported_modes": ["BRIDGE", "NAT", "VLAN"],
            "wan_port": "1.1.eth3",
            "lan_port": None,
            "ssid": {
                "mode": "BRIDGE",
                "ssid_data": {
                    "0": {
                        "ssid": "OpenWifi",
                        "encryption": "wpa2",
                        "password": "OpenWifi",
                        "band": "fiveg",
                        "bssid": "90:3C:B3:6C:43:04"
                    },
                    "1": {
                        "ssid": "OpenWifi",
                        "encryption": "wpa2",
                        "password": "OpenWifi",
                        "band": "twog",
                        "bssid": "90:3C:B3:6C:43:04"
                    }
                },
                "radio_data": {
                    "2G": {
                        "channel": 1,
                        "bandwidth": 20,
                        "frequency": 2437
                    },
                    "5G": {
                        "channel": 52,
                        "bandwidth": 20,
                        "frequency": 5260
                    },
                    "6G": {
                        "channel": None,
                        "bandwidth": None,
                        "frequency": None
                    }
                }
            },
            "mode": "wifi6",
            "identifier": "903cb36c4301",
            "method": "serial",
            "host_ip": "192.168.52.89",
            "host_username": "lanforge",
            "host_password": "lanforge",
            "host_ssh_port": 22,
            "serial_tty": "/dev/ttyUSB0",
            "firmware_version": "next-latest"
        }],
        "traffic_generator": {
            "name": "lanforge",
            "testbed": "basic",
            "scenario": "dhcp-bridge",
            "details": {
                "manager_ip": "localhost",
                "http_port": 8840,
                "ssh_port": 8841,
                "setup": {"method": "build", "DB": "Test_Scenario_Automation"},
                "wan_ports": {
                    "1.1.eth3": {"addressing": "dhcp-server", "subnet": "172.16.0.1/16", "dhcp": {
                        "lease-first": 10,
                        "lease-count": 10000,
                        "lease-time": "6h"
                    }
                                 }
                },
                "lan_ports": {

                },
                "uplink_nat_ports": {
                    "1.1.eth2": {
                        "addressing": "static",
                        "ip": "192.168.52.150",
                        "gateway_ip": "192.168.52.1/24",
                        "ip_mask": "255.255.255.0",
                        "dns_servers": "BLANK"
                    }
                }
            }
        }
    }

    obj = lf_tests(lf_data=dict(basic["traffic_generator"]), dut_data=list(basic["device_under_tests"]),
                   log_level=logging.DEBUG, run_lf=True)
    l = obj.run_lf_dut_data()
    print(l)
    # obj.add_stations()
    # obj.add_stations(band="5G")
    # obj.chamber_view(raw_lines="custom")
    # dut = {'0000c1018812': {"ssid_data": {
    #     0: {"ssid": 'TestSSID-2G', "encryption": 'wpa2', "password": 'OpenWifi', "band": '2G',
    #         "bssid": '00:00:C1:01:88:15'},
    #     1: {"ssid": 'TestSSID-5G', "encryption": 'wpa2', "password": 'OpenWifi', "band": '5G',
    #         "bssid": '00:00:C1:01:88:14'}}, "radio_data": {'2G': [1, 40, 2422], '5G': [36, 80, 5210], '6G': None}}}
    # obj.wifi_capacity(instance_name="test_client_wpa2_BRIDGE_udp_bi", mode="BRIDGE",
    #                   vlan_id=[100],
    #                   download_rate="1Gbps", batch_size="1,5,10,20,40,64,128,256",
    #                   influx_tags="Jitu",
    #                   upload_rate="1Gbps", protocol="UDP-IPv4", duration="60000",
    #                   move_to_influx=False, dut_data=dut, ssid_name="OpenWifi",
    #                   num_stations={"2G": 10, "5G": 10})
    # A =obj.setup_interfaces(band="fiveg", vlan_id=100, mode="NAT-WAN", num_sta=1)
    # print(A)
    # obj.setup_relevent_profiles()
    # obj.client_connect(ssid="OpenWifi", passkey="OpenWifi", security="wpa2", mode="BRIDGE", band="twog",
    #                    vlan_id=[None], num_sta=65, scan_ssid=True,
    #                    station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal"],
    #                    allure_attach=True)
    # obj.multi_psk_test(band="twog", mpsk_data=None, ssid="OpenWifi", bssid="['00:00:c1:01:88:12']", passkey="OpenWifi",
    #                    encryption="wpa", mode="BRIDGE", num_sta=1)
    # obj.add_vlan(vlan_iFds=[100])
    # obj.create_dhcp_external()obj.add_vlan(vlan_ids=[100, 200, 300, 400, 500, 600])
    # obj.get_cx_data()
    # obj.chamber_view()
    dut = {'903cb36c4301':
        {'ssid_data': {
            0: {'ssid': 'ssid_wpa_2g_br', 'encryption': 'wpa', 'password': 'something', 'band': '2G',
                'bssid': '90:3C:B3:6C:43:04'}}, 'radio_data': {'2G': {'channel': 6, 'bandwidth': 20, 'frequency': 2437},
                                                               '5G': {'channel': None, 'bandwidth': None,
                                                                      'frequency': None},
                                                               '6G': {'channel': None, 'bandwidth': None,
                                                                      'frequency': None}}}}

    passes, result = obj.client_connectivity_test(ssid="ssid_wpa_2g_br", passkey="something", security="wpa",
                                                  extra_securities=[],
                                                  num_sta=1, mode="BRIDGE", dut_data=dut,
                                                  band="fiveg")
    # print(passes == "PASS", result)
    # # obj.start_sniffer(radio_channel=1, radio="wiphy7", test_name="sniff_radio", duration=30)
    # print("started")
    # time.sleep(30)
    # obj.stop_sniffer()
    # lf_report.pull_reports(hostname="10.28.3.28", port=22, username="lanforge",
    #                        password="lanforge",
    #                        report_location="/home/lanforge/" + "sniff_radio.pcap",
    #                        report_dir=".")
    #     def start_sniffer(self, radio_channel=None, radio=None, test_name="sniff_radio", duration=60):
    #
    # obj.get_cx_data()
    # obj.chamber_view()
    # obj.client_connectivity_test(ssid="wpa2_5g", passkey="something", security="wpa2", extra_securities=[],
    #                              num_sta=1, mode="BRIDGE", vlan_id=1,
    # #                              band="fiveg", ssid_channel=36)
    # obj.chamber_view()
    # obj.setup_relevent_profiles()
    # obj.add_vlan(vlan_ids=[100, 200, 300])
    # # obj.chamber_view()
    # obj.setup_relevent_profiles()

    # dut = {'903cb36c46ad':
    #     {'ssid_data': {
    #         0: {'ssid': 'OpenWifi', 'encryption': 'wpa2', 'password': 'OpenWifi', 'band': '5G',
    #             'bssid': '90:3C:B3:6C:46:B1'}}, 'radio_data': {
    #                                                            '5G': {'channel': 52, 'bandwidth': None,
    #                                                                   'frequency': None}}}}
    #
    # passes, result = obj.hot_config_reload_test(ssid="OpenWifi", passkey="OpenWifi", security="wpa2",
    #                                               extra_securities=[],
    #                                               num_sta=1, mode="BRIDGE", dut_data=dut,
    #                                               band="fiveg")