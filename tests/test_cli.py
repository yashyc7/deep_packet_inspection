from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from typer.testing import CliRunner

from deep_packet_inspection.cli import app
from tests.helpers import build_tls_client_hello


def test_cli_analyze_with_block_app(tmp_path):
    input_pcap = tmp_path / "in.pcap"
    output_pcap = tmp_path / "out.pcap"
    tls = build_tls_client_hello("www.youtube.com")
    wrpcap(
        str(input_pcap),
        [Ether() / IP(src="192.168.1.100", dst="1.2.3.4") / TCP(sport=50000, dport=443) / Raw(tls)],
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [str(input_pcap), str(output_pcap), "--block-app", "YouTube"],
    )

    assert result.exit_code == 0, result.output
    assert "PROCESSING REPORT" in result.output
    assert "Blocked app" in result.output
    assert output_pcap.exists()


def test_cli_missing_input(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        app,
        [str(tmp_path / "missing.pcap"), str(tmp_path / "out.pcap")],
    )
    assert result.exit_code == 1
    assert "not found" in result.output.lower()
