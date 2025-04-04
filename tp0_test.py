import subprocess
import pytest

# Define script path
SCRIPT_PATH = "tp1.py"
SERVER_ADDRESS_NAME = "pugna.snes.dcc.ufmg.br"
SERVER_ADDRESS_IPV4 = "150.164.213.243"
SERVER_ADDRESS_IPV6 = "2804:1f4a:dcc:ff03::1"
PORT = "51001"


def run_command(command_args, address=SERVER_ADDRESS_IPV4):
    result = subprocess.run(
        ["python3", SCRIPT_PATH, address, PORT] + list(map(str, command_args)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result


@pytest.mark.skip("auxiliar method")
def test_itr(id, expected_nonce):
    result = run_command(["itr", id, expected_nonce])
    sas = result.stdout.strip()
    [id, nonce, token] = sas.split(":")
    assert id == id
    assert nonce == expected_nonce
    assert len(token) == 64
    return sas


@pytest.mark.skip("auxiliar method")
def test_all_commands_with_address(adress=SERVER_ADDRESS_IPV4):
    # Test itr
    sas1 = test_itr("user1", "0")
    sas2 = test_itr("user2", "0")
    sas3 = test_itr("user3", "0")

    assert sas1 != sas2 != sas3

    print("sas1", sas1, sas2, sas3)

    # Test itv
    result = run_command(["itv", sas1], adress)
    assert result.stdout.strip() == "0"
    result = run_command(["itv", sas2], adress)
    assert result.stdout.strip() == "0"
    result = run_command(["itv", sas3], adress)
    assert result.stdout.strip() == "0"

    # Test gtr
    result = run_command(["gtr", 3, sas1, sas2, sas3], adress)
    gas = result.stdout.strip()

    *sas_list, token = gas.split("+")
    assert len(sas_list) == 3
    assert len(token) == 64
    for sas in sas_list:
        [id, nonce, token] = sas.split(":")
        assert id == id
        assert nonce == nonce
        assert len(token) == 64

    # Test gtv
    result = run_command(["gtv", gas], adress)
    assert result.stdout.strip() == "0"


def test_all_commands():
    test_all_commands_with_address(SERVER_ADDRESS_IPV4)
    test_all_commands_with_address(SERVER_ADDRESS_NAME)
    test_all_commands_with_address(SERVER_ADDRESS_IPV6)
