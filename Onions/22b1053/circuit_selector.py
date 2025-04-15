import requests
import os
import random
from bs4 import BeautifulSoup
from datetime import datetime
from ipaddress import ip_address
from stem.descriptor import parse_file

CONSENSUS_FILE = "consensus.txt"
DESCRIPTORS_FILE = "cached-descriptors.txt"

def should_we_fetch_again(filename):
    try:
        if not os.path.exists(filename):
            return True
        last_modified = datetime.fromtimestamp(os.path.getmtime(filename))
        now = datetime.now()
        delta = now - last_modified
        return delta.total_seconds() > 3600 # 1 hour
    except Exception as e:
        print(f"[!] Error checking file: {filename}. {e}")
        return True

def fetch_file(base_url, file_suffix, local_filename):
    try:
        print(f"[*] Fetching latest {file_suffix} file...")
        response = requests.get(base_url)
        soup = BeautifulSoup(response.text, "html.parser")
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.endswith(file_suffix):
                try:
                    timestamp = datetime.strptime(href[:19], "%Y-%m-%d-%H-%M-%S")
                    links.append((timestamp, href))
                except:
                    continue
        latest_timestamp, latest_file = max(links)
        url = base_url + latest_file
        print(f"[*] Downloading: {latest_file}")
        data = requests.get(url).content
        with open(local_filename, "wb") as f:
            f.write(data)
        print(f"[+] Saved as {local_filename}")
    except Exception as e:
        print(f"[!] Couldn't update file {local_filename}. {e}")
        exit(1)

def fetch_consensus():
    fetch_file("https://collector.torproject.org/recent/relay-descriptors/consensuses/", "-consensus", CONSENSUS_FILE)

def fetch_descriptors():
    fetch_file("https://collector.torproject.org/recent/relay-descriptors/server-descriptors/", "-server-descriptors", DESCRIPTORS_FILE)

def in_same_subnet(ip1, ip2):
    try:
        return ip_address(ip1) // (1 << 16) == ip_address(ip2) // (1 << 16)
    except Exception:
        return False

def in_same_subnet_any_in_path(to_check, path):
    for node in path:
        if node['fingerprint'] != to_check['fingerprint']:
            if in_same_subnet(node['address'], to_check['address']):
                return True
    return False

def same_family(node1, node2):
    return node1['fingerprint'] in node2['family'] or node2['fingerprint'] in node1['family']

def same_family_any_in_path(to_check, path):
    for node in path:
        if node['fingerprint'] != to_check['fingerprint']:
            if same_family(node, to_check):
                return True
    return False

def get_valid_nodes():
    nodes = []
    with open(CONSENSUS_FILE, "rb") as consensus_f, open(DESCRIPTORS_FILE, "rb") as desc_f:
        descriptors = {desc.fingerprint: desc for desc in parse_file(desc_f)}
        for desc in parse_file(consensus_f):
            if not desc.flags:
                continue
            if desc.fingerprint not in descriptors:
                continue
            server_desc = descriptors[desc.fingerprint]
            nodes.append({
                'fingerprint': desc.fingerprint,
                'nickname': desc.nickname,
                'address': desc.address,
                'flags': set(desc.flags),
                'family': server_desc.family if hasattr(server_desc, 'family') else [],
                'bandwidth': desc.bandwidth
            })
    return nodes

def weighted_random_choice(nodes):
    total_bandwidth = sum(node['bandwidth'] for node in nodes)
    weights = [node['bandwidth'] / total_bandwidth for node in nodes]
    return random.choices(nodes, weights=weights)[0]

def get_path(n_hops=3):
    assert n_hops >= 3, "Tor circuits must have at least 3 hops (guard, middle, exit)."

    if should_we_fetch_again(CONSENSUS_FILE) or should_we_fetch_again(DESCRIPTORS_FILE):
        fetch_consensus()
        fetch_descriptors()

    nodes = get_valid_nodes()

    # Exit node
    exit_candidates = [n for n in nodes if 'Exit' in n['flags'] and 'BadExit' not in n['flags']]
    if len(exit_candidates) < 1:
        print("[!] No valid exit nodes found.")
        exit(1)
    exit_node = weighted_random_choice(exit_candidates)
    path = [exit_node]

    # Guard node
    guard_candidates = [n for n in nodes if 'Guard' in n['flags'] and
                        n['fingerprint'] not in {node['fingerprint'] for node in path} and
                        not same_family_any_in_path(n, path) and
                        not in_same_subnet_any_in_path(n, path)]
    if len(guard_candidates) < 1:
        print("[!] No valid guard nodes found.")
        exit(1)
    guard_node = weighted_random_choice(guard_candidates)
    path.insert(0, guard_node)

    # Middle nodes
    middle_nodes = []
    used_fingerprints = {node['fingerprint'] for node in path}
    while len(middle_nodes) < (n_hops - 2):
        candidates = []
        for node in nodes:
            if node['fingerprint'] in used_fingerprints:
                continue
            if same_family_any_in_path(node, path + middle_nodes):
                continue
            if in_same_subnet_any_in_path(node, path + middle_nodes):
                continue
            candidates.append(node)
        if len(candidates) == 0:
            print("[!] Couldn't find enough middle nodes satisfying constraints.")
            exit(1)
        middle_node = weighted_random_choice(candidates)
        middle_nodes.append(middle_node)
        used_fingerprints.add(middle_node['fingerprint'])

    full_path = [guard_node] + middle_nodes + [exit_node]

    print("\n--- Tor Path Selected ---")
    for i, node in enumerate(full_path):
        role = "Guard" if i == 0 else "Exit" if i == len(full_path) - 1 else f"Middle {i}"
        print(f"{role}: {node['nickname']} ({node['address']})")

    return [node['fingerprint'] for node in full_path]