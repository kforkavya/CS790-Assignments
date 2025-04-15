from stem.control import Controller, EventType
from stem.process import launch_tor_with_config
import time
import io
import pycurl
import argparse
from circuit_selector import get_path

SOCKS_PORT = 9050
CONNECTION_TIMEOUT = 30

def query(url):
    output = io.BytesIO()

    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.PROXY, 'localhost')
    c.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    c.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
    c.setopt(pycurl.WRITEFUNCTION, output.write)

    try:
        c.perform()
        return output.getvalue().decode()
    except pycurl.error as exc:
        raise ValueError(f"Unable to reach {url} ({exc})")

print("[*] Launching Tor with custom config...")

tor_process = launch_tor_with_config(
    config={
        'ControlPort': '9051',
        'CookieAuthentication': '0',
        '__LeaveStreamsUnattached': '1',
        'CircuitBuildTimeout': '60',
        'LearnCircuitBuildTimeout': '0',
    },
    init_msg_handler=lambda line: print("[tor] " + line),
)

def connect(task_num):
    if (task_num != 1 and task_num != 2):
        print("[-] Invalid task number. Use 1 or 2.")
        exit(1)
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            print("\n[*] Connected to Tor ControlPort.")
            print("[*] Selecting 4 relays for custom circuit...")

            if task_num == 1:
                # Pick 4 relays
                # relays = [desc.fingerprint for desc in controller.get_network_statuses()][:4]
                # if len(relays) < 4:
                #     print("[-] Not enough relays available.")
                #     tor_process.kill()
                #     exit(1)
                relays = []
                guards = [r.fingerprint for r in controller.get_network_statuses() if 'Guard' in r.flags and 'Running' in r.flags]
                if len(guards) < 1:
                    raise KeyboardInterrupt
                relays.append(guards[0])
                middles = [r.fingerprint for r in controller.get_network_statuses() if 'Exit' not in r.flags and 'Running' in r.flags]
                for middle in middles:
                    if middle not in relays:
                        relays.append(middle)
                        if len(relays) == 3:
                            break
                if len(relays) < 3:
                    raise KeyboardInterrupt
                exits = [r.fingerprint for r in controller.get_network_statuses() if 'Exit' in r.flags and 'Running' in r.flags and 'Valid' in r.flags]
                for exit in exits:
                    if exit not in relays:
                        relays.append(exit)
                        break
                if len(relays) < 4:
                    raise KeyboardInterrupt
            else:
                # Task 2
                relays = get_path(4)
                print()

            # Build the 4-hop circuit
            circuit_id = controller.new_circuit(relays, await_build=True)
            print(f"[+] Built 4-hop circuit {circuit_id}")
            for i, fp in enumerate(relays):
                print(f"  Hop {i + 1}: {fp}")
            print("[*] Circuit built successfully.\n")

            # Attach streams to the circuit
            def stream_event_listener(event):
                if event.status == 'NEW':
                    print(f"[+] Attaching stream {event.id} to circuit {circuit_id}")
                    try:
                        controller.attach_stream(event.id, circuit_id)
                    except Exception as e:
                        print(f"[-] Error attaching stream {event.id}: {e}")

            controller.add_event_listener(stream_event_listener, EventType.STREAM)

            print("[*] Waiting for request/stream to go through circuit... (Press Ctrl+C to quit)\n")
            
            start = time.time()
            result = query("https://check.torproject.org/")
            end = time.time()

            print("Time taken:", end - start)
            
            if "Congratulations. This browser is configured to use Tor." in result:
                print("[+] Tor connection recognized.")
                if "However, it does not appear to be Tor Browser." in result:
                    print("[+] But not via Tor Browser.")
                
                for line in result.split('\n'):
                    if "Your IP address appears to be:" in line:
                        print("[+] Your IP address appears to be:", line.split(':')[1].strip())
                        break
            else:
                print(result)

            print("[*] Press Ctrl+C to quit.")
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Caught Ctrl+C, exiting...")

    finally:
        print("\n[*] Shutting down Tor...")
        tor_process.kill()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--task', dest="task_num", type=int, default=1, help="Task 1 or 2")
    args = parser.parse_args()
    print("[*] Starting Tor...")
    connect(args.task_num)
    print("[*] Exiting...")