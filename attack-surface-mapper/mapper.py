import os
import json
import networkx as nx
from networkx.readwrite import json_graph
from libnmap.parser import NmapParser

class AttackSurfaceMapper:
    def __init__(self):
        #Inizializzazione di DiGraph() con NetworkX
        self.graph = nx.DiGraph()

    def parse_nmap_xml(self, xml_file_path):
        #libnmap per parsare i file XML di Nmao
        normalized_data = []
        try:
            nmap_report = NmapParser.parse_fromfile(xml_file_path)
            for host in nmap_report.hosts:
                ip = host.address
                state = host.status

                #OS fingerprinting
             
                os_name = self._extract_os(host)

                for service in host.services:
                    #normalizza l'output
                    svc_dict = service.service_dict
                    product = svc_dict.get("product", "")
                    ver     = svc_dict.get("version", "")
                    extra   = svc_dict.get("extrainfo", "")
                    version_str = " ".join(x for x in [product, ver, extra] if x) or "unknown"

                    #CPE prodotto da nmap
                    try:
                        cpe_list = [c.cpestring for c in (service.cpelist or [])]
                    except Exception:
                        cpe_list = []
                    cpe = next((c for c in cpe_list if c.startswith("cpe:/a")),
                               cpe_list[0] if cpe_list else "")

                    item = {
                        "ip": ip,
                        "port": service.port,
                        "protocol": service.protocol,
                        "service": service.service,
                        "version": version_str,
                        "cpe": cpe,
                        "state": service.state,
                        "os": os_name
                    }
                    normalized_data.append(item)
        except Exception as e:
            print(f"[ERROR] Fallito parsing Nmap XML: {e}")
        return normalized_data

    @staticmethod
    def _extract_os(host) -> str:
        #semplice operazione di osfingerprinting
        try:
            matches = host.os_match_probabilities()
            if matches:
                best = max(matches, key=lambda m: int(getattr(m, "accuracy", 0) or 0))
                name = getattr(best, "name", None)
                if name:
                    return name
        except Exception:
            pass
        # Fallback: alcune versioni espongono host.os_class_probabilities()
        try:
            classes = host.os_class_probabilities()
            if classes:
                best = classes[0]
                parts = [getattr(best, "vendor", ""), getattr(best, "osfamily", "")]
                label = " ".join(p for p in parts if p).strip()
                if label:
                    return label
        except Exception:
            pass
        return "unknown"

    def parse_masscan_json(self, json_file_path):
        """Passo 2: Parser aggiuntivo per i risultati di Masscan"""
        normalized_data = []
        try:
            with open(json_file_path, 'r') as f:
                data = json.load(f)
                for entry in data:
                    for port_info in entry.get("ports", []):
                        item = {
                            "ip": entry.get("ip"),
                            "port": port_info.get("port"),
                            "protocol": port_info.get("proto"),
                            "service": "unknown", #masscan non lo fa
                            "version": "unknown",
                            "state": port_info.get("status")
                        }
                        normalized_data.append(item)
        except Exception as e:
            print(f"[ERROR] Fallito parsing Masscan JSON: {e}")
        return normalized_data

    def build_graph(self, normalized_data):
        """Passo 5: Aggiungi nodi e archi tipizzati al grafo"""
        for item in normalized_data:
            if item['state'] != 'open':
                continue #non conta le porte chiuse
                
            ip = item['ip']
            port_node = f"{ip}:{item['port']}"
            service_node = f"{item['service']}_{item['version']}"

            #nodi(IP, Porta, Servizio)
            self.graph.add_node(ip, type='host')
            self.graph.add_node(port_node, type='port', port=item['port'], protocol=item['protocol'])
            self.graph.add_node(service_node, type='service', service=item['service'], version=item['version'], cpe=item.get('cpe', ''))

            #Archi tipizzati
            self.graph.add_edge(ip, port_node, relation='open')
            self.graph.add_edge(port_node, service_node, relation='runs')

            #OS fingerprinting
            os_name = item.get('os', 'unknown')
            if os_name and os_name != 'unknown':
                os_node = f"os::{os_name}"
                self.graph.add_node(os_node, type='os', os=os_name)
                self.graph.add_edge(ip, os_node, relation='runs_os')

  
    
    def get_open_ports(self, ip):
        if ip not in self.graph:
            return []
        return [n for n in self.graph.successors(ip) if self.graph.nodes[n].get('type') == 'port']

    def get_services_by_type(self, service_type):
        return [n for n, attr in self.graph.nodes(data=True) if attr.get('type') == 'service' and attr.get('service') == service_type]

    def get_os(self, ip):
        """Restituisce il sistema operativo rilevato per un host, o None."""
        if ip not in self.graph:
            return None
        for n in self.graph.successors(ip):
            if self.graph.nodes[n].get('type') == 'os':
                return self.graph.nodes[n].get('os')
        return None

    def get_vulnerable_paths(self):
       #percorsi base
        paths = []
        for host in [n for n, attr in self.graph.nodes(data=True) if attr.get('type') == 'host']:
            for port in self.graph.successors(host):
                for service in self.graph.successors(port):
                    paths.append(f"{host} -> {port} -> {service}")
        return paths

    def export_graph_to_json(self, output_path):
        """Passo 7: Esporta il grafo in formato JSON serializzabile"""
        data = json_graph.node_link_data(self.graph)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[SUCCESS] Grafo esportato con successo in {output_path}")

def main():
    print("[INFO] Avvio Attack Surface Mapper...")
    mapper = AttackSurfaceMapper()

    current_dir = os.path.dirname(os.path.abspath(__file__))
    xml_path = os.path.join(current_dir, '..', 'output', 'nmap_scan.xml')

    if os.path.exists(xml_path):
        print(f"[INFO] Parsing XML reale da: {xml_path}")
        normalized_data = mapper.parse_nmap_xml(xml_path)
        print(f"[INFO] {len(normalized_data)} entry estratte dallo scan XML")
    else:
        print("[WARNING] nmap_scan.xml non trovato — uso dati mock di test")
        normalized_data = [
            {"ip": "192.168.1.10", "port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2p1", "state": "open", "os": "Linux 2.6.X"},
            {"ip": "192.168.1.10", "port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.41", "state": "open", "os": "Linux 2.6.X"}
        ]

    mapper.build_graph(normalized_data)

    # Determina l'IP del target dai dati reali 
    target_ip = normalized_data[0]["ip"] if normalized_data else "N/A"

    print("\n[TEST] Test delle query sul grafo:")
    print(f"Porte aperte su {target_ip}: {mapper.get_open_ports(target_ip)}")
    print(f"Servizi HTTP trovati: {mapper.get_services_by_type('http')}")
    print(f"Sistema operativo rilevato: {mapper.get_os(target_ip) or 'non rilevato (scan senza -O/root)'}")
    print(f"Percorsi di attacco totali: {len(mapper.get_vulnerable_paths())}")

    output_dir = os.path.abspath(os.path.join(current_dir, '..', 'output'))
    os.makedirs(output_dir, exist_ok=True)
    mapper.export_graph_to_json(os.path.join(output_dir, 'attack_graph.json'))


if __name__ == "__main__":
    main()
