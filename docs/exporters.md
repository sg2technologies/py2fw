# Exporters

Exporter plugins isolate vendor-specific syntax from the Py2FW compiler. Initial targets:

- Linux: `iptables`, `nftables`
- Enterprise: `paloalto`, `fortigate`, `ciscoasa`
- Future-oriented: `checkpoint`
- Cloud: `aws-sg`, `azure-nsg`
- Container: `kubernetes`

Every exporter consumes `FirewallIR`. Do not import `py2fw.parser` inside exporter modules.
