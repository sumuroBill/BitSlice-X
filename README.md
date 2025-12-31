# BitSlice-X DPDK Prototype — README

This document describes how to deploy and run the BitSlice-X prototype, including node roles/topology, hardware/network requirements, software installation, DPDK NIC binding and hugepage setup, running `pktgen` as the traffic generator, and running BitSlice-X POT nodes (source/intermediate/destination) with per-hop forwarding configuration.

---

## 1. Topology and Node Roles

You need **N servers** connected in a multi-hop chain:

- **Node 1 (Sender)**: runs `pktgen` to generate and transmit packets
- **Node 2 (Source)**: initializes BitSlice-X headers (source POT node)
- **Node 3 … Node (N−1) (Intermediate)**: verifies and updates BitSlice-X headers (intermediate POT nodes)
- **Node N (Destination)**: performs final verification (destination POT node)

## 2. Hardware and System Requirements

### 2.1 Server Configuration

- **POT nodes (Source / Intermediate / Destination)**
  - OS: CentOS 7.5
  - CPU: 8 cores (2.7 GHz Intel Xeon Platinum 8369B)
  - Memory: 16 GB

- **Sender node (pktgen)**
  - OS: CentOS 7.5
  - CPU: 4 cores
  - Memory: 8 GB

### 2.2 NIC and Networking Requirements

Each server must have **two NICs**:
- `eth0`: management / SSH login
- `eth1`: dataplane NIC used for experiments (DPDK uses this NIC)

On each server, record `eth1`’s IP/MAC address (used later for traffic generation and forwarding configuration):
```bash
ifconfig
ip addr
ip link
```
## 3. Topology and Node Roles
### 3.1 Packet Sender Node: pktgen + DPDK + Lua
- pktgen version: 3.6.5
- DPDK version: 18.11.11
- Lua version: 5.4.3
#### 3.1.1 Download and unpack
```bash
mkdir -p /root/pktgen
cd /root/pktgen
wget https://git.dpdk.org/apps/pktgen-dpdk/snapshot/pktgen-dpdk-pktgen-3.6.5.zip \
     https://www.lua.org/ftp/lua-5.4.3.tar.gz \
     https://fast.dpdk.org/rel/dpdk-18.11.11.tar.xz
tar -Jxvf dpdk-18.11.11.tar.xz
tar -zxvf lua-5.4.3.tar.gz
unzip pktgen-dpdk-pktgen-3.6.5.zip
```
#### 3.1.2 Install dependencies
```bash
yum -y install kernel-devel.x86_64
yum -y install numactl-devel.x86_64
yum -y install elfutils-libelf-devel
yum -y install libpcap-devel
```
#### 3.1.3 Build DPDK
```bash
cd dpdk-stable-18.11.11
make config T=x86_64-native-linuxapp-gcc
make all -j32
cd ..
```
#### 3.1.4 Build Lua
```bash
cd lua-5.4.3
make
make install
cd ..
```
#### 3.1.5 Build pktgen
```bash
cd pktgen-dpdk-pktgen-3.6.5/
export RTE_SDK=/root/pktgen/dpdk-stable-18.11.11/
export RTE_TARGET=build
make -j32
```
## 3.2 POT Nodes: DPDK + OpenSSL (AES-NI enabled)
**DPDK version:** 18.11.11

Install DPDK the same way as above (§3.1).
### 3.2.1 Enable AES-NI acceleration via OpenSSL 
```bash
sudo yum groupinstall "Development Tools"
sudo yum install perl-core

wget https://www.openssl.org/source/openssl-1.1.1l.tar.gz
tar -xzvf openssl-1.1.1l.tar.gz 
cd openssl-1.1.1l

./Configure linux-x86_64 --prefix=/usr/local/openssl --openssldir=/usr/local/openssl enable-asm enable-engine
make
sudo make install

echo "/usr/local/openssl/lib" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig
sudo ln -sf /usr/local/openssl/bin/openssl /usr/bin/openssl

openssl version
ldd $(which openssl)
```
## 4. Bind NIC to vfio-pci and Configure Hugepages (All Nodes)
This section applies to **all nodes**: sender + source + intermediate + destination.
```bash
modprobe vfio
modprobe vfio-pci
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
ethtool -i eth1
echo "[$Bus-info]" > /sys/bus/pci/drivers/virtio-pci/unbind
/root/pktgen/dpdk-stable-18.11.11/usertools/dpdk-devbind.py -b vfio-pci "[$Bus-info]"
echo 3500 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```
## 5. Run Packet Sender (pktgen)

Upload `pktgen_config.txt` to the sender node and edit:
- `src mac`, `src ip`: sender node eth1 MAC/IP
- `dst mac`, `dst ip`: source node eth1 MAC/IP
```bash
./app/build/pktgen -n 4 -m 1024 -w "[$Bus-info]" -- -P -m 1.0 -f pktgen_config.txt
```
## 6. Run POT Nodes (BitSlice-X)
### 6.1 Upload codes
- Upload `l2fwd-source-hop16` to the source node server
- Upload `l2fwd-node-hop16` to each intermediate and destination node server
### 6.2 Configure BitSlice-X parameters (process.h)
Edit `process.h` inside each program:

**For `l2fwd-source-hop16` (Source node)**:
- `N`: actual POT path length (1–16)
- `G`: group size (1, 2, 4, 8, 16)
- `current_node`: set to 0

**For `l2fwd-node-hop16` (Intermediate/Destination nodes)**:
- `N`: actual POT path length (1–16)
- `G`: group size (1, 2, 4, 8, 16)
- `current_node`: hop index, first POT node after source: 1; next hop: 2, etc.; destination: last hop index

### 6.3 Configure forwarding path (per-hop next-hop settings)
For each node, you must configure its **next-hop IP** by editing:
- Source node: `source.c`
- POT node: `node.c`

Modify the function `l2fwd_mac_updating()` to rewrite IP addresses to the actual next hop.

example:

```bash
/* Replace source and destination IP with actual IP addresses */
static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
    struct ether_hdr *eth;
    struct ipv4_hdr *ipv4_hdr;
    uint16_t ether_type;

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth->ether_type);

    ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

    uint32_t new_src_ip = rte_cpu_to_be_32(0xAC113C9B);  // example: 172.17.60.155
    uint32_t new_dst_ip = rte_cpu_to_be_32(0xAC113C9D);  // example: 172.17.60.157

    ipv4_hdr->src_addr = new_src_ip;
    ipv4_hdr->dst_addr = new_dst_ip;

    /* Recalculate IP checksum */
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    /* src addr */
    ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}
```
### 6.4 Set DPDK/OpenSSL environment variables (POT nodes)

```bash
export RTE_SDK=/root/pktgen/dpdk-stable-18.11.11/
export RTE_TARGET=build
export PATH=/usr/local/openssl/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/openssl/lib:$LD_LIBRARY_PATH
export OPENSSL_CONF=/usr/local/openssl/openssl.cnf
export CFLAGS="-I/usr/local/openssl/include"
export LDFLAGS="-L/usr/local/openssl/lib"
```
### 6.5 Run the programs
```bash
./build/l2fwd-source-hop16 -- -p 0x1
./build/l2fwd-node-hop16 -- -p 0x1
```
## 7. Notes and Tips
Always start **POT nodes first**, then start `pktgen`.
Maintain a clear per-hop mapping of:
- node index (`current_node`)
- next-hop IP address
- NIC bus-info ("[$Bus-info]")


## 8. Measurement
### 8.1 RTT/IP hop measurement
We utilized traceroute data downloaded from RIPE Atlas `https://atlas.ripe.net/probes/`, collected on January 5, 2025. After filtering out failed probes, we obtained 277,647 successful traceroute samples. `last_median_rtt_filtered_clean.txt` records the RTT distribution. 

We analyzed the IP hop count distribution from source to destination based on the same RIPE Atlas data, the distribution is recorded in `all_hops.txt`.

### 8.2 AS-path measurement
To analyze AS-level path lengths, we downloaded BGP updates from Route-Views `https://archive.routeviews.org/` and RIPE RIS `https://ris.ripe.net/docs/route-collectors/`. We analyzed 100+G BGP data from all of the collectors, and due to the large amount of data, we did not put the original data, but it can be downloaded directly from the official website.
