/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
	std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

	const Interface* iface = findIfaceByName(inIface);
	if (iface == nullptr) {
		std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
		return;
	}

	std::cerr << getRoutingTable() << std::endl;

	RoutingTableEntry hehe = m_routingTable.lookup(iface->ip);
	ethernet_hdr m_ethernet_header;
	if (packet.size() < sizeof(ethernet_hdr))
	{
		std::cerr << "Received packet, but packet is smaller than the minimum size, ignoring" << std::endl;
		return;
	}
	memcpy(&m_ethernet_header, &(packet[0]), sizeof(ethernet_hdr));
	std::string ether_mac_address = macToString(Buffer(m_ethernet_header.ether_dhost, m_ethernet_header.ether_dhost + ETHER_ADDR_LEN));
	std::string m_mac_adderss = macToString(iface->addr);
	if (ether_mac_address != "ff:ff:ff:ff:ff:ff" && ether_mac_address != m_mac_adderss) return;
	auto ether_packet_type = ntohs(m_ethernet_header.ether_type);
	if (ether_packet_type != ethertype_ip && ether_packet_type != ethertype_arp)
		return;
	else if (ether_packet_type == ethertype_arp)
	{
		arp_hdr m_arp_header;
		if (packet.size() < (sizeof(ethernet_hdr) + sizeof(arp_hdr)))
		{
			std::cerr << "Received packet, but packet is smaller than the minimum size, ignoring" << std::endl;
			return;
		}
		memcpy(&m_arp_header, &(packet[sizeof(ethernet_hdr)]), sizeof(arp_hdr));
		auto m_arp_type = ntohs(m_arp_header.arp_op);
		if (m_arp_type == arp_op_request)
		{
			std::string arp_mac_address = macToString(Buffer(m_arp_header.arp_tha, m_arp_header.arp_tha + ETHER_ADDR_LEN));
			if (m_arp_header.arp_tip == iface->ip)
			{
				Buffer m_arp_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
				m_arp_header.arp_op = htons(arp_op_reply);
				auto temp = m_arp_header.arp_sip;
				m_arp_header.arp_sip = iface->ip;
				m_arp_header.arp_tip = temp;
				unsigned char temp0[6];
				memcpy(temp0, m_arp_header.arp_sha, 6);
				memcpy(m_arp_header.arp_sha, &((iface->addr)[0]), ETHER_ADDR_LEN);
				memcpy(m_arp_header.arp_tha, temp0, ETHER_ADDR_LEN);
				unsigned char temp1[6];
				memcpy(temp1, m_ethernet_header.ether_shost, 6);
				memcpy(m_ethernet_header.ether_shost, &((iface->addr)[0]), ETHER_ADDR_LEN);
				memcpy(m_ethernet_header.ether_dhost, temp1, ETHER_ADDR_LEN);
				memcpy(&(m_arp_packet[0]), &m_ethernet_header, sizeof(m_ethernet_header));
				memcpy(&(m_arp_packet[sizeof(m_ethernet_header)]), &m_arp_header, sizeof(m_arp_header));
				sendPacket(m_arp_packet, inIface);
			}
			else return;
		}
		else if (m_arp_type == arp_op_reply)
		{
			if (m_arp_header.arp_tip == iface->ip)
			{
				auto m_pending_packets = m_arp.insertArpEntry(Buffer(m_arp_header.arp_sha, m_arp_header.arp_sha + ETHER_ADDR_LEN), m_arp_header.arp_sip);
				if (m_pending_packets == nullptr) return;
				else
				{
					ethernet_hdr temp_ethernet_header;
					temp_ethernet_header.ether_type = htons(ethertype_ip);
					memcpy(temp_ethernet_header.ether_shost, &((iface->addr)[0]), ETHER_ADDR_LEN);
					memcpy(temp_ethernet_header.ether_dhost, m_arp_header.arp_sha, ETHER_ADDR_LEN);
					while (m_pending_packets->packets.size() != 0)
					{
						auto m_current_packet = m_pending_packets->packets.begin();
						auto m_current_buffer = (*m_current_packet).packet;
						memcpy(&(m_current_buffer[0]), &temp_ethernet_header, sizeof(ethernet_hdr));
						sendPacket(m_current_buffer, inIface);
						m_pending_packets->packets.erase(m_current_packet);
					}
					m_arp.removeRequest(m_pending_packets);
					return;
				}
			}
			else return;
		}
		else return;
	}
	else if (ether_packet_type == ethertype_ip)
	{
		ip_hdr m_ip_header;
		if (packet.size() < (sizeof(ethernet_hdr) + sizeof(ip_hdr)))
		{
			std::cerr << "Received packet, but packet is smaller than the minimum size, ignoring" << std::endl;
			return;
		}
		memcpy(&m_ip_header, &(packet[sizeof(ethernet_hdr)]), sizeof(ip_hdr));
		auto temp_checksum = m_ip_header.ip_sum;
		m_ip_header.ip_sum = 0;
		if (temp_checksum != cksum(&m_ip_header, sizeof(m_ip_header))) return;
		if (m_ip_header.ip_ttl < 0) return;
		if (m_ip_header.ip_ttl == 0 && findIfaceByIp(m_ip_header.ip_dst) == nullptr) return;
		else if (findIfaceByIp(m_ip_header.ip_dst) != nullptr)
		{
			if (m_ip_header.ip_p != ip_protocol_icmp) return;
			else
			{
				print_hdrs(packet);
				icmp_hdr m_icmp_header;
				if (packet.size() < (sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)))
				{
					std::cerr << "Received packet, but packet is smaller than the minimum size, ignoring" << std::endl;
					return;
				}
				memcpy(&m_icmp_header, &(packet[sizeof(ethernet_hdr) + sizeof(ip_hdr)]), sizeof(icmp_hdr));
				if (m_icmp_header.icmp_type != 8) return;
				auto m_icmp_packet = packet;
				m_icmp_header.icmp_sum = 0;
				m_icmp_header.icmp_type = 0;
				memcpy(&(m_icmp_packet[sizeof(ethernet_hdr) + sizeof(ip_hdr)]), &m_icmp_header, sizeof(icmp_hdr));
				m_icmp_header.icmp_sum = cksum(&(m_icmp_packet[sizeof(ethernet_hdr) + sizeof(ip_hdr)]), (packet.size() - sizeof(m_ip_header) - sizeof(m_ethernet_header)));
				memcpy(&(m_icmp_packet[sizeof(ethernet_hdr) + sizeof(ip_hdr)]), &m_icmp_header, sizeof(icmp_hdr));
				m_ip_header.ip_ttl = 64;
				auto temp1 = m_ip_header.ip_dst;
				m_ip_header.ip_dst = m_ip_header.ip_src;
				m_ip_header.ip_src = temp1;
				m_ip_header.ip_sum = cksum(&m_ip_header, sizeof(m_ip_header));
				memcpy(&(m_icmp_packet[sizeof(ethernet_hdr)]), &m_ip_header, sizeof(ip_hdr));
				unsigned char temp2[6];
				memcpy(temp2, &m_ethernet_header.ether_dhost, 6);
				memcpy(&m_ethernet_header.ether_dhost, &m_ethernet_header.ether_shost, 6);
				memcpy(&m_ethernet_header.ether_shost, temp2, 6);
				memcpy(&(m_icmp_packet[0]), &m_ethernet_header, sizeof(ethernet_hdr));
				sendPacket(m_icmp_packet, iface->name);
				print_hdrs(m_icmp_packet);
			}
			//icmp
		}
		else
		{
			auto m_ip_packet = packet;
			m_ip_header.ip_ttl -= 1;
			m_ip_header.ip_sum = cksum(&m_ip_header, sizeof(m_ip_header));
			memcpy(&(m_ip_packet[sizeof(m_ethernet_header)]), &m_ip_header, sizeof(m_ip_header));
			uint32_t m_dst_ip = m_ip_header.ip_dst;
			RoutingTableEntry m_routing_entry = m_routingTable.lookup(m_dst_ip);
			uint32_t m_gw_ip = m_routing_entry.gw;
			const Interface* to_go_iface = findIfaceByName(m_routing_entry.ifName);
			auto cached_arp = m_arp.lookup(m_gw_ip);
			if (cached_arp != nullptr)
			{
				memcpy(m_ethernet_header.ether_shost, &((to_go_iface->addr)[0]), ETHER_ADDR_LEN);
				memcpy(m_ethernet_header.ether_dhost, &((cached_arp->mac)[0]), ETHER_ADDR_LEN);
				memcpy(&(m_ip_packet[0]), &m_ethernet_header, sizeof(m_ethernet_header));
				sendPacket(m_ip_packet, to_go_iface->name);
			}
			else
			{
				m_arp.queueRequest(m_gw_ip, m_ip_packet, to_go_iface->name);
			}
		}
	}
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
