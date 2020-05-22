/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::handle_arpreq(std::shared_ptr<ArpRequest> req)
{
	time_point now = steady_clock::now();
	if ((now - req->timeSent) > seconds(1))
	{
		if (req->nTimesSent >= 5) removeRequest(req);
		else
		{
			uint32_t arp_req_ip = req->ip;
			RoutingTableEntry m_routing_entry = m_router.getRoutingTable().lookup(arp_req_ip);
			const Interface* m_interface = m_router.findIfaceByName(m_routing_entry.ifName);
			Buffer m_arp_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
			ethernet_hdr m_ethernet_header;
			arp_hdr m_arp_header;
			memset(m_ethernet_header.ether_dhost, 0xFF, ETHER_ADDR_LEN);
			memcpy(m_ethernet_header.ether_shost, &((m_interface->addr)[0]), ETHER_ADDR_LEN);
			m_ethernet_header.ether_type = htons(ethertype_arp);
			m_arp_header.arp_hrd = htons(arp_hrd_ethernet);
			m_arp_header.arp_pro = htons(ethertype_ip);
			m_arp_header.arp_hln = ETHER_ADDR_LEN;
			m_arp_header.arp_pln = 4;
			m_arp_header.arp_op = htons(arp_op_request);
			m_arp_header.arp_sip = m_interface->ip;
			m_arp_header.arp_tip = arp_req_ip;
			memcpy(m_arp_header.arp_sha, &((m_interface->addr)[0]), ETHER_ADDR_LEN);
			memset(m_arp_header.arp_tha, 0xFF, ETHER_ADDR_LEN);
			memcpy(&(m_arp_packet[0]), &m_ethernet_header, sizeof(m_ethernet_header));
			memcpy(&(m_arp_packet[sizeof(m_ethernet_header)]), &m_arp_header, sizeof(m_arp_header));
			m_router.sendPacket(m_arp_packet, m_interface->name);
			req->timeSent = now;
			req->nTimesSent++;
		}
	}
}
	
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
	auto current = m_arpRequests.begin();
	while (current != m_arpRequests.end())
	{
		auto next = current;
		next++;
		handle_arpreq(*current);
		current = next;
	}
	auto iter = m_cacheEntries.begin();
	while (iter != m_cacheEntries.end())
	{
		if ((*iter)->isValid == false) iter = m_cacheEntries.erase(iter);
		else iter++;
	}
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
