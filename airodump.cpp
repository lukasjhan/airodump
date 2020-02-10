#include <iostream>
#include <pcap.h>
#include <map>
#include <type_traits>

#include "802.11.hpp"

using namespace noname_core::network;

template <typename E>
constexpr auto to_underlying(E e) noexcept
{
	return static_cast<std::underlying_type_t<E>>(e);
}

int main()
{
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	int res;
	struct pcap_pkthdr* header;
	const u_char* packet;
	int count = 0;
	int total_bytes = 0;

	handle = pcap_open_offline("wpa-Induction.pcap", errbuf);
	if (handle == nullptr) return -1;

	do {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		//radiotap
		//802.11
		IEEE_802_11* ieee_802_11_header = 
			reinterpret_cast<IEEE_802_11*>(const_cast<u_char*>(packet));

		mac_address bss_id = ieee_802_11_header->IEEE_802_11.bss_id;
		int signal = ieee_802_11_header->radiotap.antenna_signal;
		float data_rate = ieee_802_11_header->radiotap.data_rate * 0.5f; // mbps

		std::cout << "BssID:" << bss_id << " Signal: " << signal << " Data rate: " << data_rate << "mbps" <<std::endl;

		if (ieee_802_11_header->IEEE_802_11.frame_control_field
			== to_underlying(IEEE_802_11_header::Type::Becon)) // becon, probe request, probe response
		{
			char ssid[20];

			//tag finding.
			for (int current = sizeof(IEEE_802_11) + 12; current < header->caplen - 4;) {
				byte* tag_id = const_cast<u_char*>(packet) + current;
				byte* tag_size = const_cast<u_char*>(packet) + current + 1;

				if (*tag_id == to_underlying(Tag::SSID)) {
					std::cout << "SSID: ";
					for (int i = 0; i < *tag_size; ++i) {
						std::cout << packet[current + 2 + i];
					}
					std::cout << std::endl;
				}
				else if (*tag_id == to_underlying(Tag::DS_Parameter_set)) {
					byte* channel = const_cast<u_char*>(packet) + current + 2;
					std::cout << "Channel: " << *(char*)channel << std::endl;
				}
				
				current = current + *tag_size + 2;
			}
		}
		else if (ieee_802_11_header->IEEE_802_11.frame_control_field
			== to_underlying(IEEE_802_11_header::Type::Probe_Req)) // becon, probe request, probe response
		{
			char ssid[20];

			//tag finding.
			for (int current = sizeof(IEEE_802_11); current < header->caplen - 4;) {
				byte* tag_id = const_cast<u_char*>(packet) + current;
				byte* tag_size = const_cast<u_char*>(packet) + current + 1;

				if (*tag_id == to_underlying(Tag::SSID)) {
					std::cout << "SSID: ";
					for (int i = 0; i < *tag_size; ++i) {
						std::cout << packet[current + 2 + i];
					}
					std::cout << std::endl;
				}
				else if (*tag_id == to_underlying(Tag::DS_Parameter_set)) {
					byte* channel = const_cast<u_char*>(packet) + current + 2;
					std::cout << "Channel: " << *(char*)channel << std::endl;
				}

				current = current + *tag_size + 2;
			}
		}
		else if (ieee_802_11_header->IEEE_802_11.frame_control_field
			== to_underlying(IEEE_802_11_header::Type::Probe_Res)) // becon, probe request, probe response
		{
			char ssid[20];

			//tag finding.
			for (int current = sizeof(IEEE_802_11) + 12; current < header->caplen - 4;) {
				byte* tag_id = const_cast<u_char*>(packet) + current;
				byte* tag_size = const_cast<u_char*>(packet) + current + 1;

				if (*tag_id == to_underlying(Tag::SSID)) {
					std::cout << "SSID: ";
					for (int i = 0; i < *tag_size; ++i) {
						std::cout << packet[current + 2 + i];
					}
					std::cout << std::endl;
				}
				else if (*tag_id == to_underlying(Tag::DS_Parameter_set)) {
					byte* channel = const_cast<u_char*>(packet) + current + 2;
					std::cout << "Channel: " << *(char*)channel << std::endl;
				}

				current = current + *tag_size + 2;
			}
		}
		else if (ieee_802_11_header->IEEE_802_11.frame_control_field
			== to_underlying(IEEE_802_11_header::Type::Data)) // becon, probe request, probe response
		{
			std::cout << "Data" << std::endl;
		}

		count++;
		total_bytes += header->caplen;

	} while (1);

	printf("total packet: %d, total bytes: %d\n", count, total_bytes);
	pcap_close(handle);
	return 0;
}