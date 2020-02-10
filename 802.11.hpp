#pragma once
#include <cstdint>

#include "network/ethernet.hpp"

namespace noname_core {

	using byte = uint8_t;
	using word = uint16_t;
	using dword = uint32_t;
	using qword = uint64_t;

	namespace network {
#pragma pack(1)
		struct radiotap_header {
			byte revision;
			byte pad;
			word length;
			dword present_flags;
			
			byte flags;
			byte data_rate;
			word channel_frequency;
			word channel_flag;

			word signal_quality;
			byte antenna;
			byte antenna_signal;
			word rx_flag;
		};

		struct IEEE_802_11_header {
			byte frame_control_field;
			byte flag;
			word duration;
			mac_address reciver;
			mac_address transmitter;
			mac_address bss_id;

			word fragment_sequence_number;

			enum class Type : byte {
				Becon = 0x80,
				Data = 0x08,
				Probe_Req = 0x40,
				Probe_Res = 0x50
			};
		};

		struct IEEE_802_11_management {
			qword timestamp;
			word becon_interval;
			word capabilities_info;
		};

		enum class Tag : byte {
			SSID = 0x00,
			Supported_Rate = 0x01,
			DS_Parameter_set = 0x03,
			Traffic_Indication_Map = 0x05,
			ERP_INFO = 0x2A,
			ERP_INFO_2 = 0x2F,
			RSN_INFO = 0x30,
			Extended_Supported_Rates = 0x32,
			Vender_Spec = 0xDD
		};

		struct Tag_Info {
			byte tag;
			std::vector<byte> tag_data;
		};

		struct IEEE_802_11 {
			radiotap_header radiotap;
			IEEE_802_11_header IEEE_802_11;
		};
	}
}