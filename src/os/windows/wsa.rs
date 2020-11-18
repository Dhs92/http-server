use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::io::Error as IoError;
use std::process::exit;
use winapi::{
    ctypes::{c_int, c_uchar, c_ulong, c_ushort},
    shared::{
        guiddef::GUID,
        minwindef::DWORD,
        ws2def::{AF_INET, IPPROTO_TCP},
    },
    um::{
        winsock2::WSAPROTOCOL_INFOA,
        winsock2::{
            WSADuplicateSocketA, WSASocketA, LPWSAPROTOCOL_INFOA, SOCK_STREAM, WSAPROTOCOLCHAIN,
            WSA_FLAG_OVERLAPPED,
        },
    },
};

// "wrappers" that will allow use of derived Ser/De
#[derive(Serialize, Deserialize)]
pub struct WSAProcessInfo {
    service_flags: [DWORD; 5],
    provider_id: Guid,
    catalogue_entry_id: DWORD,
    protocol_chain: WSAProtocolChain,
    version: c_int,
    address_family: c_int,
    max_sock_addr: c_int,
    min_sock_addr: c_int,
    socket_type: c_int,
    i_protocol: c_int,
    protocol_max_offset: c_int,
    network_byte_order: c_int,
    security_scheme: c_int,
    message_size: DWORD,
    provider_reserved: DWORD,
    sz_protocol: String, // convert to CHAR when converting back
}

impl From<WSAPROTOCOL_INFOA> for WSAProcessInfo {
    fn from(info: WSAPROTOCOL_INFOA) -> Self {
        let sz_protocol = info.szProtocol.iter().map(|&c| c as u8).collect();
        let sz_protocol = String::from_utf8(sz_protocol).unwrap(); // WinAPI should provide valid ASCII, which is also valid UTF-8

        Self {
            service_flags: [
                info.dwServiceFlags1,
                info.dwServiceFlags2,
                info.dwServiceFlags3,
                info.dwServiceFlags4,
                info.dwServiceFlags5,
            ],
            provider_id: info.ProviderId.into(),
            catalogue_entry_id: info.dwCatalogEntryId,
            protocol_chain: info.ProtocolChain.into(),
            version: info.iVersion,
            address_family: info.iAddressFamily,
            max_sock_addr: info.iMaxSockAddr,
            min_sock_addr: info.iMinSockAddr,
            socket_type: info.iSocketType,
            i_protocol: info.iProtocol,
            protocol_max_offset: info.iProtocolMaxOffset,
            network_byte_order: info.iNetworkByteOrder,
            security_scheme: info.iSecurityScheme,
            message_size: info.dwMessageSize,
            provider_reserved: info.dwProviderReserved,
            sz_protocol,
        }
    }
}

impl From<WSAProcessInfo> for WSAPROTOCOL_INFOA {
    fn from(info: WSAProcessInfo) -> Self {
        let mut sz_protocol = [0; 256];
        for (c1, c2) in info
            .sz_protocol
            .chars()
            .map(|c| c as i8)
            .zip(sz_protocol.iter_mut())
        {
            *c2 = c1;
        }

        Self {
            dwServiceFlags1: info.service_flags[0],
            dwServiceFlags2: info.service_flags[1],
            dwServiceFlags3: info.service_flags[2],
            dwServiceFlags4: info.service_flags[3],
            dwServiceFlags5: info.service_flags[4],
            ProviderId: info.provider_id.into(),
            dwCatalogEntryId: info.catalogue_entry_id,
            ProtocolChain: info.protocol_chain.into(),
            iVersion: info.version,
            iAddressFamily: info.address_family,
            iMaxSockAddr: info.max_sock_addr,
            iMinSockAddr: info.min_sock_addr,
            iSocketType: info.socket_type,
            iProtocol: info.i_protocol,
            iProtocolMaxOffset: info.protocol_max_offset,
            iNetworkByteOrder: info.network_byte_order,
            iSecurityScheme: info.security_scheme,
            dwMessageSize: info.message_size,
            dwProviderReserved: info.provider_reserved,
            szProtocol: sz_protocol,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Guid {
    data1: c_ulong,
    data2: c_ushort,
    data3: c_ushort,
    data4: [c_uchar; 8],
}

impl From<GUID> for Guid {
    fn from(guid: GUID) -> Self {
        Self {
            data1: guid.Data1,
            data2: guid.Data2,
            data3: guid.Data3,
            data4: guid.Data4,
        }
    }
}

impl From<Guid> for GUID {
    fn from(guid: Guid) -> Self {
        Self {
            Data1: guid.data1,
            Data2: guid.data2,
            Data3: guid.data3,
            Data4: guid.data4,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct WSAProtocolChain {
    chain_len: c_int,
    chain_entries: [DWORD; 7],
}

impl From<WSAPROTOCOLCHAIN> for WSAProtocolChain {
    fn from(proto_chain: WSAPROTOCOLCHAIN) -> Self {
        Self {
            chain_len: proto_chain.ChainLen,
            chain_entries: proto_chain.ChainEntries,
        }
    }
}

impl From<WSAProtocolChain> for WSAPROTOCOLCHAIN {
    fn from(proto_chain: WSAProtocolChain) -> Self {
        Self {
            ChainLen: proto_chain.chain_len,
            ChainEntries: proto_chain.chain_entries,
        }
    }
}

pub fn begin_socket_handoff(socket: usize, pid: u32, info: LPWSAPROTOCOL_INFOA) {
    if unsafe { WSADuplicateSocketA(socket, pid, info) } != 0 {
        log::error!(
            "WSADuplicateSocket returned non-zero value: {}",
            IoError::last_os_error()
        );
        exit(15)
    }
}

pub fn socket_handoff(info: LPWSAPROTOCOL_INFOA) -> u64 {
    unsafe {
        WSASocketA(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP.try_into().unwrap(),
            info,
            0, // 0 means do nothing
            WSA_FLAG_OVERLAPPED,
        )
        .try_into()
        .unwrap()
    }
}
