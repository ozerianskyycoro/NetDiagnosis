//  Pinger.swift (ICMP + UDP traceroute mode)
//
//  Adds ProbeMode.udp(portBase:) to support UDP-style traceroute (like macOS default),
//  while keeping original ICMP Echo behavior intact.
//
//  Notes:
//  - UDP mode implemented for IPv4. ICMP Echo works for IPv4/IPv6 as before.
//  - In UDP mode we send UDP datagrams with a set TTL and listen on a RAW-ICMP socket
//    for Time Exceeded / Port Unreachable. We encode identifier in source UDP port and
//    sequence in destination UDP port (portBase + seq) for matching.
//
//  Created by ChatGPT, 2025/08/12

import Darwin
import Foundation

// swiftlint: disable type_body_length force_unwrapping function_body_length
public class Pinger {
    // MARK: - Public Types
    public struct Response {
        public var len: Int
        public var from: IPAddr
        public var hopLimit: UInt8
        public var sequence: UInt16
        public var identifier: UInt16
        public var rtt: TimeInterval
    }

    public enum PingResult {
        case pong(_: Response)
        case hopLimitExceeded(_: Response)
        case timeout(sequence: UInt16, identifier: UInt16)
        case failed(_: Error)
    }

    public enum ProbeMode {
        case icmpEcho              // original behavior
        case udp(portBase: UInt16) // UDP traceroute (IPv4)
    }

    public typealias PingCallback = (_ result: PingResult) -> Void

    // MARK: - Public Properties
    public let icmpIdentifier = UInt16.random(in: 1..<UInt16.max)
    var icmpSequence: UInt16 = 0

    public let remoteAddr: IPAddr
    public let mode: ProbeMode

    // Sockets: in icmpEcho, sendSock == recvSock (ICMP). In udp, separate sockets.
    let sendSock: Int32
    let recvSock: Int32

    let serailQueue = DispatchQueue(label: "Pinger Queue", qos: .userInteractive)

    // MARK: - Init/Deinit
    public init(remoteAddr: IPAddr, mode: ProbeMode = .icmpEcho) throws {
        self.remoteAddr = remoteAddr
        self.mode = mode

        switch mode {
        case .icmpEcho:
            self.sendSock = socket(Int32(remoteAddr.addressFamily.raw), SOCK_DGRAM,
                                   { () -> Int32 in
                                       switch remoteAddr {
                                       case .ipv4: return IPPROTO_ICMP
                                       case .ipv6: return IPPROTO_ICMPV6
                                       }
                                   }())
            guard self.sendSock > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
            self.recvSock = self.sendSock
            try self.setReceiveHopLimit(true, sock: self.recvSock)

        case .udp:
            // UDP send socket (IPv4 only here)
            self.sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            guard self.sendSock > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }

            // Bind a stable source port to carry identifier for matching
            var sa = sockaddr_in()
            sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sa.sin_family = sa_family_t(AF_INET)
            sa.sin_port = icmpIdentifier.bigEndian
            sa.sin_addr = in_addr(s_addr: INADDR_ANY.bigEndian)
            let bindRes = withUnsafePointer(to: &sa) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(self.sendSock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if bindRes != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }

            // ICMP receive socket (to read Time Exceeded / Dest Unreachable)
            self.recvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
            guard self.recvSock > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
            try self.setReceiveHopLimit(true, sock: self.recvSock)
        }
    }

    deinit {
        if sendSock != recvSock { close(recvSock) }
        close(sendSock)
    }

    // MARK: - Public API
    public func ping(
        packetSize: Int? = nil,
        hopLimit: UInt8? = nil,
        timeOut: TimeInterval = 1.0,
        callback: @escaping PingCallback
    ) {
        self.serailQueue.async {
            let result = self.ping(packetSize: packetSize, hopLimit: hopLimit, timeOut: timeOut)
            callback(result)
        }
    }

    // MARK: - Core probe
    func ping(
        packetSize: Int?,
        hopLimit: UInt8?,
        timeOut: TimeInterval
    ) -> PingResult {
        let currentID = self.icmpIdentifier
        let currentSeq = self.icmpSequence

        do {
            var begin = Date()
            var timeLeft = timeOut

            // Send
            try send(icmpIdentifier: currentID, icmpSeq: currentSeq, hopLimit: hopLimit, packetSize: packetSize)
            self.icmpSequence &+= 1
            timeLeft -= Date().timeIntervalSince(begin)

            // Receive loop
            try self.setReceiveTimeout(timeLeft, sock: self.recvSock)
            repeat {
                if timeLeft <= 0 {
                    return .timeout(sequence: currentSeq, identifier: currentID)
                } else {
                    try self.setReceiveTimeout(timeLeft, sock: self.recvSock)
                }

                var cmsgBuffer = [UInt8](repeating: 0, count: MemoryLayout<cmsghdr>.size + MemoryLayout<UInt32>.size)
                var recvBuffer = [UInt8](repeating: 0, count: 2048)
                var srcAddr = sockaddr_storage()

                begin = Date()
                let receivedCount = try receive(recvBuffer: &recvBuffer, cmsgBuffer: &cmsgBuffer, srcAddr: &srcAddr, sock: self.recvSock)
                timeLeft -= Date().timeIntervalSince(begin)

                // Parse hop limit, source
                guard
                    let hopLimit = cmsgBuffer.withUnsafeBytes({ ptr in
                        getHopLimit(cmsgBufferPtr: UnsafeRawBufferPointer(start: ptr.baseAddress, count: cmsgBuffer.count))
                    }),
                    let srcIP = srcAddr.toIPAddr()
                else { continue }

                switch mode {
                case .icmpEcho:
                    // Extract ICMP packet (for v4: from inner after IPv4 header; for v6: direct)
                    guard let icmpPacketPtr = recvBuffer.withUnsafeBytes({ ptr -> UnsafeRawBufferPointer? in
                        switch self.remoteAddr.addressFamily {
                        case .ipv4:
                            return getICMPPacketPtr(ipPacketPtr: UnsafeRawBufferPointer(start: ptr.baseAddress, count: receivedCount))
                        case .ipv6:
                            return UnsafeRawBufferPointer(start: ptr.baseAddress, count: receivedCount)
                        }
                    }) else { continue }

                    if verifyICMPEcho(icmpPacketPtr: icmpPacketPtr, expectedIdentifier: currentID, expectedSequence: currentSeq) == false {
                        continue
                    }

                    let icmpHeaderPtr = icmpPacketPtr.bindMemory(to: icmp6_hdr.self)
                    let response = Response(len: icmpPacketPtr.count, from: srcIP, hopLimit: hopLimit, sequence: currentSeq, identifier: currentID, rtt: timeOut - timeLeft)

                    if icmpHeaderPtr[0].icmp6_type == icmpTypeHopLimitExceeded {
                        return .hopLimitExceeded(response)
                    } else if icmpHeaderPtr[0].icmp6_type == icmpTpeEchoReplay && srcIP == self.remoteAddr {
                        return .pong(response)
                    }

                case .udp(let portBase):
                    // In UDP mode, we read ICMP errors containing the original IP+UDP we sent.
                    // For IPv4 only in this sample.
                    // recvBuffer contains IPv4 + ICMP header + payload (original IPv4+UDP)
                    let icmpPtr = recvBuffer.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> UnsafeRawBufferPointer in
                        return UnsafeRawBufferPointer(start: ptr.baseAddress, count: receivedCount)
                    }

                    // Minimal ICMPv4 view: first bytes are type/code/cksum...
                    guard icmpPtr.count >= 8 else { continue }
                    let icmpType = icmpPtr.load(as: UInt8.self)
                    let icmpCode = icmpPtr.load(fromByteOffset: 1, as: UInt8.self)
                    let payload = payloadAfterICMP(icmpPtr)

                    guard let udpMatch = parseInnerIPv4AndUDP(payload) else { continue }

                    // Our matching rule: srcPort == identifier, dstPort == portBase + seq
                    let wantDst = portBase &+ currentSeq
                    let match = (udpMatch.srcPort == currentID && udpMatch.dstPort == wantDst)
                    if !match { continue }

                    let response = Response(len: icmpPtr.count, from: srcIP, hopLimit: hopLimit, sequence: currentSeq, identifier: currentID, rtt: timeOut - timeLeft)

                    // Time Exceeded -> intermediate hop
                    if icmpType == 11 /* Time Exceeded */ {
                        return .hopLimitExceeded(response)
                    }

                    // Destination Unreachable / Port Unreachable from target means reached dest
                    if icmpType == 3 /* Dest Unreach */ && icmpCode == 3 /* Port Unreach */ && srcIP == self.remoteAddr {
                        return .pong(response)
                    }

                    // Other unreachable codes: treat as hop (common traceroute behavior), or failed
                    if icmpType == 3 {
                        return .hopLimitExceeded(response)
                    }
                }
            } while true
        } catch let error {
            if (error as? POSIXError)?.code == POSIXError.EAGAIN {
                return .timeout(sequence: currentSeq, identifier: currentID)
            }
            return .failed(error)
        }
    }

    // MARK: - Send helpers
    func send(
        icmpIdentifier: UInt16,
        icmpSeq: UInt16,
        hopLimit: UInt8? = nil,
        packetSize: Int? = nil
    ) throws {
        if let hopLimit = hopLimit {
            try self.setHopLimit(UInt32(hopLimit), sock: self.sendSock)
        }

        switch mode {
        case .icmpEcho:
            let packetData = self.createEchoRequestPacket(identifier: icmpIdentifier, sequence: icmpSeq, packetSize: packetSize)
            try sendTo(addr: self.remoteAddr, data: packetData, sock: self.sendSock)

        case .udp(let portBase):
            let size = max(packetSize ?? 64, 1)
            let payload = Data(repeating: 0x41, count: size)
            let destPort = portBase &+ icmpSeq
            try sendUDP(to: self.remoteAddr, destPort: destPort, data: payload, sock: self.sendSock)
        }
    }

    private func sendTo(addr: IPAddr, data: Data, sock: Int32) throws {
        let sentCount = data.withUnsafeBytes { buf in
            var storage = addr.createSockStorage()
            return withUnsafePointer(to: &storage) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(sock, buf.baseAddress!, buf.count, 0, $0, socklen_t($0.pointee.sa_len))
                }
            }
        }
        if sentCount == -1 { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
    }

    private func sendUDP(to addr: IPAddr, destPort: UInt16, data: Data, sock: Int32) throws {
        switch addr {
        case .ipv4(let a4):
            var sa = sockaddr_in()
            sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sa.sin_family = sa_family_t(AF_INET)
            sa.sin_addr = in_addr(s_addr: a4.raw.bigEndian)
            sa.sin_port = destPort.bigEndian
            let sent = data.withUnsafeBytes { buf -> Int in
                withUnsafePointer(to: &sa) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(sock, buf.baseAddress!, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            if sent == -1 { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
        case .ipv6:
            throw POSIXError(.EAFNOSUPPORT) // TODO: add IPv6 UDP traceroute if needed
        }
    }

    // MARK: - Receive helpers
    func receive(
        recvBuffer: inout [UInt8],
        cmsgBuffer: inout [UInt8],
        srcAddr: inout sockaddr_storage,
        sock: Int32
    ) throws -> Int {
        var iov = iovec(iov_base: recvBuffer.withUnsafeMutableBytes { $0.baseAddress }, iov_len: recvBuffer.count)
        var msghdr = msghdr(
            msg_name: withUnsafeMutablePointer(to: &srcAddr) { $0 },
            msg_namelen: socklen_t(MemoryLayout.size(ofValue: srcAddr)),
            msg_iov: withUnsafeMutablePointer(to: &iov) { $0 },
            msg_iovlen: 1,
            msg_control: cmsgBuffer.withUnsafeMutableBytes { $0.baseAddress },
            msg_controllen: socklen_t(cmsgBuffer.count),
            msg_flags: 0
        )
        let receivedCount = withUnsafeMutablePointer(to: &msghdr) { ptr in recvmsg(sock, ptr, 0) }
        guard receivedCount >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
        return receivedCount
    }

    // MARK: - CMSG & parsing
    func getHopLimit(cmsgBufferPtr: UnsafeRawBufferPointer) -> UInt8? {
        let cmsghdrPtr = cmsgBufferPtr.bindMemory(to: cmsghdr.self)
        if cmsghdrPtr.count == 0 { return nil }
        if cmsghdrPtr[0].cmsg_level == self.ipProtocol && cmsghdrPtr[0].cmsg_type == self.receiveHopLimitOption {
            return cmsgBufferPtr.load(fromByteOffset: MemoryLayout<cmsghdr>.size, as: UInt8.self)
        } else {
            return nil
        }
    }

    func verifyICMPEcho(icmpPacketPtr: UnsafeRawBufferPointer, expectedIdentifier: UInt16, expectedSequence: UInt16) -> Bool {
        let icmpHeaderSize = MemoryLayout<icmp6_hdr>.size
        let icmpHeaderPtr = icmpPacketPtr.bindMemory(to: icmp6_hdr.self)
        if icmpHeaderPtr[0].icmp6_type == self.icmpTypeHopLimitExceeded {
            let payloadPtr = UnsafeRawBufferPointer(rebasing: Slice(base: icmpPacketPtr, bounds: icmpHeaderSize ..< icmpPacketPtr.count))
            guard let echoRequestPacketPtr = getICMPPacketPtr(ipPacketPtr: payloadPtr) else { return false }
            let echoRequestHeader = echoRequestPacketPtr.bindMemory(to: icmp6_hdr.self)
            return echoRequestHeader[0].icmp6_type == self.icmpTypeEchoRequst &&
                   echoRequestHeader[0].icmp6_dataun.icmp6_un_data16.0 == expectedIdentifier &&
                   echoRequestHeader[0].icmp6_dataun.icmp6_un_data16.1 == expectedSequence
        }
        return icmpHeaderPtr[0].icmp6_type == self.icmpTpeEchoReplay &&
               icmpHeaderPtr[0].icmp6_dataun.icmp6_un_data16.0 == expectedIdentifier &&
               icmpHeaderPtr[0].icmp6_dataun.icmp6_un_data16.1 == expectedSequence
    }

    func getICMPPacketPtr(ipPacketPtr: UnsafeRawBufferPointer) -> UnsafeRawBufferPointer? {
        guard let ipVer: IPAddr.AddressFamily = {
            let ver: UInt8 = (ipPacketPtr[0] & 0xF0) >> 4
            if ver == 0x04 { return .ipv4 }
            if ver == 0x06 { return .ipv6 }
            return nil
        }() else { return nil }

        switch ipVer {
        case .ipv4:
            let ipv4Ptr = ipPacketPtr.bindMemory(to: ip.self)
            if ipv4Ptr[0].ip_p == IPPROTO_ICMP {
                let headerLen = Int(ipv4Ptr[0].ip_hl * 4)
                return UnsafeRawBufferPointer(rebasing: Slice(base: ipPacketPtr, bounds: headerLen ..< ipPacketPtr.count))
            }
        case .ipv6:
            let ipv6Ptr = ipPacketPtr.bindMemory(to: ip6_hdr.self)
            if ipv6Ptr[0].ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6 {
                return UnsafeRawBufferPointer(rebasing: Slice(base: ipPacketPtr, bounds: 40 ..< ipPacketPtr.count))
            }
        }
        return nil
    }

    // ICMP payload immediately after header (IPv4 variant used for UDP mode)
    private func payloadAfterICMP(_ icmpPacket: UnsafeRawBufferPointer) -> UnsafeRawBufferPointer {
        let h = 8 // minimal ICMPv4 header size
        guard icmpPacket.count >= h else { return UnsafeRawBufferPointer(start: nil, count: 0) }
        return UnsafeRawBufferPointer(rebasing: Slice(base: icmpPacket, bounds: h ..< icmpPacket.count))
    }

    // Parse inner IPv4 + UDP header from ICMP payload for UDP traceroute matching
    private func parseInnerIPv4AndUDP(_ payload: UnsafeRawBufferPointer) -> (srcPort: UInt16, dstPort: UInt16)? {
        guard payload.count >= MemoryLayout<ip>.size else { return nil }
        let ipPtr = payload.bindMemory(to: ip.self)
        let ipHeaderLen = Int(ipPtr[0].ip_hl * 4)
        guard ipPtr[0].ip_p == IPPROTO_UDP, payload.count >= ipHeaderLen + 8 else { return nil }
        let udpSlice = UnsafeRawBufferPointer(rebasing: Slice(base: payload, bounds: ipHeaderLen ..< payload.count))
        let srcPort = udpSlice.load(as: UInt16.self).bigEndian
        let dstPort = udpSlice.load(fromByteOffset: 2, as: UInt16.self).bigEndian
        return (srcPort, dstPort)
    }

    // MARK: - Timeouts & socket options
    private var ipProtocol: Int32 {
        switch remoteAddr.addressFamily {
        case .ipv4: return IPPROTO_IP
        case .ipv6: return IPPROTO_IPV6
        }
    }

    private var receiveHopLimitOption: Int32 {
        switch remoteAddr.addressFamily {
        case .ipv4: return IP_RECVTTL
        case .ipv6: return IPV6_RECVHOPLIMIT
        }
    }

    func setReceiveTimeout(_ timeout: TimeInterval, sock: Int32) throws {
        var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - floor(timeout)) * 1_000_000))
        if setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size)) < 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }

    func setReceiveHopLimit(_ enable: Bool, sock: Int32) throws {
        var on: Int32 = enable ? 1 : 0
        if setsockopt(sock, ipProtocol, receiveHopLimitOption, &on, socklen_t(MemoryLayout<Int32>.size)) < 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }

    func setHopLimit(_ hop: UInt32, sock: Int32) throws {
        switch remoteAddr.addressFamily {
        case .ipv4:
            var ttl = Int32(hop)
            if setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, socklen_t(MemoryLayout<Int32>.size)) < 0 {
                throw POSIXError(POSIXErrorCode(rawValue: errno)!)
            }
        case .ipv6:
            var h = Int32(hop)
            if setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &h, socklen_t(MemoryLayout<Int32>.size)) < 0 {
                throw POSIXError(POSIXErrorCode(rawValue: errno)!)
            }
        }
    }

    // MARK: - Packet builders
    func createEchoRequestPacket(identifier: UInt16, sequence: UInt16, packetSize: Int?) -> Data {
        let packetSize = packetSize ?? 64
        let icmpHeaderSize = MemoryLayout<icmp6_hdr>.size
        assert(packetSize > icmpHeaderSize)

        var packetData = Data(repeating: 0, count: packetSize)
        for idx in icmpHeaderSize ..< packetData.count {
            packetData[idx] = UInt8.random(in: 0x21 ... 0x7E)
        }

        var time = Date().timeIntervalSince1970.toTimeValue()
        let timeSize = MemoryLayout.size(ofValue: time)
        if packetData.count >= (icmpHeaderSize + timeSize) {
            packetData.replaceSubrange(icmpHeaderSize ..< (icmpHeaderSize + timeSize), with: &time, count: timeSize)
        }

        packetData.withUnsafeMutableBytes { rawPtr in
            let icmpHeaddrPtr = rawPtr.bindMemory(to: icmp6_hdr.self)
            icmpHeaddrPtr[0].icmp6_type = UInt8(self.icmpTypeEchoRequst)
            icmpHeaddrPtr[0].icmp6_code = 0
            icmpHeaddrPtr[0].icmp6_cksum = 0
            icmpHeaddrPtr[0].icmp6_dataun.icmp6_un_data16 = (identifier, sequence)
            icmpHeaddrPtr[0].icmp6_cksum = rawPtr.withUnsafeBytes { ptr in checkSum(ptr: ptr) }
        }
        return packetData
    }

    // MARK: - ICMP constants/helpers (v4/v6 shared where possible)
    var icmpTypeHopLimitExceeded: UInt8 { remoteAddr.addressFamily == .ipv6 ? 3 /* Time Exceeded */ : 11 }
    var icmpTypeEchoRequst: UInt8 { remoteAddr.addressFamily == .ipv6 ? 128 : 8 }
    var icmpTpeEchoReplay: UInt8 { remoteAddr.addressFamily == .ipv6 ? 129 : 0 }

    // Internet checksum
    func checkSum(ptr: UnsafeRawBufferPointer) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < ptr.count {
            let word = UInt16(ptr.load(fromByteOffset: i, as: UInt16.self))
            sum &+= UInt32(word)
            i += 2
        }
        if i < ptr.count {
            sum &+= UInt32(UInt16(ptr[i]) << 8)
        }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
        return ~UInt16(sum & 0xFFFF)
    }
}

// MARK: - Utilities expected from existing codebase
private extension sockaddr_storage {
    func toIPAddr() -> IPAddr? {
        var ss = self
        if ss.ss_family == sa_family_t(AF_INET) {
            return withUnsafePointer(to: &ss) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    let addr = sin.pointee.sin_addr.s_addr.bigEndian
                    return .ipv4(.init(raw: addr))
                }
            }
        } else if ss.ss_family == sa_family_t(AF_INET6) {
            // Assuming IPAddr has a matching IPv6 factory
            return nil // implement if needed in your codebase
        }
        return nil
    }
}

private extension TimeInterval {
    func toTimeValue() -> time_t { return time_t(self) }
}

// NOTE: Assumes your IPAddr type has helpers:
// - var addressFamily: AddressFamily { .ipv4 / .ipv6 }
// - func createSockStorage() -> sockaddr_storage
// - static func == (lhs: IPAddr, rhs: IPAddr) -> Bool
// - nested AddressFamily enum with raw (Int32 AF family)
// - case ipv4(_), case ipv6(_)
