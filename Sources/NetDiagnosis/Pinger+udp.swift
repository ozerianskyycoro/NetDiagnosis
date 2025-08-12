// Add this in a new file, e.g. Pinger+UDP.swift
import Darwin
import Foundation

extension Pinger {
    /// Async wrapper (keeps your style)
    public func udpProbe(
        hopLimit: UInt8,
        destPortBase: UInt16 = 33434,
        packetIndex: UInt16,
        packetSize: Int? = 64,
        timeOut: TimeInterval = 1.0,
        callback: @escaping PingCallback
    ) {
        self.serailQueue.async {
            let r = self.udpProbe(
                hopLimit: hopLimit,
                destPortBase: destPortBase,
                packetIndex: packetIndex,
                packetSize: packetSize,
                timeOut: timeOut
            )
            callback(r)
        }
    }

    /// Synchronous single UDP probe (IPv4). No refactors to existing class.
    public func udpProbe(
        hopLimit: UInt8,
        destPortBase: UInt16 = 33434,
        packetIndex: UInt16,
        packetSize: Int? = 64,
        timeOut: TimeInterval = 1.0
    ) -> PingResult {
        // Only IPv4 UDP is implemented here to stay minimal
        guard case .ipv4(let dstIPv4) = self.remoteAddr else {
            return .failed(POSIXError(.EAFNOSUPPORT))
        }

        // Sequence/identifier for correlation (sequence comes from caller)
        let currentID = self.icmpIdentifier
        let currentSeq = packetIndex

        // --- Build UDP send socket ---
        let sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        if sendSock < 0 { return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!)) }
        defer { close(sendSock) }

        // Bind a stable source port (use identifier) so we can match in ICMP payload
        do {
            var sa = sockaddr_in()
            sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sa.sin_family = sa_family_t(AF_INET)
            sa.sin_port = currentID.bigEndian // src port == identifier
            sa.sin_addr = in_addr(s_addr: INADDR_ANY.bigEndian)
            let res = withUnsafePointer(to: &sa) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(sendSock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if res != 0 { return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!)) }
        }

        // Set TTL / hop limit on send socket
        do {
            var ttl = Int32(hopLimit)
            if setsockopt(sendSock, IPPROTO_IP, IP_TTL, &ttl, socklen_t(MemoryLayout.size(ofValue: ttl))) < 0 {
                return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!))
            }
        }

        // --- Build ICMP receive socket (to read Time Exceeded / Dest Unreach) ---
        let recvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        if recvSock < 0 { return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!)) }
        defer { close(recvSock) }

        // Ask kernel to pass TTL in control msgs (reuses your getHopLimit logic)
        do {
            var on: Int32 = 1
            if setsockopt(recvSock, IPPROTO_IP, IP_RECVTTL, &on, socklen_t(MemoryLayout<Int32>.size)) < 0 {
                return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!))
            }
        }

        // Set receive timeout
        do {
            var tv = timeval(tv_sec: Int(timeOut), tv_usec: Int32((timeOut - floor(timeOut)) * 1_000_000))
            if setsockopt(recvSock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size)) < 0 {
                return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!))
            }
        }

        // --- Send UDP payload to destination: port = base + seq ---
        let payload = Data(repeating: 0x41, count: max(packetSize ?? 64, 1))
        let destPort = destPortBase &+ currentSeq
        do {
            var sa = sockaddr_in()
            sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sa.sin_family = sa_family_t(AF_INET)
            sa.sin_addr = in_addr(s_addr: dstIPv4.raw.bigEndian)
            sa.sin_port = destPort.bigEndian

            let sent = payload.withUnsafeBytes { buf -> Int in
                withUnsafePointer(to: &sa) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(sendSock, buf.baseAddress!, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            if sent == -1 { return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!)) }
        }

        // --- Receive ICMP reply ---
        var cmsgBuffer = [UInt8](repeating: 0, count: MemoryLayout<cmsghdr>.size + MemoryLayout<UInt32>.size)
        var recvBuffer = [UInt8](repeating: 0, count: 2048)
        var srcAddr = sockaddr_storage()

        let begin = Date()
        let receivedCount: Int = {
            var iov = iovec(iov_base: recvBuffer.withUnsafeMutableBytes { $0.baseAddress },
                            iov_len: recvBuffer.count)
            var msg = msghdr(
                msg_name: withUnsafeMutablePointer(to: &srcAddr) { $0 },
                msg_namelen: socklen_t(MemoryLayout.size(ofValue: srcAddr)),
                msg_iov: withUnsafeMutablePointer(to: &iov) { $0 },
                msg_iovlen: 1,
                msg_control: cmsgBuffer.withUnsafeMutableBytes { $0.baseAddress },
                msg_controllen: socklen_t(cmsgBuffer.count),
                msg_flags: 0
            )
            return withUnsafeMutablePointer(to: &msg) { recvmsg(recvSock, $0, 0) }
        }()

        // Timed out
        if receivedCount < 0 {
            if errno == EAGAIN { return .timeout(sequence: currentSeq, identifier: currentID) }
            return .failed(POSIXError(POSIXErrorCode(rawValue: errno)!))
        }

        let rtt = Date().timeIntervalSince(begin)

        // Hop limit (TTL of the ICMP packet we got)
        guard
            let hopLimit = cmsgBuffer.withUnsafeBytes({ ptr in
                getHopLimit(cmsgBufferPtr: UnsafeRawBufferPointer(start: ptr.baseAddress, count: cmsgBuffer.count))
            }),
            let icmpSrc = srcAddr.toIPAddr()
        else {
            // If we can't parse, treat it as timeout-like
            return .timeout(sequence: currentSeq, identifier: currentID)
        }

        // Parse ICMPv4 type/code and inner IPv4+UDP for matching
        let icmpPtr = UnsafeRawBufferPointer(start: recvBuffer, count: receivedCount)
        guard icmpPtr.count >= 8 else {
            return .timeout(sequence: currentSeq, identifier: currentID)
        }
        let icmpType = icmpPtr.load(as: UInt8.self)
        let icmpCode = icmpPtr.load(fromByteOffset: 1, as: UInt8.self)

        // ICMP payload: original IP header + first 8 bytes of original L4 (UDP)
        let payloadAfterHeader: UnsafeRawBufferPointer = {
            let h = 8 // minimal ICMPv4 header
            return UnsafeRawBufferPointer(rebasing: Slice(base: icmpPtr, bounds: h ..< icmpPtr.count))
        }()

        // Parse inner IPv4
        guard payloadAfterHeader.count >= MemoryLayout<ip>.size else {
            return .timeout(sequence: currentSeq, identifier: currentID)
        }
        let ipPtr = payloadAfterHeader.bindMemory(to: ip.self)
        let ipHeaderLen = Int(ipPtr[0].ip_hl * 4)
        guard ipPtr[0].ip_p == IPPROTO_UDP, payloadAfterHeader.count >= ipHeaderLen + 8 else {
            return .timeout(sequence: currentSeq, identifier: currentID)
        }
        let udpSlice = UnsafeRawBufferPointer(rebasing: Slice(base: payloadAfterHeader,
                                                             bounds: ipHeaderLen ..< payloadAfterHeader.count))
        let innerSrcPort = udpSlice.load(as: UInt16.self).bigEndian
        let innerDstPort = udpSlice.load(fromByteOffset: 2, as: UInt16.self).bigEndian

        // Match to our probe
        let wantDst = destPortBase &+ currentSeq
        guard innerSrcPort == currentID && innerDstPort == wantDst else {
            // Not our packet; behave like a timeout so the trace loop can retry/continue
            return .timeout(sequence: currentSeq, identifier: currentID)
        }

        // Build Response (from = hop router that generated ICMP)
        let resp = Response(
            len: receivedCount,
            from: icmpSrc,
            hopLimit: hopLimit,
            sequence: currentSeq,
            identifier: currentID,
            rtt: rtt
        )

        // Map types like traceroute:
        // 11 = Time Exceeded -> intermediate hop
        if icmpType == 11 { return .hopLimitExceeded(resp) }

        // 3/3 = Destination Unreachable / Port Unreachable -> reached destination
        if icmpType == 3 && icmpCode == 3 && icmpSrc == self.remoteAddr {
            return .pong(resp)
        }

        // Other unreachable codes: treat as intermediate hop
        if icmpType == 3 { return .hopLimitExceeded(resp) }

        // Fallback
        return .timeout(sequence: currentSeq, identifier: currentID)
    }
}