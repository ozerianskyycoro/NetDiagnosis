```swift
//
//  Pinger+Trace.swift
//  
//
//  Created by Jerry on 2023/2/22.
//

import Foundation
import OrderedCollections
import Darwin

extension Pinger {
    public enum TraceStatus {
        case traced
        case maxHopExceeded
        case stoped
        case failed(_: Error)
    }
    
    public struct TracePacketResult {
        public var pingResult: PingResult
        public var hop: UInt8
        public var packetIndex: UInt8
    }
    
    public enum UDPTraceStatus {
        case traced
        case maxHopExceeded
        case stopped
        case failed(_: Error)
    }
    
    public struct UDPTracePacketResult {
        public var pingResult: PingResult
        public var hop: UInt8
        public var packetIndex: UInt8
    }
    
    public func trace(
        packetSize: Int? = nil,
        initHop: UInt8 = 1,
        maxHop: UInt8 = 64,
        packetCount: UInt8 = 3,
        timeOut: TimeInterval = 1.0,
        tracePacketCallback: ((
            _ packetResult: TracePacketResult,
            _ stopTrace: (_: Bool) -> Void
        ) -> Void)?,
        onTraceComplete: ((
            _ result: OrderedDictionary<UInt8, [PingResult]>,
            _ status: TraceStatus
        ) -> Void)?
    ) {
        // swiftlint: disable closure_body_length
        self.serialQueue.async {
            var traceResults: OrderedDictionary<UInt8, [PingResult]> = [:]
            for hopLimit in initHop ... maxHop {
                for packetIdx in 0 ..< packetCount {
                    let pingResult = self.ping(
                        packetSize: packetSize,
                        hopLimit: hopLimit,
                        timeOut: timeOut
                    )
                    var hopResults = traceResults[hopLimit] ?? []
                    hopResults.append(pingResult)
                    traceResults[hopLimit] = hopResults
                    var isStop = false
                    let packetResult = TracePacketResult(
                        pingResult: pingResult,
                        hop: hopLimit,
                        packetIndex: packetIdx
                    )
                    tracePacketCallback?(packetResult) { isStop = $0 }
                    switch pingResult {
                    case .pong:
                        if packetIdx == packetCount - 1 {
                            onTraceComplete?(traceResults, .traced)
                            return
                        }
                    case .failed(let error):
                        onTraceComplete?(traceResults, .failed(error))
                        return
                    default:
                        break
                    }
                    if isStop {
                        onTraceComplete?(traceResults, .stoped)
                        return
                    }
                }
            }
            onTraceComplete?(traceResults, .maxHopExceeded)
        }
    }

    public func udpTrace(
        packetSize: Int? = nil,
        initHop: UInt8 = 1,
        maxHop: UInt8 = 64,
        packetCount: UInt8 = 3,
        timeOut: TimeInterval = 1.0,
        destinationPort: UInt16 = 33434,
        tracePacketCallback: ((
            _ packetResult: UDPTracePacketResult,
            _ stopTrace: (_: Bool) -> Void
        ) -> Void)?,
        onTraceComplete: ((
            _ result: OrderedDictionary<UInt8, [PingResult]>,
            _ status: UDPTraceStatus
        ) -> Void)?
    ) {
        self.serialQueue.async {
            var traceResults: OrderedDictionary<UInt8, [PingResult]> = [:]
            let packetData = packetSize != nil ? Data(repeating: 0, count: packetSize!) : Data("UDP Trace".utf8)
            
            // Create a raw ICMP socket for receiving ICMP responses
            let icmpSock: Int32
            do {
                icmpSock = socket(
                    Int32(self.remoteAddr.addressFamily.raw),
                    SOCK_RAW,
                    self.remoteAddr.addressFamily == .ipv4 ? IPPROTO_ICMP : IPPROTO_ICMPV6
                )
                guard icmpSock > 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno)!)
                }
                try self.setReceiveHopLimit(true, socket: icmpSock)
            } catch {
                onTraceComplete?(traceResults, .failed(error))
                return
            }
            defer { close(icmpSock) }
            
            for hopLimit in initHop ... maxHop {
                for packetIdx in 0 ..< packetCount {
                    do {
                        let pingResult = try self.sendUDPPacket(
                            packetData: packetData,
                            hopLimit: hopLimit,
                            destinationPort: destinationPort,
                            timeOut: timeOut,
                            icmpSock: icmpSock
                        )
                        var hopResults = traceResults[hopLimit] ?? []
                        hopResults.append(pingResult)
                        traceResults[hopLimit] = hopResults
                        var isStop = false
                        let packetResult = UDPTracePacketResult(
                            pingResult: pingResult,
                            hop: hopLimit,
                            packetIndex: packetIdx
                        )
                        tracePacketCallback?(packetResult) { isStop = $0 }
                        
                        switch pingResult {
                        case .pong:
                            if packetIdx == packetCount - 1 {
                                onTraceComplete?(traceResults, .traced)
                                return
                            }
                        case .failed(let error):
                            onTraceComplete?(traceResults, .failed(error))
                            return
                        default:
                            break
                        }
                        if isStop {
                            onTraceComplete?(traceResults, .stopped)
                            return
                        }
                    } catch {
                        onTraceComplete?(traceResults, .failed(error))
                        return
                    }
                }
            }
            onTraceComplete?(traceResults, .maxHopExceeded)
        }
    }
    
    private func sendUDPPacket(
        packetData: Data,
        hopLimit: UInt8,
        destinationPort: UInt16,
        timeOut: TimeInterval,
        icmpSock: Int32
    ) throws -> PingResult {
        let currentID = self.icmpIdentifier
        let currentSeq = self.icmpSequence
        
        // Create UDP socket
        let udpSock = socket(
            Int32(self.remoteAddr.addressFamily.raw),
            SOCK_DGRAM,
            0
        )
        guard udpSock > 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        defer { close(udpSock) }
        
        // Set TTL
        try setHopLimit(UInt32(hopLimit), socket: udpSock)
        
        // Send UDP packet
        var destAddr = self.remoteAddr.createSockStorage()
        if self.remoteAddr.addressFamily == .ipv4 {
            destAddr.withMutableSockaddrIn { sin in
                sin.pointee.sin_port = destinationPort.bigEndian
            }
        } else {
            destAddr.withMutableSockaddrIn6 { sin6 in
                sin6.pointee.sin6_port = destinationPort.bigEndian
            }
        }
        
        let sentCount = packetData.withUnsafeBytes { packetPtr in
            withUnsafePointer(to: destAddr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { addrPtr in
                    sendto(
                        udpSock,
                        packetPtr.baseAddress,
                        packetPtr.count,
                        0,
                        addrPtr,
                        socklen_t(addrPtr.pointee.sa_len)
                    )
                }
            }
        }
        guard sentCount >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        
        self.icmpSequence += 1
        
        // Receive ICMP response
        var begin = Date()
        var timeLeft = timeOut
        try setReceiveTimeout(timeOut, socket: icmpSock)
        
        while true {
            if timeLeft <= 0 {
                return .timeout(sequence: currentSeq, identifier: currentID)
            }
            try setReceiveTimeout(timeLeft, socket: icmpSock)
            
            var cmsgBuffer = [UInt8](repeating: 0, count: MemoryLayout<cmsghdr>.size + MemoryLayout<UInt32>.size)
            var recvBuffer = [UInt8](repeating: 0, count: 1024)
            var srcAddr = sockaddr_storage()
            
            begin = Date()
            let receivedCount = try receive(
                recvBuffer: &recvBuffer,
                cmsgBuffer: &cmsgBuffer,
                srcAddr: &srcAddr,
                socket: icmpSock
            )
            timeLeft -= Date().timeIntervalSince(begin)
            
            guard let hopLimit = cmsgBuffer.withUnsafeBytes({ ptr in
                getHopLimit(cmsgBufferPtr: UnsafeRawBufferPointer(start: ptr.baseAddress, count: cmsgBuffer.count))
            }),
            let srcAddr = srcAddr.toIPAddr(),
            let icmpPacketPtr = recvBuffer.withUnsafeBytes({ ptr in
                getICMPPacketPtr(ipPacketPtr: UnsafeRawBufferPointer(start: ptr.baseAddress, count: receivedCount))
            }) else {
                continue
            }
            
            let icmpHeaderPtr = icmpPacketPtr.bindMemory(to: icmp6_hdr.self)
            let response = Response(
                len: icmpPacketPtr.count,
                from: srcAddr,
                hopLimit: hopLimit,
                sequence: currentSeq,
                identifier: currentID,
                rtt: timeOut - timeLeft
            )
            
            if icmpHeaderPtr[0].icmp6_type == icmpTypeHopLimitExceeded {
                return .hopLimitExceeded(response)
            } else if icmpHeaderPtr[0].icmp6_type == (self.remoteAddr.addressFamily == .ipv4 ? 3 : 1), // ICMP Destination Unreachable
                      icmpHeaderPtr[0].icmp6_code == (self.remoteAddr.addressFamily == .ipv4 ? 3 : 3), // Port Unreachable
                      srcAddr == self.remoteAddr {
                return .pong(response)
            }
        }
    }
    
    private func setHopLimit(_ hopLimit: UInt32, socket: Int32) throws {
        let hopLimitValue = UInt32(hopLimit)
        var result: Int32 = -1
        if self.remoteAddr.addressFamily == .ipv4 {
            result = setsockopt(
                socket,
                IPPROTO_IP,
                IP_TTL,
                &hopLimitValue,
                socklen_t(MemoryLayout<UInt32>.size)
            )
        } else {
            result = setsockopt(
                socket,
                IPPROTO_IPV6,
                IPV6_UNICAST_HOPS,
                &hopLimitValue,
                socklen_t(MemoryLayout<UInt32>.size)
            )
        }
        guard result == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }
    
    private func setReceiveTimeout(_ timeout: TimeInterval, socket: Int32) throws {
        var tv = timeout.toTimeValue()
        let result = setsockopt(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &tv,
            socklen_t(MemoryLayout<timeval>.size)
        )
        guard result == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }
    
    private func receive(
        recvBuffer: inout [UInt8],
        cmsgBuffer: inout [UInt8],
        srcAddr: inout sockaddr_storage,
        socket: Int32
    ) throws -> Int {
        var iov = iovec(
            iov_base: recvBuffer.withUnsafeMutableBytes { $0.baseAddress },
            iov_len: recvBuffer.count
        )
        
        var msghdr = msghdr(
            msg_name: withUnsafeMutablePointer(to: &srcAddr) { $0 },
            msg_namelen: socklen_t(MemoryLayout.size(ofValue: srcAddr)),
            msg_iov: withUnsafeMutablePointer(to: &iov) { $0 },
            msg_iovlen: 1,
            msg_control: cmsgBuffer.withUnsafeMutableBytes { $0.baseAddress },
            msg_controllen: socklen_t(cmsgBuffer.count),
            msg_flags: 0
        )
        
        let receivedCount = withUnsafeMutablePointer(to: &msghdr) { ptr in
            recvmsg(socket, ptr, 0)
        }
        guard receivedCount >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
        return receivedCount
    }
    
    private func setReceiveHopLimit(_ enabled: Bool, socket: Int32) throws {
        var value: Int32 = enabled ? 1 : 0
        let result: Int32
        if self.remoteAddr.addressFamily == .ipv4 {
            result = setsockopt(
                socket,
                IPPROTO_IP,
                IP_RECVTTL,
                &value,
                socklen_t(MemoryLayout<Int32>.size)
            )
        } else {
            result = setsockopt(
                socket,
                IPPROTO_IPV6,
                IPV6_RECVHOPLIMIT,
                &value,
                socklen_t(MemoryLayout<Int32>.size)
            )
        }
        guard result == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno)!)
        }
    }
}

extension sockaddr_storage {
    mutating func withMutableSockaddrIn<T>(_ body: (inout sockaddr_in) -> T) -> T {
        withUnsafeMutablePointer(to: &self) { ptr in
            ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sinPtr in
                var sin = sinPtr.pointee
                let result = body(&sin)
                sinPtr.pointee = sin
                return result
            }
        }
    }
    
    mutating func withMutableSockaddrIn6<T>(_ body: (inout sockaddr_in6) -> T) -> T {
        withUnsafeMutablePointer(to: &self) { ptr in
            ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6Ptr in
                var sin6 = sin6Ptr.pointee
                let result = body(&sin6)
                sin6Ptr.pointee = sin6
                return result
            }
        }
    }
}
```