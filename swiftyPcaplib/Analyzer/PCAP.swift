//
//  PCAP.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 10/20/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation


var timer = Int()
var Sniffer = PacketTree()
let progress = WrapperFunctions.init()
var count:Int32 = 0

public class analyzer {
    
    var error: UnsafeMutablePointer<CChar>?
    var startTime = clock()
    
    /*--------------------------------------------------------------------------------
     func analyze: Using C libraries open, loop and extract the contents of pcap file.
     --------------------------------------------------------------------------------*/
    
    func analyze(fileName:String) -> Void {
        
        count = 0
        
        let pcap = pcap_open_offline(fileName, error) //open pcap file
        if pcap == nil
        {
            print("couldnt open file")
            print(error!)
            return
        }
        print("capturing....")
        print("Progress:");
        print("-----------")
        
        let startTime = clock()
        
        if pcap_loop(pcap, 0, ({ (args, pkthdr,packet) in
            
            
            let etherhdr = UnsafePointer<ether_header>.init(unsafeBitCast(packet, to: UnsafeMutablePointer<ether_header>.self))
            
            //converts the unsigned short integer netshort from network byte order to host byte order.
            if NSSwapBigShortToHost(etherhdr.pointee.ether_type) == ETHERTYPE_IP {
                
                let ipHeader = get_ipHeader(packet) //wrapper function written in C to extract IpHeader data.
                let pTemp = (ipHeader?.pointee.ip_p)!
                
                if pTemp == IPPROTO_TCP || pTemp == IPPROTO_UDP {
                    
                    let LIMIT = socklen_t(INET_ADDRSTRLEN)
                    
                    var sourceIP = UnsafeMutablePointer<Int8>.allocate(capacity: Int(LIMIT))
                    defer { sourceIP.deallocate() }
                    
                    var destinationIP = UnsafeMutablePointer<Int8>.allocate(capacity: Int(LIMIT))
                    defer { destinationIP.deallocate()}
                    
                    inet_ntop(AF_INET, &(ipHeader!.pointee.ip_src), sourceIP, socklen_t(LIMIT))
                    inet_ntop(AF_INET, &(ipHeader!.pointee.ip_dst), destinationIP,  socklen_t(LIMIT))
                    
                    
                    let destination = String(cString: destinationIP)
                    let source = String(cString: sourceIP)
                    
                    let newObj = MyPackets.init()
                    
                    newObj.proto = Int(pTemp)
                    newObj.sourceIPs.append(source)
                    newObj.startTime = (pkthdr?.pointee.ts.tv_sec)!
                    newObj.timeKeeper = (pkthdr?.pointee.ts.tv_sec)!
                    newObj.endTime = (pkthdr?.pointee.ts.tv_sec)!
                    newObj.rateKeeper = 1
                    newObj.numPackets = 1
                    
                    
                    
                    //Store myPacket Object in binary tree to be processed later.
                    if pTemp == IPPROTO_UDP {
                        
                        let udpHeader = get_udpHeader(packet)
                        
                        newObj.ports = PortModel.init(withData: udpHeader!)
                        Sniffer.insert(ipname: destination, data: newObj)
                        
                    } else {
                        
                        let tcpHeader = get_tcpHeader(packet)
                        newObj.ports = PortModel.init(withData: tcpHeader!)
                        Sniffer.insert(ipname: destination, data: newObj)
                        
                    }
                }
                count += 1
                progress.displayProgress(count)
                
            }
            
            } as pcap_handler),
                     nil) < 0
        {
            print("loop failed")
            print(pcap_geterr(pcap))
            return
        }
        print()
        print("capture finished!")
        
        let totalTime = Int64(clock() - startTime) / Int64(CLOCKS_PER_SEC)
        
        print("Total amount of time elapsed is: \(totalTime/60) min ")
        
        Sniffer.findAttack() // Once pcap file is looped through Detect any potentional attacks
        Sniffer.DisplayResults()
        
        print("Thats all folks!")
        
    }
}





