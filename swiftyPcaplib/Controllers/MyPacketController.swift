//
//  MyPacketController.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 11/26/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation

class MyPacketController {

        
        func getPrototype(p:u_char) -> String {
            
            var protocolStr = String()
            
            switch p {
            case 0x06:
                protocolStr = "TCP"
                break
            case 0x11:
                protocolStr = "UDP"
                break
            case 0x01:
                protocolStr = "ICMP"
                break
            default:
                protocolStr = String(format: "Protocol:0x%2.2x",p)
                
            }
            return protocolStr
        }
    
    func calcAvgRatePerSec(packet:MyPackets) -> Int {
        
        let arr = packet.ratePerSecond
        
        var result = 0
        
        for i in arr {
            result += i
        }
        if arr.count != 0 {
            result /= arr.count
        }
        return result
    }
    
}
