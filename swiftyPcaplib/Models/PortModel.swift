//
//  PortModel.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 11/26/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation

class PortModel {
    
    var dPort:String?
    var destPort: [String:Int]?
    
    init(withData: UnsafeMutablePointer<tcphdr>) {
        
        self.dPort = String(withData.pointee.th_dport)
        self.destPort = [dPort!: 1]
        
    }
    
    init(withData: UnsafeMutablePointer<udphdr>) {
        
        self.dPort = String(withData.pointee.uh_dport)
        let dp = String(withData.pointee.uh_dport)
        
        self.destPort = [dp: 1]
        
    }
    
    
}
