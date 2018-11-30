//
//  AttackModel.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 11/26/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation

public class AttackModel {
    
    var proto:     Int?
    var sourceIPs =  [String]()
    var destination:String?
    var startTime: __darwin_time_t?
    var endTime:   __darwin_time_t?
    var numPackets: Int?
    var rate: Int?
    var hits =  [Int]()
    var destPort: [String:Int]?
    var portsAffected: [String]?
    var durationOfPortScan = [String]()
    
    init(withData:MyPackets) {
        self.proto = withData.proto
        self.sourceIPs = withData.sourceIPs
        self.destination = withData.destination
        self.startTime = withData.startTime
        self.endTime = withData.endTime
        self.numPackets = withData.numPackets
        self.destPort = withData.ports?.destPort
      
    }
    
    
    init() {
        
        self.proto = Int()
        self.sourceIPs = [String]()
        self.destination = String()
        self.startTime = __darwin_time_t()
        self.endTime = __darwin_time_t()
        self.numPackets = Int()
        self.rate = Int()
        
    }
    
    
}
