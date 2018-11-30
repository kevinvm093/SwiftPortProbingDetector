//
//  MyPacketModel.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 11/26/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation


class MyPackets {
    
    var proto:          Int?
    var sourceIPs =     [String]()
    var destination:    String?
    var startTime:      __darwin_time_t?
    var endTime:        __darwin_time_t?
    var ratePerSecond =  [Int]()
    var rateKeeper:      Int?
    var timeKeeper:      Int?
    
    var ports:          PortModel?
    var numPackets:     Int?
    
}
