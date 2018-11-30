//
//  PairIPsModel.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 11/26/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation

struct PairIPs: Hashable {
    
    // var source:[String]
    var destination:String
    var scanType:String?
    
    init(destination:String, scanType: String) {
        //  self.source = source
        self.destination = destination
        self.scanType = scanType
        
    }
    
    static func == (lhs:PairIPs, rhs:PairIPs) -> Bool {
        return lhs.destination == rhs.destination && lhs.scanType == rhs.scanType
    }
    
}
