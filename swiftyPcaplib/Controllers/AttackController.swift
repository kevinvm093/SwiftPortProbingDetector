//
//  AttackController.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 11/26/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation

class AttackController {
    
    func findStrobe(horizontal:[AttackModel], vertical:[AttackModel], suspected: [AttackModel]) -> [String] {
        
        var strobe = [String]()
        
        for h in horizontal {
            
            let newObj = AttackModel()
            
            for v in vertical {
                for d in suspected {
                    
                    let d = Set(d.sourceIPs)
                    let hSource = Set(h.sourceIPs)
                    let vSources = Set(v.sourceIPs)
            
                    let sSources = Array(hSource.intersection(vSources))
                    strobe += sSources
                }
            }
        }
        
        
        return strobe
        
        
        
    }
    
    func saveProbeType(pairs: [PairIPs:AttackModel]) -> [AttackModel] {
        
        var probes = [AttackModel]()
        
        for pair in pairs {
            
            pair.value.destination = pair.key.destination
            pair.value.durationOfPortScan = getDates(att: pair.value)
            pair.value.rate = calcAvg(dt: pair.value)
           probes.append(pair.value)
            
        }
        
        return probes
    }
    
    
    func filterPorts(att1: AttackModel, att2: AttackModel) -> [String] {
        
        let p1 = (att1.destPort?.keys.sorted())!
        let p2 = (att2.destPort?.keys.sorted())!
        
        let newPorts = Array(Set(p1 + p2)).sorted()
        
        return newPorts
        
    }
    
    func filterPorts(att1: AttackModel, att2: AttackModel, pair:[String] ) -> [String] {
        
        let p1 = (att1.destPort?.keys.sorted())!
        let p2 = (att2.destPort?.keys.sorted())!
        
        let newPorts = Array(Set(p1 + p2 + pair)).sorted()
        
        return newPorts
        
    }
    
    func filterSourceIp(source1:[String], source2:[String]) -> [String] {
        
        let filteredSources = Array(Set(source1 + source2)).sorted()
        return filteredSources
        
    }
    
    func filterSourceIp(source1: [String], source2: [String], pair: [String]) -> [String] {
        
        let filteredSources = Array(Set(source1 + source2 + pair)).sorted()
        
        return filteredSources
    }
    
    func getDates(att: AttackModel) -> [String] {
        
        
        
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        
        let st = formatter.string(from: NSDate(timeIntervalSince1970: TimeInterval(att.startTime!)) as Date)
        let ed = formatter.string(from: NSDate(timeIntervalSince1970: TimeInterval(att.endTime!)) as Date)
        
        let dt = [st, ed]
        
        return dt
        
    }
    
    func calcAvg(dt:AttackModel)-> Int {
        
        let arr = dt.hits
    
        var result = 0
        
        for i in arr {
            result += Int(i)
        }
        if arr.count != 0 {
            result /= Int(arr.count)
        }
        return result
    }
    
    
}
