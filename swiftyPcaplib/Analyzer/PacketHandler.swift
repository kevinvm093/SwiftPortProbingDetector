//
//  PacketHandler.swift
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 11/1/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

import Foundation

let MAX_TIME = 600

let MAX_NUM_OF_PACKETS = 1000
let PACKETS = 100
let MIN_INTERVALS = 6
let MICRO_PER_SECOND = 1000000
let MIN_NUM_OF_PORTS = 6
let MIN_NUMBER_OF_IP = 5

let ProbingType = [ "Horizontal Scan", "Vertical Scan" ,"Strobe Scan" ]
let converter = WrapperFunctions.init()

/******************************************************************************************************************
 Class PacketNode:
 Nodes in binary tree that store myPacket objects as its value and the ip destination from the packet as its key.
 *******************************************************************************************************************/
class PacketNode {
    
    var ipname:String
    var data:MyPackets
    
    var lchild:PacketNode?
    var rchild:PacketNode?
    
    init(ipname:String, data:MyPackets) {
        self.ipname = ipname
        self.data = data
        
        
    }
    
    init() {
        self.ipname = ""
        self.data = MyPackets()
        
    }
    
    deinit {
        print("\(self.ipname) is being deinitialized")
    }
    
    
}

var SuspectedAttacks = [AttackModel].init()
let attackController = AttackController.init() 
var Pairs = [PairIPs:AttackModel]()

var SuspectedHorizontal = [AttackModel]()
var SuspectedVertical = [AttackModel]()


var StrobeProbing = [String]()
var HorizontalProbing = [AttackModel]() // many addressed to 1 port
var VerticalProbing = [AttackModel]() // many ports to 1 address

var usedPorts = [String: [String]]()
var suspiciousPorts = [String]()

class PacketTree {
    
    var root = PacketNode()
    var treeCount = 0
    let myPacketController = MyPacketController.init()
    
    init() {
        
    }
    
    func insert(ipname:String, data:MyPackets) -> Void {
        
        insert(ipname: ipname, data: data, ptr: root)
        
    }
    /*---------------------------------------------------------------------------------------------
     As packets come in the BST they are stored with nodes of common destination. Every 10 minutes algorithm re-analyzes each node for suspicious activity.
     -------------------------------------------------------------------------------------------------------- */
    
    func insert(ipname:String, data:MyPackets, ptr: PacketNode?) -> Void {
        
        if ptr?.ipname == "" {
            ptr?.lchild = PacketNode()
            ptr?.rchild = PacketNode()
            ptr?.ipname = ipname
            ptr?.data = data
            
            
            self.treeCount += 1
            
        }
        else if (ptr?.ipname)! > ipname {
            
            insert(ipname: ipname, data: data, ptr: ptr?.lchild)
            
        } else if (ptr?.ipname)! < ipname {
            
            insert(ipname: ipname, data: data, ptr: ptr?.rchild)
            
        } else if ptr?.ipname == ipname
        {
            
            let temp = ptr?.data
            
            if (data.startTime! - (temp?.startTime)!) <= MAX_TIME {
                
                temp?.numPackets! += 1
                temp?.rateKeeper! += 1
                temp?.endTime = data.startTime
                temp?.sourceIPs.append((data.sourceIPs.last)!)
                
                let dp = data.ports?.dPort!
                
                if data.startTime! - ((temp?.timeKeeper)!) == 1 {
                    
                    temp?.ratePerSecond.append((temp?.rateKeeper)!)
                    temp?.rateKeeper = 0
                    temp?.timeKeeper = data.startTime!
                    
                }
                
                if temp?.ports?.destPort?[dp!] == nil {
                    
                    temp?.ports?.destPort![dp!] = Int()
                    
                }
                
                temp?.ports?.destPort![dp!]! += 1
                
                
            } else  {
                
                if (data.startTime! - (temp?.startTime)!) == (MAX_TIME + 1) {
                    
                    temp?.destination = ipname
                    
                    for dp in (temp?.ports?.destPort!)! {
                        
                        if let d = (usedPorts[dp.key]) {
                            
                            if !(d.contains(ipname)) {
                                usedPorts[dp.key]?.append(ipname)
                                
                                if (usedPorts[dp.key]?.count)! == 10 {
                                    suspiciousPorts.append(dp.key)
                                }
                                
                            }
                            
                        } else {
                            usedPorts[dp.key] = [String]()
                            usedPorts[dp.key]?.append(ipname)
                            
                        }
                        
                    }
                    
                    if (temp?.numPackets)! >= MAX_NUM_OF_PACKETS{
                        
                        if (temp?.ports?.destPort?.count)! >= 5 {
                            
                            let attackholder = AttackModel.init(withData: temp!)
                            //   let d = attackController.getDates(att: attackholder)
                            //  attackholder.durationOfPortScan = d
                            attackholder.rate = myPacketController.calcAvgRatePerSec(packet: temp!)
                            
                            SuspectedVertical.append(attackholder)
                            
                        } else if suspiciousPorts.count > 0 {
                            
                            for p in suspiciousPorts {
                                if temp?.ports?.destPort![p] != nil {
                                    let attackholder = AttackModel.init(withData: temp!)
                                    //     let d = attackController.getDates(att: attackholder)
                                   // attackholder.durationOfPortScan = d
                                    attackholder.rate = myPacketController.calcAvgRatePerSec(packet: temp!)
                                    SuspectedHorizontal.append(attackholder)
                                    break
                                    
                                }
                            }
                        } else {
                            let attackholder = AttackModel.init(withData: temp!)
                            attackholder.rate = myPacketController.calcAvgRatePerSec(packet: temp!)
                            let d = attackController.getDates(att: attackholder)
                            attackholder.durationOfPortScan = d
                            attackholder.rate = myPacketController.calcAvgRatePerSec(packet: temp!)
                            
                            SuspectedAttacks.append(attackholder)
                        }
                    }
                    
                    
                    
                } // end of suspected if
                
                temp?.proto = data.proto
                temp?.startTime = data.startTime
                temp?.endTime = data.endTime
                temp?.numPackets = data.numPackets
                temp?.destination = ""
                temp?.sourceIPs.removeAll()
                temp?.ports = data.ports
                temp?.ratePerSecond.removeAll()
                temp?.sourceIPs.append((data.sourceIPs.last)!)
                temp?.timeKeeper = data.timeKeeper
                
            } // end of nested else .....
            ptr?.data = temp!
        }
    }
    
    
    
    func findAttack() {
        
        findProbes()
    }
    /*--------------------------------------------------------------------------------------------------
     func - findAttacks -
     Seperate each suspected probe type into intervals of 10min. Loop thorugh each interval comparing it to the adjacent element until match is found. Essentially this calculate the length of port probe for every source IP.
     --------------------------------------------------------------------------------------------------*/
    func findProbes() {
        
        let SuspectedType = [SuspectedHorizontal, SuspectedVertical, SuspectedAttacks]
        var pt = 0
        
        for suspected in SuspectedType {
            var filteredAttacks = [__darwin_time_t:[AttackModel]]()
            
            for att in suspected {
                
                if filteredAttacks[att.endTime!] == nil {
                    
                    filteredAttacks[att.endTime!] = [AttackModel]()
                    
                }
                
                filteredAttacks[att.endTime!]?.append(att)
                
                
            }
            let keySort = filteredAttacks.keys.sorted()
            
            var attacks = [[AttackModel]]()
            
            for i in keySort {
                
                attacks.append(filteredAttacks[i]!)
                
            }
            
            var index = 0
            
            while(index < keySort.count - 1 ) {
                for att1 in attacks[index]  {
                    
                    for att2 in attacks[index + 1] {
                        
                        if att2.endTime! - att1.endTime! < MAX_TIME {
                            continue
                            
                        } else {
                            
                            let key = PairIPs.init(destination: att2.destination!, scanType: ProbingType[pt])
                            
                            if att1.destination == att2.destination {
                                
                                if Pairs[key] == nil {
                                    
                                    Pairs[key] =  AttackModel()
                                    let fsip = attackController.filterSourceIp(source1: att2.sourceIPs, source2: att1.sourceIPs)
                                    Pairs[key]?.sourceIPs = fsip
                                    Pairs[key]?.startTime = att1.startTime!
                                    Pairs[key]?.endTime = att2.endTime!
                                    Pairs[key]?.portsAffected = attackController.filterPorts(att1: att1, att2: att2)
                                    Pairs[key]?.hits.append(att1.rate!)
                                    Pairs[key]?.hits.append(att2.rate!)
                                    
                                } else {
                                    
                                    let fsip = attackController.filterSourceIp(source1: att2.sourceIPs, source2: att1.sourceIPs, pair: Pairs[key]!.sourceIPs)
                                    Pairs[key]?.sourceIPs.removeAll()
                                    Pairs[key]?.sourceIPs = fsip
                                    Pairs[key]?.endTime = att2.endTime!
                                    let portfilter = attackController.filterPorts(att1: att1, att2: att2, pair:(Pairs[key]?.portsAffected)!)
                                    Pairs[key]?.portsAffected!.removeAll()
                                    Pairs[key]?.portsAffected = portfilter
                                    Pairs[key]?.hits.append(att1.rate!)
                                    Pairs[key]?.hits.append(att2.rate!)
                                    
                                }
                            }
                        }
                    }
                }
                index += 1
            }
            switch pt {
            case 0:
                HorizontalProbing = attackController.saveProbeType(pairs: Pairs)
                Pairs.removeAll()
                break
            case 1:
                VerticalProbing = attackController.saveProbeType(pairs: Pairs)
                Pairs.removeAll()
                break
            case 2:
                StrobeProbing = attackController.findStrobe(horizontal: HorizontalProbing, vertical: VerticalProbing, suspected: SuspectedAttacks)
                
                break
            default:
                break
            }
            pt += 1
        }
    }
    
    
    func DisplayResults() {
        
        let probes = [HorizontalProbing, VerticalProbing]
        
        print("+----------Source IPs Related to Probing----------+")
        print()
        print("+-------------------------------------------------+")
        print("|                   Horizontal                    |")
        print("+-------------------------------------------------+")
        
        
        
        for hp in HorizontalProbing {
            
            let dSpaces = 17
            let spc = " "
            let num = dSpaces - hp.destination!.count
            var rSpaces = ""
            var data = ""
            var spaces = ""
            var counter = 0
            var sour = [String]()
            var idk = 0
            
            
            
            for _ in 0 ... num {
                spaces += spc
            }
            
            if Int(hp.rate!) < 10 {
                rSpaces = "  "
            } else {
                rSpaces = " "
            }
            
            let array = ["|", hp.destination!, spaces ,"|  ", String(Int(hp.rate!)), rSpaces, " |  ", hp.durationOfPortScan[0], "  | ", hp.durationOfPortScan[1], " |"]
            
            for a in array {
                data += a
            }
            
            var counter1 = 0
            
            for s in hp.sourceIPs {
                
                let num2 = dSpaces - s.count
                spaces = ""
                for _ in 0 ... num2 {
                    spaces += spc
                }
                
                if counter1 %  3 == 0 {
                    sour.append("")
                    
                    if counter1 != 0 {
                        idk += 1
                    }
                    
                }
                
                sour[idk] += " " + s + spaces
                counter1 += 1
                
            }
            
            
            print("+------------------+------+------------+----------+")
            print("| Destination   IP | Rate | Start Time | End Time |")
            print("+------------------+------+------------+----------+")
            print(data)
            print("+-------------------------------------------------+")
            print()
            
            for s in sour {
                print(s)
            }
            print()
            
        }
        
        print()
        print("+-------------------------------------------------+")
        print("|                   Vertical                      |")
        print("+-------------------------------------------------+")
        
        for vp in VerticalProbing {
            
            let dSpaces = 17
            let spc = " "
            let num = dSpaces - vp.destination!.count
            var rSpaces = ""
            var data = ""
            var spaces = ""
            var counter = 0
            var sour = [String]()
            var idk = 0
            
            
            for _ in 0 ... num {
                spaces += spc
            }
            
            if Int(vp.rate!) < 10 {
                rSpaces = "  "
            } else {
                rSpaces = " "
            }
            var counter1 = 0
            
            for s in vp.sourceIPs {
                
                let num2 = dSpaces - s.count
                spaces = ""
                for _ in 0 ... num2 {
                    spaces += spc
                }
                
                if counter1 %  3 == 0 {
                    sour.append("")
                    
                    if counter1 != 0 {
                        idk += 1
                    }
                    
                }
                
                sour[idk] += " " + s + spaces
                counter1 += 1
                
            }
            
            let array = ["|", vp.destination!, spaces ,"|  ", String(Int(vp.rate!)), rSpaces, " |  ", vp.durationOfPortScan[0], "  | ", vp.durationOfPortScan[1], " |"]
            
            for a in array {
                data += a
            }
            
            print("+------------------+------+------------+----------+")
            print("| Destination  IP  | Rate | Start Time | End Time |")
            print("+------------------+------+------------+----------+")
            print(data)
            print("+-------------------------------------------------+")
            print()
            for s in sour {
                print(s)
            }
            print()
            
        }
        
        print()
        print("+-------------------------------------------------+")
        print("|                 Strobe                          |")
        print("+-------------------------------------------------+")
        
        var sour = [String]()
        var counter1 = 0
        var idk = 0
        let dSpaces = 17
        var spaces = ""
        var spc = " "
        
        for s in StrobeProbing {
            
            let num2 = dSpaces - s.count
            
            
            for _ in 0 ... num2 {
                spaces += spc
            }
            
            
            if counter1 % 3 == 0 {
                sour.append("")
                
                if counter1 != 0 {
                    idk += 1
                }
                sour[idk] += " " + s + spaces
                
                counter1 += 1
                
            }
            
            
        }
        
    }
    
    
    
}

        


