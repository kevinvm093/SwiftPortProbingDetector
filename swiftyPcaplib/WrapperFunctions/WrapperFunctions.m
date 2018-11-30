//
//  bh.m
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 10/20/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

#import <Foundation/Foundation.h>


@implementation WrapperFunctions : NSObject

static int total = 67589746;
bool flag = false;
char *slash = "";
char *slash2 = "";

- (void) displayProgress:(int) current {
    
   
    
    if (current % 10000 == 0) {
        if (!flag){
            slash = "/";
            slash2 = "\\";
            flag = true;
        } else {
            slash = "\\";
            slash2 = "/";
            flag = false;
    }
    }
    
    
    
    double p = ((double)(current)/(double)(total))*100.00;
    

    printf("%s %.2f%% %s ", slash, p, slash2);
    fflush(stdout);
    
    if (current < 10) {
        printf("\b\b\b\b\b\b\b\b\b\b");
    }
    else {
        printf("\b\b\b\b\b\b\b\b\b\b\b");
    }
    
    
    
    
}





@end


