//
//  BLEncrytion.h
//  blecenter
//
//  Created by hancc on 6/6/16.
//  Copyright © 2016 com.het. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>
#import <Security/SecRandom.h>
#import <CommonCrypto/CommonCrypto.h>


typedef NS_ENUM(NSUInteger, BLEEncryptionType)
{
    Encryption_None=0,//supported, default
    Encryption_ByProtocol,
    DES_ECB64,
    AES_ECB128,//supported
    AES_CBC128,
};

@interface openPlatformEncrytion : NSObject
@property(nonatomic,assign)NSUInteger   encryptType;
//@property(nonatomic,strong)NSString     *mac;
@property(nonatomic,strong)NSData       *enkey;

-(NSData*)generateKey:(NSString*)macString;
// 解密数据
-(NSData*)decryption:(NSData*)data;
// 加密数据
-(NSData*)encryption:(NSData*)data;

+(openPlatformEncrytion*)getShareEncryptor;
@end
