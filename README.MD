# Aliyun Swift OpenAPI

Aliyun Swift API based on Perfect. 
All implementations are based on [Alibaba Cloud REST API](https://www.alibabacloud.com/help/zh/doc-detail/25484.htm?spm=a3c0i.o25544zh.b99.143.2715b386fwq3Z4).

# Current Implementation

All structures are JSON convertible.

## Prepare Credentials

``` swift 
let access = AcsCredential()
access.id = "an easy name to remember the key"
access.key = "Your AccessKeyId"
access.secret = "Your AccessKeySecret"
```

## Query Regions

``` swift 

let ecs = ECS(access: access)
ecs.describeRegions { regions in
}

// where regions is [Region]
// region.id is the actual usable RegionId
// region.name is a Chinese description
```

## Query Security Groups

``` swift
ecs.describeSecurityGroups(region: "RegionId") { securityGroups, message in

}
```

Callback parameter `securityGroups` is [SecurityGroup], with properties mapping as below:

Property|Alibaba Cloud Official Document Name
-------|----------
id|SecurityGroupId
name|SecurityGroupName
remark|Description
tags|Tags
creationTime|CreationTime
availableInstanceAmount|AvailableInstanceAmount
vpcId|VpcId

## Key Pairs

### Create a Key Pair

``` swift
ecs.createKeyPair(region: "RegionId",
	name: "Name of the Key Pair, will be useful for instance creation") { keyPair, msg in 
// should save the keyPair.key immediately as a .pem file with 400 mod.
}
```
Where keyPair is a `AcsKeyPair` class:
Property|Alibaba Cloud Official Document Name
-------|----------
name|KeyPairName
fingerPrint|KeyPairFingerPrint
key|PrivateKeyBody


### Delete Key Pairs

``` swift
let keypairs = ["keypair1 to delete", "keypair2 name", ... ]

ecs.deleteKeyPairs(region: "RegionId", keyNames: keypairs) { 
	success, message in
	// success should be true to confirm the deletion.
}
```

## Check Support Instance Types

Note not all instance types are available throughout the regions. `ecs.describeImageSupportInstanceTypes()` may help a bit, but still not 100% guarantee the availabilities.

``` swift
ecs.describeImageSupportInstanceTypes(region: "cn-hongkong", 
	imageId: "ubuntu_16_0402_64_40G_base_20170222.vhd") { 
	types, msg in
	
}
```

It will return an array like `[InstanceType]`, with information properties below:

Property|Alibaba Cloud Official Document Name
-------|----------
id| InstanceTypeId
typeFamily| InstanceTypeFamily
cpu|CpuCoreCount
memory|MemorySize


## Instance

### CreateInstance()

``` swift
let ecs = ECS(access: access)
let tags = ["Perfect":"1"]
// you have to pick out the security group id
// by the above security group method before creating instances.
let sid = "sg-j6c58xjb4po9jq2hsc0u"
ecs.createInstance(region: "cn-hongkong", securityGroupId: sid, name: "PT-01", description: "PerfectTemplate Test Instance", keyPair: "TestKey", tags: tags) { 
	instanceId, msg in

}
```

### allocateIP()

⚠️**Note**⚠️ The newly created instance will not be connected unless allocate a public ip:

```
ecs.allocateIP(instanceId: id) { 
	ipAddress, msg in
	if let ip = ipAddress {
		print("ssh -i /path/to/keypair.pem root@\(ip)")
	}
```


### Load Instance Status

Even a successful instance creation with an `instanceId` returned, the status would not be available in the first 5 seconds after the creation.

``` swift
ecs.loadInstances(region: "cn-hongkong", tags: ["Perfect":"1"]) { 
	instanses, msgs in
}
```

The `instances` array `[Instance]` described as below:

Property|Alibaba Cloud Official Document Name|Property|Alibaba Cloud Official Document Name
-------|----------|-------|----------
id|InstanceId|name|InstanceName
remark|Description|imageId|ImageId
region|RegionId|zone|ZoneId
cpu|CPU|memory|Memory
type|InstanceType|typeFamily|InstanceTypeFamily
host|HostName|status|Status
securityGroups|SecurityGroupIds|ipPublic|PublicIpAddress.ipAddress
maxBandwidthIn|InternetMaxBandwidthIn|maxBandwidthOut|InternetMaxBandwidthOut
chargeTypeInternet|InternetChargeType|chargeTypeInstance|InstanceChargeType
creationTime|CreationTime|ipPrivate|InnerIpAddress.ipAddress
networkType|InstanceNetworkType|operationLocks|OperationLocks
deviceAvailable|DeviceAvailable|ioOptimized|IoOptimized
expiration|ExpiredTime|keyPairName|KeyPairName

### Start an instance

``` swift
ecs.startInstance(instanceId: id) { 
	success, message in
	// success will be true if the instance started.
}
```