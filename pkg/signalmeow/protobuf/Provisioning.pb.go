//*
// Copyright (C) 2014-2016 Open Whisper Systems
//
// Licensed according to the LICENSE file in this repository.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.1
// 	protoc        v3.21.12
// source: Provisioning.proto

package signalpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

import _ "embed"

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ProvisioningVersion int32

const (
	ProvisioningVersion_INITIAL        ProvisioningVersion = 0
	ProvisioningVersion_TABLET_SUPPORT ProvisioningVersion = 1
	ProvisioningVersion_CURRENT        ProvisioningVersion = 1
)

// Enum value maps for ProvisioningVersion.
var (
	ProvisioningVersion_name = map[int32]string{
		0: "INITIAL",
		1: "TABLET_SUPPORT",
		// Duplicate value: 1: "CURRENT",
	}
	ProvisioningVersion_value = map[string]int32{
		"INITIAL":        0,
		"TABLET_SUPPORT": 1,
		"CURRENT":        1,
	}
)

func (x ProvisioningVersion) Enum() *ProvisioningVersion {
	p := new(ProvisioningVersion)
	*p = x
	return p
}

func (x ProvisioningVersion) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProvisioningVersion) Descriptor() protoreflect.EnumDescriptor {
	return file_Provisioning_proto_enumTypes[0].Descriptor()
}

func (ProvisioningVersion) Type() protoreflect.EnumType {
	return &file_Provisioning_proto_enumTypes[0]
}

func (x ProvisioningVersion) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *ProvisioningVersion) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = ProvisioningVersion(num)
	return nil
}

// Deprecated: Use ProvisioningVersion.Descriptor instead.
func (ProvisioningVersion) EnumDescriptor() ([]byte, []int) {
	return file_Provisioning_proto_rawDescGZIP(), []int{0}
}

type ProvisioningAddress struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Address       *string                `protobuf:"bytes,1,opt,name=address" json:"address,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ProvisioningAddress) Reset() {
	*x = ProvisioningAddress{}
	mi := &file_Provisioning_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ProvisioningAddress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProvisioningAddress) ProtoMessage() {}

func (x *ProvisioningAddress) ProtoReflect() protoreflect.Message {
	mi := &file_Provisioning_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProvisioningAddress.ProtoReflect.Descriptor instead.
func (*ProvisioningAddress) Descriptor() ([]byte, []int) {
	return file_Provisioning_proto_rawDescGZIP(), []int{0}
}

func (x *ProvisioningAddress) GetAddress() string {
	if x != nil && x.Address != nil {
		return *x.Address
	}
	return ""
}

type ProvisionEnvelope struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PublicKey     []byte                 `protobuf:"bytes,1,opt,name=publicKey" json:"publicKey,omitempty"`
	Body          []byte                 `protobuf:"bytes,2,opt,name=body" json:"body,omitempty"` // Encrypted ProvisionMessage
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ProvisionEnvelope) Reset() {
	*x = ProvisionEnvelope{}
	mi := &file_Provisioning_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ProvisionEnvelope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProvisionEnvelope) ProtoMessage() {}

func (x *ProvisionEnvelope) ProtoReflect() protoreflect.Message {
	mi := &file_Provisioning_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProvisionEnvelope.ProtoReflect.Descriptor instead.
func (*ProvisionEnvelope) Descriptor() ([]byte, []int) {
	return file_Provisioning_proto_rawDescGZIP(), []int{1}
}

func (x *ProvisionEnvelope) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *ProvisionEnvelope) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

type ProvisionMessage struct {
	state                 protoimpl.MessageState `protogen:"open.v1"`
	AciIdentityKeyPublic  []byte                 `protobuf:"bytes,1,opt,name=aciIdentityKeyPublic" json:"aciIdentityKeyPublic,omitempty"`
	AciIdentityKeyPrivate []byte                 `protobuf:"bytes,2,opt,name=aciIdentityKeyPrivate" json:"aciIdentityKeyPrivate,omitempty"`
	PniIdentityKeyPublic  []byte                 `protobuf:"bytes,11,opt,name=pniIdentityKeyPublic" json:"pniIdentityKeyPublic,omitempty"`
	PniIdentityKeyPrivate []byte                 `protobuf:"bytes,12,opt,name=pniIdentityKeyPrivate" json:"pniIdentityKeyPrivate,omitempty"`
	Aci                   *string                `protobuf:"bytes,8,opt,name=aci" json:"aci,omitempty"`
	Pni                   *string                `protobuf:"bytes,10,opt,name=pni" json:"pni,omitempty"`
	Number                *string                `protobuf:"bytes,3,opt,name=number" json:"number,omitempty"`
	ProvisioningCode      *string                `protobuf:"bytes,4,opt,name=provisioningCode" json:"provisioningCode,omitempty"`
	UserAgent             *string                `protobuf:"bytes,5,opt,name=userAgent" json:"userAgent,omitempty"`
	ProfileKey            []byte                 `protobuf:"bytes,6,opt,name=profileKey" json:"profileKey,omitempty"`
	ReadReceipts          *bool                  `protobuf:"varint,7,opt,name=readReceipts" json:"readReceipts,omitempty"`
	ProvisioningVersion   *uint32                `protobuf:"varint,9,opt,name=provisioningVersion" json:"provisioningVersion,omitempty"`
	MasterKey             []byte                 `protobuf:"bytes,13,opt,name=masterKey" json:"masterKey,omitempty"`
	EphemeralBackupKey    []byte                 `protobuf:"bytes,14,opt,name=ephemeralBackupKey" json:"ephemeralBackupKey,omitempty"` // 32 bytes
	AccountEntropyPool    *string                `protobuf:"bytes,15,opt,name=accountEntropyPool" json:"accountEntropyPool,omitempty"`
	MediaRootBackupKey    []byte                 `protobuf:"bytes,16,opt,name=mediaRootBackupKey" json:"mediaRootBackupKey,omitempty"` // 32-bytes
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *ProvisionMessage) Reset() {
	*x = ProvisionMessage{}
	mi := &file_Provisioning_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ProvisionMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProvisionMessage) ProtoMessage() {}

func (x *ProvisionMessage) ProtoReflect() protoreflect.Message {
	mi := &file_Provisioning_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProvisionMessage.ProtoReflect.Descriptor instead.
func (*ProvisionMessage) Descriptor() ([]byte, []int) {
	return file_Provisioning_proto_rawDescGZIP(), []int{2}
}

func (x *ProvisionMessage) GetAciIdentityKeyPublic() []byte {
	if x != nil {
		return x.AciIdentityKeyPublic
	}
	return nil
}

func (x *ProvisionMessage) GetAciIdentityKeyPrivate() []byte {
	if x != nil {
		return x.AciIdentityKeyPrivate
	}
	return nil
}

func (x *ProvisionMessage) GetPniIdentityKeyPublic() []byte {
	if x != nil {
		return x.PniIdentityKeyPublic
	}
	return nil
}

func (x *ProvisionMessage) GetPniIdentityKeyPrivate() []byte {
	if x != nil {
		return x.PniIdentityKeyPrivate
	}
	return nil
}

func (x *ProvisionMessage) GetAci() string {
	if x != nil && x.Aci != nil {
		return *x.Aci
	}
	return ""
}

func (x *ProvisionMessage) GetPni() string {
	if x != nil && x.Pni != nil {
		return *x.Pni
	}
	return ""
}

func (x *ProvisionMessage) GetNumber() string {
	if x != nil && x.Number != nil {
		return *x.Number
	}
	return ""
}

func (x *ProvisionMessage) GetProvisioningCode() string {
	if x != nil && x.ProvisioningCode != nil {
		return *x.ProvisioningCode
	}
	return ""
}

func (x *ProvisionMessage) GetUserAgent() string {
	if x != nil && x.UserAgent != nil {
		return *x.UserAgent
	}
	return ""
}

func (x *ProvisionMessage) GetProfileKey() []byte {
	if x != nil {
		return x.ProfileKey
	}
	return nil
}

func (x *ProvisionMessage) GetReadReceipts() bool {
	if x != nil && x.ReadReceipts != nil {
		return *x.ReadReceipts
	}
	return false
}

func (x *ProvisionMessage) GetProvisioningVersion() uint32 {
	if x != nil && x.ProvisioningVersion != nil {
		return *x.ProvisioningVersion
	}
	return 0
}

func (x *ProvisionMessage) GetMasterKey() []byte {
	if x != nil {
		return x.MasterKey
	}
	return nil
}

func (x *ProvisionMessage) GetEphemeralBackupKey() []byte {
	if x != nil {
		return x.EphemeralBackupKey
	}
	return nil
}

func (x *ProvisionMessage) GetAccountEntropyPool() string {
	if x != nil && x.AccountEntropyPool != nil {
		return *x.AccountEntropyPool
	}
	return ""
}

func (x *ProvisionMessage) GetMediaRootBackupKey() []byte {
	if x != nil {
		return x.MediaRootBackupKey
	}
	return nil
}

var File_Provisioning_proto protoreflect.FileDescriptor

//go:embed Provisioning.pb.raw
var file_Provisioning_proto_rawDesc []byte

var (
	file_Provisioning_proto_rawDescOnce sync.Once
	file_Provisioning_proto_rawDescData = file_Provisioning_proto_rawDesc
)

func file_Provisioning_proto_rawDescGZIP() []byte {
	file_Provisioning_proto_rawDescOnce.Do(func() {
		file_Provisioning_proto_rawDescData = protoimpl.X.CompressGZIP(file_Provisioning_proto_rawDescData)
	})
	return file_Provisioning_proto_rawDescData
}

var file_Provisioning_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_Provisioning_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_Provisioning_proto_goTypes = []any{
	(ProvisioningVersion)(0),    // 0: signalservice.ProvisioningVersion
	(*ProvisioningAddress)(nil), // 1: signalservice.ProvisioningAddress
	(*ProvisionEnvelope)(nil),   // 2: signalservice.ProvisionEnvelope
	(*ProvisionMessage)(nil),    // 3: signalservice.ProvisionMessage
}
var file_Provisioning_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_Provisioning_proto_init() }
func file_Provisioning_proto_init() {
	if File_Provisioning_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_Provisioning_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_Provisioning_proto_goTypes,
		DependencyIndexes: file_Provisioning_proto_depIdxs,
		EnumInfos:         file_Provisioning_proto_enumTypes,
		MessageInfos:      file_Provisioning_proto_msgTypes,
	}.Build()
	File_Provisioning_proto = out.File
	file_Provisioning_proto_rawDesc = nil
	file_Provisioning_proto_goTypes = nil
	file_Provisioning_proto_depIdxs = nil
}
