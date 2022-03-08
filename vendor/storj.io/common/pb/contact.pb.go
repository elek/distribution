// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: contact.proto

package pb

import (
	fmt "fmt"
	math "math"
	time "time"

	proto "github.com/gogo/protobuf/proto"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type CheckInRequest struct {
	Address              string        `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Version              *NodeVersion  `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
	Capacity             *NodeCapacity `protobuf:"bytes,3,opt,name=capacity,proto3" json:"capacity,omitempty"`
	Operator             *NodeOperator `protobuf:"bytes,4,opt,name=operator,proto3" json:"operator,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *CheckInRequest) Reset()         { *m = CheckInRequest{} }
func (m *CheckInRequest) String() string { return proto.CompactTextString(m) }
func (*CheckInRequest) ProtoMessage()    {}
func (*CheckInRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{0}
}
func (m *CheckInRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CheckInRequest.Unmarshal(m, b)
}
func (m *CheckInRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CheckInRequest.Marshal(b, m, deterministic)
}
func (m *CheckInRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckInRequest.Merge(m, src)
}
func (m *CheckInRequest) XXX_Size() int {
	return xxx_messageInfo_CheckInRequest.Size(m)
}
func (m *CheckInRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckInRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CheckInRequest proto.InternalMessageInfo

func (m *CheckInRequest) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *CheckInRequest) GetVersion() *NodeVersion {
	if m != nil {
		return m.Version
	}
	return nil
}

func (m *CheckInRequest) GetCapacity() *NodeCapacity {
	if m != nil {
		return m.Capacity
	}
	return nil
}

func (m *CheckInRequest) GetOperator() *NodeOperator {
	if m != nil {
		return m.Operator
	}
	return nil
}

type CheckInResponse struct {
	PingNodeSuccess      bool     `protobuf:"varint,1,opt,name=ping_node_success,json=pingNodeSuccess,proto3" json:"ping_node_success,omitempty"`
	PingErrorMessage     string   `protobuf:"bytes,2,opt,name=ping_error_message,json=pingErrorMessage,proto3" json:"ping_error_message,omitempty"`
	PingNodeSuccessQuic  bool     `protobuf:"varint,3,opt,name=ping_node_success_quic,json=pingNodeSuccessQuic,proto3" json:"ping_node_success_quic,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CheckInResponse) Reset()         { *m = CheckInResponse{} }
func (m *CheckInResponse) String() string { return proto.CompactTextString(m) }
func (*CheckInResponse) ProtoMessage()    {}
func (*CheckInResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{1}
}
func (m *CheckInResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CheckInResponse.Unmarshal(m, b)
}
func (m *CheckInResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CheckInResponse.Marshal(b, m, deterministic)
}
func (m *CheckInResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckInResponse.Merge(m, src)
}
func (m *CheckInResponse) XXX_Size() int {
	return xxx_messageInfo_CheckInResponse.Size(m)
}
func (m *CheckInResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckInResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CheckInResponse proto.InternalMessageInfo

func (m *CheckInResponse) GetPingNodeSuccess() bool {
	if m != nil {
		return m.PingNodeSuccess
	}
	return false
}

func (m *CheckInResponse) GetPingErrorMessage() string {
	if m != nil {
		return m.PingErrorMessage
	}
	return ""
}

func (m *CheckInResponse) GetPingNodeSuccessQuic() bool {
	if m != nil {
		return m.PingNodeSuccessQuic
	}
	return false
}

type GetTimeRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetTimeRequest) Reset()         { *m = GetTimeRequest{} }
func (m *GetTimeRequest) String() string { return proto.CompactTextString(m) }
func (*GetTimeRequest) ProtoMessage()    {}
func (*GetTimeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{2}
}
func (m *GetTimeRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetTimeRequest.Unmarshal(m, b)
}
func (m *GetTimeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetTimeRequest.Marshal(b, m, deterministic)
}
func (m *GetTimeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetTimeRequest.Merge(m, src)
}
func (m *GetTimeRequest) XXX_Size() int {
	return xxx_messageInfo_GetTimeRequest.Size(m)
}
func (m *GetTimeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetTimeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetTimeRequest proto.InternalMessageInfo

type GetTimeResponse struct {
	Timestamp            time.Time `protobuf:"bytes,1,opt,name=timestamp,proto3,stdtime" json:"timestamp"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *GetTimeResponse) Reset()         { *m = GetTimeResponse{} }
func (m *GetTimeResponse) String() string { return proto.CompactTextString(m) }
func (*GetTimeResponse) ProtoMessage()    {}
func (*GetTimeResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{3}
}
func (m *GetTimeResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetTimeResponse.Unmarshal(m, b)
}
func (m *GetTimeResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetTimeResponse.Marshal(b, m, deterministic)
}
func (m *GetTimeResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetTimeResponse.Merge(m, src)
}
func (m *GetTimeResponse) XXX_Size() int {
	return xxx_messageInfo_GetTimeResponse.Size(m)
}
func (m *GetTimeResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetTimeResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetTimeResponse proto.InternalMessageInfo

func (m *GetTimeResponse) GetTimestamp() time.Time {
	if m != nil {
		return m.Timestamp
	}
	return time.Time{}
}

type ContactPingRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ContactPingRequest) Reset()         { *m = ContactPingRequest{} }
func (m *ContactPingRequest) String() string { return proto.CompactTextString(m) }
func (*ContactPingRequest) ProtoMessage()    {}
func (*ContactPingRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{4}
}
func (m *ContactPingRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContactPingRequest.Unmarshal(m, b)
}
func (m *ContactPingRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContactPingRequest.Marshal(b, m, deterministic)
}
func (m *ContactPingRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContactPingRequest.Merge(m, src)
}
func (m *ContactPingRequest) XXX_Size() int {
	return xxx_messageInfo_ContactPingRequest.Size(m)
}
func (m *ContactPingRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ContactPingRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ContactPingRequest proto.InternalMessageInfo

type ContactPingResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ContactPingResponse) Reset()         { *m = ContactPingResponse{} }
func (m *ContactPingResponse) String() string { return proto.CompactTextString(m) }
func (*ContactPingResponse) ProtoMessage()    {}
func (*ContactPingResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{5}
}
func (m *ContactPingResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContactPingResponse.Unmarshal(m, b)
}
func (m *ContactPingResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContactPingResponse.Marshal(b, m, deterministic)
}
func (m *ContactPingResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContactPingResponse.Merge(m, src)
}
func (m *ContactPingResponse) XXX_Size() int {
	return xxx_messageInfo_ContactPingResponse.Size(m)
}
func (m *ContactPingResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ContactPingResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ContactPingResponse proto.InternalMessageInfo

type PingMeRequest struct {
	Address              string        `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Transport            NodeTransport `protobuf:"varint,2,opt,name=transport,proto3,enum=node.NodeTransport" json:"transport,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *PingMeRequest) Reset()         { *m = PingMeRequest{} }
func (m *PingMeRequest) String() string { return proto.CompactTextString(m) }
func (*PingMeRequest) ProtoMessage()    {}
func (*PingMeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{6}
}
func (m *PingMeRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PingMeRequest.Unmarshal(m, b)
}
func (m *PingMeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PingMeRequest.Marshal(b, m, deterministic)
}
func (m *PingMeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PingMeRequest.Merge(m, src)
}
func (m *PingMeRequest) XXX_Size() int {
	return xxx_messageInfo_PingMeRequest.Size(m)
}
func (m *PingMeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PingMeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PingMeRequest proto.InternalMessageInfo

func (m *PingMeRequest) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *PingMeRequest) GetTransport() NodeTransport {
	if m != nil {
		return m.Transport
	}
	return NodeTransport_TCP_TLS_GRPC
}

type PingMeResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PingMeResponse) Reset()         { *m = PingMeResponse{} }
func (m *PingMeResponse) String() string { return proto.CompactTextString(m) }
func (*PingMeResponse) ProtoMessage()    {}
func (*PingMeResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a5036fff2565fb15, []int{7}
}
func (m *PingMeResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PingMeResponse.Unmarshal(m, b)
}
func (m *PingMeResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PingMeResponse.Marshal(b, m, deterministic)
}
func (m *PingMeResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PingMeResponse.Merge(m, src)
}
func (m *PingMeResponse) XXX_Size() int {
	return xxx_messageInfo_PingMeResponse.Size(m)
}
func (m *PingMeResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PingMeResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PingMeResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*CheckInRequest)(nil), "contact.CheckInRequest")
	proto.RegisterType((*CheckInResponse)(nil), "contact.CheckInResponse")
	proto.RegisterType((*GetTimeRequest)(nil), "contact.GetTimeRequest")
	proto.RegisterType((*GetTimeResponse)(nil), "contact.GetTimeResponse")
	proto.RegisterType((*ContactPingRequest)(nil), "contact.ContactPingRequest")
	proto.RegisterType((*ContactPingResponse)(nil), "contact.ContactPingResponse")
	proto.RegisterType((*PingMeRequest)(nil), "contact.PingMeRequest")
	proto.RegisterType((*PingMeResponse)(nil), "contact.PingMeResponse")
}

func init() { proto.RegisterFile("contact.proto", fileDescriptor_a5036fff2565fb15) }

var fileDescriptor_a5036fff2565fb15 = []byte{
	// 494 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x52, 0xcd, 0x6e, 0xd3, 0x40,
	0x10, 0xc6, 0x50, 0xd5, 0xc9, 0x54, 0x4d, 0xda, 0x4d, 0x69, 0x2d, 0x83, 0x94, 0xca, 0xa7, 0x0a,
	0x90, 0x23, 0xd2, 0x13, 0x52, 0x4f, 0x89, 0x2a, 0xc4, 0xa1, 0x10, 0x96, 0xc0, 0x01, 0x21, 0x45,
	0xce, 0x66, 0x31, 0x06, 0xec, 0x71, 0x77, 0xd7, 0x48, 0xbc, 0x05, 0x8f, 0xc0, 0x5b, 0x70, 0xe2,
	0xce, 0x53, 0xc0, 0xab, 0x20, 0xef, 0x8f, 0xdd, 0x24, 0x48, 0xdc, 0x76, 0xe7, 0xfb, 0xe6, 0x9b,
	0x9f, 0x6f, 0x60, 0x9f, 0x61, 0xa1, 0x12, 0xa6, 0xe2, 0x52, 0xa0, 0x42, 0xe2, 0xdb, 0x6f, 0x08,
	0x29, 0xa6, 0x68, 0x82, 0xe1, 0x30, 0x45, 0x4c, 0x3f, 0xf3, 0x91, 0xfe, 0x2d, 0xab, 0xf7, 0x23,
	0x95, 0xe5, 0x5c, 0xaa, 0x24, 0x2f, 0x2d, 0x01, 0x0a, 0x5c, 0x71, 0xf3, 0x8e, 0x7e, 0x78, 0xd0,
	0x9b, 0x7e, 0xe0, 0xec, 0xd3, 0xb3, 0x82, 0xf2, 0xeb, 0x8a, 0x4b, 0x45, 0x02, 0xf0, 0x93, 0xd5,
	0x4a, 0x70, 0x29, 0x03, 0xef, 0xd4, 0x3b, 0xeb, 0x52, 0xf7, 0x25, 0x0f, 0xc1, 0xff, 0xc2, 0x85,
	0xcc, 0xb0, 0x08, 0x6e, 0x9f, 0x7a, 0x67, 0x7b, 0xe3, 0xc3, 0x58, 0x4b, 0x3d, 0xc7, 0x15, 0x7f,
	0x63, 0x00, 0xea, 0x18, 0x24, 0x86, 0x0e, 0x4b, 0xca, 0x84, 0x65, 0xea, 0x6b, 0x70, 0x47, 0xb3,
	0x49, 0xcb, 0x9e, 0x5a, 0x84, 0x36, 0x9c, 0x9a, 0x8f, 0x25, 0x17, 0x89, 0x42, 0x11, 0xec, 0x6c,
	0xf2, 0x5f, 0x58, 0x84, 0x36, 0x9c, 0xe8, 0xbb, 0x07, 0xfd, 0xa6, 0x73, 0x59, 0x62, 0x21, 0x39,
	0x79, 0x00, 0x87, 0x65, 0x56, 0xa4, 0x8b, 0x3a, 0x6f, 0x21, 0x2b, 0xc6, 0xdc, 0x10, 0x1d, 0xda,
	0xaf, 0x81, 0x5a, 0xea, 0x95, 0x09, 0x93, 0x47, 0x40, 0x34, 0x97, 0x0b, 0x81, 0x62, 0x91, 0x73,
	0x29, 0x93, 0x94, 0xeb, 0xb9, 0xba, 0xf4, 0xa0, 0x46, 0x2e, 0x6b, 0xe0, 0xca, 0xc4, 0xc9, 0x39,
	0x1c, 0x6f, 0x29, 0x2f, 0xae, 0xab, 0x8c, 0xe9, 0xd9, 0x3a, 0x74, 0xb0, 0x21, 0xff, 0xb2, 0xca,
	0x58, 0x74, 0x00, 0xbd, 0xa7, 0x5c, 0xcd, 0xb3, 0x9c, 0xdb, 0xdd, 0x46, 0xaf, 0xa1, 0xdf, 0x44,
	0x6c, 0xcf, 0x13, 0xe8, 0x36, 0x06, 0xe9, 0x5e, 0xf7, 0xc6, 0x61, 0x6c, 0x2c, 0x8c, 0x9d, 0x85,
	0xf1, 0xdc, 0x31, 0x26, 0x9d, 0x5f, 0xbf, 0x87, 0xb7, 0xbe, 0xfd, 0x19, 0x7a, 0xb4, 0x4d, 0x8b,
	0x8e, 0x80, 0x4c, 0xcd, 0x25, 0xcc, 0xb2, 0x22, 0x75, 0xc5, 0xee, 0xc2, 0x60, 0x2d, 0x6a, 0x0a,
	0x46, 0xef, 0x60, 0xbf, 0xfe, 0x5f, 0xf1, 0xff, 0x1b, 0xfe, 0x18, 0xba, 0x4a, 0x24, 0x85, 0x2c,
	0x51, 0x28, 0xbd, 0x9a, 0xde, 0x78, 0xd0, 0x9a, 0x32, 0x77, 0x10, 0x6d, 0x59, 0xf5, 0xcc, 0x4e,
	0xdd, 0xd4, 0x1b, 0xcf, 0xc0, 0xb7, 0x6d, 0x90, 0x4b, 0xe8, 0xcc, 0xec, 0x9e, 0xc8, 0xbd, 0xd8,
	0xdd, 0xf2, 0x76, 0xeb, 0xe1, 0xfd, 0x7f, 0x83, 0x56, 0xf1, 0xa7, 0x07, 0x3b, 0x5a, 0xe3, 0x02,
	0x7c, 0x7b, 0x02, 0xe4, 0xa4, 0xcd, 0x58, 0x3b, 0xe7, 0x30, 0xd8, 0x06, 0xec, 0xe6, 0x9f, 0xc0,
	0xae, 0x69, 0x95, 0x1c, 0x37, 0x9c, 0xb5, 0xcd, 0x84, 0x27, 0x5b, 0x71, 0x9b, 0x7a, 0x01, 0xbe,
	0xf5, 0xf1, 0x46, 0xe1, 0x75, 0xaf, 0x6f, 0x14, 0xde, 0xb0, 0x7c, 0x72, 0xf4, 0x96, 0x48, 0x85,
	0xe2, 0x63, 0x9c, 0xe1, 0x88, 0x61, 0x9e, 0x63, 0x31, 0x2a, 0x97, 0xcb, 0x5d, 0xed, 0xf6, 0xf9,
	0xdf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0xef, 0xff, 0xf4, 0xe4, 0x03, 0x00, 0x00,
}
