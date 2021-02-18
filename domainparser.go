package domainparser

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	typeA         = 1
	classIN       = 1
	eof           = byte(0)
	pointer       = 0xC0 // byte(196)
	dnsServerPort = "53"
)

// dns 头
type dnsHeader struct {
	ID      uint16
	Flag    uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// 设置 dns 头 中 flag
func (h *dnsHeader) setFlag(qr, opcode, aa, tc, rd, ra, rcode uint16) {
	h.Flag = qr<<15 + opcode<<11 + aa<<10 + tc<<9 + rd<<8 + ra<<7 + rcode
}

// dns 内容
type dnsQuestion struct {
	QName  []byte // byte 切片
	QType  uint16
	QClass uint16
}

// 设置 dns 内容 中 QName
func (q *dnsQuestion) setQName(qname string) {
	var buf bytes.Buffer

	for _, n := range strings.Split(qname, ".") {
		_ = binary.Write(&buf, binary.BigEndian, byte(len(n))) // 标签长度
		_ = binary.Write(&buf, binary.BigEndian, []byte(n))    // 标签内容
		//fmt.Println("pack qname query->", []byte(n), n)
	}
	_ = binary.Write(&buf, binary.BigEndian, eof) // 以0x00结束

	q.QName = buf.Bytes()
}

// 将请求封包
func packRequest(qname string) []byte {
	// 封 Header
	header := dnsHeader{
		ID:      0x0001,
		QDCount: 1,
	}
	header.setFlag(0, 0, 0, 0, 1, 0, 0)

	// 封 Question
	question := dnsQuestion{
		QType:  typeA,
		QClass: classIN,
	}
	question.setQName(qname)

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, header)
	//fmt.Println("pack header->", buf.Bytes())
	//fmt.Println("pack qname->", question.QName)
	_ = binary.Write(&buf, binary.BigEndian, question.QName)
	_ = binary.Write(&buf, binary.BigEndian, []uint16{question.QType, question.QClass})
	//fmt.Println("pack question->", buf.Bytes()[12:])

	return buf.Bytes()
}

// dns 应答
type dnsAnswer struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    resourceData // 空类型
}

// 空接口
type resourceData interface {
	value() string
}

// 地址数组
type rdataA struct {
	addr [4]uint8
}

// 地址数组 转 ip 地址
func (r *rdataA) value() string {
	return fmt.Sprintf("%d.%d.%d.%d", r.addr[0], r.addr[1], r.addr[2], r.addr[3])
}

func (r *dnsAnswer) setRData(rdata, data []byte) error {
	var rd resourceData // 接口类型
	switch r.Type {
	case typeA:
		rd = new(rdataA) // 普通类型转接口是隐式的
		if len(rdata) != 4 {
			return errors.New("invalid resource record data")
		}
		for i, d := range rdata {
			// 接口转普通类型需要使用断言：rd.(*rdataA)，即断言接口rd为rdataA指针类型
			_ = binary.Read(bytes.NewBuffer([]byte{d}), binary.BigEndian, &rd.(*rdataA).addr[i])

			// 断言和强制转换是不同的，Go中的强制转换用于普通类型之间的转换
			// 当然，得是互相之间可以转换的类型
			// var a float64 = 1
			// b := int(a)
		}
		// ...
	}
	r.RData = rd

	return nil
}

func getRefData(data []byte, p uint16) []byte {
	var refData []byte
	//fmt.Println("refdata", data)

	// 从初始偏移量开始对应答数据包缓存进行遍历
	for i := int(p); i < len(data); i++ {
		// fmt.Print(i, p, " ")
		// 读到新指针
		if b := data[i]; b&pointer == pointer {
			if i+1 >= len(data) {
				return []byte{}
			}
			// 更新偏移量，继续遍历
			_ = binary.Read(bytes.NewBuffer([]byte{b ^ pointer, data[i+1]}), binary.BigEndian, &p)
			i = int(p - 1)
		} else {
			refData = append(refData, b)
			// 读到0x00即可结束
			if b == eof {
				break
			}
		}
	}

	return refData
}

// 将返回拆包
func unpackResponse(rd io.Reader) ([]*dnsAnswer, error) {
	var (
		reader = bufio.NewReader(rd)
		data   []byte // 应答数据包缓存
		buf    []byte // 临时缓存
		err    error
		n      int
	)

	// 拆 返回 header
	header := new(dnsHeader)
	buf = make([]byte, 12)
	if n, err = reader.Read(buf); err != nil || n != 12 { // 12个字节
		return nil, err
	}
	_ = binary.Read(bytes.NewReader(buf[:2]), binary.BigEndian, &header.ID)
	_ = binary.Read(bytes.NewReader(buf[2:4]), binary.BigEndian, &header.Flag)
	_ = binary.Read(bytes.NewReader(buf[4:6]), binary.BigEndian, &header.QDCount)
	_ = binary.Read(bytes.NewReader(buf[6:8]), binary.BigEndian, &header.ANCount)
	_ = binary.Read(bytes.NewReader(buf[8:10]), binary.BigEndian, &header.NSCount)
	_ = binary.Read(bytes.NewReader(buf[10:12]), binary.BigEndian, &header.ARCount)
	// fmt.Println("unpack header->", header)
	data = append(data, buf...)

	// 拆 返回 Question
	question := new(dnsQuestion)
	if buf, err = reader.ReadBytes(eof); err != nil { // 域名以0x00结尾
		return nil, err
	}
	// fmt.Println("unpack QName->", buf)
	data = append(data, buf...)

	question.QName = buf
	buf = make([]byte, 4)
	if n, err = reader.Read(buf); err != nil || n != 4 { // 4个字节
		return nil, err
	}
	data = append(data, buf...)

	_ = binary.Read(bytes.NewBuffer(buf[0:2]), binary.BigEndian, &question.QType)
	_ = binary.Read(bytes.NewBuffer(buf[2:]), binary.BigEndian, &question.QClass)
	//fmt.Println("unpack question->", question)

	// 拆Answer(s)
	answers := make([]*dnsAnswer, header.ANCount)
	buf, _ = reader.Peek(59)

	// 根据 Header 中的 ANCOUNT 标识判断有几个 Answer
	for i := 0; i < int(header.ANCount); i++ {
		answer := new(dnsAnswer)
		// NAME
		var b byte
		var p uint16
		for {
			if b, err = reader.ReadByte(); err != nil {
				return nil, err
			}
			// fmt.Println("test1----->", data, b, pointer)
			data = append(data, b)

			if b&pointer == pointer { // pointer 是一个值为 0xC0 的 byte 类型常量
				buf = []byte{b ^ pointer, 0}
				if b, err = reader.ReadByte(); err != nil {
					return nil, err
				}
				data = append(data, b)

				buf[1] = b
				_ = binary.Read(bytes.NewBuffer(buf), binary.BigEndian, &p)

				if buf = getRefData(data, p); len(buf) == 0 {
					return nil, errors.New("invalid answer packet")
				}

				answer.Name = append(answer.Name, buf...)
				break
			} else {
				answer.Name = append(answer.Name, b)
				if b == eof {
					break
				}
			}
		}

		// TYPE、CLASS、TLL、RDLENGTH 等其他数据
		buf = make([]byte, 10)
		if n, err = reader.Read(buf); err != nil || n != 10 {
			return nil, err
		}
		_ = binary.Read(bytes.NewReader(buf[:2]), binary.BigEndian, &answer.Type)
		_ = binary.Read(bytes.NewReader(buf[2:4]), binary.BigEndian, &answer.Class)
		_ = binary.Read(bytes.NewReader(buf[4:8]), binary.BigEndian, &answer.TTL)
		_ = binary.Read(bytes.NewReader(buf[8:10]), binary.BigEndian, &answer.RDLength)
		// fmt.Println("unpack rdlength", int(answer.RDLength))
		data = append(data, buf...)

		// RDATA
		buf = make([]byte, int(answer.RDLength))
		if n, err = reader.Read(buf); err != nil || n < int(answer.RDLength) {
			return nil, err
		}
		data = append(data, buf...)

		// 调用之前定义的SetRData()函数处理不同类型的RDATA
		if err = answer.setRData(buf, data); err != nil {
			return nil, err
		}

		answers[i] = answer
		//fmt.Println("unpack answer->", answer)
	}

	// 拆Authority和Additional，如果有的话

	return answers, nil
}

func Resolve(qname, server string) ([]net.IP, error) {
	var names []net.IP

	reqData := packRequest(qname) // 将请求封包

	// 使用 net 包进行 UDP 连接
	conn, err := net.Dial("udp", server+":"+dnsServerPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second * 1))

	// 发包
	if i, err := conn.Write(reqData); err != nil || i <= 0 {
		return nil, err
	}

	answers, err := unpackResponse(conn) // 将返回拆包
	if err != nil {
		return nil, err
	}

	// 获取 IP
	for _, a := range answers {
		if a.Type != typeA {
			continue
		}
		if ip := net.ParseIP(a.RData.value()); ip != nil {
			names = append(names, ip)
		}
	}

	return names, nil
}
