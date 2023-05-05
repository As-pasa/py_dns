import dataclasses
import struct


class Buffer:
    def __init__(self, b: bytes, n: int = 0):
        self.src = b
        self.n = n

    def read(self, n):
        old = self.n
        self.n += n
        return self.src[old:self.n]

    def read_one(self):
        v = self.src[self.n]
        self.n += 1
        return v

    def goto(self, n):
        self.n = n

    def getp(self):
        return self.n


@dataclasses.dataclass
class DnsQuestion:
    QName: list[bytes]
    Qtype: int
    QClass: int


@dataclasses.dataclass(frozen=True)
class DnsResource:
    QName: tuple[bytes]
    Qtype: int
    Qclass: int
    ttl: int
    data_len: int
    data: bytes
    named_data: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class DnsFlags:
    QR: bool
    Opcode: int
    AA: bool
    TC: bool
    RD: bool
    RA: bool
    z: int
    RCODE: int


def bytesFromFlags(d: DnsFlags) -> bytes:
    a = 1
    a &= d.QR
    a <<= 4
    a |= d.Opcode
    a <<= 1
    a |= d.AA
    a <<= 1
    a |= d.TC
    a <<= 1
    a |= d.RD
    a <<= 1
    a |= d.RA
    a <<= 3
    a |= d.z
    a <<= 4
    a |= d.RCODE
    zz = hex(a)[2:].zfill(4)

    return bytes.fromhex(zz)


def Dns_flags_from_bytes(b: bytes):
    flags = struct.unpack(">H", b)[0]
    QR = flags >> 15
    OPCODE = (flags >> 11) & 15
    AA = (flags >> 10) & 1
    TC = (flags >> 9) & 1
    RD = (flags >> 8) & 1
    RA = (flags >> 7) & 1
    Z = (flags >> 4) & 7
    RCODE = flags & 15
    return DnsFlags(QR, OPCODE, AA, TC, RD, RA, Z, RCODE)


def readNameRec(b: Buffer):
    ln = b.read_one()
    if ln == 0:
        return []
    if ln == 192:
        return readNameRec(Buffer(b.src, b.read_one()))
    else:
        return [b.read(ln)] + readNameRec(b)


def Dns_query_from_bytes(b: Buffer):
    name = readNameRec(b)
    tpe = int.from_bytes(b.read(2), "big")
    cls = int.from_bytes(b.read(2), "big")
    return DnsQuestion(name, tpe, cls)


def Dns_resource_from_bytes(b: Buffer, resolve_name: bool = False):
    name = readNameRec(b)
    tpe = int.from_bytes(b.read(2), "big")
    cls = int.from_bytes(b.read(2), "big")
    ttl = int.from_bytes(b.read(4), 'big')
    dlen = int.from_bytes(b.read(2), 'big')
    ptr = b.getp()
    data = b.read(dlen)
    after_ptr = b.getp()
    data_dec = []
    if resolve_name and tpe == 2:
        b.goto(ptr)
        data_dec = readNameRec(b)
    b.goto(after_ptr)
    if data_dec != []:
        data_dec = [k.decode("utf-8") for k in data_dec]
        return DnsResource(name, tpe, cls, ttl, dlen, data, data_dec)
    else:
        return DnsResource(name, tpe, cls, ttl, dlen, data)


def query_to_bytes(d: DnsQuestion):
    ans = b""
    for i in d.QName:
        ans += len(i).to_bytes(1, "big")
        ans += i
    ans += int(0).to_bytes(1, "big")
    ans += d.Qtype.to_bytes(2, "big")
    ans += d.QClass.to_bytes(2, "big")
    return ans


def resourse_to_bytes(d: DnsResource):
    ans = b""
    for i in d.QName:
        ans += len(i).to_bytes(1, "big")
        ans += i
    ans += int(0).to_bytes(1, "big")
    ans += d.Qtype.to_bytes(2, "big")
    ans += d.Qclass.to_bytes(2, "big")
    ans += d.ttl.to_bytes(4, 'big')
    ans += len(d.data).to_bytes(2, "big")
    ans += d.data
    return ans


@dataclasses.dataclass
class DNSPackage:
    id: int
    flags: DnsFlags
    questions: list[DnsQuestion]
    Answers: list[DnsResource]
    Authority: list[DnsResource]
    Additional: list[DnsResource]

    def get_resources(self):
        return self.Answers + self.Authority + self.Additional


def package_from_bytes(b: Buffer, resolve_data_names: bool = False):
    idd = int.from_bytes(b.read(2), "big")
    flags = Dns_flags_from_bytes(b.read(2))
    q_count = int.from_bytes(b.read(2), "big")
    a_count = int.from_bytes(b.read(2), "big")
    auth_count = int.from_bytes(b.read(2), "big")
    add_count = int.from_bytes(b.read(2), "big")

    queries = []
    for i in range(q_count):
        queries.append(Dns_query_from_bytes(b))
    answers = []
    for i in range(a_count):
        answers.append(Dns_resource_from_bytes(b))
    auth = []
    for i in range(auth_count):
        auth.append(Dns_resource_from_bytes(b, resolve_name=resolve_data_names))
    add = []
    for i in range(add_count):
        add.append(Dns_resource_from_bytes(b))
    return DNSPackage(idd, flags, queries, answers, auth, add)


def bytes_from_package(pack: DNSPackage):
    a = b""
    a += pack.id.to_bytes(2, "big")
    a += bytesFromFlags(pack.flags)
    a += len(pack.questions).to_bytes(2, "big")
    a += len(pack.Answers).to_bytes(2, "big")
    a += len(pack.Authority).to_bytes(2, "big")
    a += len(pack.Additional).to_bytes(2, "big")

    for i in pack.questions:
        a += query_to_bytes(i)

    for i in pack.Answers:
        a += resourse_to_bytes(i)

    for i in pack.Authority:
        a += resourse_to_bytes(i)

    for i in pack.Additional:
        a += resourse_to_bytes(i)
    return a


class PackageBuilder:
    def __init__(self, id: int, flags: DnsFlags, queries=()):
        self.package: DNSPackage = DNSPackage(id, flags, list(queries), [], [], [])

    def add_q(self, q: DnsQuestion):
        self.package.questions.append(q)

    def add_r(self, r: DnsResource):

        if r.Qtype == 1:
            self.package.Answers.append(r)
            return self
        elif r.Qtype == 2:
            self.package.Authority.append(r)
            return self
        else:
            self.package.Additional.append(r)
            return self

    def end(self):
        return self.package
