import socket
import random
import cache
import sources


def get_info(data: bytes, address: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock2:
        sock2.connect((address, 53))
        sock2.send(data)
        response = sock2.recv(512)

        return response


def resolve_answer(query: sources.DnsQuestion, server_ip: str = "199.7.83.42") -> list[sources.DnsResource]:
    id = random.randint(0, 1000)
    flags = sources.DnsFlags(0, 0, 0, 0, 1, 0, 0, 0)
    package = sources.DNSPackage(id, flags, [query], [], [], [])
    ans = get_info(sources.bytes_from_package(package), server_ip)
    ans_package = sources.package_from_bytes(sources.Buffer(ans))
    if ans_package.flags.AA == 1:
        print("got authority")
        return ans_package.get_resources()
    else:
        new_server = sources.package_from_bytes(sources.Buffer(ans), True).Authority[0].named_data
        new_server_name = ""
        for i in new_server:
            new_server_name += f"{i}."
        print(f"SERVER: {new_server_name}")
        return resolve_answer(query, new_server_name)


def resolve_with_root_servers(package: sources.DNSPackage) -> sources.DNSPackage:
    with cache.CacheManager("data.pickle") as cch:

        requested = package.questions
        a = sources.PackageBuilder(package.id, package.flags, package.questions)
        for i in requested:
            if not (i.Qtype, tuple(i.QName)) in cch.value:
                print(f"Not found in cache: {i}")
                for j in resolve_answer(i):
                    cch.put(j)
            for j in cch.value[(i.Qtype, tuple(i.QName))]:
                a.add_r(j[0])
        return a.end()


def resolve_easy(package: sources.DNSPackage) -> sources.DNSPackage:
    requested = package.questions
    real_requested = []
    with cache.CacheManager("data.pickle") as cch:

        for i in requested:
            if not (i.Qtype, tuple(i.QName)) in cch.value:
                real_requested.append(i)
        if real_requested != []:
            print(f"reading server! not found in cache: {real_requested}")
            req = package
            req.questions = real_requested

            sdata = get_info(sources.bytes_from_package(req), "ns.hsdrn.ru")
            spackage = sources.package_from_bytes(sources.Buffer(sdata))
            print(f"Server answer: {spackage}")
            for i in spackage.get_resources():
                cch.put(i)

        total_answer = sources.PackageBuilder(package.id, package.flags, requested)
        for i in requested:
            for j in cch.value[(i.Qtype, tuple(i.QName))]:
                total_answer.add_r(j[0])
    return total_answer.end()


def main():
    HOST = "127.0.0.1"
    PORT = 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    while True:
        data, addr = sock.recvfrom(512)
        package = sources.package_from_bytes(sources.Buffer(data))
        print(f"Client asked: {package}")
        p = resolve_with_root_servers(package)
        sock.sendto(sources.bytes_from_package(p), addr)


if __name__ == "__main__":
    main()

