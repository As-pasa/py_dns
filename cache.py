import datetime
import pickle

import sources as src


class Cache:

    def __init__(self):
        self.value: dict[tuple[int, tuple[bytes]], list[(src.DnsResource, datetime.datetime)]] = {}

    def put(self, data: src.DnsResource):
        if (data.Qtype, tuple(data.QName)) in self.value:
            k = self.value[(data.Qtype, tuple(data.QName))]
            for i in range(len(k)):
                if k[i][0] == data:
                    k[i] = (data, datetime.datetime.now())
                    return

            k.append((data, datetime.datetime.now()))
        else:
            self.value[(data.Qtype, tuple(data.QName))] = [(data, datetime.datetime.now())]

    def refresh(self):

        tme = datetime.datetime.now()
        for i in self.value:
            self.refresh_single(i, tme)

    def refresh_single(self, key: tuple[int, tuple[bytes]], tme):
        k = self.value[key]
        for i in k:

            z = (tme - i[1]).total_seconds()

            if z - i[0].ttl > 0:
                k.remove(i)
        if k == []:
            self.value.pop(key)


class CacheManager:
    def __init__(self, filename: str):
        self.filename = filename
        self.cache = None

    def __enter__(self):
        try:
            with open(self.filename, "rb") as f:
                self.cache = pickle.load(f)
                self.cache.refresh()
        except Exception:
            self.cache = Cache()
        return self.cache

    def __exit__(self, exc_type, exc_val, exc_tb):
        with open(self.filename, "wb") as f:
            pickle.dump(self.cache, f)


if __name__=="__main__":

    with CacheManager("data.pickle") as cche:
        print(len(cche.value))
        for i in cche.value:
            print(i, cche.value[i])
