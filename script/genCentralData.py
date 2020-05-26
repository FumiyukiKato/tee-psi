import os
import sys
import getopt
import hashlib
import datetime
import random

HASH_LEN = 8

RAND = 0
ORDER = 1

def gen_rand_geohash(length):
    geohash = [''] * 32
    base32 = '0123456789bcdefghjkmnpqrstuvwxyz'
    for i in range(length):
        r = int(31 * random.random())
        geohash[i] = base32[r]
        
    return ''.join(geohash)

def gen_rand_timestamp():
    start = datetime.datetime(2020, 3, 1)
    end = datetime.datetime(2020, 5, 30)
    dt = random.random() * (end - start) + start
    return str(int(dt.timestamp()))

def generateMergeStrData(timestamp, geohash):
    timestamp = timestamp
    geohash = geohash
    return timestamp + geohash

def usage(o, a):
    print("Usage: %s [-n, --num number]" % ((o, a),))

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "n:", ["num="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage("", "")
        sys.exit(2)
    
    numData = 1
    mode = ORDER

    if len(opts) == 0:
        usage("", "")
        sys.exit(2)

    for o, arg in opts:
        if o in ("-n", "--num"):
            numData = int(arg)
        else:
            usage(o, arg)
            sys.exit(2)
    
    tmpFileName = 'data/sample.txt'
    with open(tmpFileName, 'w') as f:
        newNum = int(numData/100)
        data_list = []
        for i in range(newNum):
            timestamp = gen_rand_timestamp()
            geohash = gen_rand_geohash(9)
            mergedData = generateMergeStrData(timestamp, geohash)
            data_list.append(mergedData)
        
        # 99%のデータを100倍して高速化する
        dense_data_list = []
        for i in range(newNum):
            timestamp = gen_rand_timestamp()
            geohash = gen_rand_geohash(9)
            mergedData = generateMergeStrData(timestamp, geohash)
            dense_data_list.append(mergedData)
        data_list.extend(dense_data_list*99)
           
        f.write(''.join(data_list))
    
    byte_size = os.path.getsize(tmpFileName)
    os.rename(tmpFileName, 'data/generated-central-data-%d-%dbytes.txt' % (numData, byte_size))

        

if __name__ == "__main__":
    main()