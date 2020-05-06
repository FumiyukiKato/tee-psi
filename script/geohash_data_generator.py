import os
import sys
import getopt
import hashlib

HASH_LEN = 8

RAND = 0
ORDER = 1

def gen_rand_str_hex(length):
    buf = ''
    while len(buf) < length:
        buf += hashlib.md5(os.urandom(100)).hexdigest()
    return buf[0:length]

def gen_order_str_hex(length, count):
    return str(hex(count)).zfill(length)

def usage(o, a):
    print("Usage: %s [-m, --mode (random | order)], [-n, --num number]" % ((o, a),))

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "m:n:", ["mode=", "num="])
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
        if o in ("-m", "--mode"):
            if arg == "random":
                mode = RAND
            elif arg == "order":
                mode = ORDER
            else:
                usage(o, arg)
                sys.exit(2)
        elif o in ("-n", "--num"):
            numData = int(arg)
        else:
            usage(o, arg)
            sys.exit(2)
    
    tmpFileName = 'data/tmp-geohash-data'
    with open(tmpFileName, 'w') as f:
        geohashes = []
        if mode == RAND:
            for _ in range(numData):
                geohashes.append(gen_rand_str_hex(HASH_LEN))
        elif mode == ORDER:
            for i in range(numData):
                geohashes.append(gen_order_str_hex(HASH_LEN, i))
            
        f.write('\n'.join(geohashes))
        f.write('\n')
    
    byte_size = os.path.getsize(tmpFileName)
    os.rename(tmpFileName, 'data/generated-%d-%s-%d-bytes.txt' % 
                    (numData, { RAND: 'random', ORDER: 'order' }[mode], byte_size))

        

if __name__ == "__main__":
    main()