// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "psienclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(asm)]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate sgx_types;
extern crate sgx_trts;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tdh;
extern crate sgx_tcrypto;
extern crate sgx_tkey_exchange;
extern crate sgx_rand;

use sgx_types::*;
use sgx_trts::memeq::ConsttimeMemEq;
use sgx_tcrypto::*;
use sgx_tkey_exchange::*;
use sgx_rand::{Rng, StdRng};
use std::slice;
use std::vec::Vec;
use std::cell::RefCell;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::boxed::Box;
use std::collections::HashMap;
use std::string::String;
use std::string::ToString;

const G_SP_PUB_KEY: sgx_ec256_public_t = sgx_ec256_public_t {
    gx : [0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
          0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
          0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
          0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38],
    gy : [0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
          0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
          0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
          0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06]
};

const SGX_SALT_SIZE: usize = 32;
const CLIENT_MAX_NUMBER: usize = 2;
const HASH_DATA_FINISH: u32 = 1;
const RESULT_FINISH: u32 = 2;

const P2P_MODE: u32 = 0;
const CENTRAL_MODE: u32 = 1;

const CLIENT_ID: u32 = 1;
const CLIENT_IDX: usize = 0;
const CENTRAL_IDX: usize = 1;

const SESSIONTOKEN_SIZE: usize = 32;
const RISKLEVEL_RESULT: usize = 1;

const GEOHASH_DIDIT: usize = 10;
const U8_GEODATA_SIZE: usize = 9;
const U8_TIMESTAMP_SIZE: usize = 10;

const CLIENT_SECRET_KEY_SIZE: usize = 16;

#[derive(Clone, Default)]
struct KeyManager {
    map: HashMap<String, sgx_aes_gcm_128bit_key_t>
}

impl KeyManager {
    pub fn new() -> Self {
        KeyManager::default()
    }
}

#[derive(Clone, Default)]
struct CentralData {
    data: Vec<SpatialData>
}

impl CentralData {
    pub fn new() -> Self {
        CentralData::default()
    }
}

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd, Copy)]
struct SpatialData {
    geoHash  : [u8; U8_GEODATA_SIZE], // 普通にu8配列の方が良さそう
    timestamp: u64     // unix epochは本来u32で表現できるけど
}

impl SpatialData {
    pub fn new(u_geoHash: [u8; U8_GEODATA_SIZE], u_timestamp: [u8; U8_TIMESTAMP_SIZE]) -> Self {
        SpatialData {
            geoHash: u_geoHash,
            timestamp: parse_timestamp_from_u8(u_timestamp)
        }
    }
}

// 昇順ソート
fn sort_by_geohash(sp_data: &mut Vec<SpatialData>) {
    sp_data.sort_by(|a, b| a.geoHash.cmp(&b.geoHash));
}

static KEY_MANAGER: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());
static CENTRAL_DATA: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());

fn get_ref_key_manager() -> Option<&'static RefCell<KeyManager>>
{
    let ptr = KEY_MANAGER.load(Ordering::SeqCst) as * mut RefCell<KeyManager>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &* ptr })
    }
}

fn get_ref_central_data() -> Option<&'static RefCell<CentralData>>
{
    let ptr = CENTRAL_DATA.load(Ordering::SeqCst) as * mut RefCell<CentralData>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &* ptr })
    }
}

// 使わないことにした
fn parse_geohash_from_u8(u_geoHash: [u8; U8_GEODATA_SIZE]) -> String {
    return String::from_utf8(u_geoHash.to_vec()).unwrap();
}

fn parse_timestamp_from_u8(u_timestamp: [u8; U8_TIMESTAMP_SIZE]) -> u64 {
    let s_timestamp = String::from_utf8(u_timestamp.to_vec()).unwrap();
    let num: u64 = (&s_timestamp).parse().unwrap();
    num
}

// TODO; 初期化と解放の関数をモードで分ける
#[no_mangle]
pub extern "C"
fn initialize(salt: &mut [u8; SGX_SALT_SIZE]) -> sgx_status_t {
    let key_manager = KeyManager::new();
    let key_manager_box = Box::new(RefCell::<KeyManager>::new(key_manager));
    let key_manager_ptr = Box::into_raw(key_manager_box);
    KEY_MANAGER.store(key_manager_ptr as *mut (), Ordering::SeqCst);

    let central_data = CentralData::new();
    let central_data_box = Box::new(RefCell::<CentralData>::new(central_data));
    let central_data_ptr = Box::into_raw(central_data_box);
    CENTRAL_DATA.store(central_data_ptr as *mut (), Ordering::SeqCst);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn uninitialize() {
    let key_manager_ptr = KEY_MANAGER.swap(0 as * mut (), Ordering::SeqCst) as * mut RefCell<KeyManager>;
    if key_manager_ptr.is_null() {
        return;
    }
    let _ = unsafe { Box::from_raw(key_manager_ptr) };

    let central_data_ptr = CENTRAL_DATA.swap(0 as * mut (), Ordering::SeqCst) as * mut RefCell<CentralData>;
    if central_data_ptr.is_null() {
        return;
    }
    let _ = unsafe { Box::from_raw(central_data_ptr) };
}

#[no_mangle]
pub extern "C"
fn uploadCentralData(
    spdata: * const u8,
    spdata_size: usize,
) -> sgx_status_t {

    let sp_slice = unsafe {
        slice::from_raw_parts(spdata, spdata_size as usize)
    };

    if sp_slice.len() != spdata_size {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let mut central_data = get_ref_central_data().unwrap().borrow_mut();
    let MERGED_DATA_SIZE = U8_GEODATA_SIZE+U8_TIMESTAMP_SIZE;
    for i in 0_usize..(spdata_size/MERGED_DATA_SIZE) {
        let mut timestamp = [0_u8; U8_TIMESTAMP_SIZE];
        let mut geoHash = [0_u8; U8_GEODATA_SIZE];
        timestamp.copy_from_slice(&sp_slice[i*MERGED_DATA_SIZE..i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE]);
        geoHash.copy_from_slice(&sp_slice[i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE..(i + 1)*MERGED_DATA_SIZE]);
        let data = SpatialData::new(geoHash, timestamp);
        central_data.data.push(data);
    }
    sort_by_geohash(&mut central_data.data);
    
    sgx_status_t::SGX_SUCCESS
}

fn get_key_from_vec(token: &[u8; SESSIONTOKEN_SIZE]) -> String {
    const CHARS: &'static str = "0123456789ABCDEF";
    let mut key: String = "".to_string();
    for i in 0_usize..(SESSIONTOKEN_SIZE) {
        let high: u8 = token[i] / 16;
        let low : u8  = token[i] % 16;
        key.push(CHARS.chars().nth(high as usize).unwrap());
        key.push(CHARS.chars().nth(low as usize).unwrap());
    }
    key
}

fn geo_hash_encode(token: &[u8; U8_GEODATA_SIZE]) -> String {
    const CHARS: &'static str = "0123456789bcdefghjkmnpqrstuvwxyz";
    let mut key: String = "".to_string();
    for i in 0_usize..(SESSIONTOKEN_SIZE) {
        let high: u8 = token[i] / 16;
        let low : u8  = token[i] % 16;
        key.push(CHARS.chars().nth(high as usize).unwrap());
        key.push(CHARS.chars().nth(low as usize).unwrap());
    }
    key
}

#[no_mangle]
pub extern "C"
fn remote_attestation_mock(
    token: &mut [u8; SESSIONTOKEN_SIZE],
    sk   : &mut sgx_aes_gcm_128bit_key_t
) -> sgx_status_t {

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(token);
    rand.fill_bytes(sk);
    
    let mut key_manager = get_ref_key_manager().unwrap().borrow_mut();
    println!("{}", get_key_from_vec(token));
    key_manager.map.insert(get_key_from_vec(token), *sk);
    
    sgx_status_t::SGX_SUCCESS
}

fn decrypt_secret_key(
    session_key           : &sgx_aes_gcm_128bit_key_t,
    encrypted_secret_key  : &[u8],
    secret_key_gcm_tag    : &[u8; SGX_MAC_SIZE],
    decrypted             : &mut Vec<u8>
) {
    let iv = [0; SGX_AESGCM_IV_SIZE];
    let aad:[u8; 0] = [0; 0];
    
    let ret = rsgx_rijndael128GCM_decrypt(
        session_key,
        encrypted_secret_key,
        &iv,
        &aad,
        secret_key_gcm_tag,
        decrypted.as_mut_slice()
    );

    match ret {
        Ok(()) => {},
        Err(x) => { println!("decrypt_secret_key error {}", x) },
    };
}

// fn decrypt_encrypted_client_data(
//     secret_key            : &[u8; CLIENT_SECRET_KEY_SIZE],
//     encrypted_history_data: Vec<Vec<u8>>,
//     geo_mac               : Vec<[u8; SGX_MAC_SIZE]>,
//     data_num              : usize,
//     target_history        : &mut Vec<SpatialData>
// ) {
//     let MERGED_DATA_SIZE: usize = U8_GEODATA_SIZE + U8_TIMESTAMP_SIZE;
//     let iv = [0; SGX_AESGCM_IV_SIZE];
//     let aad:[u8; 0] = [0; 0];
    
//     for i in 0_usize..(data_num) {
//         println!("{}", i);
//         let array_size: usize = encrypted_history_data[i].len();

//         let history_data_slice = unsafe {
//             slice::from_raw_parts(encrypted_history_data[i], array_size as usize)
//         };
//         if history_data_slice.len() != array_size {
//             return sgx_status_t::SGX_ERROR_UNEXPECTED;
//         }
//         let gcm_tag = geo_mac[i];

//         let mut decrypted: Vec<u8> = vec![0; array_size];
//         let ret = rsgx_rijndael128GCM_decrypt(
//             secret_key,
//             &history_data_slice,
//             &iv,
//             &aad,
//             &gcm_tag,
//             decrypted.as_mut_slice()
//         );
//         match ret {
//             Ok(()) => {},
//             Err(x) => { println!("decrypt_encrypted_client_data error {}", x) },
//         };

//         for i in 0_usize..(array_size/MERGED_DATA_SIZE) {
//             let mut timestamp = [0_u8; U8_TIMESTAMP_SIZE];
//             let mut geoHash = [0_u8; U8_GEODATA_SIZE];
//             timestamp.copy_from_slice(&decrypted[i*MERGED_DATA_SIZE..i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE]);
//             geoHash.copy_from_slice(&decrypted[i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE..(i + 1)*MERGED_DATA_SIZE]);
//             let data = SpatialData::new(geoHash, timestamp);
//             target_history.push(data);
//         }
//     }
// }

#[no_mangle]
pub extern "C"
fn store_infected_data( 
    session_token         : &[u8; SESSIONTOKEN_SIZE],
    encrypted_secret_key  : &[u8; CLIENT_SECRET_KEY_SIZE],
    secret_key_gcm_tag    : &[u8; SGX_MAC_SIZE],
    encrypted_history_data: * const u8,
    toal_size             : usize,
    gcm_tag               : * const u8,
    gcm_tag_total_size    : usize,
    size_list             : * const usize,
    data_num              : usize
) -> sgx_status_t {

    println!("start sgx");
    let history_data_slice = unsafe {
        slice::from_raw_parts(encrypted_history_data, toal_size as usize)
    };
    if history_data_slice.len() != toal_size {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let gcm_tag_slice = unsafe {
        slice::from_raw_parts(gcm_tag, gcm_tag_total_size as usize)
    };
    if gcm_tag_slice.len() != gcm_tag_total_size {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let size_list_slice = unsafe {
        slice::from_raw_parts(size_list, data_num as usize)
    };
    if size_list_slice.len() != data_num {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    
    // session key
    let key_manager = get_ref_key_manager().unwrap().borrow_mut();
    let session_key: &sgx_aes_gcm_128bit_key_t = 
        match key_manager.map.get(&get_key_from_vec(session_token)) {
            Some(key) => key,
            None => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
        };
    
    println!("{:?}", encrypted_secret_key);
    println!("{:?}", secret_key_gcm_tag);
    println!("{:?}", session_key);
    let mut secret_key: Vec<u8> = vec![0; CLIENT_SECRET_KEY_SIZE];
    decrypt_secret_key(session_key, encrypted_secret_key, secret_key_gcm_tag, &mut secret_key);
    println!("{:?}", secret_key);

    // let mut target_history: Vec<SpatialData> = Vec::with_capacity(10000);
    // println!("{:?}", encrypted_history_data);
    // decrypt_encrypted_client_data(
    //     secret_key,
    //     encrypted_history_data,
    //     geo_mac,
    //     data_num
    //     &target_history
    // );

    // let mut central_data = get_ref_central_data().unwrap().borrow_mut();
    // central_data.data.append(&mut target_history);
    // // 追加のたびにソートする
    // sort_by_geohash(&mut central_data.data);
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn judge_contact( 
    session_token         : &[u8; SESSIONTOKEN_SIZE],
    secret_key            : &[u8; CLIENT_SECRET_KEY_SIZE],
    secret_key_gcm_tag    : &[u8; SGX_MAC_SIZE],
    encrypted_history_data: * const u8,
    toal_size             : usize,
    gcm_tag               : * const u8,
    gcm_tag_total_size    : usize,
    size_list             : * const usize,
    data_num              : usize,
    risk_level            : &mut [u8; RISKLEVEL_RESULT],
    result_mac            : &mut [u8; SGX_MAC_SIZE]
) -> sgx_status_t {

    let key_manager = get_ref_key_manager().unwrap().borrow_mut();
    let sk_key: sgx_aes_gcm_128bit_key_t = 
        match key_manager.map.get(&get_key_from_vec(session_token)) {
            Some(key) => *key,
            None => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
        };
    let central_data = get_ref_central_data().unwrap().borrow_mut();
    
    let MERGED_DATA_SIZE: usize = U8_GEODATA_SIZE + U8_TIMESTAMP_SIZE;
    let iv = [0; SGX_AESGCM_IV_SIZE];
    let aad:[u8; 0] = [0; 0];
    
    let mut target_history: Vec<SpatialData> = Vec::with_capacity(10000);
    
    // for i in 0_usize..(data_num) {
    //     let array_size: usize = max_geo_data_size;

    //     let history_data_slice = unsafe {
    //         slice::from_raw_parts(encrypted_history_data[i], array_size as usize)
    //     };
    //     if history_data_slice.len() != array_size {
    //         return sgx_status_t::SGX_ERROR_UNEXPECTED;
    //     }
    //     let gcm_tag = geo_mac[i];

    //     let mut decrypted: Vec<u8> = vec![0; array_size];
    //     let ret = rsgx_rijndael128GCM_decrypt(&sk_key,
    //                                         &history_data_slice,
    //                                         &iv,
    //                                         &aad,
    //                                         &gcm_tag,
    //                                         decrypted.as_mut_slice());
    //     match ret {
    //         Ok(()) => {},
    //         Err(x) => return x,
    //     };

    //     for i in 0_usize..(array_size/MERGED_DATA_SIZE) {
    //         let mut timestamp = [0_u8; U8_TIMESTAMP_SIZE];
    //         let mut geoHash = [0_u8; U8_GEODATA_SIZE];
    //         timestamp.copy_from_slice(&decrypted[i*MERGED_DATA_SIZE..i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE]);
    //         geoHash.copy_from_slice(&decrypted[i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE..(i + 1)*MERGED_DATA_SIZE]);
    //         let data = SpatialData::new(geoHash, timestamp);
    //         target_history.push(data);
    //     }
    // }

    let result = judge(&central_data.data, &target_history);
    let raw_risk_level: &[u8; RISKLEVEL_RESULT] = &[result as u8];
    let ret = rsgx_rijndael128GCM_encrypt(&sk_key,
                                            raw_risk_level,
                                            &iv,
                                            &aad,
                                            risk_level,
                                            result_mac);
    println!("{}", risk_level[0]);
    match ret {
        Ok(()) => {},
        Err(x) => return x,
    };

    sgx_status_t::SGX_SUCCESS
}

fn judge(central_data: &Vec<SpatialData>, target_history: &Vec<SpatialData>) -> bool {
    let mut result: Vec<SpatialData> = Vec::with_capacity(100); // なんとなく100，特に意味はない
    naive_matching(central_data, central_data, &mut result);
    result.is_empty()
}

// ナイーブなアルゴリズム
// O(mlogn)
fn naive_matching(a: &Vec<SpatialData>, b: &Vec<SpatialData>, matched_vec: &mut Vec<SpatialData>) {
    let n = a.len();
    for i in 0..n {
        // geohashでバイナリサーチしてできるだけ早く絞る
        let result: Vec<SpatialData> = binary_search(b, &(a[i].geoHash));
        
        // timestampで判定
        // 本来ならば，ここもソート済み配列に対して行うべきだけど無視
        result.iter().for_each(|sp_data| {
            if timestamp_matching(a[i].timestamp, sp_data.timestamp) {
                matched_vec.push(*sp_data);
            }
        })
    }
}

// geohashの距離感 
// 9桁目が一致していれば，だいたい5m以内
// 参考: https://www.fuzina.com/blog/2019/12/10/geohash%E3%81%A7%E7%AF%84%E5%9B%B2%E6%A4%9C%E7%B4%A2%E3%82%92%E8%A1%8C%E3%81%86.html
// when digit = 9, accuracy is 5m
// digit = 8 , about 20m
// https://doc.rust-lang.org/std/cmp/enum.Ordering.html#examples ここを元に return Orderingを実装すれば良さそう
fn geohash_matching(digit: usize, geohash1: [u8; U8_GEODATA_SIZE], geohash2: [u8; U8_GEODATA_SIZE]) -> bool {
    if geohash1[0..digit] != geohash2[0..digit] {
        return false;
    }
    return true
}

// timestampはUNIX epochなので最小単位が1秒
// だから HIGH_RISK_PERIOD = 600 = 10分
// 前後で判定するから ±10分だけど，マイナスはいらない気もする
const HIGH_RISK_PERIOD: i64 = 600;
fn timestamp_matching(timestamp1: u64, timestamp2: u64) -> bool {
    if (timestamp1 as i64 - timestamp2 as i64).abs() > HIGH_RISK_PERIOD {
        return true
    }
    return false
}

// return 
//    result: Vec<SpatialData>
// https://doc.rust-lang.org/std/cmp/enum.Ordering.html#examples このあたりを見てbinary_search_byの引数を変える？
fn binary_search(sp_vec: &Vec<SpatialData>, target: &[u8; U8_GEODATA_SIZE]) -> Vec<SpatialData> {
    let mut index = match sp_vec.binary_search_by(|sp_data| sp_data.geoHash.cmp(&target)) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };
    // 10はなんとなくの数字
    let mut result_vec: Vec<SpatialData> = Vec::with_capacity(10);
    // Vec<>のバイナリサーチは最も後ろのインデックスを返してくるので
    while index >= 0 {
        result_vec.push(sp_vec[index]);
        index = index - 1;
        if !(sp_vec[index].geoHash == *target) {
            break;
        }
    }
    result_vec
}


// oblivious functions
fn oget_intersection(a: &Vec<[u8; SGX_HASH_SIZE]>, b: &Vec<[u8; SGX_HASH_SIZE]>, v1: &mut Vec<u8>, v2: &mut Vec<u8>) {

    let n = a.len();
    for i in 0..n {
        let ret = obinary_search(b, &a[i], v2);
        let miss = oequal(usize::max_value(), ret as usize);
        v1[i] = omov(miss as isize, 0, 1) as u8;
    }
}

fn obinary_search(b: &Vec<[u8; SGX_HASH_SIZE]>, target: &[u8; SGX_HASH_SIZE], v2: &mut Vec<u8>) -> isize {

    let mut lo: isize = 0;
    let mut hi: isize = b.len() as isize - 1;
    let mut ret: isize = -1;

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let hit = eq(&b[mid as usize], target);
        ret = omov(hit, mid, ret);
        v2[mid as usize] = omov(hit, 1, v2[mid as usize] as isize) as u8;
        let be = le(&b[mid as usize], target);
        lo = omov(be, mid + 1, lo);
        hi = omov(be, hi, mid - 1);
    }
    ret
}

fn eq(a: &[u8; SGX_HASH_SIZE], b: &[u8; SGX_HASH_SIZE]) -> isize {

    let mut ret: isize = 1;
    for i in 0..SGX_HASH_SIZE {
        let hit = oequal(a[i] as usize, b[i] as usize);
        ret = omov(hit as isize, ret, 0);
    }
    ret
}

fn le(a: &[u8; SGX_HASH_SIZE], b: &[u8; SGX_HASH_SIZE]) -> isize {

    let mut ret: isize = 0;
    for i in 0..SGX_HASH_SIZE {

        let hit = oequal(a[i] as usize, b[i] as usize);
        let be = ob(a[i] as usize, b[i] as usize);
        let cmp = omov(hit as isize, 0, omov(be as isize, -1, 1));
        ret = omov(ret, ret, cmp)
    }
    (ret <= 0) as isize
}

fn ge(a: &[u8; SGX_HASH_SIZE], b: &[u8; SGX_HASH_SIZE]) -> isize {

    let mut ret: isize = 0;
    for i in 0..SGX_HASH_SIZE {

        let hit = oequal(a[i] as usize, b[i] as usize);
        let ae = oa(a[i] as usize, b[i] as usize);
        let cmp = omov(hit as isize, 0, omov(ae as isize, 1, -1));
        ret = omov(ret, ret, cmp)
    }
    (ret >= 0) as isize
}


// oblivious primitives
fn oequal(x: usize, y: usize) -> bool {

    let ret: bool;
    unsafe {
        asm!(
            "cmp %rcx, %rdx \n\t
             sete %al \n\t"
            : "={al}"(ret)
            : "{rcx}"(x), "{rdx}" (y)
            : "rcx", "rdx"
            : "volatile"
        );
    }
    ret
}

fn obe(x: usize, y: usize) -> bool {

    let ret: bool;
    unsafe {
        asm!(
            "cmp %rdx, %rcx \n\t
             setbe %al \n\t"
            : "={al}"(ret)
            : "{rcx}"(x), "{rdx}" (y)
            : "rcx", "rdx"
            : "volatile"
        );
    }
    ret
}

fn ob(x: usize, y: usize) -> bool {

    let ret: bool;
    unsafe {
        asm!(
            "cmp %rdx, %rcx \n\t
             setb %al \n\t"
            : "={al}"(ret)
            : "{rcx}"(x), "{rdx}" (y)
            : "rcx", "rdx"
            : "volatile"
        );
    }
    ret
}

fn oae(x: usize, y: usize) -> bool {

    let ret: bool;
    unsafe {
        asm!(
            "cmp %rdx, %rcx \n\t
             setae %al \n\t"
            : "={al}"(ret)
            : "{rcx}"(x), "{rdx}" (y)
            : "rcx", "rdx"
            : "volatile"
        );
    }
    ret
}

fn oa(x: usize, y: usize) -> bool {

    let ret: bool;
    unsafe {
        asm!(
            "cmp %rdx, %rcx \n\t
             seta %al \n\t"
            : "={al}"(ret)
            : "{rcx}"(x), "{rdx}" (y)
            : "rcx", "rdx"
            : "volatile"
        );
    }
    ret
}

fn omov(flag: isize, x: isize, y: isize) -> isize {

    let ret: isize;
    unsafe {
        asm!(
            "xor %rcx, %rcx \n\t
             mov $1, %rcx \n\t
             test %rcx, %rcx \n\t
             cmovz %rdx, %rax \n\t"
            : "={rax}"(ret)
            : "r"(flag), "{rax}" (x), "{rdx}" (y)
            : "rax", "rcx", "rdx"
            : "volatile"
        );
    }
    ret
}
