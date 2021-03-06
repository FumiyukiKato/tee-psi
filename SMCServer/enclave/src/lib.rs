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
extern crate num_bigint;

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
use std::time::*;
use std::untrusted::time::SystemTimeEx;
use core::convert::TryInto;
use num_bigint::BigUint;

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

const DEIGITAL_SIGNATURE_SIZE: usize = 32*2;

const UUID_SIZE: usize = 16;

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

#[derive(Debug, Clone, Default, Eq, Ord, PartialEq, PartialOrd, Copy)]
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
#[derive(Default, Clone, Copy)]
struct SignatureKey {
    private_key: sgx_ec256_private_t,
    public_key: sgx_ec256_public_t
}

impl SignatureKey {
    pub fn new() -> Self {
        SignatureKey::default()
    }
}

// 昇順ソート
fn sort_by_geohash(sp_data: &mut Vec<SpatialData>) {
    sp_data.sort_by(|a, b| a.geoHash.cmp(&b.geoHash));
}

static KEY_MANAGER: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());
static CENTRAL_DATA: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());
static SIGNATURE_KEY: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());

fn get_ref_key_manager() -> Option<&'static RefCell<KeyManager>> {
    let ptr = KEY_MANAGER.load(Ordering::SeqCst) as * mut RefCell<KeyManager>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &* ptr })
    }
}

fn get_ref_central_data() -> Option<&'static RefCell<CentralData>> {
    let ptr = CENTRAL_DATA.load(Ordering::SeqCst) as * mut RefCell<CentralData>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &* ptr })
    }
}

fn get_ref_signature_key() -> Option<&'static RefCell<SignatureKey>> {
    let ptr = SIGNATURE_KEY.load(Ordering::SeqCst) as * mut RefCell<SignatureKey>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &* ptr })
    }
}

fn key_provision(signature_key: &mut SignatureKey) {
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (mut prv_k, mut pub_k) = ecc_handle.create_key_pair().unwrap();
    signature_key.private_key = prv_k;
    let mut a = prv_k.r.clone();
    a.reverse();
    // ここでリトルエンディアンを直しておく
    pub_k.gx.reverse();
    pub_k.gy.reverse();
    signature_key.public_key = pub_k;
    let _result = ecc_handle.close();
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

    let mut signature_key = SignatureKey::new();
    key_provision(&mut signature_key);
    let signature_key_box = Box::new(RefCell::<SignatureKey>::new(signature_key));
    let signature_key_ptr = Box::into_raw(signature_key_box);
    SIGNATURE_KEY.store(signature_key_ptr as *mut (), Ordering::SeqCst);

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
    key_manager.map.insert(get_key_from_vec(token), *sk);
    
    sgx_status_t::SGX_SUCCESS
}

fn decrypt_secret_key(
    session_key           : &sgx_aes_gcm_128bit_key_t,
    encrypted_secret_key  : &[u8],
    secret_key_gcm_tag    : &[u8; SGX_MAC_SIZE],
    decrypted             : &mut Vec<u8>
) -> i8 {
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
        Ok(()) => { return 0 },
        Err(x) => { println!("[SGX] decrypt_secret_key error {}", x); return -1 },
    };
}

fn decrypt_encrypted_client_data(
    secret_key            : &[u8; CLIENT_SECRET_KEY_SIZE],
    encrypted_history_data: &[u8],    
    gcm_tag               : &[u8],    
    size_list             : &[usize],
    target_history        : &mut Vec<SpatialData>
) -> i8 {
    let MERGED_DATA_SIZE: usize = U8_GEODATA_SIZE + U8_TIMESTAMP_SIZE;
    let iv = [0; SGX_AESGCM_IV_SIZE];
    let aad:[u8; 0] = [0; 0];
    
    let mut cursor = 0;
    for i in 0_usize..(size_list.len()) {
        // println!("[SGX] {} th data decryption", i);
        let size: usize = size_list[i];
        
        let this_history_data = &encrypted_history_data[cursor..cursor+size];
        cursor = cursor+size; // 忘れないようにここで更新
        let mut this_gcm_tag: [u8; SGX_MAC_SIZE] = [0; SGX_MAC_SIZE];
        this_gcm_tag.copy_from_slice(&gcm_tag[i*SGX_MAC_SIZE..(i+1)*SGX_MAC_SIZE]);
        
        // println!("[SGX] this_history_data {:?}", this_history_data);
        // println!("[SGX] this_gcm_tag {:?}", this_gcm_tag);

        let mut decrypted: Vec<u8> = vec![0; size];
        let ret = rsgx_rijndael128GCM_decrypt(
            secret_key,
            &this_history_data,
            &iv,
            &aad,
            &this_gcm_tag,
            decrypted.as_mut_slice()
        );
        match ret {
            Ok(()) => {},
            Err(x) => { println!("[SGX] decrypt_encrypted_client_data error {}", x); return -1 },
        };

        for i in 0_usize..(size/MERGED_DATA_SIZE) {
            let mut timestamp = [0_u8; U8_TIMESTAMP_SIZE];
            let mut geoHash = [0_u8; U8_GEODATA_SIZE];
            timestamp.copy_from_slice(&decrypted[i*MERGED_DATA_SIZE..i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE]);
            geoHash.copy_from_slice(&decrypted[i*MERGED_DATA_SIZE+U8_TIMESTAMP_SIZE..(i + 1)*MERGED_DATA_SIZE]);
            let data = SpatialData::new(geoHash, timestamp);
            target_history.push(data);
        }
    }
    return 0;
}

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

    
    // get session key
    let key_manager = get_ref_key_manager().unwrap().borrow_mut();
    let session_key: &sgx_aes_gcm_128bit_key_t = 
        match key_manager.map.get(&get_key_from_vec(session_token)) {
            Some(key) => key,
            None => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
        };
    
    // decrypt secret key
    let mut tmp_secret_key: Vec<u8> = vec![0; CLIENT_SECRET_KEY_SIZE];
    let mut ret = decrypt_secret_key(
        session_key,
        encrypted_secret_key,
        secret_key_gcm_tag,
        &mut tmp_secret_key
    );
    if ret < 0 { return sgx_status_t::SGX_ERROR_INVALID_PARAMETER };
    let mut secret_key: [u8; CLIENT_SECRET_KEY_SIZE] = [0; CLIENT_SECRET_KEY_SIZE];
    secret_key.copy_from_slice(&tmp_secret_key.as_slice());
    // println!("[SGX] secret key: {:?}", secret_key);

    // decrypt client data
    let mut target_history: Vec<SpatialData> = Vec::with_capacity(10000);
    ret = decrypt_encrypted_client_data(
        &secret_key, history_data_slice,
        gcm_tag_slice,
        size_list_slice,
        &mut target_history
    );
    if ret < 0 { return sgx_status_t::SGX_ERROR_INVALID_PARAMETER };
    // println!("[SGX] timestamp {:?}", target_history[0].timestamp);
    // println!("[SGX] geohash {:?}", target_history[0].geoHash);

    let mut central_data = get_ref_central_data().unwrap().borrow_mut();
    central_data.data.append(&mut target_history);
    // 追加のたびにソートする
    sort_by_geohash(&mut central_data.data);
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn judge_contact( 
    session_token         : &[u8; SESSIONTOKEN_SIZE],
    encrypted_secret_key  : &[u8; CLIENT_SECRET_KEY_SIZE],
    secret_key_gcm_tag    : &[u8; SGX_MAC_SIZE],
    encrypted_history_data: * const u8,
    toal_size             : usize,
    gcm_tag               : * const u8,
    gcm_tag_total_size    : usize,
    size_list             : * const usize,
    data_num              : usize,
    result                : &mut [u8; RISKLEVEL_RESULT + UUID_SIZE + U8_TIMESTAMP_SIZE],
    result_mac            : &mut [u8; SGX_MAC_SIZE],
    signature             : &mut [u8; DEIGITAL_SIGNATURE_SIZE],
    user_id               : &mut [u8; UUID_SIZE],
) -> sgx_status_t {
    
    /* ここからstore_infected_dataと同じロジック   */
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

    // get session key
    let key_manager = get_ref_key_manager().unwrap().borrow_mut();
    let session_key: &sgx_aes_gcm_128bit_key_t = 
        match key_manager.map.get(&get_key_from_vec(session_token)) {
            Some(key) => key,
            None => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
        };
    
    // decrypt secret key
    let mut tmp_secret_key: Vec<u8> = vec![0; CLIENT_SECRET_KEY_SIZE];
    let mut ret = decrypt_secret_key(
        session_key,
        encrypted_secret_key,
        secret_key_gcm_tag,
        &mut tmp_secret_key
    );
    if ret < 0 { return sgx_status_t::SGX_ERROR_INVALID_PARAMETER };
    let mut secret_key: [u8; CLIENT_SECRET_KEY_SIZE] = [0; CLIENT_SECRET_KEY_SIZE];
    secret_key.copy_from_slice(&tmp_secret_key.as_slice());
    // println!("[SGX] secret key: {:?}", secret_key);

    // decrypt client data
    let mut target_history: Vec<SpatialData> = Vec::with_capacity(10000);
    ret = decrypt_encrypted_client_data(
        &secret_key, history_data_slice,
        gcm_tag_slice,
        size_list_slice,
        &mut target_history
    );
    if ret < 0 { return sgx_status_t::SGX_ERROR_INVALID_PARAMETER };
    /* ここまでstore_infected_dataと同じロジック  */

    /* main logic */
    let central_data = get_ref_central_data().unwrap().borrow_mut();
    let juege_result = judge(&central_data.data, &target_history);
    let raw_risk_level: &[u8; RISKLEVEL_RESULT] = &[!juege_result as u8];
    
    /* signature */
    /* 生データ risk_level [u8; 1] + user_id [u8; 16] + UNIX epoch timestamp [u8; 10] に対して署名する*/
    let signature_key = get_ref_signature_key().unwrap().borrow();
    let ecc_handle = SgxEccHandle::new();

    let mut timestamp = [0_u8; U8_TIMESTAMP_SIZE];
    let now: String = SystemTime::now().duration_since(UNIX_EPOCH).expect("back to the future??").as_secs().to_string();
    timestamp = now.as_bytes().try_into().expect("slice with incorrect length");

    let mut will_signed_data: Vec<u8> = vec![];
    will_signed_data.extend_from_slice(user_id);
    will_signed_data.extend_from_slice(&timestamp);
    will_signed_data.extend_from_slice(raw_risk_level);

    let _result = ecc_handle.open();
    let mut a = signature_key.private_key.r.clone();
    a.reverse();
    let mut sgx_signature = match ecc_handle.ecdsa_sign_slice(will_signed_data.as_slice(), &signature_key.private_key) {
        Ok(sig) => sig,
        Err(x) => return x,
    };
    
    // この仕様はまじでくそ，これ4バイトに対してだからリトルエンディアンではなくないか？と思うのだけれども
    let mut sig_x = sgx_signature.x.clone();
    sig_x.reverse();
    let mut sig_y = sgx_signature.y.clone();
    sig_y.reverse();

    let _result = ecc_handle.close();
    let signature_u32_vec = [sig_x, sig_y].concat();
    let n = signature_u32_vec.len();
    for i in 0..n {
        let buf: [u8; 4] = signature_u32_vec[i].to_be_bytes();
        for j in 0..4 {
            signature[4*i+j] = buf[j];
        }
    }
    
    /* encryption */
    let iv = [0; SGX_AESGCM_IV_SIZE];
    let aad:[u8; 0] = [0; 0];
    let ret = rsgx_rijndael128GCM_encrypt(
        session_key,
        will_signed_data.as_slice(),
        &iv,
        &aad,
        result,
        result_mac
    );
    match ret {
        Ok(()) => {},
        Err(x) => return x,
    };

    sgx_status_t::SGX_SUCCESS
}

fn judge(central_data: &Vec<SpatialData>, target_history: &Vec<SpatialData>) -> bool {
    let mut result: Vec<SpatialData> = Vec::with_capacity(100); // なんとなく100，特に意味はない
    naive_matching(central_data, target_history, &mut result);
    result.is_empty()
}

// ナイーブなアルゴリズム　O(mlogn)
// データ構造も含めて見直したくなったら https://github.com/ylab-public/PCT にヒントがあるはず
fn naive_matching(central_data: &Vec<SpatialData>, target_history: &Vec<SpatialData>, matched_vec: &mut Vec<SpatialData>) {
    let n = target_history.len();
    for i in 0..n {
        // geohashでバイナリサーチしてできるだけ早く絞る
        
        let result: Vec<SpatialData> = binary_search(central_data, &(target_history[i].geoHash));
        
        // timestampで判定
        // 本来ならば，ここもソート済み配列に対して行うべきだけど無視
        result.iter().for_each(|sp_data| {
            if timestamp_matching(target_history[i].timestamp, sp_data.timestamp) {
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
    if (timestamp1 as i64 - timestamp2 as i64).abs() < HIGH_RISK_PERIOD {
        return true
    }
    return false
}

// args
//   sp_vecがソート済みであることは呼び出し元の責任で呼ぶ
// return 
//    result: Vec<SpatialData>
// https://doc.rust-lang.org/std/cmp/enum.Ordering.html#examples このあたりを見てbinary_search_byの引数を変える？
fn binary_search(sp_vec: &Vec<SpatialData>, target: &[u8; U8_GEODATA_SIZE]) -> Vec<SpatialData> {
    let mut index: i64 = match sp_vec.binary_search_by(|sp_data| sp_data.geoHash.cmp(&target)) {
        Ok(i) => i as i64,
        Err(_) => return Vec::new(),
    };
    // 10はなんとなくの数字
    let mut result_vec: Vec<SpatialData> = Vec::with_capacity(10);
    // Vec<>のバイナリサーチは最も後ろのインデックスを返してくるので
    while index >= 0 {
        result_vec.push(sp_vec[index as usize]);
        index = index - 1;
        if index <= 0 || sp_vec[index as usize].geoHash != *target {
            break;
        }
    }
    result_vec
}

#[no_mangle]
pub extern "C"
fn get_public_key( 
    session_token: &[u8; SESSIONTOKEN_SIZE],
    public_key   : &mut [u8; SGX_ECP256_KEY_SIZE*2],
    gcm_tag      : &mut [u8; SGX_MAC_SIZE]
) -> sgx_status_t {
    
    let key_manager = get_ref_key_manager().unwrap().borrow_mut();
    let session_key: &sgx_aes_gcm_128bit_key_t = 
        match key_manager.map.get(&get_key_from_vec(session_token)) {
            Some(key) => key,
            None => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
        };
    let signature_key = get_ref_signature_key().unwrap().borrow();
    let public_key_vec: Vec<u8> = [signature_key.public_key.gx, signature_key.public_key.gy].concat();
    
    let iv = [0; SGX_AESGCM_IV_SIZE];
    let aad:[u8; 0] = [0; 0];
    let ret = rsgx_rijndael128GCM_encrypt(
        session_key,
        public_key_vec.as_slice(),
        &iv,
        &aad,
        public_key,
        gcm_tag
    );
    
    match ret {
        Ok(()) => {},
        Err(x) => return x,
    };
    sgx_status_t::SGX_SUCCESS
}

/* 
* oblivious functions
*   サイドチャネルを意識してコンタクトジャッジのアクセスパターンを隠蔽する時に使う
*   基本的に使わない
*/ 
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


/* 
* oblivious primitives
*   サイドチャネルを意識してコンタクトジャッジのアクセスパターンを隠蔽する時に使う
*   基本的に使わない
*/ 

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
